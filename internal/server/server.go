package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lumapanel/lumanode/internal/config"
)

type Agent struct {
	cfg         config.Config
	logger      *slog.Logger
	server      *http.Server
	replayMu    sync.Mutex
	replayCache map[string]time.Time
}

type Metrics struct {
	CPUPercent        float64 `json:"cpuPercent"`
	MemoryPercent     float64 `json:"memoryPercent"`
	DiskPercent       float64 `json:"diskPercent"`
	RunningContainers int     `json:"runningContainers"`
}

type RuntimeStatus struct {
	Ready                        bool              `json:"ready"`
	Docker                       bool              `json:"docker"`
	DockerCgroupV2               bool              `json:"dockerCgroupV2"`
	DockerCgroupDriverSystemd    bool              `json:"dockerCgroupDriverSystemd"`
	DockerDebugDisabled          bool              `json:"dockerDebugDisabled"`
	DockerExperimentalDisabled   bool              `json:"dockerExperimentalDisabled"`
	DockerSwarmInactive          bool              `json:"dockerSwarmInactive"`
	DockerOomKillEnabled         bool              `json:"dockerOomKillEnabled"`
	DockerIPv4Forwarding         bool              `json:"dockerIPv4Forwarding"`
	DockerBridgeNfIptables       bool              `json:"dockerBridgeNfIptables"`
	DockerBridgeNfIp6tables      bool              `json:"dockerBridgeNfIp6tables"`
	DockerSeccomp                bool              `json:"dockerSeccomp"`
	DockerAppArmor               bool              `json:"dockerAppArmor"`
	DockerUserNamespace          bool              `json:"dockerUserNamespace"`
	DockerLiveRestore            bool              `json:"dockerLiveRestore"`
	DockerDefaultRuntimeRunc     bool              `json:"dockerDefaultRuntimeRunc"`
	DockerNoWarnings             bool              `json:"dockerNoWarnings"`
	DockerRootDirProtected       bool              `json:"dockerRootDirProtected"`
	DockerStorageOverlay2        bool              `json:"dockerStorageOverlay2"`
	DockerStorageDType           bool              `json:"dockerStorageDType"`
	DockerServerVersionSupported bool              `json:"dockerServerVersionSupported"`
	DockerOSTypeLinux            bool              `json:"dockerOSTypeLinux"`
	DockerLocalEndpoint          bool              `json:"dockerLocalEndpoint"`
	DockerSocketProtected        bool              `json:"dockerSocketProtected"`
	Nftables                     bool              `json:"nftables"`
	NftablesUsable               bool              `json:"nftablesUsable"`
	CgroupV2                     bool              `json:"cgroupV2"`
	CgroupControllersReady       bool              `json:"cgroupControllersReady"`
	Errors                       map[string]string `json:"errors,omitempty"`
}

var containerHealthWait = 2 * time.Minute
var containerHealthPoll = 2 * time.Second

var requiredDockerMaskedPaths = []string{
	"/proc/acpi",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/sched_debug",
	"/proc/timer_list",
	"/sys/firmware",
}

var requiredDockerReadonlyPaths = []string{
	"/proc/asound",
	"/proc/bus",
	"/proc/fs",
	"/proc/irq",
	"/proc/sys",
	"/proc/sysrq-trigger",
}

type hostCapacity struct {
	CPUCores float64
	MemoryMB int
	DiskGB   int
}

type certificateRotationRequest struct {
	NodeID    string `json:"nodeId"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expiresAt"`
	Signature string `json:"signature"`
}

type certificateRotationCredentials struct {
	NodeID               string `json:"nodeId"`
	CABundlePEM          string `json:"caBundlePem"`
	ClientCertificatePEM string `json:"clientCertificatePem"`
	ClientKeyPEM         string `json:"clientKeyPem"`
	Fingerprint          string `json:"fingerprint"`
	ExpiresAt            string `json:"expiresAt"`
}

type certificateRotationResponse struct {
	Credentials certificateRotationCredentials `json:"credentials"`
}

type deploymentCompletionRequest struct {
	NodeID    string `json:"nodeId"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expiresAt"`
	Signature string `json:"signature"`
}

func New(cfg config.Config, logger *slog.Logger) *Agent {
	mux := http.NewServeMux()
	agent := &Agent{cfg: cfg, logger: logger, replayCache: map[string]time.Time{}}
	if err := agent.loadReplayCache(time.Now()); err != nil {
		logger.Warn("failed to load replay cache", "error", err, "path", cfg.ReplayStoreFile)
	}
	mux.HandleFunc("/health", agent.health)
	mux.HandleFunc("/metrics", agent.metrics)
	mux.HandleFunc("/deploy", agent.deploy)
	agent.server = &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if cfg.CAFile != "" {
		caBundle, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			logger.Error("failed to read CA bundle", "error", err, "path", cfg.CAFile)
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caBundle) {
				tlsConfig := &tls.Config{
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  pool,
					MinVersion: tls.VersionTLS12,
				}
				if cfg.RevocationListFile != "" {
					tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
						return verifyPeerCertificateNotRevoked(state, cfg.RevocationListFile)
					}
				}
				agent.server.TLSConfig = tlsConfig
			}
		}
	}
	return agent
}

type persistedRevocationList struct {
	Fingerprints        []string `json:"fingerprints"`
	RevokedFingerprints []string `json:"revokedFingerprints"`
	Revocations         []struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"revocations"`
	Revoked []struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"revoked"`
}

func verifyPeerCertificateNotRevoked(state tls.ConnectionState, revocationListFile string) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("missing peer certificate")
	}
	revokedFingerprints, err := loadRevokedFingerprints(revocationListFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate revocation list: %w", err)
	}
	fingerprint := certificateFingerprint(state.PeerCertificates[0])
	if _, revoked := revokedFingerprints[fingerprint]; revoked {
		return fmt.Errorf("peer certificate has been revoked")
	}
	return nil
}

func loadRevokedFingerprints(path string) (map[string]struct{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	revoked := map[string]struct{}{}
	var list []string
	if err := json.Unmarshal(content, &list); err == nil {
		addRevokedFingerprints(revoked, list...)
		return revoked, nil
	}
	var persisted persistedRevocationList
	if err := json.Unmarshal(content, &persisted); err == nil {
		addRevokedFingerprints(revoked, persisted.Fingerprints...)
		addRevokedFingerprints(revoked, persisted.RevokedFingerprints...)
		for _, revocation := range persisted.Revocations {
			addRevokedFingerprints(revoked, revocation.Fingerprint)
		}
		for _, revocation := range persisted.Revoked {
			addRevokedFingerprints(revoked, revocation.Fingerprint)
		}
		return revoked, nil
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			addRevokedFingerprints(revoked, fields[0])
		}
	}
	return revoked, nil
}

func addRevokedFingerprints(revoked map[string]struct{}, fingerprints ...string) {
	for _, fingerprint := range fingerprints {
		normalized := normalizeCertificateFingerprint(fingerprint)
		if normalized != "" {
			revoked[normalized] = struct{}{}
		}
	}
}

func certificateFingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return fmt.Sprintf("%x", sum[:])
}

func normalizeCertificateFingerprint(fingerprint string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fingerprint), ":", ""))
}

func (a *Agent) ListenAndServe(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.server.Shutdown(shutdownCtx)
	}()
	a.logger.Info("starting lumanode", "listen", a.cfg.ListenAddr, "location", a.cfg.Location)
	var err error
	if a.cfg.CertFile != "" && a.cfg.KeyFile != "" {
		err = a.server.ListenAndServeTLS(a.cfg.CertFile, a.cfg.KeyFile)
	} else {
		err = a.server.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (a *Agent) Heartbeat(ctx context.Context) {
	a.logger.InfoContext(ctx, "heartbeat", "node_id", a.cfg.NodeID, "panel", a.cfg.PanelURL)
}

func (a *Agent) RotateCertificateIfDue(ctx context.Context, now time.Time) (bool, error) {
	if a.cfg.CertFile == "" || a.cfg.KeyFile == "" || a.cfg.JobSigningSecret == "" {
		return false, nil
	}
	window := a.cfg.CertificateRotationWindow
	if window <= 0 {
		window = 14 * 24 * time.Hour
	}
	expiresAt, err := certificateExpiresAt(a.cfg.CertFile)
	if err != nil {
		return false, err
	}
	if now.Add(window).Before(expiresAt) {
		return false, nil
	}
	credentials, err := a.requestCertificateRotation(ctx, now)
	if err != nil {
		return false, err
	}
	if credentials.NodeID != "" && credentials.NodeID != a.cfg.NodeID {
		return false, fmt.Errorf("panel returned credentials for unexpected node %q", credentials.NodeID)
	}
	if err := writeFileAtomic(a.cfg.CertFile, []byte(credentials.ClientCertificatePEM), 0o600); err != nil {
		return false, fmt.Errorf("write rotated certificate: %w", err)
	}
	if err := writeFileAtomic(a.cfg.KeyFile, []byte(credentials.ClientKeyPEM), 0o600); err != nil {
		return false, fmt.Errorf("write rotated private key: %w", err)
	}
	if a.cfg.CAFile != "" && credentials.CABundlePEM != "" {
		if err := writeFileAtomic(a.cfg.CAFile, []byte(credentials.CABundlePEM), 0o600); err != nil {
			return false, fmt.Errorf("write rotated CA bundle: %w", err)
		}
	}
	if a.cfg.CredentialsFile != "" {
		response := certificateRotationResponse{Credentials: credentials}
		body, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return false, fmt.Errorf("marshal rotated credentials: %w", err)
		}
		body = append(body, '\n')
		if err := writeFileAtomic(a.cfg.CredentialsFile, body, 0o600); err != nil {
			return false, fmt.Errorf("write rotated credentials: %w", err)
		}
	}
	return true, nil
}

func (a *Agent) requestCertificateRotation(ctx context.Context, now time.Time) (certificateRotationCredentials, error) {
	nonce, err := randomNonce()
	if err != nil {
		return certificateRotationCredentials{}, err
	}
	expiresAt := now.Add(5 * time.Minute).UTC().Format(time.RFC3339)
	payload := certificateRotationPayload(a.cfg.NodeID, nonce, expiresAt)
	mac := hmac.New(sha256.New, []byte(a.cfg.JobSigningSecret))
	mac.Write([]byte(payload))
	requestBody, err := json.Marshal(certificateRotationRequest{
		NodeID:    a.cfg.NodeID,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
		Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		return certificateRotationCredentials{}, err
	}
	endpoint := strings.TrimRight(a.cfg.PanelURL, "/") + "/api/nodes/" + a.cfg.NodeID + "/certificate/rotate-agent"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(requestBody)))
	if err != nil {
		return certificateRotationCredentials{}, err
	}
	request.Header.Set("content-type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return certificateRotationCredentials{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return certificateRotationCredentials{}, fmt.Errorf("panel certificate rotation failed: status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var rotated certificateRotationResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&rotated); err != nil {
		return certificateRotationCredentials{}, fmt.Errorf("decode panel certificate rotation response: %w", err)
	}
	if rotated.Credentials.ClientCertificatePEM == "" || rotated.Credentials.ClientKeyPEM == "" {
		return certificateRotationCredentials{}, fmt.Errorf("panel returned incomplete certificate rotation credentials")
	}
	return rotated.Credentials, nil
}

func certificateRotationPayload(nodeID, nonce, expiresAt string) string {
	return fmt.Sprintf("nodeId:%s\nnonce:%s\nexpiresAt:%s", nodeID, nonce, expiresAt)
}

func randomNonce() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func certificateExpiresAt(path string) (time.Time, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	for {
		var block *pem.Block
		block, content = pem.Decode(content)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return certificate.NotAfter, nil
	}
	return time.Time{}, fmt.Errorf("certificate file has no parseable certificate")
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (a *Agent) health(w http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runtime := a.runtimeStatus(ctx)
	status := "ok"
	if !runtime.Ready {
		status = "degraded"
	}
	writeJSON(w, map[string]any{"status": status, "nodeId": a.cfg.NodeID, "runtime": runtime})
}

func (a *Agent) metrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, Metrics{CPUPercent: 24, MemoryPercent: 41, DiskPercent: 38, RunningContainers: 7})
}

func (a *Agent) deploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		http.Error(w, "invalid deployment job", http.StatusBadRequest)
		return
	}
	var job DeployJob
	var signedEnvelope *signedDeployJob
	if a.cfg.JobSigningSecret != "" {
		var envelope signedDeployJob
		if err := json.Unmarshal(body, &envelope); err != nil {
			http.Error(w, "invalid signed deployment job", http.StatusBadRequest)
			return
		}
		verifiedJob, err := verifySignedDeployJob(envelope, a.cfg.JobSigningSecret, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		job = verifiedJob
		signedEnvelope = &envelope
	} else if err := json.Unmarshal(body, &job); err != nil {
		http.Error(w, "invalid deployment job", http.StatusBadRequest)
		return
	}
	if err := validateDeploymentJob(job, a.cfg.NodeID); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	realExecution := os.Getenv("LUMANODE_DRY_RUN") == "false"
	if realExecution && a.cfg.RequireImageDigest && job.ImageDigest == "" {
		http.Error(w, "deployment job requires immutable image digest", http.StatusUnprocessableEntity)
		return
	}
	if signedEnvelope != nil {
		if err := a.acceptSignedDeployment(*signedEnvelope, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	plan, err := deploymentPlan(job)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if !realExecution {
		writeJSON(w, map[string]any{"status": "planned", "plan": plan, "dockerArgs": plan.ContainerRun.Args})
		return
	}
	if a.cfg.JobSigningSecret == "" {
		http.Error(w, "deployment job signing secret required for real execution", http.StatusUnauthorized)
		return
	}
	if runtime := a.runtimeStatus(r.Context()); !runtime.Ready {
		a.logger.Error("runtime preflight failed", "errors", runtime.Errors)
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"error": "runtime_preflight_failed", "runtime": runtime})
		return
	}
	if err := executeDeploymentPlan(r.Context(), plan); err != nil {
		a.logger.Error("deployment plan failed", "error", err)
		if reportErr := a.reportDeploymentCompletion(r.Context(), job, "failed", err.Error()); reportErr != nil {
			a.logger.Warn("failed to report deployment failure", "error", reportErr, "queue_id", job.QueueID)
		}
		http.Error(w, "deployment plan failed", http.StatusBadGateway)
		return
	}
	if err := a.reportDeploymentCompletion(r.Context(), job, "succeeded", ""); err != nil {
		a.logger.Warn("failed to report deployment completion", "error", err, "queue_id", job.QueueID)
	}
	writeJSON(w, map[string]string{"status": "started", "container": "luma-" + job.DeploymentID})
}

func (a *Agent) reportDeploymentCompletion(ctx context.Context, job DeployJob, status string, failure string) error {
	if job.QueueID == "" || a.cfg.PanelURL == "" || a.cfg.JobSigningSecret == "" {
		return nil
	}
	if status != "succeeded" && status != "failed" {
		return fmt.Errorf("invalid deployment completion status %q", status)
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if len(failure) > 2048 {
		failure = failure[:2048]
	}
	payload := deploymentCompletionPayload(job.QueueID, a.cfg.NodeID, status, failure, nonce, expiresAt)
	mac := hmac.New(sha256.New, []byte(a.cfg.JobSigningSecret))
	mac.Write([]byte(payload))
	requestBody, err := json.Marshal(deploymentCompletionRequest{
		NodeID:    a.cfg.NodeID,
		Status:    status,
		Error:     failure,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
		Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		return err
	}
	reportCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(a.cfg.PanelURL, "/") + "/api/jobs/" + job.QueueID + "/complete-agent"
	request, err := http.NewRequestWithContext(reportCtx, http.MethodPost, endpoint, strings.NewReader(string(requestBody)))
	if err != nil {
		return err
	}
	request.Header.Set("content-type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("panel deployment completion failed: status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func deploymentCompletionPayload(queueID, nodeID, status, failure, nonce, expiresAt string) string {
	return fmt.Sprintf("queueId:%s\nnodeId:%s\nstatus:%s\nerror:%s\nnonce:%s\nexpiresAt:%s", queueID, nodeID, status, failure, nonce, expiresAt)
}

func (a *Agent) acceptSignedDeployment(envelope signedDeployJob, now time.Time) error {
	expiresAt, err := time.Parse(time.RFC3339, envelope.Signature.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid deployment job signature expiry")
	}
	cacheKey := envelope.Signature.KeyID + ":" + envelope.Signature.Value
	a.replayMu.Lock()
	defer a.replayMu.Unlock()
	a.pruneReplayCache(now)
	if expiry, ok := a.replayCache[cacheKey]; ok && expiry.After(now) {
		return fmt.Errorf("replayed deployment job signature")
	}
	a.replayCache[cacheKey] = expiresAt
	if err := a.saveReplayCacheLocked(); err != nil {
		delete(a.replayCache, cacheKey)
		return fmt.Errorf("failed to persist deployment replay cache")
	}
	return nil
}

func (a *Agent) loadReplayCache(now time.Time) error {
	if a.cfg.ReplayStoreFile == "" {
		return nil
	}
	content, err := os.ReadFile(a.cfg.ReplayStoreFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var persisted map[string]string
	if err := json.Unmarshal(content, &persisted); err != nil {
		return err
	}
	for key, value := range persisted {
		expiresAt, err := time.Parse(time.RFC3339, value)
		if err == nil && expiresAt.After(now) {
			a.replayCache[key] = expiresAt
		}
	}
	return nil
}

func (a *Agent) pruneReplayCache(now time.Time) {
	for key, expiry := range a.replayCache {
		if !expiry.After(now) {
			delete(a.replayCache, key)
		}
	}
}

func (a *Agent) saveReplayCacheLocked() error {
	if a.cfg.ReplayStoreFile == "" {
		return nil
	}
	persisted := make(map[string]string, len(a.replayCache))
	for key, expiry := range a.replayCache {
		persisted[key] = expiry.Format(time.RFC3339)
	}
	content, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.ReplayStoreFile), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.cfg.ReplayStoreFile), ".replayed-jobs-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, a.cfg.ReplayStoreFile)
}

func (a *Agent) runtimeStatus(ctx context.Context) RuntimeStatus {
	status := RuntimeStatus{Errors: map[string]string{}}
	if _, err := exec.LookPath("docker"); err != nil {
		status.Errors["docker"] = "docker CLI not found"
	} else {
		status.Docker = true
		output, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.CgroupVersion}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerInfo"] = strings.TrimSpace(string(output))
			if status.Errors["dockerInfo"] == "" {
				status.Errors["dockerInfo"] = err.Error()
			}
		} else if strings.TrimSpace(string(output)) == "2" {
			status.DockerCgroupV2 = true
		} else {
			status.Errors["dockerCgroup"] = "docker is not using cgroups v2"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.CgroupDriver}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerCgroupDriver"] = strings.TrimSpace(string(output))
			if status.Errors["dockerCgroupDriver"] == "" {
				status.Errors["dockerCgroupDriver"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "systemd") {
			status.DockerCgroupDriverSystemd = true
		} else {
			status.Errors["dockerCgroupDriver"] = "docker cgroup driver must be systemd"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.Debug}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerDebug"] = strings.TrimSpace(string(output))
			if status.Errors["dockerDebug"] == "" {
				status.Errors["dockerDebug"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "false") {
			status.DockerDebugDisabled = true
		} else {
			status.Errors["dockerDebug"] = "docker daemon debug mode must be disabled"
		}
		output, err = exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Experimental}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerExperimental"] = strings.TrimSpace(string(output))
			if status.Errors["dockerExperimental"] == "" {
				status.Errors["dockerExperimental"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "false") {
			status.DockerExperimentalDisabled = true
		} else {
			status.Errors["dockerExperimental"] = "docker daemon experimental mode must be disabled"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.Swarm.LocalNodeState}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerSwarm"] = strings.TrimSpace(string(output))
			if status.Errors["dockerSwarm"] == "" {
				status.Errors["dockerSwarm"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "inactive") {
			status.DockerSwarmInactive = true
		} else {
			status.Errors["dockerSwarm"] = "docker swarm mode must be inactive"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.OomKillDisable}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerOomKill"] = strings.TrimSpace(string(output))
			if status.Errors["dockerOomKill"] == "" {
				status.Errors["dockerOomKill"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "false") {
			status.DockerOomKillEnabled = true
		} else {
			status.Errors["dockerOomKill"] = "docker daemon OOM kill disable must be false"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.IPv4Forwarding}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerIPv4Forwarding"] = strings.TrimSpace(string(output))
			if status.Errors["dockerIPv4Forwarding"] == "" {
				status.Errors["dockerIPv4Forwarding"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "true") {
			status.DockerIPv4Forwarding = true
		} else {
			status.Errors["dockerIPv4Forwarding"] = "docker IPv4 forwarding must be enabled"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.BridgeNfIptables}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerBridgeNfIptables"] = strings.TrimSpace(string(output))
			if status.Errors["dockerBridgeNfIptables"] == "" {
				status.Errors["dockerBridgeNfIptables"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "true") {
			status.DockerBridgeNfIptables = true
		} else {
			status.Errors["dockerBridgeNfIptables"] = "docker bridge netfilter iptables hook must be enabled"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.BridgeNfIp6tables}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerBridgeNfIp6tables"] = strings.TrimSpace(string(output))
			if status.Errors["dockerBridgeNfIp6tables"] == "" {
				status.Errors["dockerBridgeNfIp6tables"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "true") {
			status.DockerBridgeNfIp6tables = true
		} else {
			status.Errors["dockerBridgeNfIp6tables"] = "docker bridge netfilter ip6tables hook must be enabled"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{json .SecurityOptions}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerSecurityOptions"] = strings.TrimSpace(string(output))
			if status.Errors["dockerSecurityOptions"] == "" {
				status.Errors["dockerSecurityOptions"] = err.Error()
			}
		} else {
			securityOptions := strings.ToLower(strings.TrimSpace(string(output)))
			if strings.Contains(securityOptions, "seccomp") {
				status.DockerSeccomp = true
			} else {
				status.Errors["dockerSeccomp"] = "docker daemon does not advertise seccomp support"
			}
			if strings.Contains(securityOptions, "apparmor") {
				status.DockerAppArmor = true
			} else {
				status.Errors["dockerAppArmor"] = "docker daemon does not advertise AppArmor support"
			}
			if strings.Contains(securityOptions, "userns") || strings.Contains(securityOptions, "rootless") {
				status.DockerUserNamespace = true
			} else {
				status.Errors["dockerUserNamespace"] = "docker daemon does not advertise user namespace or rootless isolation"
			}
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.LiveRestoreEnabled}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerLiveRestore"] = strings.TrimSpace(string(output))
			if status.Errors["dockerLiveRestore"] == "" {
				status.Errors["dockerLiveRestore"] = err.Error()
			}
		} else if strings.TrimSpace(strings.ToLower(string(output))) == "true" {
			status.DockerLiveRestore = true
		} else {
			status.Errors["dockerLiveRestore"] = "docker daemon live-restore is not enabled"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.DefaultRuntime}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerDefaultRuntime"] = strings.TrimSpace(string(output))
			if status.Errors["dockerDefaultRuntime"] == "" {
				status.Errors["dockerDefaultRuntime"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "runc") {
			status.DockerDefaultRuntimeRunc = true
		} else {
			status.Errors["dockerDefaultRuntime"] = "docker default runtime must be runc"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Warnings}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerWarnings"] = strings.TrimSpace(string(output))
			if status.Errors["dockerWarnings"] == "" {
				status.Errors["dockerWarnings"] = err.Error()
			}
		} else if dockerWarningsEmpty(string(output)) {
			status.DockerNoWarnings = true
		} else {
			status.Errors["dockerWarnings"] = "docker daemon reports warnings: " + strings.TrimSpace(string(output))
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.DockerRootDir}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerRootDir"] = strings.TrimSpace(string(output))
			if status.Errors["dockerRootDir"] == "" {
				status.Errors["dockerRootDir"] = err.Error()
			}
		} else if protected, err := dockerRootDirProtected(strings.TrimSpace(string(output))); err != nil {
			status.Errors["dockerRootDir"] = err.Error()
		} else if protected {
			status.DockerRootDirProtected = true
		} else {
			status.Errors["dockerRootDir"] = "docker root directory must not be group- or world-writable"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.Driver}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerStorageOverlay2"] = strings.TrimSpace(string(output))
			if status.Errors["dockerStorageOverlay2"] == "" {
				status.Errors["dockerStorageOverlay2"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "overlay2") {
			status.DockerStorageOverlay2 = true
		} else {
			status.Errors["dockerStorageOverlay2"] = "docker storage driver is not overlay2"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{json .DriverStatus}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerStorageDType"] = strings.TrimSpace(string(output))
			if status.Errors["dockerStorageDType"] == "" {
				status.Errors["dockerStorageDType"] = err.Error()
			}
		} else if dockerOverlaySupportsDType(string(output)) {
			status.DockerStorageDType = true
		} else {
			status.Errors["dockerStorageDType"] = "docker overlay2 backing filesystem must support d_type"
		}
		output, err = exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerServerVersion"] = strings.TrimSpace(string(output))
			if status.Errors["dockerServerVersion"] == "" {
				status.Errors["dockerServerVersion"] = err.Error()
			}
		} else if dockerServerVersionSupported(strings.TrimSpace(string(output))) {
			status.DockerServerVersionSupported = true
		} else {
			status.Errors["dockerServerVersion"] = "docker server version must be 24.0.0 or newer"
		}
		output, err = exec.CommandContext(ctx, "docker", "info", "--format", "{{.OSType}}").CombinedOutput()
		if err != nil {
			status.Errors["dockerOSType"] = strings.TrimSpace(string(output))
			if status.Errors["dockerOSType"] == "" {
				status.Errors["dockerOSType"] = err.Error()
			}
		} else if strings.EqualFold(strings.TrimSpace(string(output)), "linux") {
			status.DockerOSTypeLinux = true
		} else {
			status.Errors["dockerOSType"] = "docker OS type must be linux"
		}
		endpoint, err := dockerEndpoint(ctx)
		if err != nil {
			status.Errors["dockerEndpoint"] = err.Error()
		} else if dockerEndpointLocal(endpoint) {
			status.DockerLocalEndpoint = true
			if protected, err := dockerSocketProtected(endpoint); err != nil {
				status.Errors["dockerSocket"] = err.Error()
			} else if protected {
				status.DockerSocketProtected = true
			} else {
				status.Errors["dockerSocket"] = "docker unix socket must not be world-writable"
			}
		} else {
			status.Errors["dockerEndpoint"] = "docker endpoint must be a local unix socket, not " + endpoint
		}
	}
	if _, err := exec.LookPath("nft"); err != nil {
		status.Errors["nftables"] = "nft CLI not found"
	} else {
		status.Nftables = true
		if output, err := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput(); err != nil {
			status.Errors["nftablesUsable"] = strings.TrimSpace(string(output))
			if status.Errors["nftablesUsable"] == "" {
				status.Errors["nftablesUsable"] = err.Error()
			}
		} else {
			status.NftablesUsable = true
		}
	}
	cgroupControllersFile := a.cfg.RuntimeCgroupControllersFile
	if cgroupControllersFile == "" {
		cgroupControllersFile = "/sys/fs/cgroup/cgroup.controllers"
	}
	if content, err := os.ReadFile(cgroupControllersFile); err != nil {
		status.Errors["cgroupV2"] = err.Error()
	} else if strings.TrimSpace(string(content)) == "" {
		status.Errors["cgroupV2"] = "cgroup controllers file is empty"
	} else {
		status.CgroupV2 = true
		if missing := missingRequiredCgroupControllers(string(content)); len(missing) == 0 {
			status.CgroupControllersReady = true
		} else {
			status.Errors["cgroupControllers"] = "missing required cgroup v2 controllers: " + strings.Join(missing, ", ")
		}
	}
	status.Ready = status.Docker && status.DockerCgroupV2 && status.DockerCgroupDriverSystemd && status.DockerDebugDisabled && status.DockerExperimentalDisabled && status.DockerSwarmInactive && status.DockerOomKillEnabled && status.DockerIPv4Forwarding && status.DockerBridgeNfIptables && status.DockerBridgeNfIp6tables && status.DockerSeccomp && status.DockerAppArmor && status.DockerUserNamespace && status.DockerLiveRestore && status.DockerDefaultRuntimeRunc && status.DockerNoWarnings && status.DockerRootDirProtected && status.DockerStorageOverlay2 && status.DockerStorageDType && status.DockerServerVersionSupported && status.DockerOSTypeLinux && status.DockerLocalEndpoint && status.DockerSocketProtected && status.Nftables && status.NftablesUsable && status.CgroupV2 && status.CgroupControllersReady
	if len(status.Errors) == 0 {
		status.Errors = nil
	}
	return status
}

func dockerWarningsEmpty(output string) bool {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || trimmed == "null" {
		return true
	}
	var warnings []string
	if err := json.Unmarshal([]byte(trimmed), &warnings); err != nil {
		return false
	}
	return len(warnings) == 0
}

func missingRequiredCgroupControllers(content string) []string {
	available := map[string]bool{}
	for _, controller := range strings.Fields(content) {
		available[controller] = true
	}
	required := []string{"cpu", "memory", "pids"}
	var missing []string
	for _, controller := range required {
		if !available[controller] {
			missing = append(missing, controller)
		}
	}
	return missing
}

func dockerEndpoint(ctx context.Context) (string, error) {
	if dockerHost := strings.TrimSpace(os.Getenv("DOCKER_HOST")); dockerHost != "" {
		return dockerHost, nil
	}
	output, err := exec.CommandContext(ctx, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return "", fmt.Errorf("%s", trimmed)
		}
		return "", err
	}
	return strings.Trim(strings.TrimSpace(string(output)), `"`), nil
}

func dockerEndpointLocal(endpoint string) bool {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	return endpoint == "" || strings.HasPrefix(endpoint, "unix://")
}

func dockerSocketProtected(endpoint string) (bool, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return true, nil
	}
	if !strings.HasPrefix(strings.ToLower(endpoint), "unix://") {
		return false, nil
	}
	socketPath := strings.TrimSpace(endpoint[len("unix://"):])
	if socketPath == "" {
		return false, fmt.Errorf("docker unix socket path is empty")
	}
	if !filepath.IsAbs(socketPath) {
		return false, fmt.Errorf("docker unix socket path %q is not absolute", socketPath)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		return false, fmt.Errorf("docker unix socket stat failed: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("docker endpoint %q must not be a symlink", socketPath)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return false, fmt.Errorf("docker endpoint %q is not a unix socket", socketPath)
	}
	return info.Mode().Perm()&0o002 == 0, nil
}

func dockerRootDirProtected(rootDir string) (bool, error) {
	rootDir = strings.TrimSpace(rootDir)
	if rootDir == "" {
		return false, fmt.Errorf("docker root directory is empty")
	}
	if !filepath.IsAbs(rootDir) {
		return false, fmt.Errorf("docker root directory %q is not absolute", rootDir)
	}
	info, err := os.Lstat(rootDir)
	if err != nil {
		return false, fmt.Errorf("docker root directory stat failed: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("docker root directory %q must not be a symlink", rootDir)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("docker root directory %q is not a directory", rootDir)
	}
	return info.Mode().Perm()&0o022 == 0, nil
}

func dockerOverlaySupportsDType(raw string) bool {
	var rows [][]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &rows); err != nil {
		status := strings.ToLower(raw)
		index := strings.Index(status, "supports d_type")
		if index < 0 {
			index = strings.Index(status, "supports dtype")
		}
		if index < 0 {
			return false
		}
		valueStart := strings.Index(status[index:], ":")
		if valueStart < 0 {
			return false
		}
		fields := strings.Fields(status[index+valueStart+1:])
		return len(fields) > 0 && fields[0] == "true"
	}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(row[0]))
		value := strings.ToLower(strings.TrimSpace(row[1]))
		if name == "supports d_type" || name == "supports dtype" {
			return value == "true"
		}
	}
	return false
}

func dockerServerVersionSupported(version string) bool {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(versionNumberPrefix(parts[0]))
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(versionNumberPrefix(parts[1]))
	if err != nil {
		return false
	}
	if major > 24 {
		return true
	}
	return major == 24 && minor >= 0
}

func versionNumberPrefix(part string) string {
	var builder strings.Builder
	for _, r := range part {
		if r < '0' || r > '9' {
			break
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func executeDeploymentPlan(ctx context.Context, plan DeploymentPlan) error {
	capacity, err := readHostCapacity(plan.TenantRoot)
	if err != nil {
		return err
	}
	if err := validateHostCapacity(plan, capacity); err != nil {
		return err
	}
	if err := validateHostPortsAvailable(plan); err != nil {
		return err
	}
	if err := ensureDeploymentDirectories(plan); err != nil {
		return err
	}
	if err := ensureTenantNetwork(ctx, plan); err != nil {
		return err
	}
	for _, command := range plan.Firewall {
		if err := runIdempotentCommand(ctx, command); err != nil {
			return err
		}
	}
	if err := reconcileDeploymentFirewall(ctx, plan.DeploymentID, desiredFirewallComments(plan.Firewall)); err != nil {
		return err
	}
	if err := removeExistingContainer(ctx, plan); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, plan.ContainerRun.Name, plan.ContainerRun.Args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if cleanupErr := cleanupFailedDeployment(ctx, plan); cleanupErr != nil {
			return fmt.Errorf("docker run failed: %w: %s; cleanup failed: %v", err, string(output), cleanupErr)
		}
		return fmt.Errorf("docker run failed: %w: %s", err, string(output))
	}
	if err := verifyStartedContainer(ctx, plan); err != nil {
		if cleanupErr := cleanupFailedDeployment(ctx, plan); cleanupErr != nil {
			return fmt.Errorf("post-start container verification failed: %w; cleanup failed: %v", err, cleanupErr)
		}
		return err
	}
	if err := enforceContainerEgress(ctx, plan); err != nil {
		if cleanupErr := cleanupFailedDeployment(ctx, plan); cleanupErr != nil {
			return fmt.Errorf("post-start egress hardening failed: %w; cleanup failed: %v", err, cleanupErr)
		}
		return err
	}
	return nil
}

func validateHostPortsAvailable(plan DeploymentPlan) error {
	checked := map[string]struct{}{}
	for _, port := range plan.Ports {
		protocol := strings.ToLower(strings.TrimSpace(port.Protocol))
		if protocol == "" {
			protocol = "tcp"
		}
		key := fmt.Sprintf("%s/%d", protocol, port.HostPort)
		if _, exists := checked[key]; exists {
			continue
		}
		checked[key] = struct{}{}
		switch protocol {
		case "tcp":
			listener, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port.HostPort)))
			if err != nil {
				return fmt.Errorf("host port preflight failed: tcp/%d is not available: %w", port.HostPort, err)
			}
			_ = listener.Close()
		case "udp":
			conn, err := net.ListenPacket("udp", net.JoinHostPort("", strconv.Itoa(port.HostPort)))
			if err != nil {
				return fmt.Errorf("host port preflight failed: udp/%d is not available: %w", port.HostPort, err)
			}
			_ = conn.Close()
		default:
			return fmt.Errorf("host port preflight failed: unsupported protocol %q", port.Protocol)
		}
	}
	return nil
}

func readHostCapacity(tenantRoot string) (hostCapacity, error) {
	memoryMB, err := readAvailableMemoryMB("/proc/meminfo")
	if err != nil {
		return hostCapacity{}, err
	}
	diskGB, err := readAvailableDiskGB(tenantRoot)
	if err != nil {
		return hostCapacity{}, err
	}
	return hostCapacity{
		CPUCores: float64(runtime.NumCPU()),
		MemoryMB: memoryMB,
		DiskGB:   diskGB,
	}, nil
}

func validateHostCapacity(plan DeploymentPlan, capacity hostCapacity) error {
	if capacity.CPUCores <= 0 || capacity.MemoryMB <= 0 || capacity.DiskGB <= 0 {
		return fmt.Errorf("host capacity preflight returned invalid capacity")
	}
	if plan.Resources.CPUCores > capacity.CPUCores {
		return fmt.Errorf("deployment requires %.2f CPU cores but host has %.2f available cores", plan.Resources.CPUCores, capacity.CPUCores)
	}
	if plan.Resources.MemoryMB > capacity.MemoryMB {
		return fmt.Errorf("deployment requires %d MiB memory but host has %d MiB available", plan.Resources.MemoryMB, capacity.MemoryMB)
	}
	if plan.Resources.DiskGB > capacity.DiskGB {
		return fmt.Errorf("deployment requires %d GiB writable disk but host has %d GiB available", plan.Resources.DiskGB, capacity.DiskGB)
	}
	return nil
}

func readAvailableMemoryMB(meminfoPath string) (int, error) {
	content, err := os.ReadFile(meminfoPath)
	if err != nil {
		return 0, fmt.Errorf("host memory preflight failed: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemAvailable:" {
			continue
		}
		kib, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("host memory preflight returned invalid MemAvailable value")
		}
		return int(kib / 1024), nil
	}
	return 0, fmt.Errorf("host memory preflight could not find MemAvailable")
}

func readAvailableDiskGB(path string) (int, error) {
	target := nearestExistingPath(path)
	var stat syscall.Statfs_t
	if err := syscall.Statfs(target, &stat); err != nil {
		return 0, fmt.Errorf("host disk preflight failed for %q: %w", target, err)
	}
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	return int(availableBytes / 1024 / 1024 / 1024), nil
}

func nearestExistingPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return string(filepath.Separator)
	}
	current := filepath.Clean(path)
	for {
		if _, err := os.Stat(current); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return string(filepath.Separator)
		}
		current = parent
	}
}

func ensureDeploymentDirectories(plan DeploymentPlan) error {
	if plan.TenantRoot == "" {
		return fmt.Errorf("deployment directory preflight missing tenant root")
	}
	for _, directory := range plan.Directories {
		if err := ensureTenantDirectory(plan.TenantRoot, directory); err != nil {
			return err
		}
	}
	return nil
}

func ensureTenantDirectory(tenantRoot string, directory string) error {
	tenantRoot = filepath.Clean(tenantRoot)
	directory = filepath.Clean(directory)
	relative, err := filepath.Rel(tenantRoot, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("deployment directory %q escapes tenant root %q", directory, tenantRoot)
	}
	return mkdirAllNoSymlinks(directory, tenantRoot)
}

func mkdirAllNoSymlinks(directory string, restrictedRoot string) error {
	directory = filepath.Clean(directory)
	restrictedRoot = filepath.Clean(restrictedRoot)
	if !filepath.IsAbs(directory) {
		return fmt.Errorf("deployment directory %q must be absolute", directory)
	}
	current := string(filepath.Separator)
	for _, element := range strings.Split(strings.TrimPrefix(directory, string(filepath.Separator)), string(filepath.Separator)) {
		if element == "" {
			continue
		}
		current = filepath.Join(current, element)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o750); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("deployment directory %q uses symlinked path component %q", directory, current)
		}
		if !info.IsDir() {
			return fmt.Errorf("deployment directory %q uses non-directory path component %q", directory, current)
		}
		if pathWithinRoot(restrictedRoot, current) && info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("deployment directory %q uses group- or world-writable tenant path component %q", directory, current)
		}
	}
	return nil
}

func pathWithinRoot(root string, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func cleanupFailedDeployment(ctx context.Context, plan DeploymentPlan) error {
	var failures []string
	if err := removeExistingContainer(ctx, plan); err != nil {
		failures = append(failures, err.Error())
	}
	if err := cleanupDeploymentFirewall(ctx, plan.DeploymentID); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func verifyStartedContainer(ctx context.Context, plan DeploymentPlan) error {
	if plan.ContainerName == "" {
		return fmt.Errorf("docker container verification missing container name")
	}
	state, err := inspectStartedContainerState(ctx, plan.ContainerName)
	if err != nil {
		return err
	}
	if !state.Running {
		return fmt.Errorf("docker container %q is not running after start", plan.ContainerName)
	}
	if state.Paused || state.Restarting || state.Dead || state.OOMKilled {
		return fmt.Errorf("docker container %q has unsafe runtime state after start", plan.ContainerName)
	}
	if state.RestartCount != 0 {
		return fmt.Errorf("docker container %q restarted unexpectedly after start", plan.ContainerName)
	}
	if !state.Managed || state.DeploymentID != plan.DeploymentID || state.TenantID != plan.TenantID || state.NodeID != plan.NodeID {
		return fmt.Errorf("docker container %q ownership labels do not match deployment plan", plan.ContainerName)
	}
	if err := verifyStartedContainerIsolation(ctx, plan); err != nil {
		return err
	}
	if err := verifyStartedContainerResources(ctx, plan); err != nil {
		return err
	}
	if err := verifyStartedContainerMounts(ctx, plan); err != nil {
		return err
	}
	if err := verifyStartedContainerImage(ctx, plan); err != nil {
		return err
	}
	if err := verifyStartedContainerWorkload(ctx, plan); err != nil {
		return err
	}
	if err := verifyStartedContainerHealthcheck(ctx, plan); err != nil {
		return err
	}
	if plan.Healthcheck == "" {
		return nil
	}
	return waitForStartedContainerHealthy(ctx, plan)
}

type startedContainerState struct {
	Running      bool
	Paused       bool
	Restarting   bool
	Dead         bool
	OOMKilled    bool
	Health       string
	Managed      bool
	DeploymentID string
	TenantID     string
	NodeID       string
	RestartCount int
}

func inspectStartedContainerState(ctx context.Context, containerName string) (startedContainerState, error) {
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{ .State.Running }} {{ .State.Paused }} {{ .State.Restarting }} {{ .State.Dead }} {{ .State.OOMKilled }} {{ if .State.Health }}{{ .State.Health.Status }}{{ else }}none{{ end }} {{ index .Config.Labels "luma.managed" }} {{ index .Config.Labels "luma.deployment" }} {{ index .Config.Labels "luma.tenant" }} {{ index .Config.Labels "luma.node" }} {{ .RestartCount }}`,
		containerName,
	).CombinedOutput()
	if err != nil {
		return startedContainerState{}, fmt.Errorf("docker container state inspect failed: %w: %s", err, string(output))
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 11 {
		return startedContainerState{}, fmt.Errorf("docker container %q state inspect returned incomplete data", containerName)
	}
	running, err := dockerInspectBool(fields[0], "running", containerName)
	if err != nil {
		return startedContainerState{}, err
	}
	paused, err := dockerInspectBool(fields[1], "paused", containerName)
	if err != nil {
		return startedContainerState{}, err
	}
	restarting, err := dockerInspectBool(fields[2], "restarting", containerName)
	if err != nil {
		return startedContainerState{}, err
	}
	dead, err := dockerInspectBool(fields[3], "dead", containerName)
	if err != nil {
		return startedContainerState{}, err
	}
	oomKilled, err := dockerInspectBool(fields[4], "OOM-killed", containerName)
	if err != nil {
		return startedContainerState{}, err
	}
	managed, err := dockerInspectBool(fields[6], "managed label", containerName)
	if err != nil {
		return startedContainerState{}, err
	}
	restartCount, err := strconv.Atoi(fields[10])
	if err != nil || restartCount < 0 {
		return startedContainerState{}, fmt.Errorf("docker container %q state inspect returned invalid restart count %q", containerName, fields[10])
	}
	return startedContainerState{
		Running:      running,
		Paused:       paused,
		Restarting:   restarting,
		Dead:         dead,
		OOMKilled:    oomKilled,
		Health:       fields[5],
		Managed:      managed,
		DeploymentID: fields[7],
		TenantID:     fields[8],
		NodeID:       fields[9],
		RestartCount: restartCount,
	}, nil
}

func dockerInspectBool(value string, field string, containerName string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("docker container %q state inspect returned invalid %s boolean %q", containerName, field, value)
	}
}

func waitForStartedContainerHealthy(ctx context.Context, plan DeploymentPlan) error {
	deadline := time.NewTimer(containerHealthWait)
	defer deadline.Stop()
	for {
		state, err := inspectStartedContainerState(ctx, plan.ContainerName)
		if err != nil {
			return err
		}
		if !state.Running {
			return fmt.Errorf("docker container %q stopped before becoming healthy", plan.ContainerName)
		}
		if state.Paused || state.Restarting || state.Dead || state.OOMKilled {
			return fmt.Errorf("docker container %q has unsafe runtime state before becoming healthy", plan.ContainerName)
		}
		if state.RestartCount != 0 {
			return fmt.Errorf("docker container %q restarted unexpectedly before becoming healthy", plan.ContainerName)
		}
		if !state.Managed || state.DeploymentID != plan.DeploymentID || state.TenantID != plan.TenantID || state.NodeID != plan.NodeID {
			return fmt.Errorf("docker container %q ownership labels do not match deployment plan", plan.ContainerName)
		}
		switch state.Health {
		case "healthy":
			return nil
		case "none":
			return fmt.Errorf("docker container %q is missing expected health status", plan.ContainerName)
		case "unhealthy":
			return fmt.Errorf("docker container %q reported unhealthy after start", plan.ContainerName)
		case "starting":
		default:
			return fmt.Errorf("docker container %q reported unexpected health status %q", plan.ContainerName, state.Health)
		}
		poll := time.NewTimer(containerHealthPoll)
		select {
		case <-ctx.Done():
			poll.Stop()
			return fmt.Errorf("docker container %q did not become healthy: %w", plan.ContainerName, ctx.Err())
		case <-deadline.C:
			poll.Stop()
			return fmt.Errorf("docker container %q did not become healthy before timeout", plan.ContainerName)
		case <-poll.C:
		}
	}
}

func verifyStartedContainerImage(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{ .Config.Image }}`,
		plan.ContainerName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container image inspect failed: %w: %s", err, string(output))
	}
	image := strings.TrimSpace(string(output))
	if image != plan.ResolvedImage {
		return fmt.Errorf("docker container %q did not keep expected image reference", plan.ContainerName)
	}
	return nil
}

type dockerWorkloadInspect struct {
	ID     string `json:"Id"`
	Config struct {
		Entrypoint      []string            `json:"Entrypoint"`
		Cmd             []string            `json:"Cmd"`
		Shell           []string            `json:"Shell"`
		Env             []string            `json:"Env"`
		WorkingDir      string              `json:"WorkingDir"`
		Hostname        string              `json:"Hostname"`
		OpenStdin       bool                `json:"OpenStdin"`
		StdinOnce       bool                `json:"StdinOnce"`
		Tty             bool                `json:"Tty"`
		AttachStdin     bool                `json:"AttachStdin"`
		AttachStdout    bool                `json:"AttachStdout"`
		AttachStderr    bool                `json:"AttachStderr"`
		NetworkDisabled bool                `json:"NetworkDisabled"`
		Labels          map[string]string   `json:"Labels"`
		ExposedPorts    map[string]struct{} `json:"ExposedPorts"`
		Volumes         map[string]struct{} `json:"Volumes"`
	} `json:"Config"`
}

func verifyStartedContainerWorkload(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{json .}}", plan.ContainerName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container workload inspect failed: %w: %s", err, string(output))
	}
	var workload dockerWorkloadInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &workload); err != nil {
		return fmt.Errorf("docker container %q workload inspect returned invalid data: %w", plan.ContainerName, err)
	}
	if len(workload.Config.Entrypoint) != 0 {
		return fmt.Errorf("docker container %q kept unexpected image entrypoint", plan.ContainerName)
	}
	expectedCommand := []string{"sh", "-lc", plan.Command}
	if !slices.Equal(workload.Config.Cmd, expectedCommand) {
		return fmt.Errorf("docker container %q did not keep expected startup command", plan.ContainerName)
	}
	if len(workload.Config.Shell) != 0 {
		return fmt.Errorf("docker container %q kept unexpected image shell", plan.ContainerName)
	}
	if workload.Config.WorkingDir != defaultContainerWorkingDir {
		return fmt.Errorf("docker container %q did not keep expected working directory", plan.ContainerName)
	}
	if workload.Config.Hostname != "" && workload.ID != "" && !dockerGeneratedHostname(workload.ID, workload.Config.Hostname) {
		return fmt.Errorf("docker container %q has unexpected hostname override", plan.ContainerName)
	}
	if workload.Config.OpenStdin || workload.Config.StdinOnce || workload.Config.Tty {
		return fmt.Errorf("docker container %q has unexpected interactive console settings", plan.ContainerName)
	}
	if workload.Config.AttachStdin || workload.Config.AttachStdout || workload.Config.AttachStderr {
		return fmt.Errorf("docker container %q has unexpected attach stream settings", plan.ContainerName)
	}
	if workload.Config.NetworkDisabled {
		return fmt.Errorf("docker container %q has networking disabled outside the signed tenant network contract", plan.ContainerName)
	}
	if err := verifyStartedContainerLumaLabels(plan, workload.Config.Labels); err != nil {
		return err
	}
	if err := verifyStartedContainerExposedPorts(plan, workload.Config.ExposedPorts); err != nil {
		return err
	}
	if err := verifyStartedContainerImageVolumes(plan, workload.Config.Volumes); err != nil {
		return err
	}
	if len(workload.Config.Env) > maxContainerEffectiveEnvVars {
		return fmt.Errorf("docker container %q has too many effective environment variables", plan.ContainerName)
	}
	actualEnv := map[string]string{}
	for _, item := range workload.Config.Env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return fmt.Errorf("docker container %q has malformed environment entry", plan.ContainerName)
		}
		if !validEnvironmentVariable(key, value) {
			return fmt.Errorf("docker container %q has invalid effective environment variable %q", plan.ContainerName, key)
		}
		if _, exists := actualEnv[key]; exists {
			return fmt.Errorf("docker container %q has duplicate environment variable %q", plan.ContainerName, key)
		}
		actualEnv[key] = value
	}
	for key, expected := range plan.Env {
		if actualEnv[key] != expected {
			return fmt.Errorf("docker container %q did not keep expected environment variable %q", plan.ContainerName, key)
		}
	}
	for key := range actualEnv {
		if strings.HasPrefix(key, "LUMA_") {
			if _, expected := plan.Env[key]; !expected {
				return fmt.Errorf("docker container %q has unexpected LUMA environment variable %q", plan.ContainerName, key)
			}
		}
	}
	reserved := map[string]string{
		"LUMA_DEPLOYMENT_ID": plan.DeploymentID,
		"LUMA_TENANT_ID":     plan.TenantID,
		"LUMA_NODE_ID":       plan.NodeID,
	}
	for key, expected := range reserved {
		if actual, ok := actualEnv[key]; ok && actual != expected {
			return fmt.Errorf("docker container %q has drifted reserved environment variable %q", plan.ContainerName, key)
		}
	}
	return nil
}

func verifyStartedContainerImageVolumes(plan DeploymentPlan, volumes map[string]struct{}) error {
	if len(volumes) == 0 {
		return nil
	}
	expected := map[string]struct{}{}
	for _, mount := range plan.Mounts {
		expected[mount.Target] = struct{}{}
	}
	for target := range volumes {
		if _, ok := expected[target]; !ok {
			return fmt.Errorf("docker container %q has unexpected image volume %q", plan.ContainerName, target)
		}
	}
	return nil
}

func verifyStartedContainerExposedPorts(plan DeploymentPlan, exposedPorts map[string]struct{}) error {
	if len(exposedPorts) == 0 {
		return nil
	}
	expected := map[string]struct{}{}
	for _, port := range plan.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		expected[fmt.Sprintf("%d/%s", port.ContainerPort, protocol)] = struct{}{}
	}
	for port := range exposedPorts {
		if _, ok := expected[port]; !ok {
			return fmt.Errorf("docker container %q has unexpected exposed port %q", plan.ContainerName, port)
		}
	}
	return nil
}

func verifyStartedContainerLumaLabels(plan DeploymentPlan, actualLabels map[string]string) error {
	if len(actualLabels) > maxContainerEffectiveLabels {
		return fmt.Errorf("docker container %q has too many effective Docker labels", plan.ContainerName)
	}
	for key, actual := range actualLabels {
		if !validDockerLabel(key, actual) {
			return fmt.Errorf("docker container %q has invalid effective Docker label %q", plan.ContainerName, key)
		}
		if !strings.HasPrefix(key, "luma.") {
			continue
		}
		expected, ok := plan.Labels[key]
		if !ok {
			return fmt.Errorf("docker container %q has unexpected LUMA label %q", plan.ContainerName, key)
		}
		if actual != expected {
			return fmt.Errorf("docker container %q has drifted LUMA label %q", plan.ContainerName, key)
		}
	}
	for key, expected := range plan.Labels {
		if !strings.HasPrefix(key, "luma.") {
			continue
		}
		if actualLabels[key] != expected {
			return fmt.Errorf("docker container %q did not keep expected LUMA label %q", plan.ContainerName, key)
		}
	}
	return nil
}

type dockerHealthcheckConfig struct {
	Test          []string `json:"Test"`
	Interval      int64    `json:"Interval"`
	Timeout       int64    `json:"Timeout"`
	Retries       int      `json:"Retries"`
	StartPeriod   int64    `json:"StartPeriod"`
	StartInterval int64    `json:"StartInterval"`
}

func verifyStartedContainerHealthcheck(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{json .Config.Healthcheck}}`,
		plan.ContainerName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container healthcheck inspect failed: %w: %s", err, string(output))
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return fmt.Errorf("docker container %q is missing expected healthcheck configuration", plan.ContainerName)
	}
	if trimmed == "null" {
		if plan.Healthcheck == "" {
			return nil
		}
		return fmt.Errorf("docker container %q is missing expected healthcheck configuration", plan.ContainerName)
	}
	if plan.Healthcheck == "" {
		return fmt.Errorf("docker container %q kept unexpected image healthcheck", plan.ContainerName)
	}
	var healthcheck dockerHealthcheckConfig
	if err := json.Unmarshal([]byte(trimmed), &healthcheck); err != nil {
		return fmt.Errorf("docker container %q healthcheck inspect returned invalid data: %w", plan.ContainerName, err)
	}
	if len(healthcheck.Test) != 2 || healthcheck.Test[0] != "CMD-SHELL" || healthcheck.Test[1] != plan.Healthcheck {
		return fmt.Errorf("docker container %q did not keep expected healthcheck command", plan.ContainerName)
	}
	if healthcheck.Interval != int64(30*time.Second) ||
		healthcheck.Timeout != int64(5*time.Second) ||
		healthcheck.Retries != defaultContainerHealthRetries ||
		healthcheck.StartPeriod != 0 ||
		healthcheck.StartInterval != 0 {
		return fmt.Errorf("docker container %q did not keep expected healthcheck timing", plan.ContainerName)
	}
	return nil
}

func verifyStartedContainerIsolation(ctx context.Context, plan DeploymentPlan) error {
	networkName := expectedTenantNetworkName(plan)
	if networkName == "" {
		return fmt.Errorf("docker container isolation verification missing tenant network")
	}
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{ .HostConfig.Privileged }} {{ .HostConfig.ReadonlyRootfs }} {{ .HostConfig.PidsLimit }} {{ .HostConfig.IpcMode }} {{ .HostConfig.CgroupnsMode }} {{ .HostConfig.UsernsMode }} {{ .HostConfig.PidMode }} {{ .HostConfig.UTSMode }} {{ .HostConfig.RestartPolicy.Name }} {{ .HostConfig.Init }} {{ .HostConfig.StopTimeout }} {{ .HostConfig.AutoRemove }} {{ .HostConfig.PublishAllPorts }} {{ .HostConfig.OomKillDisable }} {{ .HostConfig.NetworkMode }} {{ .Config.User }} {{ range .HostConfig.CapDrop }}{{ . }},{{ end }} {{ range .HostConfig.SecurityOpt }}{{ . }},{{ end }} {{ len .NetworkSettings.Networks }} {{ range $name, $_ := .NetworkSettings.Networks }}{{ $name }},{{ end }} {{ if .HostConfig.PortBindings }}{{ range $port, $bindings := .HostConfig.PortBindings }}{{ $port }}={{ range $binding := $bindings }}{{ if $binding.HostIp }}{{ $binding.HostIp }}{{ else }}*{{ end }}:{{ $binding.HostPort }};{{ end }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.Links }}{{ range .HostConfig.Links }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.ExtraHosts }}{{ range .HostConfig.ExtraHosts }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.Dns }}{{ range .HostConfig.Dns }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.DnsSearch }}{{ range .HostConfig.DnsSearch }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.DnsOptions }}{{ range .HostConfig.DnsOptions }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .Config.Hostname }}{{ .Config.Hostname }}{{ else }}none{{ end }} {{ if .Config.Domainname }}{{ .Config.Domainname }}{{ else }}none{{ end }} {{ if .Config.MacAddress }}{{ .Config.MacAddress }}{{ else }}none{{ end }} {{ if .HostConfig.CapAdd }}{{ range .HostConfig.CapAdd }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.GroupAdd }}{{ range .HostConfig.GroupAdd }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ len .HostConfig.Devices }} {{ len .HostConfig.DeviceRequests }} {{ if .HostConfig.VolumesFrom }}{{ range .HostConfig.VolumesFrom }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.Binds }}{{ range .HostConfig.Binds }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.CgroupParent }}{{ .HostConfig.CgroupParent }}{{ else }}none{{ end }} {{ len .HostConfig.Sysctls }} {{ if .HostConfig.Runtime }}{{ .HostConfig.Runtime }}{{ else }}none{{ end }} {{ if .HostConfig.Isolation }}{{ .HostConfig.Isolation }}{{ else }}none{{ end }} {{ .HostConfig.OomScoreAdj }} {{ len .HostConfig.Ulimits }} {{ if .Config.StopSignal }}{{ .Config.StopSignal }}{{ else }}none{{ end }} {{ if .HostConfig.MaskedPaths }}{{ range .HostConfig.MaskedPaths }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.ReadonlyPaths }}{{ range .HostConfig.ReadonlyPaths }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ len .HostConfig.DeviceCgroupRules }} {{ .Config.NetworkDisabled }} {{ if .HostConfig.VolumeDriver }}{{ .HostConfig.VolumeDriver }}{{ else }}none{{ end }} {{ if .HostConfig.InitPath }}{{ .HostConfig.InitPath }}{{ else }}none{{ end }}`,
		plan.ContainerName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container isolation inspect failed: %w: %s", err, string(output))
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 45 {
		return fmt.Errorf("docker container %q isolation inspect returned incomplete data", plan.ContainerName)
	}
	if fields[0] != "false" {
		return fmt.Errorf("docker container %q started privileged", plan.ContainerName)
	}
	if fields[1] != "true" {
		return fmt.Errorf("docker container %q did not keep read-only root filesystem", plan.ContainerName)
	}
	if fields[2] != strconv.Itoa(defaultContainerPidsLimit) {
		return fmt.Errorf("docker container %q did not keep expected pids limit", plan.ContainerName)
	}
	if fields[3] != "none" || fields[4] != "private" {
		return fmt.Errorf("docker container %q did not keep private IPC/cgroup namespace isolation", plan.ContainerName)
	}
	if fields[5] != defaultContainerUsernsMode {
		return fmt.Errorf("docker container %q did not keep private user namespace isolation", plan.ContainerName)
	}
	if fields[6] != defaultContainerPidMode || fields[7] != defaultContainerUTSMode {
		return fmt.Errorf("docker container %q did not keep private PID/UTS namespace isolation", plan.ContainerName)
	}
	if fields[8] != "no" {
		return fmt.Errorf("docker container %q did not keep restart policy disabled", plan.ContainerName)
	}
	if fields[9] != "true" {
		return fmt.Errorf("docker container %q did not keep init process enabled", plan.ContainerName)
	}
	if fields[10] != strconv.Itoa(defaultContainerStopTimeoutSeconds) {
		return fmt.Errorf("docker container %q did not keep expected stop timeout", plan.ContainerName)
	}
	if fields[11] != "false" {
		return fmt.Errorf("docker container %q did not keep automatic removal disabled", plan.ContainerName)
	}
	if fields[12] != "false" {
		return fmt.Errorf("docker container %q did not keep publish-all-ports disabled", plan.ContainerName)
	}
	if fields[13] != "false" {
		return fmt.Errorf("docker container %q did not keep OOM killing enabled", plan.ContainerName)
	}
	if fields[14] != networkName {
		return fmt.Errorf("docker container %q attached to unexpected network %q", plan.ContainerName, fields[14])
	}
	networkCount, err := strconv.Atoi(fields[18])
	if err != nil || networkCount != 1 {
		return fmt.Errorf("docker container %q has unexpected network attachment count", plan.ContainerName)
	}
	attachedNetworks := strings.Split(fields[19], ",")
	if !containsNetworkName(attachedNetworks, networkName) {
		return fmt.Errorf("docker container %q is missing expected tenant network attachment", plan.ContainerName)
	}
	if !containerPortBindingsMatch(plan.Ports, fields[20]) {
		return fmt.Errorf("docker container %q did not keep expected port bindings", plan.ContainerName)
	}
	if fields[21] != "none" {
		return fmt.Errorf("docker container %q has unexpected Docker links", plan.ContainerName)
	}
	if fields[22] != "none" {
		return fmt.Errorf("docker container %q has unexpected extra host aliases", plan.ContainerName)
	}
	if fields[23] != "none" || fields[24] != "none" || fields[25] != "none" {
		return fmt.Errorf("docker container %q has unexpected DNS overrides", plan.ContainerName)
	}
	if fields[27] != "none" {
		return fmt.Errorf("docker container %q has unexpected domainname override", plan.ContainerName)
	}
	if fields[28] != "none" {
		return fmt.Errorf("docker container %q has unexpected MAC address override", plan.ContainerName)
	}
	if fields[29] != "none" {
		return fmt.Errorf("docker container %q has unexpected added capabilities", plan.ContainerName)
	}
	if fields[30] != "none" {
		return fmt.Errorf("docker container %q has unexpected supplemental groups", plan.ContainerName)
	}
	if fields[31] != "0" || fields[32] != "0" {
		return fmt.Errorf("docker container %q has unexpected host device access", plan.ContainerName)
	}
	if fields[44] != "0" {
		return fmt.Errorf("docker container %q has unexpected device cgroup rules", plan.ContainerName)
	}
	if len(fields) > 45 && fields[45] != "false" {
		return fmt.Errorf("docker container %q has networking disabled outside the signed tenant network contract", plan.ContainerName)
	}
	if len(fields) > 46 && fields[46] != "none" {
		return fmt.Errorf("docker container %q has unexpected volume driver", plan.ContainerName)
	}
	if len(fields) > 47 && fields[47] != "none" {
		return fmt.Errorf("docker container %q has unexpected init path", plan.ContainerName)
	}
	if fields[33] != "none" || fields[34] != "none" {
		return fmt.Errorf("docker container %q has unexpected inherited host mounts", plan.ContainerName)
	}
	if fields[35] != "none" {
		return fmt.Errorf("docker container %q has unexpected cgroup parent", plan.ContainerName)
	}
	if fields[36] != "0" {
		return fmt.Errorf("docker container %q has unexpected sysctls", plan.ContainerName)
	}
	if fields[37] != "none" && fields[37] != "runc" {
		return fmt.Errorf("docker container %q has unexpected runtime", plan.ContainerName)
	}
	if fields[38] != "none" {
		return fmt.Errorf("docker container %q has unexpected isolation mode", plan.ContainerName)
	}
	if fields[39] != strconv.Itoa(defaultContainerOomScoreAdj) {
		return fmt.Errorf("docker container %q has unexpected OOM score adjustment", plan.ContainerName)
	}
	if fields[40] != "0" {
		return fmt.Errorf("docker container %q has unexpected ulimits", plan.ContainerName)
	}
	if fields[41] != defaultContainerStopSignal {
		return fmt.Errorf("docker container %q did not keep expected stop signal", plan.ContainerName)
	}
	if !commaListContainsAll(fields[42], requiredDockerMaskedPaths) {
		return fmt.Errorf("docker container %q lost Docker masked kernel path protections", plan.ContainerName)
	}
	if !commaListContainsAll(fields[43], requiredDockerReadonlyPaths) {
		return fmt.Errorf("docker container %q lost Docker read-only kernel path protections", plan.ContainerName)
	}
	if fields[15] != defaultContainerUser {
		return fmt.Errorf("docker container %q did not keep expected non-root user", plan.ContainerName)
	}
	capDrops := strings.Split(fields[16], ",")
	if !exactDroppedCapabilities(capDrops) {
		return fmt.Errorf("docker container %q did not keep exact drop-all capability policy", plan.ContainerName)
	}
	securityOpts := strings.Split(fields[17], ",")
	expectedSecurityOpts := []string{
		"no-new-privileges=true",
		"seccomp=" + plan.SeccompProfile,
		"apparmor=" + plan.AppArmorProfile,
	}
	if !exactSecurityOptions(securityOpts, expectedSecurityOpts) {
		return fmt.Errorf("docker container %q did not keep exact security options", plan.ContainerName)
	}
	return nil
}

func dockerGeneratedHostname(containerID string, hostname string) bool {
	containerID = strings.TrimSpace(containerID)
	hostname = strings.TrimSpace(hostname)
	if containerID == "" || hostname == "" {
		return false
	}
	return len(hostname) >= 12 && strings.HasPrefix(containerID, hostname)
}

func commaListContainsAll(actual string, required []string) bool {
	values := map[string]struct{}{}
	for _, value := range strings.Split(actual, ",") {
		value = strings.TrimSpace(value)
		if value != "" && value != "none" {
			values[value] = struct{}{}
		}
	}
	for _, value := range required {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}

func containerPortBindingsMatch(ports []PortPlan, actual string) bool {
	if len(ports) == 0 {
		return strings.TrimSpace(actual) == "none"
	}
	expected := make([]string, 0, len(ports))
	for _, port := range ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		expected = append(expected, fmt.Sprintf("%d/%s=%d;", port.ContainerPort, protocol, port.HostPort))
	}
	sort.Strings(expected)
	actualBindings := strings.Split(strings.TrimSpace(actual), ",")
	normalizedActual := make([]string, 0, len(actualBindings))
	for _, binding := range actualBindings {
		binding = strings.TrimSpace(binding)
		if binding == "" {
			continue
		}
		normalized, ok := normalizePortBinding(binding)
		if !ok {
			return false
		}
		normalizedActual = append(normalizedActual, normalized)
	}
	sort.Strings(normalizedActual)
	return slices.Equal(expected, normalizedActual)
}

func normalizePortBinding(binding string) (string, bool) {
	portSpec, hostSpec, ok := strings.Cut(binding, "=")
	if !ok || portSpec == "" || hostSpec == "" {
		return "", false
	}
	entries := strings.Split(hostSpec, ";")
	normalizedEntries := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		hostPort := entry
		if separator := strings.LastIndex(entry, ":"); separator >= 0 {
			hostIP := entry[:separator]
			port := entry[separator+1:]
			if !wildcardHostIP(hostIP) {
				return "", false
			}
			hostPort = port
		}
		if hostPort == "" {
			return "", false
		}
		normalizedEntries = append(normalizedEntries, hostPort)
	}
	if len(normalizedEntries) == 0 {
		return "", false
	}
	sort.Strings(normalizedEntries)
	return portSpec + "=" + strings.Join(normalizedEntries, ";") + ";", true
}

func wildcardHostIP(hostIP string) bool {
	hostIP = strings.TrimSpace(hostIP)
	return hostIP == "" || hostIP == "*" || hostIP == "0.0.0.0" || hostIP == "::"
}

func containsNetworkName(networks []string, target string) bool {
	for _, network := range networks {
		if strings.TrimSpace(network) == target {
			return true
		}
	}
	return false
}

func exactDroppedCapabilities(capabilities []string) bool {
	filtered := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		capability = strings.TrimSpace(capability)
		if capability == "" {
			continue
		}
		filtered = append(filtered, capability)
	}
	return len(filtered) == 1 && filtered[0] == "ALL"
}

func exactSecurityOptions(options []string, expected []string) bool {
	actualSet := map[string]bool{}
	for _, option := range options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		actualSet[option] = true
	}
	if len(actualSet) != len(expected) {
		return false
	}
	for _, option := range expected {
		if !actualSet[option] {
			return false
		}
	}
	return true
}

type dockerMountInspect struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
	Propagation string `json:"Propagation"`
}

func verifyStartedContainerMounts(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{json .Mounts}}", plan.ContainerName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container mount inspect failed: %w: %s", err, string(output))
	}
	var mounts []dockerMountInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &mounts); err != nil {
		return fmt.Errorf("docker container %q mount inspect returned invalid data", plan.ContainerName)
	}
	expectedByTarget := map[string]MountPlan{}
	for _, mount := range plan.Mounts {
		expectedByTarget[mount.Target] = mount
	}
	seenTargets := map[string]bool{}
	expectedTmpfsTargets := map[string]bool{"/tmp": false, "/run": false}
	for _, mount := range mounts {
		if mount.Type == "tmpfs" {
			if _, ok := expectedTmpfsTargets[mount.Destination]; !ok {
				return fmt.Errorf("docker container %q has unexpected tmpfs mount target %q", plan.ContainerName, mount.Destination)
			}
			if !mount.RW {
				return fmt.Errorf("docker container %q did not keep expected tmpfs mount %q writable", plan.ContainerName, mount.Destination)
			}
			expectedTmpfsTargets[mount.Destination] = true
			continue
		}
		if mount.Type != "bind" {
			return fmt.Errorf("docker container %q has unexpected mount type %q at %q", plan.ContainerName, mount.Type, mount.Destination)
		}
		expected, ok := expectedByTarget[mount.Destination]
		if !ok {
			return fmt.Errorf("docker container %q has unexpected mount target %q", plan.ContainerName, mount.Destination)
		}
		if seenTargets[mount.Destination] {
			return fmt.Errorf("docker container %q has duplicate mount target %q", plan.ContainerName, mount.Destination)
		}
		if filepath.Clean(mount.Source) != expected.Source || mount.RW == expected.ReadOnly || mount.Propagation != "rprivate" {
			return fmt.Errorf("docker container %q did not keep expected bind mount policy", plan.ContainerName)
		}
		seenTargets[mount.Destination] = true
	}
	if len(seenTargets) != len(expectedByTarget) {
		return fmt.Errorf("docker container %q has unexpected mount count", plan.ContainerName)
	}
	for target, seen := range expectedTmpfsTargets {
		if !seen {
			return fmt.Errorf("docker container %q did not keep expected tmpfs mount %q", plan.ContainerName, target)
		}
	}
	if err := verifyStartedContainerTmpfsConfig(ctx, plan); err != nil {
		return err
	}
	return nil
}

func verifyStartedContainerTmpfsConfig(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{json .HostConfig.Tmpfs}}", plan.ContainerName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container tmpfs config inspect failed: %w: %s", err, string(output))
	}
	var tmpfs map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &tmpfs); err != nil {
		return fmt.Errorf("docker container %q tmpfs config inspect returned invalid data", plan.ContainerName)
	}
	expected := map[string]string{
		"/tmp": "rw,noexec,nosuid,nodev,size=" + defaultContainerTmpfsSize,
		"/run": "rw,nosuid,nodev,size=16m",
	}
	if len(tmpfs) != len(expected) {
		return fmt.Errorf("docker container %q did not keep expected tmpfs config", plan.ContainerName)
	}
	for target, options := range expected {
		if tmpfs[target] != options {
			return fmt.Errorf("docker container %q did not keep expected tmpfs config for %q", plan.ContainerName, target)
		}
	}
	return nil
}

func verifyStartedContainerResources(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{ .HostConfig.NanoCpus }} {{ .HostConfig.Memory }} {{ .HostConfig.MemorySwap }} {{ if .HostConfig.MemorySwappiness }}{{ .HostConfig.MemorySwappiness }}{{ else }}0{{ end }} {{ index .HostConfig.StorageOpt "size" }} {{ .HostConfig.ShmSize }} {{ .HostConfig.LogConfig.Type }} {{ index .HostConfig.LogConfig.Config "max-size" }} {{ index .HostConfig.LogConfig.Config "max-file" }} {{ index .HostConfig.LogConfig.Config "mode" }} {{ index .HostConfig.LogConfig.Config "max-buffer-size" }} {{ .HostConfig.MemoryReservation }} {{ .HostConfig.CpuShares }} {{ .HostConfig.CpuQuota }} {{ .HostConfig.CpuPeriod }} {{ if .HostConfig.CpusetCpus }}{{ .HostConfig.CpusetCpus }}{{ else }}none{{ end }} {{ if .HostConfig.CpusetMems }}{{ .HostConfig.CpusetMems }}{{ else }}none{{ end }} {{ .HostConfig.BlkioWeight }} {{ len .HostConfig.BlkioWeightDevice }} {{ len .HostConfig.BlkioDeviceReadBps }} {{ len .HostConfig.BlkioDeviceWriteBps }} {{ len .HostConfig.BlkioDeviceReadIOps }} {{ len .HostConfig.BlkioDeviceWriteIOps }} {{ .HostConfig.CpuRealtimeRuntime }} {{ .HostConfig.CpuRealtimePeriod }}`,
		plan.ContainerName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container resource inspect failed: %w: %s", err, string(output))
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 25 {
		return fmt.Errorf("docker container %q resource inspect returned incomplete data", plan.ContainerName)
	}
	expectedNanoCpus := int64(math.Round(plan.Resources.CPUCores * 1_000_000_000))
	nanoCpus, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || nanoCpus != expectedNanoCpus {
		return fmt.Errorf("docker container %q did not keep expected CPU limit", plan.ContainerName)
	}
	expectedMemoryBytes := int64(plan.Resources.MemoryMB) * 1024 * 1024
	memoryBytes, memoryErr := strconv.ParseInt(fields[1], 10, 64)
	swapBytes, swapErr := strconv.ParseInt(fields[2], 10, 64)
	if memoryErr != nil || swapErr != nil || memoryBytes != expectedMemoryBytes || swapBytes != expectedMemoryBytes {
		return fmt.Errorf("docker container %q did not keep expected memory limits", plan.ContainerName)
	}
	if fields[3] != strconv.Itoa(defaultContainerMemorySwappiness) {
		return fmt.Errorf("docker container %q has unexpected memory swappiness", plan.ContainerName)
	}
	expectedDiskLimit := strconv.Itoa(plan.Resources.DiskGB) + "g"
	if fields[4] != expectedDiskLimit {
		return fmt.Errorf("docker container %q did not keep expected writable layer size", plan.ContainerName)
	}
	shmBytes, shmErr := strconv.ParseInt(fields[5], 10, 64)
	if shmErr != nil || shmBytes != defaultContainerShmBytes {
		return fmt.Errorf("docker container %q did not keep expected shared memory size", plan.ContainerName)
	}
	if fields[6] != "json-file" || fields[7] != defaultContainerLogMaxSize || fields[8] != defaultContainerLogMaxFile || fields[9] != defaultContainerLogMode || fields[10] != defaultContainerLogMaxBufferSize {
		return fmt.Errorf("docker container %q did not keep expected log rotation settings", plan.ContainerName)
	}
	if fields[11] != "0" {
		return fmt.Errorf("docker container %q has unexpected memory reservation", plan.ContainerName)
	}
	if fields[12] != "0" || fields[13] != "0" || fields[14] != "0" {
		return fmt.Errorf("docker container %q has unexpected CPU scheduler overrides", plan.ContainerName)
	}
	if fields[15] != "none" || fields[16] != "none" {
		return fmt.Errorf("docker container %q has unexpected CPU set restrictions", plan.ContainerName)
	}
	for _, field := range fields[17:23] {
		if field != "0" {
			return fmt.Errorf("docker container %q has unexpected block I/O scheduler overrides", plan.ContainerName)
		}
	}
	if fields[23] != "0" || fields[24] != "0" {
		return fmt.Errorf("docker container %q has unexpected realtime CPU scheduler overrides", plan.ContainerName)
	}
	return nil
}

func expectedTenantNetworkName(plan DeploymentPlan) string {
	if len(plan.NetworkInspect.Args) == 0 {
		return ""
	}
	return plan.NetworkInspect.Args[len(plan.NetworkInspect.Args)-1]
}

func ensureTenantNetwork(ctx context.Context, plan DeploymentPlan) error {
	if plan.TenantID == "" || plan.NetworkInspect.Name == "" || len(plan.NetworkInspect.Args) == 0 {
		return fmt.Errorf("docker network ownership inspect missing plan context")
	}
	inspect := exec.CommandContext(ctx, plan.NetworkInspect.Name, plan.NetworkInspect.Args...)
	if err := inspect.Run(); err != nil {
		create := exec.CommandContext(ctx, plan.NetworkCreate.Name, plan.NetworkCreate.Args...)
		if output, createErr := create.CombinedOutput(); createErr != nil {
			return fmt.Errorf("docker network create failed: %w: %s", createErr, string(output))
		}
		return verifyTenantNetworkOwnership(ctx, plan)
	}
	return verifyTenantNetworkOwnership(ctx, plan)
}

func verifyTenantNetworkOwnership(ctx context.Context, plan DeploymentPlan) error {
	networkName := plan.NetworkInspect.Args[len(plan.NetworkInspect.Args)-1]
	labelInspect := exec.CommandContext(
		ctx,
		plan.NetworkInspect.Name,
		"network",
		"inspect",
		"-f",
		`{{ index .Labels "luma.managed" }} {{ index .Labels "luma.tenant" }} {{ index .Options "com.docker.network.bridge.enable_icc" }}`,
		networkName,
	)
	output, err := labelInspect.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker network ownership inspect failed: %w: %s", err, string(output))
	}
	ownership := strings.Fields(strings.TrimSpace(string(output)))
	if len(ownership) < 2 || ownership[0] != "true" || ownership[1] != plan.TenantID {
		return fmt.Errorf("docker network use refused for unmanaged tenant network %q", networkName)
	}
	if len(ownership) < 3 || ownership[2] != "false" {
		return fmt.Errorf("docker network use refused for tenant network %q with inter-container communication enabled", networkName)
	}
	return nil
}

func runIdempotentCommand(ctx context.Context, command CommandPlan) error {
	if command.SkipIfRuleComment != "" && nftRuleCommentExists(ctx, command.SkipIfRuleComment) {
		return nil
	}
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	outputText := string(output)
	if strings.Contains(outputText, "File exists") || strings.Contains(outputText, "already exists") {
		return nil
	}
	return fmt.Errorf("%s failed: %w: %s", command.Name, err, outputText)
}

func desiredFirewallComments(commands []CommandPlan) map[string]struct{} {
	desired := map[string]struct{}{}
	for _, command := range commands {
		if command.SkipIfRuleComment != "" {
			desired[command.SkipIfRuleComment] = struct{}{}
		}
	}
	return desired
}

type nftManagedRule struct {
	Comment string
	Handle  string
}

func staleDeploymentFirewallRules(nftOutput string, deploymentID string, desired map[string]struct{}) []nftManagedRule {
	prefix := "luma:" + deploymentID + ":"
	var stale []nftManagedRule
	for _, line := range strings.Split(nftOutput, "\n") {
		rule, ok := parseNftManagedRule(line)
		if !ok || !strings.HasPrefix(rule.Comment, prefix) {
			continue
		}
		if _, keep := desired[rule.Comment]; !keep {
			stale = append(stale, rule)
		}
	}
	return stale
}

func parseNftManagedRule(line string) (nftManagedRule, bool) {
	commentStart := strings.Index(line, `comment "luma:`)
	if commentStart < 0 {
		return nftManagedRule{}, false
	}
	commentValueStart := commentStart + len(`comment "`)
	commentValueEnd := strings.Index(line[commentValueStart:], `"`)
	if commentValueEnd < 0 {
		return nftManagedRule{}, false
	}
	comment := line[commentValueStart : commentValueStart+commentValueEnd]
	handleStart := strings.Index(line, "# handle ")
	if handleStart < 0 {
		return nftManagedRule{}, false
	}
	handleFields := strings.Fields(line[handleStart+len("# handle "):])
	if len(handleFields) == 0 {
		return nftManagedRule{}, false
	}
	handle := handleFields[0]
	for _, r := range handle {
		if r < '0' || r > '9' {
			return nftManagedRule{}, false
		}
	}
	return nftManagedRule{Comment: comment, Handle: handle}, true
}

func reconcileDeploymentFirewall(ctx context.Context, deploymentID string, desired map[string]struct{}) error {
	if deploymentID == "" {
		return nil
	}
	list := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", "lumapanel", "input")
	output, err := list.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft firewall reconcile list failed: %w: %s", err, string(output))
	}
	for _, rule := range staleDeploymentFirewallRules(string(output), deploymentID, desired) {
		cmd := exec.CommandContext(ctx, "nft", "delete", "rule", "inet", "lumapanel", "input", "handle", rule.Handle)
		deleteOutput, deleteErr := cmd.CombinedOutput()
		if deleteErr != nil {
			return fmt.Errorf("nft firewall reconcile delete failed: %w: %s", deleteErr, string(deleteOutput))
		}
	}
	return nil
}

func cleanupDeploymentFirewall(ctx context.Context, deploymentID string) error {
	if deploymentID == "" {
		return nil
	}
	if err := deleteManagedFirewallRulesByPrefix(ctx, "input", "luma:"+deploymentID+":"); err != nil {
		return err
	}
	if err := deleteManagedFirewallRulesByPrefix(ctx, "forward", "luma:"+deploymentID+":egress:"); err != nil {
		return err
	}
	return nil
}

func deleteManagedFirewallRulesByPrefix(ctx context.Context, chain string, prefix string) error {
	list := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", "lumapanel", chain)
	output, err := list.CombinedOutput()
	if err != nil {
		if nftObjectMissing(string(output)) {
			return nil
		}
		return fmt.Errorf("nft firewall reconcile list failed: %w: %s", err, string(output))
	}
	for _, line := range strings.Split(string(output), "\n") {
		rule, ok := parseNftManagedRule(line)
		if !ok || !strings.HasPrefix(rule.Comment, prefix) {
			continue
		}
		cmd := exec.CommandContext(ctx, "nft", "delete", "rule", "inet", "lumapanel", chain, "handle", rule.Handle)
		deleteOutput, deleteErr := cmd.CombinedOutput()
		if deleteErr != nil {
			return fmt.Errorf("nft firewall reconcile delete failed: %w: %s", deleteErr, string(deleteOutput))
		}
	}
	return nil
}

func nftObjectMissing(output string) bool {
	return strings.Contains(output, "No such file or directory") ||
		strings.Contains(output, "No such chain") ||
		strings.Contains(output, "No such table") ||
		strings.Contains(output, "No such object")
}

func enforceContainerEgress(ctx context.Context, plan DeploymentPlan) error {
	if plan.DeploymentID != "" {
		if err := deleteManagedFirewallRulesByPrefix(ctx, "forward", "luma:"+plan.DeploymentID+":egress:"); err != nil {
			return err
		}
	}
	if plan.Egress.Mode == "" || plan.Egress.Mode == "allow-all" {
		return verifyDeploymentEgressFirewall(ctx, plan.DeploymentID, map[string]struct{}{})
	}
	inspect := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		plan.ContainerName,
	)
	output, err := inspect.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker inspect for egress policy failed: %w: %s", err, string(output))
	}
	containerIP := strings.TrimSpace(string(output))
	if containerIP == "" {
		return fmt.Errorf("docker inspect returned empty container IP for egress policy")
	}
	var job DeployJob
	job.DeploymentID = plan.DeploymentID
	job.Egress = plan.Egress
	commands, err := egressFirewallCommands(job, containerIP)
	if err != nil {
		return err
	}
	bootstrapCount := 3
	if len(commands) < bootstrapCount {
		bootstrapCount = len(commands)
	}
	for _, command := range commands[:bootstrapCount] {
		if err := runIdempotentCommand(ctx, command); err != nil {
			return err
		}
	}
	for _, command := range commands[bootstrapCount:] {
		if err := runIdempotentCommand(ctx, command); err != nil {
			return err
		}
	}
	if err := verifyDeploymentEgressFirewall(ctx, plan.DeploymentID, desiredFirewallComments(commands[bootstrapCount:])); err != nil {
		return err
	}
	return nil
}

func verifyDeploymentEgressFirewall(ctx context.Context, deploymentID string, desired map[string]struct{}) error {
	if deploymentID == "" {
		return nil
	}
	list := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", "lumapanel", "forward")
	output, err := list.CombinedOutput()
	if err != nil {
		if len(desired) == 0 && nftObjectMissing(string(output)) {
			return nil
		}
		return fmt.Errorf("nft egress verification list failed: %w: %s", err, string(output))
	}
	seen := map[string]struct{}{}
	prefix := "luma:" + deploymentID + ":egress:"
	for _, line := range strings.Split(string(output), "\n") {
		rule, ok := parseNftManagedRule(line)
		if !ok || !strings.HasPrefix(rule.Comment, prefix) {
			continue
		}
		if _, keep := desired[rule.Comment]; !keep {
			return fmt.Errorf("nft egress verification found unexpected deployment rule %q", rule.Comment)
		}
		seen[rule.Comment] = struct{}{}
	}
	for comment := range desired {
		if _, ok := seen[comment]; !ok {
			return fmt.Errorf("nft egress verification missing deployment rule %q", comment)
		}
	}
	return nil
}

func removeExistingContainer(ctx context.Context, plan DeploymentPlan) error {
	command := plan.ContainerRemove
	if command.Name == "" || len(command.Args) == 0 {
		return nil
	}
	containerName := command.Args[len(command.Args)-1]
	inspect := exec.CommandContext(
		ctx,
		command.Name,
		"inspect",
		"-f",
		`{{ index .Config.Labels "luma.managed" }} {{ index .Config.Labels "luma.deployment" }} {{ index .Config.Labels "luma.tenant" }} {{ index .Config.Labels "luma.node" }}`,
		containerName,
	)
	inspectOutput, inspectErr := inspect.CombinedOutput()
	if inspectErr != nil {
		inspectText := string(inspectOutput)
		if strings.Contains(inspectText, "No such container") || strings.Contains(inspectText, "No such object") {
			return nil
		}
		return fmt.Errorf("docker container ownership inspect failed: %w: %s", inspectErr, inspectText)
	}
	ownership := strings.Fields(strings.TrimSpace(string(inspectOutput)))
	if len(ownership) < 4 || ownership[0] != "true" || ownership[1] != plan.DeploymentID || ownership[2] != plan.TenantID || ownership[3] != plan.NodeID {
		return fmt.Errorf("docker container replace refused for unmanaged container %q", containerName)
	}
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	outputText := string(output)
	if strings.Contains(outputText, "No such container") || strings.Contains(outputText, "No such object") {
		return nil
	}
	return fmt.Errorf("docker container replace failed: %w: %s", err, outputText)
}

func nftRuleCommentExists(ctx context.Context, comment string) bool {
	cmd := exec.CommandContext(ctx, "nft", "list", "chain", "inet", "lumapanel", "input")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), strconv.Quote(comment))
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
