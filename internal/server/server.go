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
			status.Errors["dockerRootDir"] = "docker root directory must not be world-writable"
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
	status.Ready = status.Docker && status.DockerCgroupV2 && status.DockerCgroupDriverSystemd && status.DockerDebugDisabled && status.DockerExperimentalDisabled && status.DockerSwarmInactive && status.DockerOomKillEnabled && status.DockerIPv4Forwarding && status.DockerBridgeNfIptables && status.DockerBridgeNfIp6tables && status.DockerSeccomp && status.DockerAppArmor && status.DockerUserNamespace && status.DockerLiveRestore && status.DockerRootDirProtected && status.DockerStorageOverlay2 && status.DockerStorageDType && status.DockerServerVersionSupported && status.DockerOSTypeLinux && status.DockerLocalEndpoint && status.DockerSocketProtected && status.Nftables && status.NftablesUsable && status.CgroupV2 && status.CgroupControllersReady
	if len(status.Errors) == 0 {
		status.Errors = nil
	}
	return status
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
	info, err := os.Stat(socketPath)
	if err != nil {
		return false, fmt.Errorf("docker unix socket stat failed: %w", err)
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
	info, err := os.Stat(rootDir)
	if err != nil {
		return false, fmt.Errorf("docker root directory stat failed: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("docker root directory %q is not a directory", rootDir)
	}
	return info.Mode().Perm()&0o002 == 0, nil
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
			continue
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
		if pathWithinRoot(restrictedRoot, current) && info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("deployment directory %q uses world-writable tenant path component %q", directory, current)
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
	if plan.Healthcheck == "" {
		return nil
	}
	return waitForStartedContainerHealthy(ctx, plan)
}

type startedContainerState struct {
	Running      bool
	Health       string
	Managed      bool
	DeploymentID string
	TenantID     string
	NodeID       string
}

func inspectStartedContainerState(ctx context.Context, containerName string) (startedContainerState, error) {
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{ .State.Running }} {{ if .State.Health }}{{ .State.Health.Status }}{{ else }}none{{ end }} {{ index .Config.Labels "luma.managed" }} {{ index .Config.Labels "luma.deployment" }} {{ index .Config.Labels "luma.tenant" }} {{ index .Config.Labels "luma.node" }}`,
		containerName,
	).CombinedOutput()
	if err != nil {
		return startedContainerState{}, fmt.Errorf("docker container state inspect failed: %w: %s", err, string(output))
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 6 {
		return startedContainerState{}, fmt.Errorf("docker container %q state inspect returned incomplete data", containerName)
	}
	return startedContainerState{
		Running:      fields[0] == "true",
		Health:       fields[1],
		Managed:      fields[2] == "true",
		DeploymentID: fields[3],
		TenantID:     fields[4],
		NodeID:       fields[5],
	}, nil
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
	if plan.ImageDigest == "" {
		return nil
	}
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
		return fmt.Errorf("docker container %q did not keep expected digest-pinned image", plan.ContainerName)
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
		`{{ .HostConfig.Privileged }} {{ .HostConfig.ReadonlyRootfs }} {{ .HostConfig.PidsLimit }} {{ .HostConfig.IpcMode }} {{ .HostConfig.CgroupnsMode }} {{ .HostConfig.UsernsMode }} {{ .HostConfig.PidMode }} {{ .HostConfig.UTSMode }} {{ .HostConfig.RestartPolicy.Name }} {{ .HostConfig.Init }} {{ .HostConfig.StopTimeout }} {{ .HostConfig.AutoRemove }} {{ .HostConfig.PublishAllPorts }} {{ .HostConfig.OomKillDisable }} {{ .HostConfig.NetworkMode }} {{ .Config.User }} {{ range .HostConfig.CapDrop }}{{ . }},{{ end }} {{ range .HostConfig.SecurityOpt }}{{ . }},{{ end }} {{ len .NetworkSettings.Networks }} {{ range $name, $_ := .NetworkSettings.Networks }}{{ $name }},{{ end }} {{ if .HostConfig.PortBindings }}{{ range $port, $bindings := .HostConfig.PortBindings }}{{ $port }}={{ range $binding := $bindings }}{{ $binding.HostPort }};{{ end }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.Links }}{{ range .HostConfig.Links }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.ExtraHosts }}{{ range .HostConfig.ExtraHosts }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.Dns }}{{ range .HostConfig.Dns }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.DnsSearch }}{{ range .HostConfig.DnsSearch }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.DnsOptions }}{{ range .HostConfig.DnsOptions }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .Config.Hostname }}{{ .Config.Hostname }}{{ else }}none{{ end }} {{ if .Config.Domainname }}{{ .Config.Domainname }}{{ else }}none{{ end }} {{ if .Config.MacAddress }}{{ .Config.MacAddress }}{{ else }}none{{ end }} {{ if .HostConfig.CapAdd }}{{ range .HostConfig.CapAdd }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.GroupAdd }}{{ range .HostConfig.GroupAdd }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ len .HostConfig.Devices }} {{ len .HostConfig.DeviceRequests }} {{ if .HostConfig.VolumesFrom }}{{ range .HostConfig.VolumesFrom }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.Binds }}{{ range .HostConfig.Binds }}{{ . }},{{ end }}{{ else }}none{{ end }} {{ if .HostConfig.CgroupParent }}{{ .HostConfig.CgroupParent }}{{ else }}none{{ end }} {{ len .HostConfig.Sysctls }} {{ if .HostConfig.Runtime }}{{ .HostConfig.Runtime }}{{ else }}none{{ end }} {{ if .HostConfig.Isolation }}{{ .HostConfig.Isolation }}{{ else }}none{{ end }} {{ .HostConfig.OomScoreAdj }} {{ len .HostConfig.Ulimits }}`,
		plan.ContainerName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container isolation inspect failed: %w: %s", err, string(output))
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 41 {
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
	if fields[26] != "none" || fields[27] != "none" {
		return fmt.Errorf("docker container %q has unexpected hostname overrides", plan.ContainerName)
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
		normalizedActual = append(normalizedActual, binding)
	}
	sort.Strings(normalizedActual)
	return slices.Equal(expected, normalizedActual)
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
			if _, ok := expectedTmpfsTargets[mount.Destination]; ok && mount.RW {
				expectedTmpfsTargets[mount.Destination] = true
			}
			continue
		}
		if mount.Type != "bind" {
			continue
		}
		expected, ok := expectedByTarget[mount.Destination]
		if !ok {
			return fmt.Errorf("docker container %q has unexpected mount target %q", plan.ContainerName, mount.Destination)
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
	return nil
}

func verifyStartedContainerResources(ctx context.Context, plan DeploymentPlan) error {
	output, err := exec.CommandContext(
		ctx,
		"docker",
		"inspect",
		"-f",
		`{{ .HostConfig.NanoCpus }} {{ .HostConfig.Memory }} {{ .HostConfig.MemorySwap }} {{ index .HostConfig.StorageOpt "size" }} {{ .HostConfig.ShmSize }} {{ .HostConfig.LogConfig.Type }} {{ index .HostConfig.LogConfig.Config "max-size" }} {{ index .HostConfig.LogConfig.Config "max-file" }} {{ .HostConfig.MemoryReservation }} {{ .HostConfig.CpuShares }} {{ .HostConfig.CpuQuota }} {{ .HostConfig.CpuPeriod }} {{ if .HostConfig.CpusetCpus }}{{ .HostConfig.CpusetCpus }}{{ else }}none{{ end }} {{ if .HostConfig.CpusetMems }}{{ .HostConfig.CpusetMems }}{{ else }}none{{ end }}`,
		plan.ContainerName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container resource inspect failed: %w: %s", err, string(output))
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 14 {
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
	expectedDiskLimit := strconv.Itoa(plan.Resources.DiskGB) + "g"
	if fields[3] != expectedDiskLimit {
		return fmt.Errorf("docker container %q did not keep expected writable layer size", plan.ContainerName)
	}
	shmBytes, shmErr := strconv.ParseInt(fields[4], 10, 64)
	if shmErr != nil || shmBytes != defaultContainerShmBytes {
		return fmt.Errorf("docker container %q did not keep expected shared memory size", plan.ContainerName)
	}
	if fields[5] != "json-file" || fields[6] != defaultContainerLogMaxSize || fields[7] != defaultContainerLogMaxFile {
		return fmt.Errorf("docker container %q did not keep expected log rotation settings", plan.ContainerName)
	}
	if fields[8] != "0" {
		return fmt.Errorf("docker container %q has unexpected memory reservation", plan.ContainerName)
	}
	if fields[9] != "0" || fields[10] != "0" || fields[11] != "0" {
		return fmt.Errorf("docker container %q has unexpected CPU scheduler overrides", plan.ContainerName)
	}
	if fields[12] != "none" || fields[13] != "none" {
		return fmt.Errorf("docker container %q has unexpected CPU set restrictions", plan.ContainerName)
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
		return nil
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
