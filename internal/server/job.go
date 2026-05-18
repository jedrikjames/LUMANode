package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultContainerPidsLimit = 512
const defaultContainerUser = "10000:10000"
const defaultContainerStopTimeoutSeconds = 30
const defaultContainerHealthInterval = "30s"
const defaultContainerHealthTimeout = "5s"
const defaultContainerHealthRetries = 3
const defaultContainerTmpfsSize = "64m"
const defaultContainerLogMaxSize = "10m"
const defaultContainerLogMaxFile = "3"
const maxContainerCPUCores = 128
const maxContainerMemoryMB = 1048576
const maxContainerDiskGB = 10240
const maxContainerPortMappings = 256
const maxContainerMounts = 64
const maxContainerEnvVars = 128
const maxContainerEnvValueLength = 4096

type DeployJob struct {
	ID           string            `json:"id"`
	QueueID      string            `json:"queueId,omitempty"`
	DeploymentID string            `json:"deploymentId"`
	TenantID     string            `json:"tenantId"`
	NodeID       string            `json:"nodeId"`
	Image        string            `json:"image"`
	ImageDigest  string            `json:"imageDigest,omitempty"`
	Command      string            `json:"command"`
	Env          map[string]string `json:"env"`
	Resources    struct {
		CPUCores float64 `json:"cpuCores"`
		MemoryMB int     `json:"memoryMb"`
		DiskGB   int     `json:"diskGb"`
	} `json:"resources"`
	Network struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	} `json:"network"`
	Ports []struct {
		HostPort      int    `json:"hostPort"`
		ContainerPort int    `json:"containerPort"`
		Protocol      string `json:"protocol"`
	} `json:"ports"`
	Mounts []struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		ReadOnly bool   `json:"readOnly"`
	} `json:"mounts"`
	Security struct {
		ReadOnlyRootFS      bool     `json:"readOnlyRootFs"`
		NoNewPrivileges     bool     `json:"noNewPrivileges"`
		DroppedCapabilities []string `json:"droppedCapabilities"`
		SeccompProfile      string   `json:"seccompProfile"`
		AppArmorProfile     string   `json:"appArmorProfile"`
	} `json:"security"`
	Egress      EgressPolicy      `json:"egress"`
	Healthcheck string            `json:"healthcheck"`
	Labels      map[string]string `json:"labels"`
}

type EgressPolicyRule struct {
	Protocol        string `json:"protocol"`
	DestinationCIDR string `json:"destinationCidr"`
	Port            int    `json:"port"`
}

type EgressPolicy struct {
	Mode  string             `json:"mode"`
	Rules []EgressPolicyRule `json:"rules"`
}

type signedDeployJob struct {
	Payload   string `json:"payload"`
	Signature struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"keyId"`
		IssuedAt  string `json:"issuedAt"`
		ExpiresAt string `json:"expiresAt"`
		Value     string `json:"value"`
	} `json:"signature"`
}

type CommandPlan struct {
	Name              string   `json:"name"`
	Args              []string `json:"args"`
	SkipIfRuleComment string   `json:"skipIfRuleComment,omitempty"`
}

type DeploymentPlan struct {
	DeploymentID    string        `json:"deploymentId"`
	TenantID        string        `json:"tenantId"`
	NodeID          string        `json:"nodeId"`
	TenantRoot      string        `json:"tenantRoot"`
	ContainerName   string        `json:"containerName"`
	Resources       ResourcePlan  `json:"resources"`
	ImageDigest     string        `json:"imageDigest,omitempty"`
	ResolvedImage   string        `json:"resolvedImage,omitempty"`
	SeccompProfile  string        `json:"seccompProfile"`
	AppArmorProfile string        `json:"appArmorProfile"`
	Egress          EgressPolicy  `json:"egress"`
	Healthcheck     string        `json:"healthcheck,omitempty"`
	Directories     []string      `json:"directories"`
	Mounts          []MountPlan   `json:"mounts"`
	Ports           []PortPlan    `json:"ports"`
	NetworkInspect  CommandPlan   `json:"networkInspect"`
	NetworkCreate   CommandPlan   `json:"networkCreate"`
	Firewall        []CommandPlan `json:"firewall"`
	ContainerRemove CommandPlan   `json:"containerRemove"`
	ContainerRun    CommandPlan   `json:"containerRun"`
	Commands        []CommandPlan `json:"commands"`
}

type ResourcePlan struct {
	CPUCores float64 `json:"cpuCores"`
	MemoryMB int     `json:"memoryMb"`
	DiskGB   int     `json:"diskGb"`
}

type MountPlan struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}

type PortPlan struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

func verifySignedDeployJob(envelope signedDeployJob, secret string, now time.Time) (DeployJob, error) {
	if envelope.Payload == "" || envelope.Signature.Value == "" {
		return DeployJob{}, fmt.Errorf("missing deployment job signature")
	}
	if envelope.Signature.Algorithm != "hmac-sha256" {
		return DeployJob{}, fmt.Errorf("unsupported deployment job signature algorithm")
	}
	expiresAt, err := time.Parse(time.RFC3339, envelope.Signature.ExpiresAt)
	if err != nil {
		return DeployJob{}, fmt.Errorf("invalid deployment job signature expiry")
	}
	if now.After(expiresAt) {
		return DeployJob{}, fmt.Errorf("expired deployment job signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(envelope.Payload))
	expected := mac.Sum(nil)
	actual, err := base64.RawURLEncoding.DecodeString(envelope.Signature.Value)
	if err != nil {
		return DeployJob{}, fmt.Errorf("invalid deployment job signature encoding")
	}
	if !hmac.Equal(actual, expected) {
		return DeployJob{}, fmt.Errorf("invalid deployment job signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return DeployJob{}, fmt.Errorf("invalid deployment job payload encoding")
	}
	var job DeployJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return DeployJob{}, fmt.Errorf("invalid deployment job payload")
	}
	return job, nil
}

func validateDeploymentJob(job DeployJob, nodeID string) error {
	if job.ID == "" || job.DeploymentID == "" || job.TenantID == "" || job.Image == "" {
		return fmt.Errorf("missing required deployment job identity")
	}
	if !validImageReference(job.Image) {
		return fmt.Errorf("deployment job has invalid image reference")
	}
	if job.ImageDigest != "" && !validImageDigest(job.ImageDigest) {
		return fmt.Errorf("deployment job has invalid image digest")
	}
	if !validStartupCommand(job.Command) {
		return fmt.Errorf("deployment job has invalid startup command")
	}
	if !validLumaIdentifier(job.ID) || !validLumaIdentifier(job.DeploymentID) || !validLumaIdentifier(job.TenantID) {
		return fmt.Errorf("deployment job contains invalid identifiers")
	}
	if job.QueueID != "" && !validLumaIdentifier(job.QueueID) {
		return fmt.Errorf("deployment job contains invalid queue identifier")
	}
	if job.NodeID != "" && !validLumaIdentifier(job.NodeID) {
		return fmt.Errorf("deployment job contains invalid identifiers")
	}
	if nodeID != "" && job.NodeID != nodeID {
		return fmt.Errorf("deployment job targets node %q, not this node", job.NodeID)
	}
	if math.IsNaN(job.Resources.CPUCores) || math.IsInf(job.Resources.CPUCores, 0) ||
		job.Resources.CPUCores <= 0 || job.Resources.CPUCores > maxContainerCPUCores ||
		job.Resources.MemoryMB <= 0 || job.Resources.MemoryMB > maxContainerMemoryMB ||
		job.Resources.DiskGB <= 0 || job.Resources.DiskGB > maxContainerDiskGB {
		return fmt.Errorf("deployment job has invalid resource limits")
	}
	if len(job.Ports) > maxContainerPortMappings {
		return fmt.Errorf("deployment job has too many port mappings")
	}
	if job.Network.Mode != "tenant-bridge" || job.Network.Name != "luma-"+job.TenantID {
		return fmt.Errorf("deployment job uses invalid tenant network")
	}
	publishedPorts := map[string]struct{}{}
	for _, port := range job.Ports {
		if port.HostPort <= 0 || port.HostPort > 65535 || port.ContainerPort <= 0 || port.ContainerPort > 65535 {
			return fmt.Errorf("deployment job has invalid port mapping")
		}
		if port.Protocol != "" && port.Protocol != "tcp" && port.Protocol != "udp" {
			return fmt.Errorf("deployment job has invalid port protocol")
		}
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		publishedPort := fmt.Sprintf("%d/%s", port.HostPort, protocol)
		if _, exists := publishedPorts[publishedPort]; exists {
			return fmt.Errorf("deployment job has duplicate published port")
		}
		publishedPorts[publishedPort] = struct{}{}
	}
	if len(job.Env) > maxContainerEnvVars {
		return fmt.Errorf("deployment job has too many environment variables")
	}
	for key, value := range job.Env {
		if !validEnvironmentVariable(key, value) {
			return fmt.Errorf("deployment job has invalid environment variable")
		}
	}
	tenantRoot := filepath.Clean(filepath.Join("/srv/lumapanel/tenants", job.TenantID)) + string(filepath.Separator)
	if len(job.Mounts) > maxContainerMounts {
		return fmt.Errorf("deployment job has too many mounts")
	}
	mountTargets := map[string]struct{}{}
	for _, mount := range job.Mounts {
		source := filepath.Clean(mount.Source)
		if !validDockerMountPath(source) {
			return fmt.Errorf("deployment job has invalid mount path")
		}
		if !filepath.IsAbs(source) || !strings.HasPrefix(source+string(filepath.Separator), tenantRoot) {
			return fmt.Errorf("deployment job mount escapes tenant root")
		}
		target := filepath.Clean(mount.Target)
		if !validDockerMountPath(target) {
			return fmt.Errorf("deployment job has invalid mount path")
		}
		if !filepath.IsAbs(target) {
			return fmt.Errorf("deployment job mount target must be absolute")
		}
		if unsafeMountTarget(target) {
			return fmt.Errorf("deployment job mount target is unsafe")
		}
		for existing := range mountTargets {
			if mountTargetsOverlap(existing, target) {
				return fmt.Errorf("deployment job has overlapping mount target")
			}
		}
		mountTargets[target] = struct{}{}
	}
	if !job.Security.NoNewPrivileges {
		return fmt.Errorf("deployment job must set no-new-privileges")
	}
	if !job.Security.ReadOnlyRootFS {
		return fmt.Errorf("deployment job must set read-only root filesystem")
	}
	if !containsCapability(job.Security.DroppedCapabilities, "ALL") {
		return fmt.Errorf("deployment job must drop all Linux capabilities")
	}
	if !validConfinementProfile(job.Security.SeccompProfile) || !validConfinementProfile(job.Security.AppArmorProfile) {
		return fmt.Errorf("deployment job must set seccomp and AppArmor profiles")
	}
	for key, value := range job.Labels {
		if !validDockerLabel(key, value) {
			return fmt.Errorf("deployment job has invalid Docker label")
		}
		if reservedLabelOverride(job, key, value) {
			return fmt.Errorf("deployment job cannot override reserved LUMA labels")
		}
	}
	if err := validateEgressPolicy(job); err != nil {
		return err
	}
	if !validHealthcheck(job.Healthcheck) {
		return fmt.Errorf("deployment job has invalid healthcheck")
	}
	return nil
}

func reservedLabelOverride(job DeployJob, key string, value string) bool {
	switch key {
	case "luma.managed":
		return value != "true"
	case "luma.deployment":
		return value != job.DeploymentID
	case "luma.tenant":
		return value != job.TenantID
	case "luma.node":
		return value != job.NodeID
	default:
		return false
	}
}

func lumaOwnershipLabel(key string) bool {
	return key == "luma.managed" || key == "luma.deployment" || key == "luma.tenant" || key == "luma.node"
}

func validDockerLabel(key string, value string) bool {
	if key == "" || len(key) > 253 || len(value) > 1024 {
		return false
	}
	if strings.ContainsAny(key, "\x00\r\n=") || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	return true
}

func validEnvironmentVariable(key string, value string) bool {
	if key == "" || len(key) > 128 || len(value) > maxContainerEnvValueLength {
		return false
	}
	for i, r := range key {
		if i == 0 {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '_' {
				return false
			}
			continue
		}
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validateEgressPolicy(job DeployJob) error {
	mode := normalizedEgressMode(job)
	if mode != "allow-all" && mode != "deny-all" && mode != "restricted" {
		return fmt.Errorf("deployment job has invalid egress mode")
	}
	if mode == "allow-all" && len(job.Egress.Rules) > 0 {
		return fmt.Errorf("allow-all egress policy cannot include rules")
	}
	if mode == "restricted" && len(job.Egress.Rules) == 0 {
		return fmt.Errorf("restricted egress policy requires allow rules")
	}
	for _, rule := range job.Egress.Rules {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("deployment job has invalid egress protocol")
		}
		if rule.Port <= 0 || rule.Port > 65535 {
			return fmt.Errorf("deployment job has invalid egress port")
		}
		if _, _, err := net.ParseCIDR(rule.DestinationCIDR); err != nil {
			return fmt.Errorf("deployment job has invalid egress destination CIDR")
		}
	}
	return nil
}

func normalizedEgressMode(job DeployJob) string {
	if strings.TrimSpace(job.Egress.Mode) == "" {
		return "allow-all"
	}
	return job.Egress.Mode
}

func validLumaIdentifier(value string) bool {
	if value == "" || len(value) > 80 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func containsCapability(capabilities []string, target string) bool {
	for _, capability := range capabilities {
		if strings.EqualFold(strings.TrimSpace(capability), target) {
			return true
		}
	}
	return false
}

func unsafeMountTarget(target string) bool {
	clean := filepath.Clean(target)
	if clean == "/" {
		return true
	}
	sensitiveTargets := []string{"/boot", "/dev", "/etc", "/proc", "/root", "/run", "/sys", "/tmp", "/var/run"}
	for _, sensitive := range sensitiveTargets {
		if clean == sensitive || strings.HasPrefix(clean, sensitive+"/") {
			return true
		}
	}
	return false
}

func mountTargetsOverlap(left string, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func validDockerMountPath(path string) bool {
	if path == "" || strings.Contains(path, ",") {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validConfinementProfile(profile string) bool {
	profile = strings.TrimSpace(profile)
	if profile == "" || strings.EqualFold(profile, "unconfined") {
		return false
	}
	for _, r := range profile {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if r == '.' || r == '_' || r == '-' || r == '/' {
			continue
		}
		return false
	}
	return true
}

func validImageReference(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" || len(image) > 512 || strings.ContainsAny(image, "\x00\r\n\t ") {
		return false
	}
	for _, r := range image {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validImageDigest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return false
	}
	for _, r := range strings.TrimPrefix(digest, "sha256:") {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			continue
		}
		return false
	}
	return true
}

func validHealthcheck(healthcheck string) bool {
	if healthcheck == "" {
		return true
	}
	if len(healthcheck) > 512 || strings.TrimSpace(healthcheck) == "" {
		return false
	}
	for _, r := range healthcheck {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validStartupCommand(command string) bool {
	if len(command) > 2048 || strings.TrimSpace(command) == "" {
		return false
	}
	for _, r := range command {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func resolvedContainerImage(job DeployJob) string {
	if job.ImageDigest == "" {
		return job.Image
	}
	image := strings.TrimSpace(job.Image)
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon > lastSlash {
		image = image[:lastColon]
	}
	return image + "@" + job.ImageDigest
}

func dockerRunArgs(job DeployJob) ([]string, error) {
	if err := validateDeploymentJob(job, ""); err != nil {
		return nil, err
	}
	memoryLimit := strconv.Itoa(job.Resources.MemoryMB) + "m"
	diskLimit := strconv.Itoa(job.Resources.DiskGB) + "g"
	args := []string{
		"run",
		"--detach",
		"--name", "luma-" + job.DeploymentID,
		"--cpus", strconv.FormatFloat(job.Resources.CPUCores, 'f', -1, 64),
		"--memory", memoryLimit,
		"--memory-swap", memoryLimit,
		"--storage-opt", "size=" + diskLimit,
		"--pids-limit", strconv.Itoa(defaultContainerPidsLimit),
		"--log-driver", "json-file",
		"--log-opt", "max-size=" + defaultContainerLogMaxSize,
		"--log-opt", "max-file=" + defaultContainerLogMaxFile,
		"--user", defaultContainerUser,
		"--init",
		"--ipc", "none",
		"--cgroupns", "private",
		"--stop-timeout", strconv.Itoa(defaultContainerStopTimeoutSeconds),
		"--restart", "no",
		"--oom-kill-disable=false",
		"--pull", "never",
		"--network", job.Network.Name,
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + job.Security.SeccompProfile,
		"--security-opt", "apparmor=" + job.Security.AppArmorProfile,
		"--label", "luma.managed=true",
		"--label", "luma.deployment=" + job.DeploymentID,
		"--label", "luma.tenant=" + job.TenantID,
		"--label", "luma.node=" + job.NodeID,
	}
	if job.Security.ReadOnlyRootFS {
		args = append(args, "--read-only")
		args = append(args, "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size="+defaultContainerTmpfsSize)
		args = append(args, "--tmpfs", "/run:rw,nosuid,nodev,size=16m")
	}
	for _, capability := range job.Security.DroppedCapabilities {
		args = append(args, "--cap-drop", capability)
	}
	for key, value := range job.Labels {
		if lumaOwnershipLabel(key) {
			continue
		}
		args = append(args, "--label", key+"="+value)
	}
	for key, value := range job.Env {
		args = append(args, "--env", key+"="+value)
	}
	for _, port := range job.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		args = append(args, "--publish", fmt.Sprintf("%d:%d/%s", port.HostPort, port.ContainerPort, protocol))
	}
	for _, mount := range job.Mounts {
		mode := "rw"
		if mount.ReadOnly {
			mode = "ro"
		}
		args = append(args, "--mount", fmt.Sprintf("type=bind,src=%s,dst=%s,%s,bind-propagation=rprivate", filepath.Clean(mount.Source), filepath.Clean(mount.Target), mode))
	}
	if job.Healthcheck != "" {
		args = append(
			args,
			"--health-cmd", job.Healthcheck,
			"--health-interval", defaultContainerHealthInterval,
			"--health-timeout", defaultContainerHealthTimeout,
			"--health-retries", strconv.Itoa(defaultContainerHealthRetries),
		)
	}
	args = append(args, resolvedContainerImage(job))
	if job.Command != "" {
		args = append(args, "sh", "-lc", job.Command)
	}
	return args, nil
}

func deploymentPlan(job DeployJob) (DeploymentPlan, error) {
	if err := validateDeploymentJob(job, ""); err != nil {
		return DeploymentPlan{}, err
	}
	directorySet := map[string]struct{}{}
	mounts := make([]MountPlan, 0, len(job.Mounts))
	ports := make([]PortPlan, 0, len(job.Ports))
	for _, mount := range job.Mounts {
		source := filepath.Clean(mount.Source)
		target := filepath.Clean(mount.Target)
		directorySet[source] = struct{}{}
		mounts = append(mounts, MountPlan{Source: source, Target: target, ReadOnly: mount.ReadOnly})
	}
	for _, port := range job.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		ports = append(ports, PortPlan{HostPort: port.HostPort, ContainerPort: port.ContainerPort, Protocol: protocol})
	}
	directories := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	runArgs, err := dockerRunArgs(job)
	if err != nil {
		return DeploymentPlan{}, err
	}
	firewall := firewallCommands(job)
	plan := DeploymentPlan{
		DeploymentID:  job.DeploymentID,
		TenantID:      job.TenantID,
		NodeID:        job.NodeID,
		TenantRoot:    filepath.Clean(filepath.Join("/srv/lumapanel/tenants", job.TenantID)),
		ContainerName: "luma-" + job.DeploymentID,
		Resources: ResourcePlan{
			CPUCores: job.Resources.CPUCores,
			MemoryMB: job.Resources.MemoryMB,
			DiskGB:   job.Resources.DiskGB,
		},
		ImageDigest:     job.ImageDigest,
		ResolvedImage:   resolvedContainerImage(job),
		SeccompProfile:  job.Security.SeccompProfile,
		AppArmorProfile: job.Security.AppArmorProfile,
		Egress: EgressPolicy{
			Mode:  normalizedEgressMode(job),
			Rules: job.Egress.Rules,
		},
		Healthcheck: job.Healthcheck,
		Directories: directories,
		Mounts:      mounts,
		Ports:       ports,
		NetworkInspect: CommandPlan{
			Name: "docker",
			Args: []string{"network", "inspect", job.Network.Name},
		},
		NetworkCreate: CommandPlan{
			Name: "docker",
			Args: []string{
				"network", "create",
				"--driver", "bridge",
				"--opt", "com.docker.network.bridge.enable_icc=false",
				"--label", "luma.managed=true",
				"--label", "luma.tenant=" + job.TenantID,
				job.Network.Name,
			},
		},
		Firewall:        firewall,
		ContainerRemove: CommandPlan{Name: "docker", Args: []string{"rm", "--force", "--volumes", "luma-" + job.DeploymentID}},
		ContainerRun:    CommandPlan{Name: "docker", Args: runArgs},
	}
	plan.Commands = append([]CommandPlan{plan.NetworkInspect, plan.NetworkCreate}, firewall...)
	plan.Commands = append(plan.Commands, plan.ContainerRemove)
	plan.Commands = append(plan.Commands, plan.ContainerRun)
	return plan, nil
}

func firewallCommands(job DeployJob) []CommandPlan {
	commands := []CommandPlan{
		{Name: "nft", Args: []string{"add", "table", "inet", "lumapanel"}},
		{
			Name: "nft",
			Args: []string{
				"add", "chain", "inet", "lumapanel", "input",
				"{", "type", "filter", "hook", "input", "priority", "0;", "policy", "drop;", "}",
			},
		},
	}
	commands = append(commands, baseFirewallCommands()...)
	portRules := map[string]struct{}{}
	for _, port := range job.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		comment := fmt.Sprintf("luma:%s:%d/%s", job.DeploymentID, port.HostPort, protocol)
		if _, exists := portRules[comment]; exists {
			continue
		}
		portRules[comment] = struct{}{}
		commands = append(commands, CommandPlan{
			Name:              "nft",
			SkipIfRuleComment: comment,
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				protocol, "dport", strconv.Itoa(port.HostPort),
				"counter", "accept",
				"comment", comment,
			},
		})
	}
	return commands
}

func egressFirewallCommands(job DeployJob, containerIP string) ([]CommandPlan, error) {
	mode := normalizedEgressMode(job)
	if mode == "allow-all" {
		return nil, nil
	}
	if ip := net.ParseIP(containerIP); ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("container has invalid IPv4 address for egress policy")
	}
	if err := validateEgressPolicy(job); err != nil {
		return nil, err
	}
	commands := []CommandPlan{
		{Name: "nft", Args: []string{"add", "table", "inet", "lumapanel"}},
		{
			Name: "nft",
			Args: []string{
				"add", "chain", "inet", "lumapanel", "forward",
				"{", "type", "filter", "hook", "forward", "priority", "0;", "policy", "accept;", "}",
			},
		},
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:forward-established",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "forward",
				"ct", "state", "established,related",
				"counter", "accept",
				"comment", "luma:base:forward-established",
			},
		},
	}
	for index, rule := range job.Egress.Rules {
		comment := fmt.Sprintf("luma:%s:egress:%03d", job.DeploymentID, index+1)
		commands = append(commands, CommandPlan{
			Name:              "nft",
			SkipIfRuleComment: comment,
			Args: []string{
				"add", "rule", "inet", "lumapanel", "forward",
				"ip", "saddr", containerIP,
				"ip", "daddr", rule.DestinationCIDR,
				rule.Protocol, "dport", strconv.Itoa(rule.Port),
				"counter", "accept",
				"comment", comment,
			},
		})
	}
	dropComment := fmt.Sprintf("luma:%s:egress:drop", job.DeploymentID)
	commands = append(commands, CommandPlan{
		Name:              "nft",
		SkipIfRuleComment: dropComment,
		Args: []string{
			"add", "rule", "inet", "lumapanel", "forward",
			"ip", "saddr", containerIP,
			"counter", "drop",
			"comment", dropComment,
		},
	})
	return commands, nil
}

func baseFirewallCommands() []CommandPlan {
	return []CommandPlan{
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:established",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				"ct", "state", "established,related",
				"counter", "accept",
				"comment", "luma:base:established",
			},
		},
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:loopback",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				"iifname", "lo",
				"counter", "accept",
				"comment", "luma:base:loopback",
			},
		},
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:ssh",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				"tcp", "dport", "22",
				"counter", "accept",
				"comment", "luma:base:ssh",
			},
		},
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:lumanode",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				"tcp", "dport", "9443",
				"counter", "accept",
				"comment", "luma:base:lumanode",
			},
		},
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:icmp",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				"ip", "protocol", "icmp",
				"counter", "accept",
				"comment", "luma:base:icmp",
			},
		},
		{
			Name:              "nft",
			SkipIfRuleComment: "luma:base:icmpv6",
			Args: []string{
				"add", "rule", "inet", "lumapanel", "input",
				"ip6", "nexthdr", "ipv6-icmp",
				"counter", "accept",
				"comment", "luma:base:icmpv6",
			},
		},
	}
}
