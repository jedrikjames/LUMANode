package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lumapanel/lumanode/internal/config"
)

func sampleJob() DeployJob {
	var job DeployJob
	job.ID = "job_dep_test"
	job.DeploymentID = "dep_test"
	job.TenantID = "tenant_demo"
	job.NodeID = "node_local"
	job.Image = "nginx:1.27-alpine"
	job.Command = "nginx -g 'daemon off;'"
	job.Resources.CPUCores = 1.5
	job.Resources.MemoryMB = 512
	job.Resources.DiskGB = 5
	job.Network.Name = "luma-tenant_demo"
	job.Network.Mode = "tenant-bridge"
	job.Ports = append(job.Ports, struct {
		HostPort      int    `json:"hostPort"`
		ContainerPort int    `json:"containerPort"`
		Protocol      string `json:"protocol"`
	}{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"})
	job.Mounts = append(job.Mounts, struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		ReadOnly bool   `json:"readOnly"`
	}{Source: "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test", Target: "/data"})
	job.Security.ReadOnlyRootFS = true
	job.Security.NoNewPrivileges = true
	job.Security.DroppedCapabilities = []string{"ALL"}
	job.Security.SeccompProfile = "lumapanel-default"
	job.Security.AppArmorProfile = "lumapanel-tenant"
	job.Healthcheck = "curl -fsS http://127.0.0.1"
	job.Labels = map[string]string{
		"luma.tenant":     "tenant_demo",
		"luma.deployment": "dep_test",
		"luma.template":   "tmpl_demo",
		"luma.node":       "node_local",
	}
	job.Env = map[string]string{"LUMA_TENANT_ID": "tenant_demo"}
	return job
}

func TestDockerRunArgsIncludesIsolationControls(t *testing.T) {
	args, err := dockerRunArgs(sampleJob())
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	required := []string{
		"--cpus",
		"1.5",
		"--memory",
		"512m",
		"--memory-swap",
		"512m",
		"--storage-opt",
		"size=5g",
		"--pids-limit",
		"512",
		"--log-driver",
		"json-file",
		"--log-opt",
		"max-size=10m",
		"--log-opt",
		"max-file=3",
		"--user",
		"10000:10000",
		"--init",
		"--ipc",
		"none",
		"--cgroupns",
		"private",
		"--stop-timeout",
		"30",
		"--restart",
		"no",
		"--pull",
		"never",
		"--network",
		"luma-tenant_demo",
		"--security-opt",
		"no-new-privileges=true",
		"--security-opt",
		"seccomp=lumapanel-default",
		"--security-opt",
		"apparmor=lumapanel-tenant",
		"--read-only",
		"--tmpfs",
		"/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--tmpfs",
		"/run:rw,nosuid,nodev,size=16m",
		"luma.managed=true",
		"luma.deployment=dep_test",
		"luma.tenant=tenant_demo",
		"luma.template=tmpl_demo",
		"luma.node=node_local",
		"--cap-drop",
		"ALL",
		"--publish",
		"8080:80/tcp",
		"--mount",
		"type=bind,src=/srv/lumapanel/tenants/tenant_demo/deployments/dep_test,dst=/data,rw,bind-propagation=rprivate",
		"--health-cmd",
		"curl -fsS http://127.0.0.1",
		"--health-interval",
		"30s",
		"--health-timeout",
		"5s",
		"--health-retries",
		"3",
		"nginx:1.27-alpine",
	}
	for _, item := range required {
		if !slices.Contains(args, item) {
			t.Fatalf("expected docker args to contain %q, got %#v", item, args)
		}
	}
}

func TestDockerRunArgsUsesPinnedImageDigest(t *testing.T) {
	job := sampleJob()
	job.Image = "nginx:1.27-alpine"
	job.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	args, err := dockerRunArgs(job)
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	if !slices.Contains(args, "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("expected docker args to use immutable image digest, got %#v", args)
	}
	if slices.Contains(args, "nginx:1.27-alpine") {
		t.Fatalf("expected docker args not to run mutable image tag when digest is supplied, got %#v", args)
	}
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if plan.ImageDigest != job.ImageDigest {
		t.Fatalf("expected deployment plan to retain signed image digest, got %q", plan.ImageDigest)
	}
	if plan.ResolvedImage != "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected deployment plan to retain resolved image, got %q", plan.ResolvedImage)
	}
}

func TestDockerRunArgsRejectsIncompleteJob(t *testing.T) {
	_, err := dockerRunArgs(DeployJob{})
	if err == nil {
		t.Fatal("expected missing identity to fail")
	}
}

func TestDockerRunArgsRejectsUnsafeHealthcheck(t *testing.T) {
	job := sampleJob()
	job.Healthcheck = "curl -fsS http://127.0.0.1\nrm -rf /"
	if _, err := dockerRunArgs(job); err == nil {
		t.Fatal("expected newline in healthcheck to fail")
	}

	job = sampleJob()
	job.Healthcheck = strings.Repeat("x", 513)
	if _, err := dockerRunArgs(job); err == nil {
		t.Fatal("expected overlong healthcheck to fail")
	}
}

func TestDeploymentPlanIncludesPreflightSteps(t *testing.T) {
	job := sampleJob()
	job.Mounts = append(job.Mounts, struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		ReadOnly bool   `json:"readOnly"`
	}{Source: "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/config", Target: "/config", ReadOnly: true})
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	expectedDirectories := []string{
		"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test",
		"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/config",
	}
	if !slices.Equal(plan.Directories, expectedDirectories) {
		t.Fatalf("expected directories %#v, got %#v", expectedDirectories, plan.Directories)
	}
	if len(plan.Mounts) != 2 || plan.Mounts[0].Source != "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test" || plan.Mounts[0].Target != "/data" || plan.Mounts[0].ReadOnly {
		t.Fatalf("expected deployment plan to retain signed mount policy, got %#v", plan.Mounts)
	}
	if len(plan.Ports) != 1 || plan.Ports[0].HostPort != 8080 || plan.Ports[0].ContainerPort != 80 || plan.Ports[0].Protocol != "tcp" {
		t.Fatalf("expected deployment plan to retain signed port policy, got %#v", plan.Ports)
	}
	if !slices.Equal(plan.NetworkInspect.Args, []string{"network", "inspect", "luma-tenant_demo"}) {
		t.Fatalf("unexpected network inspect command: %#v", plan.NetworkInspect)
	}
	if plan.TenantID != "tenant_demo" {
		t.Fatalf("expected tenant ID in deployment plan, got %q", plan.TenantID)
	}
	if plan.TenantRoot != "/srv/lumapanel/tenants/tenant_demo" {
		t.Fatalf("expected tenant root in deployment plan, got %q", plan.TenantRoot)
	}
	if !slices.Contains(plan.NetworkCreate.Args, "luma.tenant=tenant_demo") {
		t.Fatalf("expected network create labels, got %#v", plan.NetworkCreate.Args)
	}
	if !slices.Contains(plan.NetworkCreate.Args, "com.docker.network.bridge.enable_icc=false") {
		t.Fatalf("expected tenant network ICC hardening, got %#v", plan.NetworkCreate.Args)
	}
	if len(plan.Firewall) != 9 {
		t.Fatalf("expected table, chain, base allow rules, and one port firewall command, got %#v", plan.Firewall)
	}
	if !slices.Equal(plan.Firewall[0].Args, []string{"add", "table", "inet", "lumapanel"}) {
		t.Fatalf("unexpected nft table command: %#v", plan.Firewall[0])
	}
	if !slices.Contains(plan.Firewall[1].Args, "drop;") {
		t.Fatalf("expected default-drop input chain, got %#v", plan.Firewall[1].Args)
	}
	if !slices.Contains(plan.Firewall[4].Args, "22") || plan.Firewall[4].SkipIfRuleComment != "luma:base:ssh" {
		t.Fatalf("expected base SSH allow rule, got %#v", plan.Firewall[4])
	}
	portRule := plan.Firewall[len(plan.Firewall)-1]
	if !slices.Contains(portRule.Args, "8080") || !slices.Contains(portRule.Args, "luma:dep_test:8080/tcp") {
		t.Fatalf("expected nft port rule with deployment comment, got %#v", portRule.Args)
	}
	if portRule.SkipIfRuleComment != "luma:dep_test:8080/tcp" {
		t.Fatalf("expected duplicate guard comment, got %q", portRule.SkipIfRuleComment)
	}
	if !slices.Equal(plan.ContainerRemove.Args, []string{"rm", "--force", "--volumes", "luma-dep_test"}) {
		t.Fatalf("expected managed container replacement command, got %#v", plan.ContainerRemove)
	}
	if len(plan.Commands) != 13 || !slices.Equal(plan.Commands[len(plan.Commands)-2].Args, plan.ContainerRemove.Args) || plan.Commands[len(plan.Commands)-1].Args[0] != "run" {
		t.Fatalf("expected inspect/create/firewall/run command plan, got %#v", plan.Commands)
	}
}

func TestHostCapacityPreflightAcceptsSufficientCapacity(t *testing.T) {
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	capacity := hostCapacity{CPUCores: 2, MemoryMB: 1024, DiskGB: 10}
	if err := validateHostCapacity(plan, capacity); err != nil {
		t.Fatalf("expected sufficient host capacity to pass, got %v", err)
	}
}

func TestHostCapacityPreflightRejectsOvercommit(t *testing.T) {
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	cases := []struct {
		name     string
		capacity hostCapacity
		contains string
	}{
		{name: "cpu", capacity: hostCapacity{CPUCores: 1, MemoryMB: 1024, DiskGB: 10}, contains: "CPU cores"},
		{name: "memory", capacity: hostCapacity{CPUCores: 2, MemoryMB: 256, DiskGB: 10}, contains: "memory"},
		{name: "disk", capacity: hostCapacity{CPUCores: 2, MemoryMB: 1024, DiskGB: 1}, contains: "writable disk"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostCapacity(plan, tt.capacity)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %q capacity error, got %v", tt.contains, err)
			}
		})
	}
}

func TestHostPortPreflightRejectsBoundTCPPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test listener: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	job := sampleJob()
	job.Ports[0].HostPort = port
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = validateHostPortsAvailable(plan)
	if err == nil || !strings.Contains(err.Error(), "tcp/") {
		t.Fatalf("expected bound TCP port preflight failure, got %v", err)
	}
}

func TestHostPortPreflightAcceptsAvailableUDPPort(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test UDP socket: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to release test UDP socket: %v", err)
	}
	job := sampleJob()
	job.Ports[0].HostPort = port
	job.Ports[0].Protocol = "udp"
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if err := validateHostPortsAvailable(plan); err != nil {
		t.Fatalf("expected available UDP port preflight to pass, got %v", err)
	}
}

func TestHostCapacityPreflightReadsMemAvailable(t *testing.T) {
	meminfo := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(meminfo, []byte("MemTotal: 4096000 kB\nMemAvailable: 1048576 kB\n"), 0o600); err != nil {
		t.Fatalf("failed to write meminfo fixture: %v", err)
	}
	memoryMB, err := readAvailableMemoryMB(meminfo)
	if err != nil {
		t.Fatalf("readAvailableMemoryMB returned error: %v", err)
	}
	if memoryMB != 1024 {
		t.Fatalf("expected 1024 MiB available memory, got %d", memoryMB)
	}
}

func TestHostCapacityPreflightFindsNearestExistingPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tenants", "tenant_demo", "deployments", "dep_test")
	if got := nearestExistingPath(path); got != root {
		t.Fatalf("expected nearest existing path %q, got %q", root, got)
	}
}

func TestEnsureTenantDirectoryCreatesNestedTenantPath(t *testing.T) {
	tenantRoot := filepath.Join(t.TempDir(), "tenant_demo")
	target := filepath.Join(tenantRoot, "deployments", "dep_test", "data")

	if err := ensureTenantDirectory(tenantRoot, target); err != nil {
		t.Fatalf("expected tenant directory preflight to create nested path, got %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("expected nested tenant directory to exist, info=%#v err=%v", info, err)
	}
}

func TestEnsureTenantDirectoryRejectsSymlinkedPathComponent(t *testing.T) {
	tempDir := t.TempDir()
	tenantRoot := filepath.Join(tempDir, "tenant_demo")
	outsideRoot := filepath.Join(tempDir, "outside")
	if err := os.MkdirAll(tenantRoot, 0o750); err != nil {
		t.Fatalf("create tenant root: %v", err)
	}
	if err := os.MkdirAll(outsideRoot, 0o750); err != nil {
		t.Fatalf("create outside root: %v", err)
	}
	if err := os.Symlink(outsideRoot, filepath.Join(tenantRoot, "deployments")); err != nil {
		t.Fatalf("create symlinked deployment directory: %v", err)
	}

	err := ensureTenantDirectory(tenantRoot, filepath.Join(tenantRoot, "deployments", "dep_test"))
	if err == nil || !strings.Contains(err.Error(), "symlinked path component") {
		t.Fatalf("expected symlinked tenant directory refusal, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outsideRoot, "dep_test")); !os.IsNotExist(statErr) {
		t.Fatalf("expected preflight not to create outside tenant root, statErr=%v", statErr)
	}
}

func TestEnsureTenantDirectoryRejectsWorldWritableTenantPathComponent(t *testing.T) {
	tenantRoot := filepath.Join(t.TempDir(), "tenant_demo")
	deployments := filepath.Join(tenantRoot, "deployments")
	if err := os.MkdirAll(deployments, 0o750); err != nil {
		t.Fatalf("create deployment directory: %v", err)
	}
	if err := os.Chmod(deployments, 0o777); err != nil {
		t.Fatalf("make deployment directory world-writable: %v", err)
	}

	target := filepath.Join(deployments, "dep_test")
	err := ensureTenantDirectory(tenantRoot, target)
	if err == nil || !strings.Contains(err.Error(), "world-writable tenant path component") {
		t.Fatalf("expected world-writable tenant directory refusal, got %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("expected preflight not to create child inside world-writable directory, statErr=%v", statErr)
	}
}

func TestFirewallCommandsDeduplicatePublishedPorts(t *testing.T) {
	job := sampleJob()
	job.Ports = append(job.Ports, job.Ports[0])
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if len(plan.Firewall) != 9 {
		t.Fatalf("expected duplicate published port to produce one nft rule, got %#v", plan.Firewall)
	}
}

func TestFirewallCommandsUseDefaultDenyBasePolicy(t *testing.T) {
	commands := firewallCommands(sampleJob())
	requiredComments := []string{
		"luma:base:established",
		"luma:base:loopback",
		"luma:base:ssh",
		"luma:base:lumanode",
		"luma:base:icmp",
		"luma:base:icmpv6",
		"luma:dep_test:8080/tcp",
	}
	if !slices.Contains(commands[1].Args, "drop;") {
		t.Fatalf("expected default drop chain policy, got %#v", commands[1].Args)
	}
	for _, comment := range requiredComments {
		if !slices.ContainsFunc(commands, func(command CommandPlan) bool {
			return command.SkipIfRuleComment == comment && slices.Contains(command.Args, comment)
		}) {
			t.Fatalf("expected firewall command with idempotency comment %q in %#v", comment, commands)
		}
	}
}

func TestEgressFirewallCommandsRestrictContainerIP(t *testing.T) {
	job := sampleJob()
	job.Egress.Mode = "restricted"
	job.Egress.Rules = []EgressPolicyRule{
		{Protocol: "tcp", DestinationCIDR: "10.20.0.0/16", Port: 443},
		{Protocol: "udp", DestinationCIDR: "192.0.2.10/32", Port: 53},
	}
	commands, err := egressFirewallCommands(job, "172.18.0.4")
	if err != nil {
		t.Fatalf("egressFirewallCommands returned error: %v", err)
	}
	if len(commands) != 6 {
		t.Fatalf("expected table, chain, established, two allow rules, and drop rule, got %#v", commands)
	}
	if !slices.Contains(commands[3].Args, "172.18.0.4") ||
		!slices.Contains(commands[3].Args, "10.20.0.0/16") ||
		commands[3].SkipIfRuleComment != "luma:dep_test:egress:001" {
		t.Fatalf("expected first egress allow rule scoped to container IP and CIDR, got %#v", commands[3])
	}
	drop := commands[len(commands)-1]
	if !slices.Contains(drop.Args, "drop") || drop.SkipIfRuleComment != "luma:dep_test:egress:drop" {
		t.Fatalf("expected final egress drop rule, got %#v", drop)
	}
}

func TestEgressFirewallCommandsRejectInvalidContainerIP(t *testing.T) {
	job := sampleJob()
	job.Egress.Mode = "deny-all"
	if _, err := egressFirewallCommands(job, "not-an-ip"); err == nil {
		t.Fatal("expected invalid container IP to fail")
	}
}

func TestStaleDeploymentFirewallRulesOnlyTargetsCurrentDeployment(t *testing.T) {
	output := `
table inet lumapanel {
  chain input {
    tcp dport 8080 counter accept comment "luma:dep_test:8080/tcp" # handle 10
    udp dport 8081 counter accept comment "luma:dep_test:8081/udp" # handle 11
    tcp dport 25565 counter accept comment "luma:dep_other:25565/tcp" # handle 12
    tcp dport 22 counter accept comment "luma:base:ssh" # handle 13
  }
}
`
	desired := map[string]struct{}{"luma:dep_test:8080/tcp": {}}
	stale := staleDeploymentFirewallRules(output, "dep_test", desired)
	if len(stale) != 1 {
		t.Fatalf("expected one stale current-deployment rule, got %#v", stale)
	}
	if stale[0].Comment != "luma:dep_test:8081/udp" || stale[0].Handle != "11" {
		t.Fatalf("unexpected stale rule: %#v", stale[0])
	}
}

func TestExecuteDeploymentPlanRemovesFirewallRulesWhenDockerRunFails(t *testing.T) {
	tempDir := t.TempDir()
	dockerLog := filepath.Join(tempDir, "docker.log")
	nftLog := filepath.Join(tempDir, "nft.log")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  echo "No such container" >&2
  exit 1
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
if [ "$1" = "run" ]; then
  echo "image rejected" >&2
  exit 1
fi
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
printf '%s\n' "$*" >> "$NFT_LOG"
if [ "$1" = "-a" ] && [ "$6" = "input" ]; then
  echo 'tcp dport 8080 counter accept comment "luma:dep_test:8080/tcp" # handle 10'
  exit 0
fi
if [ "$1" = "-a" ] && [ "$6" = "forward" ]; then
  echo 'ip saddr 172.18.0.4 drop comment "luma:dep_test:egress:drop" # handle 20'
  exit 0
fi
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", dockerLog)
	t.Setenv("NFT_LOG", nftLog)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "docker run failed") {
		t.Fatalf("expected docker run failure, got %v", err)
	}
	dockerContent, readErr := os.ReadFile(dockerLog)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(dockerContent), "run ") {
		t.Fatalf("expected docker run to execute, got %q", string(dockerContent))
	}
	nftContent, readErr := os.ReadFile(nftLog)
	if readErr != nil {
		t.Fatalf("read nft log: %v", readErr)
	}
	nftText := string(nftContent)
	if !strings.Contains(nftText, "delete rule inet lumapanel input handle 10") {
		t.Fatalf("expected failed deployment to delete input rule, got %q", nftText)
	}
	if !strings.Contains(nftText, "delete rule inet lumapanel forward handle 20") {
		t.Fatalf("expected failed deployment to delete forward egress rule, got %q", nftText)
	}
}

func TestParseNftManagedRuleRejectsUnsafeHandles(t *testing.T) {
	line := `tcp dport 8080 accept comment "luma:dep_test:8080/tcp" # handle 12;reboot`
	if _, ok := parseNftManagedRule(line); ok {
		t.Fatal("expected nonnumeric nft handle to be rejected")
	}
}

func TestValidateDeploymentJobEnforcesAgentBoundary(t *testing.T) {
	cases := []struct {
		name string
		edit func(*DeployJob)
		want string
	}{
		{
			name: "unsafe image reference",
			edit: func(job *DeployJob) { job.Image = "nginx:1.27-alpine\n--privileged" },
			want: "invalid image reference",
		},
		{
			name: "invalid image digest",
			edit: func(job *DeployJob) { job.ImageDigest = "sha256:not-a-digest" },
			want: "invalid image digest",
		},
		{
			name: "blank startup command",
			edit: func(job *DeployJob) { job.Command = "  " },
			want: "invalid startup command",
		},
		{
			name: "unsafe startup command",
			edit: func(job *DeployJob) { job.Command = "nginx\nrm -rf /" },
			want: "invalid startup command",
		},
		{
			name: "overlong startup command",
			edit: func(job *DeployJob) { job.Command = strings.Repeat("x", 2049) },
			want: "invalid startup command",
		},
		{
			name: "wrong node",
			edit: func(job *DeployJob) { job.NodeID = "node_other" },
			want: "not this node",
		},
		{
			name: "unsafe deployment identifier",
			edit: func(job *DeployJob) { job.DeploymentID = "dep_test;rm" },
			want: "invalid identifiers",
		},
		{
			name: "unsafe tenant identifier",
			edit: func(job *DeployJob) {
				job.TenantID = "../tenant_demo"
				job.Network.Name = "luma-" + job.TenantID
			},
			want: "invalid identifiers",
		},
		{
			name: "mount outside tenant root",
			edit: func(job *DeployJob) { job.Mounts[0].Source = "/etc" },
			want: "mount escapes tenant root",
		},
		{
			name: "relative mount target",
			edit: func(job *DeployJob) { job.Mounts[0].Target = "data" },
			want: "mount target must be absolute",
		},
		{
			name: "wrong tenant network",
			edit: func(job *DeployJob) { job.Network.Name = "bridge" },
			want: "invalid tenant network",
		},
		{
			name: "invalid resources",
			edit: func(job *DeployJob) { job.Resources.MemoryMB = 0 },
			want: "invalid resource limits",
		},
		{
			name: "excessive cpu resources",
			edit: func(job *DeployJob) { job.Resources.CPUCores = maxContainerCPUCores + 1 },
			want: "invalid resource limits",
		},
		{
			name: "excessive memory resources",
			edit: func(job *DeployJob) { job.Resources.MemoryMB = maxContainerMemoryMB + 1 },
			want: "invalid resource limits",
		},
		{
			name: "excessive disk resources",
			edit: func(job *DeployJob) { job.Resources.DiskGB = maxContainerDiskGB + 1 },
			want: "invalid resource limits",
		},
		{
			name: "too many port mappings",
			edit: func(job *DeployJob) {
				job.Ports = nil
				for i := 0; i <= maxContainerPortMappings; i++ {
					job.Ports = append(job.Ports, struct {
						HostPort      int    `json:"hostPort"`
						ContainerPort int    `json:"containerPort"`
						Protocol      string `json:"protocol"`
					}{HostPort: 10000 + i, ContainerPort: 10000 + i, Protocol: "tcp"})
				}
			},
			want: "too many port mappings",
		},
		{
			name: "invalid port",
			edit: func(job *DeployJob) { job.Ports[0].HostPort = 70000 },
			want: "invalid port mapping",
		},
		{
			name: "invalid protocol",
			edit: func(job *DeployJob) { job.Ports[0].Protocol = "sctp" },
			want: "invalid port protocol",
		},
		{
			name: "invalid environment key",
			edit: func(job *DeployJob) { job.Env["BAD-KEY"] = "value" },
			want: "invalid environment variable",
		},
		{
			name: "invalid environment value",
			edit: func(job *DeployJob) { job.Env["SAFE_KEY"] = "line\nbreak" },
			want: "invalid environment variable",
		},
		{
			name: "too many environment variables",
			edit: func(job *DeployJob) {
				for i := 0; i <= maxContainerEnvVars; i++ {
					job.Env[fmt.Sprintf("KEY_%d", i)] = "value"
				}
			},
			want: "too many environment variables",
		},
		{
			name: "too many mounts",
			edit: func(job *DeployJob) {
				job.Mounts = nil
				for i := 0; i <= maxContainerMounts; i++ {
					job.Mounts = append(job.Mounts, struct {
						Source   string `json:"source"`
						Target   string `json:"target"`
						ReadOnly bool   `json:"readOnly"`
					}{
						Source: fmt.Sprintf("/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/data_%d", i),
						Target: fmt.Sprintf("/data_%d", i),
					})
				}
			},
			want: "too many mounts",
		},
		{
			name: "missing no new privileges",
			edit: func(job *DeployJob) { job.Security.NoNewPrivileges = false },
			want: "no-new-privileges",
		},
		{
			name: "writable root filesystem",
			edit: func(job *DeployJob) { job.Security.ReadOnlyRootFS = false },
			want: "read-only root filesystem",
		},
		{
			name: "does not drop all capabilities",
			edit: func(job *DeployJob) { job.Security.DroppedCapabilities = []string{"NET_RAW"} },
			want: "drop all Linux capabilities",
		},
		{
			name: "unconfined seccomp",
			edit: func(job *DeployJob) { job.Security.SeccompProfile = "unconfined" },
			want: "seccomp and AppArmor",
		},
		{
			name: "unsafe apparmor profile",
			edit: func(job *DeployJob) { job.Security.AppArmorProfile = "profile,unconfined" },
			want: "seccomp and AppArmor",
		},
		{
			name: "reserved LUMA label override",
			edit: func(job *DeployJob) { job.Labels["luma.managed"] = "false" },
			want: "reserved LUMA labels",
		},
		{
			name: "reserved deployment label override",
			edit: func(job *DeployJob) { job.Labels["luma.deployment"] = "dep_other" },
			want: "reserved LUMA labels",
		},
		{
			name: "invalid docker label",
			edit: func(job *DeployJob) { job.Labels["bad\nkey"] = "value" },
			want: "invalid Docker label",
		},
		{
			name: "invalid egress mode",
			edit: func(job *DeployJob) { job.Egress.Mode = "internet" },
			want: "invalid egress mode",
		},
		{
			name: "invalid egress cidr",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = []EgressPolicyRule{{Protocol: "tcp", DestinationCIDR: "example.com", Port: 443}}
			},
			want: "invalid egress destination CIDR",
		},
		{
			name: "invalid egress port",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = []EgressPolicyRule{{Protocol: "tcp", DestinationCIDR: "0.0.0.0/0", Port: 0}}
			},
			want: "invalid egress port",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := sampleJob()
			tc.edit(&job)
			err := validateDeploymentJob(job, "node_local")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateDeploymentJobAcceptsTenantSubdirectories(t *testing.T) {
	job := sampleJob()
	job.Mounts[0].Source = "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/world"
	if err := validateDeploymentJob(job, "node_local"); err != nil {
		t.Fatalf("expected tenant subdirectory mount to pass: %v", err)
	}
}

func signSampleJob(t *testing.T, job DeployJob, secret string, expiresAt time.Time) signedDeployJob {
	t.Helper()
	payloadJSON, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal sample job: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	var envelope signedDeployJob
	envelope.Payload = payload
	envelope.Signature.Algorithm = "hmac-sha256"
	envelope.Signature.KeyID = "luma-job-v1"
	envelope.Signature.IssuedAt = expiresAt.Add(-time.Minute).Format(time.RFC3339)
	envelope.Signature.ExpiresAt = expiresAt.Format(time.RFC3339)
	envelope.Signature.Value = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return envelope
}

func TestVerifySignedDeployJob(t *testing.T) {
	secret := "test-signing-secret"
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	envelope := signSampleJob(t, sampleJob(), secret, now.Add(10*time.Minute))
	job, err := verifySignedDeployJob(envelope, secret, now)
	if err != nil {
		t.Fatalf("verifySignedDeployJob returned error: %v", err)
	}
	if job.ID != "job_dep_test" || job.TenantID != "tenant_demo" {
		t.Fatalf("unexpected verified job: %#v", job)
	}

	envelope.Signature.Value = "tampered"
	if _, err := verifySignedDeployJob(envelope, secret, now); err == nil {
		t.Fatal("expected tampered signature to fail")
	}
}

func TestVerifySignedDeployJobRejectsExpiredEnvelope(t *testing.T) {
	secret := "test-signing-secret"
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	envelope := signSampleJob(t, sampleJob(), secret, now.Add(-time.Minute))
	if _, err := verifySignedDeployJob(envelope, secret, now); err == nil {
		t.Fatal("expected expired signature to fail")
	}
}

func TestVerifyPeerCertificateRejectsRevokedFingerprint(t *testing.T) {
	certificate := testCertificate(t)
	fingerprint := certificateFingerprint(certificate)
	revocationList := filepath.Join(t.TempDir(), "revocations.json")
	colonFingerprint := strings.ToUpper(strings.Join(splitEvery(fingerprint, 2), ":"))
	if err := os.WriteFile(revocationList, []byte(`{"revokedFingerprints":["`+colonFingerprint+`"]}`), 0o600); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}

	err := verifyPeerCertificateNotRevoked(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}, revocationList)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked certificate error, got %v", err)
	}
}

func TestVerifyPeerCertificateAcceptsUnlistedFingerprint(t *testing.T) {
	certificate := testCertificate(t)
	revocationList := filepath.Join(t.TempDir(), "revocations.txt")
	if err := os.WriteFile(revocationList, []byte("# synced from panel\n001122\n"), 0o600); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}

	if err := verifyPeerCertificateNotRevoked(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}, revocationList); err != nil {
		t.Fatalf("expected unlisted certificate to pass: %v", err)
	}
}

func TestVerifyPeerCertificateFailsClosedWhenRevocationListMissing(t *testing.T) {
	certificate := testCertificate(t)
	missing := filepath.Join(t.TempDir(), "missing.json")

	if err := verifyPeerCertificateNotRevoked(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}, missing); err == nil {
		t.Fatal("expected missing configured revocation list to fail")
	}
}

func TestLoadRevokedFingerprintsSupportsPanelExportShape(t *testing.T) {
	revocationList := filepath.Join(t.TempDir(), "revocations.json")
	if err := os.WriteFile(revocationList, []byte(`{"revocations":[{"fingerprint":"AA:BB"},{"fingerprint":"ccdd"}]}`), 0o600); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}

	revoked, err := loadRevokedFingerprints(revocationList)
	if err != nil {
		t.Fatalf("load revoked fingerprints: %v", err)
	}
	if _, ok := revoked["aabb"]; !ok {
		t.Fatalf("expected colon fingerprint to be normalized, got %#v", revoked)
	}
	if _, ok := revoked["ccdd"]; !ok {
		t.Fatalf("expected plain fingerprint to be loaded, got %#v", revoked)
	}
}

func TestRotateCertificateIfDueWritesReturnedCredentials(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	caFile := filepath.Join(dir, "ca.crt")
	credentialsFile := filepath.Join(dir, "credentials.json")
	oldCert, oldKey := testCertificatePEM(t, time.Now().Add(time.Hour))
	newCert, newKey := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	for path, content := range map[string]string{certFile: oldCert, keyFile: oldKey, caFile: oldCert} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	secret := "agent-rotation-secret"
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/nodes/node_local/certificate/rotate-agent" {
			t.Fatalf("unexpected rotation path %s", r.URL.Path)
		}
		var request certificateRotationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode rotation request: %v", err)
		}
		payload := certificateRotationPayload(request.NodeID, request.Nonce, request.ExpiresAt)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(payload))
		if request.Signature != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
			t.Fatalf("unexpected rotation signature")
		}
		writeJSON(w, certificateRotationResponse{Credentials: certificateRotationCredentials{
			NodeID:               "node_local",
			CABundlePEM:          newCert,
			ClientCertificatePEM: newCert,
			ClientKeyPEM:         newKey,
			Fingerprint:          "abc123",
			ExpiresAt:            time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		}})
	}))
	defer panel.Close()

	agent := New(config.Config{
		NodeID:                    "node_local",
		PanelURL:                  panel.URL,
		CertFile:                  certFile,
		KeyFile:                   keyFile,
		CAFile:                    caFile,
		CredentialsFile:           credentialsFile,
		JobSigningSecret:          secret,
		CertificateRotationWindow: 24 * time.Hour,
	}, slog.Default())
	rotated, err := agent.RotateCertificateIfDue(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RotateCertificateIfDue returned error: %v", err)
	}
	if !rotated {
		t.Fatal("expected certificate to rotate inside renewal window")
	}
	for path, want := range map[string]string{certFile: newCert, keyFile: newKey, caFile: newCert} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("unexpected content for %s", path)
		}
	}
	credentials, err := os.ReadFile(credentialsFile)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if !strings.Contains(string(credentials), `"fingerprint": "abc123"`) {
		t.Fatalf("expected rotated credentials to be persisted, got %s", string(credentials))
	}
}

func TestReportDeploymentCompletionSignsQueueCallback(t *testing.T) {
	secret := "agent-completion-secret"
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/jobs/queue_dep_test/complete-agent" {
			t.Fatalf("unexpected completion path %s", r.URL.Path)
		}
		var request deploymentCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode completion request: %v", err)
		}
		if request.NodeID != "node_local" || request.Status != "succeeded" || request.Error != "" {
			t.Fatalf("unexpected completion request %#v", request)
		}
		payload := deploymentCompletionPayload("queue_dep_test", request.NodeID, request.Status, request.Error, request.Nonce, request.ExpiresAt)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(payload))
		if request.Signature != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
			t.Fatalf("unexpected completion signature")
		}
		writeJSON(w, map[string]string{"status": "ok"})
	}))
	defer panel.Close()

	agent := New(config.Config{
		NodeID:           "node_local",
		PanelURL:         panel.URL,
		JobSigningSecret: secret,
	}, slog.Default())
	job := sampleJob()
	job.QueueID = "queue_dep_test"
	if err := agent.reportDeploymentCompletion(context.Background(), job, "succeeded", ""); err != nil {
		t.Fatalf("reportDeploymentCompletion returned error: %v", err)
	}
}

func testCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node_test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

func testCertificatePEM(t *testing.T, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "node_local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func splitEvery(value string, width int) []string {
	parts := make([]string, 0, len(value)/width)
	for i := 0; i < len(value); i += width {
		end := i + width
		if end > len(value) {
			end = len(value)
		}
		parts = append(parts, value[i:end])
	}
	return parts
}

func TestDeployRejectsReplayedSignedEnvelope(t *testing.T) {
	secret := "test-signing-secret"
	envelope := signSampleJob(t, sampleJob(), secret, time.Now().Add(10*time.Minute))
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal signed envelope: %v", err)
	}
	agent := New(config.Config{NodeID: "node_local", JobSigningSecret: secret}, slog.Default())

	first := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))
	if first.Code != http.StatusOK {
		t.Fatalf("expected first deployment to be accepted, got %d: %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))
	if second.Code != http.StatusConflict {
		t.Fatalf("expected replayed deployment to be rejected, got %d: %s", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "replayed deployment job signature") {
		t.Fatalf("expected replay rejection body, got %q", second.Body.String())
	}
}

func TestDeployCanRequireImmutableImageDigest(t *testing.T) {
	secret := "test-signing-secret"
	job := sampleJob()
	unsignedEnvelope := signSampleJob(t, job, secret, time.Now().Add(10*time.Minute))
	body, err := json.Marshal(unsignedEnvelope)
	if err != nil {
		t.Fatalf("marshal signed envelope: %v", err)
	}
	agent := New(config.Config{NodeID: "node_local", JobSigningSecret: secret, RequireImageDigest: true}, slog.Default())

	dryRunEnvelope := signSampleJob(t, job, secret, time.Now().Add(11*time.Minute))
	dryRunBody, err := json.Marshal(dryRunEnvelope)
	if err != nil {
		t.Fatalf("marshal dry-run signed envelope: %v", err)
	}
	dryRun := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(dryRun, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(dryRunBody)))
	if dryRun.Code != http.StatusOK {
		t.Fatalf("expected digest policy to allow dry-run planning, got %d: %s", dryRun.Code, dryRun.Body.String())
	}

	t.Setenv("LUMANODE_DRY_RUN", "false")
	missingDigest := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(missingDigest, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))
	if missingDigest.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected digest policy rejection, got %d: %s", missingDigest.Code, missingDigest.Body.String())
	}
	if !strings.Contains(missingDigest.Body.String(), "requires immutable image digest") {
		t.Fatalf("expected digest policy error body, got %q", missingDigest.Body.String())
	}

	// Policy failures are not added to the replay cache, so a corrected signed job can still run.
	t.Setenv("LUMANODE_DRY_RUN", "true")
	job.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	signedPinnedJob := signSampleJob(t, job, secret, time.Now().Add(10*time.Minute))
	pinnedBody, err := json.Marshal(signedPinnedJob)
	if err != nil {
		t.Fatalf("marshal pinned signed envelope: %v", err)
	}
	accepted := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(accepted, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(pinnedBody)))
	if accepted.Code != http.StatusOK {
		t.Fatalf("expected digest-pinned deployment to be accepted, got %d: %s", accepted.Code, accepted.Body.String())
	}
}

func TestDeployRejectsReplayedSignedEnvelopeAfterRestart(t *testing.T) {
	secret := "test-signing-secret"
	replayStore := filepath.Join(t.TempDir(), "replayed-jobs.json")
	envelope := signSampleJob(t, sampleJob(), secret, time.Now().Add(10*time.Minute))
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal signed envelope: %v", err)
	}

	firstAgent := New(config.Config{NodeID: "node_local", JobSigningSecret: secret, ReplayStoreFile: replayStore}, slog.Default())
	first := httptest.NewRecorder()
	firstAgent.server.Handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))
	if first.Code != http.StatusOK {
		t.Fatalf("expected first deployment to be accepted, got %d: %s", first.Code, first.Body.String())
	}
	if _, err := os.Stat(replayStore); err != nil {
		t.Fatalf("expected replay store to be written: %v", err)
	}

	restartedAgent := New(config.Config{NodeID: "node_local", JobSigningSecret: secret, ReplayStoreFile: replayStore}, slog.Default())
	replayed := httptest.NewRecorder()
	restartedAgent.server.Handler.ServeHTTP(replayed, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))
	if replayed.Code != http.StatusConflict {
		t.Fatalf("expected persisted replay to be rejected, got %d: %s", replayed.Code, replayed.Body.String())
	}
	if !strings.Contains(replayed.Body.String(), "replayed deployment job signature") {
		t.Fatalf("expected replay rejection body, got %q", replayed.Body.String())
	}
}

func TestReplayCacheLoadIgnoresExpiredEntries(t *testing.T) {
	secret := "test-signing-secret"
	replayStore := filepath.Join(t.TempDir(), "replayed-jobs.json")
	expiredEnvelope := signSampleJob(t, sampleJob(), secret, time.Now().Add(-time.Minute))
	cacheKey := expiredEnvelope.Signature.KeyID + ":" + expiredEnvelope.Signature.Value
	content, err := json.Marshal(map[string]string{cacheKey: time.Now().Add(-time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatalf("marshal replay cache: %v", err)
	}
	if err := os.WriteFile(replayStore, content, 0o600); err != nil {
		t.Fatalf("write replay cache: %v", err)
	}

	agent := New(config.Config{NodeID: "node_local", JobSigningSecret: secret, ReplayStoreFile: replayStore}, slog.Default())
	if len(agent.replayCache) != 0 {
		t.Fatalf("expected expired replay cache entries to be ignored, got %#v", agent.replayCache)
	}
}

func TestRuntimeStatusRequiresDockerNftAndCgroupV2(t *testing.T) {
	tempDir := t.TempDir()
	cgroupFile := filepath.Join(tempDir, "cgroup.controllers")
	if err := os.WriteFile(cgroupFile, []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatalf("write cgroup controllers: %v", err)
	}
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "info" ]; then
  if [ "$3" = "{{json .SecurityOptions}}" ]; then
    echo '["name=apparmor","name=seccomp,profile=default","name=cgroupns","name=userns"]'
    exit 0
  fi
  if [ "$3" = "{{.CgroupDriver}}" ]; then
    echo systemd
    exit 0
  fi
  if [ "$3" = "{{.Debug}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.Swarm.LocalNodeState}}" ]; then
    echo inactive
    exit 0
  fi
  if [ "$3" = "{{.OomKillDisable}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.Driver}}" ]; then
    echo overlay2
    exit 0
  fi
  if [ "$3" = "{{json .DriverStatus}}" ]; then
    echo '[["Backing Filesystem","extfs"],["Supports d_type","true"],["Native Overlay Diff","true"]]'
    exit 0
  fi
  echo 2
  exit 0
fi
if [ "$1" = "version" ]; then
  if [ "$3" = "{{.Server.Experimental}}" ]; then
    echo false
    exit 0
  fi
  echo 25.0.3
  exit 0
fi
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", "#!/bin/sh\nexit 0\n")
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if !status.Ready || !status.Docker || !status.DockerCgroupV2 || !status.DockerCgroupDriverSystemd || !status.DockerDebugDisabled || !status.DockerExperimentalDisabled || !status.DockerSwarmInactive || !status.DockerOomKillEnabled || !status.DockerLiveRestore || !status.DockerStorageOverlay2 || !status.DockerStorageDType || !status.DockerServerVersionSupported || !status.DockerLocalEndpoint || !status.DockerSocketProtected || !status.Nftables || !status.CgroupV2 {
		t.Fatalf("expected ready runtime status, got %#v", status)
	}
	if !status.DockerSeccomp || !status.DockerAppArmor || !status.DockerUserNamespace {
		t.Fatalf("expected Docker seccomp/AppArmor/userns readiness, got %#v", status)
	}
}

func TestRuntimeStatusRejectsRemoteDockerEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	cgroupFile := filepath.Join(tempDir, "cgroup.controllers")
	if err := os.WriteFile(cgroupFile, []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatalf("write cgroup controllers: %v", err)
	}
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "info" ]; then
  if [ "$3" = "{{json .SecurityOptions}}" ]; then
    echo '["name=apparmor","name=seccomp,profile=default","name=cgroupns","name=userns"]'
    exit 0
  fi
  if [ "$3" = "{{.CgroupDriver}}" ]; then
    echo systemd
    exit 0
  fi
  if [ "$3" = "{{.Debug}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.Swarm.LocalNodeState}}" ]; then
    echo inactive
    exit 0
  fi
  if [ "$3" = "{{.OomKillDisable}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.Driver}}" ]; then
    echo overlay2
    exit 0
  fi
  if [ "$3" = "{{json .DriverStatus}}" ]; then
    echo '[["Backing Filesystem","extfs"],["Supports d_type","true"],["Native Overlay Diff","true"]]'
    exit 0
  fi
  echo 2
  exit 0
fi
if [ "$1" = "version" ]; then
  if [ "$3" = "{{.Server.Experimental}}" ]; then
    echo false
    exit 0
  fi
  echo 25.0.3
  exit 0
fi
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", "#!/bin/sh\nexit 0\n")
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready || status.DockerLocalEndpoint {
		t.Fatalf("expected remote Docker endpoint to fail runtime readiness, got %#v", status)
	}
	if status.Errors["dockerEndpoint"] == "" {
		t.Fatalf("expected Docker endpoint error, got %#v", status.Errors)
	}
}

func TestRuntimeStatusRejectsWorldWritableDockerSocket(t *testing.T) {
	tempDir := t.TempDir()
	cgroupFile := filepath.Join(tempDir, "cgroup.controllers")
	if err := os.WriteFile(cgroupFile, []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatalf("write cgroup controllers: %v", err)
	}
	socketPath := filepath.Join(tempDir, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatalf("chmod unix socket: %v", err)
	}
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "info" ]; then
  if [ "$3" = "{{json .SecurityOptions}}" ]; then
    echo '["name=apparmor","name=seccomp,profile=default","name=cgroupns","name=userns"]'
    exit 0
  fi
  if [ "$3" = "{{.CgroupDriver}}" ]; then
    echo systemd
    exit 0
  fi
  if [ "$3" = "{{.Debug}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.Swarm.LocalNodeState}}" ]; then
    echo inactive
    exit 0
  fi
  if [ "$3" = "{{.OomKillDisable}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.Driver}}" ]; then
    echo overlay2
    exit 0
  fi
  if [ "$3" = "{{json .DriverStatus}}" ]; then
    echo '[["Backing Filesystem","extfs"],["Supports d_type","true"],["Native Overlay Diff","true"]]'
    exit 0
  fi
  echo 2
  exit 0
fi
if [ "$1" = "version" ]; then
  if [ "$3" = "{{.Server.Experimental}}" ]; then
    echo false
    exit 0
  fi
  echo 25.0.3
  exit 0
fi
if [ "$1" = "context" ]; then
  echo "unix://$DOCKER_SOCKET_PATH"
  exit 0
fi
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", "#!/bin/sh\nexit 0\n")
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_SOCKET_PATH", socketPath)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready || !status.DockerLocalEndpoint || status.DockerSocketProtected {
		t.Fatalf("expected world-writable Docker socket to fail runtime readiness, got %#v", status)
	}
	if status.Errors["dockerSocket"] == "" {
		t.Fatalf("expected Docker socket error, got %#v", status.Errors)
	}
}

func TestRuntimeStatusRequiresDockerSecurityOptions(t *testing.T) {
	tempDir := t.TempDir()
	cgroupFile := filepath.Join(tempDir, "cgroup.controllers")
	if err := os.WriteFile(cgroupFile, []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatalf("write cgroup controllers: %v", err)
	}
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "info" ]; then
  if [ "$3" = "{{json .SecurityOptions}}" ]; then
    echo '["name=cgroupns"]'
    exit 0
  fi
  if [ "$3" = "{{.CgroupDriver}}" ]; then
    echo cgroupfs
    exit 0
  fi
  if [ "$3" = "{{.Debug}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.Swarm.LocalNodeState}}" ]; then
    echo active
    exit 0
  fi
  if [ "$3" = "{{.OomKillDisable}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.Driver}}" ]; then
    echo aufs
    exit 0
  fi
  echo 2
  exit 0
fi
if [ "$1" = "version" ]; then
  if [ "$3" = "{{.Server.Experimental}}" ]; then
    echo true
    exit 0
  fi
  echo 20.10.24
  exit 0
fi
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", "#!/bin/sh\nexit 0\n")
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready {
		t.Fatalf("expected runtime status to fail without Docker seccomp/AppArmor, got %#v", status)
	}
	if status.DockerSeccomp || status.DockerAppArmor || status.DockerUserNamespace || status.DockerCgroupDriverSystemd || status.DockerDebugDisabled || status.DockerExperimentalDisabled || status.DockerSwarmInactive || status.DockerOomKillEnabled || status.DockerLiveRestore || status.DockerStorageOverlay2 || status.DockerStorageDType || status.DockerServerVersionSupported {
		t.Fatalf("expected missing Docker seccomp/AppArmor/userns/live-restore/storage/version support, got %#v", status)
	}
	if status.Errors["dockerSeccomp"] == "" || status.Errors["dockerAppArmor"] == "" || status.Errors["dockerUserNamespace"] == "" || status.Errors["dockerCgroupDriver"] == "" || status.Errors["dockerDebug"] == "" || status.Errors["dockerExperimental"] == "" || status.Errors["dockerSwarm"] == "" || status.Errors["dockerOomKill"] == "" || status.Errors["dockerLiveRestore"] == "" || status.Errors["dockerStorageOverlay2"] == "" || status.Errors["dockerStorageDType"] == "" || status.Errors["dockerServerVersion"] == "" {
		t.Fatalf("expected Docker security option errors, got %#v", status.Errors)
	}
}

func TestDockerOverlaySupportsDType(t *testing.T) {
	if !dockerOverlaySupportsDType(`[["Backing Filesystem","extfs"],["Supports d_type","true"],["Native Overlay Diff","true"]]`) {
		t.Fatal("expected JSON DriverStatus with Supports d_type=true to pass")
	}
	if dockerOverlaySupportsDType(`[["Backing Filesystem","xfs"],["Supports d_type","false"]]`) {
		t.Fatal("expected JSON DriverStatus with Supports d_type=false to fail")
	}
	if !dockerOverlaySupportsDType("Backing Filesystem: extfs Supports d_type: true") {
		t.Fatal("expected text fallback with Supports d_type true to pass")
	}
	if dockerOverlaySupportsDType("Backing Filesystem: extfs Supports d_type: false") {
		t.Fatal("expected text fallback with Supports d_type false to fail")
	}
	if dockerOverlaySupportsDType("Supports d_type: false\nNative Overlay Diff: true") {
		t.Fatal("expected text fallback with unrelated true value to fail")
	}
}

func TestDockerServerVersionSupported(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "24.0.0", want: true},
		{version: "25.0.3", want: true},
		{version: "24.0.7+azure", want: true},
		{version: "23.0.6", want: false},
		{version: "20.10.24", want: false},
		{version: "bad-version", want: false},
	}
	for _, test := range tests {
		if got := dockerServerVersionSupported(test.version); got != test.want {
			t.Fatalf("dockerServerVersionSupported(%q) = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestDeployFailsClosedWhenRuntimePreflightFails(t *testing.T) {
	secret := "test-signing-secret"
	envelope := signSampleJob(t, sampleJob(), secret, time.Now().Add(10*time.Minute))
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal signed envelope: %v", err)
	}
	t.Setenv("LUMANODE_DRY_RUN", "false")
	agent := New(config.Config{
		NodeID:                       "node_local",
		JobSigningSecret:             secret,
		RuntimeCgroupControllersFile: filepath.Join(t.TempDir(), "missing-cgroup.controllers"),
	}, slog.Default())

	response := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected runtime preflight failure, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "runtime_preflight_failed") {
		t.Fatalf("expected runtime preflight error body, got %q", response.Body.String())
	}
}

func TestDeployRequiresSigningSecretForRealExecution(t *testing.T) {
	body, err := json.Marshal(sampleJob())
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	t.Setenv("LUMANODE_DRY_RUN", "false")
	agent := New(config.Config{NodeID: "node_local"}, slog.Default())

	response := httptest.NewRecorder()
	agent.server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/deploy", bytes.NewReader(body)))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned real deployment to be rejected, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "signing secret required") {
		t.Fatalf("expected signing secret error body, got %q", response.Body.String())
	}
}

func TestRemoveExistingContainerRequiresLumaOwnershipLabels(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "$DOCKER_LABEL_OUTPUT"
  exit 0
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)

	t.Setenv("DOCKER_LABEL_OUTPUT", "false dep_test")
	err := removeExistingContainer(context.Background(), CommandPlan{Name: "docker", Args: []string{"rm", "--force", "--volumes", "luma-dep_test"}})
	if err == nil || !strings.Contains(err.Error(), "unmanaged container") {
		t.Fatalf("expected unmanaged container refusal, got %v", err)
	}
	if _, readErr := os.ReadFile(logFile); !os.IsNotExist(readErr) {
		t.Fatalf("expected docker rm not to run for unmanaged container, readErr=%v", readErr)
	}

	t.Setenv("DOCKER_LABEL_OUTPUT", "true dep_test")
	if err := removeExistingContainer(context.Background(), CommandPlan{Name: "docker", Args: []string{"rm", "--force", "--volumes", "luma-dep_test"}}); err != nil {
		t.Fatalf("expected managed container removal to pass, got %v", err)
	}
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read docker log: %v", err)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected docker rm to run for managed container, got %q", string(content))
	}
}

func TestEnsureTenantNetworkRequiresLumaOwnershipLabels(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "$DOCKER_NETWORK_LABEL_OUTPUT"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}

	t.Setenv("DOCKER_NETWORK_LABEL_OUTPUT", "false tenant_demo false")
	err = ensureTenantNetwork(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unmanaged tenant network") {
		t.Fatalf("expected unmanaged tenant network refusal, got %v", err)
	}
	if _, readErr := os.ReadFile(logFile); !os.IsNotExist(readErr) {
		t.Fatalf("expected docker network create not to run for unmanaged existing network, readErr=%v", readErr)
	}

	t.Setenv("DOCKER_NETWORK_LABEL_OUTPUT", "true tenant_demo false")
	if err := ensureTenantNetwork(context.Background(), plan); err != nil {
		t.Fatalf("expected managed tenant network to pass, got %v", err)
	}

	t.Setenv("DOCKER_NETWORK_LABEL_OUTPUT", "true tenant_demo true")
	err = ensureTenantNetwork(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "inter-container communication enabled") {
		t.Fatalf("expected tenant network ICC refusal, got %v", err)
	}
}

func TestEnsureTenantNetworkVerifiesLabelsAfterCreate(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "$DOCKER_NETWORK_LABEL_OUTPUT"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 1
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}

	t.Setenv("DOCKER_NETWORK_LABEL_OUTPUT", "false tenant_demo false")
	err = ensureTenantNetwork(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unmanaged tenant network") {
		t.Fatalf("expected created network ownership verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "network create") {
		t.Fatalf("expected docker network create to run before ownership verification, got %q", string(content))
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWhenEgressHardeningFails(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
    *NetworkSettings.Networks*)
      echo ""
      exit 0
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
if [ "$1" = "-a" ]; then
  exit 0
fi
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	job := sampleJob()
	job.Egress.Mode = "deny-all"
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "empty container IP") {
		t.Fatalf("expected egress hardening failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	log := string(content)
	if !strings.Contains(log, "run ") {
		t.Fatalf("expected docker run to execute, got %q", log)
	}
	if !strings.Contains(log, "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected failed egress hardening to remove started container, got %q", log)
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanPrunesStaleEgressRulesForAllowAllRedeploy(t *testing.T) {
	tempDir := t.TempDir()
	dockerLog := filepath.Join(tempDir, "docker.log")
	nftLog := filepath.Join(tempDir, "nft.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
printf '%s\n' "$*" >> "$NFT_LOG"
if [ "$1" = "-a" ] && [ "$6" = "input" ]; then
  exit 0
fi
if [ "$1" = "-a" ] && [ "$6" = "forward" ]; then
  echo 'ip saddr 172.18.0.4 drop comment "luma:dep_test:egress:drop" # handle 55'
  exit 0
fi
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", dockerLog)
	t.Setenv("NFT_LOG", nftLog)
	t.Setenv("CONTAINER_STATE", stateFile)

	job := sampleJob()
	job.Egress.Mode = "allow-all"
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	if err := executeDeploymentPlan(context.Background(), plan); err != nil {
		t.Fatalf("expected allow-all redeploy to prune stale egress and pass, got %v", err)
	}
	content, err := os.ReadFile(nftLog)
	if err != nil {
		t.Fatalf("read nft log: %v", err)
	}
	log := string(content)
	if !strings.Contains(log, "-a list chain inet lumapanel forward") {
		t.Fatalf("expected forward chain inspection for stale egress rules, got %q", log)
	}
	if !strings.Contains(log, "delete rule inet lumapanel forward handle 55") {
		t.Fatalf("expected stale egress rule deletion before allow-all return, got %q", log)
	}
}

func TestExecuteDeploymentPlanRemovesUnhealthyStartedContainer(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true unhealthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "reported unhealthy") {
		t.Fatalf("expected unhealthy container verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	log := string(content)
	if !strings.Contains(log, "run ") {
		t.Fatalf("expected docker run to execute, got %q", log)
	}
	if !strings.Contains(log, "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected unhealthy container cleanup, got %q", log)
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanWaitsForHealthyStartedContainer(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	previousWait := containerHealthWait
	previousPoll := containerHealthPoll
	containerHealthWait = 25 * time.Millisecond
	containerHealthPoll = time.Millisecond
	t.Cleanup(func() {
		containerHealthWait = previousWait
		containerHealthPoll = previousPoll
	})
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true starting true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "did not become healthy before timeout") {
		t.Fatalf("expected starting health status to fail after timeout, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	log := string(content)
	if !strings.Contains(log, "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected starting container cleanup, got %q", log)
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithMismatchedOwnershipLabels(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_other tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "ownership labels") {
		t.Fatalf("expected container ownership verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected mismatched ownership cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithIsolationDrift(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "true true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "started privileged") {
		t.Fatalf("expected container isolation verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected isolation drift cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithUnexpectedNetworkAttachment(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 2 luma-tenant_demo,bridge,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unexpected network attachment count") {
		t.Fatalf("expected container network attachment verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected unexpected network cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithMountDrift(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":false,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "bind mount policy") {
		t.Fatalf("expected container mount verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected mount drift cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithSecurityProfileDrift(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "expected security options") {
		t.Fatalf("expected security profile drift verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected security profile drift cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithImageDigestDrift(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	job := sampleJob()
	job.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "digest-pinned image") {
		t.Fatalf("expected image digest drift verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected image digest drift cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanRemovesStartedContainerWithResourceDrift(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "docker.log")
	stateFile := filepath.Join(tempDir, "container-state")
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ] && [ "$3" = "-f" ]; then
  echo "true tenant_demo false"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1000000000 536870912 536870912 5g json-file 10m 3"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private no luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo,"
      exit 0
      ;;
    *.State.Running*)
      echo "true healthy true dep_test tenant_demo"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
  esac
fi
if [ "$1" = "run" ]; then
  touch "$CONTAINER_STATE"
fi
if [ "$1" = "rm" ]; then
  rm -f "$CONTAINER_STATE"
fi
printf '%s\n' "$*" >> "$DOCKER_LOG"
exit 0
`)
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", logFile)
	t.Setenv("CONTAINER_STATE", stateFile)

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "expected CPU limit") {
		t.Fatalf("expected container resource verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected resource drift cleanup, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func writeFakeCommand(t *testing.T, directory string, name string, content string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write fake command %s: %v", name, err)
	}
}
