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
		"--memory-swappiness",
		"0",
		"--storage-opt",
		"size=5g",
		"--pids-limit",
		"512",
		"--shm-size",
		"64m",
		"--log-driver",
		"json-file",
		"--log-opt",
		"max-size=10m",
		"--log-opt",
		"max-file=3",
		"--log-opt",
		"mode=non-blocking",
		"--log-opt",
		"max-buffer-size=4m",
		"--user",
		"10000:10000",
		"--init",
		"--ipc",
		"none",
		"--cgroupns",
		"private",
		"--userns",
		"private",
		"--pid",
		"private",
		"--uts",
		"private",
		"--stop-timeout",
		"30",
		"--stop-signal",
		"SIGTERM",
		"--restart",
		"no",
		"--oom-kill-disable=false",
		"--oom-score-adj",
		"0",
		"--pull",
		"never",
		"--entrypoint",
		"",
		"--workdir",
		"/",
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

func TestDockerRunArgsClearsImageEntrypoint(t *testing.T) {
	args, err := dockerRunArgs(sampleJob())
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	entrypoint := slices.Index(args, "--entrypoint")
	image := slices.Index(args, "nginx:1.27-alpine")
	if entrypoint < 0 || entrypoint+1 >= len(args) || args[entrypoint+1] != "" {
		t.Fatalf("expected docker run to clear inherited image entrypoint, got %#v", args)
	}
	if image < 0 || entrypoint > image {
		t.Fatalf("expected entrypoint reset before image argument, got %#v", args)
	}
}

func TestDockerRunArgsPinsWorkingDirectory(t *testing.T) {
	args, err := dockerRunArgs(sampleJob())
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	workdir := slices.Index(args, "--workdir")
	image := slices.Index(args, "nginx:1.27-alpine")
	if workdir < 0 || workdir+1 >= len(args) || args[workdir+1] != "/" {
		t.Fatalf("expected docker run to pin working directory, got %#v", args)
	}
	if image < 0 || workdir > image {
		t.Fatalf("expected working directory pin before image argument, got %#v", args)
	}
}

func TestDockerRunArgsDisablesInheritedImageHealthcheck(t *testing.T) {
	job := sampleJob()
	job.Healthcheck = ""
	args, err := dockerRunArgs(job)
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	if !slices.Contains(args, "--no-healthcheck") {
		t.Fatalf("expected docker run to disable inherited image healthchecks, got %#v", args)
	}
	if slices.Contains(args, "--health-cmd") {
		t.Fatalf("expected docker run not to configure a healthcheck when none is signed, got %#v", args)
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

func TestDockerRunArgsCleansMountPaths(t *testing.T) {
	job := sampleJob()
	job.Mounts[0].Source = "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/./world/.."
	job.Mounts[0].Target = "/data/./world/.."
	args, err := dockerRunArgs(job)
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	expectedMount := "type=bind,src=/srv/lumapanel/tenants/tenant_demo/deployments/dep_test,dst=/data,rw,bind-propagation=rprivate"
	if !slices.Contains(args, expectedMount) {
		t.Fatalf("expected cleaned mount argument %q, got %#v", expectedMount, args)
	}
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if len(plan.Mounts) != 1 || plan.Mounts[0].Source != "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test" || plan.Mounts[0].Target != "/data" {
		t.Fatalf("expected cleaned mount plan, got %#v", plan.Mounts)
	}
}

func TestDockerRunArgsOrdersUserLabelsAndEnvironment(t *testing.T) {
	job := sampleJob()
	job.Labels["z.example"] = "last"
	job.Labels["a.example"] = "first"
	job.Env["Z_ENV"] = "last"
	job.Env["A_ENV"] = "first"
	args, err := dockerRunArgs(job)
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	aLabel := slices.Index(args, "a.example=first")
	zLabel := slices.Index(args, "z.example=last")
	aEnv := slices.Index(args, "A_ENV=first")
	zEnv := slices.Index(args, "Z_ENV=last")
	if aLabel < 0 || zLabel < 0 || aLabel > zLabel {
		t.Fatalf("expected user labels to be sorted in docker args, got %#v", args)
	}
	if aEnv < 0 || zEnv < 0 || aEnv > zEnv {
		t.Fatalf("expected environment variables to be sorted in docker args, got %#v", args)
	}
}

func TestDockerRunArgsOrdersPublishedPorts(t *testing.T) {
	job := sampleJob()
	job.Ports = []struct {
		HostPort      int    `json:"hostPort"`
		ContainerPort int    `json:"containerPort"`
		Protocol      string `json:"protocol"`
	}{
		{HostPort: 9000, ContainerPort: 9000, Protocol: "udp"},
		{HostPort: 25565, ContainerPort: 25565, Protocol: ""},
		{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
	}
	args, err := dockerRunArgs(job)
	if err != nil {
		t.Fatalf("dockerRunArgs returned error: %v", err)
	}
	first := slices.Index(args, "8080:80/tcp")
	second := slices.Index(args, "25565:25565/tcp")
	third := slices.Index(args, "9000:9000/udp")
	if first < 0 || second < 0 || third < 0 || first > second || second > third {
		t.Fatalf("expected published ports to be sorted in docker args, got %#v", args)
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
	for _, path := range []string{tenantRoot, filepath.Join(tenantRoot, "deployments"), filepath.Join(tenantRoot, "deployments", "dep_test"), target} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat created tenant directory %q: %v", path, err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("expected created tenant directory %q not to be group- or world-writable, mode=%#o", path, info.Mode().Perm())
		}
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

func TestEnsureTenantDirectoryRejectsGroupOrWorldWritableTenantPathComponent(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
	}{
		{name: "group-writable", mode: 0o770},
		{name: "world-writable", mode: 0o777},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tenantRoot := filepath.Join(t.TempDir(), "tenant_demo")
			deployments := filepath.Join(tenantRoot, "deployments")
			if err := os.MkdirAll(deployments, 0o750); err != nil {
				t.Fatalf("create deployment directory: %v", err)
			}
			if err := os.Chmod(deployments, tt.mode); err != nil {
				t.Fatalf("make deployment directory writable by untrusted principals: %v", err)
			}

			target := filepath.Join(deployments, "dep_test")
			err := ensureTenantDirectory(tenantRoot, target)
			if err == nil || !strings.Contains(err.Error(), "group- or world-writable tenant path component") {
				t.Fatalf("expected writable tenant directory refusal, got %v", err)
			}
			if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
				t.Fatalf("expected preflight not to create child inside writable directory, statErr=%v", statErr)
			}
		})
	}
}

func TestEnsureTenantDirectoryAllowsOwnerWritableTenantPathComponent(t *testing.T) {
	tenantRoot := filepath.Join(t.TempDir(), "tenant_demo")
	deployments := filepath.Join(tenantRoot, "deployments")
	if err := os.MkdirAll(deployments, 0o750); err != nil {
		t.Fatalf("create deployment directory: %v", err)
	}

	target := filepath.Join(deployments, "dep_test")
	if err := ensureTenantDirectory(tenantRoot, target); err != nil {
		t.Fatalf("expected owner-writable tenant directory to pass, got %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("expected preflight to create child inside owner-writable directory, info=%#v err=%v", info, err)
	}
}

func TestFirewallCommandsDeduplicatePublishedPorts(t *testing.T) {
	job := sampleJob()
	job.Ports = append(job.Ports, job.Ports[0])
	firewall := firewallCommands(job)
	if len(firewall) != 9 {
		t.Fatalf("expected duplicate published port to produce one nft rule, got %#v", firewall)
	}
}

func TestFirewallCommandsOrdersPublishedPorts(t *testing.T) {
	job := sampleJob()
	job.Ports = []struct {
		HostPort      int    `json:"hostPort"`
		ContainerPort int    `json:"containerPort"`
		Protocol      string `json:"protocol"`
	}{
		{HostPort: 9000, ContainerPort: 9000, Protocol: "udp"},
		{HostPort: 25565, ContainerPort: 25565, Protocol: ""},
		{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
	}
	firewall := firewallCommands(job)
	want := []string{
		"luma:dep_test:8080/tcp",
		"luma:dep_test:25565/tcp",
		"luma:dep_test:9000/udp",
	}
	got := []string{}
	for _, command := range firewall {
		if strings.HasPrefix(command.SkipIfRuleComment, "luma:dep_test:") {
			got = append(got, command.SkipIfRuleComment)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("expected sorted published port firewall comments %#v, got %#v", want, got)
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

func TestEgressFirewallCommandsOrdersRules(t *testing.T) {
	job := sampleJob()
	job.Egress.Mode = "restricted"
	job.Egress.Rules = []EgressPolicyRule{
		{Protocol: "udp", DestinationCIDR: "192.0.2.10/32", Port: 53},
		{Protocol: "tcp", DestinationCIDR: "192.0.2.20/32", Port: 443},
		{Protocol: "tcp", DestinationCIDR: "10.20.0.0/16", Port: 80},
	}
	commands, err := egressFirewallCommands(job, "172.18.0.4")
	if err != nil {
		t.Fatalf("egressFirewallCommands returned error: %v", err)
	}
	want := []struct {
		comment string
		cidr    string
		port    string
	}{
		{comment: "luma:dep_test:egress:001", cidr: "10.20.0.0/16", port: "80"},
		{comment: "luma:dep_test:egress:002", cidr: "192.0.2.20/32", port: "443"},
		{comment: "luma:dep_test:egress:003", cidr: "192.0.2.10/32", port: "53"},
	}
	for index, expected := range want {
		command := commands[index+3]
		if command.SkipIfRuleComment != expected.comment ||
			!slices.Contains(command.Args, expected.cidr) ||
			!slices.Contains(command.Args, expected.port) {
			t.Fatalf("expected sorted egress command %#v at index %d, got %#v", expected, index, command)
		}
	}
}

func TestEgressFirewallCommandsRejectInvalidContainerIP(t *testing.T) {
	job := sampleJob()
	job.Egress.Mode = "deny-all"
	if _, err := egressFirewallCommands(job, "not-an-ip"); err == nil {
		t.Fatal("expected invalid container IP to fail")
	}
}

func TestVerifyDeploymentEgressFirewallRequiresExpectedRules(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
if [ "$1" = "-a" ] && [ "$6" = "forward" ]; then
  echo 'ip saddr 172.18.0.4 drop comment "luma:dep_test:egress:drop" # handle 20'
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := verifyDeploymentEgressFirewall(context.Background(), "dep_test", map[string]struct{}{"luma:dep_test:egress:drop": {}}); err != nil {
		t.Fatalf("expected matching deployment egress rule to verify, got %v", err)
	}
	err := verifyDeploymentEgressFirewall(context.Background(), "dep_test", map[string]struct{}{"luma:dep_test:egress:001": {}})
	if err == nil || !strings.Contains(err.Error(), "unexpected deployment rule") {
		t.Fatalf("expected unexpected egress rule verification failure, got %v", err)
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
			name: "leading dash image reference",
			edit: func(job *DeployJob) { job.Image = "--privileged" },
			want: "invalid image reference",
		},
		{
			name: "unnormalized image reference",
			edit: func(job *DeployJob) { job.Image = " nginx:1.27-alpine " },
			want: "invalid image reference",
		},
		{
			name: "url-like image reference",
			edit: func(job *DeployJob) { job.Image = "https://registry.example.com/nginx:latest" },
			want: "invalid image reference",
		},
		{
			name: "digest embedded in image reference",
			edit: func(job *DeployJob) {
				job.Image = "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
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
			name: "missing node identifier",
			edit: func(job *DeployJob) { job.NodeID = "" },
			want: "missing required deployment job identity",
		},
		{
			name: "unsafe deployment identifier",
			edit: func(job *DeployJob) { job.DeploymentID = "dep_test;rm" },
			want: "invalid identifiers",
		},
		{
			name: "leading separator deployment identifier",
			edit: func(job *DeployJob) { job.DeploymentID = "-dep_test" },
			want: "invalid identifiers",
		},
		{
			name: "trailing separator tenant identifier",
			edit: func(job *DeployJob) {
				job.TenantID = "tenant_demo_"
				job.Network.Name = "luma-" + job.TenantID
			},
			want: "invalid identifiers",
		},
		{
			name: "doubled separator node identifier",
			edit: func(job *DeployJob) { job.NodeID = "node__local" },
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
			name: "mount source with docker option separator",
			edit: func(job *DeployJob) {
				job.Mounts[0].Source = "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/data,ro"
			},
			want: "invalid mount path",
		},
		{
			name: "mount target with docker option separator",
			edit: func(job *DeployJob) { job.Mounts[0].Target = "/data,ro" },
			want: "invalid mount path",
		},
		{
			name: "mount target with control character",
			edit: func(job *DeployJob) { job.Mounts[0].Target = "/data\tlogs" },
			want: "invalid mount path",
		},
		{
			name: "relative mount target",
			edit: func(job *DeployJob) { job.Mounts[0].Target = "data" },
			want: "mount target must be absolute",
		},
		{
			name: "root mount target",
			edit: func(job *DeployJob) { job.Mounts[0].Target = "/" },
			want: "mount target is unsafe",
		},
		{
			name: "sensitive mount target",
			edit: func(job *DeployJob) { job.Mounts[0].Target = "/proc/luma" },
			want: "mount target is unsafe",
		},
		{
			name: "duplicate mount target",
			edit: func(job *DeployJob) {
				job.Mounts = append(job.Mounts, struct {
					Source   string `json:"source"`
					Target   string `json:"target"`
					ReadOnly bool   `json:"readOnly"`
				}{
					Source: "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/other",
					Target: "/data/../data",
				})
			},
			want: "overlapping mount target",
		},
		{
			name: "nested mount target",
			edit: func(job *DeployJob) {
				job.Mounts = append(job.Mounts, struct {
					Source   string `json:"source"`
					Target   string `json:"target"`
					ReadOnly bool   `json:"readOnly"`
				}{
					Source: "/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/config",
					Target: "/data/config",
				})
			},
			want: "overlapping mount target",
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
			name: "duplicate published port",
			edit: func(job *DeployJob) {
				job.Ports = append(job.Ports, struct {
					HostPort      int    `json:"hostPort"`
					ContainerPort int    `json:"containerPort"`
					Protocol      string `json:"protocol"`
				}{HostPort: 8080, ContainerPort: 8081, Protocol: "tcp"})
			},
			want: "duplicate published port",
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
			name: "environment value with control character",
			edit: func(job *DeployJob) { job.Env["SAFE_KEY"] = "value\twith-tab" },
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
			name: "reserved tenant environment override",
			edit: func(job *DeployJob) { job.Env["LUMA_TENANT_ID"] = "tenant_other" },
			want: "reserved LUMA environment variables",
		},
		{
			name: "reserved deployment environment override",
			edit: func(job *DeployJob) { job.Env["LUMA_DEPLOYMENT_ID"] = "dep_other" },
			want: "reserved LUMA environment variables",
		},
		{
			name: "reserved node environment override",
			edit: func(job *DeployJob) { job.Env["LUMA_NODE_ID"] = "node_other" },
			want: "reserved LUMA environment variables",
		},
		{
			name: "unsupported LUMA environment variable",
			edit: func(job *DeployJob) { job.Env["LUMA_IMAGE_HINT"] = "spoofed" },
			want: "unsupported LUMA environment variable",
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
			want: "drop only all Linux capabilities",
		},
		{
			name: "extra capability drops",
			edit: func(job *DeployJob) { job.Security.DroppedCapabilities = []string{"ALL", "NET_RAW"} },
			want: "drop only all Linux capabilities",
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
			name: "path traversal seccomp profile",
			edit: func(job *DeployJob) { job.Security.SeccompProfile = "../lumapanel-default" },
			want: "seccomp and AppArmor",
		},
		{
			name: "absolute apparmor profile path",
			edit: func(job *DeployJob) { job.Security.AppArmorProfile = "/lumapanel-tenant" },
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
			name: "reserved node label override",
			edit: func(job *DeployJob) { job.Labels["luma.node"] = "node_other" },
			want: "reserved LUMA labels",
		},
		{
			name: "unsupported luma label",
			edit: func(job *DeployJob) { job.Labels["luma.image_hint"] = "spoofed" },
			want: "unsupported LUMA Docker label",
		},
		{
			name: "invalid docker label",
			edit: func(job *DeployJob) { job.Labels["bad\nkey"] = "value" },
			want: "invalid Docker label",
		},
		{
			name: "docker label key with space",
			edit: func(job *DeployJob) { job.Labels["bad key"] = "value" },
			want: "invalid Docker label",
		},
		{
			name: "docker label key with separator edge",
			edit: func(job *DeployJob) { job.Labels["bad."] = "value" },
			want: "invalid Docker label",
		},
		{
			name: "docker label value with control character",
			edit: func(job *DeployJob) { job.Labels["safe.label"] = "value\twith-tab" },
			want: "invalid Docker label",
		},
		{
			name: "too many docker labels",
			edit: func(job *DeployJob) {
				for i := 0; i <= maxContainerLabels; i++ {
					job.Labels[fmt.Sprintf("example.label.%d", i)] = "value"
				}
			},
			want: "too many Docker labels",
		},
		{
			name: "invalid egress mode",
			edit: func(job *DeployJob) { job.Egress.Mode = "internet" },
			want: "invalid egress mode",
		},
		{
			name: "deny all with egress rules",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "deny-all"
				job.Egress.Rules = []EgressPolicyRule{{Protocol: "tcp", DestinationCIDR: "10.0.0.1/32", Port: 443}}
			},
			want: "deny-all egress policy cannot include rules",
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
			name: "non-canonical egress cidr",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = []EgressPolicyRule{{Protocol: "tcp", DestinationCIDR: "10.0.0.1/24", Port: 443}}
			},
			want: "non-canonical egress destination CIDR",
		},
		{
			name: "ipv6 egress cidr",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = []EgressPolicyRule{{Protocol: "tcp", DestinationCIDR: "2001:db8::/32", Port: 443}}
			},
			want: "egress destination CIDR must be IPv4",
		},
		{
			name: "invalid egress port",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = []EgressPolicyRule{{Protocol: "tcp", DestinationCIDR: "0.0.0.0/0", Port: 0}}
			},
			want: "invalid egress port",
		},
		{
			name: "duplicate egress rule",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = []EgressPolicyRule{
					{Protocol: "tcp", DestinationCIDR: "10.0.0.1/32", Port: 443},
					{Protocol: "tcp", DestinationCIDR: "10.0.0.1/32", Port: 443},
				}
			},
			want: "duplicate egress rule",
		},
		{
			name: "too many egress rules",
			edit: func(job *DeployJob) {
				job.Egress.Mode = "restricted"
				job.Egress.Rules = nil
				for i := 0; i <= maxEgressPolicyRules; i++ {
					job.Egress.Rules = append(job.Egress.Rules, EgressPolicyRule{
						Protocol:        "tcp",
						DestinationCIDR: fmt.Sprintf("10.10.%d.%d/32", i/256, i%256),
						Port:            443,
					})
				}
			},
			want: "too many egress rules",
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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo runc
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
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
  if [ "$3" = "{{.OSType}}" ]; then
    echo linux
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
	t.Setenv("DOCKER_ROOT_DIR", tempDir)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if !status.Ready || !status.Docker || !status.DockerCgroupV2 || !status.DockerCgroupDriverSystemd || !status.DockerDebugDisabled || !status.DockerExperimentalDisabled || !status.DockerSwarmInactive || !status.DockerOomKillEnabled || !status.DockerIPv4Forwarding || !status.DockerBridgeNfIptables || !status.DockerBridgeNfIp6tables || !status.DockerLiveRestore || !status.DockerDefaultRuntimeRunc || !status.DockerNoWarnings || !status.DockerRootDirProtected || !status.DockerStorageOverlay2 || !status.DockerStorageDType || !status.DockerServerVersionSupported || !status.DockerOSTypeLinux || !status.DockerLocalEndpoint || !status.DockerSocketProtected || !status.Nftables || !status.NftablesUsable || !status.CgroupV2 || !status.CgroupControllersReady {
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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo runc
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
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
  if [ "$3" = "{{.OSType}}" ]; then
    echo linux
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
	t.Setenv("DOCKER_ROOT_DIR", tempDir)

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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo runc
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
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
  if [ "$3" = "{{.OSType}}" ]; then
    echo linux
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
	t.Setenv("DOCKER_ROOT_DIR", tempDir)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready || !status.DockerLocalEndpoint || status.DockerSocketProtected {
		t.Fatalf("expected world-writable Docker socket to fail runtime readiness, got %#v", status)
	}
	if status.Errors["dockerSocket"] == "" {
		t.Fatalf("expected Docker socket error, got %#v", status.Errors)
	}
}

func TestDockerSocketProtectedRejectsSymlink(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	defer listener.Close()
	linkPath := filepath.Join(tempDir, "docker-link.sock")
	if err := os.Symlink(socketPath, linkPath); err != nil {
		t.Fatalf("create socket symlink: %v", err)
	}
	protected, err := dockerSocketProtected("unix://" + linkPath)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") || protected {
		t.Fatalf("expected docker socket symlink rejection, protected=%v err=%v", protected, err)
	}
}

func TestDockerSocketProtectedRejectsRelativePath(t *testing.T) {
	protected, err := dockerSocketProtected("unix://docker.sock")
	if err == nil || !strings.Contains(err.Error(), "not absolute") || protected {
		t.Fatalf("expected relative docker socket path rejection, protected=%v err=%v", protected, err)
	}
}

func TestRuntimeStatusRejectsWorldWritableDockerRootDir(t *testing.T) {
	tempDir := t.TempDir()
	cgroupFile := filepath.Join(tempDir, "cgroup.controllers")
	if err := os.WriteFile(cgroupFile, []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatalf("write cgroup controllers: %v", err)
	}
	rootDir := filepath.Join(tempDir, "docker-root")
	if err := os.Mkdir(rootDir, 0o777); err != nil {
		t.Fatalf("create docker root dir: %v", err)
	}
	if err := os.Chmod(rootDir, 0o777); err != nil {
		t.Fatalf("chmod docker root dir: %v", err)
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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo runc
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
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
  if [ "$3" = "{{.OSType}}" ]; then
    echo linux
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
	t.Setenv("DOCKER_ROOT_DIR", rootDir)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready || status.DockerRootDirProtected {
		t.Fatalf("expected world-writable Docker root directory to fail runtime readiness, got %#v", status)
	}
	if status.Errors["dockerRootDir"] == "" {
		t.Fatalf("expected Docker root directory error, got %#v", status.Errors)
	}
}

func TestDockerRootDirProtectedRejectsGroupWritableDirectory(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "docker-root")
	if err := os.Mkdir(rootDir, 0o770); err != nil {
		t.Fatalf("create docker root dir: %v", err)
	}
	if err := os.Chmod(rootDir, 0o770); err != nil {
		t.Fatalf("chmod docker root dir: %v", err)
	}
	protected, err := dockerRootDirProtected(rootDir)
	if err != nil || protected {
		t.Fatalf("expected group-writable Docker root directory to be unprotected, protected=%v err=%v", protected, err)
	}
}

func TestDockerRootDirProtectedRejectsSymlink(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "docker-root")
	if err := os.Mkdir(rootDir, 0o700); err != nil {
		t.Fatalf("create docker root dir: %v", err)
	}
	linkPath := filepath.Join(tempDir, "docker-root-link")
	if err := os.Symlink(rootDir, linkPath); err != nil {
		t.Fatalf("create docker root symlink: %v", err)
	}
	protected, err := dockerRootDirProtected(linkPath)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") || protected {
		t.Fatalf("expected docker root symlink rejection, protected=%v err=%v", protected, err)
	}
}

func TestRuntimeStatusRequiresCgroupControllers(t *testing.T) {
	tempDir := t.TempDir()
	cgroupFile := filepath.Join(tempDir, "cgroup.controllers")
	if err := os.WriteFile(cgroupFile, []byte("cpu memory\n"), 0o600); err != nil {
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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo runc
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
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
  if [ "$3" = "{{.OSType}}" ]; then
    echo linux
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
	t.Setenv("DOCKER_ROOT_DIR", tempDir)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready || !status.CgroupV2 || status.CgroupControllersReady {
		t.Fatalf("expected missing cgroup controllers to fail runtime readiness, got %#v", status)
	}
	if status.Errors["cgroupControllers"] == "" || !strings.Contains(status.Errors["cgroupControllers"], "pids") {
		t.Fatalf("expected missing pids cgroup controller error, got %#v", status.Errors)
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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo false
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo kata
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[\"WARNING: No swap limit support\"]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
    exit 0
  fi
  if [ "$3" = "{{.Driver}}" ]; then
    echo aufs
    exit 0
  fi
  if [ "$3" = "{{.OSType}}" ]; then
    echo windows
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
	t.Setenv("DOCKER_ROOT_DIR", tempDir)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready {
		t.Fatalf("expected runtime status to fail without Docker seccomp/AppArmor, got %#v", status)
	}
	if status.DockerSeccomp || status.DockerAppArmor || status.DockerUserNamespace || status.DockerCgroupDriverSystemd || status.DockerDebugDisabled || status.DockerExperimentalDisabled || status.DockerSwarmInactive || status.DockerOomKillEnabled || status.DockerIPv4Forwarding || status.DockerBridgeNfIptables || status.DockerBridgeNfIp6tables || status.DockerLiveRestore || status.DockerDefaultRuntimeRunc || status.DockerNoWarnings || !status.DockerRootDirProtected || status.DockerStorageOverlay2 || status.DockerStorageDType || status.DockerServerVersionSupported || status.DockerOSTypeLinux {
		t.Fatalf("expected missing Docker seccomp/AppArmor/userns/live-restore/storage/version support, got %#v", status)
	}
	if status.Errors["dockerSeccomp"] == "" || status.Errors["dockerAppArmor"] == "" || status.Errors["dockerUserNamespace"] == "" || status.Errors["dockerCgroupDriver"] == "" || status.Errors["dockerDebug"] == "" || status.Errors["dockerExperimental"] == "" || status.Errors["dockerSwarm"] == "" || status.Errors["dockerOomKill"] == "" || status.Errors["dockerIPv4Forwarding"] == "" || status.Errors["dockerBridgeNfIptables"] == "" || status.Errors["dockerBridgeNfIp6tables"] == "" || status.Errors["dockerLiveRestore"] == "" || status.Errors["dockerDefaultRuntime"] == "" || status.Errors["dockerWarnings"] == "" || status.Errors["dockerStorageOverlay2"] == "" || status.Errors["dockerStorageDType"] == "" || status.Errors["dockerServerVersion"] == "" || status.Errors["dockerOSType"] == "" {
		t.Fatalf("expected Docker security option errors, got %#v", status.Errors)
	}
}

func TestDockerWarningsEmpty(t *testing.T) {
	if !dockerWarningsEmpty("[]") || !dockerWarningsEmpty("null") || !dockerWarningsEmpty("") {
		t.Fatal("expected empty, null, and blank Docker warnings to pass")
	}
	if dockerWarningsEmpty(`["WARNING: No swap limit support"]`) {
		t.Fatal("expected Docker warnings to fail readiness")
	}
	if dockerWarningsEmpty("not-json") {
		t.Fatal("expected malformed Docker warnings output to fail readiness")
	}
}

func TestRuntimeStatusRequiresUsableNftables(t *testing.T) {
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
  if [ "$3" = "{{.IPv4Forwarding}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIptables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.BridgeNfIp6tables}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.LiveRestoreEnabled}}" ]; then
    echo true
    exit 0
  fi
  if [ "$3" = "{{.DefaultRuntime}}" ]; then
    echo runc
    exit 0
  fi
  if [ "$3" = "{{json .Warnings}}" ]; then
    echo "[]"
    exit 0
  fi
  if [ "$3" = "{{.DockerRootDir}}" ]; then
    echo "$DOCKER_ROOT_DIR"
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
  if [ "$3" = "{{.OSType}}" ]; then
    echo linux
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
	writeFakeCommand(t, tempDir, "nft", `#!/bin/sh
if [ "$1" = "list" ] && [ "$2" = "ruleset" ]; then
  echo "Operation not permitted"
  exit 1
fi
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_ROOT_DIR", tempDir)

	agent := New(config.Config{NodeID: "node_local", RuntimeCgroupControllersFile: cgroupFile}, slog.Default())
	status := agent.runtimeStatus(context.Background())
	if status.Ready || !status.Nftables || status.NftablesUsable {
		t.Fatalf("expected unusable nftables to fail runtime readiness, got %#v", status)
	}
	if status.Errors["nftablesUsable"] == "" {
		t.Fatalf("expected nftables usability error, got %#v", status.Errors)
	}
}

func TestMissingRequiredCgroupControllers(t *testing.T) {
	if missing := missingRequiredCgroupControllers("cpu memory pids io"); len(missing) != 0 {
		t.Fatalf("expected all required controllers to pass, got %v", missing)
	}
	missing := missingRequiredCgroupControllers("memory")
	if strings.Join(missing, ",") != "cpu,pids" {
		t.Fatalf("expected missing cpu,pids, got %v", missing)
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

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}

	t.Setenv("DOCKER_LABEL_OUTPUT", "false dep_test tenant_demo node_local")
	err = removeExistingContainer(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unmanaged container") {
		t.Fatalf("expected unmanaged container refusal, got %v", err)
	}
	if _, readErr := os.ReadFile(logFile); !os.IsNotExist(readErr) {
		t.Fatalf("expected docker rm not to run for unmanaged container, readErr=%v", readErr)
	}

	t.Setenv("DOCKER_LABEL_OUTPUT", "true dep_test tenant_demo node_other")
	err = removeExistingContainer(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unmanaged container") {
		t.Fatalf("expected mismatched node label refusal, got %v", err)
	}
	if _, readErr := os.ReadFile(logFile); !os.IsNotExist(readErr) {
		t.Fatalf("expected docker rm not to run for mismatched node label, readErr=%v", readErr)
	}

	t.Setenv("DOCKER_LABEL_OUTPUT", "true dep_test tenant_demo node_local")
	if err := removeExistingContainer(context.Background(), plan); err != nil {
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *json\ .*)
      echo '{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g '\''daemon off;'\''"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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

func TestExecuteDeploymentPlanRemovesStartedContainerWhenEgressVerificationFails(t *testing.T) {
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *json\ .*)
      echo '{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g '\''daemon off;'\''"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
    *NetworkSettings.Networks*)
      echo "172.18.0.4"
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
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
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
	if err == nil || !strings.Contains(err.Error(), "missing deployment rule") {
		t.Fatalf("expected egress verification failure, got %v", err)
	}
	content, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(content), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected failed egress verification to remove started container, got %q", string(content))
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanCleansPartialEgressRulesAfterVerificationFailure(t *testing.T) {
	tempDir := t.TempDir()
	dockerLog := filepath.Join(tempDir, "docker.log")
	nftLog := filepath.Join(tempDir, "nft.log")
	stateFile := filepath.Join(tempDir, "container-state")
	egressApplied := filepath.Join(tempDir, "egress-applied")
	egressCleaned := filepath.Join(tempDir, "egress-cleaned")
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *json\ .*)
      echo '{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g '\''daemon off;'\''"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
        exit 0
      fi
      echo "No such container" >&2
      exit 1
      ;;
    *NetworkSettings.Networks*)
      echo "172.18.0.4"
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
printf '%s\n' "$*" >> "$NFT_LOG"
if [ "$1" = "-a" ] && [ "$6" = "input" ]; then
  exit 0
fi
if [ "$1" = "-a" ] && [ "$6" = "forward" ]; then
  if [ -f "$EGRESS_CLEANED" ]; then
    exit 0
  fi
  if [ -f "$EGRESS_APPLIED" ]; then
    echo 'ip saddr 172.18.0.4 drop comment "luma:dep_test:egress:drop" # handle 55'
    echo 'ip saddr 172.18.0.4 ip daddr 203.0.113.10 tcp dport 443 counter accept comment "luma:dep_test:egress:stale" # handle 56'
  fi
  exit 0
fi
if [ "$1" = "add" ] && [ "$5" = "forward" ]; then
  touch "$EGRESS_APPLIED"
  exit 0
fi
if [ "$1" = "delete" ] && [ "$5" = "forward" ]; then
  if [ "$7" = "55" ] || [ "$7" = "56" ]; then
    touch "$EGRESS_CLEANED"
  fi
  exit 0
fi
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", dockerLog)
	t.Setenv("NFT_LOG", nftLog)
	t.Setenv("CONTAINER_STATE", stateFile)
	t.Setenv("EGRESS_APPLIED", egressApplied)
	t.Setenv("EGRESS_CLEANED", egressCleaned)

	job := sampleJob()
	job.Egress.Mode = "deny-all"
	plan, err := deploymentPlan(job)
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = executeDeploymentPlan(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unexpected deployment rule") {
		t.Fatalf("expected egress verification failure, got %v", err)
	}
	dockerContent, readErr := os.ReadFile(dockerLog)
	if readErr != nil {
		t.Fatalf("read docker log: %v", readErr)
	}
	if !strings.Contains(string(dockerContent), "rm --force --volumes luma-dep_test") {
		t.Fatalf("expected failed egress verification to remove started container, got %q", string(dockerContent))
	}
	nftContent, readErr := os.ReadFile(nftLog)
	if readErr != nil {
		t.Fatalf("read nft log: %v", readErr)
	}
	nftText := string(nftContent)
	if !strings.Contains(nftText, "delete rule inet lumapanel forward handle 55") {
		t.Fatalf("expected cleanup to delete applied egress drop rule, got %q", nftText)
	}
	if !strings.Contains(nftText, "delete rule inet lumapanel forward handle 56") {
		t.Fatalf("expected cleanup to delete unexpected egress rule, got %q", nftText)
	}
	if _, statErr := os.Stat(stateFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cleanup to remove container state, statErr=%v", statErr)
	}
}

func TestExecuteDeploymentPlanPrunesStaleEgressRulesForAllowAllRedeploy(t *testing.T) {
	tempDir := t.TempDir()
	dockerLog := filepath.Join(tempDir, "docker.log")
	nftLog := filepath.Join(tempDir, "nft.log")
	egressDeleted := filepath.Join(tempDir, "egress-deleted")
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *json\ .*)
      echo '{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g '\''daemon off;'\''"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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
  if [ -f "$EGRESS_DELETED" ]; then
    exit 0
  fi
  echo 'ip saddr 172.18.0.4 drop comment "luma:dep_test:egress:drop" # handle 55'
  exit 0
fi
if [ "$1" = "delete" ] && [ "$5" = "forward" ] && [ "$7" = "55" ]; then
  touch "$EGRESS_DELETED"
fi
exit 0
`)
	previousPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+previousPath)
	t.Setenv("DOCKER_LOG", dockerLog)
	t.Setenv("NFT_LOG", nftLog)
	t.Setenv("EGRESS_DELETED", egressDeleted)
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *json\ .*)
      echo '{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g '\''daemon off;'\''"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false unhealthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *json\ .*)
      echo '{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g '\''daemon off;'\''"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false starting true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_other tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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

func TestWaitForStartedContainerHealthyRejectsNodeLabelDrift(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "true false false false false healthy true dep_test tenant_demo node_other 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = waitForStartedContainerHealthy(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "ownership labels") {
		t.Fatalf("expected node ownership label verification failure, got %v", err)
	}
}

func TestStartedContainerStateRejectsUnsafeRuntimeStates(t *testing.T) {
	cases := []struct {
		name   string
		output string
	}{
		{name: "paused", output: "true true false false false healthy true dep_test tenant_demo node_local 0"},
		{name: "restarting", output: "true false true false false healthy true dep_test tenant_demo node_local 0"},
		{name: "dead", output: "true false false true false healthy true dep_test tenant_demo node_local 0"},
		{name: "oom-killed", output: "true false false false true healthy true dep_test tenant_demo node_local 0"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo %q
  exit 0
fi
exit 1
`, tt.output))
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			if err := verifyStartedContainer(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "unsafe runtime state") {
				t.Fatalf("expected unsafe runtime state verification failure, got %v", err)
			}
			if err := waitForStartedContainerHealthy(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "unsafe runtime state") {
				t.Fatalf("expected unsafe runtime state health wait failure, got %v", err)
			}
		})
	}
}

func TestStartedContainerStateRejectsMalformedBooleanFields(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{name: "running", output: "yes false false false false healthy true dep_test tenant_demo node_local 0", contains: "boolean"},
		{name: "paused", output: "true maybe false false false healthy true dep_test tenant_demo node_local 0", contains: "boolean"},
		{name: "managed-label", output: "true false false false false healthy <no-value> dep_test tenant_demo node_local 0", contains: "boolean"},
		{name: "restart-count", output: "true false false false false healthy true dep_test tenant_demo node_local invalid", contains: "restart count"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo %q
  exit 0
fi
exit 1
`, tt.output))
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			_, err := inspectStartedContainerState(context.Background(), "luma-dep_test")
			if err == nil || !strings.Contains(err.Error(), "invalid") || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected malformed %s failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestStartedContainerStateRejectsRestartCountDrift(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "true false false false false healthy true dep_test tenant_demo node_local 1"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if err := verifyStartedContainer(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "restarted unexpectedly") {
		t.Fatalf("expected restart count verification failure, got %v", err)
	}
	if err := waitForStartedContainerHealthy(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "restarted unexpectedly") {
		t.Fatalf("expected restart count health wait failure, got %v", err)
	}
}

func TestVerifyStartedContainerHealthcheckRequiresExpectedConfig(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "missing",
			output:   "null",
			contains: "missing expected healthcheck",
		},
		{
			name:     "command",
			output:   `{"Test":["CMD-SHELL","curl -fsS http://127.0.0.2"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}`,
			contains: "healthcheck command",
		},
		{
			name:     "interval",
			output:   `{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":60000000000,"Timeout":5000000000,"Retries":3}`,
			contains: "healthcheck timing",
		},
		{
			name:     "timeout",
			output:   `{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":10000000000,"Retries":3}`,
			contains: "healthcheck timing",
		},
		{
			name:     "retries",
			output:   `{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":10}`,
			contains: "healthcheck timing",
		},
		{
			name:     "start-period",
			output:   `{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3,"StartPeriod":60000000000}`,
			contains: "healthcheck timing",
		},
		{
			name:     "start-interval",
			output:   `{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3,"StartInterval":1000000000}`,
			contains: "healthcheck timing",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then\n  echo '"+tt.output+"'\n  exit 0\nfi\nexit 1\n")
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerHealthcheck(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %s verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerHealthcheckRejectsInheritedImageHealthcheck(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\n' "$DOCKER_HEALTHCHECK_OUTPUT"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Healthcheck = ""

	t.Setenv("DOCKER_HEALTHCHECK_OUTPUT", `{"Test":["CMD-SHELL","curl -fsS http://image.local"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}`)
	err = verifyStartedContainerHealthcheck(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "unexpected image healthcheck") {
		t.Fatalf("expected inherited image healthcheck rejection, got %v", err)
	}

	t.Setenv("DOCKER_HEALTHCHECK_OUTPUT", "null")
	if err := verifyStartedContainerHealthcheck(context.Background(), plan); err != nil {
		t.Fatalf("expected absent healthcheck to pass when none is signed, got %v", err)
	}
}

func TestVerifyStartedContainerWorkloadRequiresSignedCommandAndEnvironment(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "entrypoint",
			output:   `{"Config":{"Entrypoint":["/docker-entrypoint.sh"],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "unexpected image entrypoint",
		},
		{
			name:     "command",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","sleep 999"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "startup command",
		},
		{
			name:     "image-shell",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"Shell":["/bin/bash","-c"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "unexpected image shell",
		},
		{
			name:     "working-dir",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/app","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "working directory",
		},
		{
			name:     "hostname-override",
			output:   `{"Id":"aabbccddeeff00112233445566778899","Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Hostname":"custom-host","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "hostname override",
		},
		{
			name:     "open-stdin",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","OpenStdin":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "interactive console settings",
		},
		{
			name:     "stdin-once",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","StdinOnce":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "interactive console settings",
		},
		{
			name:     "tty",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Tty":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "interactive console settings",
		},
		{
			name:     "attach-stdin",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","AttachStdin":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "attach stream settings",
		},
		{
			name:     "attach-stdout",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","AttachStdout":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "attach stream settings",
		},
		{
			name:     "attach-stderr",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","AttachStderr":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "attach stream settings",
		},
		{
			name:     "network-disabled",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","NetworkDisabled":true,"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: "networking disabled",
		},
		{
			name:     "unexpected-luma-label",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo","luma.image_hint":"spoofed"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `unexpected LUMA label "luma.image_hint"`,
		},
		{
			name:     "drifted-luma-label",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_other","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `drifted LUMA label "luma.deployment"`,
		},
		{
			name:     "missing-luma-label",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `expected LUMA label "luma.template"`,
		},
		{
			name:     "invalid-effective-label",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo","bad/label":"value"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `invalid effective Docker label "bad/label"`,
		},
		{
			name:     "unexpected-exposed-port",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"ExposedPorts":{"80/tcp":{},"25565/tcp":{}},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `unexpected exposed port "25565/tcp"`,
		},
		{
			name:     "unexpected-image-volume",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Volumes":{"/cache":{}},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `unexpected image volume "/cache"`,
		},
		{
			name:     "signed-env",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_other"]}}`,
			contains: `environment variable "LUMA_TENANT_ID"`,
		},
		{
			name:     "reserved-env",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_other","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `environment variable "LUMA_DEPLOYMENT_ID"`,
		},
		{
			name:     "malformed-env",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo","BROKEN"]}}`,
			contains: "malformed environment entry",
		},
		{
			name:     "invalid-effective-env",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo","IMAGE.ENV=value"]}}`,
			contains: `invalid effective environment variable "IMAGE.ENV"`,
		},
		{
			name:     "duplicate-env",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo","LUMA_TENANT_ID=tenant_demo"]}}`,
			contains: `duplicate environment variable "LUMA_TENANT_ID"`,
		},
		{
			name:     "unexpected-luma-env",
			output:   `{"Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Env":["LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo","LUMA_IMAGE_HINT=spoofed"]}}`,
			contains: `unexpected LUMA environment variable "LUMA_IMAGE_HINT"`,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\n' "$DOCKER_WORKLOAD_OUTPUT"
  exit 0
fi
exit 1
`)
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("DOCKER_WORKLOAD_OUTPUT", tt.output)
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerWorkload(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %s verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerWorkloadAllowsImageEnvironmentWithoutReservedDrift(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\n' "$DOCKER_WORKLOAD_OUTPUT"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_WORKLOAD_OUTPUT", `{"Id":"aabbccddeeff00112233445566778899","Config":{"Entrypoint":[],"Cmd":["sh","-lc","nginx -g 'daemon off;'"],"WorkingDir":"/","Hostname":"aabbccddeeff","Labels":{"luma.managed":"true","luma.deployment":"dep_test","luma.tenant":"tenant_demo","luma.node":"node_local","luma.template":"tmpl_demo"},"Volumes":{"/data":{}},"Env":["PATH=/usr/local/bin","LUMA_DEPLOYMENT_ID=dep_test","LUMA_NODE_ID=node_local","LUMA_TENANT_ID=tenant_demo"]}}`)
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if err := verifyStartedContainerWorkload(context.Background(), plan); err != nil {
		t.Fatalf("expected workload verification to allow non-reserved image environment, got %v", err)
	}
}

func TestVerifyStartedContainerWorkloadRejectsExcessiveEffectiveEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\n' "$DOCKER_WORKLOAD_OUTPUT"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	env := []string{
		"LUMA_DEPLOYMENT_ID=dep_test",
		"LUMA_NODE_ID=node_local",
		"LUMA_TENANT_ID=tenant_demo",
	}
	for i := 0; len(env) <= maxContainerEffectiveEnvVars; i++ {
		env = append(env, fmt.Sprintf("IMAGE_ENV_%03d=value", i))
	}
	output, err := json.Marshal(map[string]any{
		"Config": map[string]any{
			"Entrypoint": []string{},
			"Cmd":        []string{"sh", "-lc", "nginx -g 'daemon off;'"},
			"WorkingDir": "/",
			"Labels": map[string]string{
				"luma.managed":    "true",
				"luma.deployment": "dep_test",
				"luma.tenant":     "tenant_demo",
				"luma.node":       "node_local",
				"luma.template":   "tmpl_demo",
			},
			"Env": env,
		},
	})
	if err != nil {
		t.Fatalf("marshal workload output: %v", err)
	}
	t.Setenv("DOCKER_WORKLOAD_OUTPUT", string(output))

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerWorkload(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "too many effective environment variables") {
		t.Fatalf("expected effective environment cap failure, got %v", err)
	}
}

func TestVerifyStartedContainerWorkloadRejectsExcessiveEffectiveLabels(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\n' "$DOCKER_WORKLOAD_OUTPUT"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	labels := map[string]string{
		"luma.managed":    "true",
		"luma.deployment": "dep_test",
		"luma.tenant":     "tenant_demo",
		"luma.node":       "node_local",
		"luma.template":   "tmpl_demo",
	}
	for i := 0; len(labels) <= maxContainerEffectiveLabels; i++ {
		labels[fmt.Sprintf("image.label.%03d", i)] = "value"
	}
	output, err := json.Marshal(map[string]any{
		"Config": map[string]any{
			"Entrypoint": []string{},
			"Cmd":        []string{"sh", "-lc", "nginx -g 'daemon off;'"},
			"WorkingDir": "/",
			"Labels":     labels,
			"Env": []string{
				"LUMA_DEPLOYMENT_ID=dep_test",
				"LUMA_NODE_ID=node_local",
				"LUMA_TENANT_ID=tenant_demo",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal workload output: %v", err)
	}
	t.Setenv("DOCKER_WORKLOAD_OUTPUT", string(output))

	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerWorkload(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "too many effective Docker labels") {
		t.Fatalf("expected effective label cap failure, got %v", err)
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "true true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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

func TestVerifyStartedContainerIsolationRequiresInit(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no false 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "init process") {
		t.Fatalf("expected init verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresPrivateUserNamespace(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private host private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "private user namespace") {
		t.Fatalf("expected private user namespace verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresPrivatePidAndUTSNamespaces(t *testing.T) {
	cases := []struct {
		name   string
		output string
	}{
		{
			name:   "host-pid",
			output: "false true 512 none private private host private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
		},
		{
			name:   "host-uts",
			output: "false true 512 none private private private host no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then\n  echo \""+tt.output+"\"\n  exit 0\nfi\nexit 1\n")
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerIsolation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), "private PID/UTS namespace") {
				t.Fatalf("expected private PID/UTS namespace verification failure, got %v", err)
			}
		})
	}
}

func TestVerifyStartedContainerIsolationRequiresExactCapabilityDropPolicy(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL,NET_RAW, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "exact drop-all capability") {
		t.Fatalf("expected exact capability-drop verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresExactSecurityOptions(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant,label=disable, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "exact security options") {
		t.Fatalf("expected exact security option verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerImageRejectsTagDrift(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "nginx:latest"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerImage(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "expected image reference") {
		t.Fatalf("expected image reference drift verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsHostIntegrations(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "cap-add",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none NET_ADMIN, none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "added capabilities",
		},
		{
			name:     "group-add",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none docker, 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "supplemental groups",
		},
		{
			name:     "devices",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 1 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "host device access",
		},
		{
			name:     "device-requests",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 1 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "host device access",
		},
		{
			name:     "device-cgroup-rules",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 1",
			contains: "device cgroup rules",
		},
		{
			name:     "volumes-from",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 dep_db, none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "inherited host mounts",
		},
		{
			name:     "binds",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none /host:/container, none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "inherited host mounts",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then\n  echo \""+tt.output+"\"\n  exit 0\nfi\nexit 1\n")
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			plan.Ports = nil
			err = verifyStartedContainerIsolation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %s verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerIsolationRejectsRuntimeTuning(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "cgroup-parent",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none custom.slice 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "cgroup parent",
		},
		{
			name:     "sysctls",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 1 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "sysctls",
		},
		{
			name:     "runtime",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 nvidia none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "runtime",
		},
		{
			name:     "isolation",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none hyperv 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "isolation mode",
		},
		{
			name:     "oom-score-adj",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none -500 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "OOM score adjustment",
		},
		{
			name:     "ulimits",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 1 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "ulimits",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then\n  echo \""+tt.output+"\"\n  exit 0\nfi\nexit 1\n")
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			plan.Ports = nil
			err = verifyStartedContainerIsolation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %s verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerIsolationRequiresStopTimeout(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 5 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "stop timeout") {
		t.Fatalf("expected stop timeout verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresStopSignal(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGKILL /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	plan.Ports = nil
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "stop signal") {
		t.Fatalf("expected stop signal verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresKernelPathProtections(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "masked-paths",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM none /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "masked kernel path protections",
		},
		{
			name:     "partial-masked-paths",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "masked kernel path protections",
		},
		{
			name:     "readonly-paths",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, none 0",
			contains: "read-only kernel path protections",
		},
		{
			name:     "partial-readonly-paths",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys, 0",
			contains: "read-only kernel path protections",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo %q
  exit 0
fi
exit 1
`, tt.output))
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			plan.Ports = nil
			err = verifyStartedContainerIsolation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %s verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerIsolationRequiresAutoRemoveDisabled(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 true false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "automatic removal") {
		t.Fatalf("expected automatic removal verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresOomKillEnabled(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false true luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "OOM killing enabled") {
		t.Fatalf("expected OOM kill verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRequiresPublishAllPortsDisabled(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false true false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "publish-all-ports") {
		t.Fatalf("expected publish-all-ports verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsNetworkDisabled(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0 true"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "networking disabled") {
		t.Fatalf("expected network-disabled verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsVolumeDriver(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0 false nfs"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "volume driver") {
		t.Fatalf("expected volume-driver verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsInitPath(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0 false none /host/tini"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "init path") {
		t.Fatalf("expected init-path verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsContainerIDFile(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0 false none none /host/container.id"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "container ID file") {
		t.Fatalf("expected container-id-file verification failure, got %v", err)
	}
}

func TestContainerPortBindingsMatchSignedPlan(t *testing.T) {
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if !containerPortBindingsMatch(plan.Ports, "80/tcp=8080;,") {
		t.Fatal("expected signed TCP port binding to match Docker inspect output")
	}
	if !containerPortBindingsMatch(plan.Ports, "80/tcp=0.0.0.0:8080;,") {
		t.Fatal("expected wildcard host IP port binding to match Docker inspect output")
	}
	if !containerPortBindingsMatch(plan.Ports, "80/tcp=:::8080;,") {
		t.Fatal("expected IPv6 wildcard host IP port binding to match Docker inspect output")
	}
	if containerPortBindingsMatch(plan.Ports, "80/tcp=127.0.0.1:8080;,") {
		t.Fatal("expected narrowed host IP port binding to fail")
	}
	if containerPortBindingsMatch(plan.Ports, "80/tcp=9090;,") {
		t.Fatal("expected mismatched host port binding to fail")
	}
	if containerPortBindingsMatch(plan.Ports, "80/tcp=8080;,443/tcp=8443;,") {
		t.Fatal("expected unexpected extra port binding to fail")
	}
	if !containerPortBindingsMatch(nil, "none") {
		t.Fatal("expected empty signed port plan to match empty Docker bindings")
	}
}

func TestVerifyStartedContainerIsolationRejectsLinksAndExtraHosts(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "links",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, dep_db:/db, none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "Docker links",
		},
		{
			name:     "extra-hosts",
			output:   "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none db.internal:10.0.0.5, none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
			contains: "extra host aliases",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo %q
  exit 0
fi
exit 1
`, tt.output))
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerIsolation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %q verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerIsolationRejectsDNSOverrides(t *testing.T) {
	cases := []struct {
		name   string
		output string
	}{
		{
			name:   "dns-server",
			output: "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none 1.1.1.1, none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
		},
		{
			name:   "dns-search",
			output: "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none example.internal, none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
		},
		{
			name:   "dns-options",
			output: "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none ndots:0, none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo %q
  exit 0
fi
exit 1
`, tt.output))
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerIsolation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), "DNS overrides") {
				t.Fatalf("expected DNS override verification failure, got %v", err)
			}
		})
	}
}

func TestVerifyStartedContainerIsolationAllowsDockerGeneratedHostname(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none aabbccddeeff none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	if err := verifyStartedContainerIsolation(context.Background(), plan); err != nil {
		t.Fatalf("expected Docker-generated hostname to pass isolation verification, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsDomainnameOverride(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none example.internal none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "domainname override") {
		t.Fatalf("expected domainname override verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerIsolationRejectsMacAddressOverride(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, 80/tcp=8080;, none none none none none none none 02:42:ac:11:00:02 none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerIsolation(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "MAC address override") {
		t.Fatalf("expected MAC address override verification failure, got %v", err)
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 2 luma-tenant_demo,bridge, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":false,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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

func TestVerifyStartedContainerMountsRequiresTmpfsScratchPaths(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""}]'
      exit 0
      ;;
  esac
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerMounts(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), `tmpfs mount "/run"`) {
		t.Fatalf("expected missing /run tmpfs drift failure, got %v", err)
	}
}

func TestVerifyStartedContainerMountsRejectsUnexpectedMounts(t *testing.T) {
	cases := []struct {
		name     string
		mounts   string
		contains string
	}{
		{
			name:     "volume",
			mounts:   `[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"volume","Source":"/var/lib/docker/volumes/cache/_data","Destination":"/cache","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]`,
			contains: `unexpected mount type "volume"`,
		},
		{
			name:     "extra tmpfs",
			mounts:   `[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/var/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]`,
			contains: `unexpected tmpfs mount target "/var/tmp"`,
		},
		{
			name:     "readonly tmpfs",
			mounts:   `[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":false,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]`,
			contains: `tmpfs mount "/tmp" writable`,
		},
		{
			name:     "duplicate bind",
			mounts:   `[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test/other","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]`,
			contains: `duplicate mount target "/data"`,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo %q
      exit 0
      ;;
  esac
fi
exit 1
`, tt.mounts))
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerMounts(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %q mount verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func TestVerifyStartedContainerMountsRequiresTmpfsConfig(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  case "$3" in
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
  esac
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerMounts(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), `tmpfs config for "/tmp"`) {
		t.Fatalf("expected tmpfs option drift failure, got %v", err)
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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
	if err == nil || !strings.Contains(err.Error(), "exact security options") {
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *.Config.Image*)
      echo "nginx:1.27-alpine"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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
	if err == nil || !strings.Contains(err.Error(), "expected image reference") {
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
    *json\ .HostConfig.Tmpfs*)
      echo '{"/run":"rw,nosuid,nodev,size=16m","/tmp":"rw,noexec,nosuid,nodev,size=64m"}'
      exit 0
      ;;
    *json\ .Mounts*)
      echo '[{"Type":"bind","Source":"/srv/lumapanel/tenants/tenant_demo/deployments/dep_test","Destination":"/data","RW":true,"Propagation":"rprivate"},{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true,"Propagation":""},{"Type":"tmpfs","Source":"","Destination":"/run","RW":true,"Propagation":""}]'
      exit 0
      ;;
    *.HostConfig.NanoCpus*)
      echo "1000000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
      exit 0
      ;;
    *.HostConfig.Privileged*)
      echo "false true 512 none private private private private no true 30 false false false luma-tenant_demo 10000:10000 ALL, no-new-privileges=true,seccomp=lumapanel-default,apparmor=lumapanel-tenant, 1 luma-tenant_demo, none none none none none none none none none none none 0 0 none none none 0 none none 0 0 SIGTERM /proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/sched_debug,/sys/firmware, /proc/asound,/proc/bus,/proc/fs,/proc/irq,/proc/sys,/proc/sysrq-trigger, 0"
      exit 0
      ;;
    *json\ .Config.Healthcheck*)
      echo '{"Test":["CMD-SHELL","curl -fsS http://127.0.0.1"],"Interval":30000000000,"Timeout":5000000000,"Retries":3}'
      exit 0
      ;;
    *.State.Running*)
      echo "true false false false false healthy true dep_test tenant_demo node_local 0"
      exit 0
      ;;
    *luma.managed*)
      if [ -f "$CONTAINER_STATE" ]; then
        echo "true dep_test tenant_demo node_local"
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

func TestVerifyStartedContainerResourcesRequiresSharedMemorySize(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "1500000000 536870912 536870912 0 5g 33554432 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerResources(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "shared memory size") {
		t.Fatalf("expected shared memory size verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerResourcesRequiresLogBackpressurePolicy(t *testing.T) {
	cases := []struct {
		name   string
		output string
	}{
		{
			name:   "driver",
			output: "1500000000 536870912 536870912 0 5g 67108864 local 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
		},
		{
			name:   "max-size",
			output: "1500000000 536870912 536870912 0 5g 67108864 json-file 100m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
		},
		{
			name:   "max-file",
			output: "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 10 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
		},
		{
			name:   "mode",
			output: "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
		},
		{
			name:   "max-buffer-size",
			output: "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 32m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then\n  echo \""+tt.output+"\"\n  exit 0\nfi\nexit 1\n")
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerResources(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), "log rotation settings") {
				t.Fatalf("expected log policy verification failure, got %v", err)
			}
		})
	}
}

func TestVerifyStartedContainerResourcesRejectsExtraLogOptions(t *testing.T) {
	tempDir := t.TempDir()
	writeFakeCommand(t, tempDir, "docker", `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 5"
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := deploymentPlan(sampleJob())
	if err != nil {
		t.Fatalf("deploymentPlan returned error: %v", err)
	}
	err = verifyStartedContainerResources(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "log driver options") {
		t.Fatalf("expected extra log option verification failure, got %v", err)
	}
}

func TestVerifyStartedContainerResourcesRejectsSchedulerOverrides(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		contains string
	}{
		{
			name:     "memory-reservation",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 268435456 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
			contains: "memory reservation",
		},
		{
			name:     "memory-swappiness",
			output:   "1500000000 536870912 536870912 60 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
			contains: "memory swappiness",
		},
		{
			name:     "cpu-shares",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 1024 0 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
			contains: "CPU scheduler overrides",
		},
		{
			name:     "cpu-quota",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 100000 0 none none 0 0 0 0 0 0 0 0 0 0 0 0",
			contains: "CPU scheduler overrides",
		},
		{
			name:     "cpu-period",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 100000 none none 0 0 0 0 0 0 0 0 0 0 0 0",
			contains: "CPU scheduler overrides",
		},
		{
			name:     "cpuset-cpus",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 0-1 none 0 0 0 0 0 0 0 0 0 0",
			contains: "CPU set restrictions",
		},
		{
			name:     "cpuset-mems",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none 0 0 0 0 0 0 0 0 0 0 0",
			contains: "CPU set restrictions",
		},
		{
			name:     "blkio-weight",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 500 0 0 0 0 0 0 0 0 0",
			contains: "block I/O scheduler overrides",
		},
		{
			name:     "blkio-weight-device",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 1 0 0 0 0 0 0",
			contains: "block I/O scheduler overrides",
		},
		{
			name:     "blkio-read-bps",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 1 0 0 0 0 0",
			contains: "block I/O scheduler overrides",
		},
		{
			name:     "blkio-write-bps",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 1 0 0 0 0",
			contains: "block I/O scheduler overrides",
		},
		{
			name:     "blkio-read-iops",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 1 0 0 0",
			contains: "block I/O scheduler overrides",
		},
		{
			name:     "blkio-write-iops",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 1 0 0",
			contains: "block I/O scheduler overrides",
		},
		{
			name:     "cpu-realtime-runtime",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 1000 0",
			contains: "realtime CPU scheduler overrides",
		},
		{
			name:     "cpu-realtime-period",
			output:   "1500000000 536870912 536870912 0 5g 67108864 json-file 10m 3 non-blocking 4m 0 0 0 0 none none 0 0 0 0 0 0 0 100000",
			contains: "realtime CPU scheduler overrides",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			writeFakeCommand(t, tempDir, "docker", "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then\n  echo \""+tt.output+"\"\n  exit 0\nfi\nexit 1\n")
			t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			plan, err := deploymentPlan(sampleJob())
			if err != nil {
				t.Fatalf("deploymentPlan returned error: %v", err)
			}
			err = verifyStartedContainerResources(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected %s verification failure, got %v", tt.contains, err)
			}
		})
	}
}

func writeFakeCommand(t *testing.T, directory string, name string, content string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write fake command %s: %v", name, err)
	}
}
