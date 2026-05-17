package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lumapanel/lumanode/internal/config"
	"github.com/lumapanel/lumanode/internal/server"
)

func main() {
	var cfg config.Config
	flag.StringVar(&cfg.NodeID, "node-id", "node_local", "registered node id")
	flag.StringVar(&cfg.PanelURL, "panel", "https://127.0.0.1:8080", "LUMAPanel control plane URL")
	flag.StringVar(&cfg.ListenAddr, "listen", ":9443", "agent listen address")
	flag.StringVar(&cfg.Location, "location", "local", "node location")
	flag.StringVar(&cfg.CertFile, "cert", "", "node TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", "", "node TLS private key file")
	flag.StringVar(&cfg.CAFile, "ca", "", "panel CA bundle for client certificate verification")
	flag.StringVar(&cfg.CredentialsFile, "credentials", os.Getenv("LUMANODE_CREDENTIALS"), "node enrollment credentials JSON file to update after certificate rotation")
	flag.StringVar(&cfg.JobSigningSecret, "job-signing-secret", os.Getenv("LUMANODE_JOB_SIGNING_SECRET"), "HMAC secret used to verify panel deployment jobs")
	flag.StringVar(&cfg.ReplayStoreFile, "replay-store", "/var/lib/lumanode/replayed-jobs.json", "durable accepted job signature replay cache")
	flag.StringVar(&cfg.RevocationListFile, "revocation-list", os.Getenv("LUMANODE_REVOCATION_LIST"), "JSON or line-delimited revoked client certificate fingerprint list")
	flag.StringVar(&cfg.RuntimeCgroupControllersFile, "cgroup-controllers", "/sys/fs/cgroup/cgroup.controllers", "cgroups v2 controllers file used for runtime preflight")
	flag.DurationVar(&cfg.CertificateRotationWindow, "cert-rotation-window", 14*24*time.Hour, "rotate the node client certificate when it expires within this duration")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	agent := server.New(cfg, slog.Default())
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				agent.Heartbeat(ctx)
				if rotated, err := agent.RotateCertificateIfDue(ctx, time.Now()); err != nil {
					slog.Error("certificate rotation check failed", "error", err)
				} else if rotated {
					slog.Info("rotated node client certificate")
				}
			}
		}
	}()

	if err := agent.ListenAndServe(ctx); err != nil {
		slog.Error("lumanode stopped", "error", err)
		os.Exit(1)
	}
}
