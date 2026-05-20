package config

import "time"

type Config struct {
	NodeID                       string
	PanelURL                     string
	ListenAddr                   string
	Location                     string
	CertFile                     string
	KeyFile                      string
	CAFile                       string
	CredentialsFile              string
	JobSigningSecret             string
	ReplayStoreFile              string
	RevocationListFile           string
	RuntimeCgroupControllersFile string
	CertificateRotationWindow    time.Duration
	DeploymentTimeout            time.Duration
	RequireImageDigest           bool
}
