package kube

const (
	Namespace      = "kglance"
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "kglance"
	SnapshotLabel  = "kglance.io/snapshot"
	FieldManager   = "kglance"
	AgentSA        = "kglance-agent"
	CollectorSA    = "kglance-collector"
	CollectorDS    = "kglance-collector"
	ClusterEnv     = "KGLANCE_CLUSTER"
	NodeEnv        = "KGLANCE_NODE"
	DefaultImage   = "ghcr.io/rosenhouse-bot-sandbox/kglance:latest"
)
