package kube

const (
	Namespace           = "kglance"
	ManagedByLabel      = "app.kubernetes.io/managed-by"
	ManagedByValue      = "kglance"
	NameLabel           = "app.kubernetes.io/name"
	ControlPlaneLabel   = "node-role.kubernetes.io/control-plane"
	SnapshotLabel       = "kglance.io/snapshot"
	TruncatedAnnotation = "kglance.io/truncated"
	FieldManager        = "kglance"
	AgentSA             = "kglance-agent"
	CollectorSA         = "kglance-collector"
	CollectorDS         = "kglance-collector"
	ClusterEnv          = "KGLANCE_CLUSTER"
	NodeEnv             = "KGLANCE_NODE"
	DefaultImage        = "ghcr.io/rosenhouse-bot-sandbox/kglance:latest"
)
