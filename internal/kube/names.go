package kube

const (
	Namespace           = "kglance"
	ManagedByLabel      = "app.kubernetes.io/managed-by"
	ManagedByValue      = "kglance"
	NameLabel           = "app.kubernetes.io/name"
	ControlPlaneLabel   = "node-role.kubernetes.io/control-plane"
	SnapshotLabel       = "kglance.rosenhouse-bot-sandbox.github.io/snapshot"
	TruncatedAnnotation = "kglance.rosenhouse-bot-sandbox.github.io/truncated"
	FieldManager        = "kglance"
	AgentSA             = "kglance-agent"
	CollectorSA         = "kglance-collector"
	CollectorDS         = "kglance-collector"
	ClusterEnv          = "KGLANCE_CLUSTER"
	NodeEnv             = "KGLANCE_NODE"
)
