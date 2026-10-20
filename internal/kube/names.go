package kube

const (
	Namespace                = "kglance"
	ManagedByLabel           = "app.kubernetes.io/managed-by"
	ManagedByValue           = "kglance"
	NameLabel                = "app.kubernetes.io/name"
	ControlPlaneLabel        = "node-role.kubernetes.io/control-plane"
	SnapshotLabel            = "kglance.rosenhouse-bot-sandbox.github.io/snapshot"
	TruncatedAnnotation      = "kglance.rosenhouse-bot-sandbox.github.io/truncated"
	ExpiresAtAnnotation      = "kglance.rosenhouse-bot-sandbox.github.io/expires-at"
	TokensExpireAtAnnotation = "kglance.rosenhouse-bot-sandbox.github.io/tokens-expire-at"
	FieldManager             = "kglance"
	AgentSA                  = "kglance-agent"
	CollectorSA              = "kglance-collector"
	CollectorDS              = "kglance-collector"
	ReaperSA                 = "kglance-reaper"
	ReaperDeployment         = "kglance-reaper"
	ClusterEnv               = "KGLANCE_CLUSTER"
	NodeEnv                  = "KGLANCE_NODE"
)
