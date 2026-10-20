package kube

import (
	"fmt"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	AgentViewRole = "kglance-agent-view"
	AgentMgmtRole = "kglance-agent-capi"
	AgentRole     = "kglance-agent"
	collectorRole = "kglance-collector"
	reaperRole    = "kglance-reaper"
)

type Object interface {
	runtime.Object
	metav1.Object
}

var readVerbs = []string{"get", "list", "watch"}

var mgmtCRDGroups = []string{
	"cluster.x-k8s.io",
	"infrastructure.cluster.x-k8s.io",
	"controlplane.cluster.x-k8s.io",
	"bootstrap.cluster.x-k8s.io",
	"addons.cluster.x-k8s.io",
	"ipam.cluster.x-k8s.io",
	"runtime.cluster.x-k8s.io",
	"vmoperator.vmware.com",
}

var eventRules = []rbacv1.PolicyRule{
	{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: readVerbs},
	{APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"}, Verbs: readVerbs},
}

func meta(kind, apiVersion, namespace, name string) (metav1.TypeMeta, metav1.ObjectMeta) {
	return metav1.TypeMeta{Kind: kind, APIVersion: apiVersion},
		metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{ManagedByLabel: ManagedByValue}}
}

// NamespaceObject is the workload namespace, which allows the privileged collector and which the reaper deletes at expiresAt.
func NamespaceObject(expiresAt time.Time) *corev1.Namespace {
	tm, om := meta("Namespace", "v1", "", Namespace)
	om.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
	om.Annotations = map[string]string{ExpiresAtAnnotation: expiresAt.UTC().Format(time.RFC3339)}
	return &corev1.Namespace{TypeMeta: tm, ObjectMeta: om}
}

// ExpiresAt returns the time at which the reaper deletes ns.
func ExpiresAt(ns *corev1.Namespace) (time.Time, error) {
	v, ok := ns.Annotations[ExpiresAtAnnotation]
	if !ok {
		return time.Time{}, fmt.Errorf("namespace %s has no %s annotation", ns.Name, ExpiresAtAnnotation)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("namespace %s: annotation %s: %w", ns.Name, ExpiresAtAnnotation, err)
	}
	return t, nil
}

func ServiceAccount(ns, name string) *corev1.ServiceAccount {
	tm, om := meta("ServiceAccount", "v1", ns, name)
	return &corev1.ServiceAccount{TypeMeta: tm, ObjectMeta: om}
}

func clusterRole(name string, rules []rbacv1.PolicyRule) *rbacv1.ClusterRole {
	tm, om := meta("ClusterRole", "rbac.authorization.k8s.io/v1", "", name)
	return &rbacv1.ClusterRole{TypeMeta: tm, ObjectMeta: om, Rules: rules}
}

func role(ns, name string, rules []rbacv1.PolicyRule) *rbacv1.Role {
	tm, om := meta("Role", "rbac.authorization.k8s.io/v1", ns, name)
	return &rbacv1.Role{TypeMeta: tm, ObjectMeta: om, Rules: rules}
}

func saSubject(ns, sa string) []rbacv1.Subject {
	return []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: ns}}
}

// ClusterRoleBinding binds the ClusterRole of the same name to a ServiceAccount in the kglance namespace.
func ClusterRoleBinding(name, sa string) *rbacv1.ClusterRoleBinding {
	tm, om := meta("ClusterRoleBinding", "rbac.authorization.k8s.io/v1", "", name)
	return &rbacv1.ClusterRoleBinding{TypeMeta: tm, ObjectMeta: om, Subjects: saSubject(Namespace, sa),
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}}
}

// RoleBinding binds the Role of the same name to ServiceAccount ns/sa.
func RoleBinding(name, ns, sa string) *rbacv1.RoleBinding {
	tm, om := meta("RoleBinding", "rbac.authorization.k8s.io/v1", ns, name)
	return &rbacv1.RoleBinding{TypeMeta: tm, ObjectMeta: om, Subjects: saSubject(ns, sa),
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name}}
}

var forbiddenSubresources = []string{"log", "exec", "attach", "portforward", "proxy"}

func allowedResource(r string) bool {
	if strings.Contains(r, "*") || r == "secrets" || strings.HasPrefix(r, "secrets/") {
		return false
	}
	_, sub, ok := strings.Cut(r, "/")
	return !ok || !slices.Contains(forbiddenSubresources, sub)
}

// FilterViewRules keeps only read verbs on resources that expose no logs, exec, proxies or secrets.
func FilterViewRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	var out []rbacv1.PolicyRule
	for _, r := range rules {
		if len(r.NonResourceURLs) > 0 {
			continue
		}
		res := slices.DeleteFunc(slices.Clone(r.Resources), func(s string) bool { return !allowedResource(s) })
		verbs := slices.DeleteFunc(slices.Clone(r.Verbs), func(v string) bool { return !slices.Contains(readVerbs, v) })
		if slices.Contains(r.Verbs, "*") {
			verbs = slices.Clone(readVerbs)
		}
		if len(res) == 0 || len(verbs) == 0 {
			continue
		}
		r = *r.DeepCopy()
		r.Resources, r.Verbs = res, verbs
		out = append(out, r)
	}
	return out
}

func AgentViewClusterRole(viewRules []rbacv1.PolicyRule) *rbacv1.ClusterRole {
	return clusterRole(AgentViewRole, append(FilterViewRules(viewRules), eventRules...))
}

func MgmtReadRole(ns string) *rbacv1.Role {
	return role(ns, AgentMgmtRole, append([]rbacv1.PolicyRule{
		{APIGroups: mgmtCRDGroups, Resources: []string{"*"}, Verbs: readVerbs},
		{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: readVerbs},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: readVerbs},
	}, eventRules...))
}

func AgentSnapshotRole() *rbacv1.Role {
	return role(Namespace, AgentRole, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: readVerbs}})
}

func CollectorClusterRole() *rbacv1.ClusterRole {
	return clusterRole(collectorRole, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}},
	})
}

func CollectorRole() *rbacv1.Role {
	return role(Namespace, collectorRole, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "create", "update", "patch"}},
	})
}

// ReaperRole lets the reaper read and delete only the namespace it runs in.
// A Role suffices because the API server authorizes requests for a namespace object within that namespace.
func ReaperRole() *rbacv1.Role {
	return role(Namespace, reaperRole, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{Namespace}, Verbs: []string{"get", "delete"}},
	})
}

type DaemonSetOptions struct {
	Image    string
	Cluster  string
	Interval time.Duration
}

// pullPolicy mirrors the Kubernetes default: Always for :latest or untagged images.
func pullPolicy(image string) corev1.PullPolicy {
	if strings.Contains(image, "@") {
		return corev1.PullIfNotPresent
	}
	name := image[strings.LastIndexByte(image, '/')+1:]
	_, tag, ok := strings.Cut(name, ":")
	if !ok || tag == "latest" {
		return corev1.PullAlways
	}
	return corev1.PullIfNotPresent
}

func DaemonSet(o DaemonSetOptions) *appsv1.DaemonSet {
	tm, om := meta("DaemonSet", "apps/v1", Namespace, CollectorDS)
	podLabels := map[string]string{NameLabel: CollectorDS, ManagedByLabel: ManagedByValue}
	yes, no, root := true, false, int64(0)
	grace := int64(5)
	return &appsv1.DaemonSet{TypeMeta: tm, ObjectMeta: om, Spec: appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{NameLabel: CollectorDS}},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
			Spec: corev1.PodSpec{
				ServiceAccountName:            CollectorSA,
				AutomountServiceAccountToken:  &yes,
				HostNetwork:                   true,
				HostPID:                       true,
				DNSPolicy:                     corev1.DNSClusterFirstWithHostNet,
				NodeSelector:                  map[string]string{corev1.LabelOSStable: "linux"},
				Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
				TerminationGracePeriodSeconds: &grace,
				Containers: []corev1.Container{{
					Name:            "collector",
					Image:           o.Image,
					ImagePullPolicy: pullPolicy(o.Image),
					Args:            []string{"collect", "--interval", o.Interval.String()},
					Env: []corev1.EnvVar{
						{Name: ClusterEnv, Value: o.Cluster},
						{Name: NodeEnv, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
					},
					SecurityContext: &corev1.SecurityContext{
						RunAsUser:                &root,
						ReadOnlyRootFilesystem:   &yes,
						AllowPrivilegeEscalation: &no,
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"SYS_PTRACE", "DAC_READ_SEARCH"}},
						SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
				}},
			},
		},
	}}
}

// Reaper runs "kglance reap", which deletes the namespace at its deadline.
// Its startup probe dry-runs that delete, so the pod becomes ready only if the delete would succeed.
func Reaper(image string) *appsv1.Deployment {
	tm, om := meta("Deployment", "apps/v1", Namespace, ReaperDeployment)
	podLabels := map[string]string{NameLabel: ReaperDeployment, ManagedByLabel: ManagedByValue}
	yes, no := true, false
	replicas, nonRoot, grace := int32(1), int64(65532), int64(5)
	return &appsv1.Deployment{TypeMeta: tm, ObjectMeta: om, Spec: appsv1.DeploymentSpec{
		Replicas: &replicas,
		Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{NameLabel: ReaperDeployment}},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
			Spec: corev1.PodSpec{
				ServiceAccountName:            ReaperSA,
				AutomountServiceAccountToken:  &yes,
				NodeSelector:                  map[string]string{corev1.LabelOSStable: "linux"},
				Tolerations:                   []corev1.Toleration{{Key: ControlPlaneLabel, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
				TerminationGracePeriodSeconds: &grace,
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot:   &yes,
					RunAsUser:      &nonRoot,
					RunAsGroup:     &nonRoot,
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
				Containers: []corev1.Container{{
					Name:            "reaper",
					Image:           image,
					ImagePullPolicy: pullPolicy(image),
					Args:            []string{"reap"},
					StartupProbe: &corev1.Probe{
						ProbeHandler:     corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/kglance", "reap", "--check"}}},
						PeriodSeconds:    2,
						TimeoutSeconds:   10,
						FailureThreshold: 30,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
					},
					SecurityContext: &corev1.SecurityContext{
						ReadOnlyRootFilesystem:   &yes,
						AllowPrivilegeEscalation: &no,
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					},
				}},
			},
		},
	}}
}

// MgmtObjects grants reads in the existing namespace ns only.
func MgmtObjects(ns string) []Object {
	return []Object{
		ServiceAccount(ns, AgentSA),
		MgmtReadRole(ns),
		RoleBinding(AgentMgmtRole, ns, AgentSA),
	}
}

// ReaperObjects run the reaper in the workload namespace.
func ReaperObjects(image string) []Object {
	return []Object{
		ServiceAccount(Namespace, ReaperSA),
		ReaperRole(),
		RoleBinding(reaperRole, Namespace, ReaperSA),
		Reaper(image),
	}
}

// WorkloadObjects give the agent access and run the collector.
// ns owns the cluster-scoped ones, so that deleting ns removes them.
func WorkloadObjects(ns *corev1.Namespace, viewRules []rbacv1.PolicyRule, ds DaemonSetOptions) []Object {
	objs := []Object{
		ServiceAccount(Namespace, AgentSA),
		ServiceAccount(Namespace, CollectorSA),
		AgentViewClusterRole(viewRules),
		ClusterRoleBinding(AgentViewRole, AgentSA),
		AgentSnapshotRole(),
		RoleBinding(AgentRole, Namespace, AgentSA),
		CollectorClusterRole(),
		ClusterRoleBinding(collectorRole, CollectorSA),
		CollectorRole(),
		RoleBinding(collectorRole, Namespace, CollectorSA),
		DaemonSet(ds),
	}
	owner := []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: ns.Name, UID: ns.UID}}
	for _, o := range objs {
		if o.GetNamespace() == "" {
			o.SetOwnerReferences(owner)
		}
	}
	return objs
}
