package kube

import (
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
	AgentViewRole     = "kglance-agent-view"
	AgentCAPIRoleName = "kglance-agent-capi"
	AgentRole         = "kglance-agent"
	collectorRole     = "kglance-collector"
)

type Object interface {
	runtime.Object
	metav1.Object
}

var readVerbs = []string{"get", "list", "watch"}

var capiGroups = []string{
	"cluster.x-k8s.io",
	"infrastructure.cluster.x-k8s.io",
	"controlplane.cluster.x-k8s.io",
	"bootstrap.cluster.x-k8s.io",
	"addons.cluster.x-k8s.io",
	"ipam.cluster.x-k8s.io",
	"runtime.cluster.x-k8s.io",
}

var eventRules = []rbacv1.PolicyRule{
	{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: readVerbs},
	{APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"}, Verbs: readVerbs},
}

func meta(kind, apiVersion, namespace, name string) (metav1.TypeMeta, metav1.ObjectMeta) {
	return metav1.TypeMeta{Kind: kind, APIVersion: apiVersion},
		metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{ManagedByLabel: ManagedByValue}}
}

// NamespaceObject is the workload namespace, which allows the privileged collector.
func NamespaceObject() *corev1.Namespace {
	tm, om := meta("Namespace", "v1", "", Namespace)
	om.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
	return &corev1.Namespace{TypeMeta: tm, ObjectMeta: om}
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

func AgentCAPIRole(ns string) *rbacv1.Role {
	return role(ns, AgentCAPIRoleName, append([]rbacv1.PolicyRule{{APIGroups: capiGroups, Resources: []string{"*"}, Verbs: readVerbs}}, eventRules...))
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

// MgmtObjects grants reads in the existing namespace ns only.
func MgmtObjects(ns string) []Object {
	return []Object{
		ServiceAccount(ns, AgentSA),
		AgentCAPIRole(ns),
		RoleBinding(AgentCAPIRoleName, ns, AgentSA),
	}
}

func WorkloadObjects(viewRules []rbacv1.PolicyRule, ds DaemonSetOptions) []Object {
	return []Object{
		NamespaceObject(),
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
}
