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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
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

var eventRules = []rbacv1.PolicyRule{
	{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: readVerbs},
	{APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"}, Verbs: readVerbs},
}

func meta(kind, apiVersion, namespace, name string) (metav1.TypeMeta, metav1.ObjectMeta) {
	return metav1.TypeMeta{Kind: kind, APIVersion: apiVersion},
		metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{ManagedByLabel: ManagedByValue}}
}

// NamespaceObject is the workload namespace, which allows the privileged collector and which the reaper deletes at expiresAt.
// A non-zero tokensExpireAt records when the latest agent token expires.
func NamespaceObject(expiresAt, tokensExpireAt time.Time) *corev1.Namespace {
	tm, om := meta("Namespace", "v1", "", Namespace)
	om.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
	om.Annotations = map[string]string{ExpiresAtAnnotation: expiresAt.UTC().Format(time.RFC3339)}
	if !tokensExpireAt.IsZero() {
		om.Annotations[TokensExpireAtAnnotation] = tokensExpireAt.UTC().Format(time.RFC3339)
	}
	return &corev1.Namespace{TypeMeta: tm, ObjectMeta: om}
}

// TimeAnnotation parses the RFC3339 annotation key of ns.
func TimeAnnotation(ns *corev1.Namespace, key string) (time.Time, error) {
	v, ok := ns.Annotations[key]
	if !ok {
		return time.Time{}, fmt.Errorf("namespace %s has no %s annotation", ns.Name, key)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("namespace %s: annotation %s: %w", ns.Name, key, err)
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

// MgmtReadRole grants reads, one rule per API group and set of verbs.
func MgmtReadRole(ns string, reads []Access) *rbacv1.Role {
	var rules []rbacv1.PolicyRule
	var order []schema.GroupResource
	verbs := map[schema.GroupResource][]string{}
	for _, a := range reads {
		gr := schema.GroupResource{Group: a.Group, Resource: a.Resource}
		if _, seen := verbs[gr]; !seen {
			order = append(order, gr)
		}
		verbs[gr] = append(verbs[gr], a.Verb)
	}
	for _, gr := range order {
		i := slices.IndexFunc(rules, func(r rbacv1.PolicyRule) bool {
			return r.APIGroups[0] == gr.Group && slices.Equal(r.Verbs, verbs[gr])
		})
		if i < 0 {
			rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{gr.Group}, Verbs: verbs[gr]})
			i = len(rules) - 1
		}
		rules[i].Resources = append(rules[i].Resources, gr.Resource)
	}
	return role(ns, AgentMgmtRole, rules)
}

func AgentSnapshotRole() *rbacv1.Role {
	return role(Namespace, AgentRole, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: readVerbs}})
}

func CollectorClusterRole() *rbacv1.ClusterRole {
	return clusterRole(collectorRole, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}},
	})
}

func CollectorRole() *rbacv1.Role {
	return role(Namespace, collectorRole, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"create", "patch"}},
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
// Its readiness probe dry-runs that delete, so the pod is ready only while the delete would succeed.
func Reaper(image string) *appsv1.Deployment {
	tm, om := meta("Deployment", "apps/v1", Namespace, ReaperDeployment)
	podLabels := map[string]string{NameLabel: ReaperDeployment, ManagedByLabel: ManagedByValue}
	yes, no := true, false
	replicas, nonRoot, grace := int32(1), int64(65532), int64(5)
	maxSurge, maxUnavailable := intstr.FromInt32(1), intstr.FromInt32(0)
	return &appsv1.Deployment{TypeMeta: tm, ObjectMeta: om, Spec: appsv1.DeploymentSpec{
		Replicas: &replicas,
		// The old reaper keeps running until its replacement passes the check.
		Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxSurge: &maxSurge, MaxUnavailable: &maxUnavailable,
		}},
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
					ReadinessProbe: &corev1.Probe{
						ProbeHandler:     corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/kglance", "reap", "--check"}}},
						PeriodSeconds:    30,
						TimeoutSeconds:   10,
						FailureThreshold: 1,
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

// MgmtObjects returns the objects that grant reads in the existing namespace ns only.
func MgmtObjects(ns string, reads []Access) []Object {
	return []Object{
		ServiceAccount(ns, AgentSA),
		MgmtReadRole(ns, reads),
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
