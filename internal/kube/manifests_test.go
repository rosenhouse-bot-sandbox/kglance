package kube

import (
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestFilterViewRulesDropsDangerousSubresourcesSecretsAndWriteVerbs(t *testing.T) {
	in := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "pods/log", "pods/status", "pods/exec", "pods/attach", "pods/portforward", "services/proxy", "nodes/proxy", "secrets"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		{APIGroups: []string{"x"}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
		{APIGroups: []string{"y"}, Resources: []string{"things"}, Verbs: []string{"update"}},
		{APIGroups: []string{"z"}, Resources: []string{"pods/*", "*/*", "*/status", "widgets"}, Verbs: []string{"get"}},
	}
	got := FilterViewRules(in)
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "pods/status"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"z"}, Resources: []string{"widgets"}, Verbs: []string{"get"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if !slices.Equal(got[i].Resources, want[i].Resources) || !slices.Equal(got[i].Verbs, want[i].Verbs) || !slices.Equal(got[i].APIGroups, want[i].APIGroups) {
			t.Errorf("rule %d: got %+v want %+v", i, got[i], want[i])
		}
	}
	if in[0].Resources[1] != "pods/log" {
		t.Error("input mutated")
	}
}

func TestFilterViewRulesDropsWildcardResources(t *testing.T) {
	got := FilterViewRules([]rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}},
		{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}},
	})
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestFilterViewRulesReducesWildcardVerbToReadVerbs(t *testing.T) {
	got := FilterViewRules([]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}})
	if len(got) != 1 || !slices.Equal(got[0].Verbs, []string{"get", "list", "watch"}) {
		t.Fatalf("got %+v", got)
	}
}

func allows(rules []rbacv1.PolicyRule, group, resource, verb string) bool {
	for _, r := range rules {
		if (slices.Contains(r.APIGroups, group) || slices.Contains(r.APIGroups, "*")) &&
			(slices.Contains(r.Resources, resource) || slices.Contains(r.Resources, "*")) &&
			(slices.Contains(r.Verbs, verb) || slices.Contains(r.Verbs, "*")) {
			return true
		}
	}
	return false
}

func TestAgentViewClusterRoleAddsEvents(t *testing.T) {
	cr := AgentViewClusterRole([]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "pods/log"}, Verbs: []string{"get"}}})
	if cr.Name != "kglance-agent-view" {
		t.Errorf("name %s", cr.Name)
	}
	for _, c := range []struct{ group, res string }{{"", "events"}, {"events.k8s.io", "events"}} {
		for _, v := range []string{"get", "list", "watch"} {
			if !allows(cr.Rules, c.group, c.res, v) {
				t.Errorf("missing %s %q/%s", v, c.group, c.res)
			}
		}
	}
	if !allows(cr.Rules, "", "pods", "get") || allows(cr.Rules, "", "pods/log", "get") {
		t.Errorf("view rules not filtered: %+v", cr.Rules)
	}
}

func TestMgmtReadRoleGrantsExactlyTheGivenReads(t *testing.T) {
	r := MgmtReadRole("team", []Access{
		{Verb: "get", Group: "cluster.x-k8s.io", Resource: "clusters", Namespace: "team"},
		{Verb: "list", Group: "cluster.x-k8s.io", Resource: "clusters", Namespace: "team"},
		{Verb: "get", Group: "cluster.x-k8s.io", Resource: "machines", Namespace: "team"},
		{Verb: "list", Group: "cluster.x-k8s.io", Resource: "machines", Namespace: "team"},
		{Verb: "get", Group: "cluster.x-k8s.io", Resource: "machinesets", Namespace: "team"},
		{Verb: "get", Resource: "pods", Namespace: "team"},
	})
	if r.Namespace != "team" || r.Name != AgentMgmtRole {
		t.Errorf("%s/%s", r.Namespace, r.Name)
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"cluster.x-k8s.io"}, Resources: []string{"clusters", "machines"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"cluster.x-k8s.io"}, Resources: []string{"machinesets"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
	}
	if !equality.Semantic.DeepEqual(r.Rules, want) {
		t.Errorf("got %+v", r.Rules)
	}
}

func TestCollectorRBAC(t *testing.T) {
	cr := CollectorClusterRole()
	wantCluster := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}},
	}
	if !equality.Semantic.DeepEqual(cr.Rules, wantCluster) {
		t.Errorf("cluster role %+v", cr.Rules)
	}
	r := CollectorRole()
	if r.Namespace != Namespace {
		t.Errorf("ns %s", r.Namespace)
	}
	want := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"create", "patch"}}}
	if !equality.Semantic.DeepEqual(r.Rules, want) {
		t.Errorf("role %+v", r.Rules)
	}
}

func TestAgentSnapshotRoleReadsConfigMaps(t *testing.T) {
	r := AgentSnapshotRole()
	if r.Namespace != Namespace || !allows(r.Rules, "", "configmaps", "list") || allows(r.Rules, "", "configmaps", "update") {
		t.Errorf("%+v", r)
	}
}

func TestBindingsTargetServiceAccountInNamespace(t *testing.T) {
	crb := ClusterRoleBinding("role-x", "sa-y")
	rb := RoleBinding("role-z", "ns-v", "sa-w")
	if crb.Name != "role-x" || crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "role-x" ||
		crb.Subjects[0] != (rbacv1.Subject{Kind: "ServiceAccount", Name: "sa-y", Namespace: Namespace}) {
		t.Errorf("crb %+v", crb)
	}
	if rb.Namespace != "ns-v" || rb.Subjects[0].Namespace != "ns-v" || rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != "role-z" || rb.Subjects[0].Name != "sa-w" {
		t.Errorf("rb %+v", rb)
	}
}

func TestWorkloadNamespaceAllowsPrivilegedPods(t *testing.T) {
	ns := NamespaceObject(time.Now(), time.Time{})
	if ns.Name != Namespace || ns.Labels["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Errorf("%+v", ns)
	}
}

func TestWorkloadNamespaceRecordsDeadlinesInUTC(t *testing.T) {
	at := time.Date(2026, 10, 19, 14, 5, 6, 0, time.FixedZone("PDT", -7*3600))
	ns := NamespaceObject(at, at.Add(-time.Hour))
	if got := ns.Annotations[ExpiresAtAnnotation]; got != "2026-10-19T21:05:06Z" {
		t.Errorf("deadline %q", got)
	}
	if got := ns.Annotations[TokensExpireAtAnnotation]; got != "2026-10-19T20:05:06Z" {
		t.Errorf("token expiry %q", got)
	}
	if got, err := TimeAnnotation(ns, ExpiresAtAnnotation); err != nil || !got.Equal(at) {
		t.Errorf("TimeAnnotation %v %v", got, err)
	}
	if _, ok := NamespaceObject(at, time.Time{}).Annotations[TokensExpireAtAnnotation]; ok {
		t.Error("zero token expiry recorded")
	}
}

func TestReaperRoleDeletesOnlyItsNamespace(t *testing.T) {
	r := ReaperRole()
	want := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{Namespace}, Verbs: []string{"get", "delete"}}}
	if r.Namespace != Namespace || !equality.Semantic.DeepEqual(r.Rules, want) {
		t.Errorf("%s %+v", r.Namespace, r.Rules)
	}
	for _, o := range ReaperObjects("i") {
		if rb, ok := o.(*rbacv1.RoleBinding); ok && rb.Name == r.Name {
			if rb.RoleRef.Name != r.Name || rb.Subjects[0] != (rbacv1.Subject{Kind: "ServiceAccount", Name: ReaperSA, Namespace: Namespace}) {
				t.Errorf("binding %+v", rb)
			}
			return
		}
	}
	t.Error("no reaper RoleBinding")
}

func TestReaperContract(t *testing.T) {
	d := Reaper("img:1")
	if d.Name != ReaperDeployment || d.Namespace != Namespace || *d.Spec.Replicas != 1 {
		t.Fatalf("%s/%s %+v", d.Namespace, d.Name, d.Spec)
	}
	surge, unavailable := intstr.FromInt32(1), intstr.FromInt32(0)
	if want := (appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{
		MaxSurge: &surge, MaxUnavailable: &unavailable,
	}}); !equality.Semantic.DeepEqual(d.Spec.Strategy, want) {
		t.Errorf("strategy %+v", d.Spec.Strategy)
	}
	if d.Spec.Selector.MatchLabels[NameLabel] != ReaperDeployment || d.Spec.Template.Labels[NameLabel] != ReaperDeployment {
		t.Error("selector")
	}
	p := d.Spec.Template.Spec
	if p.HostNetwork || p.HostPID || p.HostIPC || len(p.Volumes) != 0 {
		t.Error("host namespaces or volumes")
	}
	if p.ServiceAccountName != ReaperSA || p.AutomountServiceAccountToken == nil || !*p.AutomountServiceAccountToken {
		t.Error("service account")
	}
	if len(p.Tolerations) != 1 || p.Tolerations[0] != (corev1.Toleration{Key: ControlPlaneLabel, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}) {
		t.Errorf("tolerations %+v", p.Tolerations)
	}
	if p.NodeSelector[corev1.LabelOSStable] != "linux" || p.TerminationGracePeriodSeconds == nil || *p.TerminationGracePeriodSeconds != 5 {
		t.Errorf("node selector %v, grace %v", p.NodeSelector, p.TerminationGracePeriodSeconds)
	}
	psc := p.SecurityContext
	if psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.RunAsUser == nil || *psc.RunAsUser == 0 ||
		psc.RunAsGroup == nil || *psc.RunAsGroup == 0 ||
		psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("pod security context %+v", psc)
	}
	if len(p.Containers) != 1 {
		t.Fatal("containers")
	}
	c := p.Containers[0]
	if c.Image != "img:1" || c.ImagePullPolicy != corev1.PullIfNotPresent || !slices.Equal(c.Args, []string{"reap"}) {
		t.Errorf("container %s %s %v", c.Image, c.ImagePullPolicy, c.Args)
	}
	sc := c.SecurityContext
	if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation ||
		sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 ||
		(sc.Privileged != nil && *sc.Privileged) || sc.RunAsUser != nil {
		t.Errorf("security context %+v", sc)
	}
	if want := (&corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/kglance", "reap", "--check"}}},
		PeriodSeconds: 30, TimeoutSeconds: 10, FailureThreshold: 1,
	}); !equality.Semantic.DeepEqual(c.ReadinessProbe, want) || c.StartupProbe != nil || c.LivenessProbe != nil {
		t.Errorf("probes %+v %+v %+v", c.ReadinessProbe, c.StartupProbe, c.LivenessProbe)
	}
	if want := (corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
	}); !equality.Semantic.DeepEqual(c.Resources, want) {
		t.Errorf("resources %+v", c.Resources)
	}
	if got := Reaper("img").Spec.Template.Spec.Containers[0].ImagePullPolicy; got != corev1.PullAlways {
		t.Errorf("untagged image pull policy %s", got)
	}
}

func TestWorkloadClusterScopedObjectsAreOwnedByTheNamespace(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: Namespace, UID: "ns-uid"}}
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "Namespace", Name: Namespace, UID: "ns-uid"}
	clusterScoped := 0
	for _, o := range slices.Concat(ReaperObjects("i"), WorkloadObjects(ns, nil, DaemonSetOptions{Image: "i", Cluster: "c", Interval: time.Minute})) {
		refs := o.GetOwnerReferences()
		if o.GetNamespace() != "" {
			if len(refs) != 0 {
				t.Errorf("%T %s: owners %+v", o, o.GetName(), refs)
			}
			continue
		}
		clusterScoped++
		if len(refs) != 1 || refs[0] != owner {
			t.Errorf("%T %s: owners %+v", o, o.GetName(), refs)
		}
	}
	if clusterScoped != 4 {
		t.Errorf("%d cluster-scoped objects", clusterScoped)
	}
}

func TestDaemonSetContract(t *testing.T) {
	ds := DaemonSet(DaemonSetOptions{Image: "img:1", Cluster: "wl1", Interval: 90 * time.Second})
	if ds.Name != CollectorDS || ds.Namespace != Namespace {
		t.Fatalf("name %s/%s", ds.Namespace, ds.Name)
	}
	p := ds.Spec.Template.Spec
	if !p.HostNetwork || !p.HostPID || p.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Error("host namespaces/dns")
	}
	if p.ServiceAccountName != CollectorSA || p.AutomountServiceAccountToken == nil || !*p.AutomountServiceAccountToken {
		t.Error("service account")
	}
	if len(p.Tolerations) != 1 || p.Tolerations[0].Operator != corev1.TolerationOpExists || p.Tolerations[0].Key != "" {
		t.Errorf("tolerations %+v", p.Tolerations)
	}
	if len(p.NodeSelector) != 1 || p.NodeSelector["kubernetes.io/os"] != "linux" {
		t.Errorf("node selector %v", p.NodeSelector)
	}
	if len(p.Volumes) != 0 {
		t.Error("volumes present")
	}
	if len(p.Containers) != 1 {
		t.Fatal("containers")
	}
	c := p.Containers[0]
	if c.Image != "img:1" || c.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Errorf("image %s %s", c.Image, c.ImagePullPolicy)
	}
	if !slices.Equal(c.Args, []string{"collect", "--interval", "1m30s"}) {
		t.Errorf("args %v", c.Args)
	}
	env := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		env[e.Name] = e
	}
	if env[ClusterEnv].Value != "wl1" {
		t.Errorf("cluster env %+v", env[ClusterEnv])
	}
	if f := env[NodeEnv].ValueFrom; f == nil || f.FieldRef == nil || f.FieldRef.FieldPath != "spec.nodeName" {
		t.Errorf("node env %+v", env[NodeEnv])
	}
	sc := c.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 0 || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem ||
		sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || (sc.Privileged != nil && *sc.Privileged) {
		t.Errorf("security context %+v", sc)
	}
	if sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || !slices.Equal(sc.Capabilities.Add, []corev1.Capability{"SYS_PTRACE", "DAC_READ_SEARCH"}) {
		t.Errorf("capabilities %+v", sc.Capabilities)
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("seccomp")
	}
	if sc.AppArmorProfile == nil || sc.AppArmorProfile.Type != corev1.AppArmorProfileTypeUnconfined {
		t.Errorf("apparmor %+v", sc.AppArmorProfile)
	}
	if c.Resources.Limits.Memory().IsZero() || c.Resources.Requests.Cpu().IsZero() {
		t.Error("resources")
	}
	if ds.Spec.Selector.MatchLabels["app.kubernetes.io/name"] != CollectorDS || ds.Spec.Template.Labels["app.kubernetes.io/name"] != CollectorDS {
		t.Error("selector")
	}
}

func TestObjectSetsAreLabelledAndTyped(t *testing.T) {
	sets := map[string][]Object{
		"mgmt":     MgmtObjects("team", nil),
		"workload": allWorkloadObjects(),
	}
	for name, objs := range sets {
		for _, o := range objs {
			if o.GetLabels()[ManagedByLabel] != ManagedByValue {
				t.Errorf("%s: %T %s unlabelled", name, o, o.GetName())
			}
			if o.GetObjectKind().GroupVersionKind().Kind == "" {
				t.Errorf("%s: %T missing TypeMeta", name, o)
			}
		}
	}
	kinds := func(objs []Object) []string {
		var ks []string
		for _, o := range objs {
			ks = append(ks, o.GetObjectKind().GroupVersionKind().Kind+"/"+o.GetName())
		}
		return ks
	}
	wantMgmt := []string{"ServiceAccount/kglance-agent", "Role/kglance-agent-capi", "RoleBinding/kglance-agent-capi"}
	if got := kinds(sets["mgmt"]); !slices.Equal(got, wantMgmt) {
		t.Errorf("mgmt %v", got)
	}
	wantWl := []string{"Namespace/kglance",
		"ServiceAccount/kglance-reaper", "Role/kglance-reaper", "RoleBinding/kglance-reaper", "Deployment/kglance-reaper",
		"ServiceAccount/kglance-agent", "ServiceAccount/kglance-collector",
		"ClusterRole/kglance-agent-view", "ClusterRoleBinding/kglance-agent-view", "Role/kglance-agent", "RoleBinding/kglance-agent",
		"ClusterRole/kglance-collector", "ClusterRoleBinding/kglance-collector", "Role/kglance-collector", "RoleBinding/kglance-collector",
		"DaemonSet/kglance-collector"}
	if got := kinds(sets["workload"]); !slices.Equal(got, wantWl) {
		t.Errorf("workload %v", got)
	}
}

func TestDaemonSetPullsLatestOrUntaggedImagesAlways(t *testing.T) {
	cases := map[string]corev1.PullPolicy{
		"ghcr.io/x/kglance:latest":   corev1.PullAlways,
		"ghcr.io/x/kglance":          corev1.PullAlways,
		"localhost:5000/kglance":     corev1.PullAlways,
		"kglance:xt":                 corev1.PullIfNotPresent,
		"localhost:5000/kglance:v1":  corev1.PullIfNotPresent,
		"ghcr.io/x/kglance@sha256:0": corev1.PullIfNotPresent,
	}
	for img, want := range cases {
		got := DaemonSet(DaemonSetOptions{Image: img, Interval: time.Minute}).Spec.Template.Spec.Containers[0].ImagePullPolicy
		if got != want {
			t.Errorf("%s: got %s want %s", img, got, want)
		}
	}
}

func TestMgmtObjectsAreInTheGivenNamespace(t *testing.T) {
	objs := MgmtObjects("team", nil)
	for _, o := range objs {
		if o.GetNamespace() != "team" {
			t.Errorf("%T %s in %q", o, o.GetName(), o.GetNamespace())
		}
	}
	if rb := objs[2].(*rbacv1.RoleBinding); rb.RoleRef.Name != AgentMgmtRole || rb.Subjects[0] != (rbacv1.Subject{Kind: "ServiceAccount", Name: AgentSA, Namespace: "team"}) {
		t.Errorf("binding %+v", rb)
	}
}
