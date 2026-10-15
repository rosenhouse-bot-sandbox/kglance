package kube

import (
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestFilterViewRulesDropsDangerousSubresourcesSecretsAndWriteVerbs(t *testing.T) {
	in := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "pods/log", "pods/status", "pods/exec", "pods/attach", "pods/portforward", "services/proxy", "nodes/proxy", "secrets"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		{APIGroups: []string{"x"}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
		{APIGroups: []string{"y"}, Resources: []string{"things"}, Verbs: []string{"update"}},
	}
	got := FilterViewRules(in)
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "pods/status"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
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

func TestFilterViewRulesDropsWildcards(t *testing.T) {
	got := FilterViewRules([]rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}},
		{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}},
	})
	if len(got) != 0 {
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

func TestAgentCAPIClusterRoleIsReadOnlyCAPIWithoutSecrets(t *testing.T) {
	cr := AgentCAPIClusterRole()
	for _, g := range []string{"cluster.x-k8s.io", "infrastructure.cluster.x-k8s.io", "controlplane.cluster.x-k8s.io", "bootstrap.cluster.x-k8s.io", "addons.cluster.x-k8s.io", "ipam.cluster.x-k8s.io", "runtime.cluster.x-k8s.io"} {
		if !allows(cr.Rules, g, "anything", "list") {
			t.Errorf("missing group %s", g)
		}
	}
	for _, res := range []string{"namespaces", "events", "nodes"} {
		if !allows(cr.Rules, "", res, "list") {
			t.Errorf("missing core %s", res)
		}
	}
	if !allows(cr.Rules, "events.k8s.io", "events", "watch") {
		t.Error("missing events.k8s.io")
	}
	if allows(cr.Rules, "", "secrets", "get") || allows(cr.Rules, "", "anything", "get") {
		t.Error("core wildcard or secrets granted")
	}
	for _, r := range cr.Rules {
		if !slices.Equal(r.Verbs, []string{"get", "list", "watch"}) {
			t.Errorf("verbs %v", r.Verbs)
		}
	}
}

func TestCollectorRBAC(t *testing.T) {
	cr := CollectorClusterRole()
	if !allows(cr.Rules, "", "pods", "list") || !allows(cr.Rules, "", "nodes", "get") || allows(cr.Rules, "", "configmaps", "create") {
		t.Errorf("cluster role %+v", cr.Rules)
	}
	r := CollectorRole()
	if r.Namespace != Namespace {
		t.Errorf("ns %s", r.Namespace)
	}
	for _, v := range []string{"get", "create", "update", "patch"} {
		if !allows(r.Rules, "", "configmaps", v) {
			t.Errorf("missing %s configmaps", v)
		}
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
	rb := RoleBinding("role-z", "sa-w")
	if crb.Name != "role-x" || crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "role-x" ||
		crb.Subjects[0] != (rbacv1.Subject{Kind: "ServiceAccount", Name: "sa-y", Namespace: Namespace}) {
		t.Errorf("crb %+v", crb)
	}
	if rb.Namespace != Namespace || rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != "role-z" || rb.Subjects[0].Name != "sa-w" {
		t.Errorf("rb %+v", rb)
	}
}

func TestNamespaceAllowsPrivilegedPods(t *testing.T) {
	ns := NamespaceObject()
	if ns.Name != Namespace || ns.Labels["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Errorf("%+v", ns)
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
	if sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || !slices.Equal(sc.Capabilities.Add, []corev1.Capability{"SYS_PTRACE"}) {
		t.Errorf("capabilities %+v", sc.Capabilities)
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("seccomp")
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
		"mgmt":     MgmtObjects(),
		"workload": WorkloadObjects(nil, DaemonSetOptions{Image: "i", Cluster: "c", Interval: time.Minute}),
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
	wantMgmt := []string{"Namespace/kglance", "ServiceAccount/kglance-agent", "ClusterRole/kglance-agent-capi", "ClusterRoleBinding/kglance-agent-capi"}
	if got := kinds(sets["mgmt"]); !slices.Equal(got, wantMgmt) {
		t.Errorf("mgmt %v", got)
	}
	wantWl := []string{"Namespace/kglance", "ServiceAccount/kglance-agent", "ServiceAccount/kglance-collector",
		"ClusterRole/kglance-agent-view", "ClusterRoleBinding/kglance-agent-view", "Role/kglance-agent", "RoleBinding/kglance-agent",
		"ClusterRole/kglance-collector", "ClusterRoleBinding/kglance-collector", "Role/kglance-collector", "RoleBinding/kglance-collector",
		"DaemonSet/kglance-collector"}
	if got := kinds(sets["workload"]); !slices.Equal(got, wantWl) {
		t.Errorf("workload %v", got)
	}
}
