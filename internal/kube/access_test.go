package kube

import (
	"context"
	"slices"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestAccessString(t *testing.T) {
	for want, a := range map[string]Access{
		"list nodes":             {Verb: "list", Resource: "nodes"},
		"get namespaces/kglance": {Verb: "get", Resource: "namespaces", Name: "kglance"},
		"create roles.rbac.authorization.k8s.io -n ns1": {Verb: "create", Group: rbacv1.GroupName, Resource: "roles", Namespace: "ns1"},
		"create serviceaccounts/kglance-agent --subresource=token -n ns1": {
			Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: "ns1", Name: "kglance-agent"},
		"list *.cluster.x-k8s.io -n ns1": {Verb: "list", Group: "cluster.x-k8s.io", Resource: "*", Namespace: "ns1"},
	} {
		if got := a.String(); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestAccessToObject(t *testing.T) {
	r := MgmtReadRole("ns1", nil)
	want := Access{Verb: "patch", Group: rbacv1.GroupName, Resource: "roles", Namespace: "ns1", Name: AgentMgmtRole}
	if got := AccessTo("patch", r); got != want {
		t.Errorf("got %+v", got)
	}
	for _, o := range slices.Concat(MgmtObjects("ns1", nil), allWorkloadObjects()) {
		if a := AccessTo("get", o); a.Resource == "" || a.Name != o.GetName() || a.Namespace != o.GetNamespace() {
			t.Errorf("%T: %+v", o, a)
		}
	}
}

func TestRuleAccessesExpandEveryGroupResourceAndVerb(t *testing.T) {
	got := RuleAccesses([]rbacv1.PolicyRule{
		{APIGroups: []string{"", "apps"}, Resources: []string{"pods", "pods/status"}, Verbs: []string{"get", "list"}},
	}, "ns1")
	if len(got) != 8 {
		t.Fatalf("%d accesses: %+v", len(got), got)
	}
	for _, want := range []Access{
		{Verb: "get", Resource: "pods", Namespace: "ns1"},
		{Verb: "list", Group: "apps", Resource: "pods", Subresource: "status", Namespace: "ns1"},
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %+v", want)
		}
	}
}

func TestAllowedAsksTheAPIServer(t *testing.T) {
	cs := fake.NewClientset()
	var asked authzv1.ResourceAttributes
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).DeepCopy()
		asked = *r.Spec.ResourceAttributes
		r.Status.Allowed = asked.Verb == "get"
		return true, r, nil
	})
	a := Access{Verb: "get", Group: "apps", Resource: "daemonsets", Subresource: "status", Namespace: "kglance", Name: "x"}
	ok, err := Allowed(context.Background(), cs, a)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if asked != (authzv1.ResourceAttributes{Verb: "get", Group: "apps", Resource: "daemonsets", Subresource: "status", Namespace: "kglance", Name: "x"}) {
		t.Errorf("asked %+v", asked)
	}
	a.Verb = "delete"
	if ok, err := Allowed(context.Background(), cs, a); err != nil || ok {
		t.Errorf("delete: %v %v", ok, err)
	}
}

func TestRuleAccessesExpandResourceNamesAndSkipURLs(t *testing.T) {
	got := RuleAccesses([]rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"get"}},
		{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}},
	}, "ns1")
	want := []Access{
		{Verb: "get", Resource: "configmaps", Namespace: "ns1", Name: "a"},
		{Verb: "get", Resource: "configmaps", Namespace: "ns1", Name: "b"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v", got)
	}
}
