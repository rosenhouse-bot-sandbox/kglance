package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestDryRunReportsEveryStepAndChangesNothing(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	o.DryRun = true
	for _, fc := range h.clusters {
		fc.cs.ClearActions()
	}
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	for name, fc := range h.clusters {
		for _, a := range fc.cs.Actions() {
			if !slices.Contains([]string{"get", "list", "watch"}, a.GetVerb()) && a.GetResource().Resource != "selfsubjectaccessreviews" {
				t.Errorf("%s: %s %s", name, a.GetVerb(), a.GetResource().Resource)
			}
		}
	}
	for _, p := range []string{o.StatePath, o.KubeconfigPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s: %v", p, err)
		}
	}
	want := `mgmt: apply ServiceAccount ns1/kglance-agent: ok
mgmt: apply Role ns1/kglance-agent-capi: ok
mgmt: apply RoleBinding ns1/kglance-agent-capi: ok
mgmt: request token for ns1/kglance-agent: ok
wl1: apply Namespace kglance: ok
wl1: delete cluster RBAC owned by an earlier namespace: ok
wl1: apply ServiceAccount kglance/kglance-reaper: ok
wl1: apply Role kglance/kglance-reaper: ok
wl1: apply RoleBinding kglance/kglance-reaper: ok
wl1: apply Deployment kglance/kglance-reaper: ok
wl1: wait for reaper kglance/kglance-reaper: ok
wl1: apply ServiceAccount kglance/kglance-agent: ok
wl1: apply ServiceAccount kglance/kglance-collector: ok
wl1: apply ClusterRole kglance-agent-view: ok
wl1: apply ClusterRoleBinding kglance-agent-view: ok
wl1: apply Role kglance/kglance-agent: ok
wl1: apply RoleBinding kglance/kglance-agent: ok
wl1: apply ClusterRole kglance-collector: ok
wl1: apply ClusterRoleBinding kglance-collector: ok
wl1: apply Role kglance/kglance-collector: ok
wl1: apply RoleBinding kglance/kglance-collector: ok
wl1: apply DaemonSet kglance/kglance-collector: ok
wl1: request token for kglance/kglance-agent: ok
wl1: read collector status: ok
dry run passed
`
	if got := h.out.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func denies(verb, resource string) func(authzv1.ResourceAttributes) bool {
	return func(a authzv1.ResourceAttributes) bool { return a.Verb == verb && a.Resource == resource }
}

func deniesAny(fs ...func(authzv1.ResourceAttributes) bool) func(authzv1.ResourceAttributes) bool {
	return func(a authzv1.ResourceAttributes) bool {
		return slices.ContainsFunc(fs, func(f func(authzv1.ResourceAttributes) bool) bool { return f(a) })
	}
}

func TestDryRunReportsWhatWouldFail(t *testing.T) {
	cases := map[string]struct {
		cluster string
		deny    func(authzv1.ResourceAttributes) bool
		want    []string
	}{
		"create": {"mgmt", denies("create", "roles"), []string{
			"mgmt: apply Role ns1/kglance-agent-capi: denied: create roles.rbac.authorization.k8s.io/kglance-agent-capi -n ns1",
		}},
		"patch": {"wl1", denies("patch", "daemonsets"), []string{
			"wl1: apply DaemonSet kglance/kglance-collector: denied: patch daemonsets.apps/kglance-collector -n kglance",
		}},
		"get": {"wl1", denies("get", "namespaces"), []string{
			"wl1: apply Namespace kglance: denied: get namespaces/kglance",
		}},
		"token": {"mgmt", func(a authzv1.ResourceAttributes) bool { return a.Subresource == "token" }, []string{
			"mgmt: request token for ns1/kglance-agent: denied: create serviceaccounts/kglance-agent --subresource=token -n ns1",
		}},
		"earlier RBAC": {"wl1", denies("delete", "clusterroles"), []string{
			"wl1: delete cluster RBAC owned by an earlier namespace: denied: delete clusterroles.rbac.authorization.k8s.io",
		}},
		"reaper": {"wl1", func(a authzv1.ResourceAttributes) bool { return a.Verb == "get" && a.Resource == "deployments" }, []string{
			"wl1: apply Deployment kglance/kglance-reaper: denied: get deployments.apps/kglance-reaper -n kglance",
			"wl1: wait for reaper kglance/kglance-reaper: denied: get deployments.apps/kglance-reaper -n kglance",
		}},
		"collector nodes": {"wl1", denies("list", "nodes"), []string{
			"wl1: read collector status: denied: list nodes",
		}},
		"collector pods": {"wl1", denies("list", "pods"), []string{
			"wl1: read collector status: denied: list pods -n kglance",
		}},
		"role grants without escalate or bind": {"mgmt", deniesAny(denies("escalate", "roles"), denies("bind", "roles"), denies("list", "pods")), []string{
			"mgmt: apply Role ns1/kglance-agent-capi: needs escalate or these permissions: list pods -n ns1",
			"mgmt: apply RoleBinding ns1/kglance-agent-capi: needs bind or these permissions: list pods -n ns1",
		}},
		"role grants without escalate": {"mgmt", deniesAny(denies("escalate", "roles"), denies("list", "pods"), denies("watch", "pods")), []string{
			"mgmt: apply Role ns1/kglance-agent-capi: needs escalate or these permissions: list,watch pods -n ns1",
		}},
		"cluster role grants without escalate": {"wl1", deniesAny(denies("escalate", "clusterroles"), denies("get", "configmaps")), []string{
			"wl1: apply ClusterRole kglance-agent-view: needs escalate or these permissions: get configmaps",
		}},
		"cluster role binding grants without bind": {"wl1", deniesAny(denies("escalate", "clusterroles"), denies("bind", "clusterroles"), denies("get", "configmaps")), []string{
			"wl1: apply ClusterRole kglance-agent-view: needs escalate or these permissions: get configmaps",
			"wl1: apply ClusterRoleBinding kglance-agent-view: needs bind or these permissions: get configmaps",
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.clusters[c.cluster].deny = c.deny
			o := h.options(wl1)
			o.DryRun = true
			err := Run(context.Background(), o)
			if err == nil || err.Error() != fmt.Sprintf("dry run: %d of 24 steps would fail", len(c.want)) {
				t.Errorf("err %v", err)
			}
			for _, line := range c.want {
				if !strings.Contains(h.out.String(), line+"\n") {
					t.Errorf("missing %q in:\n%s", line, h.out.String())
				}
			}
			if strings.Contains(h.out.String(), "dry run passed") {
				t.Error("reported a pass")
			}
		})
	}
}

func TestDryRunChecksGrantsOnlyWithoutEscalate(t *testing.T) {
	h := newHarness(t)
	o := h.options()
	o.DryRun = true
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for _, a := range h.clusters["mgmt"].reviews {
		if a.Resource == "pods" {
			t.Errorf("checked grant %+v despite escalate", a)
		}
	}
}

func TestDryRunReportsObjectsNotManagedByKglance(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1"].cs.Tracker().Add(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: kube.AgentViewRole}})
	o := h.options(wl1)
	o.DryRun = true
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	if want := "wl1: apply ClusterRole kglance-agent-view: exists and is not managed by kglance\n"; !strings.Contains(h.out.String(), want) {
		t.Errorf("missing %q in:\n%s", want, h.out.String())
	}
}

func TestDryRunNeedsCreateOnlyForNewObjects(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for _, fc := range h.clusters {
		fc.deny = denies("create", "daemonsets")
	}
	o.DryRun = true
	if err := Run(context.Background(), o); err != nil {
		t.Errorf("%v\n%s", err, h.out.String())
	}
}

func TestDryRunTreatsTerminatingNamespaceAsGone(t *testing.T) {
	h := newHarness(t)
	deleting := metav1.NewTime(now)
	h.clusters["wl1"].cs.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace, DeletionTimestamp: &deleting}})
	o := h.options(wl1)
	o.DryRun = true
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if want := "wl1: wait for namespace kglance to finish terminating: ok\nwl1: apply Namespace kglance: ok\n"; !strings.Contains(h.out.String(), want) {
		t.Errorf("missing %q in:\n%s", want, h.out.String())
	}
}

func TestDryRunReportsReadErrors(t *testing.T) {
	h := newHarness(t)
	h.clusters["mgmt"].cs.PrependReactor("get", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	o := h.options()
	o.DryRun = true
	if err := Run(context.Background(), o); err == nil || err.Error() != "dry run: 1 of 4 steps would fail" {
		t.Errorf("err %v", err)
	}
	if want := "mgmt: apply ServiceAccount ns1/kglance-agent: get ServiceAccount kglance-agent: boom\n"; !strings.Contains(h.out.String(), want) {
		t.Errorf("missing %q in:\n%s", want, h.out.String())
	}
}

func TestDryRunFailsWhenAccessReviewsFail(t *testing.T) {
	h := newHarness(t)
	h.clusters["mgmt"].cs.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).Spec.ResourceAttributes.Verb == "escalate" {
			return true, nil, errors.New("boom")
		}
		return false, nil, nil
	})
	o := h.options()
	o.DryRun = true
	want := "mgmt: review escalate roles.rbac.authorization.k8s.io/kglance-agent-capi -n ns1: boom"
	if err := Run(context.Background(), o); err == nil || err.Error() != want {
		t.Errorf("got %v want %s", err, want)
	}
}

func TestRunPrintsTheStepsDryRunChecks(t *testing.T) {
	dry := newHarness(t)
	o := dry.options(wl1)
	o.DryRun = true
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(dry.out.String(), "\n") {
		if !strings.Contains(line, ": read collector status") && line != "dry run passed" {
			if !strings.Contains(h.out.String(), line+"\n") {
				t.Errorf("missing %q in:\n%s", line, h.out.String())
			}
		}
	}
}

func TestRunNamesTheFailedStepAsDryRunDoes(t *testing.T) {
	h := newHarness(t)
	h.clusters["mgmt"].cs.PrependReactor("patch", "roles", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	err := Run(context.Background(), h.options())
	if err == nil || !strings.HasPrefix(err.Error(), "mgmt: apply Role ns1/kglance-agent-capi: boom") {
		t.Errorf("err %v", err)
	}
}
