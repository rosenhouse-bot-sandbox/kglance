package setup

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// dryRun prints each step setup would take and whether access reviews allow it, changing nothing.
func dryRun(ctx context.Context, o Options, clusters []*cluster) error {
	steps, failed := 0, 0
	for _, c := range clusters {
		report := func(step string, problems []string, err error) error {
			if err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			steps++
			result := "ok"
			if len(problems) > 0 {
				failed++
				result = strings.Join(problems, "; ")
			}
			fmt.Fprintf(o.Out, "%s: %s: %s\n", c.Name, step, result)
			return nil
		}
		if err := dryRunCluster(ctx, o, c, report); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("dry run: %d of %d steps would fail", failed, steps)
	}
	fmt.Fprintln(o.Out, "dry run passed")
	return nil
}

// dryRunCluster reports each of c's steps in the order setup takes them.
func dryRunCluster(ctx context.Context, o Options, c *cluster, report func(string, []string, error) error) error {
	r := reviewer{cs: c.conn.Client, asked: map[kube.Access]bool{}}
	workload := c.Role == state.RoleWorkload
	var ns *corev1.Namespace
	var reaper []kube.Object
	if workload {
		ns = kube.NamespaceObject(o.Now(), time.Time{})
		reaper = kube.ReaperObjects(o.Image)
	}
	access, err := accessObjects(ctx, o, c, ns)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	planned := slices.Concat(reaper, access)
	apply := func(obj kube.Object) error {
		problems, err := r.applyProblems(ctx, obj, planned)
		return report("apply "+kube.Describe(obj), problems, err)
	}
	if workload {
		var err error
		if r.terminating, err = r.namespaceTerminating(ctx); err != nil || r.terminating {
			if err := report("wait for namespace "+kube.Namespace+" to finish terminating", nil, err); err != nil {
				return err
			}
		}
		if err := apply(ns); err != nil {
			return err
		}
		problems, err := r.deniedProblems(ctx,
			kube.Access{Verb: "list", Group: rbacv1.GroupName, Resource: "clusterrolebindings"},
			kube.Access{Verb: "delete", Group: rbacv1.GroupName, Resource: "clusterrolebindings"},
			kube.Access{Verb: "list", Group: rbacv1.GroupName, Resource: "clusterroles"},
			kube.Access{Verb: "delete", Group: rbacv1.GroupName, Resource: "clusterroles"})
		if err := report(deleteEarlierStep, problems, err); err != nil {
			return err
		}
		for _, obj := range reaper {
			if err := apply(obj); err != nil {
				return err
			}
		}
		problems, err = r.deniedProblems(ctx,
			kube.Access{Verb: "get", Group: "apps", Resource: "deployments", Namespace: kube.Namespace, Name: kube.ReaperDeployment})
		if err := report(waitReaperStep, problems, err); err != nil {
			return err
		}
	}
	for _, obj := range access {
		if err := apply(obj); err != nil {
			return err
		}
	}
	problems, err := r.deniedProblems(ctx,
		kube.Access{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: c.namespace, Name: kube.AgentSA})
	if err := report("request token for "+c.namespace+"/"+kube.AgentSA, problems, err); err != nil {
		return err
	}
	if workload {
		problems, err := r.deniedProblems(ctx,
			kube.Access{Verb: "list", Resource: "pods", Namespace: kube.Namespace}, kube.Access{Verb: "list", Resource: "nodes"})
		return report("read collector status", problems, err)
	}
	return nil
}

// reviewer asks one cluster's API server about each access at most once.
type reviewer struct {
	cs          kubernetes.Interface
	asked       map[kube.Access]bool
	terminating bool
}

func (r reviewer) namespaceTerminating(ctx context.Context) (bool, error) {
	denied, err := r.denied(ctx, kube.Access{Verb: "get", Resource: "namespaces", Name: kube.Namespace})
	if err != nil || len(denied) > 0 {
		return false, err
	}
	ns, err := r.cs.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil && ns.DeletionTimestamp != nil, err
}

// gone reports whether obj will be deleted with the terminating kglance namespace before setup applies it.
func (r reviewer) gone(obj kube.Object) bool {
	return r.terminating && (obj.GetNamespace() == kube.Namespace || obj.GetObjectKind().GroupVersionKind().Kind == "Namespace")
}

func (r reviewer) denied(ctx context.Context, accesses ...kube.Access) ([]kube.Access, error) {
	var out []kube.Access
	for _, a := range accesses {
		ok, done := r.asked[a]
		if !done {
			var err error
			if ok, err = kube.Allowed(ctx, r.cs, a); err != nil {
				return nil, fmt.Errorf("review %s: %w", a, err)
			}
			r.asked[a] = ok
		}
		if !ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r reviewer) deniedProblems(ctx context.Context, accesses ...kube.Access) ([]string, error) {
	denied, err := r.denied(ctx, accesses...)
	if err != nil || len(denied) == 0 {
		return nil, err
	}
	return []string{"denied: " + joinByResource(denied)}, nil
}

// applyProblems explains why applying obj would fail, if it would. planned holds the roles that bindings refer to.
func (r reviewer) applyProblems(ctx context.Context, obj kube.Object, planned []kube.Object) ([]string, error) {
	get := kube.AccessTo("get", obj)
	getDenied, err := r.denied(ctx, get)
	if err != nil {
		return nil, err
	}
	exists, existing := false, ""
	if len(getDenied) == 0 && !r.gone(obj) {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		var managed bool
		exists, managed, err = kube.Managed(ctx, r.cs, kind, obj.GetNamespace(), obj.GetName())
		switch {
		case err != nil:
			existing = err.Error()
		case exists && !managed:
			existing = "exists and is not managed by kglance"
		}
	}
	// Server-side apply needs create only when the object does not exist yet.
	accesses := []kube.Access{get}
	if !exists {
		accesses = append(accesses, kube.AccessTo("create", obj))
	}
	denied, err := r.denied(ctx, append(accesses, kube.AccessTo("patch", obj))...)
	if err != nil {
		return nil, err
	}
	var problems []string
	if len(denied) > 0 {
		problems = append(problems, "denied: "+joinByResource(denied))
	}
	if existing != "" {
		problems = append(problems, existing)
	}
	if rules, bypass, ok := grants(obj, planned); ok {
		missing, err := r.ungranted(ctx, bypass, rules, obj.GetNamespace())
		if err != nil {
			return nil, err
		}
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("needs %s or these permissions: %s", bypass.Verb, joinByResource(missing)))
		}
	}
	return problems, nil
}

// ungranted returns the accesses in rules that the caller may not grant, which is none if bypass is allowed.
func (r reviewer) ungranted(ctx context.Context, bypass kube.Access, rules []rbacv1.PolicyRule, ns string) ([]kube.Access, error) {
	denied, err := r.denied(ctx, bypass)
	if err != nil || len(denied) == 0 {
		return nil, err
	}
	return r.denied(ctx, kube.RuleAccesses(rules, ns)...)
}

// grants returns the rules obj grants and the access that lets the caller grant them without holding them.
// Kubernetes refuses to create a role or binding that grants permissions the caller lacks.
func grants(obj kube.Object, planned []kube.Object) (rules []rbacv1.PolicyRule, bypass kube.Access, ok bool) {
	var ref rbacv1.RoleRef
	switch o := obj.(type) {
	case *rbacv1.Role:
		return o.Rules, kube.AccessTo("escalate", o), true
	case *rbacv1.ClusterRole:
		return o.Rules, kube.AccessTo("escalate", o), true
	case *rbacv1.RoleBinding:
		ref = o.RoleRef
	case *rbacv1.ClusterRoleBinding:
		ref = o.RoleRef
	default:
		return nil, kube.Access{}, false
	}
	roleNS := ""
	if ref.Kind == "Role" {
		roleNS = obj.GetNamespace()
	}
	for _, p := range planned {
		if p.GetObjectKind().GroupVersionKind().Kind == ref.Kind && p.GetNamespace() == roleNS && p.GetName() == ref.Name {
			rules, _, _ := grants(p, nil)
			return rules, kube.AccessTo("bind", p), true
		}
	}
	return nil, kube.Access{}, false
}

// joinByResource lists accesses with the verbs on each resource joined, as in "list,watch pods -n ns1".
func joinByResource(accesses []kube.Access) string {
	var resources []kube.Access
	verbs := map[kube.Access][]string{}
	for _, a := range accesses {
		res := a
		res.Verb = ""
		if _, seen := verbs[res]; !seen {
			resources = append(resources, res)
		}
		verbs[res] = append(verbs[res], a.Verb)
	}
	var parts []string
	for _, res := range resources {
		res.Verb = strings.Join(verbs[res], ",")
		parts = append(parts, res.String())
	}
	return strings.Join(parts, ", ")
}
