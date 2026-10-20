package kube

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// mgmtReadCRDs are the custom resources the agent reads on mgmt.
var mgmtReadCRDs = []schema.GroupResource{
	{Group: "cluster.x-k8s.io", Resource: "clusters"},
	{Group: "vmoperator.vmware.com", Resource: "virtualmachines"},
	{Group: "vmoperator.vmware.com", Resource: "virtualmachineservices"},
}

// builtIn reports whether group is reserved for Kubernetes: the core group, an unqualified group such as apps, or a *.k8s.io group.
func builtIn(group string) bool {
	return !strings.Contains(group, ".") || strings.HasSuffix(group, ".k8s.io")
}

func mgmtResource(gr schema.GroupResource) bool {
	return slices.Contains(mgmtReadCRDs, gr) || builtIn(gr.Group) && gr != schema.GroupResource{Resource: "secrets"}
}

// ResourceLister is the part of a discovery client that MgmtReads uses.
type ResourceLister interface {
	ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error)
}

// MgmtReads lists the get, list and watch requests in namespace ns that the server supports
// for mgmtReadCRDs and the namespaced built-in resources other than Secrets.
// It ignores discovery failures of groups without mgmtReadCRDs, such as an unavailable metrics.k8s.io.
func MgmtReads(d ResourceLister, ns string) ([]Access, error) {
	_, lists, err := d.ServerGroupsAndResources()
	if failed := (*discovery.ErrGroupDiscoveryFailed)(nil); errors.As(err, &failed) {
		for gv, gvErr := range failed.Groups {
			if slices.ContainsFunc(mgmtReadCRDs, func(gr schema.GroupResource) bool { return gr.Group == gv.Group }) {
				return nil, fmt.Errorf("discover %s: %w", gv, gvErr)
			}
		}
	} else if err != nil {
		return nil, fmt.Errorf("discover resources: %w", err)
	}
	var out []Access
	for _, l := range lists {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			return nil, err
		}
		for _, r := range l.APIResources {
			if !r.Namespaced || strings.Contains(r.Name, "/") || !mgmtResource(gv.WithResource(r.Name).GroupResource()) {
				continue
			}
			for _, v := range readVerbs {
				a := Access{Verb: v, Group: gv.Group, Resource: r.Name, Namespace: ns}
				if slices.Contains(r.Verbs, v) && !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b Access) int {
		return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Resource, b.Resource),
			cmp.Compare(slices.Index(readVerbs, a.Verb), slices.Index(readVerbs, b.Verb)))
	})
	return out, nil
}
