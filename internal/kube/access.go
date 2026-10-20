package kube

import (
	"context"
	"strings"

	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// Access is one API request, as an access review asks about it.
type Access struct {
	Verb, Group, Resource, Subresource, Namespace, Name string
}

// String formats a like kubectl auth can-i arguments.
func (a Access) String() string {
	res := a.Resource
	if a.Group != "" {
		res += "." + a.Group
	}
	if a.Name != "" {
		res += "/" + a.Name
	}
	s := a.Verb + " " + res
	if a.Subresource != "" {
		s += " --subresource=" + a.Subresource
	}
	if a.Namespace != "" {
		s += " -n " + a.Namespace
	}
	return s
}

var resources = map[string]schema.GroupResource{
	"Namespace":          {Resource: "namespaces"},
	"ServiceAccount":     {Resource: "serviceaccounts"},
	"ClusterRole":        {Group: rbacv1.GroupName, Resource: "clusterroles"},
	"ClusterRoleBinding": {Group: rbacv1.GroupName, Resource: "clusterrolebindings"},
	"Role":               {Group: rbacv1.GroupName, Resource: "roles"},
	"RoleBinding":        {Group: rbacv1.GroupName, Resource: "rolebindings"},
	"DaemonSet":          {Group: "apps", Resource: "daemonsets"},
	"Deployment":         {Group: "apps", Resource: "deployments"},
}

// AccessTo is the request to verb obj.
func AccessTo(verb string, obj Object) Access {
	gr := resources[obj.GetObjectKind().GroupVersionKind().Kind]
	return Access{Verb: verb, Group: gr.Group, Resource: gr.Resource, Namespace: obj.GetNamespace(), Name: obj.GetName()}
}

// RuleAccesses lists the resource requests that rules allow in namespace ns, or cluster-wide when ns is empty.
// It ignores non-resource URLs.
func RuleAccesses(rules []rbacv1.PolicyRule, ns string) []Access {
	var out []Access
	for _, r := range rules {
		names := r.ResourceNames
		if len(names) == 0 {
			names = []string{""}
		}
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				res, sub, _ := strings.Cut(res, "/")
				for _, name := range names {
					for _, v := range r.Verbs {
						out = append(out, Access{Verb: v, Group: g, Resource: res, Subresource: sub, Namespace: ns, Name: name})
					}
				}
			}
		}
	}
	return out
}

// Allowed asks the API server whether the caller may make request a.
func Allowed(ctx context.Context, cs kubernetes.Interface, a Access) (bool, error) {
	review := &authzv1.SelfSubjectAccessReview{Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{
		Verb: a.Verb, Group: a.Group, Resource: a.Resource, Subresource: a.Subresource, Namespace: a.Namespace, Name: a.Name,
	}}}
	r, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return r.Status.Allowed, nil
}
