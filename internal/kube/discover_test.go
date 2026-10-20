package kube

import (
	"errors"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

type fakeResourceLister struct {
	lists []*metav1.APIResourceList
	err   error
}

func (f fakeResourceLister) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return nil, f.lists, f.err
}

var servedResources = []*metav1.APIResourceList{
	{GroupVersion: "cluster.x-k8s.io/v1beta2", APIResources: []metav1.APIResource{
		{Name: "machines", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
		{Name: "clusters", Namespaced: true, Verbs: []string{"create", "delete", "get", "list", "patch", "watch"}},
		{Name: "clusters/status", Namespaced: true, Verbs: []string{"get", "patch"}},
	}},
	{GroupVersion: "cluster.x-k8s.io/v1beta1", APIResources: []metav1.APIResource{
		{Name: "clusters", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
	}},
	{GroupVersion: "infrastructure.cluster.x-k8s.io/v1beta1", APIResources: []metav1.APIResource{
		{Name: "dockerclusters", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
	}},
	{GroupVersion: "vmoperator.vmware.com/v1alpha3", APIResources: []metav1.APIResource{
		{Name: "virtualmachines", Namespaced: true, Verbs: []string{"get", "list"}},
		{Name: "virtualmachineimages", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
		{Name: "virtualmachineservices", Namespaced: true, Verbs: []string{"get"}},
	}},
	{GroupVersion: "v1", APIResources: []metav1.APIResource{
		{Name: "secrets", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
		{Name: "pods", Namespaced: true, Verbs: []string{"create", "get", "list", "watch"}},
		{Name: "pods/log", Namespaced: true, Verbs: []string{"get"}},
		{Name: "bindings", Namespaced: true, Verbs: []string{"create"}},
		{Name: "nodes", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
	}},
	{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{
		{Name: "deployments", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
	}},
	{GroupVersion: "networking.k8s.io/v1", APIResources: []metav1.APIResource{
		{Name: "ingresses", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
	}},
	{GroupVersion: "example.com/v1", APIResources: []metav1.APIResource{
		{Name: "widgets", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
	}},
}

func TestMgmtReadsListsReadVerbsOfServedMgmtResources(t *testing.T) {
	got, err := MgmtReads(fakeResourceLister{lists: servedResources}, "team")
	if err != nil {
		t.Fatal(err)
	}
	var want []Access
	for _, gr := range []schema.GroupResource{{Resource: "pods"}, {Group: "apps", Resource: "deployments"}, {Group: "cluster.x-k8s.io", Resource: "clusters"}, {Group: "networking.k8s.io", Resource: "ingresses"}} {
		for _, v := range []string{"get", "list", "watch"} {
			want = append(want, Access{Verb: v, Group: gr.Group, Resource: gr.Resource, Namespace: "team"})
		}
	}
	want = append(want,
		Access{Verb: "get", Group: "vmoperator.vmware.com", Resource: "virtualmachines", Namespace: "team"},
		Access{Verb: "list", Group: "vmoperator.vmware.com", Resource: "virtualmachines", Namespace: "team"},
		Access{Verb: "get", Group: "vmoperator.vmware.com", Resource: "virtualmachineservices", Namespace: "team"})
	if !slices.Equal(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestMgmtReadsIgnoresDiscoveryFailuresOfOtherGroups(t *testing.T) {
	failed := &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{{Group: "metrics.k8s.io", Version: "v1beta1"}: errors.New("down")}}
	got, err := MgmtReads(fakeResourceLister{lists: servedResources, err: failed}, "team")
	if err != nil || len(got) != 15 {
		t.Errorf("%d reads, err %v", len(got), err)
	}
}

func TestMgmtReadsFailsWhenDiscoveryOfACRDGroupFails(t *testing.T) {
	for name, err := range map[string]error{
		"mgmt group":  &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{{Group: "vmoperator.vmware.com", Version: "v1alpha3"}: errors.New("down")}},
		"cluster api": &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{{Group: "cluster.x-k8s.io", Version: "v1beta2"}: errors.New("down")}},
		"all":         errors.New("down"),
	} {
		if _, err := MgmtReads(fakeResourceLister{lists: servedResources, err: err}, "team"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
