package kube

import (
	"context"
	"slices"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestApplyCreatesAndReappliesEveryWorkloadObject(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	objs := allWorkloadObjects()
	for range 2 {
		for _, o := range objs {
			if err := Apply(ctx, cs, o); err != nil {
				t.Fatalf("%T: %v", o, err)
			}
		}
	}
	ds, err := cs.AppsV1().DaemonSets(Namespace).Get(ctx, CollectorDS, metav1.GetOptions{})
	if err != nil || ds.Spec.Template.Spec.Containers[0].Image != "i" {
		t.Fatalf("%v %v", ds, err)
	}
	if _, err := cs.RbacV1().RoleBindings(Namespace).Get(ctx, AgentRole, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, Namespace, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppsV1().Deployments(Namespace).Get(ctx, ReaperDeployment, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
}

func allWorkloadObjects() []Object {
	ns := NamespaceObject(time.Now(), time.Time{})
	return slices.Concat([]Object{ns}, ReaperObjects("i"), WorkloadObjects(ns, nil, DaemonSetOptions{Image: "i", Cluster: "c", Interval: time.Minute}))
}

func TestApplyUpdatesChangedSpec(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	Apply(ctx, cs, DaemonSet(DaemonSetOptions{Image: "a", Interval: time.Minute}))
	if err := Apply(ctx, cs, DaemonSet(DaemonSetOptions{Image: "b", Interval: time.Minute})); err != nil {
		t.Fatal(err)
	}
	ds, _ := cs.AppsV1().DaemonSets(Namespace).Get(ctx, CollectorDS, metav1.GetOptions{})
	if ds.Spec.Template.Spec.Containers[0].Image != "b" {
		t.Fatal("not updated")
	}
}

func TestDeleteRemovesEachKindAndTreatsNotFoundAsSuccess(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	objs := allWorkloadObjects()
	for _, o := range objs {
		Apply(ctx, cs, o)
	}
	for range 2 {
		for _, o := range objs {
			gvk := o.GetObjectKind().GroupVersionKind()
			if err := Delete(ctx, cs, gvk.Kind, o.GetNamespace(), o.GetName()); err != nil {
				t.Fatalf("%s: %v", gvk.Kind, err)
			}
		}
	}
	if _, err := cs.AppsV1().DaemonSets(Namespace).Get(ctx, CollectorDS, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("ds still there: %v", err)
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, AgentViewRole, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("clusterrole still there: %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts(Namespace).Get(ctx, AgentSA, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("sa still there: %v", err)
	}
	if _, err := cs.AppsV1().Deployments(Namespace).Get(ctx, ReaperDeployment, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("deployment still there: %v", err)
	}
}

func TestDeleteRejectsUnknownKind(t *testing.T) {
	if err := Delete(context.Background(), fake.NewClientset(), "Secret", "kglance", "x"); err == nil {
		t.Fatal("expected error")
	}
}
