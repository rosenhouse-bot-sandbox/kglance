package kube

import (
	"context"
	"encoding/json"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Apply server-side applies obj with the kglance field manager.
func Apply(ctx context.Context, cs kubernetes.Interface, obj Object) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	kind, ns, name := obj.GetObjectKind().GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName()
	opts := metav1.PatchOptions{FieldManager: FieldManager, Force: new(true)}
	pt := types.ApplyPatchType
	switch kind {
	case "Namespace":
		_, err = cs.CoreV1().Namespaces().Patch(ctx, name, pt, data, opts)
	case "ServiceAccount":
		_, err = cs.CoreV1().ServiceAccounts(ns).Patch(ctx, name, pt, data, opts)
	case "ClusterRole":
		_, err = cs.RbacV1().ClusterRoles().Patch(ctx, name, pt, data, opts)
	case "ClusterRoleBinding":
		_, err = cs.RbacV1().ClusterRoleBindings().Patch(ctx, name, pt, data, opts)
	case "Role":
		_, err = cs.RbacV1().Roles(ns).Patch(ctx, name, pt, data, opts)
	case "RoleBinding":
		_, err = cs.RbacV1().RoleBindings(ns).Patch(ctx, name, pt, data, opts)
	case "DaemonSet":
		_, err = cs.AppsV1().DaemonSets(ns).Patch(ctx, name, pt, data, opts)
	default:
		return fmt.Errorf("apply: unsupported kind %s", kind)
	}
	if err != nil {
		return fmt.Errorf("apply %s %s: %w", kind, name, err)
	}
	return nil
}

// Delete removes one object; NotFound counts as success.
func Delete(ctx context.Context, cs kubernetes.Interface, kind, ns, name string) error {
	var err error
	opts := metav1.DeleteOptions{}
	switch kind {
	case "Namespace":
		err = cs.CoreV1().Namespaces().Delete(ctx, name, opts)
	case "ServiceAccount":
		err = cs.CoreV1().ServiceAccounts(ns).Delete(ctx, name, opts)
	case "ClusterRole":
		err = cs.RbacV1().ClusterRoles().Delete(ctx, name, opts)
	case "ClusterRoleBinding":
		err = cs.RbacV1().ClusterRoleBindings().Delete(ctx, name, opts)
	case "Role":
		err = cs.RbacV1().Roles(ns).Delete(ctx, name, opts)
	case "RoleBinding":
		err = cs.RbacV1().RoleBindings(ns).Delete(ctx, name, opts)
	case "DaemonSet":
		err = cs.AppsV1().DaemonSets(ns).Delete(ctx, name, opts)
	default:
		return fmt.Errorf("delete: unsupported kind %s", kind)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s %s: %w", kind, name, err)
	}
	return nil
}
