// Package reaper deletes the kglance namespace once the agent's tokens expire.
package reaper

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
)

const interval = 10 * time.Second

// newClient connects as the pod's ServiceAccount.
var newClient = func() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// Main runs the reaper inside its Deployment pod. With --check it runs the pod's readiness check instead.
func Main(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("reap", flag.ContinueOnError)
	check := fl.Bool("check", false, "check once that the namespace could be deleted, then exit")
	if err := fl.Parse(args); err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	r := &Reaper{Client: client, Now: time.Now}
	if *check {
		return r.Check(ctx)
	}
	r.Run(ctx)
	return nil
}

type Reaper struct {
	Client kubernetes.Interface
	Now    func() time.Time
}

// Run calls Reap immediately and then every interval until ctx is done.
func (r *Reaper) Run(ctx context.Context) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.Reap(ctx); err != nil && ctx.Err() == nil {
			slog.Error("reap failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Reap deletes the namespace if its deadline has passed.
func (r *Reaper) Reap(ctx context.Context) error {
	ns, err := r.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if ns.DeletionTimestamp != nil {
		return nil
	}
	at, err := kube.TimeAnnotation(ns, kube.ExpiresAtAnnotation)
	if err != nil {
		return err
	}
	if r.Now().Before(at) {
		return nil
	}
	err = r.Client.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{ResourceVersion: &ns.ResourceVersion},
	})
	if apierrors.IsConflict(err) {
		// Setup changed the namespace since the read, so the deadline may have moved.
		return nil
	}
	if err != nil {
		return err
	}
	slog.Info("deleted namespace", "namespace", ns.Name, "expiresAt", at)
	return nil
}

// Check dry-runs the delete, so that missing RBAC or a blocking admission policy makes the reaper unready.
func (r *Reaper) Check(ctx context.Context) error {
	ns, err := r.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if _, err := kube.TimeAnnotation(ns, kube.ExpiresAtAnnotation); err != nil {
		return err
	}
	return r.Client.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}})
}
