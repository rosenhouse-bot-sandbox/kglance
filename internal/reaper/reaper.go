// Package reaper deletes the kglance namespace once the agent's tokens expire.
package reaper

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
)

// Main runs the reaper inside its Deployment pod. With --check it runs the pod's startup check instead.
func Main(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("reap", flag.ContinueOnError)
	interval := fl.Duration("interval", 10*time.Second, "time between deadline checks")
	check := fl.Bool("check", false, "check once that the namespace could be deleted, then exit")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *interval <= 0 {
		return fmt.Errorf("--interval must be positive")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	r := &Reaper{Client: client, Now: time.Now}
	if *check {
		return r.Check(ctx)
	}
	r.Run(ctx, *interval)
	return nil
}

type Reaper struct {
	Client kubernetes.Interface
	Now    func() time.Time
}

// Run calls Reap immediately and then every interval until ctx is done.
func (r *Reaper) Run(ctx context.Context, interval time.Duration) {
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
	at, err := kube.ExpiresAt(ns)
	if err != nil {
		return err
	}
	if r.Now().Before(at) {
		return nil
	}
	err = deleteUnchanged(ctx, r.Client, ns, nil)
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

// Check dry-runs the delete, so that missing RBAC or a blocking admission policy shows before any token exists.
func (r *Reaper) Check(ctx context.Context) error {
	ns, err := r.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if _, err := kube.ExpiresAt(ns); err != nil {
		return err
	}
	return deleteUnchanged(ctx, r.Client, ns, []string{metav1.DryRunAll})
}

func deleteUnchanged(ctx context.Context, client kubernetes.Interface, ns *corev1.Namespace, dryRun []string) error {
	return client.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{
		DryRun:        dryRun,
		Preconditions: &metav1.Preconditions{ResourceVersion: &ns.ResourceVersion},
	})
}
