package reaper

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func namespace(annotations map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace, ResourceVersion: "7", Annotations: annotations}}
}

func expiring(at time.Time) *corev1.Namespace {
	return namespace(map[string]string{kube.ExpiresAtAnnotation: at.Format(time.RFC3339)})
}

// deletes records namespace deletes, which the fake clientset performs unless handled.
// The fake clientset ignores DeleteOptions.
func deletes(cs *fake.Clientset, handled bool) *[]metav1.DeleteOptions {
	var got []metav1.DeleteOptions
	cs.PrependReactor("delete", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		got = append(got, a.(k8stesting.DeleteActionImpl).DeleteOptions)
		return handled, nil, nil
	})
	return &got
}

func newReaper(cs *fake.Clientset) *Reaper {
	return &Reaper{Client: cs, Now: func() time.Time { return now }}
}

// nsExists reads the tracker directly, bypassing reactors.
func nsExists(t *testing.T, cs *fake.Clientset) bool {
	t.Helper()
	_, err := cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", kube.Namespace)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestReapKeepsNamespaceBeforeDeadline(t *testing.T) {
	cs := fake.NewClientset(expiring(now.Add(time.Second)))
	got := deletes(cs, false)
	if err := newReaper(cs).Reap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 0 || !nsExists(t, cs) {
		t.Errorf("deleted before deadline: %+v", *got)
	}
}

func TestReapDeletesAtDeadlineOnlyIfNamespaceUnchanged(t *testing.T) {
	cs := fake.NewClientset(expiring(now))
	got := deletes(cs, false)
	if err := newReaper(cs).Reap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if nsExists(t, cs) {
		t.Error("namespace not deleted")
	}
	if len(*got) != 1 {
		t.Fatalf("deletes %+v", *got)
	}
	opts := (*got)[0]
	if opts.Preconditions == nil || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != "7" || len(opts.DryRun) != 0 {
		t.Errorf("delete options %+v", opts)
	}
}

func TestReapLeavesNamespaceThatChangedSinceRead(t *testing.T) {
	cs := fake.NewClientset(expiring(now))
	cs.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, kube.Namespace, errors.New("rv"))
	})
	if err := newReaper(cs).Reap(context.Background()); err != nil {
		t.Fatalf("conflict should be retried quietly: %v", err)
	}
	if !nsExists(t, cs) {
		t.Error("namespace deleted")
	}
}

func TestReapRefusesWithoutValidDeadline(t *testing.T) {
	for name, ns := range map[string]*corev1.Namespace{
		"missing": namespace(nil),
		"invalid": namespace(map[string]string{kube.ExpiresAtAnnotation: "soon"}),
	} {
		t.Run(name, func(t *testing.T) {
			cs := fake.NewClientset(ns)
			got := deletes(cs, false)
			err := newReaper(cs).Reap(context.Background())
			if err == nil || !strings.Contains(err.Error(), kube.ExpiresAtAnnotation) {
				t.Errorf("err %v", err)
			}
			if len(*got) != 0 {
				t.Errorf("deleted: %+v", *got)
			}
		})
	}
}

func TestReapIgnoresTerminatingOrMissingNamespace(t *testing.T) {
	terminating := expiring(now.Add(-time.Hour))
	terminating.DeletionTimestamp = &metav1.Time{Time: now}
	for name, cs := range map[string]*fake.Clientset{
		"terminating": fake.NewClientset(terminating),
		"missing":     fake.NewClientset(),
	} {
		t.Run(name, func(t *testing.T) {
			got := deletes(cs, false)
			if err := newReaper(cs).Reap(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(*got) != 0 {
				t.Errorf("deleted again: %+v", *got)
			}
		})
	}
}

func TestReapReportsDeleteFailure(t *testing.T) {
	cs := fake.NewClientset(expiring(now))
	cs.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, kube.Namespace, errors.New("denied"))
	})
	if err := newReaper(cs).Reap(context.Background()); !apierrors.IsForbidden(err) {
		t.Fatalf("err %v", err)
	}
}

func TestCheckDryRunsTheDelete(t *testing.T) {
	cs := fake.NewClientset(expiring(now.Add(time.Hour)))
	got := deletes(cs, true)
	if err := newReaper(cs).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || len((*got)[0].DryRun) != 1 || (*got)[0].DryRun[0] != metav1.DryRunAll ||
		(*got)[0].Preconditions == nil || *(*got)[0].Preconditions.ResourceVersion != "7" {
		t.Errorf("delete options %+v", *got)
	}
}

func TestCheckFailsWhenReapingWouldFail(t *testing.T) {
	forbidden := fake.NewClientset(expiring(now.Add(time.Hour)))
	forbidden.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, kube.Namespace, errors.New("denied"))
	})
	for name, cs := range map[string]*fake.Clientset{
		"no deadline":   fake.NewClientset(namespace(nil)),
		"no namespace":  fake.NewClientset(),
		"delete denied": forbidden,
	} {
		t.Run(name, func(t *testing.T) {
			if err := newReaper(cs).Check(context.Background()); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestReapReportsReadFailure(t *testing.T) {
	cs := fake.NewClientset(expiring(now))
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	if err := newReaper(cs).Reap(context.Background()); err == nil || !strings.Contains(err.Error(), "apiserver down") {
		t.Fatalf("err %v", err)
	}
}

func TestRunReapsOnceTheDeadlinePassesAndStopsWhenCancelled(t *testing.T) {
	cs := fake.NewClientset(expiring(now.Add(time.Minute)))
	got := deletes(cs, false)
	var failed atomic.Bool
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failed.CompareAndSwap(false, true) {
			return true, nil, errors.New("apiserver down")
		}
		return false, nil, nil
	})
	var calls atomic.Int32
	r := &Reaper{Client: cs, Now: func() time.Time { return now.Add(time.Duration(calls.Add(1)) * 30 * time.Second) }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, time.Millisecond)
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for nsExists(t, cs) {
		select {
		case <-deadline:
			t.Fatal("namespace not reaped")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if len(*got) != 1 || calls.Load() < 2 {
		t.Errorf("deletes %d after %d clock reads", len(*got), calls.Load())
	}
}

func TestRunReapsBeforeTheFirstTick(t *testing.T) {
	cs := fake.NewClientset(expiring(now))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		newReaper(cs).Run(ctx, time.Hour)
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for nsExists(t, cs) {
		select {
		case <-deadline:
			t.Fatal("namespace not reaped")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestMainValidation(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, tt := range []struct {
		args    []string
		wantErr string
	}{
		{[]string{"--bogus"}, "bogus"},
		{[]string{"--interval", "0s"}, "interval"},
		{nil, "in-cluster"},
		{[]string{"--check"}, "in-cluster"},
	} {
		if err := Main(context.Background(), tt.args); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%v: got %v, want error containing %q", tt.args, err, tt.wantErr)
		}
	}
}
