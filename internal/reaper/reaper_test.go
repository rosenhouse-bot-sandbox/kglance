package reaper

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
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

// deletes records namespace deletes. Unlike the fake clientset, it honours dry runs.
func deletes(cs *fake.Clientset) *[]metav1.DeleteOptions {
	var got []metav1.DeleteOptions
	cs.PrependReactor("delete", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		opts := a.(k8stesting.DeleteActionImpl).DeleteOptions
		got = append(got, opts)
		return len(opts.DryRun) > 0, nil, nil
	})
	return &got
}

func forbidDeletes(cs *fake.Clientset) {
	cs.PrependReactor("delete", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, kube.Namespace, errors.New("denied"))
	})
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
	got := deletes(cs)
	if err := newReaper(cs).Reap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 0 || !nsExists(t, cs) {
		t.Errorf("deleted before deadline: %+v", *got)
	}
}

func TestReapDeletesAtDeadlineOnlyIfNamespaceUnchanged(t *testing.T) {
	cs := fake.NewClientset(expiring(now))
	got := deletes(cs)
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
			got := deletes(cs)
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
			got := deletes(cs)
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
	forbidDeletes(cs)
	if err := newReaper(cs).Reap(context.Background()); !apierrors.IsForbidden(err) {
		t.Fatalf("err %v", err)
	}
}

func TestCheckDryRunsTheDelete(t *testing.T) {
	cs := fake.NewClientset(expiring(now.Add(time.Hour)))
	got := deletes(cs)
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
	forbidDeletes(forbidden)
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
	synctest.Test(t, func(t *testing.T) {
		cs := fake.NewClientset(expiring(time.Now().Add(interval + time.Second)))
		failed := false
		cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
			if !failed {
				failed = true
				return true, nil, errors.New("apiserver down")
			}
			return false, nil, nil
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			(&Reaper{Client: cs, Now: time.Now}).Run(ctx)
			close(done)
		}()
		time.Sleep(interval)
		synctest.Wait()
		if !nsExists(t, cs) {
			t.Fatal("reaped before the deadline")
		}
		time.Sleep(interval)
		synctest.Wait()
		if nsExists(t, cs) {
			t.Fatal("not reaped after the deadline")
		}
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("Run did not stop")
		}
	})
}

func TestRunReapsBeforeTheFirstTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs := fake.NewClientset(expiring(time.Now()))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go (&Reaper{Client: cs, Now: time.Now}).Run(ctx)
		synctest.Wait()
		if nsExists(t, cs) {
			t.Error("namespace not reaped")
		}
	})
}

// runMain runs Main against cs until it returns or a minute passes.
func runMain(t *testing.T, cs *fake.Clientset, args ...string) error {
	t.Helper()
	orig := newClient
	t.Cleanup(func() { newClient = orig })
	newClient = func() (kubernetes.Interface, error) { return cs, nil }
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	return Main(ctx, args)
}

func TestMainReaps(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs := fake.NewClientset(expiring(time.Now()))
		deletes(cs)
		if err := runMain(t, cs); err != nil {
			t.Fatal(err)
		}
		if nsExists(t, cs) {
			t.Error("namespace not reaped")
		}
	})
}

func TestMainChecksWithoutDeleting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs := fake.NewClientset(expiring(time.Now()))
		got := deletes(cs)
		if err := runMain(t, cs, "--check"); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || len((*got)[0].DryRun) != 1 || !nsExists(t, cs) {
			t.Errorf("deletes %+v", *got)
		}
	})
}

func TestMainValidation(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, tt := range []struct {
		args    []string
		wantErr string
	}{
		{[]string{"--bogus"}, "bogus"},
		{nil, "in-cluster"},
		{[]string{"--check"}, "in-cluster"},
	} {
		if err := Main(context.Background(), tt.args); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%v: got %v, want error containing %q", tt.args, err, tt.wantErr)
		}
	}
}
