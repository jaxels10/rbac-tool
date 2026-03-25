package k8s

import (
	"context"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const feedbackConfigMap = "rbac-tool-feedback"

// FeedbackStore persists finding feedback in a Kubernetes ConfigMap.
// Keys are finding IDs; values are "confirmed" or "dismissed".
type FeedbackStore struct {
	cs        *kubernetes.Clientset
	namespace string
}

func newFeedbackStore(cs *kubernetes.Clientset) *FeedbackStore {
	return &FeedbackStore{cs: cs, namespace: podNamespace()}
}

// All returns the current feedback map. Returns an empty map if none exists yet.
func (f *FeedbackStore) All(ctx context.Context) (map[string]string, error) {
	cm, err := f.cs.CoreV1().ConfigMaps(f.namespace).Get(ctx, feedbackConfigMap, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cm.Data))
	for k, v := range cm.Data {
		out[k] = v
	}
	return out, nil
}

// Set records feedback for a single finding ID.
func (f *FeedbackStore) Set(ctx context.Context, findingID, status string) error {
	cm, err := f.cs.CoreV1().ConfigMaps(f.namespace).Get(ctx, feedbackConfigMap, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: feedbackConfigMap, Namespace: f.namespace},
			Data:       map[string]string{findingID: status},
		}
		_, err = f.cs.CoreV1().ConfigMaps(f.namespace).Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[findingID] = status
	_, err = f.cs.CoreV1().ConfigMaps(f.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// Delete removes feedback for a finding ID (resets it to "open").
func (f *FeedbackStore) Delete(ctx context.Context, findingID string) error {
	cm, err := f.cs.CoreV1().ConfigMaps(f.namespace).Get(ctx, feedbackConfigMap, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	delete(cm.Data, findingID)
	_, err = f.cs.CoreV1().ConfigMaps(f.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// podNamespace returns the namespace this pod is running in.
func podNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "default"
}
