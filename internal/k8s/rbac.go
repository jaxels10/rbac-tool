package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes clientset.
type Client struct {
	cs       *kubernetes.Clientset
	feedback *FeedbackStore
}

// NewClient creates a Kubernetes client. It tries in-cluster config first,
// then falls back to the local kubeconfig.
func NewClient() (*Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}
	return &Client{cs: cs, feedback: newFeedbackStore(cs)}, nil
}

// ---- View models ----

type RBACData struct {
	ServiceAccounts     []ServiceAccountView
	Roles               []RoleView
	RoleBindings        []BindingView
	ClusterRoles        []RoleView
	ClusterRoleBindings []BindingView
	Namespaces          []string
	Findings            []Finding
}

type ServiceAccountView struct {
	Namespace           string
	Name                string
	Age                 string
	RoleBindings        []SABindingDetail
	ClusterRoleBindings []SABindingDetail
	Workloads           []WorkloadView
}

type WorkloadView struct {
	Kind      string
	Namespace string
	Name      string
}

type SABindingDetail struct {
	BindingName      string
	BindingNamespace string // empty for ClusterRoleBindings
	RoleRef          string
	Rules            []PolicyRuleView
}

type RoleView struct {
	Namespace  string // empty for ClusterRoles
	Name       string
	Age        string
	RulesCount int
	Rules      []PolicyRuleView
}

type PolicyRuleView struct {
	Verbs     string
	Resources string
	APIGroups string
}

type BindingView struct {
	Namespace string // empty for ClusterRoleBindings
	Name      string
	Age       string
	RoleRef   string
	Subjects  []SubjectView
}

type SubjectView struct {
	Kind      string
	Namespace string
	Name      string
}

// ---- Fetch ----

func (c *Client) GetRBACData(ctx context.Context) (*RBACData, error) {
	data := &RBACData{}

	// Roles
	roleList, err := c.cs.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	roleRules := map[string][]PolicyRuleView{} // "namespace/name" -> rules
	nsSet := map[string]struct{}{}
	for _, r := range roleList.Items {
		nsSet[r.Namespace] = struct{}{}
		rv := toRoleView(r.Namespace, r.Name, r.CreationTimestamp, r.Rules)
		data.Roles = append(data.Roles, rv)
		roleRules[r.Namespace+"/"+r.Name] = rv.Rules
	}

	// ClusterRoles
	crList, err := c.cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	clusterRoleRules := map[string][]PolicyRuleView{} // "name" -> rules
	for _, cr := range crList.Items {
		rv := toRoleView("", cr.Name, cr.CreationTimestamp, cr.Rules)
		data.ClusterRoles = append(data.ClusterRoles, rv)
		clusterRoleRules[cr.Name] = rv.Rules
	}

	// RoleBindings
	rbList, err := c.cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	// index: "saNamespace/saName" -> []SABindingDetail
	saRoleBindings := map[string][]SABindingDetail{}
	for _, rb := range rbList.Items {
		nsSet[rb.Namespace] = struct{}{}
		data.RoleBindings = append(data.RoleBindings, toBindingView(rb.Namespace, rb.Name, rb.CreationTimestamp, rb.RoleRef, rb.Subjects))
		roleRef := rb.RoleRef.Kind + "/" + rb.RoleRef.Name
		var rules []PolicyRuleView
		if rb.RoleRef.Kind == "ClusterRole" {
			rules = clusterRoleRules[rb.RoleRef.Name]
		} else {
			rules = roleRules[rb.Namespace+"/"+rb.RoleRef.Name]
		}
		for _, s := range rb.Subjects {
			if s.Kind != "ServiceAccount" {
				continue
			}
			key := s.Namespace + "/" + s.Name
			saRoleBindings[key] = append(saRoleBindings[key], SABindingDetail{
				BindingName:      rb.Name,
				BindingNamespace: rb.Namespace,
				RoleRef:          roleRef,
				Rules:            rules,
			})
		}
	}

	// ClusterRoleBindings
	crbList, err := c.cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	saClusterRoleBindings := map[string][]SABindingDetail{}
	for _, crb := range crbList.Items {
		data.ClusterRoleBindings = append(data.ClusterRoleBindings, toBindingView("", crb.Name, crb.CreationTimestamp, crb.RoleRef, crb.Subjects))
		roleRef := crb.RoleRef.Kind + "/" + crb.RoleRef.Name
		rules := clusterRoleRules[crb.RoleRef.Name]
		for _, s := range crb.Subjects {
			if s.Kind != "ServiceAccount" {
				continue
			}
			key := s.Namespace + "/" + s.Name
			saClusterRoleBindings[key] = append(saClusterRoleBindings[key], SABindingDetail{
				BindingName: crb.Name,
				RoleRef:     roleRef,
				Rules:       rules,
			})
		}
	}

	// Workloads — build SA -> workload index
	saWorkloads := map[string][]WorkloadView{}
	addWorkload := func(ns, saName, kind, wNs, wName string) {
		if saName == "" {
			return
		}
		key := ns + "/" + saName
		saWorkloads[key] = append(saWorkloads[key], WorkloadView{Kind: kind, Namespace: wNs, Name: wName})
	}
	if deployList, err := c.cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, d := range deployList.Items {
			addWorkload(d.Namespace, d.Spec.Template.Spec.ServiceAccountName, "Deployment", d.Namespace, d.Name)
		}
	}
	if ssList, err := c.cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, ss := range ssList.Items {
			addWorkload(ss.Namespace, ss.Spec.Template.Spec.ServiceAccountName, "StatefulSet", ss.Namespace, ss.Name)
		}
	}
	if dsList, err := c.cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, ds := range dsList.Items {
			addWorkload(ds.Namespace, ds.Spec.Template.Spec.ServiceAccountName, "DaemonSet", ds.Namespace, ds.Name)
		}
	}
	if jobList, err := c.cs.BatchV1().Jobs("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, j := range jobList.Items {
			addWorkload(j.Namespace, j.Spec.Template.Spec.ServiceAccountName, "Job", j.Namespace, j.Name)
		}
	}
	if cjList, err := c.cs.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, cj := range cjList.Items {
			addWorkload(cj.Namespace, cj.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName, "CronJob", cj.Namespace, cj.Name)
		}
	}

	// Service Accounts
	saList, err := c.cs.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	for _, sa := range saList.Items {
		nsSet[sa.Namespace] = struct{}{}
		key := sa.Namespace + "/" + sa.Name
		sav := toServiceAccountView(sa)
		sav.RoleBindings = saRoleBindings[key]
		sav.ClusterRoleBindings = saClusterRoleBindings[key]
		sav.Workloads = saWorkloads[key]
		data.ServiceAccounts = append(data.ServiceAccounts, sav)
	}

	// Sorted namespace list
	for ns := range nsSet {
		data.Namespaces = append(data.Namespaces, ns)
	}
	sort.Strings(data.Namespaces)

	// Findings — run analysis with persisted feedback
	fb, _ := c.feedback.All(ctx) // non-fatal: empty feedback on error
	data.Findings = Analyze(data, fb)

	return data, nil
}

// SetFeedback persists feedback for a finding.
func (c *Client) SetFeedback(ctx context.Context, findingID, status string) error {
	if status == "" {
		return c.feedback.Delete(ctx, findingID)
	}
	return c.feedback.Set(ctx, findingID, status)
}

// ---- Converters ----

func toServiceAccountView(sa corev1.ServiceAccount) ServiceAccountView {
	return ServiceAccountView{
		Namespace: sa.Namespace,
		Name:      sa.Name,
		Age:       age(sa.CreationTimestamp),
	}
}

func toRoleView(namespace, name string, ts metav1.Time, rules []rbacv1.PolicyRule) RoleView {
	rv := RoleView{
		Namespace:  namespace,
		Name:       name,
		Age:        age(ts),
		RulesCount: len(rules),
	}
	for _, rule := range rules {
		rv.Rules = append(rv.Rules, PolicyRuleView{
			Verbs:     strings.Join(rule.Verbs, ", "),
			Resources: strings.Join(rule.Resources, ", "),
			APIGroups: strings.Join(rule.APIGroups, ", "),
		})
	}
	return rv
}

func toBindingView(namespace, name string, ts metav1.Time, roleRef rbacv1.RoleRef, subjects []rbacv1.Subject) BindingView {
	bv := BindingView{
		Namespace: namespace,
		Name:      name,
		Age:       age(ts),
		RoleRef:   roleRef.Kind + "/" + roleRef.Name,
	}
	for _, s := range subjects {
		bv.Subjects = append(bv.Subjects, SubjectView{
			Kind:      s.Kind,
			Namespace: s.Namespace,
			Name:      s.Name,
		})
	}
	return bv
}

func age(ts metav1.Time) string {
	if ts.IsZero() {
		return "unknown"
	}
	d := time.Since(ts.Time)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
