package k8s

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Severity levels for findings.
type Severity string

const (
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Finding represents a single detected RBAC issue.
type Finding struct {
	ID          string   // stable fingerprint — same finding across runs has the same ID
	Rule        string   // machine-readable rule identifier
	Severity    Severity
	Title       string
	Description string
	Resources   []string // human-readable list of affected resources
	Feedback    string   // "confirmed", "dismissed", or "" (open)
}

// Rule is a function that inspects RBACData and returns zero or more findings.
// Add new rules to the allRules slice below to extend detection.
type Rule func(*RBACData) []Finding

// allRules is the ordered list of active detection rules.
// To add a new rule: write a func(*RBACData) []Finding and append it here.
var allRules = []Rule{
	ruleSharedServiceAccount,
	ruleWildcardPermissions,
	ruleDefaultSAInUse,
	ruleClusterAdminBinding,
	ruleCrossNamespaceBinding,
}

// Analyze runs all rules against data, attaches persisted feedback, and returns findings.
func Analyze(data *RBACData, feedback map[string]string) []Finding {
	var findings []Finding
	seen := map[string]bool{} // deduplicate by ID
	for _, rule := range allRules {
		for _, f := range rule(data) {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			if status, ok := feedback[f.ID]; ok {
				f.Feedback = status
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// fp produces a short stable fingerprint from the given parts.
func fp(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

// ── Rules ────────────────────────────────────────────────────────────────────

// ruleSharedServiceAccount warns when multiple workloads in the same namespace
// share a service account, violating the one-workload-per-SA best practice.
func ruleSharedServiceAccount(data *RBACData) []Finding {
	var findings []Finding
	for _, sa := range data.ServiceAccounts {
		if len(sa.Workloads) < 2 {
			continue
		}
		names := make([]string, len(sa.Workloads))
		for i, w := range sa.Workloads {
			names[i] = w.Kind + "/" + w.Name
		}
		findings = append(findings, Finding{
			ID:       fp("shared-sa", sa.Namespace, sa.Name),
			Rule:     "shared-sa",
			Severity: SeverityWarning,
			Title:    fmt.Sprintf("Service account %q shared by %d workloads", sa.Name, len(sa.Workloads)),
			Description: fmt.Sprintf(
				"Service account %s/%s is used by %d workloads (%s). "+
					"Kubernetes best practice recommends one dedicated service account per workload "+
					"so that a compromised workload cannot leverage another workload's permissions.",
				sa.Namespace, sa.Name, len(sa.Workloads), strings.Join(names, ", "),
			),
			Resources: append([]string{sa.Namespace + "/ServiceAccount/" + sa.Name}, names...),
		})
	}
	return findings
}

// ruleWildcardPermissions warns when a Role or ClusterRole contains wildcard
// verbs or resources, granting broader access than necessary.
func ruleWildcardPermissions(data *RBACData) []Finding {
	var findings []Finding
	check := func(ns, kind, name string, rules []PolicyRuleView) {
		for _, r := range rules {
			if !strings.Contains(r.Verbs, "*") && !strings.Contains(r.Resources, "*") {
				continue
			}
			// Skip well-known system roles — they are intentionally broad.
			if strings.HasPrefix(name, "system:") {
				return
			}
			findings = append(findings, Finding{
				ID:       fp("wildcard-perms", ns, kind, name),
				Rule:     "wildcard-perms",
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("%s %q grants wildcard permissions", kind, name),
				Description: fmt.Sprintf(
					"%s %s/%s contains a rule with wildcard verbs or resources. "+
						"This grants broader access than necessary and violates least-privilege. "+
						"Scope the rule to specific verbs and resources.",
					kind, ns, name,
				),
				Resources: []string{ns + "/" + kind + "/" + name},
			})
			return // one finding per role is enough
		}
	}
	for _, r := range data.Roles {
		check(r.Namespace, "Role", r.Name, r.Rules)
	}
	for _, cr := range data.ClusterRoles {
		check("(cluster)", "ClusterRole", cr.Name, cr.Rules)
	}
	return findings
}

// ruleDefaultSAInUse warns when workloads explicitly use the default service
// account instead of a dedicated one.
func ruleDefaultSAInUse(data *RBACData) []Finding {
	var findings []Finding
	for _, sa := range data.ServiceAccounts {
		if sa.Name != "default" || len(sa.Workloads) == 0 {
			continue
		}
		names := make([]string, len(sa.Workloads))
		for i, w := range sa.Workloads {
			names[i] = w.Kind + "/" + w.Name
		}
		findings = append(findings, Finding{
			ID:       fp("default-sa-used", sa.Namespace),
			Rule:     "default-sa-used",
			Severity: SeverityWarning,
			Title:    fmt.Sprintf("Default service account used in namespace %q", sa.Namespace),
			Description: fmt.Sprintf(
				"The default service account in namespace %s is actively used by: %s. "+
					"Workloads should use dedicated service accounts to follow least-privilege. "+
					"The default service account often receives unintended permissions.",
				sa.Namespace, strings.Join(names, ", "),
			),
			Resources: append([]string{sa.Namespace + "/ServiceAccount/default"}, names...),
		})
	}
	return findings
}

// ruleClusterAdminBinding warns when a service account is bound to cluster-admin
// or an equivalent all-wildcard ClusterRole via a ClusterRoleBinding.
func ruleClusterAdminBinding(data *RBACData) []Finding {
	// Build set of effectively cluster-admin roles.
	adminRoles := map[string]bool{"cluster-admin": true}
	for _, cr := range data.ClusterRoles {
		if strings.HasPrefix(cr.Name, "system:") {
			continue
		}
		for _, r := range cr.Rules {
			if strings.Contains(r.Verbs, "*") && strings.Contains(r.Resources, "*") {
				adminRoles[cr.Name] = true
				break
			}
		}
	}

	var findings []Finding
	for _, crb := range data.ClusterRoleBindings {
		roleName, _ := strings.CutPrefix(crb.RoleRef, "ClusterRole/")
		if !adminRoles[roleName] {
			continue
		}
		for _, s := range crb.Subjects {
			if s.Kind != "ServiceAccount" {
				continue
			}
			findings = append(findings, Finding{
				ID:       fp("cluster-admin-binding", crb.Name, s.Namespace, s.Name),
				Rule:     "cluster-admin-binding",
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("Service account %q/%q has cluster-admin privileges", s.Namespace, s.Name),
				Description: fmt.Sprintf(
					"Service account %s/%s is bound to %s via ClusterRoleBinding %q. "+
						"This grants unrestricted access to the entire cluster. "+
						"Replace with a scoped ClusterRole or namespace-scoped Role.",
					s.Namespace, s.Name, crb.RoleRef, crb.Name,
				),
				Resources: []string{
					s.Namespace + "/ServiceAccount/" + s.Name,
					"ClusterRoleBinding/" + crb.Name,
				},
			})
		}
	}
	return findings
}

// ruleCrossNamespaceBinding warns when a RoleBinding grants access to a service
// account from a different namespace, which can enable lateral movement.
func ruleCrossNamespaceBinding(data *RBACData) []Finding {
	var findings []Finding
	for _, rb := range data.RoleBindings {
		for _, s := range rb.Subjects {
			if s.Kind != "ServiceAccount" || s.Namespace == "" || s.Namespace == rb.Namespace {
				continue
			}
			findings = append(findings, Finding{
				ID:       fp("cross-ns-binding", rb.Namespace, rb.Name, s.Namespace, s.Name),
				Rule:     "cross-ns-binding",
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("RoleBinding %q grants access to SA from another namespace", rb.Name),
				Description: fmt.Sprintf(
					"RoleBinding %s/%s grants %s to service account %s/%s, which is in a different namespace. "+
						"Cross-namespace bindings can enable lateral movement between namespaces.",
					rb.Namespace, rb.Name, rb.RoleRef, s.Namespace, s.Name,
				),
				Resources: []string{
					rb.Namespace + "/RoleBinding/" + rb.Name,
					s.Namespace + "/ServiceAccount/" + s.Name,
				},
			})
		}
	}
	return findings
}
