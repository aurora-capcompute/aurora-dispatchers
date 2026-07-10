package k8s

import (
	"fmt"
	"regexp"
	"strings"
)

// Every value a guest can place into a request URL is validated against a strict
// Kubernetes-shaped pattern here, BEFORE it is url-escaped into the path or
// query. The host is fixed by host-side config and never guest-supplied, so a
// guest cannot change which server is contacted; these guards close the
// remaining surface — a resource/namespace/name that smuggles a slash, "..", a
// query separator, or a control character to reach an unintended path or splice
// extra query parameters onto the request.

var (
	// resourcePattern is a lowercase plural resource name (pods, replicasets).
	resourcePattern = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	// groupPattern is an API group: a DNS subdomain (apps, networking.k8s.io).
	groupPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	// versionPattern is a Kubernetes API version (v1, v1beta1, v2alpha1).
	versionPattern = regexp.MustCompile(`^v[0-9]+((alpha|beta)[0-9]+)?$`)
	// namespacePattern and namePattern are DNS-1123 label / subdomain — the shapes
	// Kubernetes itself enforces for namespaces and object names.
	namespacePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	namePattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
)

const (
	maxNameLen      = 253
	maxNamespaceLen = 63
	maxGroupLen     = 253
	maxSelectorLen  = 2048
	maxContinueLen  = 8192
)

// validateResource checks a plural resource name.
func validateResource(resource string) error {
	if !resourcePattern.MatchString(resource) {
		return fmt.Errorf("resource %q is not a valid lowercase resource name", resource)
	}
	return nil
}

// validateGroup checks an API group; the empty group is the core group and is
// always valid.
func validateGroup(group string) error {
	if group == "" {
		return nil
	}
	if len(group) > maxGroupLen || !groupPattern.MatchString(group) {
		return fmt.Errorf("api group %q is not a valid DNS subdomain", group)
	}
	return nil
}

// validateVersion checks an API version string.
func validateVersion(version string) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("version %q is not a valid Kubernetes API version", version)
	}
	return nil
}

// validateNamespace checks a namespace (DNS-1123 label).
func validateNamespace(namespace string) error {
	if len(namespace) > maxNamespaceLen || !namespacePattern.MatchString(namespace) {
		return fmt.Errorf("namespace %q is not a valid DNS-1123 label", namespace)
	}
	return nil
}

// validateName checks an object name (DNS-1123 subdomain). The subdomain shape
// cannot begin with a dot, so "." and ".." are rejected structurally — no path
// segment a guest supplies can traverse.
func validateName(name string) error {
	if len(name) > maxNameLen || !namePattern.MatchString(name) {
		return fmt.Errorf("name %q is not a valid DNS-1123 object name", name)
	}
	return nil
}

// validateSelector bounds a label/field selector and rejects control characters.
// The selector grammar itself is not parsed — it is carried only as a url-encoded
// query value, so it cannot splice extra parameters or reach the path — but it is
// length-capped so a guest cannot push a pathological selector, and control
// characters are refused so it cannot corrupt the request line.
func validateSelector(kind, selector string) error {
	if len(selector) > maxSelectorLen {
		return fmt.Errorf("%s is %d bytes, over the %d-byte limit", kind, len(selector), maxSelectorLen)
	}
	if i := strings.IndexFunc(selector, isControl); i >= 0 {
		return fmt.Errorf("%s contains a control character", kind)
	}
	return nil
}

// validateContinue bounds a pagination continue token (an opaque server-issued
// string) and rejects control characters. Like a selector it rides only the
// query string url-encoded, so this is a size/hygiene bound, not an escape guard.
func validateContinue(token string) error {
	if len(token) > maxContinueLen {
		return fmt.Errorf("continue token is %d bytes, over the %d-byte limit", len(token), maxContinueLen)
	}
	if i := strings.IndexFunc(token, isControl); i >= 0 {
		return fmt.Errorf("continue token contains a control character")
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// ValidateResourceIdentity checks a (group, version, resource) triple — the
// exported guard the registry uses to validate an allowlist entry's identity.
func ValidateResourceIdentity(group, version, resource string) error {
	if err := validateGroup(group); err != nil {
		return err
	}
	if err := validateVersion(version); err != nil {
		return err
	}
	return validateResource(resource)
}

// ValidateNamespaceName checks a namespace — the exported guard the registry
// uses to validate an allowlist entry's namespaces.
func ValidateNamespaceName(namespace string) error { return validateNamespace(namespace) }
