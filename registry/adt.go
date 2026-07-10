package registry

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/capcompute/sys"
)

// EgressForbidFloor is the reserved taint every network-egress sink refuses by
// default, unioned on top of a manifest's declared per-operation taints. It
// makes the flow policy fail CLOSED on omission: labeling a SOURCE with the
// reserved class once — e.g. a filesystem read over a secrets dir,
// {"operation":"read","labels":["secret"]} — guarantees that data cannot flow to
// any network egress (internet of any method, http templates, the LLM provider)
// even when a sink's own "taints" list forgets it. Lift it only through the
// governed sys.declassify. A manifest that never uses the reserved label is
// unaffected (the floor is inert unless something is labeled with it).
var EgressForbidFloor = []string{"secret"}

// WithEgressFloor unions the egress forbid floor onto an operation's declared
// sink taints. Applied at every network-egress driver's build so a sink is never
// a fully open channel for the reserved secret class. Returns a fresh slice: for
// an op with no declared taints, UnionLabels would otherwise return the shared
// EgressForbidFloor backing array, so every such sink would alias one slice.
func WithEgressFloor(taints []string) []string {
	return append([]string(nil), builtin.UnionLabels(taints, EgressForbidFloor)...)
}

// FlowPolicy is the per-operation data-flow declaration carried on a leaf grant's
// capability entry. Labels are the source classes the operation's results carry —
// stamped onto every result and accumulated into the run's taint. Taints are the
// labels barred from flowing into the operation — the sink guard: a run that has
// observed one is refused before the effect runs. A manifest entry reads
// {"operation":"put","labels":["stored"],"taints":["untrusted_web"]}: the write
// tags stored data `stored`, and refuses to persist anything `untrusted_web`.
type FlowPolicy struct {
	Labels []string `json:"labels,omitempty"`
	Taints []string `json:"taints,omitempty"`
}

// Normalized canonicalizes both label sets (trim/dedup/sort, reserved "syscall:"
// prefix rejected) with the kernel's shared hygiene.
func (f FlowPolicy) Normalized() (FlowPolicy, error) {
	labels, err := sys.NormalizeLabels("labels", f.Labels)
	if err != nil {
		return FlowPolicy{}, err
	}
	taints, err := sys.NormalizeLabels("taints", f.Taints)
	if err != nil {
		return FlowPolicy{}, err
	}
	return FlowPolicy{Labels: labels, Taints: taints}, nil
}

// OperationGrant is one entry in an enum-discriminated leaf grant's
// `capabilities` list: the operation it enables (a case of the ADT, keyed by the
// `operation` discriminator), its optional human-approval requirement, and its
// data-flow policy. Unknown fields are rejected so a typo surfaces at manifest
// time.
type OperationGrant struct {
	Operation       string `json:"operation"`
	RequireApproval *bool  `json:"require_approval,omitempty"`
	FlowPolicy
}

// DecodeOperationGrants parses a leaf grant's `capabilities` list strictly.
func DecodeOperationGrants(raw json.RawMessage) ([]OperationGrant, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var grants []OperationGrant
	if err := decoder.Decode(&grants); err != nil {
		return nil, err
	}
	return grants, nil
}

// OperationBranch builds one oneOf branch of a leaf capability's ADT: the
// operation's field schema with the `operation` discriminator pinned to a const
// and made required. opSchema must be a JSON object schema; an empty schema
// yields a closed object taking only `operation`.
func OperationBranch(operation string, opSchema json.RawMessage) (json.RawMessage, error) {
	schema := map[string]json.RawMessage{}
	if len(opSchema) == 0 {
		opSchema = json.RawMessage(`{"type":"object","additionalProperties":false}`)
	}
	if err := json.Unmarshal(opSchema, &schema); err != nil {
		return nil, fmt.Errorf("operation %q schema: %w", operation, err)
	}
	props := map[string]json.RawMessage{}
	if raw, ok := schema["properties"]; ok {
		if err := json.Unmarshal(raw, &props); err != nil {
			return nil, fmt.Errorf("operation %q properties: %w", operation, err)
		}
	}
	operationConst, _ := json.Marshal(operation)
	props["operation"] = json.RawMessage(fmt.Sprintf(`{"const":%s}`, operationConst))
	schema["properties"], _ = json.Marshal(props)
	var required []string
	if raw, ok := schema["required"]; ok {
		if err := json.Unmarshal(raw, &required); err != nil {
			return nil, fmt.Errorf("operation %q required: %w", operation, err)
		}
	}
	required = append([]string{"operation"}, required...)
	schema["required"], _ = json.Marshal(required)
	if _, ok := schema["type"]; !ok {
		schema["type"] = json.RawMessage(`"object"`)
	}
	return json.Marshal(schema)
}

// OneOfSchema wraps per-operation branches in a discriminated union — the input
// schema the guest is shown and the kernel Validator enforces.
func OneOfSchema(branches []json.RawMessage) json.RawMessage {
	arr, _ := json.Marshal(branches)
	return json.RawMessage(fmt.Sprintf(`{"oneOf":%s}`, arr))
}
