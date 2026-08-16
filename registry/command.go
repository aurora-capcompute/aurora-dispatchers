package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/command"
)

// CommandRule is one allowlisted command — one operation of core.command.
type CommandRule struct {
	// Operation is what a guest calls this command by: the ADT case it selects.
	Operation string `json:"operation"`
	// Description tells the model what the command does and when to reach for it.
	Description string `json:"description,omitempty"`
	// Path is the absolute executable. There is deliberately no PATH lookup:
	// which binary runs must not depend on an inherited environment.
	Path string `json:"path"`
	// Args is the argument vector, with {slot} placeholders filled from params.
	Args []string `json:"args,omitempty"`
	// Dir is the working directory (absolute).
	Dir string `json:"dir,omitempty"`
	// Env is the child's entire environment — it inherits nothing. Values may be
	// secret references ({"secret":"NAME"}) resolved host-side.
	Env map[string]Secret `json:"env,omitempty"`
	// Params declares each slot Args may reference. A value is either a JSON
	// array (the closed set of permitted values) or a string (a regular
	// expression, anchored by the loader).
	Params map[string]CommandParam `json:"params,omitempty"`

	TimeoutMS      int64 `json:"timeout_ms,omitempty"`
	MaxOutputBytes int64 `json:"max_output_bytes,omitempty"`

	RequireApproval *bool `json:"require_approval,omitempty"`
	FlowPolicy
}

// CommandParam declares one slot: a closed set of values, or a pattern. Prefer
// the set wherever the choices can be enumerated — a context, an environment, a
// cluster. It states the policy exactly, it cannot over-match, and it reaches
// the guest as a JSON Schema enum, so the kernel Validator refuses a bad value
// before the driver runs and the model can see which values exist.
type CommandParam struct {
	oneOf   []string
	pattern string
}

func (p *CommandParam) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return fmt.Errorf(`a parameter must be a list of values or a pattern string`)
	}
	if trimmed[0] == '[' {
		var values []string
		if err := json.Unmarshal(trimmed, &values); err != nil {
			return fmt.Errorf("parameter value list: %w", err)
		}
		*p = CommandParam{oneOf: values}
		return nil
	}
	var expr string
	if err := json.Unmarshal(trimmed, &expr); err != nil {
		return fmt.Errorf(`a parameter must be a list of values or a pattern string: %w`, err)
	}
	*p = CommandParam{pattern: expr}
	return nil
}

func (p CommandParam) MarshalJSON() ([]byte, error) {
	if len(p.oneOf) > 0 {
		return json.Marshal(p.oneOf)
	}
	return json.Marshal(p.pattern)
}

// commandConfig is a core.command grant's driver configuration.
type commandConfig struct {
	Capabilities []CommandRule `json:"capabilities,omitempty"`
}

// paramNamePattern is the shape of a slot name — also the shape the {slot}
// placeholder syntax can express, so a declared name is always referenceable.
var paramNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// commandNamePattern is the shape of a command's guest-facing name.
var commandNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// CommandRegistration runs host commands from an author-declared allowlist. Each
// allowlisted command is one operation of core.command: the host owns the entire
// command line and the guest fills only the slots that command declared. There
// is no shell — a command is executed with its argument vector, so a parameter
// cannot become syntax.
type CommandRegistration struct{}

func (CommandRegistration) Matches(syscall string) bool { return syscall == command.Capability }

func (CommandRegistration) Configure(_ context.Context, raw json.RawMessage, services Services) (capability.Family, error) {
	_, grants, err := parseCommandConfig(raw)
	if err != nil {
		return capability.Family{}, err
	}

	commands := make([]command.Command, 0, len(grants))
	for _, rule := range grants {
		built, err := buildCommand(rule, services)
		if err != nil {
			return capability.Family{}, fmt.Errorf("command %q: %w", rule.Operation, err)
		}
		commands = append(commands, built)
	}

	handler := command.Handler{
		Name:     command.Capability,
		Commands: commands,
	}

	// One entry per command: two commands may declare the same slot name with
	// different constraints, and a merged params object would have to pick one of
	// them — publishing a constraint that does not match the command being called.
	sorted := append([]command.Command(nil), commands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	entries := make([]capability.Entry, 0, len(sorted))
	for _, c := range sorted {
		branch, err := OperationBranch(c.Name, commandParamsSchema(c))
		if err != nil {
			return capability.Family{}, err
		}
		entries = append(entries, capability.Entry{
			Key:             capability.Key{Syscall: command.Capability, Operation: c.Name},
			Discriminator:   "operation",
			Description:     c.Description,
			Input:           branch,
			Labels:          c.Labels,
			Forbid:          c.Taints,
			RequireApproval: c.RequireApproval,
			Handler:         handler,
		})
	}
	return capability.Family{Entries: entries,
		Description: commandDescription(commands),
	}, nil
}

// buildCommand resolves one validated rule into the executable form, resolving
// secret-referencing environment values host-side.
func buildCommand(rule CommandRule, services Services) (command.Command, error) {
	env := make(map[string]string, len(rule.Env))
	for key, secret := range rule.Env {
		value, err := secret.Resolve(services.Secrets)
		if err != nil {
			return command.Command{}, fmt.Errorf("env %q: %w", key, err)
		}
		env[key] = value
	}
	params := make(map[string]command.Param, len(rule.Params))
	for name, declared := range rule.Params {
		built, err := declared.compile(name)
		if err != nil {
			return command.Command{}, err
		}
		params[name] = built
	}
	return command.Command{
		Name:            rule.Operation,
		Description:     rule.Description,
		Path:            rule.Path,
		Args:            append([]string(nil), rule.Args...),
		Dir:             rule.Dir,
		Env:             env,
		Params:          params,
		Timeout:         time.Duration(rule.TimeoutMS) * time.Millisecond,
		MaxOutputBytes:  rule.MaxOutputBytes,
		RequireApproval: rule.RequireApproval == nil || *rule.RequireApproval,
		Labels:          rule.Labels,
		Taints:          rule.Taints,
	}, nil
}

// compile turns a declared slot into its enforcing form. A pattern is anchored
// here rather than trusted to be anchored by its author: an unanchored
// expression matches anywhere in the value, so "prod" would admit
// "not-prod-really" — the classic way a regular expression admits more than the
// author read it as admitting.
func (p CommandParam) compile(name string) (command.Param, error) {
	if len(p.oneOf) > 0 {
		values := make([]string, 0, len(p.oneOf))
		seen := make(map[string]struct{}, len(p.oneOf))
		for _, value := range p.oneOf {
			if value == "" {
				return command.Param{}, fmt.Errorf("parameter %q: a permitted value is empty", name)
			}
			if strings.HasPrefix(value, "-") {
				return command.Param{}, fmt.Errorf("parameter %q: permitted value %q begins with %q and would be read as a flag", name, value, "-")
			}
			if _, dup := seen[value]; dup {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
		sort.Strings(values)
		return command.Param{OneOf: values}, nil
	}
	if strings.TrimSpace(p.pattern) == "" {
		return command.Param{}, fmt.Errorf("parameter %q declares neither permitted values nor a pattern", name)
	}
	compiled, err := regexp.Compile(`\A(?:` + p.pattern + `)\z`)
	if err != nil {
		return command.Param{}, fmt.Errorf("parameter %q pattern: %w", name, err)
	}
	return command.Param{Pattern: compiled, Source: p.pattern}, nil
}

// parseCommandConfig validates and canonicalizes a core.command grant's config.
func parseCommandConfig(raw json.RawMessage) (commandConfig, []CommandRule, error) {
	var config commandConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return commandConfig{}, nil, err
		}
	}
	if len(config.Capabilities) == 0 {
		return commandConfig{}, nil, fmt.Errorf("capabilities must grant at least one operation")
	}
	seen := make(map[string]struct{}, len(config.Capabilities))
	grants := make([]CommandRule, len(config.Capabilities))
	for i, rule := range config.Capabilities {
		normalized, err := normalizeCommandRule(rule)
		if err != nil {
			return commandConfig{}, nil, fmt.Errorf("capability %d: %w", i, err)
		}
		if _, dup := seen[normalized.Operation]; dup {
			return commandConfig{}, nil, fmt.Errorf("operation %q is granted more than once", normalized.Operation)
		}
		seen[normalized.Operation] = struct{}{}
		grants[i] = normalized
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Operation < grants[j].Operation })
	return config, grants, nil
}

// normalizeCommandRule validates one allowlisted command: its identity, its
// executable, and the agreement between its argument template and its declared
// slots.
func normalizeCommandRule(rule CommandRule) (CommandRule, error) {
	rule.Operation = strings.ToLower(strings.TrimSpace(rule.Operation))
	rule.Path = strings.TrimSpace(rule.Path)
	rule.Dir = strings.TrimSpace(rule.Dir)
	if !commandNamePattern.MatchString(rule.Operation) {
		return CommandRule{}, fmt.Errorf("operation %q must be a lowercase identifier", rule.Operation)
	}
	if !filepath.IsAbs(rule.Path) || rule.Path != filepath.Clean(rule.Path) {
		return CommandRule{}, fmt.Errorf("path %q must be an absolute, cleaned path (there is no PATH lookup)", rule.Path)
	}
	if rule.Dir != "" && (!filepath.IsAbs(rule.Dir) || rule.Dir != filepath.Clean(rule.Dir)) {
		return CommandRule{}, fmt.Errorf("dir %q must be an absolute, cleaned path", rule.Dir)
	}
	for key := range rule.Env {
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "=\x00") {
			return CommandRule{}, fmt.Errorf("env name %q is not a valid variable name", key)
		}
	}

	// Slot names must be referenceable, and template and declarations must agree
	// in both directions: an unreferenced slot is dead config, and an undeclared
	// placeholder would run as the literal text "{name}".
	for name, param := range rule.Params {
		if !paramNamePattern.MatchString(name) {
			return CommandRule{}, fmt.Errorf("parameter name %q must be a lowercase identifier", name)
		}
		if _, err := param.compile(name); err != nil {
			return CommandRule{}, err
		}
	}
	referenced := map[string]struct{}{}
	for _, arg := range rule.Args {
		for _, match := range placeholderPattern.FindAllStringSubmatch(arg, -1) {
			name := match[1]
			if _, declared := rule.Params[name]; !declared {
				return CommandRule{}, fmt.Errorf("argument references undeclared parameter {%s}", name)
			}
			referenced[name] = struct{}{}
		}
	}
	for name := range rule.Params {
		if _, used := referenced[name]; !used {
			return CommandRule{}, fmt.Errorf("parameter %q is declared but never referenced by an argument", name)
		}
	}

	if rule.TimeoutMS < 0 || rule.MaxOutputBytes < 0 {
		return CommandRule{}, fmt.Errorf("timeout_ms and max_output_bytes must not be negative")
	}
	flow, err := rule.FlowPolicy.Normalized()
	if err != nil {
		return CommandRule{}, err
	}
	rule.FlowPolicy = flow
	return rule, nil
}

// placeholderPattern mirrors the driver's own placeholder syntax.
var placeholderPattern = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// commandParamsSchema types the params object of one command's call: exactly
// that command's slots with their own enum or pattern, all required.
// OperationBranch pins the operation itself. The kernel Validator enforces this
// before dispatch, so a missing slot or an out-of-set value is refused before
// the driver sees it — and the driver checks again.
func commandParamsSchema(c command.Command) json.RawMessage {
	names := c.ParamNames()
	if len(names) == 0 {
		return nil
	}
	properties := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		properties[name] = paramSchema(c.Params[name])
	}
	props, _ := json.Marshal(properties)
	required, _ := json.Marshal(names)
	return json.RawMessage(fmt.Sprintf(
		`{"type":"object","properties":{"params":{"type":"object","properties":%s,"required":%s,"additionalProperties":false}},"required":["params"],"additionalProperties":false}`,
		props, required))
}

func paramSchema(param command.Param) json.RawMessage {
	if len(param.OneOf) > 0 {
		values, _ := json.Marshal(param.OneOf)
		return json.RawMessage(fmt.Sprintf(`{"enum":%s}`, values))
	}
	pattern, _ := json.Marshal(`\A(?:` + param.Source + `)\z`)
	return json.RawMessage(fmt.Sprintf(`{"type":"string","pattern":%s}`, pattern))
}

// commandDescription composes the published tool doc: what may be run, and for
// each command the slots it takes and the values they admit.
func commandDescription(commands []command.Command) string {
	var b strings.Builder
	b.WriteString("Run one of the allowlisted host commands. The command line is fixed by the host; you choose one with `operation` and supply values for its declared parameters. Commands:")
	sorted := append([]command.Command(nil), commands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, c := range sorted {
		fmt.Fprintf(&b, "\n- %q", c.Name)
		if c.Description != "" {
			fmt.Fprintf(&b, ": %s", c.Description)
		}
		for _, name := range c.ParamNames() {
			param := c.Params[name]
			if len(param.OneOf) > 0 {
				fmt.Fprintf(&b, "\n    %s: one of %s", name, strings.Join(param.OneOf, ", "))
				continue
			}
			fmt.Fprintf(&b, "\n    %s: matching %s", name, param.Source)
		}
		if c.RequireApproval {
			b.WriteString("\n    (requires human approval)")
		}
	}
	return b.String()
}
