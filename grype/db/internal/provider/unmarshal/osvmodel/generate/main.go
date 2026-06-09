// This program regenerates the osvmodel package from the upstream OSV JSON
// schema (github.com/ossf/osv-schema) by shelling out to the maintained
// JSON-Schema-to-Go generator at github.com/atombender/go-jsonschema.
//
// It writes into the parent osvmodel directory:
//   - schema-v1.json                  pinned upstream schema (latest v1.* tag)
//   - schema-v1.tag                   the upstream tag the pinned schema came from
//   - vulnerability_v1_generated.go   Go model emitted by go-jsonschema
//
// Run via `make generate:osv-model` (regenerates from the committed pin) or
// `make update:osv-model` (fetches latest v1 upstream, then regenerates).
//
// The schema is rewritten before go-jsonschema sees it. Off-the-shelf output
// against the raw OSV schema has unusable shapes for our callers: every
// optional field is *T, list elements are anonymous structs, ID and Ecosystem
// are typed-string aliases, Event is map[string]any (oneOf bails out), and so
// on. stripConstraints below runs a small pipeline of transforms that fix
// these one by one; each helper documents the specific shape it's working
// around.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	releasesAPI   = "https://api.github.com/repos/ossf/osv-schema/releases/latest"
	schemaURLFmt  = "https://raw.githubusercontent.com/ossf/osv-schema/%s/validation/schema.json"
	pinnedFile    = "schema-v1.json"
	pinnedTagFile = "schema-v1.tag"
	generatedFile = "vulnerability_v1_generated.go"
	generatorMod  = "github.com/atombender/go-jsonschema@v0.23.1"
	requirePrefix = "v1."
)

// packageDir returns the absolute path to the osvmodel package (one level up
// from this generator). Anchoring to the source-file location via
// runtime.Caller keeps output paths stable regardless of caller CWD.
func packageDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller(0) failed; can't locate generator source")
	}
	return filepath.Dir(filepath.Dir(thisFile))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	pull := flag.Bool("pull", false,
		"fetch the latest v1 schema from upstream and overwrite the pinned schema-v1.json before regenerating")
	flag.Parse()

	tag, schemaBytes, err := loadSchema(*pull)
	if err != nil {
		return err
	}
	if schemaBytes == nil {
		return nil // soft refusal path
	}

	stripped, err := stripConstraints(schemaBytes)
	if err != nil {
		return fmt.Errorf("preprocess schema: %w", err)
	}

	out, err := invokeGenerator(stripped)
	if err != nil {
		return fmt.Errorf("invoke go-jsonschema: %w", err)
	}
	out = addHeader(out, tag)

	if err := atomicWrite(filepath.Join(packageDir(), generatedFile), out); err != nil {
		return fmt.Errorf("write %s: %w", generatedFile, err)
	}
	fmt.Printf("regenerated %s from osv-schema %s via %s\n", generatedFile, tag, generatorMod)
	return nil
}

// ============================================================================
// Schema loading (pinned file vs fetched)
// ============================================================================

func loadSchema(pull bool) (string, []byte, error) {
	if !pull {
		data, err := os.ReadFile(filepath.Join(packageDir(), pinnedFile))
		if err != nil {
			return "", nil, fmt.Errorf("read pinned %s: %w (run with --pull to fetch upstream)", pinnedFile, err)
		}
		tagBytes, err := os.ReadFile(filepath.Join(packageDir(), pinnedTagFile))
		if err != nil {
			return "", nil, fmt.Errorf("read pinned %s: %w (run with --pull to fetch upstream)", pinnedTagFile, err)
		}
		return strings.TrimSpace(string(tagBytes)), data, nil
	}

	tag, err := latestReleaseTag()
	if err != nil {
		return "", nil, fmt.Errorf("fetch latest release tag: %w", err)
	}
	if !strings.HasPrefix(tag, requirePrefix) {
		fmt.Fprintf(os.Stderr,
			"upstream cut %s; refusing to overwrite the %s* track.\n"+
				"manual steps to handle a major bump:\n"+
				"  1. copy schema-v1.json to schema-v1-final.json (preserve old track)\n"+
				"  2. write a new generator for v2 (likely a fork of this file)\n"+
				"  3. emit a parallel vulnerability_v2_generated.go\n",
			tag, requirePrefix)
		return tag, nil, nil
	}

	body, err := fetchBytes(fmt.Sprintf(schemaURLFmt, tag))
	if err != nil {
		return "", nil, fmt.Errorf("fetch schema at %s: %w", tag, err)
	}
	if err := atomicWrite(filepath.Join(packageDir(), pinnedFile), body); err != nil {
		return "", nil, fmt.Errorf("write %s: %w", pinnedFile, err)
	}
	if err := atomicWrite(filepath.Join(packageDir(), pinnedTagFile), []byte(tag+"\n")); err != nil {
		return "", nil, fmt.Errorf("write %s: %w", pinnedTagFile, err)
	}
	return tag, body, nil
}

func latestReleaseTag() (string, error) {
	req, _ := http.NewRequest(http.MethodGet, releasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("%s: %s: %s", releasesAPI, resp.Status, b)
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.TagName == "" {
		return "", errors.New("no tag_name in release response")
	}
	return r.TagName, nil
}

func fetchBytes(url string) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ============================================================================
// Schema preprocessing
// ============================================================================

// stripConstraints applies a pipeline of transforms to the upstream OSV schema
// so go-jsonschema's emitter produces an ergonomic Go type set. Each step
// targets a specific shortcoming in the off-the-shelf output; comments on the
// individual helpers explain what each step buys us.
//
// Net result: zero `*string`/`*T` fields, zero anonymous slice-element types,
// named enum types (RangeType vs Type), plain string ID/Ecosystem fields
// instead of typed-string aliases.
func stripConstraints(in []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(in, &doc); err != nil {
		return nil, err
	}

	doc["title"] = "Vulnerability" // rename root struct
	inlineSimpleRefs(doc)          // collapse $defs/prefix etc. → plain string
	dropInlinedDefs(doc)           // delete the now-orphan $defs entries
	liftInlineItems(doc)           // []struct{...} → []NamedType
	liftInlineEnums(doc)           // SeverityEntry.Type Type → SeverityType etc.
	flattenOneOfProperties(doc)    // Event oneOf → flat struct
	strip(doc)                     // drop remaining oneOf/allOf
	markAllRequired(doc)           // every field non-pointer
	denullTypeUnions(doc)          // ["array","null"] → "array"

	return json.MarshalIndent(doc, "", "  ")
}

// inlineSimpleRefs replaces references to $defs that are plain typed-string
// validators (osv prefix, ecosystem name patterns) with `{"type": "string"}`
// inline. Without this the library generates ugly typed aliases:
//
//	ID CurrentlySupportedHomeDatabaseIdentifierPrefixes
//	Ecosystem CurrentlySupportedEcosystems
//
// which force string() conversion at every use site in strategy code.
func inlineSimpleRefs(node any) {
	targets := map[string]bool{
		"#/$defs/prefix":              true,
		"#/$defs/ecosystemName":       true,
		"#/$defs/ecosystemSuffix":     true,
		"#/$defs/ecosystemWithSuffix": true,
	}
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if ref, _ := v["$ref"].(string); targets[ref] {
				for k := range v {
					delete(v, k)
				}
				v["type"] = "string"
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(node)
}

// dropInlinedDefs removes the $defs entries we just inlined, so the library
// doesn't emit orphan typed-string aliases that nothing references.
func dropInlinedDefs(doc map[string]any) {
	defs, _ := doc["$defs"].(map[string]any)
	for _, name := range []string{"prefix", "ecosystemName", "ecosystemSuffix", "ecosystemWithSuffix"} {
		delete(defs, name)
	}
}

// liftInlineItems moves the inline `items` of array-typed properties into
// $defs entries with friendly names. Without this, `affected` becomes
// `[]struct{...}` (anonymous element type) and you can't write a helper that
// takes a single Affected entry as a parameter.
func liftInlineItems(doc map[string]any) {
	defs, _ := doc["$defs"].(map[string]any)
	if defs == nil {
		defs = map[string]any{}
		doc["$defs"] = defs
	}

	lift := func(host map[string]any, key, defName string) {
		field, _ := host[key].(map[string]any)
		if field == nil {
			return
		}
		items, _ := field["items"].(map[string]any)
		if items == nil {
			return
		}
		if _, hasRef := items["$ref"]; hasRef {
			return
		}
		defs[defName] = items
		field["items"] = map[string]any{"$ref": "#/$defs/" + defName}
	}

	props, _ := doc["properties"].(map[string]any)
	lift(props, "affected", "affected_package")
	lift(props, "references", "reference")
	lift(props, "credits", "credit")

	// Lift inside the freshly-created affected_package entry.
	if ap, _ := defs["affected_package"].(map[string]any); ap != nil {
		if apProps, _ := ap["properties"].(map[string]any); apProps != nil {
			lift(apProps, "ranges", "range")
		}
	}
	if rng, _ := defs["range"].(map[string]any); rng != nil {
		if rngProps, _ := rng["properties"].(map[string]any); rngProps != nil {
			lift(rngProps, "events", "event")
		}
	}
	// $defs/severity is itself the array schema; lift its items.
	if sev, _ := defs["severity"].(map[string]any); sev != nil {
		items, _ := sev["items"].(map[string]any)
		if items != nil {
			if _, hasRef := items["$ref"]; !hasRef {
				defs["severity_entry"] = items
				sev["items"] = map[string]any{"$ref": "#/$defs/severity_entry"}
			}
		}
	}
}

// liftInlineEnums moves the inline `type` enum on Range/Reference/Severity/
// Credit element schemas into top-level $defs so they get clean names
// (RangeType, ReferenceType, SeverityType, CreditType) instead of being
// derived from the field name (which produces collisions and clutter — e.g.
// the bare `Type` would shadow anything else of that name in callers).
func liftInlineEnums(doc map[string]any) {
	defs, _ := doc["$defs"].(map[string]any)

	lift := func(parent map[string]any, defName string) {
		props, _ := parent["properties"].(map[string]any)
		if props == nil {
			return
		}
		field, _ := props["type"].(map[string]any)
		if field == nil {
			return
		}
		if _, hasRef := field["$ref"]; hasRef {
			return
		}
		defs[defName] = field
		props["type"] = map[string]any{"$ref": "#/$defs/" + defName}
	}

	if v, _ := defs["range"].(map[string]any); v != nil {
		lift(v, "range_type")
	}
	if v, _ := defs["reference"].(map[string]any); v != nil {
		lift(v, "reference_type")
	}
	if v, _ := defs["severity_entry"].(map[string]any); v != nil {
		lift(v, "severity_type")
	}
	if v, _ := defs["credit"].(map[string]any); v != nil {
		lift(v, "credit_type")
	}
}

// markAllRequired walks every object schema and marks all of its properties
// as required. Combined with --only-models (which skips validation), this
// gives us non-pointer Go fields for everything optional in OSV. The library
// emits `*T` for any property that's not in the `required` array, regardless
// of whether the field actually carries useful absent/zero distinction.
func markAllRequired(node any) {
	switch v := node.(type) {
	case map[string]any:
		if props, ok := v["properties"].(map[string]any); ok {
			names := make([]string, 0, len(props))
			for k := range props {
				names = append(names, k)
			}
			required := make([]any, 0, len(names))
			for _, n := range names {
				required = append(required, n)
			}
			v["required"] = required
		}
		for _, child := range v {
			markAllRequired(child)
		}
	case []any:
		for _, child := range v {
			markAllRequired(child)
		}
	}
}

// denullTypeUnions rewrites `"type": ["array", "null"]` (etc.) to just
// `"type": "array"`. OSV uses null unions to indicate "optional or empty
// list", but the library reads them as "nullable" and emits `*T`. We don't
// distinguish null from missing in our use, so the union just causes pointer
// noise.
func denullTypeUnions(node any) {
	switch v := node.(type) {
	case map[string]any:
		if raw, ok := v["type"].([]any); ok {
			cleaned := raw[:0]
			for _, t := range raw {
				if s, _ := t.(string); s != "null" {
					cleaned = append(cleaned, t)
				}
			}
			if len(cleaned) == 1 {
				v["type"] = cleaned[0]
			} else {
				v["type"] = cleaned
			}
		}
		for _, child := range v {
			denullTypeUnions(child)
		}
	case []any:
		for _, child := range v {
			denullTypeUnions(child)
		}
	}
}

func strip(node any) {
	switch v := node.(type) {
	case map[string]any:
		delete(v, "oneOf")
		delete(v, "allOf")
		for _, child := range v {
			strip(child)
		}
	case []any:
		for _, child := range v {
			strip(child)
		}
	}
}

// flattenOneOfProperties walks the schema and, for any object whose `oneOf`
// branches are all object schemas with `properties`, merges those properties
// into a single `properties` block on the parent (with all of them optional
// since the constraint information is being discarded).
//
// In practice the only place this matters in OSV is the events items schema,
// where each oneOf branch has a single required property (introduced /
// fixed / last_affected / limit). After flattening, Event is a proper struct.
func flattenOneOfProperties(node any) {
	switch v := node.(type) {
	case map[string]any:
		mergeOneOfIntoProperties(v)
		for _, child := range v {
			flattenOneOfProperties(child)
		}
	case []any:
		for _, child := range v {
			flattenOneOfProperties(child)
		}
	}
}

func mergeOneOfIntoProperties(obj map[string]any) {
	oneOfList, ok := obj["oneOf"].([]any)
	if !ok {
		return
	}
	merged, ok := collectBranchProperties(oneOfList)
	if !ok || len(merged) == 0 {
		return
	}
	existing, _ := obj["properties"].(map[string]any)
	if existing == nil {
		existing = map[string]any{}
	}
	for k, p := range merged {
		if _, has := existing[k]; !has {
			existing[k] = p
		}
	}
	obj["properties"] = existing
}

// collectBranchProperties returns the union of `properties` across the oneOf
// branches, plus a flag that's false if any branch isn't a property-bearing
// object (in which case the merge is unsafe and we leave the schema alone).
func collectBranchProperties(branches []any) (map[string]any, bool) {
	merged := map[string]any{}
	for _, branch := range branches {
		b, ok := branch.(map[string]any)
		if !ok {
			return nil, false
		}
		props, ok := b["properties"].(map[string]any)
		if !ok {
			return nil, false
		}
		for k, p := range props {
			merged[k] = p
		}
	}
	return merged, true
}

// ============================================================================
// Generator invocation
// ============================================================================

// invokeGenerator runs go-jsonschema against the stripped schema written to a
// tempfile and returns the generated Go source on stdout.
func invokeGenerator(stripped []byte) ([]byte, error) {
	tmp, err := os.CreateTemp("", "osv-schema-stripped-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(stripped); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	// generatorMod is a compile-time constant pointing to a versioned Go
	// module; tmp.Name() is a path we just created in os.CreateTemp. Neither
	// is attacker-influenced at runtime, so the G204 warning is a false alarm.
	// `--only-models` skips the generator's validation code. We need to skip
	// it because markAllRequired() marks every field required, which would
	// otherwise cause runtime UnmarshalJSON to reject real OSV records that
	// omit any field. The trade-off: we lose enum-value validation and need
	// a custom Timestamp.UnmarshalJSON (in aliases.go).
	cmd := exec.Command("go", "run", generatorMod, //nolint:gosec // G204: args are compile-time constants and a tempfile we just created
		"-p", "osvmodel",
		"--only-models",
		"--minimal-names",
		"-t", // use schema title for root struct name
		"--capitalization", "ID",
		"--capitalization", "URL",
		"--capitalization", "CVSS",
		"--tags", "json",
		"-o", "-",
		tmp.Name(),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// addHeader prepends our standard "DO NOT EDIT" preamble so the file is
// recognizable as generated and exempted from lint rules that ignore
// generated code (golangci-lint's `generated: lax` mode).
func addHeader(body []byte, tag string) []byte {
	header := fmt.Sprintf(`// Code generated by ./generate/main.go from osv-schema %s. DO NOT EDIT.
// Regenerate via: make generate:osv-model
// Source: github.com/ossf/osv-schema@%s (validation/schema.json)
// Generator: %s
//
// Package osvmodel is grype's representation of an OSV record. The Go types
// here come from go-jsonschema, fed a constraint-stripped copy of the OSV v1
// schema. Strategy authors looking for a not-yet-present field should
// regenerate (make generate:osv-model) after bumping the pinned schema-v1.json.

`, tag, tag, generatorMod)
	// Drop the library's own header (first non-blank comment line + a blank line).
	lines := bytes.SplitN(body, []byte("\n"), 3)
	if len(lines) >= 3 && bytes.HasPrefix(lines[0], []byte("// Code generated")) {
		body = bytes.Join(lines[2:], []byte("\n"))
	}
	return append([]byte(header), body...)
}
