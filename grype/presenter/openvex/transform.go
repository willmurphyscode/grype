package openvex

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	govex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/grype/grype/presenter/models"
)

// buildOwnershipMap constructs a lookup from package PURL to its owned package PURLs
// and from owned package ID to its owner's PURL, using the SBOM's relationships.
func buildOwnershipMap(s *sbom.SBOM) (ownerOf map[string][]string, ownerPURLByChild map[string]string) {
	ownerOf = make(map[string][]string)
	ownerPURLByChild = make(map[string]string)

	if s == nil {
		return
	}

	// Build a package ID → PURL lookup from the SBOM
	purlByID := make(map[string]string)
	for p := range s.Artifacts.Packages.Enumerate() {
		if p.PURL != "" {
			purlByID[string(p.ID())] = p.PURL
		}
	}

	for _, rel := range s.Relationships {
		if rel.Type != artifact.OwnershipByFileOverlapRelationship {
			continue
		}

		parentID := string(rel.From.ID())
		childID := string(rel.To.ID())

		parentPURL := purlByID[parentID]
		childPURL := purlByID[childID]
		if parentPURL == "" || childPURL == "" {
			continue
		}

		ownerOf[parentPURL] = append(ownerOf[parentPURL], childPURL)
		ownerPURLByChild[childPURL] = parentPURL
	}

	return
}

// statementKey is used to deduplicate VEX statements by (vulnerability, product).
type statementKey struct {
	vulnID      string
	productPURL string
}

// matchToStatement converts an active grype match into a VEX "affected" statement.
func matchToStatement(m models.Match, ownerOf map[string][]string) govex.Statement {
	vuln := buildVulnerability(m)
	product := buildProduct(m.Artifact.PURL, ownerOf)

	stmt := govex.Statement{
		Vulnerability: vuln,
		Products:      []govex.Product{product},
		Status:        govex.StatusAffected,
	}

	if fixStr := formatFixInfo(m); fixStr != "" {
		stmt.ActionStatement = fixStr
	}

	return stmt
}

// ignoredMatchToStatement converts an ignored grype match into a VEX statement,
// returning the statement and true if the ignored match should produce VEX output.
// Returns zero-value and false for ignored matches that should not emit VEX
// (e.g., user-configured ignore rules that are not scanner determinations).
func ignoredMatchToStatement(im models.IgnoredMatch, ownerOf map[string][]string) (govex.Statement, bool) {
	if len(im.AppliedIgnoreRules) == 0 {
		return govex.Statement{}, false
	}

	rule := im.AppliedIgnoreRules[0]

	// Determine VEX status and justification based on the ignore reason
	status, justification, shouldEmit := classifyIgnoreRule(rule)
	if !shouldEmit {
		return govex.Statement{}, false
	}

	vuln := buildVulnerability(im.Match)
	product := buildProduct(im.Artifact.PURL, ownerOf)

	stmt := govex.Statement{
		Vulnerability: vuln,
		Products:      []govex.Product{product},
		Status:        status,
	}

	if justification != "" {
		stmt.Justification = govex.Justification(justification)
	}

	if status == govex.StatusFixed {
		if fixStr := formatFixInfo(im.Match); fixStr != "" {
			stmt.StatusNotes = fixStr
		}
	}

	return stmt, true
}

// classifyIgnoreRule determines the VEX status and justification for an ignored match
// based on the applied ignore rule. Returns shouldEmit=false for rules that should
// not produce VEX output (user-configured ignore rules, etc.).
func classifyIgnoreRule(rule models.IgnoreRule) (status govex.Status, justification string, shouldEmit bool) {
	// VEX-based ignore: pass through the original status and justification
	if rule.VexStatus != "" {
		return govex.Status(rule.VexStatus), rule.VexJustification, true
	}

	switch rule.Reason {
	case "DistroPackageFixed":
		// If the fix state indicates "not-fixed" with version 0, this is an
		// unaffected determination, not a fix.
		if rule.FixState == "not-affected" || rule.FixState == "" {
			return govex.StatusNotAffected, string(govex.InlineMitigationsAlreadyExist), true
		}
		return govex.StatusFixed, "", true

	case "CPE not vulnerable":
		return govex.StatusNotAffected, string(govex.VulnerableCodeNotPresent), true

	default:
		// User-configured ignore rules, etc. — not a scanner determination
		return "", "", false
	}
}

// buildVulnerability creates an OpenVEX Vulnerability from a grype match.
func buildVulnerability(m models.Match) govex.Vulnerability {
	vuln := govex.Vulnerability{
		Name: govex.VulnerabilityID(m.Vulnerability.ID),
	}

	if m.Vulnerability.Description != "" {
		vuln.Description = m.Vulnerability.Description
	}

	if m.Vulnerability.DataSource != "" {
		vuln.ID = m.Vulnerability.DataSource
	}

	// Populate aliases from related vulnerabilities
	seen := make(map[string]bool)
	seen[m.Vulnerability.ID] = true
	for _, rv := range m.RelatedVulnerabilities {
		if !seen[rv.ID] {
			vuln.Aliases = append(vuln.Aliases, govex.VulnerabilityID(rv.ID))
			seen[rv.ID] = true
		}
	}

	return vuln
}

// buildProduct creates an OpenVEX Product for a package PURL, including any
// owned language packages as subcomponents.
func buildProduct(purl string, ownerOf map[string][]string) govex.Product {
	product := govex.Product{
		Component: govex.Component{
			ID: purl,
			Identifiers: map[govex.IdentifierType]string{
				govex.PURL: purl,
			},
		},
	}

	// Add owned packages as subcomponents
	if owned, ok := ownerOf[purl]; ok {
		for _, ownedPURL := range owned {
			product.Subcomponents = append(product.Subcomponents, govex.Subcomponent{
				Component: govex.Component{
					ID: ownedPURL,
					Identifiers: map[govex.IdentifierType]string{
						govex.PURL: ownedPURL,
					},
				},
			})
		}
	}

	return product
}

// formatFixInfo returns a human-readable string describing available fix versions.
func formatFixInfo(m models.Match) string {
	if len(m.Vulnerability.Fix.Versions) == 0 {
		return ""
	}
	return fmt.Sprintf("Update to %s", strings.Join(m.Vulnerability.Fix.Versions, " or "))
}

// deduplicateStatements merges statements with the same (vulnerability, product) key.
// When duplicates exist, the first one wins and additional aliases are merged.
func deduplicateStatements(stmts []govex.Statement) []govex.Statement {
	type entry struct {
		idx  int
		stmt govex.Statement
	}

	seen := make(map[string]*entry)
	var order []string

	for _, s := range stmts {
		productID := ""
		if len(s.Products) > 0 {
			productID = s.Products[0].ID
		}
		key := fmt.Sprintf("%s|%s|%s", s.Vulnerability.Name, productID, s.Status)

		if existing, ok := seen[key]; ok {
			// Merge aliases
			aliasSet := make(map[govex.VulnerabilityID]bool)
			for _, a := range existing.stmt.Vulnerability.Aliases {
				aliasSet[a] = true
			}
			for _, a := range s.Vulnerability.Aliases {
				if !aliasSet[a] {
					existing.stmt.Vulnerability.Aliases = append(existing.stmt.Vulnerability.Aliases, a)
				}
			}
			// Merge subcomponents
			if len(s.Products) > 0 && len(existing.stmt.Products) > 0 {
				scSet := make(map[string]bool)
				for _, sc := range existing.stmt.Products[0].Subcomponents {
					scSet[sc.ID] = true
				}
				for _, sc := range s.Products[0].Subcomponents {
					if !scSet[sc.ID] {
						existing.stmt.Products[0].Subcomponents = append(
							existing.stmt.Products[0].Subcomponents, sc,
						)
					}
				}
			}
		} else {
			seen[key] = &entry{idx: len(order), stmt: s}
			order = append(order, key)
		}
	}

	result := make([]govex.Statement, 0, len(order))
	for _, key := range order {
		result = append(result, seen[key].stmt)
	}

	return result
}

// sortStatements sorts statements for deterministic output: by vulnerability name,
// then by product PURL, then by status.
func sortStatements(stmts []govex.Statement) {
	sort.Slice(stmts, func(i, j int) bool {
		vi, vj := string(stmts[i].Vulnerability.Name), string(stmts[j].Vulnerability.Name)
		if vi != vj {
			return vi < vj
		}
		pi, pj := "", ""
		if len(stmts[i].Products) > 0 {
			pi = stmts[i].Products[0].ID
		}
		if len(stmts[j].Products) > 0 {
			pj = stmts[j].Products[0].ID
		}
		if pi != pj {
			return pi < pj
		}
		return string(stmts[i].Status) < string(stmts[j].Status)
	})
}

// generateDocumentID creates a deterministic document ID from the content hash.
func generateDocumentID(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("https://openvex.dev/docs/generated/%x", hash[:16])
}
