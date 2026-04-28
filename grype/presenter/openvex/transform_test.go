package openvex

import (
	"bytes"
	"encoding/json"
	"testing"

	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/models"
)

func TestMatchToStatement_Affected(t *testing.T) {
	m := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-2024-1234",
				DataSource:  "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
				Description: "A test vulnerability",
			},
			Fix: models.Fix{
				Versions: []string{"1.2.3"},
				State:    "fixed",
			},
		},
		RelatedVulnerabilities: []models.VulnerabilityMetadata{
			{ID: "GHSA-xxxx-yyyy-zzzz"},
		},
		Artifact: models.Package{
			Name:    "curl",
			Version: "7.68.0-1",
			PURL:    "pkg:deb/debian/curl@7.68.0-1?distro=debian-13",
		},
	}

	stmt := matchToStatement(m, nil)

	assert.Equal(t, govex.StatusAffected, stmt.Status)
	assert.Equal(t, govex.VulnerabilityID("CVE-2024-1234"), stmt.Vulnerability.Name)
	assert.Contains(t, stmt.Vulnerability.Aliases, govex.VulnerabilityID("GHSA-xxxx-yyyy-zzzz"))
	require.Len(t, stmt.Products, 1)
	assert.Equal(t, "pkg:deb/debian/curl@7.68.0-1?distro=debian-13", stmt.Products[0].ID)
	assert.Equal(t, "Update to 1.2.3", stmt.ActionStatement)
}

func TestMatchToStatement_WithSubcomponents(t *testing.T) {
	ownerOf := map[string][]string{
		"pkg:deb/debian/python3-packaging@25.0-1?distro=debian-13": {
			"pkg:pypi/packaging@25.0",
		},
	}

	m := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID: "CVE-2024-5678",
			},
		},
		Artifact: models.Package{
			Name:    "python3-packaging",
			Version: "25.0-1",
			PURL:    "pkg:deb/debian/python3-packaging@25.0-1?distro=debian-13",
		},
	}

	stmt := matchToStatement(m, ownerOf)

	require.Len(t, stmt.Products, 1)
	require.Len(t, stmt.Products[0].Subcomponents, 1)
	assert.Equal(t, "pkg:pypi/packaging@25.0", stmt.Products[0].Subcomponents[0].ID)
}

func TestIgnoredMatchToStatement_DistroPackageFixed(t *testing.T) {
	im := models.IgnoredMatch{
		Match: models.Match{
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID: "CVE-2024-1234",
				},
			},
			Artifact: models.Package{
				PURL: "pkg:rpm/redhat/nodejs-undici@5.28.0-1.el10?distro=rhel-10",
			},
		},
		AppliedIgnoreRules: []models.IgnoreRule{
			{Reason: "DistroPackageFixed"},
		},
	}

	stmt, shouldEmit := ignoredMatchToStatement(im, nil)

	assert.True(t, shouldEmit)
	assert.Equal(t, govex.StatusNotAffected, stmt.Status)
	assert.Equal(t, govex.InlineMitigationsAlreadyExist, stmt.Justification)
}

func TestIgnoredMatchToStatement_VexBased(t *testing.T) {
	im := models.IgnoredMatch{
		Match: models.Match{
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID: "CVE-2024-1234",
				},
			},
			Artifact: models.Package{
				PURL: "pkg:npm/lodash@4.17.21",
			},
		},
		AppliedIgnoreRules: []models.IgnoreRule{
			{
				VexStatus:        "not_affected",
				VexJustification: "vulnerable_code_not_in_execute_path",
			},
		},
	}

	stmt, shouldEmit := ignoredMatchToStatement(im, nil)

	assert.True(t, shouldEmit)
	assert.Equal(t, govex.StatusNotAffected, stmt.Status)
	assert.Equal(t, govex.VulnerableCodeNotInExecutePath, stmt.Justification)
}

func TestIgnoredMatchToStatement_UserIgnoreRule_NotEmitted(t *testing.T) {
	im := models.IgnoredMatch{
		Match: models.Match{
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID: "CVE-2024-1234",
				},
			},
			Artifact: models.Package{
				PURL: "pkg:deb/debian/curl@7.68.0-1",
			},
		},
		AppliedIgnoreRules: []models.IgnoreRule{
			{Reason: "user-configured"},
		},
	}

	_, shouldEmit := ignoredMatchToStatement(im, nil)
	assert.False(t, shouldEmit)
}

func TestIgnoredMatchToStatement_NoRules_NotEmitted(t *testing.T) {
	im := models.IgnoredMatch{
		Match: models.Match{
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID: "CVE-2024-1234",
				},
			},
			Artifact: models.Package{
				PURL: "pkg:deb/debian/curl@7.68.0-1",
			},
		},
		AppliedIgnoreRules: nil,
	}

	_, shouldEmit := ignoredMatchToStatement(im, nil)
	assert.False(t, shouldEmit)
}

func TestBuildVulnerability_WithAliases(t *testing.T) {
	m := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-2024-24758",
				DataSource:  "https://access.redhat.com/security/cve/CVE-2024-24758",
				Description: "A test vuln",
			},
		},
		RelatedVulnerabilities: []models.VulnerabilityMetadata{
			{ID: "GHSA-3787-6prv-h9w3"},
			{ID: "CVE-2024-24758"}, // duplicate of primary — should be deduplicated
		},
	}

	vuln := buildVulnerability(m)

	assert.Equal(t, govex.VulnerabilityID("CVE-2024-24758"), vuln.Name)
	assert.Equal(t, "A test vuln", vuln.Description)
	require.Len(t, vuln.Aliases, 1)
	assert.Equal(t, govex.VulnerabilityID("GHSA-3787-6prv-h9w3"), vuln.Aliases[0])
}

func TestBuildProduct_NoOwnership(t *testing.T) {
	product := buildProduct("pkg:npm/picomatch@4.0.3", nil)

	assert.Equal(t, "pkg:npm/picomatch@4.0.3", product.ID)
	assert.Equal(t, "pkg:npm/picomatch@4.0.3", product.Identifiers[govex.PURL])
	assert.Empty(t, product.Subcomponents)
}

func TestBuildProduct_WithOwnership(t *testing.T) {
	ownerOf := map[string][]string{
		"pkg:deb/debian/mercurial-common@7.0.1-2?distro=debian-13": {
			"pkg:pypi/mercurial@7.0.1",
		},
	}

	product := buildProduct("pkg:deb/debian/mercurial-common@7.0.1-2?distro=debian-13", ownerOf)

	require.Len(t, product.Subcomponents, 1)
	assert.Equal(t, "pkg:pypi/mercurial@7.0.1", product.Subcomponents[0].ID)
	assert.Equal(t, "pkg:pypi/mercurial@7.0.1", product.Subcomponents[0].Identifiers[govex.PURL])
}

func TestDeduplicateStatements(t *testing.T) {
	stmts := []govex.Statement{
		{
			Vulnerability: govex.Vulnerability{Name: "CVE-2024-1234"},
			Products:      []govex.Product{{Component: govex.Component{ID: "pkg:deb/debian/curl@1.0"}}},
			Status:        govex.StatusAffected,
		},
		{
			Vulnerability: govex.Vulnerability{
				Name:    "CVE-2024-1234",
				Aliases: []govex.VulnerabilityID{"GHSA-xxxx"},
			},
			Products: []govex.Product{{Component: govex.Component{ID: "pkg:deb/debian/curl@1.0"}}},
			Status:   govex.StatusAffected,
		},
	}

	result := deduplicateStatements(stmts)

	require.Len(t, result, 1)
	assert.Contains(t, result[0].Vulnerability.Aliases, govex.VulnerabilityID("GHSA-xxxx"))
}

func TestSortStatements(t *testing.T) {
	stmts := []govex.Statement{
		{
			Vulnerability: govex.Vulnerability{Name: "CVE-2024-9999"},
			Products:      []govex.Product{{Component: govex.Component{ID: "pkg:b"}}},
			Status:        govex.StatusAffected,
		},
		{
			Vulnerability: govex.Vulnerability{Name: "CVE-2024-1111"},
			Products:      []govex.Product{{Component: govex.Component{ID: "pkg:a"}}},
			Status:        govex.StatusAffected,
		},
	}

	sortStatements(stmts)

	assert.Equal(t, govex.VulnerabilityID("CVE-2024-1111"), stmts[0].Vulnerability.Name)
	assert.Equal(t, govex.VulnerabilityID("CVE-2024-9999"), stmts[1].Vulnerability.Name)
}

func TestPresenter_ProducesValidJSON(t *testing.T) {
	doc := models.Document{
		Matches: []models.Match{
			{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: models.VulnerabilityMetadata{
						ID: "CVE-2024-1234",
					},
				},
				Artifact: models.Package{
					Name:    "curl",
					Version: "7.68.0",
					PURL:    "pkg:deb/debian/curl@7.68.0?distro=debian-13",
				},
			},
		},
		IgnoredMatches: []models.IgnoredMatch{
			{
				Match: models.Match{
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							ID: "CVE-2024-5678",
						},
					},
					Artifact: models.Package{
						PURL: "pkg:rpm/redhat/openssl@3.1.1?distro=rhel-8",
					},
				},
				AppliedIgnoreRules: []models.IgnoreRule{
					{Reason: "DistroPackageFixed"},
				},
			},
		},
	}

	pb := models.PresenterConfig{
		Document: doc,
	}

	p := NewPresenter(pb)

	var buf bytes.Buffer
	err := p.Present(&buf)
	require.NoError(t, err)

	// Verify it's valid JSON
	var result map[string]any
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	// Verify OpenVEX structure
	assert.Equal(t, govex.ContextLocator(), result["@context"])
	assert.NotEmpty(t, result["@id"])

	stmts, ok := result["statements"].([]any)
	require.True(t, ok)
	assert.Len(t, stmts, 2) // one affected, one not_affected

	// Parse as VEX document to validate
	vexDoc, err := govex.Parse(buf.Bytes())
	require.NoError(t, err)
	assert.Len(t, vexDoc.Statements, 2)

	// Check the affected statement
	var affected, notAffected *govex.Statement
	for i := range vexDoc.Statements {
		switch vexDoc.Statements[i].Status {
		case govex.StatusAffected:
			affected = &vexDoc.Statements[i]
		case govex.StatusNotAffected:
			notAffected = &vexDoc.Statements[i]
		}
	}

	require.NotNil(t, affected)
	assert.Equal(t, govex.VulnerabilityID("CVE-2024-1234"), affected.Vulnerability.Name)
	require.Len(t, affected.Products, 1)
	assert.Equal(t, "pkg:deb/debian/curl@7.68.0?distro=debian-13", affected.Products[0].ID)

	require.NotNil(t, notAffected)
	assert.Equal(t, govex.VulnerabilityID("CVE-2024-5678"), notAffected.Vulnerability.Name)
	assert.Equal(t, govex.InlineMitigationsAlreadyExist, notAffected.Justification)
}
