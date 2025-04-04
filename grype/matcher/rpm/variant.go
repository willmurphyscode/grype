package rpm

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// matchRHELVariant uses advisories specific to a rhel variant (like EUS)
// but disclosures from both the variant and upstream RHEL.
// This allows the database to record the fact that RHEL EUS vulneabilities are patched
// / at different package versions than upstream RHEL, and by different RHSAs
func (m *Matcher) matchRHELVariant(store vulnerability.Provider, p pkg.Package, dislosureDistro *distro.Distro) ([]match.Match, []match.IgnoredMatch, error) {
	// TODO: upstreams!!!
	// Find all vulnerabilities affecting any version of this package in the disclosure distro
	disclosures, err := store.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*dislosureDistro),
		internal.OnlyQualifiedPackages(p),
	)
	if err != nil {
		return nil, nil, err
	}

	// Find all vulnerabilities affecting any version of this package in the advisory distro (p.distro)
	advisories, err := store.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
		internal.OnlyQualifiedPackages(p),
	)
	if err != nil {
		return nil, nil, err
	}

	// Map disclosure vulnerabilities by CVE ID.
	disclosureVulnsByCVE := make(map[string]vulnerability.Vulnerability)
	for _, vuln := range disclosures {
		disclosureVulnsByCVE[vuln.ID] = vuln
	}

	// Map advisory vulnerabilities by related CVE ID.
	advisoryVulnsByCVE := make(map[string]vulnerability.Vulnerability)
	for _, vuln := range advisories {
		advisoryVulnsByCVE[vuln.ID] = vuln
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, nil, err
	}

	var results []match.Match
	for id, vuln := range disclosureVulnsByCVE {
		advisory, hasAdvisory := advisoryVulnsByCVE[id]
		if hasAdvisory {
			if advisory.Constraint != nil {
				vulnerable, err := advisory.Constraint.Satisfied(verObj)
				if err != nil {
					return nil, nil, err
				}
				if !vulnerable {
					continue
				}
			}
		}
		// we are vulnerable unless there's an advisory with a constraint that's satisfied
		results = append(results, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details:       []match.Detail{
				// TODO: some details please
			},
		})

	}
	return results, nil, nil
}
