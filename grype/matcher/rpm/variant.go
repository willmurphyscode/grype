package rpm

import (
	"errors"
	"regexp"
	"strconv"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
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
		// internal.OnlyQualifiedPackages(p), // TODO: figure out how to deal with modularity
	)
	if err != nil {
		return nil, nil, err
	}

	// Find all vulnerabilities affecting any version of this package in the advisory distro (p.distro)
	advisories, err := store.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
		// internal.OnlyQualifiedPackages(p),
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

	distroMajorVersion, err := strconv.Atoi(p.Distro.MajorVersion())
	canCompareVersion := err == nil
	distroMinorVersion, err := strconv.Atoi(p.Distro.MinorVersion())
	canCompareVersion = canCompareVersion && err == nil

	var results []match.Match
	for id, vuln := range disclosureVulnsByCVE {
		advisory, hasAdvisory := advisoryVulnsByCVE[id]
		vulnerable := true
		if hasAdvisory {
			if advisory.Constraint != nil {
				sat, err := advisory.Constraint.Satisfied(verObj)
				if err != nil {
					return nil, nil, err
				}
				if !sat {
					vulnerable = false
				}
			}
		}

		// Check whether there was a fix in RHEL main before this version of EUS was released

		for _, fixVersion := range advisory.Fix.Versions {
			if !canCompareVersion {
				continue
			}
			if fixVersion == "" {
				continue
			}
			// regex rhel major and minor versions from fixVersion,
			// which is a string like 0:4.18.0-513.9.1.el8_9
			major, minor, err := extractRhelVersion(fixVersion)
			if err != nil {
				continue // if a rhel minor version can't be extracted, assume the fix is not applicable
			}

			if major == distroMajorVersion && minor <= distroMinorVersion {
				sat, err := vuln.Constraint.Satisfied(verObj)
				if err != nil {
					continue
				}
				if !sat {
					vulnerable = false
				}
			}
		}
		// we are vulnerable unless there's an advisory with a constraint that's satisfied
		if vulnerable {
			results = append(results, match.Match{
				Vulnerability: vuln,
				Package:       p,
				Details: []match.Detail{
					// TODO: some details please
				},
			})
		}

	}
	return results, nil, nil
}

// Pre-compile the regular expression for efficiency.
var rhelVersionRegex = regexp.MustCompile(`el(\d+)_(\d+)`)

// errRhelPatternNotFound is returned when the "el<major>_<minor>" pattern isn't found.
// Define it here or ensure it's defined elsewhere in your package.
var errRhelPatternNotFound = errors.New("RHEL version pattern (elX_Y) not found in string")

// extractRhelVersion attempts to find and parse the RHEL major and minor version
// from an RPM version string.
// Returns (0, 0, errRhelPatternNotFound) if the pattern is not found.
// Returns (0, 0, err) if the captured numbers cannot be parsed as integers.
func extractRhelVersion(rpmVersion string) (major int, minor int, err error) {
	matches := rhelVersionRegex.FindStringSubmatch(rpmVersion)

	if len(matches) != 3 {
		return 0, 0, errRhelPatternNotFound
	}

	majorStr := matches[1]
	minorStr := matches[2]

	major, err = strconv.Atoi(majorStr)
	if err != nil {
		// Optional: wrap error for more context (requires "fmt" import)
		// return 0, 0, fmt.Errorf("failed to parse major version '%s': %w", majorStr, err)
		return 0, 0, err // Simpler return if fmt isn't available/desired
	}

	minor, err = strconv.Atoi(minorStr)
	if err != nil {
		// Optional: wrap error for more context (requires "fmt" import)
		// return 0, 0, fmt.Errorf("failed to parse minor version '%s': %w", minorStr, err)
		return 0, 0, err // Simpler return if fmt isn't available/desired
	}

	return major, minor, nil
}
