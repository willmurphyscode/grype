package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
)

// TestMatcherGolang_GoSymbols_GHSA is the third-party analogue of
// TestMatcherGolang_GoSymbols: it proves symbol matching can suppress a false
// positive on a GHSA advisory for a third-party Go module, not just the
// govulndb-sourced stdlib/golang.org/x records.
//
// Grype sources third-party Go advisories from GHSA (the github provider), which
// today carries no per-symbol reachability, so a module merely being present at a
// vulnerable version is enough to match. GHSA-6vm3-jj99-7229 (CVE-2020-36567)
// flags github.com/gin-gonic/gin < 1.6.0, but the vulnerability lives only in the
// Logger middleware — govulndb's GO-2020-0001 (linked from the GHSA via its
// pkg.go.dev/vuln reference) scopes it to Default/Logger/LoggerWith* imports.
//
// EXPECTED TO FAIL on this branch: the gin-symbols fixture ships both the GHSA and
// the govulndb record, but the db builder does not yet graft the govulndb symbols
// onto the GHSA-derived package blob (a colleague's work in progress). Until that
// lands there is no go-imports qualifier on the GHSA, so the "safe" gin binary
// still matches. Once the augmentation lands, the gosymbols qualifier suppresses
// it and this test passes unchanged.
func TestMatcherGolang_GoSymbols_GHSA(t *testing.T) {
	const ginLoggerInjection = "GHSA-6vm3-jj99-7229" // CVE-2020-36567; gin < 1.6.0, scoped to Logger symbols

	dbtest.DBs(t, "gin-symbols").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		t.Run("gin binary using the Logger symbols matches (true positive kept)", func(t *testing.T) {
			// built against gin v1.5.0 (< 1.6.0) and uses gin.Default()/Logger, so the
			// vulnerable symbols are compiled in. This must match with or without the
			// symbol augmentation.
			p := dbtest.GoBinaryFixture(t, "gobin-gin-vuln").
				Package("github.com/gin-gonic/gin").
				Build()

			db.Match(t, matcher, p).
				SelectMatch(ginLoggerInjection).
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		t.Run("gin binary not using the Logger symbols is suppressed", func(t *testing.T) {
			// built against the same vulnerable gin v1.5.0 but only uses gin.New() + a
			// route handler, so none of the Logger symbols are present. Once the GHSA
			// carries the govulndb symbols, this binary must not match.
			p := dbtest.GoBinaryFixture(t, "gobin-gin-safe").
				Package("github.com/gin-gonic/gin").
				Build()

			db.Match(t, matcher, p).
				DoesNotHaveAnyVulnerabilities(ginLoggerInjection)
		})
	})
}
