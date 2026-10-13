package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSearchRuleStore_SeededDefaults(t *testing.T) {
	// an empty writable store seeds InitialData, including KnownSearchRules
	s := setupTestStore(t)

	got, err := s.GetSearchRules()
	require.NoError(t, err)

	require.Equal(t, KnownSearchRules(), got)
}

func TestSearchRuleStore_MissingTableIsNilNotError(t *testing.T) {
	// a DB built before the table existed reads as nil, not an error
	s := setupTestStore(t)
	require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))

	got, err := s.GetSearchRules()
	require.NoError(t, err)
	require.Nil(t, got)
}

// A 6.1.9 DB has no search_rules table. Hydrating it on import (a writable, non-empty open, which
// auto-migrates) creates an empty one; the provider must still apply the built-in rules.
func TestNewVulnerabilityProvider_HydratedPreTableDBUsesKnownRules(t *testing.T) {
	dir := t.TempDir()
	s := setupTestStore(t, dir)
	require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))
	require.NoError(t, s.Close())

	require.NoError(t, Hydrater()(dir))

	vp, ok := NewVulnerabilityProvider(setupReadOnlyTestStore(t, dir)).(*vulnerabilityProvider)
	require.True(t, ok)

	debian := *distro.New(distro.Debian, "12", "")
	search := nameSearch(searchOf("curl", "7.88.1-10+deb12u5.echo1", debian, syftPkg.DebPkg))

	// the built-in echo rule adds the echo search beside debian's own
	assert.ElementsMatch(t,
		[]searched{own("debian@12+", "curl"), ruled("echo@12+", "curl", 0)},
		searchesOf(rewrites(*vp, pkg.Package{}, search)),
	)
}
