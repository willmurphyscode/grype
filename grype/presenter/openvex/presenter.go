package openvex

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	govex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/grype/grype/presenter/models"
)

type Presenter struct {
	id      string
	version string
	config  models.PresenterConfig
}

func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:      pb.ID.Name,
		version: pb.ID.Version,
		config:  pb,
	}
}

func (p *Presenter) Present(output io.Writer) error {
	// Build ownership map from SBOM relationships
	ownerOf, _ := buildOwnershipMap(p.config.SBOM)

	// Collect all statements
	var statements []govex.Statement

	// Transform active matches → affected statements
	for _, m := range p.config.Document.Matches {
		stmt := matchToStatement(m, ownerOf)
		statements = append(statements, stmt)
	}

	// Transform relevant ignored matches → not_affected/fixed statements
	for _, im := range p.config.Document.IgnoredMatches {
		stmt, shouldEmit := ignoredMatchToStatement(im, ownerOf)
		if shouldEmit {
			statements = append(statements, stmt)
		}
	}

	// Deduplicate and sort for deterministic output
	statements = deduplicateStatements(statements)
	sortStatements(statements)

	// Build the VEX document
	now := time.Now()
	tooling := p.id
	if p.version != "" {
		tooling = p.id + "/" + p.version
	}

	doc := govex.VEX{
		Metadata: govex.Metadata{
			Context:   govex.ContextLocator(),
			Author:    tooling,
			Timestamp: &now,
			Version:   1,
			Tooling:   tooling,
		},
		Statements: statements,
	}

	// Generate a deterministic document ID from content
	buf := &bytes.Buffer{}
	if err := doc.ToJSON(buf); err != nil {
		return err
	}
	doc.ID = generateDocumentID(buf.Bytes())

	// Write final output
	enc := json.NewEncoder(output)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(&doc)
}
