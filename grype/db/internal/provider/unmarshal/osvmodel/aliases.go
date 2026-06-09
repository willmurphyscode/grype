package osvmodel

import (
	"encoding/json"
	"strings"
	"time"
)

// This file fills two gaps in go-jsonschema's output:
//
//  1. Constant naming. The library generates SCREAMING-suffix consts like
//     RangeTypeSEMVER and SeverityTypeCVSSV2. The aliases below give them
//     shorter, idiomatic names (RangeSemVer, SeverityCVSSV2) for callers.
//
//  2. Timestamp parsing. The library defines Timestamp as `type Timestamp
//     time.Time` (a defined type, not an alias) and does not emit a custom
//     UnmarshalJSON for it, so encoding/json fails with "cannot unmarshal
//     string into ... Timestamp". The method below closes that gap.

// Range type constants matching the names strategies use.
const (
	RangeEcosystem = RangeTypeECOSYSTEM
	RangeGit       = RangeTypeGIT
	RangeSemVer    = RangeTypeSEMVER
)

// Reference type constants. Only ADVISORY is read directly by strategies
// today; the rest of the enum lives on ReferenceType in the generated file.
const (
	ReferenceAdvisory = ReferenceTypeADVISORY
)

// Severity type constants used by helpers.
const (
	SeverityCVSSV2 = SeverityTypeCVSSV2
	SeverityCVSSV3 = SeverityTypeCVSSV3
	SeverityCVSSV4 = SeverityTypeCVSSV4
)

// UnmarshalJSON parses an RFC 3339 timestamp string into a Timestamp. Required
// because go-jsonschema treats Timestamp as opaque and doesn't emit one.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return err
	}
	*t = Timestamp(parsed)
	return nil
}

// AsTime returns the timestamp as a *time.Time. Strategy code pulls
// ModifiedDate and PublishedDate as *time.Time on db.VulnerabilityHandle,
// so converting at the call site needs an intermediate variable; this helper
// avoids that boilerplate.
func (t Timestamp) AsTime() *time.Time {
	out := time.Time(t)
	return &out
}
