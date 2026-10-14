package goredact

import "github.com/baum-ai/goredact/internal/span"

// MaskStrategy selects how each confirmed secret span is replaced in the
// output. The zero value is MaskFixedMarker, so the zero Config keeps the
// documented fixed-marker behavior.
type MaskStrategy int

const (
	// MaskFixedMarker replaces each confirmed span with exactly one copy
	// of Config.Marker, regardless of the span's length. This is the
	// default and discloses nothing about the redacted value, not even
	// its length.
	MaskFixedMarker MaskStrategy = iota

	// MaskLengthPreserving replaces each redacted byte with '*'. Output
	// length equals input length, so fixed-width records and offsets in
	// surrounding text survive redaction. The length of each secret is
	// disclosed; its contents are not.
	MaskLengthPreserving

	// MaskFormatPreserving replaces each redacted byte with a stand-in
	// of the same coarse character class: uppercase letters become 'X',
	// lowercase letters 'x', digits '9'; the separator bytes
	// - _ . : / + = @ pass through verbatim; every other byte becomes
	// '*'. Output length equals input length and token shapes (JWT dots,
	// UUID dashes, base64 padding) survive, which keeps
	// structured/fixed-format consumers parsing. The preserved shape and
	// separators are information about the original secret — choose this
	// only when downstream consumers need format fidelity.
	MaskFormatPreserving
)

// String returns the strategy name.
func (m MaskStrategy) String() string {
	switch m {
	case MaskFixedMarker:
		return "fixed-marker"
	case MaskLengthPreserving:
		return "length-preserving"
	case MaskFormatPreserving:
		return "format-preserving"
	default:
		return "unknown"
	}
}

func (m MaskStrategy) valid() bool {
	return m >= MaskFixedMarker && m <= MaskFormatPreserving
}

// internal converts to the span package's strategy enum. The two
// enumerations are numerically aligned; this conversion is the single
// place that alignment is relied on.
func (m MaskStrategy) internal() span.MaskStrategy {
	return span.MaskStrategy(m)
}
