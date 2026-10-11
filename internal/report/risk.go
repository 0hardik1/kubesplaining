// Package report: risk-index math used by the HTML dashboard's headline score.
package report

import "math"

// computeRiskIndex returns a 0–100 severity-weighted index and a coarse level label.
// Weights are tuned so a handful of critical or many high findings push toward the top of the scale.
func computeRiskIndex(s Summary) (int, string) {
	raw := 15.0*float64(s.Critical) + 4.0*float64(s.High) + 1.5*float64(s.Medium) + 0.3*float64(s.Low)
	if raw > 100 {
		raw = 100
	}
	idx := int(math.Round(raw))
	switch {
	case idx >= 80:
		return idx, "CRITICAL"
	case idx >= 60:
		return idx, "HIGH"
	case idx >= 30:
		return idx, "MODERATE"
	default:
		return idx, "LOW"
	}
}
