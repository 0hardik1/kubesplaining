// Package report — risk-index gauge math used by the HTML dashboard's headline
// score and arc rendering.
package report

import (
	"fmt"
	"math"
)

// computeRiskIndex returns a 0–100 severity-weighted index, a coarse level label, and the gauge stroke color.
// Weights are tuned so a handful of critical or many high findings push toward the top of the scale.
func computeRiskIndex(s Summary) (int, string, string) {
	raw := 15.0*float64(s.Critical) + 4.0*float64(s.High) + 1.5*float64(s.Medium) + 0.3*float64(s.Low)
	if raw > 100 {
		raw = 100
	}
	idx := int(math.Round(raw))
	switch {
	case idx >= 80:
		return idx, "CRITICAL", "#ff5568"
	case idx >= 60:
		return idx, "HIGH", "#ff5568"
	case idx >= 30:
		return idx, "MODERATE", "#ff9a3c"
	default:
		return idx, "LOW", "#52e3a4"
	}
}

// gaugeDash returns the stroke-dasharray value used by the radial gauge SVG. Circumference = 2π·56.
func gaugeDash(idx int) string {
	const circumference = 2.0 * math.Pi * 56.0
	arc := circumference * float64(idx) / 100.0
	gap := circumference - arc
	return fmt.Sprintf("%.2f %.2f", arc, gap)
}
