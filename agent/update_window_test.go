package agent

import (
	"testing"
	"time"
)

func TestParseUpdateWindowValid(t *testing.T) {
	parsed, err := parseUpdateWindow("days=Mon,Tue,Fri|time=06:45-21:14")
	if err != nil {
		t.Fatalf("parseUpdateWindow returned error: %v", err)
	}
	if !parsed.days[time.Monday] || !parsed.days[time.Tuesday] || !parsed.days[time.Friday] {
		t.Fatalf("parseUpdateWindow did not capture expected days")
	}
	if parsed.startMins != (6*60 + 45) {
		t.Fatalf("startMins = %d, want %d", parsed.startMins, 6*60+45)
	}
	if parsed.endMins != (21*60 + 14) {
		t.Fatalf("endMins = %d, want %d", parsed.endMins, 21*60+14)
	}
}

func TestParseUpdateWindowInvalid(t *testing.T) {
	tests := []string{
		"",
		"days=Monday|time=06:45-21:14",
		"days=Mon,Tue|time=6:45-21:14",
		"days=Mon,Tue|time=21:14-06:45",
		"Days:Mon,Tue|Time:06:45-21:14",
		"days=Mon,Tue|time=06:60-21:14",
		"days=Mon,Tue|time=06:45-24:00",
		"days=Mon, Tue|time=06:45-21:14",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := parseUpdateWindow(input)
			if err == nil {
				t.Fatalf("parseUpdateWindow(%q) expected error", input)
			}
		})
	}
}

func TestIsWithinUpdateWindowEmptyAllows(t *testing.T) {
	now := time.Date(2026, time.February, 16, 9, 0, 0, 0, time.Local)
	allowed, err := IsWithinUpdateWindow(now, "")
	if err != nil {
		t.Fatalf("IsWithinUpdateWindow returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("IsWithinUpdateWindow should allow empty window")
	}
}

func TestIsWithinUpdateWindowDayAndTime(t *testing.T) {
	window := "days=Mon,Tue|time=06:45-21:14"

	monInside := time.Date(2026, time.February, 16, 7, 0, 0, 0, time.Local)
	allowed, err := IsWithinUpdateWindow(monInside, window)
	if err != nil {
		t.Fatalf("IsWithinUpdateWindow returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected window to allow Monday inside range")
	}

	wedInsideTime := time.Date(2026, time.February, 18, 7, 0, 0, 0, time.Local)
	allowed, err = IsWithinUpdateWindow(wedInsideTime, window)
	if err != nil {
		t.Fatalf("IsWithinUpdateWindow returned error: %v", err)
	}
	if allowed {
		t.Fatalf("expected window to reject Wednesday")
	}
}

func TestIsWithinUpdateWindowBoundaries(t *testing.T) {
	window := "days=Mon|time=06:45-21:14"

	start := time.Date(2026, time.February, 16, 6, 45, 0, 0, time.Local)
	allowed, err := IsWithinUpdateWindow(start, window)
	if err != nil {
		t.Fatalf("IsWithinUpdateWindow returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected start boundary to be inclusive")
	}

	end := time.Date(2026, time.February, 16, 21, 14, 0, 0, time.Local)
	allowed, err = IsWithinUpdateWindow(end, window)
	if err != nil {
		t.Fatalf("IsWithinUpdateWindow returned error: %v", err)
	}
	if allowed {
		t.Fatalf("expected end boundary to be exclusive")
	}
}
