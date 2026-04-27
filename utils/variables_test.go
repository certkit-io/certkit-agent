package utils

import "testing"

func TestIsValidVariableName(t *testing.T) {
	good := []string{"DB", "_X", "DB_PASSWORD", "x9", "_0", "Mixed_Case_99"}
	bad := []string{"", "9LEAD", "FOO BAR", "FOO;rm", "FOO-BAR", "FOO$", "FOO\nBAR"}

	for _, name := range good {
		if !IsValidVariableName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	for _, name := range bad {
		if IsValidVariableName(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}
