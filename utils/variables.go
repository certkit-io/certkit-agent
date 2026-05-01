package utils

// UpdateVariable is a name/value pair injected into update_cmd execution.
// Values are sensitive and must never be persisted to disk or sent back to
// the server.
type UpdateVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// IsValidVariableName matches [A-Za-z_][A-Za-z0-9_]* — defense in depth so
// a malformed variable name from the server cannot inject shell or
// PowerShell syntax via the assignment line.
func IsValidVariableName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
