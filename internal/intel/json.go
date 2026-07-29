package intel

import "encoding/json"

// Kept behind a tiny helper so trust-store and install code use the same
// deterministic standard-library encoder as bundle canonicalization.
func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}
