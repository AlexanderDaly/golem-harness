package sanitize_test

import (
	"encoding/json"
	"testing"
)

func marshalForTest(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
