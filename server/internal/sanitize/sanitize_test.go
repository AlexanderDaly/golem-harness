package sanitize_test

import (
	"context"
	"strings"
	"testing"

	"golem-harness/server/internal/sanitize"
	"golem-harness/server/internal/testutil"
	"golem-harness/server/pkg/trajectory"
)

func TestSensitivePackageKillSwitchQuarantinesFrame(t *testing.T) {
	pipeline := sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil)
	result, err := pipeline.Process(context.Background(), testutil.RawFrame(testutil.SensitivePkg, "frame-1", 1, "Settings"))
	if err != nil {
		t.Fatalf("unexpected sanitizer error: %v", err)
	}
	if result.Decision != trajectory.DecisionQuarantine {
		t.Fatalf("expected quarantine, got %s", result.Decision)
	}
	if !contains(result.ReasonCodes, "sensitive_package") {
		t.Fatalf("missing sensitive package reason: %v", result.ReasonCodes)
	}
}

func TestNonAllowlistedPackageIsRejectedByDefault(t *testing.T) {
	pipeline := sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil)
	result, err := pipeline.Process(context.Background(), testutil.RawFrame("com.example.other", "frame-1", 1, "Settings"))
	if err != nil {
		t.Fatalf("unexpected sanitizer error: %v", err)
	}
	if result.Decision != trajectory.DecisionDrop {
		t.Fatalf("expected drop, got %s", result.Decision)
	}
	if !contains(result.ReasonCodes, "package_not_allowlisted") {
		t.Fatalf("missing allowlist reason: %v", result.ReasonCodes)
	}
}

func TestRegexRedactionRemovesSyntheticPII(t *testing.T) {
	tests := []struct {
		name string
		text string
		rule string
	}{
		{name: "email", text: "alice@example.test", rule: "regex_email"},
		{name: "phone", text: "Call 415-555-1212", rule: "regex_phone"},
		{name: "address", text: "Ship to 123 Main St", rule: "regex_address"},
		{name: "ssn", text: "SSN 123-45-6789", rule: "regex_ssn"},
		{name: "card", text: "Card 4111 1111 1111 1111", rule: "regex_payment_card"},
		{name: "token", text: "Bearer token: sk_test_123456789", rule: "regex_token"},
		{name: "long numeric", text: "Case 123456789012345", rule: "regex_long_numeric_identifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil)
			result, err := pipeline.Process(context.Background(), testutil.RawFrame(testutil.AllowedPkg, "frame-"+tt.name, 1, tt.text))
			if err != nil {
				t.Fatalf("unexpected sanitizer error: %v", err)
			}
			if result.Decision != trajectory.DecisionAccept {
				t.Fatalf("expected accept with redaction, got %s", result.Decision)
			}
			if result.Frame.UIRoot.TextRedactionStatus != trajectory.RedactionRedacted {
				t.Fatalf("expected redacted text status, got %s", result.Frame.UIRoot.TextRedactionStatus)
			}
			if result.Frame.UIRoot.TextHash != "" {
				t.Fatalf("expected no text hash for redacted sensitive text")
			}
			if !contains(result.Report.RulesApplied, tt.rule) {
				t.Fatalf("missing rule %q in %v", tt.rule, result.Report.RulesApplied)
			}
			encoded := marshalForTest(t, result.Frame)
			if strings.Contains(encoded, tt.text) {
				t.Fatalf("sanitized frame leaked raw text %q: %s", tt.text, encoded)
			}
		})
	}
}

func TestNonSensitiveTextIsHashed(t *testing.T) {
	pipeline := sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil)
	result, err := pipeline.Process(context.Background(), testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"))
	if err != nil {
		t.Fatalf("unexpected sanitizer error: %v", err)
	}
	if result.Frame.UIRoot.TextRedactionStatus != trajectory.RedactionHashed {
		t.Fatalf("expected hashed text, got %s", result.Frame.UIRoot.TextRedactionStatus)
	}
	if result.Frame.UIRoot.TextHash == "" {
		t.Fatalf("expected text hash")
	}
	if strings.Contains(marshalForTest(t, result.Frame), "Settings") {
		t.Fatalf("sanitized frame leaked raw text")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
