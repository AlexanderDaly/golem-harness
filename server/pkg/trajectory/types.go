package trajectory

import "time"

type Decision string

const (
	DecisionAccept     Decision = "accept"
	DecisionDrop       Decision = "drop"
	DecisionQuarantine Decision = "quarantine"
)

type RedactionStatus string

const (
	RedactionNotPresent RedactionStatus = "not_present"
	RedactionHashed     RedactionStatus = "hashed"
	RedactionRedacted   RedactionStatus = "redacted"
	RedactionDropped    RedactionStatus = "dropped"
)

type RawFrame struct {
	ProtocolVersion string            `json:"protocol_version"`
	TrajectoryID    string            `json:"trajectory_id"`
	FrameID         string            `json:"frame_id"`
	Sequence        uint64            `json:"sequence"`
	EventTimestamp  time.Time         `json:"event_timestamp"`
	Device          DeviceMetadata    `json:"device"`
	ForegroundApp   ForegroundApp     `json:"foreground_app"`
	UIRoot          RawNode           `json:"ui_root"`
	Intent          IntentMetadata    `json:"intent"`
	Action          ActionMetadata    `json:"action"`
	UISettle        UISettleMetadata  `json:"ui_settle"`
	ScreenshotRef   ScreenshotRef     `json:"screenshot_ref"`
	Signature       SignatureMetadata `json:"signature"`
	PreStorageRaw   map[string]string `json:"pre_storage_raw_fields,omitempty"`
}

type SanitizedFrame struct {
	ProtocolVersion string            `json:"protocol_version"`
	TrajectoryID    string            `json:"trajectory_id"`
	FrameID         string            `json:"frame_id"`
	Sequence        uint64            `json:"sequence"`
	EventTimestamp  time.Time         `json:"event_timestamp"`
	Device          DeviceMetadata    `json:"device"`
	ForegroundApp   ForegroundApp     `json:"foreground_app"`
	Allowlist       DecisionMetadata  `json:"allowlist_decision"`
	UIRoot          SanitizedNode     `json:"ui_root"`
	Intent          IntentMetadata    `json:"intent"`
	Action          ActionMetadata    `json:"action"`
	UISettle        UISettleMetadata  `json:"ui_settle"`
	ScreenshotRef   ScreenshotRef     `json:"screenshot_ref"`
	Sanitizer       SanitizerMetadata `json:"sanitizer"`
	Signature       SignatureMetadata `json:"signature"`
	SanitizedAt     time.Time         `json:"sanitized_at"`
}

type DeviceMetadata struct {
	DeviceID                     string `json:"device_id"`
	AndroidSDKVersion            string `json:"android_sdk_version"`
	BuildFingerprintHash         string `json:"build_fingerprint_hash"`
	BuildMetadataRedactionStatus string `json:"build_metadata_redaction_status"`
}

type ForegroundApp struct {
	PackageName  string `json:"package_name"`
	ActivityName string `json:"activity_name,omitempty"`
}

type DecisionMetadata struct {
	Decision         Decision `json:"decision"`
	ReasonCodes      []string `json:"reason_codes,omitempty"`
	KillSwitchReason string   `json:"kill_switch_reason,omitempty"`
}

type RawNode struct {
	StableNodeID                      string    `json:"stable_node_id"`
	Bounds                            Bounds    `json:"bounds"`
	ClassName                         string    `json:"class_name"`
	PackageName                       string    `json:"package_name"`
	ResourceIDHash                    string    `json:"resource_id_hash,omitempty"`
	RawText                           string    `json:"pre_storage_text,omitempty"`
	TextHash                          string    `json:"text_hash,omitempty"`
	TextRedactionStatus               string    `json:"text_redaction_status,omitempty"`
	RawContentDescription             string    `json:"pre_storage_content_description,omitempty"`
	ContentDescriptionHash            string    `json:"content_description_hash,omitempty"`
	ContentDescriptionRedactionStatus string    `json:"content_description_redaction_status,omitempty"`
	Clickable                         bool      `json:"clickable"`
	Enabled                           bool      `json:"enabled"`
	Focused                           bool      `json:"focused"`
	Selected                          bool      `json:"selected"`
	Checkable                         bool      `json:"checkable"`
	Children                          []RawNode `json:"children,omitempty"`
}

type SanitizedNode struct {
	StableNodeID                      string          `json:"stable_node_id"`
	Bounds                            Bounds          `json:"bounds"`
	ClassName                         string          `json:"class_name"`
	PackageName                       string          `json:"package_name"`
	ResourceIDHash                    string          `json:"resource_id_hash,omitempty"`
	TextHash                          string          `json:"text_hash,omitempty"`
	TextRedactionStatus               RedactionStatus `json:"text_redaction_status"`
	ContentDescriptionHash            string          `json:"content_description_hash,omitempty"`
	ContentDescriptionRedactionStatus RedactionStatus `json:"content_description_redaction_status"`
	Clickable                         bool            `json:"clickable"`
	Enabled                           bool            `json:"enabled"`
	Focused                           bool            `json:"focused"`
	Selected                          bool            `json:"selected"`
	Checkable                         bool            `json:"checkable"`
	Children                          []SanitizedNode `json:"children,omitempty"`
}

type Bounds struct {
	Left   int32 `json:"left"`
	Top    int32 `json:"top"`
	Right  int32 `json:"right"`
	Bottom int32 `json:"bottom"`
}

type IntentMetadata struct {
	OperatorIntentID               string          `json:"operator_intent_id,omitempty"`
	IntentType                     string          `json:"intent_type,omitempty"`
	Tags                           []string        `json:"tags,omitempty"`
	NaturalLanguageHash            string          `json:"natural_language_hash,omitempty"`
	NaturalLanguageRedactionStatus RedactionStatus `json:"natural_language_redaction_status,omitempty"`
}

type ActionMetadata struct {
	ActionID           string   `json:"action_id,omitempty"`
	ActionType         string   `json:"action_type,omitempty"`
	TargetStableNodeID string   `json:"target_stable_node_id,omitempty"`
	TargetBounds       Bounds   `json:"target_bounds"`
	Deterministic      bool     `json:"deterministic"`
	Preconditions      []string `json:"preconditions,omitempty"`
}

type UISettleMetadata struct {
	Observed        bool   `json:"observed"`
	SettleTimeoutMS uint32 `json:"settle_timeout_ms,omitempty"`
	ElapsedMS       uint32 `json:"elapsed_ms,omitempty"`
	SettleStatus    string `json:"settle_status,omitempty"`
}

type ScreenshotRef struct {
	ReferenceID     string         `json:"reference_id,omitempty"`
	SHA256Hex       string         `json:"sha256_hex,omitempty"`
	MediaType       string         `json:"media_type,omitempty"`
	RedactionStatus string         `json:"redaction_status,omitempty"`
	RedactionBoxes  []RedactionBox `json:"redaction_boxes,omitempty"`
}

type RedactionBox struct {
	Bounds     Bounds `json:"bounds"`
	ReasonCode string `json:"reason_code"`
}

type SanitizerMetadata struct {
	SanitizerVersion      string   `json:"sanitizer_version"`
	Decision              Decision `json:"decision"`
	RedactionRulesApplied []string `json:"redaction_rules_applied,omitempty"`
	FieldsDropped         []string `json:"fields_dropped,omitempty"`
	ReasonCodes           []string `json:"reason_codes,omitempty"`
	KillSwitchReason      string   `json:"kill_switch_reason,omitempty"`
}

type SignatureMetadata struct {
	SignatureAlg       string `json:"signature_alg,omitempty"`
	KeyID              string `json:"key_id,omitempty"`
	PayloadSHA256Hex   string `json:"payload_sha256_hex,omitempty"`
	VerificationStatus string `json:"verification_status,omitempty"`
}

type RedactionReport struct {
	RulesApplied  []string `json:"rules_applied,omitempty"`
	FieldsDropped []string `json:"fields_dropped,omitempty"`
	ReasonCodes   []string `json:"reason_codes,omitempty"`
}
