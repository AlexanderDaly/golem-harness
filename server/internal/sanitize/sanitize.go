package sanitize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"golem-harness/server/pkg/trajectory"
)

const DefaultVersion = "sanitize-v0.1.0"

var (
	ErrSanitizerFailed = errors.New("sanitizer failed")

	emailPattern       = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	phonePattern       = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b`)
	ssnPattern         = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	cardPattern        = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	addressPattern     = regexp.MustCompile(`(?i)\b\d{1,6}\s+[A-Z0-9][A-Z0-9.\-]*(?:\s+[A-Z0-9][A-Z0-9.\-]*){0,4}\s+(?:st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|ln|lane|way|ct|court)\b`)
	tokenPattern       = regexp.MustCompile(`(?i)\b(?:bearer|api[_-]?key|access[_-]?token|secret|token)\s*[:=]\s*[A-Z0-9._\-]{8,}\b`)
	longNumericPattern = regexp.MustCompile(`\b\d{9,}\b`)
)

type Decision = trajectory.Decision

type Result struct {
	Frame            trajectory.SanitizedFrame
	Report           trajectory.RedactionReport
	Decision         trajectory.Decision
	ReasonCodes      []string
	SanitizerVersion string
	KillSwitchReason string
}

type Pipeline struct {
	AllowedPackages   map[string]struct{}
	SensitivePackages map[string]string
	Version           string
	NER               NER
	Vision            VisionRedactor
	Now               func() time.Time
}

type NER interface {
	FindEntities(ctx context.Context, text string) ([]Entity, error)
}

type Entity struct {
	Start      int
	End        int
	Label      string
	Confidence float64
}

type ConservativeNER struct{}

func (ConservativeNER) FindEntities(context.Context, string) ([]Entity, error) {
	return nil, nil
}

type VisionRedactor interface {
	PlanRedactions(ctx context.Context, screenshot trajectory.ScreenshotRef) ([]trajectory.RedactionBox, error)
}

type NoopVisionRedactor struct{}

func (NoopVisionRedactor) PlanRedactions(context.Context, trajectory.ScreenshotRef) ([]trajectory.RedactionBox, error) {
	return nil, nil
}

func NewPipeline(allowedPackages, sensitivePackages []string) *Pipeline {
	p := &Pipeline{
		AllowedPackages:   make(map[string]struct{}, len(allowedPackages)),
		SensitivePackages: defaultSensitivePackages(),
		Version:           DefaultVersion,
		NER:               ConservativeNER{},
		Vision:            NoopVisionRedactor{},
	}
	for _, pkg := range allowedPackages {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" {
			p.AllowedPackages[pkg] = struct{}{}
		}
	}
	for _, pkg := range sensitivePackages {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" {
			p.SensitivePackages[pkg] = "configured_sensitive_package"
		}
	}
	return p
}

func (p *Pipeline) Process(ctx context.Context, frame trajectory.RawFrame) (Result, error) {
	if p.Version == "" {
		p.Version = DefaultVersion
	}
	if p.NER == nil {
		p.NER = ConservativeNER{}
	}
	if p.Vision == nil {
		p.Vision = NoopVisionRedactor{}
	}
	report := trajectory.RedactionReport{}
	pkg := strings.TrimSpace(frame.ForegroundApp.PackageName)
	if pkg == "" {
		return p.drop(report, "missing_foreground_package"), nil
	}
	if reason, ok := p.SensitivePackages[pkg]; ok {
		return p.quarantine(report, "sensitive_package", reason), nil
	}
	if _, ok := p.AllowedPackages[pkg]; !ok {
		return p.drop(report, "package_not_allowlisted"), nil
	}

	redactor := newTextRedactor(p.NER)
	root, err := redactor.node(ctx, frame.UIRoot, "ui_root")
	if err != nil {
		return p.drop(report, "sanitizer_error"), ErrSanitizerFailed
	}
	report.RulesApplied = append(report.RulesApplied, redactor.rules()...)
	report.FieldsDropped = append(report.FieldsDropped, redactor.fieldsDropped...)
	report.ReasonCodes = append(report.ReasonCodes, redactor.reasonCodes...)
	report.RulesApplied = append(report.RulesApplied, "structural_attrition")
	if len(frame.PreStorageRaw) > 0 {
		report.FieldsDropped = append(report.FieldsDropped, "pre_storage_raw_fields")
	}

	boxes, err := p.Vision.PlanRedactions(ctx, frame.ScreenshotRef)
	if err != nil {
		return p.drop(report, "vision_redaction_error"), ErrSanitizerFailed
	}
	screenshot := frame.ScreenshotRef
	screenshot.RedactionBoxes = boxes
	if screenshot.ReferenceID != "" && screenshot.RedactionStatus == "" {
		screenshot.RedactionStatus = "metadata_only_no_raw_bytes"
	}

	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	reasonCodes := unique(append(report.ReasonCodes, "sanitized"))
	report.RulesApplied = unique(report.RulesApplied)
	report.FieldsDropped = unique(report.FieldsDropped)
	report.ReasonCodes = reasonCodes

	sanitized := trajectory.SanitizedFrame{
		ProtocolVersion: frame.ProtocolVersion,
		TrajectoryID:    frame.TrajectoryID,
		FrameID:         frame.FrameID,
		Sequence:        frame.Sequence,
		EventTimestamp:  frame.EventTimestamp,
		Device: trajectory.DeviceMetadata{
			DeviceID:                     frame.Device.DeviceID,
			AndroidSDKVersion:            frame.Device.AndroidSDKVersion,
			BuildFingerprintHash:         frame.Device.BuildFingerprintHash,
			BuildMetadataRedactionStatus: frame.Device.BuildMetadataRedactionStatus,
		},
		ForegroundApp: frame.ForegroundApp,
		Allowlist: trajectory.DecisionMetadata{
			Decision:    trajectory.DecisionAccept,
			ReasonCodes: []string{"package_allowlisted"},
		},
		UIRoot:        root,
		Intent:        frame.Intent,
		Action:        frame.Action,
		UISettle:      frame.UISettle,
		ScreenshotRef: screenshot,
		Sanitizer: trajectory.SanitizerMetadata{
			SanitizerVersion:      p.Version,
			Decision:              trajectory.DecisionAccept,
			RedactionRulesApplied: report.RulesApplied,
			FieldsDropped:         report.FieldsDropped,
			ReasonCodes:           reasonCodes,
		},
		Signature: trajectory.SignatureMetadata{
			SignatureAlg:       frame.Signature.SignatureAlg,
			KeyID:              frame.Signature.KeyID,
			PayloadSHA256Hex:   frame.Signature.PayloadSHA256Hex,
			VerificationStatus: "verified",
		},
		SanitizedAt: now().UTC(),
	}

	return Result{
		Frame:            sanitized,
		Report:           report,
		Decision:         trajectory.DecisionAccept,
		ReasonCodes:      reasonCodes,
		SanitizerVersion: p.Version,
	}, nil
}

func (p *Pipeline) drop(report trajectory.RedactionReport, reason string) Result {
	report.ReasonCodes = unique(append(report.ReasonCodes, reason))
	return Result{
		Report:           report,
		Decision:         trajectory.DecisionDrop,
		ReasonCodes:      report.ReasonCodes,
		SanitizerVersion: p.Version,
	}
}

func (p *Pipeline) quarantine(report trajectory.RedactionReport, reason, killSwitchReason string) Result {
	report.ReasonCodes = unique(append(report.ReasonCodes, reason))
	return Result{
		Report:           report,
		Decision:         trajectory.DecisionQuarantine,
		ReasonCodes:      report.ReasonCodes,
		SanitizerVersion: p.Version,
		KillSwitchReason: killSwitchReason,
	}
}

func defaultSensitivePackages() map[string]string {
	return map[string]string{
		"com.example.bank":            "banking_app",
		"com.example.passwordmanager": "password_manager",
		"com.example.medical":         "medical_app",
		"com.google.android.gm":       "email_app",
		"com.whatsapp":                "private_messaging_app",
		"org.signal":                  "private_messaging_app",
	}
}

type textRedactor struct {
	ner           NER
	ruleSet       map[string]struct{}
	fieldsDropped []string
	reasonCodes   []string
}

func newTextRedactor(ner NER) *textRedactor {
	return &textRedactor{
		ner:     ner,
		ruleSet: make(map[string]struct{}),
	}
}

func (r *textRedactor) node(ctx context.Context, in trajectory.RawNode, path string) (trajectory.SanitizedNode, error) {
	textHash, textStatus, err := r.sanitizeText(ctx, in.RawText, path+".pre_storage_text")
	if err != nil {
		return trajectory.SanitizedNode{}, err
	}
	cdHash, cdStatus, err := r.sanitizeText(ctx, in.RawContentDescription, path+".pre_storage_content_description")
	if err != nil {
		return trajectory.SanitizedNode{}, err
	}

	children := make([]trajectory.SanitizedNode, 0, len(in.Children))
	for i, child := range in.Children {
		out, err := r.node(ctx, child, path+".children["+strconvI(i)+"]")
		if err != nil {
			return trajectory.SanitizedNode{}, err
		}
		children = append(children, out)
	}

	return trajectory.SanitizedNode{
		StableNodeID:                      in.StableNodeID,
		Bounds:                            in.Bounds,
		ClassName:                         in.ClassName,
		PackageName:                       in.PackageName,
		ResourceIDHash:                    in.ResourceIDHash,
		TextHash:                          textHash,
		TextRedactionStatus:               textStatus,
		ContentDescriptionHash:            cdHash,
		ContentDescriptionRedactionStatus: cdStatus,
		Clickable:                         in.Clickable,
		Enabled:                           in.Enabled,
		Focused:                           in.Focused,
		Selected:                          in.Selected,
		Checkable:                         in.Checkable,
		Children:                          children,
	}, nil
}

func (r *textRedactor) sanitizeText(ctx context.Context, raw, field string) (string, trajectory.RedactionStatus, error) {
	if raw == "" {
		return "", trajectory.RedactionNotPresent, nil
	}
	r.addRule("structural_attrition")
	if r.hasRegexPII(raw, field) {
		r.fieldsDropped = append(r.fieldsDropped, field)
		return "", trajectory.RedactionRedacted, nil
	}
	entities, err := r.ner.FindEntities(ctx, raw)
	if err != nil {
		return "", "", err
	}
	if len(entities) > 0 {
		r.addRule("local_ner_redaction")
		r.reasonCodes = append(r.reasonCodes, "local_ner_entity_detected")
		r.fieldsDropped = append(r.fieldsDropped, field)
		return "", trajectory.RedactionRedacted, nil
	}

	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:]), trajectory.RedactionHashed, nil
}

func (r *textRedactor) hasRegexPII(raw, field string) bool {
	matched := false
	for _, pattern := range []struct {
		name string
		re   *regexp.Regexp
	}{
		{"regex_email", emailPattern},
		{"regex_phone", phonePattern},
		{"regex_ssn", ssnPattern},
		{"regex_payment_card", cardPattern},
		{"regex_address", addressPattern},
		{"regex_token", tokenPattern},
		{"regex_long_numeric_identifier", longNumericPattern},
	} {
		if pattern.re.MatchString(raw) {
			r.addRule(pattern.name)
			r.reasonCodes = append(r.reasonCodes, pattern.name)
			matched = true
		}
	}
	if matched {
		r.reasonCodes = append(r.reasonCodes, "redacted_sensitive_text")
		r.fieldsDropped = append(r.fieldsDropped, field)
	}
	return matched
}

func (r *textRedactor) addRule(rule string) {
	r.ruleSet[rule] = struct{}{}
}

func (r *textRedactor) rules() []string {
	out := make([]string, 0, len(r.ruleSet))
	for rule := range r.ruleSet {
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func strconvI(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = digits[i%10]
		i /= 10
	}
	return string(buf[pos:])
}
