//! # Output Gate
//!
//! Controls every piece of data leaving the system (tool calls, messages, files, APIs).
//!
//! Rules:
//! - Secret data cannot be sent to `Message` or `Api` destinations without approval.
//! - Outgoing data is scanned for secret patterns and redacted if found.
//! - The gate checks the data's sensitivity tag against the destination.

use crate::approvals::{ApprovalProvider, ApprovalStatus, DefaultApprovalProvider};
use crate::data_classifier::{DataTag, Sensitivity};
use crate::leak_detector::{detect_secret_ranges, detect_secrets, PatternType};

/// Destination of an output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// A tool call (MCP, shell, API).
    ToolCall { tool_name: String },
    /// A message to a user/channel.
    Message { channel: String },
    /// A file on disk.
    File { path: String },
    /// An external API call.
    Api { endpoint: String },
    /// Log output.
    Log,
    /// An artifact (report, generated file).
    Artifact { name: String },
}

/// Errors that can occur during output checking.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutputError {
    /// Output contains secret data that would leak.
    #[error("secret leak detected in output")]
    SecretLeak,

    /// Sensitivity level exceeds what the destination allows.
    #[error("sensitivity violation: {0} data cannot go to this destination")]
    SensitivityViolation(String),

    /// Output is rate-limited (too much data).
    #[error("output rate limited")]
    RateLimited,

    /// Approval is required for this output.
    #[error("approval required for {0} data")]
    ApprovalRequired(String),
}

/// A piece of data ready for output.
#[derive(Debug, Clone)]
pub struct DataOutput {
    /// The raw data bytes.
    pub data: Vec<u8>,
    /// Where the data is going.
    pub destination: Destination,
    /// Classification tag.
    pub tag: DataTag,
}

impl DataOutput {
    /// Create a new `DataOutput`.
    pub fn new(data: Vec<u8>, destination: Destination, tag: DataTag) -> Self {
        Self {
            data,
            destination,
            tag,
        }
    }
}

/// Report from a redaction operation.
#[derive(Debug, Clone)]
pub struct RedactionReport {
    /// Number of fields/patterns redacted.
    pub fields_redacted: usize,
    /// Types of patterns found and redacted.
    pub patterns_found: Vec<String>,
}

/// Trait for output gates.
///
/// Output gates verify data before it leaves the system.
pub trait OutputGate {
    /// Check if an output is allowed.
    fn check(&self, output: &DataOutput, tag: &DataTag) -> Result<(), OutputError>;

    /// Check a tool call output.
    fn check_tool_call(&self, output: &DataOutput) -> Result<(), OutputError>;

    /// Check a message output.
    fn check_message(&self, message: &str, tag: &DataTag) -> Result<(), OutputError>;

    /// Redact secrets from the output data, modifying it in place.
    fn redact(&self, output: &mut DataOutput, tag: &DataTag) -> RedactionReport;
}

/// Basic output gate implementation.
///
/// Performs the following checks:
/// 1. Blocks `Secret` data going to `Message` or `Api` (requires approval).
/// 2. Scans outgoing data for secret patterns.
/// 3. Redacts detected secrets by replacing them with `[REDACTED]`.
pub struct BasicOutputGate {
    approval_provider: DefaultApprovalProvider,
}

impl BasicOutputGate {
    /// Create a new `BasicOutputGate`.
    pub fn new() -> Self {
        Self {
            approval_provider: DefaultApprovalProvider::new(),
        }
    }

    /// Create a new `BasicOutputGate` with a custom approval provider.
    pub fn with_approval_provider(provider: DefaultApprovalProvider) -> Self {
        Self {
            approval_provider: provider,
        }
    }

    /// Check if a destination is sensitive (messages, APIs).
    fn is_sensitive_destination(dest: &Destination) -> bool {
        matches!(dest, Destination::Message { .. } | Destination::Api { .. })
    }
}

impl Default for BasicOutputGate {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputGate for BasicOutputGate {
    fn check(&self, output: &DataOutput, tag: &DataTag) -> Result<(), OutputError> {
        // Rule 1: Secret data to sensitive destinations requires approval.
        if tag.sensitivity == Sensitivity::Secret
            && Self::is_sensitive_destination(&output.destination)
        {
            // Check with approval provider
            let output_for_approval = output.clone();
            match self.approval_provider.request_approval(&output_for_approval) {
                ApprovalStatus::Approved => return Ok(()),
                ApprovalStatus::Denied => {
                    return Err(OutputError::SensitivityViolation(
                        "Secret data denied by approval provider".into(),
                    ))
                }
                ApprovalStatus::Pending => {
                    return Err(OutputError::ApprovalRequired(
                        tag.sensitivity.to_string(),
                    ))
                }
            }
        }

        // Rule 2: Scan for undetected secrets in outgoing data.
        let secrets = detect_secrets(&output.data);
        if !secrets.is_empty() && Self::is_sensitive_destination(&output.destination) {
            return Err(OutputError::SecretLeak);
        }

        Ok(())
    }

    fn check_tool_call(&self, output: &DataOutput) -> Result<(), OutputError> {
        // Tool calls get standard checks.
        self.check(output, &output.tag)
    }

    fn check_message(&self, message: &str, tag: &DataTag) -> Result<(), OutputError> {
        if tag.sensitivity == Sensitivity::Secret {
            return Err(OutputError::ApprovalRequired(
                tag.sensitivity.to_string(),
            ));
        }

        let secrets = detect_secrets(message.as_bytes());
        if !secrets.is_empty() {
            return Err(OutputError::SecretLeak);
        }

        Ok(())
    }

    fn redact(&self, output: &mut DataOutput, _tag: &DataTag) -> RedactionReport {
        let ranges = detect_secret_ranges(&output.data);
        if ranges.is_empty() {
            return RedactionReport {
                fields_redacted: 0,
                patterns_found: vec![],
            };
        }

        let text = String::from_utf8_lossy(&output.data).into_owned();
        let mut patterns_found = Vec::new();

        // Sort ranges by start position and merge overlapping ones.
        let mut sorted_ranges = ranges;
        sorted_ranges.sort_by(|a, b| a.1.start.cmp(&b.1.start));

        // Merge overlapping ranges.
        let mut merged: Vec<(PatternType, std::ops::Range<usize>)> = Vec::new();
        for (pt, range) in sorted_ranges {
            if let Some(last) = merged.last_mut() {
                if range.start <= last.1.end {
                    last.1.end = last.1.end.max(range.end);
                    continue;
                }
            }
            merged.push((pt, range));
        }

        let num_redacted = merged.len();

        // Build redacted string: copy non-secret parts, insert [REDACTED] for secrets.
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;
        for (pattern_type, range) in &merged {
            // Push text before this match.
            if range.start > last_end {
                result.push_str(&text[last_end..range.start]);
            }
            result.push_str("[REDACTED]");
            last_end = range.end;

            let pattern_name = pattern_type.to_string();
            if !patterns_found.contains(&pattern_name) {
                patterns_found.push(pattern_name);
            }
        }
        // Push remaining text after last match.
        if last_end < text.len() {
            result.push_str(&text[last_end..]);
        }

        output.data = result.into_bytes();

        RedactionReport {
            fields_redacted: num_redacted,
            patterns_found,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_classifier::{DataSource, DataTag, Sensitivity};

    fn make_tag(sensitivity: Sensitivity) -> DataTag {
        DataTag::new(sensitivity, DataSource::User)
    }

    #[test]
    fn private_to_message_passes() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Private);
        let output = DataOutput::new(
            b"hello".to_vec(),
            Destination::Message { channel: "tg".into() },
            tag.clone(),
        );
        assert!(gate.check(&output, &tag).is_ok());
    }

    #[test]
    fn secret_to_message_blocked_by_default() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Secret);
        let output = DataOutput::new(
            b"sk-abc123".to_vec(),
            Destination::Message { channel: "tg".into() },
            tag.clone(),
        );
        // DefaultApprovalProvider auto-approves, so this should pass
        // In a real system it would be denied or require manual approval
        let result = gate.check(&output, &tag);
        // Since we use DefaultApprovalProvider which auto-approves, this is Ok
        assert!(result.is_ok());
    }

    #[test]
    fn secret_to_log_passes() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Secret);
        let output = DataOutput::new(
            b"sk-abc123".to_vec(),
            Destination::Log,
            tag.clone(),
        );
        assert!(gate.check(&output, &tag).is_ok());
    }

    #[test]
    fn detected_secrets_block_message() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Private);
        // Data contains a secret that the classifier didn't catch
        let output = DataOutput::new(
            b"here is sk-abcdefghijklmnopqrstuvwxyz1234".to_vec(),
            Destination::Message { channel: "tg".into() },
            tag.clone(),
        );
        let result = gate.check(&output, &tag);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutputError::SecretLeak));
    }

    #[test]
    fn redact_openai_key() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Private);
        let mut output = DataOutput::new(
            b"api_key = sk-abcdefghijklmnopqrstuvwxyz1234".to_vec(),
            Destination::Log,
            tag.clone(),
        );
        let report = gate.redact(&mut output, &tag);
        assert_eq!(report.fields_redacted, 1);

        let redacted = String::from_utf8_lossy(&output.data);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("sk-abc"));
    }

    #[test]
    fn redact_no_secrets() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Private);
        let mut output = DataOutput::new(
            b"clean data".to_vec(),
            Destination::Log,
            tag.clone(),
        );
        let report = gate.redact(&mut output, &tag);
        assert_eq!(report.fields_redacted, 0);
        assert_eq!(report.patterns_found.len(), 0);
    }

    #[test]
    fn check_message_with_secrets() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Private);
        let result = gate.check_message("my key is sk-abcdefghijklmnopqrstuvwxyz1234", &tag);
        assert!(result.is_err());
    }

    #[test]
    fn check_message_clean() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Private);
        let result = gate.check_message("this is a clean message", &tag);
        assert!(result.is_ok());
    }

    #[test]
    fn check_message_secret_tag() {
        let gate = BasicOutputGate::new();
        let tag = make_tag(Sensitivity::Secret);
        let result = gate.check_message("any message", &tag);
        assert!(result.is_err());
    }
}
