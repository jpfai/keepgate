//! # KeepGate — Data protection layer for the IGNIS ecosystem
//!
//! KeepGate is a data-centric security layer that classifies, controls, and audits
//! all data flowing through the IGNIS agent ecosystem.
//!
//! ## Modules
//!
//! - [`data_classifier`] — Assigns sensitivity tags to data
//! - [`output_gate`] — Controls data leaving the system
//! - [`leak_detector`] — Detects secret patterns in data
//! - [`approvals`] — Approval system for sensitive outputs

pub mod data_classifier;
pub mod output_gate;
pub mod leak_detector;
pub mod approvals;

// Re-exports of primary types
pub use data_classifier::{DataContext, DataTag, DataSource, Sensitivity, BasicClassifier, DataClassifier};
pub use output_gate::{DataOutput, Destination, OutputError, OutputGate, BasicOutputGate, RedactionReport};
pub use leak_detector::{detect_secrets, SecretMatch, PatternType};
pub use approvals::{ApprovalStatus, ApprovalProvider, DefaultApprovalProvider};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_classify_then_check_output() {
        let classifier = BasicClassifier::new();
        let data = b"This is a normal message";
        let ctx = DataContext::new(DataSource::User);
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Private);

        let gate = BasicOutputGate::new();
        let output = DataOutput::new(data.to_vec(), Destination::Message { channel: "telegram".into() }, tag.clone());
        // Private to Message should pass
        assert!(gate.check(&output, &tag).is_ok());
    }

    #[test]
    fn integration_secret_detected_and_blocked() {
        let classifier = BasicClassifier::new();
        let data = b"Here is my API key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx";
        let ctx = DataContext::new(DataSource::User);
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Secret);

        let provider = DefaultApprovalProvider::deny_all();
        let gate = BasicOutputGate::with_approval_provider(provider);
        let output = DataOutput::new(data.to_vec(), Destination::Message { channel: "telegram".into() }, tag.clone());
        // Secret to Message should be blocked (denied by approval provider)
        assert!(gate.check(&output, &tag).is_err());
    }

    #[test]
    fn integration_redact_secrets() {
        let classifier = BasicClassifier::new();
        let data = b"User config: name=John, api_key=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx";
        let ctx = DataContext::new(DataSource::User);
        let tag = classifier.classify(data, &ctx);

        let gate = BasicOutputGate::new();
        let mut output = DataOutput::new(data.to_vec(), Destination::Log, tag.clone());
        let report = gate.redact(&mut output, &tag);
        assert!(report.fields_redacted > 0);

        let redacted = String::from_utf8_lossy(&output.data);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("sk-abc123"));
    }
}
