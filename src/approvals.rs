//! # Approvals
//!
//! Approval system for sensitive outputs.
//! Provides a trait for pluggable approval backends and a default
//! implementation that auto-approves (to be replaced with a real provider).

use crate::output_gate::DataOutput;

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Request is pending review.
    Pending,
    /// Request has been approved.
    Approved,
    /// Request has been denied.
    Denied,
}

/// Trait for approval providers.
///
/// Implement this trait to plug in different approval mechanisms
/// (manual review, policy-based, auto-approve, etc.)
pub trait ApprovalProvider {
    /// Request approval for a data output.
    ///
    /// Returns the approval status for the given output.
    fn request_approval(&self, output: &DataOutput) -> ApprovalStatus;
}

/// Default approval provider that auto-approves everything.
///
/// **Warning:** This is a placeholder. In production, replace with
/// a provider that requires manual review or policy-based checks.
pub struct DefaultApprovalProvider {
    /// If true, auto-approve all requests. If false, deny all.
    auto_approve: bool,
}

impl DefaultApprovalProvider {
    /// Create a new auto-approving provider.
    pub fn new() -> Self {
        Self {
            auto_approve: true,
        }
    }

    /// Create a provider that denies all requests.
    pub fn deny_all() -> Self {
        Self {
            auto_approve: false,
        }
    }

    /// Create a provider with explicit mode.
    pub fn with_mode(auto_approve: bool) -> Self {
        Self { auto_approve }
    }
}

impl Default for DefaultApprovalProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalProvider for DefaultApprovalProvider {
    fn request_approval(&self, _output: &DataOutput) -> ApprovalStatus {
        if self.auto_approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_classifier::{DataTag, DataSource, Sensitivity};
    use crate::output_gate::Destination;

    fn make_output() -> DataOutput {
        DataOutput::new(
            b"test".to_vec(),
            Destination::Message { channel: "tg".into() },
            DataTag::new(Sensitivity::Secret, DataSource::User),
        )
    }

    #[test]
    fn default_provider_approves() {
        let provider = DefaultApprovalProvider::new();
        let output = make_output();
        assert_eq!(provider.request_approval(&output), ApprovalStatus::Approved);
    }

    #[test]
    fn deny_all_provider_denies() {
        let provider = DefaultApprovalProvider::deny_all();
        let output = make_output();
        assert_eq!(provider.request_approval(&output), ApprovalStatus::Denied);
    }

    #[test]
    fn with_mode_true_approves() {
        let provider = DefaultApprovalProvider::with_mode(true);
        let output = make_output();
        assert_eq!(provider.request_approval(&output), ApprovalStatus::Approved);
    }

    #[test]
    fn with_mode_false_denies() {
        let provider = DefaultApprovalProvider::with_mode(false);
        let output = make_output();
        assert_eq!(provider.request_approval(&output), ApprovalStatus::Denied);
    }
}
