//! # Data Classifier
//!
//! Assigns sensitivity tags to data flowing through the IGNIS ecosystem.
//! Default sensitivity is `Private` (never `Public` — lesson from Anthropic CMS leak).
//!
//! The classifier scans content for secret patterns and automatically tags
//! data containing API keys, tokens, or credentials as `Secret`.

use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Sensitivity level of a piece of data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    /// Accessible without restriction.
    Public,
    /// Internal to the IGNIS ecosystem.
    Internal,
    /// Personal / user data.
    Private,
    /// Credentials, API keys, tokens.
    Secret,
}

/// Default is `Private` — never `Public` by default (Anthropic CMS lesson).
impl Default for Sensitivity {
    fn default() -> Self {
        Sensitivity::Private
    }
}

impl std::fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sensitivity::Public => write!(f, "public"),
            Sensitivity::Internal => write!(f, "internal"),
            Sensitivity::Private => write!(f, "private"),
            Sensitivity::Secret => write!(f, "secret"),
        }
    }
}

/// Source of the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSource {
    /// External source (URL, email, file).
    External(String),
    /// Created by an identified agent.
    Agent(String),
    /// From persistent memory (RAG, files).
    Memory,
    /// Direct user input.
    User,
}

/// Classification metadata attached to a piece of data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTag {
    /// Sensitivity level.
    pub sensitivity: Sensitivity,
    /// Origin of the data.
    pub source: DataSource,
    /// Unix timestamp (seconds) of tag creation.
    pub created_at: i64,
    /// Optional parent tag for inheritance.
    pub parent_id: Option<Uuid>,
    /// Unique identifier for this tag.
    pub id: Uuid,
}

impl DataTag {
    /// Create a new `DataTag` with the current timestamp.
    pub fn new(sensitivity: Sensitivity, source: DataSource) -> Self {
        Self {
            sensitivity,
            source,
            created_at: Utc::now().timestamp(),
            parent_id: None,
            id: Uuid::new_v4(),
        }
    }

    /// Create a new `DataTag` that inherits from a parent.
    pub fn with_parent(sensitivity: Sensitivity, source: DataSource, parent: &DataTag) -> Self {
        Self {
            sensitivity,
            source,
            created_at: Utc::now().timestamp(),
            parent_id: Some(parent.id),
            id: Uuid::new_v4(),
        }
    }
}

/// Context provided to the classifier for decision-making.
#[derive(Debug, Clone)]
pub struct DataContext {
    /// Source of the data being classified.
    pub source: DataSource,
    /// Optional hint about expected sensitivity.
    pub expected_sensitivity: Option<Sensitivity>,
}

impl DataContext {
    /// Create a new context with just a source.
    pub fn new(source: DataSource) -> Self {
        Self {
            source,
            expected_sensitivity: None,
        }
    }

    /// Create a context with an expected sensitivity hint.
    pub fn with_expected(source: DataSource, expected: Sensitivity) -> Self {
        Self {
            source,
            expected_sensitivity: Some(expected),
        }
    }
}

/// Trait for data classifiers.
///
/// Classifiers assign sensitivity tags to data and verify existing tags.
pub trait DataClassifier {
    /// Classify raw data and return a `DataTag`.
    fn classify(&self, data: &[u8], context: &DataContext) -> DataTag;

    /// Verify that data matches the expected sensitivity level.
    fn verify(&self, data: &[u8], expected: Sensitivity) -> bool;

    /// Create a child tag that inherits from a parent.
    fn inherit_tag(&self, parent: &DataTag, child_source: DataSource) -> DataTag;
}

/// Basic classifier that scans for secret patterns.
///
/// - Returns `Secret` if any secret pattern is found in the data.
/// - Otherwise returns the default sensitivity (`Private`).
pub struct BasicClassifier {
    secret_patterns: Vec<Regex>,
}

impl BasicClassifier {
    /// Create a new `BasicClassifier` with built-in secret detection patterns.
    pub fn new() -> Self {
        let patterns = vec![
            // OpenAI API keys: sk-...
            Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap(),
            // AWS Access Key IDs
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            // GCP API keys
            Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            // Generic Bearer tokens
            Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_.-]{20,}").unwrap(),
            // Generic API key patterns
            Regex::new(r#"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?[a-zA-Z0-9_.-]{16,}"#).unwrap(),
            // JWT tokens
            Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_.-]+").unwrap(),
            // Private keys
            Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            // Generic passwords
            Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}"#).unwrap(),
        ];

        Self {
            secret_patterns: patterns,
        }
    }

    /// Check if data contains any secret patterns.
    pub fn contains_secrets(&self, data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data);
        self.secret_patterns.iter().any(|re| re.is_match(&text))
    }
}

impl Default for BasicClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DataClassifier for BasicClassifier {
    fn classify(&self, data: &[u8], context: &DataContext) -> DataTag {
        let sensitivity = if self.contains_secrets(data) {
            Sensitivity::Secret
        } else {
            Sensitivity::default()
        };

        DataTag::new(sensitivity, context.source.clone())
    }

    fn verify(&self, data: &[u8], expected: Sensitivity) -> bool {
        if self.contains_secrets(data) {
            expected == Sensitivity::Secret
        } else {
            expected != Sensitivity::Secret
        }
    }

    fn inherit_tag(&self, parent: &DataTag, child_source: DataSource) -> DataTag {
        // Child inherits the parent's sensitivity (conservative approach).
        DataTag::with_parent(parent.sensitivity, child_source, parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sensitivity_is_private() {
        assert_eq!(Sensitivity::default(), Sensitivity::Private);
    }

    #[test]
    fn classify_normal_data_returns_private() {
        let classifier = BasicClassifier::new();
        let data = b"Just some regular text content";
        let ctx = DataContext::new(DataSource::User);
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Private);
    }

    #[test]
    fn classify_openai_key_returns_secret() {
        let classifier = BasicClassifier::new();
        let data = b"my key is sk-abcdefghijklmnopqrstuvwxyz1234";
        let ctx = DataContext::new(DataSource::User);
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Secret);
    }

    #[test]
    fn classify_aws_key_returns_secret() {
        let classifier = BasicClassifier::new();
        let data = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let ctx = DataContext::new(DataSource::External("config".into()));
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Secret);
    }

    #[test]
    fn classify_jwt_returns_secret() {
        let classifier = BasicClassifier::new();
        let data = b"token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let ctx = DataContext::new(DataSource::User);
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Secret);
    }

    #[test]
    fn classify_private_key_returns_secret() {
        let classifier = BasicClassifier::new();
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        let ctx = DataContext::new(DataSource::External("keyfile".into()));
        let tag = classifier.classify(data, &ctx);
        assert_eq!(tag.sensitivity, Sensitivity::Secret);
    }

    #[test]
    fn verify_normal_data() {
        let classifier = BasicClassifier::new();
        let data = b"normal data";
        assert!(classifier.verify(data, Sensitivity::Private));
        assert!(!classifier.verify(data, Sensitivity::Secret));
    }

    #[test]
    fn verify_secret_data() {
        let classifier = BasicClassifier::new();
        let data = b"api_key=sk-abcdefghijklmnopqrstuvwxyz1234";
        assert!(classifier.verify(data, Sensitivity::Secret));
        assert!(!classifier.verify(data, Sensitivity::Private));
    }

    #[test]
    fn inherit_tag_preserves_parent_sensitivity() {
        let classifier = BasicClassifier::new();
        let parent = DataTag::new(Sensitivity::Internal, DataSource::Memory);
        let child = classifier.inherit_tag(&parent, DataSource::Agent("agent-1".into()));
        assert_eq!(child.sensitivity, Sensitivity::Internal);
        assert_eq!(child.parent_id, Some(parent.id));
    }

    #[test]
    fn data_tag_has_unique_id() {
        let tag1 = DataTag::new(Sensitivity::Private, DataSource::User);
        let tag2 = DataTag::new(Sensitivity::Private, DataSource::User);
        assert_ne!(tag1.id, tag2.id);
    }
}
