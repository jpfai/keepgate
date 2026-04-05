//! # Leak Detector
//!
//! Detects secret patterns in data using regex matching.
//! Covers API keys (AWS, GCP, OpenAI), JWT tokens, passwords, and private keys.

use regex::Regex;

/// Type of secret pattern detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternType {
    /// OpenAI-style API key.
    OpenAiKey,
    /// AWS Access Key.
    AwsKey,
    /// GCP API key.
    GcpKey,
    /// JWT bearer token.
    JwtToken,
    /// Generic API key / token pattern.
    GenericApiKey,
    /// Private key (PEM format).
    PrivateKey,
    /// Password pattern.
    Password,
}

impl std::fmt::Display for PatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternType::OpenAiKey => write!(f, "openai_key"),
            PatternType::AwsKey => write!(f, "aws_key"),
            PatternType::GcpKey => write!(f, "gcp_key"),
            PatternType::JwtToken => write!(f, "jwt_token"),
            PatternType::GenericApiKey => write!(f, "generic_api_key"),
            PatternType::PrivateKey => write!(f, "private_key"),
            PatternType::Password => write!(f, "password"),
        }
    }
}

/// A detected secret match.
#[derive(Debug, Clone)]
pub struct SecretMatch {
    /// Type of pattern matched.
    pub pattern_type: PatternType,
    /// Byte offset in the input data.
    pub location: usize,
    /// Length of the matched region in bytes.
    pub length: usize,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
}

/// Internal pattern definition.
struct SecretPattern {
    pattern_type: PatternType,
    regex: Regex,
    confidence: f64,
}

/// Build the list of secret detection patterns.
fn build_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            pattern_type: PatternType::OpenAiKey,
            regex: Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap(),
            confidence: 0.95,
        },
        SecretPattern {
            pattern_type: PatternType::AwsKey,
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            confidence: 0.95,
        },
        SecretPattern {
            pattern_type: PatternType::GcpKey,
            regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            confidence: 0.95,
        },
        SecretPattern {
            pattern_type: PatternType::JwtToken,
            regex: Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_.-]+").unwrap(),
            confidence: 0.90,
        },
        SecretPattern {
            pattern_type: PatternType::PrivateKey,
            regex: Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            confidence: 0.99,
        },
        SecretPattern {
            pattern_type: PatternType::Password,
            regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}"#).unwrap(),
            confidence: 0.70,
        },
        SecretPattern {
            pattern_type: PatternType::GenericApiKey,
            regex: Regex::new(r#"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?[a-zA-Z0-9_.-]{16,}"#).unwrap(),
            confidence: 0.80,
        },
    ]
}

/// Detect secrets in raw data.
///
/// Scans the input with regex patterns and returns all matches found.
///
/// # Arguments
///
/// * `data` — The raw bytes to scan.
///
/// # Returns
///
/// A `Vec<SecretMatch>` with all detected secrets.
pub fn detect_secrets(data: &[u8]) -> Vec<SecretMatch> {
    let text = String::from_utf8_lossy(data);
    let patterns = build_patterns();
    let mut matches = Vec::new();

    for pat in &patterns {
        for m in pat.regex.find_iter(&text) {
            matches.push(SecretMatch {
                pattern_type: pat.pattern_type.clone(),
                location: m.start(),
                length: m.len(),
                confidence: pat.confidence,
            });
        }
    }

    matches
}

/// Detect secrets and return them as (PatternType, matched_text) tuples
/// for redaction purposes.
pub(crate) fn detect_secret_ranges(data: &[u8]) -> Vec<(PatternType, std::ops::Range<usize>)> {
    let text = String::from_utf8_lossy(data);
    let patterns = build_patterns();
    let mut ranges = Vec::new();

    for pat in &patterns {
        for m in pat.regex.find_iter(&text) {
            ranges.push((pat.pattern_type.clone(), m.start()..m.end()));
        }
    }

    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secrets_in_clean_data() {
        let data = b"This is a clean message with no secrets.";
        let results = detect_secrets(data);
        assert!(results.is_empty());
    }

    #[test]
    fn detect_openai_key() {
        let data = b"my openai key: sk-abcdefghijklmnopqrstuvwxyz1234";
        let results = detect_secrets(data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_type, PatternType::OpenAiKey);
        assert!(results[0].confidence > 0.9);
    }

    #[test]
    fn detect_aws_key() {
        let data = b"aws_key_id = AKIAIOSFODNN7EXAMPLE";
        let results = detect_secrets(data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_type, PatternType::AwsKey);
    }

    #[test]
    fn detect_gcp_key() {
        let data = b"gcp key: AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q";
        let results = detect_secrets(data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_type, PatternType::GcpKey);
    }

    #[test]
    fn detect_jwt() {
        let data = b"Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
        let results = detect_secrets(data);
        assert!(!results.is_empty());
        assert!(results.iter().any(|m| m.pattern_type == PatternType::JwtToken));
    }

    #[test]
    fn detect_private_key() {
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let results = detect_secrets(data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_type, PatternType::PrivateKey);
    }

    #[test]
    fn detect_password() {
        let data = r#"password = "supersecret123""#;
        let results = detect_secrets(data.as_bytes());
        assert!(!results.is_empty());
        assert!(results.iter().any(|m| m.pattern_type == PatternType::Password));
    }

    #[test]
    fn detect_multiple_secrets() {
        let data = b"config:\n  api_key=sk-abcdefghijklmnopqrstuvwxyz1234\n  aws_id=AKIAIOSFODNN7EXAMPLE";
        let results = detect_secrets(data);
        assert!(results.len() >= 2);
    }

    #[test]
    fn location_is_accurate() {
        let prefix = b"prefix ";
        let key = b"sk-abcdefghijklmnopqrstuvwxyz1234";
        let mut data = prefix.to_vec();
        data.extend_from_slice(key);
        let results = detect_secrets(&data);
        assert_eq!(results[0].location, prefix.len());
    }
}
