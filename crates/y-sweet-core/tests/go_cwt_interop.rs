//! Interop check: tokens minted by the Go control plane's Ed25519 COSE_Sign1
//! signer must verify through the production Authenticator path.

use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::Authenticator;
use y_sweet_core::config::{AuthKeyConfig, TokenType};

const PUB_KEY: &str = "S7TFl0UkOJ6n6Egs6xdcLjM7qksjKuC17+oEJvZm6U0=";
const FULL_TOK: &str = "2D3ShFKiAScETXRlc3Rfa2V5XzIwMjWgWF6mOgABOUhtZG9jOmRvYzEyMzpydwF4GHRlc3QtcmVsYXktY29udHJvbC1wbGFuZQJldXNlcjEDeBlodHRwczovL3JlbGF5LmV4YW1wbGUuY29tBBpqTY4TBhpqTYADWEAzgglJdOKPyUmTJ4MyfPdQWu9zjGPxe0bTQ5mJA-iI0bs8qdI5ZYISY2mr4WIbh9b_t5fcrq_W11A5qACKSnEO";
const RO_TOK: &str = "2D3ShFKiAScETXRlc3Rfa2V5XzIwMjWgWF2mAmV1c2VyMQN4GWh0dHBzOi8vcmVsYXkuZXhhbXBsZS5jb20EGmpNjhMGGmpNgAM6AAE5SGxkb2M6ZG9jMTIzOnIBeBh0ZXN0LXJlbGF5LWNvbnRyb2wtcGxhbmVYQPzB1dipr7Ti1mISxwi686WTia7DMgBtNsJYmfeguJAzRbob0ucq4XgPIj7w7Tit2TlGAGTkQfPyXebd6NOC3Ak";
const FILE_TOK: &str = "2D3ShFKiAScETXRlc3Rfa2V5XzIwMjWgWGemA3gZaHR0cHM6Ly9yZWxheS5leGFtcGxlLmNvbQQaak2OEwYaak2AAzoAATlIdmZpbGU6aGFzaGFiYzpkb2MxMjM6cncBeBh0ZXN0LXJlbGF5LWNvbnRyb2wtcGxhbmUCZXVzZXIxWEDa_QtIjBBrag4UzNm5FCsv_qnPxPSk8uuu0yl_mthR3Nkp2ThiXVhJ-ZJYkZhOqkHI7tO4nh8Qgr5KUMuUFp8D";
const BAD_ISSUER_TOK: &str = "2D3ShFKiAScETXRlc3Rfa2V5XzIwMjWgWDmmAWtldmlsLWlzc3VlcgJldXNlcjEDY2F1ZAQaak2OEwYaak2AAzoAATlIbWRvYzpkb2MxMjM6cndYQGX9xIx47GBePSbeXDxHTgpWzd0_2IaPJGkMamco4YuT6uI9q5kDsM-IRLo1Zdduw6cPxofgQUoSE_ypNK76nAI";
// Within the tokens' 1h validity window (iat 1783464089).
const NOW_MS: u64 = 1783464089000;

fn authenticator() -> Authenticator {
    let config = AuthKeyConfig {
        key_id: Some("test_key_2025".to_string()),
        private_key: None,
        public_key: Some(PUB_KEY.to_string()),
        allowed_token_types: vec![TokenType::Document, TokenType::File],
    };
    let mut auth = Authenticator::from_multi_key_config(&[config]).expect("build authenticator");
    auth.set_valid_issuers(vec!["test-relay-control-plane".to_string()]);
    // Production sets this from server.url; CWT verification refuses to run without it.
    auth.set_expected_audience(Some("https://relay.example.com".to_string()));
    auth
}

#[test]
fn full_doc_token_verifies() {
    let auth = authenticator();
    assert_eq!(auth.verify_doc_token(FULL_TOK, "doc123", NOW_MS).unwrap(), Authorization::Full);
}

#[test]
fn read_only_doc_token_verifies() {
    let auth = authenticator();
    assert_eq!(auth.verify_doc_token(RO_TOK, "doc123", NOW_MS).unwrap(), Authorization::ReadOnly);
}

#[test]
fn doc_token_rejected_for_other_doc() {
    let auth = authenticator();
    assert!(auth.verify_doc_token(FULL_TOK, "otherdoc", NOW_MS).is_err());
}

#[test]
fn file_token_verifies() {
    let auth = authenticator();
    assert_eq!(auth.verify_file_token(FILE_TOK, "hashabc", NOW_MS).unwrap(), Authorization::Full);
}

#[test]
fn file_token_rejected_for_wrong_hash() {
    let auth = authenticator();
    assert!(auth.verify_file_token(FILE_TOK, "wronghash", NOW_MS).is_err());
}

#[test]
fn bad_issuer_rejected() {
    let auth = authenticator();
    assert!(auth.verify_doc_token(BAD_ISSUER_TOK, "doc123", NOW_MS).is_err());
}

#[test]
fn tampered_token_rejected() {
    let auth = authenticator();
    let mut tampered = FULL_TOK.to_string();
    let n = tampered.len() - 3;
    let c = tampered.remove(n);
    tampered.insert(n, if c == 'A' { 'B' } else { 'A' });
    assert!(auth.verify_doc_token(&tampered, "doc123", NOW_MS).is_err());
}

#[test]
fn expired_token_rejected() {
    let auth = authenticator();
    // Two hours past iat, tokens carry 1h expiry.
    assert!(auth.verify_doc_token(FULL_TOK, "doc123", NOW_MS + 7_200_000).is_err());
}
