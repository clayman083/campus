use crate::tokens;
use chrono::DateTime;
use std::collections::HashMap;
use uuid::Uuid;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

pub struct TokenDecoder {
    keys: HashMap<String, DecodingKey>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    InvalidToken,
    WrongKey,
    MissingKey,
    MissingClaim(String),
    InvalidJson(String),
    TokenExpired,
    UnhandledError,
    UnknownKey,
}

impl TokenDecoder {
    pub fn new() -> Self {
        TokenDecoder {
            keys: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, key_id: String, key: DecodingKey) {
        self.keys.insert(key_id, key);
    }

    pub fn decode(&self, token: &str, issued_for: &str) -> Result<tokens::Token, TokenError> {
        let header = match decode_header(token) {
            Ok(header) => header,
            Err(_) => return Err(TokenError::InvalidToken),
        };

        let key = match self.keys.get(&header.kid.unwrap()) {
            Some(key) => key,
            None => return Err(TokenError::UnknownKey),
        };

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 5;
        validation.set_audience(&[issued_for.to_string()]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "ext", "iat", "nbf"]);

        let decoded = match decode::<tokens::TokenClaims>(&token, &key, &validation) {
            Ok(token) => token,
            Err(err) => match *err.kind() {
                ErrorKind::ExpiredSignature => return Err(TokenError::TokenExpired),
                ErrorKind::InvalidToken => return Err(TokenError::InvalidToken),
                ErrorKind::InvalidSignature => return Err(TokenError::WrongKey),
                ErrorKind::MissingRequiredClaim(ref claim) => {
                    return Err(TokenError::MissingClaim(claim.clone()));
                }
                ErrorKind::Json(ref error) => {
                    return Err(TokenError::InvalidJson(error.to_string()));
                }
                _ => return Err(TokenError::UnhandledError),
            },
        };

        Ok(tokens::Token {
            issuer: decoded.claims.iss,
            issued_for: decoded.claims.aud,
            user_id: tokens::UserID(Uuid::parse_str(&decoded.claims.sub).unwrap()),
            expired_at: DateTime::from_timestamp(decoded.claims.exp as i64, 0).unwrap(),
            token_type: tokens::TokenType::User,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens;

    use chrono::{DateTime, Duration, Timelike, Utc};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use rstest::{fixture, rstest};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[fixture]
    #[once]
    fn keypair() -> (EncodingKey, DecodingKey, String) {
        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let encoding_key = EncodingKey::from_ed_der(doc.as_ref());

        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

        (encoding_key, decoding_key, "passport.0".to_string())
    }

    #[fixture]
    #[once]
    fn user_id() -> tokens::UserID {
        tokens::UserID(Uuid::new_v4())
    }

    #[fixture]
    #[once]
    fn issuer() -> String {
        "passport".to_string()
    }

    #[fixture]
    #[once]
    fn issued_for() -> String {
        "wallet".to_string()
    }

    #[fixture]
    #[once]
    fn created_at() -> DateTime<Utc> {
        Utc::now().with_nanosecond(0).unwrap()
    }

    #[fixture]
    #[once]
    fn expired_at(created_at: &DateTime<Utc>) -> DateTime<Utc> {
        *created_at + Duration::hours(1)
    }

    #[fixture]
    fn normal_token(
        keypair: &(EncodingKey, DecodingKey, String),
        issuer: &String,
        issued_for: &String,
        user_id: &tokens::UserID,
        created_at: &DateTime<Utc>,
        expired_at: &DateTime<Utc>,
    ) -> String {
        let claims = tokens::TokenClaims {
            iss: issuer.to_string(),
            aud: issued_for.to_string(),
            sub: user_id.0.to_string(),
            nbf: created_at.timestamp() as usize,
            iat: created_at.timestamp() as usize,
            exp: expired_at.timestamp() as usize,
        };
        let header = Header {
            kid: Some(keypair.2.clone()),
            alg: Algorithm::EdDSA,
            ..Default::default()
        };

        jsonwebtoken::encode(&header, &claims, &keypair.0).unwrap()
    }

    #[fixture]
    fn token_wo_issuer(
        keypair: &(EncodingKey, DecodingKey, String),
        issued_for: &String,
        user_id: &tokens::UserID,
        created_at: &DateTime<Utc>,
        expired_at: &DateTime<Utc>,
    ) -> String {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        struct Claims {
            aud: String,
            sub: String,
            nbf: usize,
            iat: usize,
            exp: usize,
        }

        let claims = Claims {
            aud: issued_for.to_string(),
            sub: user_id.0.to_string(),
            nbf: created_at.timestamp() as usize,
            iat: created_at.timestamp() as usize,
            exp: expired_at.timestamp() as usize,
        };
        let header = Header {
            kid: Some(keypair.2.clone()),
            alg: Algorithm::EdDSA,
            ..Default::default()
        };

        jsonwebtoken::encode(&header, &claims, &keypair.0).unwrap()
    }

    #[fixture]
    fn token_wo_audience(
        keypair: &(EncodingKey, DecodingKey, String),
        issuer: &String,
        user_id: &tokens::UserID,
        created_at: &DateTime<Utc>,
        expired_at: &DateTime<Utc>,
    ) -> String {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        struct Claims {
            iss: String,
            sub: String,
            nbf: usize,
            iat: usize,
            exp: usize,
        }

        let claims = Claims {
            iss: issuer.to_string(),
            sub: user_id.0.to_string(),
            nbf: created_at.timestamp() as usize,
            iat: created_at.timestamp() as usize,
            exp: expired_at.timestamp() as usize,
        };
        let header = Header {
            kid: Some(keypair.2.clone()),
            alg: Algorithm::EdDSA,
            ..Default::default()
        };

        jsonwebtoken::encode(&header, &claims, &keypair.0).unwrap()
    }

    #[fixture]
    fn token_wo_user(
        keypair: &(EncodingKey, DecodingKey, String),
        issuer: &String,
        issued_for: &String,
        created_at: &DateTime<Utc>,
        expired_at: &DateTime<Utc>,
    ) -> String {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        struct Claims {
            iss: String,
            aud: String,
            nbf: usize,
            iat: usize,
            exp: usize,
        }

        let claims = Claims {
            iss: issuer.to_string(),
            aud: issued_for.to_string(),
            nbf: created_at.timestamp() as usize,
            iat: created_at.timestamp() as usize,
            exp: expired_at.timestamp() as usize,
        };
        let header = Header {
            kid: Some(keypair.2.clone()),
            alg: Algorithm::EdDSA,
            ..Default::default()
        };

        jsonwebtoken::encode(&header, &claims, &keypair.0).unwrap()
    }

    #[fixture]
    fn expired_token(
        keypair: &(EncodingKey, DecodingKey, String),
        issuer: &String,
        issued_for: &String,
        user_id: &tokens::UserID,
        created_at: &DateTime<Utc>,
    ) -> String {
        let claims = tokens::TokenClaims {
            iss: issuer.to_string(),
            aud: issued_for.to_string(),
            sub: user_id.0.to_string(),
            nbf: created_at.timestamp() as usize,
            iat: created_at.timestamp() as usize,
            exp: (*created_at + Duration::hours(-1)).timestamp() as usize,
        };
        let header = Header {
            kid: Some(keypair.2.clone()),
            alg: Algorithm::EdDSA,
            ..Default::default()
        };

        jsonwebtoken::encode(&header, &claims, &keypair.0).unwrap()
    }

    #[rstest]
    fn test_decode_success(
        keypair: &(EncodingKey, DecodingKey, String),
        issuer: &String,
        issued_for: &String,
        user_id: &tokens::UserID,
        expired_at: &DateTime<Utc>,
        normal_token: String,
    ) {
        let mut decoder = TokenDecoder::new();
        decoder.add_key(keypair.2.clone(), keypair.1.clone());

        let result = match decoder.decode(&normal_token, issued_for) {
            Ok(token) => token,
            Err(err) => panic!("Failed to decode token: {:?}", err),
        };

        assert_eq!(
            result,
            tokens::Token {
                issuer: issuer.to_string(),
                issued_for: issued_for.to_string(),
                user_id: user_id.clone(),
                expired_at: expired_at.clone(),
                token_type: tokens::TokenType::User
            }
        );
    }

    #[rstest]
    fn test_decode_failed_wo_key(issued_for: &String, normal_token: String) {
        let decoder = TokenDecoder::new();

        let result = decoder.decode(&normal_token, issued_for);

        assert_eq!(result, Err(TokenError::UnknownKey));
    }

    #[rstest]
    fn test_decode_failed_w_wrong_key(issued_for: &String, normal_token: String) {
        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();

        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

        let mut decoder = TokenDecoder::new();
        decoder.add_key(String::from("passport.0"), decoding_key);

        let result = decoder.decode(&normal_token, issued_for);

        assert_eq!(result, Err(TokenError::WrongKey));
    }

    #[rstest]
    fn test_decode_failed_w_expired_token(
        keypair: &(EncodingKey, DecodingKey, String),
        issued_for: &String,
        expired_token: String,
    ) {
        let mut decoder = TokenDecoder::new();
        decoder.add_key(keypair.2.clone(), keypair.1.clone());

        let result = decoder.decode(&expired_token, issued_for);

        assert_eq!(result, Err(TokenError::TokenExpired));
    }

    #[rstest]
    fn test_decode_failed_w_empty_token(
        keypair: &(EncodingKey, DecodingKey, String),
        issued_for: &String,
    ) {
        let token = "".to_string();

        let mut decoder = TokenDecoder::new();
        decoder.add_key(keypair.2.clone(), keypair.1.clone());

        let result = decoder.decode(&token, &issued_for);

        assert_eq!(result, Err(TokenError::InvalidToken));
    }

    #[rstest]
    fn test_decode_failed_wo_iss(
        keypair: &(EncodingKey, DecodingKey, String),
        issued_for: &String,
        token_wo_issuer: String,
    ) {
        let mut decoder = TokenDecoder::new();
        decoder.add_key(keypair.2.clone(), keypair.1.clone());

        match decoder.decode(&token_wo_issuer, &issued_for) {
            Ok(_) => panic!("Test should fail"),
            Err(err) => match err {
                TokenError::InvalidJson(msg) => {
                    assert_eq!(msg.contains("missing field `iss`"), true)
                }
                _ => panic!("Unexpected error"),
            },
        }
    }

    #[rstest]
    fn test_decode_failed_wo_aud(
        keypair: &(EncodingKey, DecodingKey, String),
        issued_for: &String,
        token_wo_audience: String,
    ) {
        let mut decoder = TokenDecoder::new();
        decoder.add_key(keypair.2.clone(), keypair.1.clone());

        match decoder.decode(&token_wo_audience, &issued_for) {
            Ok(_) => panic!("Test should fail"),
            Err(err) => match err {
                TokenError::InvalidJson(msg) => {
                    assert_eq!(msg.contains("missing field `aud`"), true)
                }
                _ => panic!("Unexpected error"),
            },
        }
    }
    #[rstest]
    fn test_decode_failed_wo_sub(
        keypair: &(EncodingKey, DecodingKey, String),
        issued_for: &String,
        token_wo_user: String,
    ) {
        let mut decoder = TokenDecoder::new();
        decoder.add_key(keypair.2.clone(), keypair.1.clone());

        match decoder.decode(&token_wo_user, &issued_for) {
            Ok(_) => panic!("Test should fail"),
            Err(err) => match err {
                TokenError::InvalidJson(msg) => {
                    assert_eq!(msg.contains("missing field `sub`"), true)
                }
                _ => panic!("Unexpected error"),
            },
        }
    }
}
