use crate::tokens;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

pub struct TokenEncoder {
    key_id: String,
    key: EncodingKey,
}

impl TokenEncoder {
    pub fn new(key: EncodingKey, key_id: String) -> Self {
        TokenEncoder { key, key_id }
    }

    pub fn encode(&self, token: &tokens::Token) -> String {
        let claims = tokens::TokenClaims::from_token(token);

        let header = Header {
            kid: Some(self.key_id.to_string()),
            alg: Algorithm::EdDSA,
            ..Default::default()
        };

        let token = match encode(&header, &claims, &self.key) {
            Ok(token) => token,
            Err(err) => panic!("Failed to encode token: {}", err),
        };

        token
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::TokenClaims;

    use chrono::Duration;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation, decode};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use rstest::*;
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

    #[rstest]
    fn test_encode_success(
        keypair: &(EncodingKey, DecodingKey, String),
        issuer: &String,
        issued_for: &String,
        user_id: &tokens::UserID,
    ) {
        let token = tokens::Token::for_user(
            user_id.clone(),
            issuer.to_string(),
            issued_for.to_string(),
            Duration::seconds(180),
        );

        let encoder = TokenEncoder::new(keypair.0.clone(), keypair.2.clone());
        let result = encoder.encode(&token);

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.sub = Some(user_id.0.to_string());
        validation.set_audience(&[issued_for.to_string()]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "ext", "iat", "nbf"]);

        let decoded = match decode::<TokenClaims>(&result, &keypair.1.clone(), &validation) {
            Ok(token) => token,
            Err(err) => panic!("Failed to decode token: {}", err),
        };

        assert_eq!(decoded.claims.sub, user_id.0.to_string());
        assert_eq!(decoded.claims.aud, "wallet".to_string());
        assert_eq!(decoded.claims.iss, "passport".to_string());
    }
}
