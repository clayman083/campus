use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserID(pub Uuid);

#[derive(Debug, PartialEq, Eq)]
pub enum TokenType {
    User,
    Device,
    Service,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub nbf: usize,
    pub iat: usize,
    pub exp: usize,
}

impl TokenClaims {
    pub(crate) fn from_token(token: &Token) -> Self {
        let now = Utc::now().timestamp() as usize;

        TokenClaims {
            iss: token.issuer.to_string(),
            aud: token.issued_for.to_string(),
            sub: token.user_id.0.to_string(),
            nbf: now,
            iat: now,
            exp: token.expired_at.timestamp() as usize,
        }
    }
}

/// Authentication token implementation
#[derive(Debug, PartialEq, Eq)]
pub struct Token {
    /// The issuer service name
    pub issuer: String,
    /// Service, that can use this token
    pub issued_for: String,
    /// Token valid until date
    pub expired_at: DateTime<Utc>,
    /// Token type
    pub token_type: TokenType,
    /// User ID
    pub user_id: UserID,
}

impl Token {
    pub fn for_user(
        user_id: UserID,
        issuer: String,
        issued_for: String,
        lifetime: chrono::Duration,
    ) -> Self {
        Token {
            issuer,
            issued_for,
            expired_at: Utc::now() + lifetime,
            token_type: TokenType::User,
            user_id,
        }
    }

    pub fn for_device(
        user_id: UserID,
        issuer: String,
        issued_for: String,
        lifetime: chrono::Duration,
    ) -> Self {
        Token {
            issuer,
            issued_for,
            expired_at: Utc::now() + lifetime,
            token_type: TokenType::Device,
            user_id,
        }
    }

    pub fn for_service(
        user_id: UserID,
        issuer: String,
        issued_for: String,
        lifetime: chrono::Duration,
    ) -> Self {
        Token {
            issuer,
            issued_for,
            expired_at: Utc::now() + lifetime,
            token_type: TokenType::Service,
            user_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_for_user() {
        let user_id = UserID(Uuid::new_v4());

        let token = Token::for_user(
            user_id.clone(),
            "issuer".to_string(),
            "issued_for".to_string(),
            Duration::seconds(3600),
        );
        assert_eq!(token.token_type, TokenType::User);
        assert_eq!(token.user_id, user_id);
    }

    #[test]
    fn test_for_device() {
        let user_id = UserID(Uuid::new_v4());

        let token = Token::for_device(
            user_id.clone(),
            "issuer".to_string(),
            "issued_for".to_string(),
            Duration::seconds(3600),
        );
        assert_eq!(token.token_type, TokenType::Device);
        assert_eq!(token.user_id, user_id);
    }

    #[test]
    fn test_for_service() {
        let user_id = UserID(Uuid::new_v4());

        let token = Token::for_service(
            user_id.clone(),
            "issuer".to_string(),
            "issued_for".to_string(),
            Duration::seconds(3600),
        );
        assert_eq!(token.token_type, TokenType::Service);
        assert_eq!(token.user_id, user_id);
    }
}
