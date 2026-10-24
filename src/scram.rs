//! SCRAM-SHA-256 client (RFC 5802, RFC 7677) for authenticating to the server, without channel
//! binding. It works from either the plaintext password or the `ClientKey`/`ServerKey` derived
//! from it for one server verifier, so lokaj can open new server connections without keeping
//! the plaintext.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MECHANISM: &str = "SCRAM-SHA-256";
/// Upper bound on the PBKDF2 iteration count a server may demand.
const MAX_ITERATIONS: u32 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScramError {
    #[error("malformed SCRAM server message")]
    Malformed,
    #[error("SCRAM server nonce does not extend the client nonce")]
    NonceMismatch,
    #[error("SCRAM iteration count {0} is out of range")]
    Iterations(u32),
    /// The server's salt or iteration count no longer match the cached keys: the password
    /// changed on the server.
    #[error("the server's SCRAM verifier changed")]
    VerifierChanged,
    #[error("the server rejected the SCRAM proof: {0}")]
    ServerError(String),
    #[error("the server signature does not match")]
    BadServerSignature,
}

/// Keys derived from a password for one server-side SCRAM verifier (salt and iteration count).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScramKeys {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub client_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl std::fmt::Debug for ScramKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramKeys")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

impl ScramKeys {
    pub fn derive(password: &str, salt: &[u8], iterations: u32) -> Self {
        // PostgreSQL applies SASLprep and falls back to the raw bytes when it fails.
        let prepared = stringprep::saslprep(password);
        let normalized: &str = match &prepared {
            Ok(normalized) => normalized,
            Err(_) => password,
        };
        let mut salted =
            pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(normalized.as_bytes(), salt, iterations);
        let keys = Self {
            salt: salt.to_vec(),
            iterations,
            client_key: hmac(&salted, b"Client Key"),
            server_key: hmac(&salted, b"Server Key"),
        };
        salted.zeroize();
        if let Ok(std::borrow::Cow::Owned(mut normalized)) = prepared {
            normalized.zeroize();
        }
        keys
    }
}

#[derive(Clone, Copy)]
pub enum Secret<'a> {
    Password(&'a str),
    Keys(&'a ScramKeys),
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// A server-first-message that passed [`ScramClient::read_server_first`].
pub struct ServerFirst {
    message: String,
    nonce: String,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

pub struct ScramClient {
    client_nonce: String,
    client_first_bare: String,
    server_signature: Option<[u8; 32]>,
}

impl ScramClient {
    /// Starts an exchange and returns the client-first-message.
    pub fn start() -> (Self, Vec<u8>) {
        let mut raw = [0u8; 18];
        rand::rng().fill_bytes(&mut raw);
        let client_nonce = BASE64.encode(raw);
        // The server takes the user name from the startup packet, so it is left empty here.
        let client_first_bare = format!("n=,r={client_nonce}");
        let message = format!("n,,{client_first_bare}").into_bytes();
        (
            Self {
                client_nonce,
                client_first_bare,
                server_signature: None,
            },
            message,
        )
    }

    /// Parses and checks the server-first-message. The caller then derives the keys for its
    /// salt and iteration count, or brings cached ones, and calls [`ScramClient::respond`].
    pub fn read_server_first(&self, server_first: &[u8]) -> Result<ServerFirst, ScramError> {
        let message = std::str::from_utf8(server_first).map_err(|_| ScramError::Malformed)?;
        let mut parts = message.split(',');
        let nonce = parts
            .next()
            .and_then(|p| p.strip_prefix("r="))
            .ok_or(ScramError::Malformed)?;
        let salt = parts
            .next()
            .and_then(|p| p.strip_prefix("s="))
            .ok_or(ScramError::Malformed)?;
        let iterations = parts
            .next()
            .and_then(|p| p.strip_prefix("i="))
            .ok_or(ScramError::Malformed)?;
        if parts.next().is_some() {
            return Err(ScramError::Malformed);
        }
        if nonce.len() <= self.client_nonce.len() || !nonce.starts_with(&self.client_nonce) {
            return Err(ScramError::NonceMismatch);
        }
        if !nonce
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
        {
            return Err(ScramError::Malformed);
        }
        let salt = BASE64.decode(salt).map_err(|_| ScramError::Malformed)?;
        let iterations: u32 = iterations.parse().map_err(|_| ScramError::Malformed)?;
        if salt.is_empty() {
            return Err(ScramError::Malformed);
        }
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(ScramError::Iterations(iterations));
        }
        Ok(ServerFirst {
            message: message.to_owned(),
            nonce: nonce.to_owned(),
            salt,
            iterations,
        })
    }

    /// Returns the client-final-message, proving knowledge of `keys`.
    pub fn respond(
        &mut self,
        first: &ServerFirst,
        keys: &ScramKeys,
    ) -> Result<Vec<u8>, ScramError> {
        if keys.salt != first.salt || keys.iterations != first.iterations {
            return Err(ScramError::VerifierChanged);
        }
        let ServerFirst {
            message: server_first,
            nonce,
            ..
        } = first;

        // c=biws is base64("n,,"): no channel binding.
        let client_final_without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!(
            "{},{server_first},{client_final_without_proof}",
            self.client_first_bare
        );
        let stored_key: [u8; 32] = Sha256::digest(keys.client_key).into();
        let client_signature = hmac(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; 32];
        for (p, (k, s)) in proof
            .iter_mut()
            .zip(keys.client_key.iter().zip(client_signature.iter()))
        {
            *p = k ^ s;
        }
        self.server_signature = Some(hmac(&keys.server_key, auth_message.as_bytes()));
        Ok(format!("{client_final_without_proof},p={}", BASE64.encode(proof)).into_bytes())
    }

    /// Verifies the server-final-message, which proves the server knows the verifier.
    pub fn finish(&self, server_final: &[u8]) -> Result<(), ScramError> {
        let server_final = std::str::from_utf8(server_final).map_err(|_| ScramError::Malformed)?;
        if let Some(error) = server_final.strip_prefix("e=") {
            return Err(ScramError::ServerError(error.to_owned()));
        }
        let signature = server_final
            .strip_prefix("v=")
            .ok_or(ScramError::Malformed)?;
        let signature = BASE64
            .decode(signature)
            .map_err(|_| ScramError::Malformed)?;
        let expected = self.server_signature.ok_or(ScramError::Malformed)?;
        if bool::from(expected.ct_eq(signature.as_slice())) {
            Ok(())
        } else {
            Err(ScramError::BadServerSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal SCRAM server holding a verifier, as PostgreSQL stores it.
    struct Server {
        salt: Vec<u8>,
        iterations: u32,
        stored_key: [u8; 32],
        server_key: [u8; 32],
    }

    impl Server {
        fn new(password: &str) -> Self {
            let keys = ScramKeys::derive(password, b"0123456789abcdef", 4096);
            Self {
                salt: keys.salt.clone(),
                iterations: keys.iterations,
                stored_key: Sha256::digest(keys.client_key).into(),
                server_key: keys.server_key,
            }
        }

        fn exchange(&self, secret: Secret<'_>) -> Result<ScramKeys, ScramError> {
            let (mut client, first) = ScramClient::start();
            let first = String::from_utf8(first).unwrap();
            let bare = first.strip_prefix("n,,").unwrap();
            let client_nonce = bare.strip_prefix("n=,r=").unwrap();
            let server_first = format!(
                "r={client_nonce}servernonce,s={},i={}",
                BASE64.encode(&self.salt),
                self.iterations
            );
            let first = client.read_server_first(server_first.as_bytes())?;
            let keys = match secret {
                Secret::Password(password) => {
                    ScramKeys::derive(password, &first.salt, first.iterations)
                }
                Secret::Keys(keys) => keys.clone(),
            };
            let final_message = client.respond(&first, &keys)?;
            let final_message = String::from_utf8(final_message).unwrap();
            let (without_proof, proof) = final_message.rsplit_once(",p=").unwrap();
            let auth_message = format!("{bare},{server_first},{without_proof}");
            let signature = hmac(&self.stored_key, auth_message.as_bytes());
            let proof = BASE64.decode(proof).unwrap();
            let client_key: Vec<u8> = proof
                .iter()
                .zip(signature.iter())
                .map(|(p, s)| p ^ s)
                .collect();
            let computed: [u8; 32] = Sha256::digest(&client_key).into();
            if computed != self.stored_key {
                return Err(ScramError::ServerError("invalid-proof".into()));
            }
            let server_signature = hmac(&self.server_key, auth_message.as_bytes());
            client.finish(format!("v={}", BASE64.encode(server_signature)).as_bytes())?;
            Ok(keys)
        }
    }

    #[test]
    fn authenticates_with_password_and_then_with_cached_keys() {
        let server = Server::new("secret");
        let keys = server.exchange(Secret::Password("secret")).unwrap();
        server.exchange(Secret::Keys(&keys)).unwrap();
    }

    #[test]
    fn wrong_password_fails() {
        let server = Server::new("secret");
        assert!(server.exchange(Secret::Password("other")).is_err());
    }

    #[test]
    fn changed_verifier_is_detected_before_sending_a_proof() {
        let keys = Server::new("old")
            .exchange(Secret::Password("old"))
            .unwrap();
        let mut server = Server::new("new");
        server.salt = b"another salt 123".to_vec();
        assert_eq!(
            server.exchange(Secret::Keys(&keys)).unwrap_err(),
            ScramError::VerifierChanged
        );
    }

    #[test]
    fn rejects_forged_server_signature() {
        let (mut client, first) = ScramClient::start();
        let nonce = String::from_utf8(first)
            .unwrap()
            .strip_prefix("n,,n=,r=")
            .unwrap()
            .to_owned();
        let server_first = format!("r={nonce}x,s={},i=4096", BASE64.encode(b"salt"));
        let first = client.read_server_first(server_first.as_bytes()).unwrap();
        let keys = ScramKeys::derive("p", &first.salt, first.iterations);
        client.respond(&first, &keys).unwrap();
        assert_eq!(
            client.finish(format!("v={}", BASE64.encode([0u8; 32])).as_bytes()),
            Err(ScramError::BadServerSignature)
        );
    }

    #[test]
    fn rejects_nonce_not_extending_client_nonce() {
        let (client, _) = ScramClient::start();
        let server_first = format!("r=foreign,s={},i=4096", BASE64.encode(b"salt"));
        assert_eq!(
            client
                .read_server_first(server_first.as_bytes())
                .err()
                .unwrap(),
            ScramError::NonceMismatch
        );
    }

    /// RFC 7677 section 3 test vector.
    #[test]
    fn rfc7677_vector() {
        let salt = BASE64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let keys = ScramKeys::derive("pencil", &salt, 4096);
        let mut client = ScramClient {
            client_nonce: "rOprNGfwEbeRWgbNEkqO".into(),
            client_first_bare: "n=user,r=rOprNGfwEbeRWgbNEkqO".into(),
            server_signature: None,
        };
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let first = client.read_server_first(server_first.as_bytes()).unwrap();
        let message = client.respond(&first, &keys).unwrap();
        assert_eq!(
            String::from_utf8(message).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        client
            .finish(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
    }
}
