#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
use std::ptr;

use bitmask_enum::bitmask;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
mod hex_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use std::vec::Vec; // Ensure Vec is in scope

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(Error::custom)
    }
}

#[cfg(feature = "serde")]
mod algorithm_serde {
    use super::Algorithm;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(algorithm: &Algorithm, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as the string name of the variant
        let s = match *algorithm {
            Algorithm::SECP256K1_SCHNORR => "SECP256K1_SCHNORR",
            Algorithm::FN_DSA_512 => "FN_DSA_512",
            Algorithm::ML_DSA_44 => "ML_DSA_44",
            Algorithm::SLH_DSA_128S => "SLH_DSA_128S",
            _ => return Err(serde::ser::Error::custom("Unknown algorithm variant")),
        };
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Algorithm, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "SECP256K1_SCHNORR" => Ok(Algorithm::SECP256K1_SCHNORR),
            "FN_DSA_512" => Ok(Algorithm::FN_DSA_512),
            "ML_DSA_44" => Ok(Algorithm::ML_DSA_44),
            "SLH_DSA_128S" => Ok(Algorithm::SLH_DSA_128S),
            _ => Err(Error::unknown_variant(
                &s,
                &[
                    "SECP256K1_SCHNORR",
                    "FN_DSA_512",
                    "ML_DSA_44",
                    "SLH_DSA_128S",
                ],
            )),
        }
    }
}

// Include the auto-generated bindings using our wrapper
// Make it pub(crate) so doctests can access these symbols
pub(crate) mod bindings_include;
// Use a glob import to get all the symbols consistently
use bindings_include::*;

/// Error type for PQC operations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PqcError {
    /// Invalid arguments provided
    BadArgument,
    /// Invalid key provided
    BadKey,
    /// Invalid signature provided
    BadSignature,
    /// Algorithm not implemented
    NotImplemented,
    /// Other unexpected error
    Other(i32),
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PqcError::BadArgument => write!(f, "Invalid arguments provided"),
            PqcError::BadKey => write!(f, "Invalid key provided"),
            PqcError::BadSignature => write!(f, "Invalid signature provided"),
            PqcError::NotImplemented => write!(f, "Algorithm not implemented"),
            PqcError::Other(code) => write!(f, "Unexpected error code: {}", code),
        }
    }
}

impl Error for PqcError {}

impl From<bitcoin_pqc_error_t> for Result<(), PqcError> {
    fn from(error: bitcoin_pqc_error_t) -> Self {
        match error {
            bitcoin_pqc_error_t::BITCOIN_PQC_OK => Ok(()),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_ARG => Err(PqcError::BadArgument),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_KEY => Err(PqcError::BadKey),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_SIGNATURE => Err(PqcError::BadSignature),
            bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => Err(PqcError::NotImplemented),
            _ => Err(PqcError::Other(error.0)),
        }
    }
}

/// PQC Algorithm type
#[bitmask(u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Algorithm {
    /// BIP-340 Schnorr + X-Only - Elliptic Curve Digital Signature Algorithm
    SECP256K1_SCHNORR,
    /// FN-DSA-512 (FALCON) - Fast Fourier lattice-based signature scheme
    FN_DSA_512,
    /// ML-DSA-44 (CRYSTALS-Dilithium) - Lattice-based signature scheme
    ML_DSA_44,
    /// SLH-DSA-Shake-128s (SPHINCS+) - Hash-based signature scheme
    SLH_DSA_128S,
}

impl From<Algorithm> for bitcoin_pqc_algorithm_t {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::SECP256K1_SCHNORR => bitcoin_pqc_algorithm_t::BITCOIN_PQC_SECP256K1_SCHNORR,
            Algorithm::FN_DSA_512 => bitcoin_pqc_algorithm_t::BITCOIN_PQC_FN_DSA_512,
            Algorithm::ML_DSA_44 => bitcoin_pqc_algorithm_t::BITCOIN_PQC_ML_DSA_44,
            Algorithm::SLH_DSA_128S => bitcoin_pqc_algorithm_t::BITCOIN_PQC_SLH_DSA_SHAKE_128S,
            _ => panic!("Invalid algorithm"),
        }
    }
}

/// Public key wrapper
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    /// The algorithm this key belongs to
    #[cfg_attr(feature = "serde", serde(with = "algorithm_serde"))]
    pub algorithm: Algorithm,
    /// The raw key bytes (serialized as hex)
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a PublicKey from a hex string.
    ///
    /// Validates the length of the decoded bytes against the expected public key size for the algorithm.
    pub fn from_str(algorithm: Algorithm, s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from((algorithm, bytes.as_slice()))
    }

    /// Creates a PublicKey directly from a byte slice.
    ///
    /// Note: This does not validate the length of the byte slice. Use `try_from` for validation.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Self {
        PublicKey {
            algorithm,
            bytes: bytes.to_vec(),
        }
    }
}

impl TryFrom<(Algorithm, &[u8])> for PublicKey {
    type Error = PqcError;

    /// Attempts to create a PublicKey from an algorithm and a byte slice.
    ///
    /// Validates that the byte slice length matches the expected public key size for the algorithm.
    fn try_from(value: (Algorithm, &[u8])) -> Result<Self, Self::Error> {
        let (algorithm, bytes) = value;
        if bytes.len() != public_key_size(algorithm) {
            Err(PqcError::BadKey)
        } else {
            Ok(PublicKey {
                algorithm,
                bytes: bytes.to_vec(),
            })
        }
    }
}

/// Secret key wrapper
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// The algorithm this key belongs to
    #[cfg_attr(feature = "serde", serde(with = "algorithm_serde"))]
    pub algorithm: Algorithm,
    /// The raw key bytes (serialized as hex)
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl SecretKey {
    /// Creates a SecretKey from a hex string.
    ///
    /// Validates the length of the decoded bytes against the expected secret key size for the algorithm.
    pub fn from_str(algorithm: Algorithm, s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from((algorithm, bytes.as_slice()))
    }

    /// Creates a SecretKey directly from a byte slice.
    ///
    /// Note: This does not validate the length of the byte slice. Use `try_from` for validation.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Self {
        SecretKey {
            algorithm,
            bytes: bytes.to_vec(),
        }
    }
}

impl TryFrom<(Algorithm, &[u8])> for SecretKey {
    type Error = PqcError;

    /// Attempts to create a SecretKey from an algorithm and a byte slice.
    ///
    /// Validates that the byte slice length matches the expected secret key size for the algorithm.
    fn try_from(value: (Algorithm, &[u8])) -> Result<Self, Self::Error> {
        let (algorithm, bytes) = value;
        if bytes.len() != secret_key_size(algorithm) {
            Err(PqcError::BadKey)
        } else {
            Ok(SecretKey {
                algorithm,
                bytes: bytes.to_vec(),
            })
        }
    }
}

/// Signature wrapper
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The algorithm this signature belongs to
    #[cfg_attr(feature = "serde", serde(with = "algorithm_serde"))]
    pub algorithm: Algorithm,
    /// The raw signature bytes (serialized as hex)
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Creates a Signature from a hex string.
    ///
    /// Validates the length of the decoded bytes against the expected signature size for the algorithm.
    pub fn from_str(algorithm: Algorithm, s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from((algorithm, bytes.as_slice()))
    }

    /// Creates a Signature directly from a byte slice.
    ///
    /// Note: This does not validate the length of the byte slice. Use `try_from` for validation.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Self {
        Signature {
            algorithm,
            bytes: bytes.to_vec(),
        }
    }
}

impl TryFrom<(Algorithm, &[u8])> for Signature {
    type Error = PqcError;

    /// Attempts to create a Signature from an algorithm and a byte slice.
    ///
    /// Validates that the byte slice length matches the expected signature size for the algorithm.
    fn try_from(value: (Algorithm, &[u8])) -> Result<Self, Self::Error> {
        let (algorithm, bytes) = value;
        if bytes.len() != signature_size(algorithm) {
            Err(PqcError::BadSignature)
        } else {
            Ok(Signature {
                algorithm,
                bytes: bytes.to_vec(),
            })
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zero out secret key memory on drop
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

/// Key pair containing both public and secret keys
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyPair {
    /// The public key
    pub public_key: PublicKey,
    /// The secret key
    pub secret_key: SecretKey,
}

/// Generate a key pair for the specified algorithm
///
/// # Arguments
///
/// * `algorithm` - The PQC algorithm to use
/// * `random_data` - Random bytes for key generation (must be at least 128 bytes)
///
/// # Returns
///
/// A new key pair on success, or an error
pub fn generate_keypair(algorithm: Algorithm, random_data: &[u8]) -> Result<KeyPair, PqcError> {
    if random_data.len() < 128 {
        return Err(PqcError::BadArgument);
    }

    unsafe {
        let mut keypair = bitcoin_pqc_keypair_t {
            algorithm: algorithm.into(),
            public_key: ptr::null_mut(),
            secret_key: ptr::null_mut(),
            public_key_size: 0,
            secret_key_size: 0,
        };

        let result = bitcoin_pqc_keygen(
            algorithm.into(),
            &mut keypair,
            random_data.as_ptr(),
            random_data.len(),
        );

        if result != bitcoin_pqc_error_t::BITCOIN_PQC_OK {
            return Err(match result {
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_ARG => PqcError::BadArgument,
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_KEY => PqcError::BadKey,
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => PqcError::NotImplemented,
                _ => PqcError::Other(result.0 as i32),
            });
        }

        // Extract and copy the keys
        let pk_slice =
            std::slice::from_raw_parts(keypair.public_key as *const u8, keypair.public_key_size);
        let sk_slice =
            std::slice::from_raw_parts(keypair.secret_key as *const u8, keypair.secret_key_size);

        let pk_bytes = pk_slice.to_vec();
        let sk_bytes = sk_slice.to_vec();

        // Free the C memory
        bitcoin_pqc_keypair_free(&mut keypair);

        Ok(KeyPair {
            public_key: PublicKey {
                algorithm,
                bytes: pk_bytes,
            },
            secret_key: SecretKey {
                algorithm,
                bytes: sk_bytes,
            },
        })
    }
}

/// Sign a message using the specified secret key
///
/// # Arguments
///
/// * `secret_key` - The secret key to sign with
/// * `message` - The message to sign
///
/// # Returns
///
/// A signature on success, or an error
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature, PqcError> {
    unsafe {
        let mut signature = bitcoin_pqc_signature_t {
            algorithm: secret_key.algorithm.into(),
            signature: ptr::null_mut(),
            signature_size: 0,
        };

        let result = bitcoin_pqc_sign(
            secret_key.algorithm.into(),
            secret_key.bytes.as_ptr(),
            secret_key.bytes.len(),
            message.as_ptr(),
            message.len(),
            &mut signature,
        );

        if result != bitcoin_pqc_error_t::BITCOIN_PQC_OK {
            return Err(match result {
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_ARG => PqcError::BadArgument,
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_KEY => PqcError::BadKey,
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_BAD_SIGNATURE => PqcError::BadSignature,
                bitcoin_pqc_error_t::BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => PqcError::NotImplemented,
                _ => PqcError::Other(result.0 as i32),
            });
        }

        // Extract and copy the signature
        let sig_slice =
            std::slice::from_raw_parts(signature.signature as *const u8, signature.signature_size);
        let sig_bytes = sig_slice.to_vec();

        // Free the C memory
        bitcoin_pqc_signature_free(&mut signature);

        Ok(Signature {
            algorithm: secret_key.algorithm,
            bytes: sig_bytes,
        })
    }
}

/// Verify a signature using the specified public key
///
/// # Arguments
///
/// * `public_key` - The public key to verify with
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// Ok(()) if the signature is valid, an error otherwise
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), PqcError> {
    if public_key.algorithm != signature.algorithm {
        return Err(PqcError::BadArgument);
    }

    unsafe {
        let result = bitcoin_pqc_verify(
            public_key.algorithm.into(),
            public_key.bytes.as_ptr(),
            public_key.bytes.len(),
            message.as_ptr(),
            message.len(),
            signature.bytes.as_ptr(),
            signature.bytes.len(),
        );

        result.into()
    }
}

/// Get the public key size for an algorithm
///
/// # Arguments
///
/// * `algorithm` - The algorithm to get the size for
///
/// # Returns
///
/// The size in bytes
pub fn public_key_size(algorithm: Algorithm) -> usize {
    unsafe { bitcoin_pqc_public_key_size(algorithm.into()) }
}

/// Get the secret key size for an algorithm
///
/// # Arguments
///
/// * `algorithm` - The algorithm to get the size for
///
/// # Returns
///
/// The size in bytes
pub fn secret_key_size(algorithm: Algorithm) -> usize {
    unsafe { bitcoin_pqc_secret_key_size(algorithm.into()) }
}

/// Get the signature size for an algorithm
///
/// # Arguments
///
/// * `algorithm` - The algorithm to get the size for
///
/// # Returns
///
/// The size in bytes
pub fn signature_size(algorithm: Algorithm) -> usize {
    unsafe { bitcoin_pqc_signature_size(algorithm.into()) }
}
