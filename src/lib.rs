#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::error::Error;
use std::fmt;
use std::ptr;

use bitmask_enum::bitmask;

// Include the auto-generated bindings using our wrapper
// Make it pub(crate) so doctests can access these symbols
pub(crate) mod bindings_include;
// Use a glob import to get all the symbols consistently
use bindings_include::*;

/// Error type for PQC operations
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug)]
pub struct PublicKey {
    /// The algorithm this key belongs to
    pub algorithm: Algorithm,
    /// The raw key bytes
    pub bytes: Vec<u8>,
}

/// Secret key wrapper
#[derive(Debug)]
pub struct SecretKey {
    /// The algorithm this key belongs to
    pub algorithm: Algorithm,
    /// The raw key bytes
    pub bytes: Vec<u8>,
}

/// Signature wrapper
#[derive(Debug, Clone)]
pub struct Signature {
    /// The algorithm this signature belongs to
    pub algorithm: Algorithm,
    /// The raw signature bytes
    pub bytes: Vec<u8>,
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
#[derive(Debug)]
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
