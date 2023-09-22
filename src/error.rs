use thiserror::Error;

#[derive(Error, Debug)]
pub enum VrfError {
    #[error("affine: cannot convert from bytes to affine point")]
    AffineFromBytes,
    #[error("encode_to_curve: cannot find a valid EC point using TAI")]
    EncodeToCurveTai,
    #[error("decode_proof: invalid proof (pi) length")]
    InvalidPiLength,
    #[error("verify: invalid proof")]
    InvalidProof,
    #[error("scalar: cannot convert from bytes to scalar")]
    ScalarFromBytes,
    #[error("verify: invalid public key")]
    VerifyInvalidKey,
}

pub type Result<T, E = VrfError> = core::result::Result<T, E>;
