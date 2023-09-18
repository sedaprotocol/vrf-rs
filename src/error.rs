use thiserror::Error;

#[derive(Error, Debug)]
pub enum VrfError {
    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] p256::ecdsa::Error),
    #[error("Elliptic Curve error: {0}")]
    EllipticCurve(#[from] p256::elliptic_curve::Error),
    #[error("Encode to Point (TAI) error: could not find a valid EC point")]
    EncodeToCurveTai,
    #[error("Encoded Point error: {0}")]
    EncodedPoint(String),
    #[error("Affine Point error: {0}")]
    AffinePoint(String),
    #[error("Invalid Proof while verifying")]
    InvalidProof,
    // TweakOutOfRange,
    // InvalidAffine,
}

pub type Result<T, E = VrfError> = core::result::Result<T, E>;
