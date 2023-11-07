use elliptic_curve::{
    generic_array::GenericArray,
    sec1::{FromEncodedPoint, ModulusSize},
    CurveArithmetic,
    FieldBytesEncoding,
};
use sha2::{
    digest::{crypto_common::BlockSizeUser, FixedOutput, FixedOutputReset},
    Digest,
};

use crate::VrfStruct;

impl<C, D> VrfStruct<C, D>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = C::FieldBytesSize> + FixedOutputReset,
{
    /// Function to generate a nonce deterministically by following the algorithm described in the [RFC6979](https://tools.ietf.org/html/rfc6979).
    /// Spec: `ECVRF_nonce_generation_RFC6979` function (section 5.4.2.1.)
    ///
    /// # Arguments
    ///
    /// * `secret_key`    - A scalar representing the secret key.
    /// * `mesage`        - A slice of octets representing the data (message).
    ///
    /// # Returns
    ///
    /// * If successful, the scalar representing the nonce.
    pub(super) fn generate_nonce(&self, secret_key: &[u8], message: &[u8]) -> GenericArray<u8, C::FieldBytesSize> {
        rfc6979::generate_k::<D, C::FieldBytesSize>(
            secret_key.into(),
            &FieldBytesEncoding::encode_field_bytes(&C::ORDER),
            &D::digest(message),
            &[],
        )
    }
}
