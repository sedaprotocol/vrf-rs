use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize},
    CurveArithmetic,
    FieldBytesEncoding,
    Scalar,
};
use sha2::{
    digest::{crypto_common::BlockSizeUser, FixedOutput, FixedOutputReset},
    Digest,
};

use crate::{error::Result, VrfStruct};

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
    /// * `secret_key`  - A scalar representing the secret key.
    /// * `data`        - A slice of octets representing the data (message).
    ///
    /// # Returns
    ///
    /// * If successful, the scalar representing the nonce.
    pub fn generate_nonce(&self, secret_key: &[u8], digest_msg: &[u8]) -> Result<Scalar<C>> {
        let k = rfc6979::generate_k::<D, C::FieldBytesSize>(
            secret_key.into(),
            &FieldBytesEncoding::encode_field_bytes(&C::ORDER),
            digest_msg.into(),
            &[],
        );

        self.scalar_from_bytes(&k)
    }
}
