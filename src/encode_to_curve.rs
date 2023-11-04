use std::ops::Mul;

use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize},
    CurveArithmetic,
    ProjectivePoint,
};
use sha2::Digest;

use crate::{
    error::{Result, VrfError},
    VrfStruct,
};

impl<C, D> VrfStruct<C, D>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C>,
    D: Digest,
{
    /// Function to encode a hash, derived from the public key and a given data, to a point in the curve as stated in
    /// the [RFC9381](https://datatracker.ietf.org/doc/rfc9381/) (ECVRF_encode_to_curve_try_and_increment, section 5.4.1.1).
    ///
    /// `ECVRF_encode_to_curve_try_and_increment` implements `ECVRF_encode_to_curve` in a simple and generic way that
    /// works for any elliptic curve.
    ///
    /// To use this algorithm, `hLen` MUST be at least `fLen`, where:
    /// - `hLen` is the output length, in octets, of Hash.
    /// - `fLen` is length, in octets, of an element in F encoded as an octet string
    ///
    /// The running time of this algorithm depends on `alpha`. For most ciphersuites, this algorithm is expected to find
    /// a valid curve point after approximately two attempts (i.e., when ctr = 1) on average.
    /// It is overwhelmingly unlikely that the algorithm does not find a solution (the probability that the ctr counter
    /// reaches 256 is about 2^-256).
    ///
    /// However, because the algorithm's running time depends on alpha_string, this algorithm SHOULD be avoided in
    /// applications where it is important that the VRF input alpha remain secret.
    ///
    /// # Arguments
    ///
    /// * `encode_to_curve_salt` - A public salt value, an octet string.
    /// * `alpha`                - A slice containing the input data, to be hashed.
    ///
    /// # Returns
    ///
    /// * If successful, an EC point representing the hashed value.
    pub fn encode_to_curve_tai(&self, encode_to_curve_salt: &[u8], alpha: &[u8]) -> Result<C::AffinePoint> {
        // Step 1:  ctr = 0
        let mut ctr_range = 0..255;

        // Step 2-3:  domain separators & cipher suite
        const ENCODE_TO_CURVE_DOMAIN_SEPARATOR_FRONT: u8 = 0x01;
        const ENCODE_TO_CURVE_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // Step 4-5: Loop over ctr checking if hash_string is a valid EC point
        // hash_string = Hash(suite_string ||
        //               encode_to_curve_domain_separator_front ||
        //               encode_to_curve_salt || alpha_string || ctr_string ||
        //               encode_to_curve_domain_separator_back)
        let mut hash_input = [
            &[self.suite_id],
            &[ENCODE_TO_CURVE_DOMAIN_SEPARATOR_FRONT],
            encode_to_curve_salt,
            alpha,
            &[0x00], // First iteration: CTR=0
            &[ENCODE_TO_CURVE_DOMAIN_SEPARATOR_BACK],
        ]
        .concat();

        let ctr_position = hash_input.len() - 2;
        let point_opt = ctr_range.find_map(|ctr| {
            hash_input[ctr_position] = ctr;
            let hash_string = D::digest(&hash_input);
            self.try_hash_to_point(&hash_string).ok()
        });

        // No solution found (really unlikely with probability about 2^-256)
        let h_point = point_opt.ok_or(VrfError::EncodeToCurveTai)?;

        // Step 5d: H = cofactor * H (ECVRF_validate_key)
        // TODO: Check step 5d alternative `ProjectivePoint::<Self::Curve>::from(h_point).clear_cofactor().to_affine()`
        if self.cofactor() != Into::into(1) {
            return Ok(elliptic_curve::group::Curve::to_affine(
                &ProjectivePoint::<C>::from(h_point).mul(self.cofactor()),
            ));
        }

        Ok(h_point)
    }
}
