use elliptic_curve::{sec1::ModulusSize, CurveArithmetic};
use sha2::Digest;

use crate::{error::Result, VrfStruct};

impl<C, D> VrfStruct<C, D>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    D: Digest,
{
    /// Function to hash a certain set of points, used as part of the VRF prove and verify functions.
    /// Spec: `ECVRF_challenge_generation` function in section 5.4.3.
    ///
    /// # Arguments
    ///
    /// * `points` - A reference to an array containing the points that need to be hashed.
    ///
    /// # Returns
    ///
    /// * If successful, a challenge value, an integer between `0` and `2^(8*cLen)-1`. Truncated to length `cLen`.
    pub(super) fn challenge_generation(&self, points: &[&[u8]], truncate_len: usize) -> Result<Vec<u8>> {
        // Step 1: challenge_generation_domain_separator_front = 0x02
        const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: u8 = 0x02;

        // point_bytes = [P1||P2||...||Pn]
        let point_bytes = points.iter().try_fold(
            // Step 2: Initialize str = suite_string || challenge_generation_domain_separator_front
            vec![self.suite_id, CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT],
            // Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || point_to_string(PJ)
            |mut acc, &point| {
                acc.extend(point.to_vec());

                Ok(acc)
            },
        )?;

        // Step 4: challenge_generation_domain_separator_back = 0x00
        const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // Step 5-6: c_string = Hash(str) = Hash (str || challenge_generation_domain_separator_back)
        // Hash (suite_string || challenge_generation_domain_separator_front || point_bytes ||
        // challenge_generation_domain_separator_back)
        let mut c_bytes =
            D::digest([&point_bytes[..], &[CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]].concat()).to_vec();

        // Step 7: truncated_c_string = c_string[0]...c_string[cLen-1]
        c_bytes.truncate(truncate_len);

        // Step 8: c = string_to_int(truncated_c_string)
        // Note: not needed because `prove` and `verify` functions need bytes and scalar values

        Ok(c_bytes)
    }
}
