use std::ops::Mul;

use elliptic_curve::{
    bigint::Encoding,
    generic_array::{typenum::Unsigned, GenericArray},
    group::cofactor::CofactorGroup,
    ops::MulByGenerator,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve,
    CurveArithmetic,
    FieldBytesEncoding,
    ProjectivePoint,
    Scalar,
    ScalarPrimitive,
};
use k256::Secp256k1;
use sha2::{
    digest::{crypto_common::BlockSizeUser, FixedOutput, FixedOutputReset},
    Digest,
};

use crate::error::{Result, VrfError};

pub struct EcVrfStruct<Curve, Hasher> {
    pub curve:    Curve,
    pub hasher:   Hasher,
    /// ECVRF suite string as specific by RFC9381
    pub suite_id: u8,
}

impl<C: Default, D: Default> EcVrfStruct<C, D> {
    pub fn new(suite_id: u8) -> Self {
        Self {
            curve: C::default(),
            hasher: D::default(),
            suite_id,
        }
    }
}

pub type P256k1Sha256 = EcVrfStruct<p256::NistP256, sha2::Sha256>;
impl Default for P256k1Sha256 {
    fn default() -> Self {
        Self {
            curve:    Default::default(),
            hasher:   Default::default(),
            suite_id: 0x01,
        }
    }
}

pub type Secp256k1Sha256 = EcVrfStruct<Secp256k1, sha2::Sha256>;
impl Default for Secp256k1Sha256 {
    fn default() -> Self {
        Self {
            curve:    Default::default(),
            hasher:   Default::default(),
            suite_id: 0xFE,
        }
    }
}

use elliptic_curve::Field;

impl<C, D> EcVrfStruct<C, D>
where
    C: Curve,
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::Uint: elliptic_curve::bigint::Integer,
{
    /// Curve cofactor, i.e., number of points on EC divided by prime order of group G.
    const fn cofactor(&self) -> Scalar<C> {
        // TODO: Change me! Wrong assumption that all curves have cofactor 1
        <C as CurveArithmetic>::Scalar::ONE
    }

    /// Length, in octets, of a point on E encoded as an octet string.
    const fn pt_len(&self) -> usize {
        <C as Curve>::FieldBytesSize::USIZE
    }

    /// Length, in octets, of a challenge value used by the VRF.
    /// Note: in the typical case, cLen is qLen/2 or close to it.
    const fn c_len(&self) -> usize {
        self.q_len() / 2
    }

    /// Length, in octets, of the prime order of group G (subgroup of EC of large prime order),
    /// i.e., the smallest integer such that `2^(8qLen) > q`.
    const fn q_len(&self) -> usize {
        // TODO: Change me! It should be:
        // const Q_LEN: usize = <Self::Curve as Curve>::ORDER.bits() / 8;
        <C as Curve>::FieldBytesSize::USIZE
    }
}

impl<C, D> EcVrfStruct<C, D>
where
    C: Curve,
    C: CurveArithmetic,
    C::Uint: Encoding,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C>,
    C::ProjectivePoint: ToEncodedPoint<C> + CofactorGroup,
{
    /// Decodes a VRF proof by extracting the gamma EC point, and parameters `c` and `s` as bytes.
    /// Spec: `ECVRF_decode_proof` function in section 5.4.4.
    ///
    /// # Arguments
    ///
    /// * `pi`  - A slice of octets representing the VRF proof
    ///
    /// # Returns
    ///
    /// * A tuple containing `gamma` point, and parameters `c` and `s`.
    pub fn decode_proof(&self, pi: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        // Expected size of proof: len(pi) = len(gamma) + len(c) + len(s)
        // len(s) = 2 * len(c), so len(pi) = len(gamma) + 3 * len(c)
        let gamma_oct = self.pt_len() + 1;
        if pi.len() != gamma_oct + self.c_len() * 3 {
            return Err(VrfError::InvalidPiLength);
        }

        // Gamma point
        let gamma = pi[0..gamma_oct].to_vec();

        // C scalar (needs to be padded with leading zeroes)
        let mut c_scalar: Vec<u8> = vec![0; <C as Curve>::FieldBytesSize::USIZE - self.c_len()];
        c_scalar.extend_from_slice(&pi[gamma_oct..gamma_oct + self.c_len()]);

        // S scalar
        let s_scalar = pi[gamma_oct + self.c_len()..].to_vec();

        Ok((gamma, c_scalar, s_scalar))
    }
}

impl<C, D> EcVrfStruct<C, D>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C>,
{
    /// Auxiliary function to convert an encoded point (as bytes) to a point in the curve.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice representing the encoded data point.
    ///
    /// # Returns
    ///
    /// * If successful, an EC affine point representing the converted point.
    pub fn point_from_bytes(&self, data: &[u8]) -> Result<C::AffinePoint> {
        let encoded_point: EncodedPoint<C> =
            EncodedPoint::<C>::from_bytes(data).map_err(|_| VrfError::AffineFromBytes)?;

        Option::from(C::AffinePoint::from_encoded_point(&encoded_point)).ok_or(VrfError::AffineFromBytes)
    }

    /// Function to interpret an array of bytes as a point in the curve.
    /// Spec: `interpret_hash_value_as_a_point(s) = sring_to_point(0x02 || s)` (section 5.5).
    ///
    /// # Arguments
    ///
    /// * `data` - A slice representing the data to be converted to a point.
    ///
    /// # Returns
    ///
    /// * If successful, an EC affine point representing the converted point.
    pub fn try_hash_to_point(&self, data: &[u8]) -> Result<C::AffinePoint> {
        self.point_from_bytes(&[&[0x02], data].concat())
    }

    /// Auxiliary function to convert an encoded scalar (as bytes) to a field scalar.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice representing the encoded scalar.
    ///
    /// # Returns
    ///
    /// * If successful, a field scalar.
    pub fn scalar_from_bytes(&self, data: &[u8]) -> Result<Scalar<C>> {
        let primitive = ScalarPrimitive::<C>::from_slice(data).map_err(|_| VrfError::ScalarFromBytes)?;

        Ok(primitive.into())
    }
}

impl<C, D> EcVrfStruct<C, D>
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

impl<C, D> EcVrfStruct<C, D>
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
    pub fn challenge_generation(&self, points: &[&[u8]]) -> Result<Vec<u8>> {
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
        c_bytes.truncate(self.c_len());

        // Step 8: c = string_to_int(truncated_c_string)
        // Note: not needed because `prove` and `verify` functions need bytes and scalar values

        Ok(c_bytes)
    }
}

impl<C, D> EcVrfStruct<C, D>
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

impl<C, D> EcVrfStruct<C, D>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::ProjectivePoint: ToEncodedPoint<C> + CofactorGroup,
    D: Digest + FixedOutput<OutputSize = C::FieldBytesSize>,
{
    /// Function to compute VRF hash output for a given gamma point (part of the VRF proof).
    /// Spec: `ECVRF_proof_to_hash` function (steps 4-to 7).
    ///
    /// # Arguments
    ///
    /// * `gamma`  - An EC point representing the VRF gamma.
    ///
    /// # Returns
    ///
    /// * A vector of octets with the VRF hash output.
    pub fn gamma_to_hash(&self, gamma: &C::ProjectivePoint) -> Result<GenericArray<u8, C::FieldBytesSize>> {
        // Step 4: proof_to_hash_domain_separator_front = 0x03
        const PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT: u8 = 0x03;

        // Step 5: proof_to_hash_domain_separator_back = 0x00
        const PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // Step 6: Compute beta
        // beta_string = Hash(suite_string || proof_to_hash_domain_separator_front ||
        //                    point_to_string(cofactor * Gamma) || proof_to_hash_domain_separator_back)
        let point: ProjectivePoint<C> = gamma.mul(self.cofactor());
        let point_bytes = point.to_encoded_point(true).as_bytes().to_vec();

        Ok(D::digest(
            [
                &[self.suite_id],
                &[PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT],
                &point_bytes[..],
                &[PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK],
            ]
            .concat(),
        ))
    }
}

impl<C, D> EcVrfStruct<C, D>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C>,
    C::ProjectivePoint: ToEncodedPoint<C> + CofactorGroup,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = C::FieldBytesSize> + FixedOutputReset,
{
    /// Generates a VRF proof from a secret key and message.
    /// Spec: `ECVRF_prove` function (section 5.1).
    ///
    /// # Arguments
    ///
    /// * `x` - A slice representing the secret key in octets.
    /// * `alpha` - A slice representing the message in octets.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets representing the proof of the VRF.
    pub fn prove(&self, secret_key: &[u8], alpha: &[u8]) -> Result<Vec<u8>> {
        // Step 1: derive public key from secret key as `Y = x * B`
        let secret_key_scalar = self.scalar_from_bytes(secret_key)?;
        let public_key_point = C::ProjectivePoint::mul_by_generator(&secret_key_scalar);

        let public_key_bytes: Vec<u8> = public_key_point.to_encoded_point(true).as_bytes().to_vec();

        // Step 2: Encode to curve (using TAI)
        let h_point = ProjectivePoint::<C>::from(self.encode_to_curve_tai(&public_key_bytes, alpha)?);

        // Step 3: point to string (or bytes)
        let h_point_bytes = h_point.to_encoded_point(true).as_bytes().to_vec();

        // Step 4: Gamma = x * H
        let gamma_point = h_point.mul(secret_key_scalar);
        let gamma_point_bytes = gamma_point.to_encoded_point(true).as_bytes().to_vec();

        // Step 5: nonce (k generation)
        let k_scalar = self.generate_nonce(secret_key, &D::digest(&h_point_bytes))?;

        // Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
        // U = k*B = k&Generator
        let u_point = C::ProjectivePoint::mul_by_generator(&k_scalar);
        let u_point_bytes = u_point.to_encoded_point(true).as_bytes().to_vec();
        // V = k*H
        let v_point = h_point * k_scalar;
        let v_point_bytes = v_point.to_encoded_point(true).as_bytes().to_vec();
        // Challenge generation (returns hash output truncated by `cLen`)
        let c_scalar_bytes = self.challenge_generation(&[
            &public_key_bytes,
            &h_point_bytes,
            &gamma_point_bytes,
            &u_point_bytes,
            &v_point_bytes,
        ])?;
        let mut c_padded_bytes: Vec<u8> = vec![0; C::FieldBytesSize::USIZE - self.c_len()];
        c_padded_bytes.extend_from_slice(&c_scalar_bytes);
        let c_scalar = self.scalar_from_bytes(&c_padded_bytes)?;

        // Step 7: s = (k + c*x) mod q
        let s_scalar = k_scalar + c_scalar * secret_key_scalar;
        let s_scalar_bytes = Into::<ScalarPrimitive<C>>::into(s_scalar).to_bytes();

        // Step 8: encode (gamma, c, s)
        let proof = [&gamma_point_bytes[..], &c_scalar_bytes, &s_scalar_bytes].concat();

        Ok(proof)
    }

    /// Verifies the provided VRF proof and computes the VRF hash output.
    /// Spec: `ECVRF_verify` function (section 5.2).
    ///
    /// # Arguments
    ///
    /// * `y`   - A slice representing the public key in octets.
    /// * `pi`  - A slice of octets representing the VRF proof.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets with the VRF hash output.
    pub fn verify(&self, public_key: &[u8], pi: &[u8], alpha: &[u8]) -> Result<GenericArray<u8, C::FieldBytesSize>> {
        // Step 1-2: Y = string_to_point(PK_string)
        let public_key_point = C::ProjectivePoint::from(self.point_from_bytes(public_key)?);

        // Step 3: If validate_key, run ECVRF_validate_key(Y) (Section 5.4.5)
        // TODO: Check step 3 again
        if public_key_point.is_small_order().into() {
            return Err(VrfError::VerifyInvalidKey);
        }

        // Step 4-6: D = ECVRF_decode_proof(pi_string)
        let (gamma_point_bytes, c_scalar_bytes, s_scalar_bytes) = self.decode_proof(pi)?;
        let gamma_point = C::ProjectivePoint::from(self.point_from_bytes(&gamma_point_bytes)?);
        let c_scalar = self.scalar_from_bytes(&c_scalar_bytes)?;
        let s_scalar = self.scalar_from_bytes(&s_scalar_bytes)?;

        // Step 7: H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
        let h_point = ProjectivePoint::<C>::from(self.encode_to_curve_tai(public_key, alpha)?);
        let h_point_bytes = h_point.to_encoded_point(true).as_bytes().to_vec();

        // Step 8: U = s*B - c*Y
        let u_point = C::ProjectivePoint::mul_by_generator(&s_scalar) - public_key_point * c_scalar;
        let u_point_bytes = u_point.to_encoded_point(true).as_bytes().to_vec();

        // Step 9: V = s*H - c*Gamma
        let v_point = h_point * s_scalar - gamma_point * c_scalar;
        let v_point_bytes = v_point.to_encoded_point(true).as_bytes().to_vec();

        // Step 10: c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
        let derived_c_bytes = self.challenge_generation(&[
            public_key,
            &h_point_bytes,
            &gamma_point_bytes,
            &u_point_bytes,
            &v_point_bytes,
        ])?;
        let mut padded_derived_c_bytes: Vec<u8> = vec![0; C::FieldBytesSize::USIZE - self.c_len()];
        padded_derived_c_bytes.extend_from_slice(&derived_c_bytes);

        // Step 11: Check if c and c' are equal
        if padded_derived_c_bytes != c_scalar_bytes {
            return Err(VrfError::InvalidProof);
        }

        // If valid VRF proof, ECVRF_proof_to_hash(pi_string)
        self.gamma_to_hash(&gamma_point)
    }
}
