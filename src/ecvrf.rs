use std::ops::Mul;

use elliptic_curve::{
    generic_array::{typenum::Unsigned, GenericArray},
    group::cofactor::CofactorGroup,
    ops::MulByGenerator,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve,
    CurveArithmetic,
    Field,
    ProjectivePoint,
    Scalar,
    ScalarPrimitive,
};
use sha2::{
    digest::{crypto_common::BlockSizeUser, FixedOutput, FixedOutputReset},
    Digest,
};

use crate::{
    error::{Result, VrfError},
    VrfStruct,
};

impl<C, D> VrfStruct<C, D>
where
    C: Curve,
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
{
    /// Curve cofactor, i.e., number of points on EC divided by prime order of group G.
    pub const fn cofactor(&self) -> Scalar<C> {
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

impl<C, D> VrfStruct<C, D>
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
        let k_scalar = self.scalar_from_bytes(&self.generate_nonce(secret_key, &h_point_bytes))?;

        // Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
        // U = k*B = k*Generator
        let u_point = C::ProjectivePoint::mul_by_generator(&k_scalar);
        let u_point_bytes = u_point.to_encoded_point(true).as_bytes().to_vec();
        // V = k*H
        let v_point = h_point * k_scalar;
        let v_point_bytes = v_point.to_encoded_point(true).as_bytes().to_vec();
        // Challenge generation (returns hash output truncated by `cLen`)
        let c_scalar_bytes = self.challenge_generation(
            &[
                &public_key_bytes,
                &h_point_bytes,
                &gamma_point_bytes,
                &u_point_bytes,
                &v_point_bytes,
            ],
            self.c_len(),
        )?;
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
    /// * `y`     - A slice representing the public key in octets.
    /// * `pi`    - A slice of octets representing the VRF proof.
    /// * `alpha` - A slice containing the input data, to be hashed.
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
        let derived_c_bytes = self.challenge_generation(
            &[
                public_key,
                &h_point_bytes,
                &gamma_point_bytes,
                &u_point_bytes,
                &v_point_bytes,
            ],
            self.c_len(),
        )?;
        let mut padded_derived_c_bytes: Vec<u8> = vec![0; C::FieldBytesSize::USIZE - self.c_len()];
        padded_derived_c_bytes.extend_from_slice(&derived_c_bytes);

        // Step 11: Check if c and c' are equal
        if padded_derived_c_bytes != c_scalar_bytes {
            return Err(VrfError::InvalidProof);
        }

        // If valid VRF proof, ECVRF_proof_to_hash(pi_string)
        self.gamma_to_hash(&gamma_point)
    }

    /// Function to compute VRF hash output for a given proof.
    /// Spec: `ECVRF_proof_to_hash` function (steps 4-to 7).
    ///
    /// # Arguments
    ///
    /// * `proof`  - A vector of octets representing the proof of the VRF
    ///
    /// # Returns
    ///
    /// * A vector of octets with the VRF hash output.
    pub fn proof_to_hash(&self, pi: &[u8]) -> Result<GenericArray<u8, C::FieldBytesSize>> {
        let gamma_point_bytes = self.decode_proof(pi)?.0;
        let gamma_point = C::ProjectivePoint::from(self.point_from_bytes(&gamma_point_bytes)?);

        self.gamma_to_hash(&gamma_point)
    }

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
    pub(crate) fn gamma_to_hash(&self, gamma: &C::ProjectivePoint) -> Result<GenericArray<u8, C::FieldBytesSize>> {
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
    pub(crate) fn decode_proof(&self, pi: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
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
