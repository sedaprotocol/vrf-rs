use elliptic_curve::{
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize},
    CurveArithmetic,
    Scalar,
    ScalarPrimitive,
};

use crate::{
    error::{Result, VrfError},
    VrfStruct,
};

impl<C, D> VrfStruct<C, D>
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
