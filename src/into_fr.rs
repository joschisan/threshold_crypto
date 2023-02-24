use bls12_381::Scalar;
use pairing::group::ff::PrimeField;

/// A conversion into an element of the field `Scalar`.
pub trait IntoScalar: Copy {
    /// Converts `self` to a field element.
    fn into_fr(self) -> Scalar;
}

impl IntoScalar for Scalar {
    fn into_fr(self) -> Scalar {
        self
    }
}

impl IntoScalar for u64 {
    fn into_fr(self) -> Scalar {
        Scalar::from(self)
    }
}

impl IntoScalar for usize {
    fn into_fr(self) -> Scalar {
        (self as u64).into_fr()
    }
}

impl IntoScalar for i32 {
    fn into_fr(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            result.neg()
        }
    }
}

impl IntoScalar for i64 {
    fn into_fr(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            result.neg();
            result
        }
    }
}

impl<'a, T: IntoScalar> IntoScalar for &'a T {
    fn into_fr(self) -> Scalar {
        (*self).into_fr()
    }
}
