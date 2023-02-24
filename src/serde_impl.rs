//! Serialization and deserialization implementations for group and field elements.

pub use self::field_vec::FieldWrap;

use std::borrow::Cow;
use std::ops::Deref;
use bls12_381::{G1Affine, G2Affine, G2Projective};
use group::{Curve, GroupEncoding};

use crate::G1Projective;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::poly::{coeff_pos, BivarCommitment};
use crate::serde_impl::serialize_secret_internal::SerializeSecret;

const ERR_DEG: &str = "commitment degree does not match coefficients";

mod serialize_secret_internal {
    use serde::Serializer;

    /// To avoid deriving [`Serialize`] automatically for structs containing secret keys this trait
    /// should be implemented instead. It only enables explicit serialization through
    /// [`::serde_impls::SerdeSecret`].
    pub trait SerializeSecret {
        fn serialize_secret<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
    }

    impl<T: SerializeSecret> SerializeSecret for &T {
        fn serialize_secret<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> {
            (*self).serialize_secret(serializer)
        }
    }
}

/// `SerdeSecret` is a wrapper struct for serializing and deserializing secret keys. Due to security
/// concerns serialize shouldn't be implemented for secret keys to avoid accidental leakage.
///
/// Whenever this struct is used the integrity of security boundaries should be checked carefully.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SerdeSecret<T>(pub T);

impl<T> Deref for SerdeSecret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<T> SerdeSecret<T> {
    /// Returns the actual secret from the wrapper
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Returns a reference to the actual secret contained in the wrapper
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SerdeSecret<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(SerdeSecret(Deserialize::deserialize(deserializer)?))
    }
}

impl<T: SerializeSecret> Serialize for SerdeSecret<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize_secret(serializer)
    }
}

impl<'de> Deserialize<'de> for crate::SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use crate::{Scalar};
        use ff::PrimeField;
        use serde::de;

        let parsed_scalar_res = Scalar::from_repr(Deserialize::deserialize(deserializer)?);

        // FIXME: make constant time
        if parsed_scalar_res.is_none().into() {
            return Err(de::Error::invalid_value(
                de::Unexpected::Other(&"Number outside of prime field."),
                &"Valid prime field element.",
            ));
        }

        Ok(crate::SecretKey::from_mut(&mut parsed_scalar_res.unwrap()))
    }
}

impl SerializeSecret for crate::SecretKey {
    fn serialize_secret<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use ff::PrimeField;

        Serialize::serialize(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for crate::SecretKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(crate::SecretKeyShare(Deserialize::deserialize(
            deserializer,
        )?))
    }
}

impl SerializeSecret for crate::SecretKeyShare {
    fn serialize_secret<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_secret(serializer)
    }
}

/// A type with the same content as `BivarCommitment`, but that has not been validated yet.
#[derive(Serialize, Deserialize)]
struct WireBivarCommitment<'a> {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The commitments to the coefficients.
    #[serde(with = "projective_vec")]
    coeff: Cow<'a, [G1Projective]>,
}

impl Serialize for BivarCommitment {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        WireBivarCommitment {
            degree: self.degree,
            coeff: Cow::Borrowed(&self.coeff),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for BivarCommitment {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let WireBivarCommitment { degree, coeff } = Deserialize::deserialize(d)?;
        if coeff_pos(degree, degree).and_then(|l| l.checked_add(1)) != Some(coeff.len()) {
            return Err(D::Error::custom(ERR_DEG));
        }
        Ok(BivarCommitment {
            degree,
            coeff: coeff.into(),
        })
    }
}

/// Serialization and deserialization of a group element's compressed representation.
pub(crate) mod projective {
    use std::fmt;
    use std::marker::PhantomData;
    use group::{Curve, GroupEncoding};

    use pairing::{PairingCurveAffine};
    use serde::de::{Error as DeserializeError, SeqAccess, Visitor};
    use serde::{ser::SerializeTuple, Deserializer, Serializer};

    const ERR_CODE: &str = "deserialized bytes don't encode a group element";

    pub fn serialize<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: Curve,
        <C as Curve>::AffineRepr: GroupEncoding,
    {
        let serialized = c.to_affine().to_bytes();
        let mut tup = s.serialize_tuple(serialized.as_ref().len())?;
        for byte in serialized.as_ref() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D, C>(d: D) -> Result<C, D::Error>
    where
        D: Deserializer<'de>,
        C: Curve,
        C: From<C::AffineRepr>,
        <C as Curve>::AffineRepr: GroupEncoding,
    {
        struct TupleVisitor<C> {
            _ph: PhantomData<C>,
        }

        impl<'de, C> Visitor<'de> for TupleVisitor<C> where
            C: Curve,
            C::AffineRepr: GroupEncoding,
            C: From<C::AffineRepr>,
        {
            type Value = C;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // FIXME: hack to get array length, it will always be a u8 array. Upstream should adopt const generics, blocked on https://github.com/rust-lang/rust/issues/60551
                let len = <<<C as Curve>::AffineRepr as GroupEncoding>::Repr as Default>::default().as_ref().len();
                write!(f, "a tuple of size {}", len)
            }

            #[inline]
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<C, A::Error> {
                let mut compressed = <<C::AffineRepr as GroupEncoding>::Repr as Default>::default();
                for (i, byte) in compressed.as_mut().iter_mut().enumerate() {
                    let len_err = || DeserializeError::invalid_length(i, &self);
                    *byte = seq.next_element()?.ok_or_else(len_err)?;
                }
                // FIXME: make const time
                let affine: Option<_> = C::AffineRepr::from_bytes(&compressed).into();
                affine.ok_or_else(|| DeserializeError::custom("point not on curve")).map(|affine: C::AffineRepr| affine.into())
            }
        }

        // FIXME: find better way to get length
        let len = <<<C as Curve>::AffineRepr as GroupEncoding>::Repr as Default>::default().as_ref().len();
        d.deserialize_tuple(len, TupleVisitor { _ph: PhantomData })
    }
}

/// Serialize and Deserialize PublicKey
pub(crate) mod projective_publickey {
    use std::fmt;
    use std::marker::PhantomData;
    use group::{Curve, GroupEncoding};
    use serde::de::Visitor;
    use serde::de::Error as DeserializeError;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: Curve,
        <C as Curve>::AffineRepr: GroupEncoding,
    {
        let mut bytes = Vec::new();
        for &byte in c.to_affine().to_bytes().as_ref() {
            bytes.push(byte);
        }

        let number = hex_fmt::HexFmt(bytes).to_string();
        
        s.serialize_str(&number)
    }

    pub fn deserialize<'de, D, C>(d: D) -> Result<C, D::Error>
    where
        D: Deserializer<'de>,
        C: Curve,
        C::AffineRepr: GroupEncoding,
        C: From<C::AffineRepr>,
    {
        struct TupleVisitor<C> {
            _ph: PhantomData<C>,
        }

        impl<'de, C> Visitor<'de> for TupleVisitor<C> where
            C: Curve,
            C::AffineRepr: GroupEncoding,
            C: From<C::AffineRepr>,
        {
            type Value = C;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let len = <<C::AffineRepr as GroupEncoding>::Repr as Default>::default().as_ref().len();
                write!(f, "a tuple of size {}", len)
            }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<C, E> where
                E: DeserializeError
            {
                let mut compressed = <<C::AffineRepr as GroupEncoding>::Repr as Default>::default();
                let mut v = v.chars();

                for byte in compressed.as_mut().iter_mut() {
                    let s: String = vec![v.next().expect("first char missing"), 
                                         v.next().expect("second char missing")]
                                        .into_iter().collect();
                    let n = u8::from_str_radix(s.as_str(), 16).expect("reduxed number wasn't a number");
                    *byte = n;
                }
                // FIXME: make const time
                let affine: Option<_> = C::AffineRepr::from_bytes(&compressed).into();
                affine.ok_or_else(|| <E as DeserializeError>::custom("point not on curve")).map(|affine: C::AffineRepr| affine.into())
            }
        }
        d.deserialize_str(TupleVisitor { _ph: PhantomData })
    }
}

/// Serialize and Deserialize PublicKeySet
pub(crate) mod projective_publickeyset {
    use std::borrow::Borrow;
    use std::iter::FromIterator;
    use std::marker::PhantomData;
    use group::{Curve, GroupEncoding};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::projective_publickey;

    /// A wrapper type to facilitate serialization and deserialization of group elements.
    struct CurveWrap<C, B>(B, PhantomData<C>);

    impl<C, B> CurveWrap<C, B> {
        fn new(c: B) -> Self {
            CurveWrap(c, PhantomData)
        }
    }

    impl<C, B: Borrow<C>> Serialize for CurveWrap<C, B> where
        C: Curve,
        C::AffineRepr: GroupEncoding,
    {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            projective_publickey::serialize(self.0.borrow(), s)
        }
    }

    impl<'de, C> Deserialize<'de> for CurveWrap<C, C>  where
        C: Curve,
        C::AffineRepr: GroupEncoding,
        C: From<C::AffineRepr>,
    {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(CurveWrap::new(projective_publickey::deserialize(d)?))
        }
    }

    pub fn serialize<S, C, T>(vec: T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: Curve,
        C::AffineRepr: GroupEncoding,
        T: AsRef<[C]>,
    {
        let wrap_vec: Vec<CurveWrap<C, &C>> = vec.as_ref().iter().map(CurveWrap::new).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'de, D, C, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        C: Curve,
        C::AffineRepr: GroupEncoding,
        C: From<C::AffineRepr>,
        T: FromIterator<C>,
    {
        let wrap_vec = <Vec<CurveWrap<C, C>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(|CurveWrap(c, _)| c).collect())
    }
}

/// Serialization and deserialization of vectors of projective curve elements.
pub mod projective_vec {
    use std::borrow::Borrow;
    use std::iter::FromIterator;
    use std::marker::PhantomData;
    use group::{Curve, GroupEncoding};


    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::projective;

    /// A wrapper type to facilitate serialization and deserialization of group elements.
    struct CurveWrap<C, B>(B, PhantomData<C>);

    impl<C, B> CurveWrap<C, B> {
        fn new(c: B) -> Self {
            CurveWrap(c, PhantomData)
        }
    }

    impl<C, B: Borrow<C>> Serialize for CurveWrap<C, B> where
        C: Curve,
        C::AffineRepr: GroupEncoding,
    {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            projective::serialize(self.0.borrow(), s)
        }
    }

    impl<'de, C> Deserialize<'de> for CurveWrap<C, C> where
        C: Curve,
        C::AffineRepr: GroupEncoding,
        C: From<C::AffineRepr>,
    {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(CurveWrap::new(projective::deserialize(d)?))
        }
    }

    pub fn serialize<S, C, T>(vec: T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: Curve,
        C::AffineRepr: GroupEncoding,
        T: AsRef<[C]>,
    {
        let wrap_vec: Vec<CurveWrap<C, &C>> = vec.as_ref().iter().map(CurveWrap::new).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'de, D, C, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        C: Curve,
        C::AffineRepr: GroupEncoding,
        C: From<C::AffineRepr>,
        T: FromIterator<C>,
    {
        let wrap_vec = <Vec<CurveWrap<C, C>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(|CurveWrap(c, _)| c).collect())
    }
}

/// Serialization and deserialization of vectors of field elements.
pub(crate) mod field_vec {
    use std::borrow::Borrow;

    use ff::PrimeField;
    use serde::de::Error as DeserializeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{Scalar};

    /// A wrapper type to facilitate serialization and deserialization of field elements.
    pub struct FieldWrap<B>(pub B);

    impl FieldWrap<Scalar> {
        /// Returns the wrapped field element.
        pub fn into_inner(self) -> Scalar {
            self.0
        }
    }

    impl<B: Borrow<Scalar>> Serialize for FieldWrap<B> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.0.borrow().to_bytes().serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for FieldWrap<Scalar> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let repr = Deserialize::deserialize(d)?;
            // FIXME: make const time
            let scalar: Option<_> = Scalar::from_repr(repr).into();
            Ok(FieldWrap(scalar.ok_or_else( || {
                D::Error::custom("invalid field element representation")
            })?))
        }
    }

    pub fn serialize<S: Serializer>(vec: &[Scalar], s: S) -> Result<S::Ok, S::Error> {
        let wrap_vec: Vec<FieldWrap<&Scalar>> = vec.iter().map(FieldWrap).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Scalar>, D::Error> {
        let wrap_vec = <Vec<FieldWrap<Scalar>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(FieldWrap::into_inner).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use ff::Field;
    use group::Group;
    use serde::{Deserialize, Serialize};

    use crate::poly::BivarPoly;
    use crate::{Scalar, G1Projective};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Vecs {
        #[serde(with = "super::projective_vec")]
        curve_points: Vec<G1Projective>,
        #[serde(with = "super::field_vec")]
        field_elements: Vec<Scalar>,
    }

    impl PartialEq for Vecs {
        fn eq(&self, other: &Self) -> bool {
            self.curve_points == other.curve_points && self.field_elements == other.field_elements
        }
    }

    #[test]
    fn vecs() {
        let mut rng = rand::thread_rng();
        let vecs = Vecs {
            curve_points: repeat_with(|| G1Projective::random(&mut rng)).take(10).collect(),
            field_elements: repeat_with(|| Scalar::random(&mut rng)).take(10).collect(),
        };
        let ser_vecs = bincode::serialize(&vecs).expect("serialize vecs");
        let de_vecs = bincode::deserialize(&ser_vecs).expect("deserialize vecs");
        assert_eq!(vecs, de_vecs);
    }

    #[test]
    fn bivar_commitment() {
        let mut rng = rand::thread_rng();
        for deg in 1..8 {
            let poly = BivarPoly::random(deg, &mut rng);
            let comm = poly.commitment();
            let ser_comm = bincode::serialize(&comm).expect("serialize commitment");
            let de_comm = bincode::deserialize(&ser_comm).expect("deserialize commitment");
            assert_eq!(comm, de_comm);
        }
    }

    #[test]
    #[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
    fn serde_secret_key() {
        use crate::serde_impl::SerdeSecret;
        use crate::SecretKey;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        for _ in 0..2048 {
            let sk: SecretKey = rng.gen();
            let ser_ref = bincode::serialize(&SerdeSecret(&sk)).expect("serialize secret key");

            let de = bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de);

            let de_serde_secret: SerdeSecret<SecretKey> =
                bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de_serde_secret.into_inner());

            let ser_val = bincode::serialize(&SerdeSecret(sk)).expect("serialize secret key");
            assert_eq!(ser_ref, ser_val);
        }
    }

    #[test]
    fn serde_secret_key_share() {
        use crate::serde_impl::SerdeSecret;
        use crate::SecretKeyShare;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        for _ in 0..2048 {
            let sk: SecretKeyShare = rng.gen();
            let ser_ref = bincode::serialize(&SerdeSecret(&sk)).expect("serialize secret key");

            let de = bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de);

            let de_serde_secret: SerdeSecret<SecretKeyShare> =
                bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de_serde_secret.into_inner());

            let ser_val = bincode::serialize(&SerdeSecret(sk)).expect("serialize secret key");
            assert_eq!(ser_ref, ser_val);

            #[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
            assert_eq!(ser_val.len(), 32);
        }
    }
}
