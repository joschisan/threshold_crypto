//! Utilities for distributed key generation: uni- and bivariate polynomials and commitments.
//!
//! If `G` is a group of prime order `r` (written additively), and `g` is a generator, then
//! multiplication by integers factors through `r`, so the map `x -> x * g` (the sum of `x`
//! copies of `g`) is a homomorphism from the field `Scalar` of integers modulo `r` to `G`. If the
//! _discrete logarithm_ is hard, i.e. it is infeasible to reverse this map, then `x * g` can be
//! considered a _commitment_ to `x`: By publishing it, you can guarantee to others that you won't
//! change your mind about the value `x`, without revealing it.
//!
//! This concept extends to polynomials: If you have a polynomial `f` over `Scalar`, defined as
//! `a * X * X + b * X + c`, you can publish `a * g`, `b * g` and `c * g`. Then others will be able
//! to verify any single value `f(x)` of the polynomial without learning the original polynomial,
//! because `f(x) * g == x * x * (a * g) + x * (b * g) + (c * g)`. Only after learning three (in
//! general `degree + 1`) values, they can interpolate `f` itself.
//!
//! This module defines univariate polynomials (in one variable) and _symmetric_ bivariate
//! polynomials (in two variables) over a field `Scalar`, as well as their _commitments_ in `G`.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::iter::repeat_with;
use std::{cmp, iter, ops};
use std::ops::{AddAssign, BitAnd, BitAndAssign, BitOr, Mul, MulAssign, Not, SubAssign};

use ff::Field;
use group::{Curve, Group, GroupEncoding};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::Choice;
use zeroize::Zeroize;

use crate::cmp_pairing::cmp_projective;
use crate::error::{Error, Result};
use crate::into_fr::IntoScalar;
use crate::{Scalar, G1Affine, G1Projective};

/// A univariate polynomial in the prime field.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Poly {
    /// The coefficients of a polynomial.
    #[serde(with = "super::serde_impl::field_vec")]
    pub(super) coeff: Vec<Scalar>,
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        for fr in self.coeff.iter_mut() {
            fr.zeroize()
        }
    }
}

impl Drop for Poly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A debug statement where the `coeff` vector of prime field elements has been redacted.
impl Debug for Poly {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poly").field("coeff", &"...").finish()
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<B: Borrow<Poly>> ops::AddAssign<B> for Poly {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Scalar::zero());
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            *self_c += rhs_c;
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> ops::Add<B> for &'a Poly {
    type Output = Poly;

    fn add(self, rhs: B) -> Poly {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Poly>> ops::Add<B> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: B) -> Poly {
        self += rhs;
        self
    }
}

impl<'a> ops::Add<Scalar> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: Scalar) -> Self::Output {
        // FIXME: this is not constant time, maybe always populate all polynomial coefficients?
        if self.is_zero().bitand(rhs.is_zero().not()).into() {
            self.coeff.push(rhs);
        } else {
            self.coeff[0].add_assign(&rhs);
            self.remove_zeros();
        }
        self
    }
}

impl<'a> ops::Add<u64> for Poly {
    type Output = Poly;

    fn add(self, rhs: u64) -> Self::Output {
        self + rhs.into_fr()
    }
}

impl<B: Borrow<Poly>> ops::SubAssign<B> for Poly {
    fn sub_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Scalar::zero());
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.sub_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> ops::Sub<B> for &'a Poly {
    type Output = Poly;

    fn sub(self, rhs: B) -> Poly {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Poly>> ops::Sub<B> for Poly {
    type Output = Poly;

    fn sub(mut self, rhs: B) -> Poly {
        self -= rhs;
        self
    }
}

// Clippy thinks using `+` in a `Sub` implementation is suspicious.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> ops::Sub<Scalar> for Poly {
    type Output = Poly;

    fn sub(self, mut rhs: Scalar) -> Self::Output {
        self + rhs.neg()
    }
}

impl<'a> ops::Sub<u64> for Poly {
    type Output = Poly;

    fn sub(self, rhs: u64) -> Self::Output {
        self - rhs.into_fr()
    }
}

// Clippy thinks using any `+` and `-` in a `Mul` implementation is suspicious.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, B: Borrow<Poly>> ops::Mul<B> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        let rhs = rhs.borrow();
        // FIXME: make const time
        if rhs.is_zero().bitor(self.is_zero()).into() {
            return Poly::zero();
        }
        let n_coeffs = self.coeff.len() + rhs.coeff.len() - 1;
        let mut coeffs = vec![Scalar::zero(); n_coeffs];
        let mut tmp = Scalar::zero();
        for (i, ca) in self.coeff.iter().enumerate() {
            for (j, cb) in rhs.coeff.iter().enumerate() {
                tmp = *ca;
                tmp.mul_assign(cb);
                coeffs[i + j].add_assign(&tmp);
            }
        }
        tmp.zeroize();
        Poly::from(coeffs)
    }
}

impl<B: Borrow<Poly>> ops::Mul<B> for Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Poly {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl ops::MulAssign<Scalar> for Poly {
    fn mul_assign(&mut self, rhs: Scalar) {
        // FIXME: make const time
        if rhs.is_zero().into() {
            self.zeroize();
            self.coeff.clear();
        } else {
            for c in &mut self.coeff {
                c.mul_assign(&rhs);
            }
        }
    }
}

impl<'a> ops::Mul<&'a Scalar> for Poly {
    type Output = Poly;

    fn mul(mut self, rhs: &Scalar) -> Self::Output {
        // FIXME: make const time
        if rhs.is_zero().into() {
            self.zeroize();
            self.coeff.clear();
        } else {
            self.coeff.iter_mut().for_each(|c| c.mul_assign(rhs));
        }
        self
    }
}

impl ops::Mul<Scalar> for Poly {
    type Output = Poly;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let rhs = &rhs;
        self * rhs
    }
}

impl<'a> ops::Mul<&'a Scalar> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl<'a> ops::Mul<Scalar> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: Scalar) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl ops::Mul<u64> for Poly {
    type Output = Poly;

    fn mul(self, rhs: u64) -> Self::Output {
        self * rhs.into_fr()
    }
}

/// Creates a new `Poly` instance from a vector of prime field elements representing the
/// coefficients of the polynomial.
impl From<Vec<Scalar>> for Poly {
    fn from(coeff: Vec<Scalar>) -> Self {
        Poly { coeff }
    }
}

impl Poly {
    /// Creates a random polynomial.
    ///
    /// # Panics
    ///
    /// Panics if the `degree` is too large for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        Poly::try_random(degree, rng)
            .unwrap_or_else(|e| panic!("Failed to create random `Poly`: {}", e))
    }

    /// Creates a random polynomial. This constructor is identical to the `Poly::random()`
    /// constructor in every way except that this constructor will return an `Err` where
    /// `try_random` would return an error.
    pub fn try_random(degree: usize, mut rng: impl RngCore) -> Result<Self> {
        if degree == usize::max_value() {
            return Err(Error::DegreeTooHigh);
        }
        let coeff: Vec<Scalar> = repeat_with(|| Scalar::random(&mut rng)).take(degree + 1).collect();
        Ok(Poly::from(coeff))
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Poly { coeff: vec![] }
    }

    /// Returns `true` if the polynomial is the constant value `0`.
    pub fn is_zero(&self) -> Choice {
        self.coeff
            .iter()
            .map(|coeff| coeff.is_zero())
            .fold(Choice::from(1), |a, b| a.bitand(b))
    }

    /// Returns the polynomial with constant value `1`.
    pub fn one() -> Self {
        Poly::constant(Scalar::one())
    }

    /// Returns the polynomial with constant value `c`.
    pub fn constant(mut c: Scalar) -> Self {
        // We create a raw pointer to the field element within this method's stack frame so we can
        // overwrite that portion of memory with zeros once we have copied the element onto the
        // heap as part of the vector of polynomial coefficients.
        let poly = Poly::from(vec![c]);
        c.zeroize();
        poly
    }

    /// Returns the identity function, i.e. the polynomial "`x`".
    pub fn identity() -> Self {
        Poly::monomial(1)
    }

    /// Returns the (monic) monomial: `x.pow(degree)`.
    pub fn monomial(degree: usize) -> Self {
        let coeff: Vec<Scalar> = iter::repeat(Scalar::zero())
            .take(degree)
            .chain(iter::once(Scalar::one()))
            .collect();
        Poly::from(coeff)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    pub fn interpolate<T, U, I>(samples_repr: I) -> Self
    where
        I: IntoIterator<Item = (T, U)>,
        T: IntoScalar,
        U: IntoScalar,
    {
        let convert = |(x, y): (T, U)| (x.into_fr(), y.into_fr());
        let samples: Vec<(Scalar, Scalar)> = samples_repr.into_iter().map(convert).collect();
        Poly::compute_interpolation(&samples)
    }

    /// Returns the degree.
    pub fn degree(&self) -> usize {
        self.coeff.len().saturating_sub(1)
    }

    /// Returns the value at the point `i`.
    pub fn evaluate<T: IntoScalar>(&self, i: T) -> Scalar {
        let mut result = match self.coeff.last() {
            None => return Scalar::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(&x);
            result.add_assign(c);
        }
        result
    }

    /// Returns the corresponding commitment.
    pub fn commitment(&self) -> Commitment {
        let to_g1 = |c: &Scalar| G1Affine::generator().mul(*c);
        Commitment {
            coeff: self.coeff.iter().map(to_g1).collect(),
        }
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        // FIXME: make constant time
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero().into()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len);
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    fn compute_interpolation(samples: &[(Scalar, Scalar)]) -> Self {
        if samples.is_empty() {
            return Poly::zero();
        }
        // Interpolates on the first `i` samples.
        let mut poly = Poly::constant(samples[0].1);
        let mut minus_s0 = samples[0].0;
        minus_s0 = minus_s0.neg();
        // Is zero on the first `i` samples.
        let mut base = Poly::from(vec![minus_s0, Scalar::one()]);

        // We update `base` so that it is always zero on all previous samples, and `poly` so that
        // it has the correct values on the previous samples.
        for (ref x, ref y) in &samples[1..] {
            // Scale `base` so that its value at `x` is the difference between `y` and `poly`'s
            // current value at `x`: Adding it to `poly` will then make it correct for `x`.
            let mut diff = *y;
            diff.sub_assign(&poly.evaluate(x));
            let base_val = base.evaluate(x);
            diff.mul_assign(&Into::<Option<_>>::into(base_val.invert()).expect("sample points must be distinct"));
            base *= diff;
            poly += &base;

            // Finally, multiply `base` by X - x, so that it is zero at `x`, too, now.
            let mut minus_x = *x;
            minus_x = minus_x.neg();
            base *= Poly::from(vec![minus_x, Scalar::one()]);
        }
        poly
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field elements.
    pub fn reveal(&self) -> String {
        format!("Poly {{ coeff: {:?} }}", self.coeff)
    }
}

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// The coefficients of the polynomial.
    #[serde(with = "super::serde_impl::projective_publickeyset")]
    pub coeff: Vec<G1Projective>,
}

impl PartialOrd for Commitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Commitment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.coeff.len().cmp(&other.coeff.len()).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(Ordering::Equal, |(x, y)| cmp_projective(x, y))
        })
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.to_affine().to_bytes().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment>> ops::AddAssign<B> for Commitment {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, G1Projective::identity());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Commitment>> ops::Add<B> for &'a Commitment {
    type Output = Commitment;

    fn add(self, rhs: B) -> Commitment {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Commitment>> ops::Add<B> for Commitment {
    type Output = Commitment;

    fn add(mut self, rhs: B) -> Commitment {
        self += rhs;
        self
    }
}

impl Commitment {
    pub fn from(coeff: Vec<G1Projective>) -> Self {
        Self { coeff }
    }

    /// Returns the polynomial's degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th public key share.
    pub fn evaluate<T: IntoScalar>(&self, i: T) -> G1Projective {
        let mut result = match self.coeff.last() {
            None => return G1Projective::identity(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(x);
            result.add_assign(c);
        }
        result
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        // FIXME: make const time
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_identity().into()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len)
    }
}

/// A symmetric bivariate polynomial in the prime field.
///
/// This can be used for Verifiable Secret Sharing and Distributed Key Generation. See the module
/// documentation for details.
#[derive(Clone)]
pub struct BivarPoly {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The coefficients of the polynomial. Coefficient `(i, j)` for `i <= j` is in position
    /// `j * (j + 1) / 2 + i`.
    coeff: Vec<Scalar>,
}

impl Zeroize for BivarPoly {
    fn zeroize(&mut self) {
        for fr in self.coeff.iter_mut() {
            fr.zeroize();
        }
        self.degree.zeroize();
    }
}

impl Drop for BivarPoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A debug statement where the `coeff` vector has been redacted.
impl Debug for BivarPoly {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BivarPoly")
            .field("degree", &self.degree)
            .field("coeff", &"...")
            .finish()
    }
}

impl BivarPoly {
    /// Creates a random polynomial.
    ///
    /// # Panics
    ///
    /// Panics if the degree is too high for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        BivarPoly::try_random(degree, rng).unwrap_or_else(|e| {
            panic!(
                "Failed to create random `BivarPoly` of degree {}: {}",
                degree, e
            )
        })
    }

    /// Creates a random polynomial.
    pub fn try_random(degree: usize, mut rng: impl RngCore) -> Result<Self> {
        let len = coeff_pos(degree, degree)
            .and_then(|l| l.checked_add(1))
            .ok_or(Error::DegreeTooHigh)?;
        let poly = BivarPoly {
            degree,
            coeff: repeat_with(|| Scalar::random(&mut rng)).take(len).collect(),
        };
        Ok(poly)
    }

    /// Returns the polynomial's degree; which is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the polynomial's value at the point `(x, y)`.
    pub fn evaluate<T: IntoScalar>(&self, x: T, y: T) -> Scalar {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = Scalar::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let index = coeff_pos(i, j).expect("polynomial degree too high");
                let mut summand = self.coeff[index];
                summand.mul_assign(&x_pow_i);
                summand.mul_assign(y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a univariate polynomial.
    pub fn row<T: IntoScalar>(&self, x: T) -> Poly {
        let x_pow = self.powers(x);
        let coeff: Vec<Scalar> = (0..=self.degree)
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut result = Scalar::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let index = coeff_pos(i, j).expect("polynomial degree too high");
                    let mut summand = self.coeff[index];
                    summand.mul_assign(x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Poly::from(coeff)
    }

    /// Returns the corresponding commitment. That information can be shared publicly.
    pub fn commitment(&self) -> BivarCommitment {
        let to_pub = |c: &Scalar| G1Affine::generator().mul(*c);
        BivarCommitment {
            degree: self.degree,
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoScalar>(&self, x: T) -> Vec<Scalar> {
        powers(x, self.degree)
    }

    /// Generates a non-redacted debug string. This method differs from the
    /// `Debug` implementation in that it *does* leak the the struct's
    /// internal state.
    pub fn reveal(&self) -> String {
        format!(
            "BivarPoly {{ degree: {}, coeff: {:?} }}",
            self.degree, self.coeff
        )
    }
}

/// A commitment to a symmetric bivariate polynomial.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BivarCommitment {
    /// The polynomial's degree in each of the two variables.
    pub(crate) degree: usize,
    /// The commitments to the coefficients.
    pub(crate) coeff: Vec<G1Projective>,
}

impl Hash for BivarCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        for c in &self.coeff {
            c.to_affine().to_bytes().as_ref().hash(state);
        }
    }
}

impl PartialOrd for BivarCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for BivarCommitment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.degree.cmp(&other.degree).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(Ordering::Equal, |(x, y)| cmp_projective(x, y))
        })
    }
}

impl BivarCommitment {
    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the commitment's value at the point `(x, y)`.
    pub fn evaluate<T: IntoScalar>(&self, x: T, y: T) -> G1Projective {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = G1Projective::identity();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let index = coeff_pos(i, j).expect("polynomial degree too high");
                let mut summand = self.coeff[index];
                summand.mul_assign(x_pow_i);
                summand.mul_assign(*y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a commitment to a univariate polynomial.
    pub fn row<T: IntoScalar>(&self, x: T) -> Commitment {
        let x_pow = self.powers(x);
        let coeff: Vec<G1Projective> = (0..=self.degree)
            .map(|i| {
                let mut result = G1Projective::identity();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let index = coeff_pos(i, j).expect("polynomial degree too high");
                    let mut summand = self.coeff[index];
                    summand.mul_assign(*x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Commitment { coeff }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoScalar>(&self, x: T) -> Vec<Scalar> {
        powers(x, self.degree)
    }
}

/// Returns the `0`-th to `degree`-th power of `x`.
fn powers<T: IntoScalar>(into_x: T, degree: usize) -> Vec<Scalar> {
    let x = into_x.into_fr();
    let mut x_pow_i = Scalar::one();
    iter::once(x_pow_i)
        .chain((0..degree).map(|_| {
            x_pow_i.mul_assign(&x);
            x_pow_i
        }))
        .collect()
}

/// Returns the position of coefficient `(i, j)` in the vector describing a symmetric bivariate
/// polynomial. If `i` or `j` are too large to represent the position as a `usize`, `None` is
/// returned.
pub(crate) fn coeff_pos(i: usize, j: usize) -> Option<usize> {
    // Since the polynomial is symmetric, we can order such that `j >= i`.
    let (j, i) = if j >= i { (j, i) } else { (i, j) };
    i.checked_add(j.checked_mul(j.checked_add(1)?)? / 2)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ops::{AddAssign, Mul};

    use super::{coeff_pos, BivarPoly, IntoScalar, Poly};
    use super::{Scalar, G1Affine, G1Projective};
    use ff::Field;
    use zeroize::Zeroize;

    #[test]
    fn test_coeff_pos() {
        let mut i = 0;
        let mut j = 0;
        for n in 0..100 {
            assert_eq!(Some(n), coeff_pos(i, j));
            if i >= j {
                j += 1;
                i = 0;
            } else {
                i += 1;
            }
        }
        let too_large = 1 << (0usize.count_zeros() / 2);
        assert_eq!(None, coeff_pos(0, too_large));
    }

    #[test]
    fn poly() {
        // The polynomial 5 X³ + X - 2.
        let x_pow_3 = Poly::monomial(3);
        let x_pow_1 = Poly::monomial(1);
        let poly = x_pow_3 * 5 + x_pow_1 - 2;

        let coeff: Vec<_> = [-2, 1, 0, 5].iter().map(IntoScalar::into_fr).collect();
        assert_eq!(Poly { coeff }, poly);
        let samples = vec![(-1, -8), (2, 40), (3, 136), (5, 628)];
        for &(x, y) in &samples {
            assert_eq!(y.into_fr(), poly.evaluate(x));
        }
        let interp = Poly::interpolate(samples);
        assert_eq!(interp, poly);
    }

    #[test]
    fn test_zeroize() {
        let mut poly = Poly::monomial(3) + Poly::monomial(2) - 1;
        poly.zeroize();
        assert!(bool::from(poly.is_zero()));

        let mut bi_poly = BivarPoly::random(3, &mut rand::thread_rng());
        let random_commitment = bi_poly.commitment();

        bi_poly.zeroize();

        let zero_commitment = bi_poly.commitment();
        assert_ne!(random_commitment, zero_commitment);

        let mut rng = rand::thread_rng();
        let (x, y): (Scalar, Scalar) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        assert_eq!(zero_commitment.evaluate(x, y), G1Projective::identity());
    }

    #[test]
    fn distributed_key_generation() {
        let mut rng = rand::thread_rng();
        let dealer_num = 3;
        let node_num = 5;
        let faulty_num = 2;

        // For distributed key generation, a number of dealers, only one of who needs to be honest,
        // generates random bivariate polynomials and publicly commits to them. In practice, the
        // dealers can e.g. be any `faulty_num + 1` nodes.
        let bi_polys: Vec<BivarPoly> = (0..dealer_num)
            .map(|_| BivarPoly::random(faulty_num, &mut rng))
            .collect();
        let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();

        let mut sec_keys = vec![Scalar::zero(); node_num];

        // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
        // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
        // verify the values they received, and collect them.
        for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
            for m in 1..=node_num {
                // Node `m` receives its row and verifies it.
                let row_poly = bi_poly.row(m);
                let row_commit = bi_commit.row(m);
                assert_eq!(row_poly.commitment(), row_commit);
                // Node `s` receives the `s`-th value and verifies it.
                for s in 1..=node_num {
                    let val = row_poly.evaluate(s);
                    let val_g1 = G1Affine::generator().mul(val);
                    assert_eq!(bi_commit.evaluate(m, s), val_g1);
                    // The node can't verify this directly, but it should have the correct value:
                    assert_eq!(bi_poly.evaluate(m, s), val);
                }

                // A cheating dealer who modified the polynomial would be detected.
                let x_pow_2 = Poly::monomial(2);
                let five = Poly::constant(5.into_fr());
                let wrong_poly = row_poly.clone() + x_pow_2 * five;
                assert_ne!(wrong_poly.commitment(), row_commit);

                // If `2 * faulty_num + 1` nodes confirm that they received a valid row, then at
                // least `faulty_num + 1` honest ones did, and sent the correct values on to node
                // `s`. So every node received at least `faulty_num + 1` correct entries of their
                // column/row (remember that the bivariate polynomial is symmetric). They can
                // reconstruct the full row and in particular value `0` (which no other node knows,
                // only the dealer). E.g. let's say nodes `1`, `2` and `4` are honest. Then node
                // `m` received three correct entries from that row:
                let received: BTreeMap<_, _> = [1, 2, 4]
                    .iter()
                    .map(|&i| (i, bi_poly.evaluate(m, i)))
                    .collect();
                let my_row = Poly::interpolate(received);
                assert_eq!(bi_poly.evaluate(m, 0), my_row.evaluate(0));
                assert_eq!(row_poly, my_row);

                // The node sums up all values number `0` it received from the different dealer. No
                // dealer and no other node knows the sum in the end.
                sec_keys[m - 1].add_assign(&my_row.evaluate(Scalar::zero()));
            }
        }

        // Each node now adds up all the first values of the rows it received from the different
        // dealers (excluding the dealers where fewer than `2 * faulty_num + 1` nodes confirmed).
        // The whole first column never gets added up in practice, because nobody has all the
        // information. We do it anyway here; entry `0` is the secret key that is not known to
        // anyone, neither a dealer, nor a node:
        let mut sec_key_set = Poly::zero();
        for bi_poly in &bi_polys {
            sec_key_set += bi_poly.row(0);
        }
        for m in 1..=node_num {
            assert_eq!(sec_key_set.evaluate(m), sec_keys[m - 1]);
        }

        // The sum of the first rows of the public commitments is the commitment to the secret key
        // set.
        let mut sum_commit = Poly::zero().commitment();
        for bi_commit in &pub_bi_commits {
            sum_commit += bi_commit.row(0);
        }
        assert_eq!(sum_commit, sec_key_set.commitment());
    }
}
