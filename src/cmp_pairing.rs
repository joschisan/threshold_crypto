use std::cmp::Ordering;

use group::{Curve, Group, GroupEncoding};

// FIXME: probably get rid of this?
/// Compares two curve elements and returns their `Ordering`.
pub fn cmp_projective<G>(x: &G, y: &G) -> Ordering where
    G: Curve,
    G::AffineRepr: GroupEncoding
{
    let xc = x.to_affine().to_bytes();
    let yc = y.to_affine().to_bytes();
    xc.as_ref().cmp(yc.as_ref())
}
