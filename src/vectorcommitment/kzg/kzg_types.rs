use ark_ec::pairing::Pairing;
use ark_poly::DenseUVPolynomial;
use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use std::marker::PhantomData;


/// Types for the Simulation Extractable KZG Vector commitment


pub struct VcKZG<
    E: Pairing,
    P: DenseUVPolynomial<E::ScalarField>,
    D: EvaluationDomain<E::ScalarField>,
> {
    _e: PhantomData<E>,
    _p: PhantomData<P>,
    _d: PhantomData<D>,
}

pub struct CommitmentKey<E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    /// length of messages to which we commit,
    /// This is called ell in the paper
    pub message_length: usize,

    /// evaluation domain that we use to represent vectors
    /// should support polynomials of degree deg >= ell+1
    pub domain: D,

    /// powers-of-alpha: u[i] = g1^{alpha^i}
    /// i should range from 0 to deg
    /// Note: u[0] = g1
    pub u: Vec<E::G1Affine>,

    /// lagrange version of u
    /// u_lag[i] = g1^{l_i(alpha)}, where
    /// l_i is the ith lagrange polynomial
    /// i should range from 0 to deg
    pub u_lag: Vec<E::G1Affine>,

    /// same as u, but for the hiding part
    /// hat_u[i] = h1^{alpha^i}
    /// i should range from 0 to deg
    pub hat_u: Vec<E::G1Affine>,

    /// lagrange version of u
    /// hat_u_lag[i] = h1^{l_i(alpha)}, where
    /// l_i is the ith lagrange polynomial
    /// i should range from 0 to deg
    pub hat_u_lag: Vec<E::G1Affine>,

    /// generator of G2
    pub g2: E::G2Affine,

    /// generator of G2, prepared for pairing
    pub g2_prepared: E::G2Prepared,

    /// r = g2^{\alpha}, needed for verification
    pub r: E::G2Affine,

    /// precomputed denominators in the exponent
    /// all prepared for pairing
    /// namely, d[i] = g2^{alpha - zi},
    /// where zi is the ith evaluation point
    /// i should range from 0 to ell-1
    pub d: Vec<E::G2Prepared>,
}

#[derive(CanonicalSerialize)]
pub struct Opening<E: Pairing> {
    /// evaluation of the randomizer polynomial
    pub hat_y: E::ScalarField,

    /// commitment to witness polynomial g1^{psi(alpha)}
    pub v: E::G1Affine,
}

#[derive(CanonicalSerialize)]
pub struct Commitment<E: Pairing> {
    /// actual kzg commitment, g1^{f(alpha)}
    pub com_kzg: E::G1Affine,

    /// value of f at z0 = Hash(com_kzg)
    pub y0: E::ScalarField,

    /// opening proof for y0 at z0
    pub tau0: Opening<E>,
}

pub struct State<E: Pairing> {
    pub evals: Vec<E::ScalarField>,
    pub hat_evals: Vec<E::ScalarField>,
}