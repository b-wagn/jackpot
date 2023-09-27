use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use std::marker::PhantomData;

// This module contains types for the Simulation Extractable KZG Vector commitment

/// Simulation-Extractable vector commitment based on KZG
pub struct VcKZG<
    E: Pairing,
    D: EvaluationDomain<E::ScalarField>,
> {
    _e: PhantomData<E>,
    _d: PhantomData<D>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
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

    // /// lagrange version of u
    // /// u_lag[i] = g1^{l_i(alpha)}, where
    // /// l_i is the ith lagrange polynomial
    // /// i should range from 0 to deg
    // pub u_lag: Vec<E::G1Affine>,
    /// same as u, but for the hiding part
    /// hat_u[i] = h1^{alpha^i}
    /// i should range from 0 to deg
    pub hat_u: Vec<E::G1Affine>,

    /// lagrange version of u and hat_u
    /// Let l_i be the ith lagrange poly. Then:
    /// lag[i] = g1^{l_i(alpha)}
    /// lag[deg+i] = h1^{l_i(alpha)}
    /// for i in 0..deg
    pub lagranges: Vec<E::G1Affine>,

    /// generator of G2
    pub g2: E::G2Affine,

    /// r = g2^{\alpha}, needed for verification
    pub r: E::G2Affine,

    /// precomputed denominators in the exponent
    /// all prepared for pairing
    /// namely, d[i] = g2^{alpha - zi},
    /// where zi is the ith evaluation point
    /// i should range from 0 to deg
    pub d: Vec<E::G2Affine>,

    /// y = DFT_{2d}(hat_s) for
    /// hat_s = [u[d-1],...,u[0], d+2 neutral elements]
    /// precomputed for use in the FK technique
    pub y: Vec<E::G1Affine>,

    /// same as y, but with hat_u instead of u
    pub hat_y: Vec<E::G1Affine>,
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
    /// stores both the evaluations of the polynomial
    /// and the evaluations of the masking polynomial
    /// polynomial: 0..deg, masking: deg..2*deg
    pub evals: Vec<E::ScalarField>,

    /// optionally stores precomputed KZG openings
    /// Note: this is only the group element part
    pub precomputed_v: Option<Vec<E::G1>>,
}
