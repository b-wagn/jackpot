use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_poly::EvaluationDomain;
use ark_std::UniformRand;
use ark_std::{One, Zero};
use std::iter::zip;
use std::ops::Mul;

/// this module contains all types associated with
/// the KZG-based sim-extractable vector commitment
pub mod kzg_types;

/// this module contains several functions
/// we use often for our vector commitment
mod kzg_utils;

/// this module allows to compute all
/// openings in a fast amortized way
pub mod kzg_fk_open;
pub use kzg_fk_open::all_openings;

use self::kzg_fk_open::precompute_y;
pub use self::kzg_types::Commitment;
pub use self::kzg_types::CommitmentKey;
pub use self::kzg_types::Opening;
pub use self::kzg_types::State;
pub use self::kzg_types::VcKZG;

use self::kzg_utils::evaluate_outside;
use self::kzg_utils::find_in_domain;
use self::kzg_utils::get_chi;
use self::kzg_utils::get_z0;
use self::kzg_utils::inv_diffs;
use self::kzg_utils::plain_kzg_com;
use self::kzg_utils::plain_kzg_verify;
use self::kzg_utils::plain_kzg_verify_inside;
use self::kzg_utils::witness_evals_inside;
use self::kzg_utils::witness_evals_outside;

use super::VectorCommitmentScheme;

/* Note:
    - message length + 2 should probably be power of two, to make use of roots of unity
*/

impl<E: Pairing, D: EvaluationDomain<E::ScalarField>> VectorCommitmentScheme<E::ScalarField>
    for VcKZG<E, D>
{
    type CommitmentKey = CommitmentKey<E, D>;
    type Commitment = Commitment<E>;
    type Opening = Opening<E>;
    type State = State<E>;

    fn setup<R: rand::Rng>(rng: &mut R, message_length: usize) -> Option<Self::CommitmentKey> {
        if message_length < 1 {
            return None;
        }

        // generate an evaluation domain
        // should support polynomials to degree >= message_length + 1
        let domain = D::new(message_length + 2);
        if domain.is_none() {
            return None;
        }
        let domain = domain.unwrap();

        // sample generators g1 and g2
        let g1 = E::G1::rand(rng);
        let g2 = E::G2::rand(rng);
        if g1.is_zero() || g2.is_zero() {
            return None;
        }

        // sample hiding generator h
        let h = E::G1::rand(rng);

        // sample secret exponent alpha
        let alpha = E::ScalarField::rand(rng);

        // raise g1 to the powers of alpha --> u
        // raise h to the powers of alpha  --> hat_u
        let deg = domain.size() - 1;
        let mut u: Vec<E::G1Affine> = Vec::new();
        let mut hat_u: Vec<E::G1Affine> = Vec::new();
        let mut curr_g = g1;
        let mut curr_h = h;
        u.push(curr_g.into_affine());
        hat_u.push(curr_h.into_affine());
        for _ in 1..=deg {
            curr_g = curr_g.mul(alpha);
            u.push(curr_g.into_affine());
            curr_h = curr_h.mul(alpha);
            hat_u.push(curr_h.into_affine());
        }

        // compute exponentiated lagrange coefficients
        // Note: If a standard powers-of-tau setup is used,
        // this can be publicly computed from u and hat_u
        let lf = domain.evaluate_all_lagrange_coefficients(alpha);
        let mut lagranges = Vec::with_capacity(2 * deg);
        for i in 0..=deg {
            lagranges.push(u[0].mul(lf[i]).into_affine());
        }
        for i in 0..=deg {
            lagranges.push(hat_u[0].mul(lf[i]).into_affine());
        }

        //compute r = g2^{alpha}
        let r = g2.mul(alpha).into_affine();

        // compute all d[i] = g2^{alpha - zi}
        let mut d = Vec::new();
        for i in 0..message_length {
            let z = domain.element(i);
            let exponent: E::ScalarField = alpha - z;
            d.push(g2.mul(exponent).into_affine());
        }

        // precompute y and hat_y for FK algorithm
        let y = precompute_y::<E, D>(&u, &domain);
        let hat_y = precompute_y::<E, D>(&hat_u, &domain);

        // assemble commitment key
        let g2 = g2.into_affine();
        Some(CommitmentKey {
            message_length,
            domain,
            u,
            hat_u,
            lagranges,
            g2,
            r,
            d,
            y,
            hat_y,
        })
    }

    fn commit<R: rand::Rng>(
        rng: &mut R,
        ck: &Self::CommitmentKey,
        m: &Vec<E::ScalarField>,
    ) -> (Self::Commitment, Self::State) {
        // evals[0..domain.size] will store evaluations of our polynomial
        // over our evaluation domain, namely
        // evals[i] = m[i]   if m[i] is defined,
        // evals[i] = random if not
        // evals[domain.size()..2*domain.size()] will store evaluations of
        // the random masking polynomial used for hiding
        // we keep both evaluations in the same vector so that
        // we can easily do a single MSM later
        let dsize = ck.domain.size();
        let mut evals = Vec::with_capacity(2 * dsize);
        for i in 0..m.len() {
            evals.push(m[i]);
        }
        for _ in m.len()..2 * ck.domain.size() {
            evals.push(E::ScalarField::rand(rng));
        }

        // hat_evals will store the masking polynomial
        // we need for hiding in evaluation form
        // this is just a slice of evals
        let hat_evals = &evals[dsize..2 * dsize];

        // from our evaluations, we compute a standard KZG commitment
        let com_kzg = plain_kzg_com(ck, &evals);

        // determine the random point at which we have to open,
        // and evaluate the polynomial at that point
        let z0: E::ScalarField = get_z0::<E>(&com_kzg);
        if find_in_domain::<E, D>(&ck.domain, z0).is_some() {
            // should happen with negl probability for poly size domain
            // we actually don't want to reveal our vector, so it is
            // better to panick than to do anything
            panic!("Random evaluation point z0 was in evaluation domain");
        }
        // Now we can assume that z0 is not in the domain
        // compute evaluation y0 = f(z0) and the respective
        // witness polynomial (f-y0) / (X-z0) in evaluation form
        let inv_diffs = inv_diffs::<E, D>(&ck.domain, z0);
        let y0 = evaluate_outside::<E, D>(&ck.domain, &evals, z0, &inv_diffs);
        let mut witn_evals = Vec::with_capacity(2 * dsize);
        witness_evals_outside::<E, D>(&ck.domain, &evals, y0, &inv_diffs, &mut witn_evals);
        // do the same for the masking term
        let hat_y0 = evaluate_outside::<E, D>(&ck.domain, &hat_evals, z0, &inv_diffs);
        witness_evals_outside::<E, D>(&ck.domain, &hat_evals, hat_y0, &inv_diffs, &mut witn_evals);
        // opening v is just a KZG commitment to the witness polys
        let v = plain_kzg_com(ck, &witn_evals);
        let tau0 = Opening { hat_y: hat_y0, v };
        // return composed commitment and state
        let state = State {
            evals,
            precomputed_v: None,
        };
        let com = Commitment { com_kzg, y0, tau0 };
        (com, state)
    }

    fn verify_commitment(ck: &Self::CommitmentKey, com: &Self::Commitment) -> bool {
        // compute the 'challenge' z0 at which the commitment has to be opened
        let z0 = get_z0::<E>(&com.com_kzg);
        // check opening
        plain_kzg_verify(ck, &com.com_kzg, z0, com.y0, &com.tau0)
    }

    fn open(ck: &Self::CommitmentKey, st: &Self::State, i: u32) -> Option<Self::Opening> {
        if i as usize >= ck.message_length {
            return None;
        }

        // compute v: the KZG opening, which is a KZG commitment
        // to the witness polynomial. Either we already have it
        // precomputed, or we compute it in evaluation form
        let v = if let Some(vs) = &st.precomputed_v {
            vs[i as usize].into_affine()
        } else {
            let deg = ck.domain.size();
            let mut witn_evals = Vec::new();
            witness_evals_inside::<E, D>(&ck.domain, &st.evals, i as usize, &mut witn_evals);
            witness_evals_inside::<E, D>(
                &ck.domain,
                &st.evals[deg..2 * deg],
                i as usize,
                &mut witn_evals,
            );
            plain_kzg_com(&ck, &witn_evals)
        };

        // the opening is v and the evaluation of the masking polynomial
        let hat_y = st.evals[i as usize + ck.domain.size()];
        Some(Opening { hat_y, v })
    }

    fn aggregate(
        _ck: &Self::CommitmentKey,
        i: u32,
        mis: &Vec<E::ScalarField>,
        coms: &Vec<&Self::Commitment>,
        openings: &Vec<&Self::Opening>,
    ) -> Option<Self::Opening> {
        if mis.len() < 1 {
            return None;
        }
        let le = mis.len();

        // compute aggregation challenge chi
        let chi = get_chi::<E>(i, mis, coms);

        // compute aggregated opening
        // hat_y = sum_{j=1}^L hat_yj * chi^{j-1}
        // v = prod_{j=1}^L vj^{chi^{j-1}}
        // we compute v using a MSM, and we compute mi
        // naively, as we have the powers of chi anyway
        let mut chi_powers = Vec::with_capacity(le);
        chi_powers.push(E::ScalarField::one());
        for j in 1..le {
            chi_powers.push(chi_powers[j - 1] * chi);
        }
        let vs: Vec<_> = openings.iter().map(|opening| opening.v).collect();
        let v = <E::G1 as VariableBaseMSM>::msm(&vs, &chi_powers).unwrap();
        let v = v.into_affine();
        let hat_y: <E as Pairing>::ScalarField = zip(openings, chi_powers)
            .map(|(opening, c)| opening.hat_y * c)
            .sum();

        // let mut hat_y = openings[le - 1].hat_y;
        // let mut v = openings[le - 1].v.into_group();
        // if le >= 2 {
        //     for j in (0..=le - 2).rev() {
        //         hat_y *= chi;
        //         v *= chi;
        //         hat_y += openings[j].hat_y;
        //         v += openings[j].v.into_group();
        //     }
        // }
        // let v = v.into_affine();
        Some(Opening { hat_y, v })
    }

    fn verify(
        ck: &Self::CommitmentKey,
        i: u32,
        mis: &Vec<E::ScalarField>,
        coms: &Vec<&Self::Commitment>,
        opening: &Self::Opening,
    ) -> bool {
        if mis.len() < 1 {
            return false;
        }
        let le = mis.len();

        // compute aggregation challenge chi
        let chi = get_chi::<E>(i, mis, coms);

        // compute aggregated value and commitment
        // com = prod_{j=1}^L comj^{chi^{j-1}}
        // mi = sum_{j=1}^L mij * chi^{j-1}
        // we compute com using a MSM, and we compute mi
        // naively, as we have the powers of chi anyway
        let mut chi_powers = Vec::with_capacity(le);
        chi_powers.push(E::ScalarField::one());
        for j in 1..le {
            chi_powers.push(chi_powers[j - 1] * chi);
        }
        let com_kzgs: Vec<_> = coms.iter().map(|com| com.com_kzg).collect();
        let com = <E::G1 as VariableBaseMSM>::msm(&com_kzgs, &chi_powers).unwrap();
        let mi: <E as Pairing>::ScalarField = zip(mis, chi_powers).map(|(m, c)| *m * c).sum();

        // verify the aggregated commitment using standard KZG
        let com = com.into_affine();
        plain_kzg_verify_inside(ck, i as usize, &com, mi, opening)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::ops::Mul;

    use ark_bls12_381::Bls12_381;
    use ark_ec::{bls12::Bls12, pairing::Pairing, CurveGroup};
    use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain};
    use ark_poly::{DenseUVPolynomial, EvaluationDomain};
    use ark_serialize::CanonicalSerialize;
    use ark_serialize::{CanonicalDeserialize, Write};
    use ark_std::Zero;

    use super::kzg_types::CommitmentKey;

    use super::VcKZG;
    use crate::vectorcommitment::{
        VectorCommitmentScheme, _vc_test_agg_opening, _vc_test_com_ver, _vc_test_opening,
        _vc_test_setup,
    };

    type F = <Bls12_381 as Pairing>::ScalarField;
    type D = Radix2EvaluationDomain<F>;
    type VC = VcKZG<Bls12_381, D>;

    /// test that serialization of commitment key works
    #[test]
    fn kzg_vc_test_par_to_file() {
        // generate a commitment key
        let mut rng = ark_std::rand::thread_rng();
        let message_length = 14;
        let ck = VC::setup(&mut rng, message_length).unwrap();

        // write it to a file
        let mut ck_bytes = Vec::new();
        ck.serialize_compressed(&mut ck_bytes).unwrap();
        let mut file = File::create("ck.crs").expect("fail to create file");
        file.write_all(&ck_bytes).expect("fail to write to file");

        // read from file
        let file = File::open("ck.crs").unwrap();
        let ck_r = CommitmentKey::<Bls12_381, D>::deserialize_compressed(&file).unwrap();

        // compare
        assert_eq!(ck, ck_r);
    }

    #[test]
    fn kzg_vc_test_par_well_formed() {
        let mut rng = ark_std::rand::thread_rng();
        let message_length = 14;
        let ck = VC::setup(&mut rng, message_length);
        assert!(ck.is_some());
        let ck = ck.unwrap() as CommitmentKey<Bls12_381, D>;

        // with message length 14, we should have 16 degrees of freedom
        assert_eq!(ck.domain.size(), 16);

        // verify that lagranges consistent with u. To do so:
        // Compute g1^f(alpha) once with u (lhs)
        // and once with u_lag (rhs)
        let f: DensePolynomial<F> = DenseUVPolynomial::rand(15, &mut rng);
        let cpow: Vec<<Bls12<ark_bls12_381::Config> as Pairing>::G1> = f
            .coeffs
            .iter()
            .enumerate()
            .map(|(i, c)| ck.u[i].mul(c))
            .collect();

        let lhs: <Bls12<ark_bls12_381::Config> as Pairing>::G1 = cpow.iter().sum();
        let evals = f.evaluate_over_domain(ck.domain);
        let mut rhs = <Bls12<ark_bls12_381::Config> as Pairing>::G1::zero();
        for i in 0..ck.domain.size() {
            rhs += ck.lagranges[i].mul(evals[i]);
        }
        assert_eq!(lhs.into_affine(), rhs.into_affine());

        // verify that lagranges consistent with hat_u in the same way
        let f: DensePolynomial<F> = DenseUVPolynomial::rand(15, &mut rng);
        let cpow: Vec<<Bls12<ark_bls12_381::Config> as Pairing>::G1> = f
            .coeffs
            .iter()
            .enumerate()
            .map(|(i, c)| ck.hat_u[i].mul(c))
            .collect();
        let lhs: <Bls12<ark_bls12_381::Config> as Pairing>::G1 = cpow.iter().sum();
        let evals = f.evaluate_over_domain(ck.domain);
        let mut rhs = <Bls12<ark_bls12_381::Config> as Pairing>::G1::zero();
        for i in 0..ck.domain.size() {
            rhs += ck.lagranges[i + ck.domain.size()].mul(evals[i]);
        }
        assert_eq!(lhs.into_affine(), rhs.into_affine());
    }

    #[test]
    fn kzg_vc_test_setup() {
        _vc_test_setup::<F, VC>();
    }
    #[test]
    fn kzg_vc_test_com_ver() {
        _vc_test_com_ver::<F, VC>();
    }

    #[test]
    fn kzg_vc_test_opening() {
        _vc_test_opening::<F, VC>();
    }

    #[test]
    fn kzg_vc_test_agg_opening() {
        _vc_test_agg_opening::<F, VC>();
    }
}
