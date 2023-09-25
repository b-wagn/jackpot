use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;

use super::{CommitmentKey, State};

// this module allows to compute all openings in a
// fast amortized way following the FK technique:
// https://eprint.iacr.org/2023/033.pdf

/// function to precompute all openings using the FK technique
pub fn precompute_openings<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    ck: &CommitmentKey<E, D>,
    st: &mut State<E>,
) {
    todo!();
    // compute openings for polynomial

    // do the same for the masking polynomial,
    // but with different basis

    // do a componentwise product to get the final openings
}

/// FK technique to compute openings in a *non-hiding* way
/// evals contains the domain.size() many evaluations
/// of the polynomial over the evaluation domain
fn precompute_openings_single<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    domain: &D,
    evals: &[E::ScalarField],
) -> Vec<E::G1Affine> {
    todo!();
    // compute the base polynomial h

    // evaluate h in the exponent using FFT
    // the evaluations are the openings

    // move them into affine (batched)
}

/// compute the polynomial h (in exponent) from the paper (see Proposition 1)
/// The ith KZG opening is h(domain.element(i)). Hence, one we have h, we can
/// compute all openings efficiently using a single FFT in the exponent
fn base_poly<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    domain: &D,
    evals: &[E::ScalarField],
) -> Vec<E::G1> {
    todo!();
}

#[cfg(test)]
mod tests {

    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::EvaluationDomain;
    use ark_poly::{DenseUVPolynomial, Radix2EvaluationDomain};
    use ark_std::One;
    use ark_std::UniformRand;

    use crate::vectorcommitment::kzg::VcKZG;
    use crate::vectorcommitment::VectorCommitmentScheme;

    use super::{precompute_openings_single, base_poly};

    type F = <Bls12_381 as Pairing>::ScalarField;
    type D = Radix2EvaluationDomain<F>;

    /// test function base_polynomial
    #[test]
    fn test_base_poly() {
        let mut rng = ark_std::rand::thread_rng();
        let degree = 15;
        let runs = 10;

        // generate some parameters
        let ck = VcKZG::<Bls12_381, D>::setup(&mut rng, degree - 1).unwrap();

        for _ in 0..runs {
            // sample random polynomial f and its evaluations
            let mut coeffs = Vec::new();
            for _ in 0..ck.domain.size() {
                coeffs.push(F::rand(&mut rng));
            }
            let f = DensePolynomial::from_coefficients_vec(coeffs);
            let evals = ck.domain.fft(&f.coeffs);
            // compute the expected coefficients of h
            // in the exponent (expensive version)
            let mut naive = Vec::new();
            for i in 1..=degree {
                // according to paper:
                // h_i = f[d]u[d-i] + f[d-1]u[d-i-1] + ... + f[i+1]u[1] + f[i]u[0],
                // where u[j] = g1^{secret^j} and d = degree
                // note that this is an MSM of f[i..=d] and u[0..=d-i]
                let hi = <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm(
                    &ck.u[0..=(degree-i)],
                    &f.coeffs[i..=degree],
                )
                .unwrap().into_affine();
                naive.push(hi);
            }
            // compute h using the function we want to test
            let h = base_poly::<Bls12_381,D>(&ck.domain, &evals);
            // check that they are indeed equal
            for i in 0..=degree-1 {
                assert_eq!(naive[i], h[i]);
            }
        }
    }

    /// test function precompute_openings_single
    #[test]
    fn test_precompute_openings_single() {
        let mut rng = ark_std::rand::thread_rng();
        let degree = 15;
        let runs = 10;

        // generate some parameters
        let ck = VcKZG::<Bls12_381, D>::setup(&mut rng, degree - 1).unwrap();

        for _ in 0..runs {
            // generate random polynomial and its evaluations
            let mut coeffs = Vec::new();
            for _ in 0..ck.domain.size() {
                coeffs.push(F::rand(&mut rng));
            }
            let f = DensePolynomial::from_coefficients_vec(coeffs);
            let evals = ck.domain.fft(&f.coeffs);
            // precompute the openings naively using long division (very slow)
            let mut naive: Vec<<Bls12_381 as Pairing>::G1Affine> = Vec::new();
            for i in 0..ck.domain.size() {
                // witness poly using long division
                let z = ck.domain.element(i);
                let fshift = &f - &DensePolynomial::from_coefficients_vec(vec![evals[i]]);
                let div = DensePolynomial::from_coefficients_vec(vec![-z, F::one()]);
                let witness_poly = &fshift / &div;
                // commit to witness poly at alpha
                let c = <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm(
                    &ck.u,
                    &witness_poly.coeffs,
                )
                .unwrap();
                naive.push(c.into_affine());
            }
            // precompute the openings using the function we want to test
            let fk: Vec<<Bls12_381 as Pairing>::G1Affine> =
                precompute_openings_single::<Bls12_381, D>(&ck.domain, &evals);
            // compare the results
            for i in 0..ck.domain.size() {
                assert_eq!(naive[i], fk[i]);
            }
        }
    }
}
