use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_ff::batch_inversion;
use ark_ff::Field;
use ark_poly::EvaluationDomain;
use ark_poly::Polynomial;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::Zero;
use sha2::{Digest, Sha256};
use std::ops::Mul;

use super::Commitment;
use super::CommitmentKey;
use super::Opening;

/// Helper functions for the Simulation Extractable KZG Vector commitment

/// Computes the challenge for a commitment
pub fn get_z0<E: Pairing>(com_kzg: &E::G1Affine) -> E::ScalarField {
    // z0 = Hash(com_kzg)
    let mut com_ser = Vec::new();
    com_kzg
        .serialize_uncompressed(&mut com_ser)
        .expect("Failed to serialize commitment in get_z0");
    let mut res = None;
    let mut i = 0u64;
    // Efficiency could be improved here by copying midstate
    while res.is_none() {
        let mut hasher = Sha256::new_with_prefix("KZG-SIM-EXT//".as_bytes());
        i += 1;
        hasher.update(&com_ser);
        hasher.update(i.to_le_bytes());
        let digest = hasher.finalize();
        res = E::ScalarField::from_random_bytes(&digest);
    }
    res.unwrap()
}

/// Computes the aggregation coefficient
/// for a bunch of commitments and expected values
pub fn get_chi<E: Pairing>(
    i: u32,
    mis: &Vec<E::ScalarField>,
    coms: &Vec<&Commitment<E>>,
) -> E::ScalarField {
    // chi = Hash(i,(mi[j],com[j])_j)
    let mut mis_ser = Vec::new();
    let mut coms_ser = Vec::new();
    for j in 0..mis.len() {
        let mut mi_ser = Vec::new();
        let mut com_ser = Vec::new();
        mis[j]
            .serialize_uncompressed(&mut mi_ser)
            .expect("Failed to serialize mi in get_chi");
        coms[j]
            .serialize_uncompressed(&mut com_ser)
            .expect("Failed to serialize com in get_chi");
        mis_ser.push(mi_ser);
        coms_ser.push(com_ser);
    }
    let mut cnt = 0u64;
    let mut res = None;
    while res.is_none() {
        let mut hasher = Sha256::new_with_prefix("KZG-AGG//".as_bytes());
        cnt += 1;
        hasher.update(cnt.to_le_bytes());
        hasher.update(i.to_be_bytes());
        for j in 0..mis.len() {
            hasher.update(&mis_ser[j]);
            hasher.update(&coms_ser[j]);
        }
        let digest = hasher.finalize();
        res = E::ScalarField::from_random_bytes(&digest);
    }
    res.unwrap()
}

/// Standard KZG verification. Verifies that f(z) = y
pub fn plain_kzg_verify<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    ck: &CommitmentKey<E, D>,
    com_kzg: &E::G1Affine,
    z: E::ScalarField,
    y: E::ScalarField,
    tau: &Opening<E>,
) -> bool {
    // check e(com*g1^{-y_0}*h^{-hat_y0},g2) == e(v0,r*g2^{-z0})
    let mut lhs_left = com_kzg.into_group();
    lhs_left -= ck.u[0].mul(y);
    lhs_left -= ck.hat_u[0].mul(tau.hat_y);
    let lhs = E::pairing(lhs_left, ck.g2_prepared.clone());
    let rhs_right = ck.r.into_group() - ck.g2.mul(z);
    let rhs = E::pairing(tau.v, rhs_right);
    lhs == rhs
}

/// Compute a KZG commitment for the given vector of evaluations
pub fn plain_kzg_com<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    ck: &CommitmentKey<E, D>,
    evals: &Vec<E::ScalarField>,
    hat_evals: &Vec<E::ScalarField>,
) -> E::G1Affine {
    let plain = <E::G1 as VariableBaseMSM>::msm(&ck.u_lag, evals).unwrap();
    let mask = <E::G1 as VariableBaseMSM>::msm(&ck.hat_u_lag, hat_evals).unwrap();
    (plain + mask).into_affine()
}

/// Check if the given element is in the evaluation domain
/// and if so, return the index of it. Otherwise, return None
pub fn find_in_domain<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    domain: &D,
    z: E::ScalarField,
) -> Option<usize> {
    if domain.vanishing_polynomial().evaluate(&z) == E::ScalarField::zero() {
        // this should happen with negl prob.
        let mut y = None;
        for i in 0..domain.size() {
            if z == domain.element(i) {
                y = Some(i);
            }
        }
        y
    } else {
        None
    }
}

/// Compute the evaluation form of the KZG witness polynomial
/// (f - f(z)) / (X - w_i) when f is given in evaluation form
/// Note: This assumes that w_i is the ith element of the domain
pub fn witness_evals_inside<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    domain: &D,
    evals: &Vec<E::ScalarField>,
    i: usize,
) -> Vec<E::ScalarField> {
    // let x_j denote the elements of the evaluation domain
    // then for each j != i, we can compute the evaluation
    // as in witness_evals_outside,
    // namely, as (evals[j] - evals[i]) / (x_j-x_i)
    // for that, we first compute all denominators
    // using batch inversion
    let fxi = evals[i];
    let xi = domain.element(i);
    let mut nums = Vec::new();
    let mut denoms = Vec::new();
    for j in 0..domain.size() {
        nums.push(evals[j] - fxi);
        if j != i {
            // push x_j-x_i
            denoms.push(domain.element(j) - xi);
        } else {
            // push a sentinel
            denoms.push(E::ScalarField::one());
        }
    }
    batch_inversion(&mut denoms);
    let mut witn_evals = Vec::new();
    for j in 0..domain.size() {
        witn_evals.push(nums[j] * denoms[j]);
    }
    // now witn_evals is correctly computed for all j!=i.
    // whats left is to compute witn_evals[i] properly
    // https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html
    witn_evals[i] = {
        let mut sum = E::ScalarField::zero();
        for j in 0..domain.size() {
            if j == i {
                continue;
            }
            let mut term = nums[j] * (-denoms[j]);
            let d = domain.size();
            let exponent = (j as isize) - (i as isize);
            let exponent = ((exponent + d as isize) as usize) % d;
            term *= domain.element(exponent);
            sum += term;
        }
        sum
    };

    witn_evals
}

/// Compute the evaluation form of the KZG witness polynomial
/// (f - f(z)) / (X - z) when f is given in evaluation form
/// Note: This assumes that z is not in the evaluation domain
pub fn witness_evals_outside<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    domain: &D,
    evals: &Vec<E::ScalarField>,
    z: E::ScalarField,
    fz: E::ScalarField,
) -> Vec<E::ScalarField> {
    // witn_evals[i] = (evals[i] - fz) / (domain[i]-z)
    // we use batch inversion for the denominators
    let mut nums = Vec::new();
    let mut denoms = Vec::new();
    for i in 0..domain.size() {
        nums.push(evals[i] - fz);
        denoms.push(domain.element(i) - z);
    }
    batch_inversion(&mut denoms);
    let mut witn_evals = Vec::new();
    for i in 0..domain.size() {
        witn_evals.push(nums[i] * denoms[i]);
    }
    witn_evals
}

/// Evaluate the polynomial given by the evaluations evals over domain at‚ z
/// Note: This assumes that z is not in the evaluation domain
pub fn evaluate_outside<E: Pairing, D: EvaluationDomain<E::ScalarField>>(
    domain: &D,
    evals: &Vec<E::ScalarField>,
    z: E::ScalarField,
) -> E::ScalarField {
    // formula taken from https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html
    // f(z) = {z^d-1}/d * sum_i (f_i * {w^i}/{z-w^i}), where d is the size of the domain
    let nom = domain.vanishing_polynomial().evaluate(&z);
    let factor = nom / domain.size_as_field_element();
    let mut sum = E::ScalarField::zero();
    for i in 0..domain.size() {
        let omegai = domain.element(i);
        let denom = z - omegai;
        let term = omegai / denom;
        sum += evals[i] * term;
    }
    factor * sum
}


#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{DenseUVPolynomial, Radix2EvaluationDomain};
    use ark_poly::{EvaluationDomain, Evaluations, Polynomial};
    use ark_std::One;
    use ark_std::UniformRand;

    use crate::vectorcommitment::kzg::kzg_utils::find_in_domain;

    use super::{evaluate_outside, get_z0, witness_evals_inside, witness_evals_outside};

    type F = <Bls12_381 as Pairing>::ScalarField;
    type D = Radix2EvaluationDomain<F>;

    /// test function find_in_domain
    #[test]
    fn test_find_in_domain() {
        let mut rng = ark_std::rand::thread_rng();
        let degree = 15;
        let domain = D::new(degree + 1).unwrap();
        let runs = 20;
        for _ in 0..runs {
            // check that it returns None
            // for element outside of domain
            let z = domain.sample_element_outside_domain(&mut rng);
            assert!(find_in_domain::<Bls12_381, D>(&domain, z).is_none());
        }
        // check that it returns the right
        // index for all elements in domain
        for i in 0..domain.size() {
            let fi = find_in_domain::<Bls12_381, D>(&domain, domain.element(i));
            assert!(fi.is_some());
            let j = fi.unwrap();
            assert_eq!(i, j);
        }
    }

    /// test function witness_evals_inside
    #[test]
    fn test_witness_evals_inside() {
        let mut rng = ark_std::rand::thread_rng();
        let degree = 15;
        let domain = D::new(degree + 1).unwrap();
        let runs = 10;
        for _ in 0..runs {
            // sample a random polynomial by sampling coefficients
            let mut coeffs = Vec::new();
            for _ in 0..domain.size() {
                coeffs.push(F::rand(&mut rng));
            }
            let f = DensePolynomial::from_coefficients_vec(coeffs);
            // evaluate the polynomial on the domain
            let evals = domain.fft(&f.coeffs);
            // test that witness_evals_inside works properly over the entire domain
            for i in 0..domain.size() {
                let z = domain.element(i);
                // compute the witness polynomial by long division
                let fshift = &f - &DensePolynomial::from_coefficients_vec(vec![evals[i]]);
                let div = DensePolynomial::from_coefficients_vec(vec![-z, F::one()]);
                let witness_poly = &fshift / &div;
                let witn_evals_expected = domain.fft(&witness_poly.coeffs);
                // compare with what we get from our function
                let witn_evals = witness_evals_inside::<Bls12_381, D>(&domain, &evals, i);
                for i in 0..domain.size() {
                    assert_eq!(witn_evals[i], witn_evals_expected[i]);
                }
            }
        }
    }

    /// test function witness_evals_outside
    #[test]
    fn test_witness_evals_outside() {
        let mut rng = ark_std::rand::thread_rng();
        let degree = 15;
        let domain = D::new(degree + 1).unwrap();
        let runs = 10;
        for _ in 0..runs {
            // sample a random polynomial by sampling coefficients
            let mut coeffs = Vec::new();
            for _ in 0..domain.size() {
                coeffs.push(F::rand(&mut rng));
            }
            let f = DensePolynomial::from_coefficients_vec(coeffs);
            // evaluate the polynomial on the domain
            let evals = domain.fft(&f.coeffs);
            // do a few tests with this polynomial
            for _ in 0..runs {
                // sample a random point outside the domain
                let z = domain.sample_element_outside_domain(&mut rng);
                let fz = f.evaluate(&z);
                let fshift = &f - &DensePolynomial::from_coefficients_vec(vec![fz]);
                // compute the witness polynomial by long division
                let div = DensePolynomial::from_coefficients_vec(vec![-z, F::one()]);
                let witness_poly = &fshift / &div;
                let witn_evals_expected = domain.fft(&witness_poly.coeffs);
                // compare with what we get from our function
                let witn_evals = witness_evals_outside::<Bls12_381, D>(&domain, &evals, z, fz);
                for i in 0..domain.size() {
                    assert_eq!(witn_evals[i], witn_evals_expected[i]);
                }
            }
        }
    }

    /// test function evaluate_outside
    #[test]
    fn test_evaluate_outside() {
        let mut rng = ark_std::rand::thread_rng();
        let degree = 15;
        let domain = D::new(degree + 1).unwrap();
        let runs = 20;
        for _ in 0..runs {
            // sample a random polynomial by sampling random evaluations
            let mut evals = Vec::new();
            for _ in 0..domain.size() {
                evals.push(F::rand(&mut rng));
            }
            let evals = Evaluations::from_vec_and_domain(evals, domain);
            let f = evals.interpolate_by_ref();

            // sample a bunch of points and
            // evaluate the polynomial classically
            // and evaluate it using our function
            // result should then be the same
            // tests will most likely be outside of the domain
            for _ in 0..runs {
                let z = F::rand(&mut rng);
                let expected: F = f.evaluate(&z);
                let obtained: F = evaluate_outside::<Bls12_381, D>(&domain, &evals.evals, z);
                assert_eq!(obtained, expected);
            }
        }
    }

    /// test function get_z0
    #[test]
    fn test_get_z0() {
        // we test the following:
        // (a) if we input the same twice, we get the same output
        // (b) if we input two different things, we get different outputs
        let mut rng = ark_std::rand::thread_rng();
        let runs = 20;
        for _ in 0..runs {
            // sample two random 'commitments'. They should be different with high prob
            let com1 = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
            let com2 = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
            // run the function we want to test
            let z10 = get_z0::<Bls12_381>(&com1);
            let z11 = get_z0::<Bls12_381>(&com1);
            let z20 = get_z0::<Bls12_381>(&com2);
            let z21 = get_z0::<Bls12_381>(&com2);
            assert_eq!(z10, z11);
            assert_eq!(z20, z21);
            assert_ne!(z10, z20);
        }
    }
}
