use ark_std::{end_timer, start_timer};
use jackpot::lotteryscheme::{jack::get_jack_parameters, jack_pre::JackPre, LotteryScheme};

/* run with `cargo run --release --features print-trace parallel` */

fn main() {
    let mut rng = ark_std::rand::thread_rng();

    let num_lotteries = (1 << 10) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    let keygen_timer = start_timer!(|| "keygen_fk 2^10 512");
    <JackPre as LotteryScheme>::gen(&mut rng, &par);
    end_timer!(keygen_timer);

    let num_lotteries = (1 << 15) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    let keygen_timer = start_timer!(|| "keygen_fk 2^15 512");
    <JackPre as LotteryScheme>::gen(&mut rng, &par);
    end_timer!(keygen_timer);

    let num_lotteries = (1 << 20) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    let keygen_timer = start_timer!(|| "keygen_fk 2^20 512");
    <JackPre as LotteryScheme>::gen(&mut rng, &par);
    end_timer!(keygen_timer);
}
