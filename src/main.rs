use ark_std::{start_timer, end_timer};
use jackpot::lotteryscheme::{jack::get_jack_parameters, LotteryScheme, jack_pre::JackPre};

fn main() {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1<<10) - 2;
    let k = 1000;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    let keygen_timer = start_timer!(|| "keygen_fk 2^10 1000");
    <JackPre as LotteryScheme>::gen(&mut rng, &par);
    end_timer!(keygen_timer);
}