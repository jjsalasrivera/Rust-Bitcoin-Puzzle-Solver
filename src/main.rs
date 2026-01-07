use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::str::FromStr;

use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use log::{error, info, warn};
use rand::Rng;
use rayon::prelude::*;

const SECONDS_LOG: u64 = 10;
const FOUND_FILE: &str = "found.txt";

struct BitcoinChecker {
    checked_addresses: Arc<AtomicUsize>,
    from: u128,
    to: u128,
    range_size: u128,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    found: Arc<AtomicBool>,
    target_address: Address,
}

impl BitcoinChecker {
    fn new(from: String, to: String, target: String) -> Self {
        let from_num = u128::from_str_radix(from.as_str(), 16).expect("invalid 'from' number");
        let to_num = u128::from_str_radix(to.as_str(), 16).expect("invalid 'to' number");
        let range_size = to_num - from_num;

        BitcoinChecker {
            checked_addresses: Arc::new(AtomicUsize::new(0)),
            from: from_num,
            to: to_num,
            range_size,
            secp: Secp256k1::new(),
            found: Arc::new(AtomicBool::new(false)),
            target_address: Address::from_str(&target).unwrap()
                .require_network(Network::Bitcoin).unwrap(),
        }
    }

    fn main(&self) {
        // check if file exist
        let path = Path::new(FOUND_FILE);
        if path.exists()
        {
            info!("Private key found in {}", FOUND_FILE);
        } else {
            info!("Iniciando búsqueda de direcciones entre {} y {}", self.from, self.to);
            self.run();
        }
    }



    fn run(&self) {
        let num_threads = rayon::current_num_threads() as u128;
        let sub_range_size = self.range_size / num_threads;
        let block_size = 100_000u128;
        let mut last_log = Instant::now();
        let mut last_checks = 0;

        loop {
            if self.found.load(Ordering::Relaxed) {
                break;
            }

            (0..num_threads as usize).into_par_iter().for_each(|thread_id| {
                let sub_from = self.from + thread_id as u128 * sub_range_size;
                let sub_to = if thread_id as u128 == num_threads - 1 { self.to } else { sub_from + sub_range_size };
                let max_start = sub_to.saturating_sub(block_size);
                let start = if sub_from > max_start { sub_from } else {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(sub_from..=max_start)
                };
                
                let mut key_bytes = [0u8; 32];
                let mut local_found = false;
                
                for i in 0..block_size {
                    let num = start + i;
                    let num_bytes = num.to_be_bytes();
                    key_bytes[16..].copy_from_slice(&num_bytes);
                    
                    if let Ok(key) = PrivateKey::from_slice(&key_bytes, Network::Bitcoin) {
                        let public_key = PublicKey::from_private_key(&self.secp, &key);
                        let address = Address::p2pkh(&public_key, Network::Bitcoin);

                        if address == self.target_address {
                            info!("\n¡ENCONTRADA DIRECCIÓN CON BALANCE!");
                            info!("Clave Privada: {}", hex::encode(&key_bytes));
                            info!("WIF: {}", key.to_wif());
                            info!("Dirección: {}", address);
                            self.found.swap(true, Ordering::SeqCst);
                            local_found = true;

                            if let Err(e) = Self::log_found_address(
                                &key_bytes,
                                &key.to_wif(),
                                &address.to_string()
                            ) {
                                warn!("Error al escribir en archivo: {}", e);
                            }
                        }
                    }
                }
            });

            self.checked_addresses.fetch_add((num_threads as u128 * block_size) as usize, Ordering::Relaxed);

            if last_log.elapsed() >= Duration::from_secs(SECONDS_LOG) {
                let total_checked = self.checked_addresses.load(Ordering::Relaxed);
                let elapsed = last_log.elapsed().as_secs_f64();
                let partial_checks = (total_checked - last_checks) as f64;
                let rate = (partial_checks / elapsed) as u64;
                info!("Direcciones revisadas: {} - Tasa de calculo: {} addr/s", total_checked, rate);
                last_log = Instant::now();
                last_checks = total_checked;
            }
        }
    }

    fn log_found_address(
        private_key: &[u8],
        wif: &str,
        address: &str
    ) -> Result<(), std::io::Error> {
        let file_path = Path::new(FOUND_FILE);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;

        let mut writer = BufWriter::new(file);

        writeln!(writer, "ENCONTRADA DIRECCIÓN CON BALANCE!")?;
        writeln!(writer, "Private Key: {}", hex::encode(private_key))?;
        writeln!(writer, "WIF: {}", wif)?;
        writeln!(writer, "Address: {}", address)?;

        Ok(())
    }
}

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();

    let mut puzzles: HashMap<u8, (String, String, String)> = HashMap::new();
    puzzles.insert(69, ("100000000000000000".to_string(), "1fffffffffffffffff".to_string(), "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG".to_string()));
    puzzles.insert(70, ("200000000000000000".to_string(), "3fffffffffffffffff".to_string(), "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR".to_string()));
    puzzles.insert(71, ("400000000000000000".to_string(),"7fffffffffffffffff".to_string(),"1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU".to_string()));
    puzzles.insert(72, ("800000000000000000".to_string(), "ffffffffffffffffff".to_string(),"1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR".to_string()));
    puzzles.insert(73, ("1000000000000000000".to_string(), "1ffffffffffffffffff".to_string(), "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4".to_string()));
    puzzles.insert(74, ("2000000000000000000".to_string(), "3ffffffffffffffffff".to_string(), "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv".to_string()));
    // add more puzzless from https://btcpuzzle.info/es/puzzle

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        error!("Use: {} <number>", args[0]);
        error!("Valid numbers: ");
        for k in puzzles.keys() {
            error!("{}", k);
        }
        return;
    }

    let numero= match args[1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: Argument must be a number");
            return;
        }
    };

    match puzzles.get(&numero) {
        Some((a, b, c)) => {
            let checker = BitcoinChecker::new(a.to_string(), b.to_string(), c.to_string());
            info!("{}: {} {} {}", numero, a, b, c);

            checker.main();
        },
        None => {
            error!("Number not found");
            error!("Valid numbers: ");
            for k in puzzles.keys() {
                error!("{}", k);
            }
        },
    }
}