use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::key::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, PublicKey};
use log::{error, info, warn};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Num, Zero};
use rand::{thread_rng, RngCore};
use rayon::prelude::*;

const MAX_CHUNK: usize = 50_000;  // Chunk más grande para reducir overhead
const SECONDS_LOG: u64 = 10;

struct BitcoinChecker {
    checked_addresses: Arc<AtomicUsize>,
    from: BigUint,
    to: BigUint,
    range_size: BigUint,
    target: String,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl BitcoinChecker {
    fn new(from: String, to: String, target: String) -> Self {
        let from_num = BigUint::from_str_radix(from.as_str(), 16).expect("invalid 'from' number");
        let to_num = BigUint::from_str_radix(to.as_str(), 16).expect("invalid 'to' number");
        let range_size = &to_num - &from_num;

        BitcoinChecker {
            checked_addresses: Arc::new(AtomicUsize::new(0)),
            from: from_num,
            to: to_num,
            range_size,
            target,
            secp: Secp256k1::new(),
        }
    }

    fn main(&self) {
        info!("Iniciando búsqueda de direcciones entre {} y {}", self.from, self.to);
        self.run();
    }

    fn run(&self) {
        let mut last_log = Instant::now();
        let target_addr = Address::from_str(&self.target).unwrap().assume_checked();

        loop {
            (0..MAX_CHUNK).into_par_iter().for_each(|_| {
                let mut key_bytes = [0u8; 32];
                let mut rng = thread_rng();

                // Generación más eficiente usando números dentro del rango
                let random_num = &self.from + (rng.gen_biguint_below(&self.range_size));
                let bytes = random_num.to_bytes_be();
                let start = 32 - bytes.len();
                key_bytes[start..].copy_from_slice(&bytes);

                self.process_private_key(&key_bytes);
            });

            self.checked_addresses.fetch_add(MAX_CHUNK, Ordering::Relaxed);

            if last_log.elapsed() >= Duration::from_secs(SECONDS_LOG) {
                info!("Direcciones revisadas: {}",
                    self.checked_addresses.load(Ordering::Relaxed)
                );
                last_log = Instant::now();
            }
        }
    }

    fn process_private_key(&self, private_key: &[u8]) {
        if let Ok(key) = PrivateKey::from_slice(private_key, Network::Bitcoin) {
            let compressed_pk = CompressedPublicKey::from_private_key(&self.secp, &key);

            // Dirección verificada con conversión explícita
            let address = Address::p2wpkh(&compressed_pk.unwrap(), Network::Bitcoin);

            if address.to_string() == self.target {
                info!("\n¡ENCONTRADA DIRECCIÓN CON BALANCE!");
                info!("Clave Privada: {}", hex::encode(private_key));
                info!("WIF: {}", key.to_wif());
                info!("Dirección: {}", address);

                if let Err(e) = Self::log_found_address(
                    private_key,
                    &key.to_wif(),
                    &address.to_string()
                ) {
                    warn!("Error al escribir en archivo: {}", e);
                }
            }
        }
    }

    fn log_found_address(
        private_key: &[u8],
        wif: &str,
        address: &str
    ) -> Result<(), std::io::Error> {
        let file_path = Path::new("found.txt");
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
            let targets: Vec<String> = puzzles
                .values()
                .map(|(_, _, target)| target.clone())
                .collect();

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