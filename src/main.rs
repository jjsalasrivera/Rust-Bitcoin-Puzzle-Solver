use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::key::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, PublicKey};
use log::{error, info, warn};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;
use rand::thread_rng;
use rayon::prelude::*;

const MAX_CHUNK: usize = 5000;
const SECONDS_LOG: u64 = 10;

struct BitcoinChecker {
    checked_addresses: Arc<AtomicUsize>,
    from: BigUint,
    to: BigUint,
    target: String,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl BitcoinChecker {
    fn new(from: String, to: String, target: String) -> Self {
        BitcoinChecker {
            checked_addresses: Arc::new(AtomicUsize::new(0)),
            from: BigUint::from_str_radix(from.as_str(), 16).expect("invalid 'from' number"),
            to: BigUint::from_str_radix(to.as_str(), 16).expect("invalid 'to' number"),
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

        loop {
            (0..MAX_CHUNK).into_par_iter().for_each(|_| {
                let key = self.generate_private_key();
                self.process_private_key(&key);
            });

            self.checked_addresses.fetch_add(MAX_CHUNK, Ordering::SeqCst);

            if last_log.elapsed() >= Duration::from_secs(SECONDS_LOG) {
                info!("Direcciones revisadas: {}",
                self.checked_addresses.load(Ordering::SeqCst)
            );
                last_log = Instant::now();
            }
        }
    }
    #[allow(dead_code)]
    #[warn(dead_code)]
    fn process_keys_batch(&self) {
        let keys: Vec<Vec<u8>> = (0..MAX_CHUNK)
            .map(|_| Self::generate_private_key(&self))
            .collect();

        let len = keys.len();

        for key in keys {
            self.process_private_key(&key);
        }

        self.checked_addresses.fetch_add(len, Ordering::SeqCst);
    }

    fn generate_private_key(&self) -> Vec<u8> {
        let mut rng = thread_rng();
        let random_num = rng.gen_biguint_range(&self.from, &self.to);

        let random_bytes = random_num.to_bytes_be();
        let mut array256 = [0u8; 32];
        let start = 32 - random_bytes.len();
        array256[start..].copy_from_slice(&random_bytes);

        array256.to_vec()
    }

    fn process_private_key(&self, private_key: &[u8]) {
        // Convert private key bytes to Bitcoin PrivateKey
        match PrivateKey::from_slice(&private_key, Network::Bitcoin) {
            Ok(key) => {
                let public_key = PublicKey::from_private_key(&self.secp, &key);
                let compressed_pk_res = CompressedPublicKey::from_private_key(&self.secp, &key);
                let addresses_types = if let Ok(compressed_pk) = compressed_pk_res {
                    vec![
                        Address::p2pkh(&public_key, Network::Bitcoin),
                        Address::p2shwpkh(&compressed_pk, Network::Bitcoin),
                        Address::p2wpkh(&compressed_pk, Network::Bitcoin)
                    ]
                } else {
                    vec![
                        Address::p2pkh(&public_key, Network::Bitcoin),
                    ]
                };

                for address in addresses_types.iter() {
                    let address_str = address.to_string();

                    if self.check_address_balance(&address_str) {
                        info!("\n¡ENCONTRADA DIRECCIÓN CON BALANCE!");
                        info!("Clave Privada: {}", hex::encode(private_key));
                        info!("WIF: {}", key.to_wif());
                        info!("Dirección: {}", address_str);

                        if let Err(e) = Self::log_found_address(
                            private_key,
                            &key.to_wif(),
                            &address_str
                        ) {
                            warn!("Error al escribir en archivo: {}", e);
                        }
                    }
                }
            }
            Err(e) => warn!("Error creating private key: {}", e)
        }
    }

    fn check_address_balance(&self, address: &str) -> bool {
        address == self.target
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