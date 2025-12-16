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
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;

const MAX_CHUNK: usize = 1_000_000;  // Chunk más grande para reducir overhead
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
    mask: u128,
    needs_rejection: bool,
}

impl BitcoinChecker {
    fn new(from: String, to: String, target: String) -> Self {
        let from_num = u128::from_str_radix(from.as_str(), 16).expect("invalid 'from' number");
        let to_num = u128::from_str_radix(to.as_str(), 16).expect("invalid 'to' number");
        let range_size = &to_num - &from_num;
        let num_bits = 128 - range_size.leading_zeros();

        let mask = if num_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << num_bits) - 1
        };
        let is_power_of_two = range_size.count_ones() == 1;
        let needs_rejection = !is_power_of_two;

        BitcoinChecker {
            checked_addresses: Arc::new(AtomicUsize::new(0)),
            from: from_num,
            to: to_num,
            range_size,
            secp: Secp256k1::new(),
            found: Arc::new(AtomicBool::new(false)),
            target_address: Address::from_str(&target).unwrap()
                .require_network(Network::Bitcoin).unwrap(),
            mask,
            needs_rejection,
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

    fn run_with_rejection(&self) {
        let mut last_log = Instant::now();
        let mut lasts_checks: usize = 0;

        loop {
            (0..MAX_CHUNK).into_par_iter().for_each(|_| {
                thread_local! {
                    static RNG: std::cell::RefCell<ChaCha20Rng> =
                        std::cell::RefCell::new(ChaCha20Rng::from_entropy());
                }

                let mut key_bytes = [0u8; 32];

                RNG.with(|rng| {
                    let mut rng = rng.borrow_mut();

                    let random_num = loop {
                        // Genera 16 bytes aleatorios
                        let mut temp_bytes = [0u8; 16];
                        rng.fill(&mut temp_bytes[..]);
                        let random = u128::from_be_bytes(temp_bytes);

                        // Aplica máscara
                        let masked = random & self.mask;

                        // Rejection sampling
                        if masked < self.range_size {
                            break self.from + masked;
                        }
                    };

                    // Convierte a bytes
                    let num_bytes = random_num.to_be_bytes();
                    key_bytes[16..].copy_from_slice(&num_bytes);
                });

                self.process_private_key(&key_bytes);
            });

            self.checked_addresses.fetch_add(MAX_CHUNK, Ordering::Relaxed);

            if last_log.elapsed() >= Duration::from_secs(SECONDS_LOG) {
                let total_checked = self.checked_addresses.load(Ordering::Relaxed);
                let elapsed = last_log.elapsed().as_secs() as usize;
                let partial_checks = total_checked - lasts_checks;

                info!("Direcciones revisadas: {} - Tasa de calculo: {} addr/s",
                    self.checked_addresses.load(Ordering::Relaxed), partial_checks / elapsed
                );
                last_log = Instant::now();
                lasts_checks = total_checked;
            }

            if self.found.load(Ordering::Relaxed) {
                break;
            }
        }
    }

    fn run_without_rejection(&self) {
        let mut last_log = Instant::now();

        loop {
            (0..MAX_CHUNK).into_par_iter().for_each(|_| {
                thread_local! {
                    static RNG: std::cell::RefCell<ChaCha20Rng> =
                        std::cell::RefCell::new(ChaCha20Rng::from_entropy());
                }

                let key_bytes = RNG.with(|rng| {
                    let mut rng = rng.borrow_mut();
                    let mut key = [0u8; 32];

                    // Genera solo los últimos 16 bytes
                    rng.fill(&mut key[16..]);

                    // Lee como u128, aplica máscara y offset
                    let mut num = u128::from_be_bytes([
                        key[16], key[17], key[18], key[19],
                        key[20], key[21], key[22], key[23],
                        key[24], key[25], key[26], key[27],
                        key[28], key[29], key[30], key[31],
                    ]);

                    num &= self.mask;
                    num += self.from;

                    // Escribe de vuelta
                    let final_bytes = num.to_be_bytes();
                    key[16..].copy_from_slice(&final_bytes);

                    key
                });

                self.process_private_key(&key_bytes);
            });

            self.checked_addresses.fetch_add(MAX_CHUNK, Ordering::Relaxed);

            if last_log.elapsed() >= Duration::from_secs(SECONDS_LOG) {
                info!("Direcciones revisadas: {}",
                    self.checked_addresses.load(Ordering::Relaxed)
                );
                last_log = Instant::now();
            }

            if self.found.load(Ordering::Relaxed) {
                break;
            }
        }
    }

    fn run(&self) {
        if self.needs_rejection {
            // Calcula tasa de rechazo esperada
            let rejection_rate = 1.0 - (self.range_size as f64 / (self.mask as f64 + 1.0));

            // Si la tasa de rechazo es baja (<10%), usa rejection sampling
            // Si es alta, usa el método sin rejection (sesgo despreciable)
            if rejection_rate < 0.10 {
                println!("Usando rejection sampling (tasa rechazo: {:.2}%)", rejection_rate * 100.0);
                self.run_with_rejection();
            } else {
                println!("Usando método sin rejection (sesgo despreciable para búsqueda)");
                self.run_without_rejection();
            }
        } else {
            println!("Rango es potencia de 2 - sin rejection necesario");
            self.run_without_rejection();
        }
    }

    #[inline(always)]
    fn process_private_key(&self, private_key: &[u8]) {
        if let Ok(key) = PrivateKey::from_slice(private_key, Network::Bitcoin) {
            //let compressed_pk = CompressedPublicKey::from_private_key(&self.secp, &key);

            // Dirección verificada con conversión explícita
            //let address = Address::p2wpkh(&compressed_pk.unwrap(), Network::Bitcoin);
            let public_key = PublicKey::from_private_key(&self.secp, &key);
            let address = Address::p2pkh(&public_key, Network::Bitcoin);

            if address == self.target_address {
                info!("\n¡ENCONTRADA DIRECCIÓN CON BALANCE!");
                info!("Clave Privada: {}", hex::encode(private_key));
                info!("WIF: {}", key.to_wif());
                info!("Dirección: {}", address);
                self.found.swap(true, Ordering::SeqCst);

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