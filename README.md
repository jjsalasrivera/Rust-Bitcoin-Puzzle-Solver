# 🧩 Rust Bitcoin Puzzle Solver

This is a Rust program designed to attempt solving some of the challenges from [btcpuzzle.info](https://btcpuzzle.info/), by searching for Bitcoin private keys that correspond to known addresses with balance.

> ⚠️ **Disclaimer:** This project is for educational and research purposes only. The Bitcoin private key space is astronomically large, and brute-force approaches are not feasible for real-world key recovery. Do **not** use this for malicious purposes.

## 🚀 How It Works

The program randomly generates private keys within a specific range (defined by each puzzle), derives their corresponding public addresses, and compares them against a target address. If a match is found, the private key and address are saved to `found.txt`.

### Example of built-in puzzles:

| Puzzle ID | Private Key Range | Target Address |
|-----------|-------------------|----------------|
|69 | 100000000000000000 | 1fffffffffffffffff | 19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG |
|71 | 400000000000000000 | 7fffffffffffffffff | 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU |
| 72 | 800000000000000000 | ffffffffffffffff | 1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR |
| 73 | 1000000000000000000 | 1ffffffffffffffffff | 12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4 |
| 74 | 2000000000000000000 | 3ffffffffffffffffff | 1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv |
