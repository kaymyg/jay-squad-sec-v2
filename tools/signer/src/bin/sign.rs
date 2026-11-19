//! jaysec-sign — sign a payload into a verifiable Jay Squad Sec patch file.
//!
//!   jaysec-sign --key jaysec-signing.key --product jay-squad-sec-android \
//!               --version 2 --payload rules.bin --out rules-v2.jssp
//!
//! The output is a self-contained `.jssp` container the product verifies with
//! the embedded public key before applying. Run offline, on the machine that
//! holds the secret key.

use std::process::exit;

fn main() {
    let (mut key, mut product, mut version, mut payload, mut out) =
        (None, None, None, None, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => key = args.next(),
            "--product" => product = args.next(),
            "--version" => version = args.next(),
            "--payload" => payload = args.next(),
            "--out" => out = args.next(),
            "--help" | "-h" => {
                usage();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                exit(2);
            }
        }
    }

    let (key, product, version, payload_path, out) =
        match (key, product, version, payload, out) {
            (Some(k), Some(p), Some(v), Some(pl), Some(o)) => (k, p, v, pl, o),
            _ => {
                usage();
                exit(2);
            }
        };

    let version: u64 = match version.parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("--version must be a non-negative integer");
            exit(2);
        }
    };
    // Devices accept only versions strictly newer than installed (>= 1 on a
    // fresh device), and a huge version would be unrecoverable: once a device
    // installs it, no later patch can ever be newer. Keep versions sane.
    if version == 0 || version > u64::from(u32::MAX) {
        eprintln!("--version must be between 1 and {} (got {version})", u32::MAX);
        exit(2);
    }

    let sk_bytes = read_or_die(&key, "secret key");
    let sk: [u8; 64] = match sk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("secret key file must be exactly 64 bytes (got {})", sk_bytes.len());
            exit(1);
        }
    };
    let payload = read_or_die(&payload_path, "payload");

    let patch = match jay_squad_sec_update::sign_patch(&sk, product.as_str(), version, payload) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("signing failed: {e}");
            exit(1);
        }
    };
    let encoded = patch.encode();
    if let Err(e) = std::fs::write(&out, &encoded) {
        eprintln!("cannot write {out}: {e}");
        exit(1);
    }

    println!("Signed patch written: {out}");
    println!("  product: {product}");
    println!("  version: {version}");
    println!("  payload: {} bytes", patch.payload.len());
    println!("  file:    {} bytes", encoded.len());
}

fn read_or_die(path: &str, what: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {what} {path}: {e}");
            exit(1);
        }
    }
}

fn usage() {
    eprintln!(
        "jaysec-sign --key KEYFILE --product ID --version N --payload FILE --out PATCH.jssp"
    );
}
