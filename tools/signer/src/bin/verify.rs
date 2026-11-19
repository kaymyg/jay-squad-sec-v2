//! jaysec-verify — self-check a patch before shipping, using the public key.
//!
//! This runs the exact same verification the product will run, so you can
//! confirm a patch is acceptable (authentic, right product, newer than the
//! stated installed version) before distributing it.
//!
//!   jaysec-verify --pub jaysec-signing.pub --product jay-squad-sec-android \
//!                 --current 1 --patch rules-v2.jssp

use jay_squad_sec_update::{SignedPatch, Verifier};
use std::process::exit;

fn main() {
    let (mut pubfile, mut product, mut current, mut patchfile) = (None, None, None, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--pub" => pubfile = args.next(),
            "--product" => product = args.next(),
            "--current" => current = args.next(),
            "--patch" => patchfile = args.next(),
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

    let (pubfile, product, current, patchfile) =
        match (pubfile, product, current, patchfile) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => {
                usage();
                exit(2);
            }
        };

    let current: u64 = current.parse().unwrap_or_else(|_| {
        eprintln!("--current must be a non-negative integer");
        exit(2);
    });

    let pub_hex = std::fs::read_to_string(&pubfile).unwrap_or_else(|e| {
        eprintln!("cannot read public key {pubfile}: {e}");
        exit(1);
    });
    let pk = match from_hex_32(pub_hex.trim()) {
        Some(k) => k,
        None => {
            eprintln!("public key file must be 64 hex chars (32 bytes)");
            exit(1);
        }
    };

    let patch_bytes = std::fs::read(&patchfile).unwrap_or_else(|e| {
        eprintln!("cannot read patch {patchfile}: {e}");
        exit(1);
    });
    let patch = match SignedPatch::decode(&patch_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("REJECTED: {e}");
            exit(1);
        }
    };

    let verifier = Verifier::new(pk, product, current);
    match verifier.verify(&patch) {
        Ok(v) => {
            println!("OK: patch version {} accepted ({} bytes payload)", v.patch_version, v.payload.len());
        }
        Err(e) => {
            eprintln!("REJECTED: {e}");
            exit(1);
        }
    }
}

fn from_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn usage() {
    eprintln!("jaysec-verify --pub PUBFILE --product ID --current N --patch PATCH.jssp");
}
