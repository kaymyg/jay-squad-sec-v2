//! jaysec-keygen — generate an offline ed25519 signing keypair.
//!
//! The secret key signs patches and must NEVER leave the builder's offline
//! machine. The public key is embedded in the shipped product so devices can
//! verify patches. Run this once; guard the secret key like any signing secret.
//!
//!   jaysec-keygen [--out jaysec-signing.key] [--pub jaysec-signing.pub]

use std::io::Write;
use std::process::exit;

fn main() {
    let mut out = "jaysec-signing.key".to_string();
    let mut pubout = "jaysec-signing.pub".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = args.next().unwrap_or(out),
            "--pub" => pubout = args.next().unwrap_or(pubout),
            "--help" | "-h" => {
                println!("jaysec-keygen [--out KEYFILE] [--pub PUBFILE]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                exit(2);
            }
        }
    }

    let (pk, sk) = jay_squad_sec_update::generate_keypair();

    if let Err(e) = write_secret(&out, &sk) {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            eprintln!("refusing to overwrite existing key file {out} (remove it or pass --out NEWPATH)");
        } else {
            eprintln!("failed to write secret key {out}: {e}");
        }
        exit(1);
    }
    let pk_hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
    if let Err(e) = std::fs::write(&pubout, format!("{pk_hex}\n")) {
        eprintln!("failed to write public key {pubout}: {e}");
        exit(1);
    }

    println!("Secret signing key (KEEP OFFLINE, never ship): {out}");
    println!("Public key (embed in the product):             {pubout}");
    println!();
    println!("public key (hex): {pk_hex}");
    println!();
    println!("Embed in the product as:");
    let arr: Vec<String> = pk.iter().map(|b| format!("0x{b:02x}")).collect();
    println!("pub const BUILDER_PUBLIC_KEY: [u8; 32] = [{}];", arr.join(", "));
}

#[cfg(unix)]
fn write_secret(path: &str, sk: &[u8; 64]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    // create_new refuses to clobber an existing file, which could keep weak
    // permissions or be a planted symlink redirecting the secret elsewhere.
    // mode(0o600) takes effect because the file is newly created.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600) // owner read/write only
        .open(path)?;
    f.write_all(sk)
}

#[cfg(not(unix))]
fn write_secret(path: &str, sk: &[u8; 64]) -> std::io::Result<()> {
    // No Unix permission bits here; at least refuse to overwrite an existing
    // file. Treat the secret key as sensitive and lock down its location.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    std::io::Write::write_all(&mut f, sk)
}
