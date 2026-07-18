//! Dev helper: emit a self-signed cert.pem + key.pem for a host into a dir.
//! Used by smoke tests to stand up a local HTTPS origin.
//!
//!   cargo run -p flowmint-tls --example gen_selfsigned -- <host> <out_dir>

use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1".into());
    let dir = args.get(2).cloned().unwrap_or_else(|| ".".into());
    fs::create_dir_all(&dir).unwrap();

    let certified = rcgen::generate_simple_self_signed(vec![host.clone()]).unwrap();
    fs::write(format!("{dir}/cert.pem"), certified.cert.pem()).unwrap();
    fs::write(format!("{dir}/key.pem"), certified.key_pair.serialize_pem()).unwrap();
    println!("wrote cert.pem + key.pem for {host} into {dir}");
}
