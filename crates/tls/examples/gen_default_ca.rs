//! 生成软件内置的**默认共享 CA**，写入 `crates/tls/default-ca/`（随后提交到仓库）。
//!
//! ⚠️ 生成物的**私钥会公开**。凡是安装/信任了这张默认 CA 的机器，任何拿到本项目的人
//! 都能伪造任意站点证书并解密其 HTTPS——仅用于图省事的临时调试，绝不要在正式/敏感机器上装。
//!
//! 运行（在仓库根目录）：`cargo run -p flowmint-tls --example gen_default_ca`

use std::fs;

fn main() {
    let (cert_pem, key_pem) = flowmint_tls::CertAuthority::generate_pem(
        "FlowMint Default CA (INSECURE public shared key - testing only)",
    )
    .expect("生成默认 CA 失败");

    fs::create_dir_all("crates/tls/default-ca").expect("建目录失败");
    fs::write("crates/tls/default-ca/ca.pem", cert_pem).expect("写 ca.pem 失败");
    fs::write("crates/tls/default-ca/ca.key.pem", key_pem).expect("写 ca.key.pem 失败");
    println!("已生成 crates/tls/default-ca/ca.pem + ca.key.pem");
}
