//! Per-profile CA and on-demand MITM leaf minting (design §7.2).
//!
//! Each capture profile owns its own CA. The CA cert (public) is exported for
//! the user to explicitly trust; the private key is persisted in the profile
//! directory.
//!
//! SECURITY NOTE / TODO: design §7.2 requires the CA private key live in the OS
//! keychain (DPAPI / Keychain / libsecret) and export be gated behind a second
//! confirmation. This MVP stores `ca.key.pem` on disk in the profile dir — an
//! honest interim; keychain integration is a tracked follow-up. MITM is opt-in
//! per profile and never enabled by default.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use std::net::IpAddr;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no crypto signing key for minted leaf")]
    SigningKey,
}

pub type Result<T> = std::result::Result<T, TlsError>;

/// A profile's certificate authority. Mints and caches leaf certs per SNI host.
pub struct CertAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_pem: String,
    /// 原始 PEM 对应的 DER（= 实际安装/被信任的那张证书；不能用重签后的 ca_cert.der()）。
    ca_der: Vec<u8>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

// 内置默认共享 CA（公开、私钥公开——见 bundled_default 的安全警告）。
// 由 `cargo run -p flowmint-tls --example gen_default_ca` 生成后提交。
const DEFAULT_CA_PEM: &str = include_str!("../default-ca/ca.pem");
const DEFAULT_CA_KEY_PEM: &str = include_str!("../default-ca/ca.key.pem");

impl CertAuthority {
    /// 从 (ca_cert, ca_key, ca_pem) 组装，附带从原始 PEM 解析出的 DER。
    fn build(ca_cert: rcgen::Certificate, ca_key: KeyPair, ca_pem: String) -> Self {
        let ca_der = pem::parse(&ca_pem)
            .map(|p| p.contents().to_vec())
            .unwrap_or_default();
        Self {
            ca_cert,
            ca_key,
            ca_pem,
            ca_der,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Load the CA from `dir` (ca.pem + ca.key.pem), creating a fresh one on
    /// first use.
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let cert_path: PathBuf = dir.join("ca.pem");
        let key_path: PathBuf = dir.join("ca.key.pem");

        if cert_path.exists() && key_path.exists() {
            let ca_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            let ca_key = KeyPair::from_pem(&key_pem)?;
            // Reconstruct issuer params from the stored CA cert so we can sign
            // leaves. Subject DN + public key are preserved, so leaves chain to
            // the already-trusted ca.pem.
            let params = CertificateParams::from_ca_cert_pem(&ca_pem)?;
            let ca_cert = params.self_signed(&ca_key)?;
            Ok(Self::build(ca_cert, ca_key, ca_pem))
        } else {
            let (ca_cert, ca_key) = Self::generate_ca()?;
            let ca_pem = ca_cert.pem();
            fs::write(&cert_path, &ca_pem)?;
            fs::write(&key_path, ca_key.serialize_pem())?;
            Ok(Self::build(ca_cert, ca_key, ca_pem))
        }
    }

    /// 从内存 PEM 构造 CA（不落盘）：SDK「证书不落地」与内置默认 CA 都走这里。
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let ca_key = KeyPair::from_pem(key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)?;
        let ca_cert = params.self_signed(&ca_key)?;
        Ok(Self::build(ca_cert, ca_key, cert_pem.to_string()))
    }

    /// 软件内置的**默认共享 CA**（编译进二进制）。⚠️ 私钥是公开的——任何拿到本项目的人
    /// 都能用它伪造任意站点证书。仅用于图省事的临时调试；正式/敏感环境请用本机生成的 CA。
    pub fn bundled_default() -> Result<Self> {
        Self::from_pem(DEFAULT_CA_PEM, DEFAULT_CA_KEY_PEM)
    }

    /// 生成一张新 CA 的 (cert_pem, key_pem)（供生成内置默认 CA 的工具用）。
    pub fn generate_pem(common_name: &str) -> Result<(String, String)> {
        let params = Self::ca_params(common_name)?;
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    fn ca_params(common_name: &str) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // 根 CA 无 398 天限制；给个较长有效期，向前挪一天容忍时钟偏差。
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(3650); // ~10 年
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "FlowMint");
        params.distinguished_name = dn;
        Ok(params)
    }

    fn generate_ca() -> Result<(rcgen::Certificate, KeyPair)> {
        let params = Self::ca_params("FlowMint Local CA")?;
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok((cert, key))
    }

    /// The CA certificate in PEM, for the user to install/trust.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The CA certificate in DER（iOS 等更认这个格式的 `.cer`；与 `ca_pem()` 是同一张证书）。
    pub fn ca_der(&self) -> Vec<u8> {
        self.ca_der.clone()
    }

    /// Mint (or fetch cached) a leaf cert+key for `host`, as a rustls
    /// [`CertifiedKey`] ready for a server handshake.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.cache.lock().unwrap().get(host) {
            return Ok(hit.clone());
        }

        // IP-literal targets need an IP SAN, not a DNS SAN, or clients reject
        // the leaf. Hostnames get a DNS SAN.
        let mut params = if let Ok(ip) = host.parse::<IpAddr>() {
            let mut p = CertificateParams::new(Vec::<String>::new())?;
            p.subject_alt_names.push(SanType::IpAddress(ip));
            p
        } else {
            CertificateParams::new(vec![host.to_string()])?
        };
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Apple 要求服务器证书有效期 ≤ 398 天（对本地根签出的叶子也照查）；
        // 取 397 天并向前挪一天容忍时钟偏差，确保 iOS/macOS 能握手。
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(397);

        let leaf_key = KeyPair::generate()?;
        let leaf_cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|_| TlsError::SigningKey)?;

        let certified = Arc::new(CertifiedKey::new(vec![cert_der], signing_key));
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), certified.clone());
        Ok(certified)
    }
}

impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority").finish_non_exhaustive()
    }
}

/// Resolver that always returns one pre-minted leaf, regardless of SNI.
#[derive(Debug)]
struct FixedResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Build a rustls [`ServerConfig`] for one known CONNECT target `host`.
///
/// The leaf is minted up front for `host`, so this works even when the client
/// omits SNI (e.g. Windows schannel connecting to an IP literal).
pub fn server_config_for_host(ca: Arc<CertAuthority>, host: &str) -> Result<Arc<ServerConfig>> {
    let leaf = ca.leaf_for(host)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedResolver(leaf)));
    Ok(Arc::new(cfg))
}

/// Build a rustls [`ClientConfig`] for upstream TLS, trusting the Mozilla root
/// set (design §7.2: real verification by default; insecure is a flagged option
/// added later).
pub fn upstream_client_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Build an upstream [`ClientConfig`] that does NOT verify server certs.
///
/// Design §7.2 item 4: `insecureSkipVerify` is permitted ONLY as an explicit
/// test-profile option and must be surfaced (red) in UI and audit logs. Use
/// only against origins you control (e.g. self-signed dev servers).
pub fn insecure_upstream_client_config() -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoVerify(provider)))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

mod danger {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerify(pub Arc<CryptoProvider>);

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_persists_and_mints_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertAuthority::load_or_create(dir.path()).unwrap();
        assert!(ca.ca_pem().contains("BEGIN CERTIFICATE"));
        let a = ca.leaf_for("example.com").unwrap();
        let b = ca.leaf_for("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b)); // cached
        assert!(!a.cert.is_empty());

        // Reload uses the same on-disk CA and can build a per-host server config.
        let ca2 = CertAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(ca.ca_pem(), ca2.ca_pem());
        let _ = server_config_for_host(Arc::new(ca2), "example.com").unwrap();
    }

    #[test]
    fn bundled_default_loads_and_mints() {
        // 内置默认共享 CA：能从提交的 PEM 加载并签发叶子证书。
        let ca = CertAuthority::bundled_default().unwrap();
        assert!(ca.ca_pem().contains("BEGIN CERTIFICATE"));
        let leaf = ca.leaf_for("example.com").unwrap();
        assert!(!leaf.cert.is_empty());
        let _ = server_config_for_host(Arc::new(ca), "example.com").unwrap();
    }

    #[test]
    fn from_pem_roundtrips() {
        let (cert, key) = CertAuthority::generate_pem("Test CA").unwrap();
        let ca = CertAuthority::from_pem(&cert, &key).unwrap();
        assert_eq!(ca.ca_pem(), cert);
        assert!(ca.leaf_for("h.example").is_ok());
    }
}
