//! TLS (and optional mutual TLS) for the server, on rustls.
//!
//! `server_config` reads a PEM certificate chain and key. With a `client_ca`
//! bundle the handshake **requires** a client certificate signed by it (mTLS):
//! a peer without one never gets as far as an HTTP request. The bearer token is
//! still checked on top, so a stolen client certificate alone is not enough.
//! TLS 1.2 and 1.3 only.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::http::Conn;

fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut r = BufReader::new(File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let v: Vec<_> = rustls_pemfile::certs(&mut r)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if v.is_empty() {
        return Err(format!("{}: no certificate (PEM) found", path.display()));
    }
    Ok(v)
}

fn key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let mut r = BufReader::new(File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
    rustls_pemfile::private_key(&mut r)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .ok_or_else(|| format!("{}: no private key (PEM) found", path.display()))
}

/// The server's TLS configuration. `client_ca` turns on mutual TLS.
pub fn server_config(
    cert: &Path,
    key_file: &Path,
    client_ca: Option<&Path>,
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in certs(ca)? {
                roots.add(c).map_err(|e| format!("{}: {e}", ca.display()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| format!("client CA: {e}"))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let cfg = builder
        .with_single_cert(certs(cert)?, key(key_file)?)
        .map_err(|e| format!("certificate and key do not match: {e}"))?;
    Ok(Arc::new(cfg))
}

/// A TLS stream over an accepted TCP connection. The handshake runs on the
/// first read, under the same read timeout as the request.
pub struct TlsConn {
    inner: StreamOwned<ServerConnection, TcpStream>,
}

impl TlsConn {
    pub fn accept(cfg: &Arc<ServerConfig>, tcp: TcpStream) -> Result<TlsConn, String> {
        let conn = ServerConnection::new(cfg.clone()).map_err(|e| e.to_string())?;
        Ok(TlsConn {
            inner: StreamOwned::new(conn, tcp),
        })
    }
}

impl Read for TlsConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Conn for TlsConn {
    fn set_read_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> {
        self.inner.sock.set_read_timeout(d)
    }
    fn set_write_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> {
        self.inner.sock.set_write_timeout(d)
    }
    fn peer_ip(&self) -> String {
        self.inner
            .sock
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod testpki {
    //! Throwaway certificates for the tests: a CA, a `localhost` server
    //! certificate and a client certificate, all written as PEM.
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use std::path::{Path, PathBuf};

    pub struct Pki {
        pub dir: PathBuf,
        pub ca: PathBuf,
        pub server_cert: PathBuf,
        pub server_key: PathBuf,
        pub client_cert: PathBuf,
        pub client_key: PathBuf,
        pub other_client_cert: PathBuf,
        pub other_client_key: PathBuf,
    }

    fn ca(name: &str) -> (rcgen::Certificate, KeyPair) {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let k = KeyPair::generate().unwrap();
        (p.self_signed(&k).unwrap(), k)
    }

    fn leaf(
        name: &str,
        sans: Vec<String>,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut p = CertificateParams::new(sans).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        let k = KeyPair::generate().unwrap();
        (p.signed_by(&k, ca, ca_key).unwrap(), k)
    }

    fn write(dir: &Path, name: &str, pem: String) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, pem).unwrap();
        p
    }

    pub fn make(tag: &str) -> Pki {
        let dir = std::env::temp_dir().join(format!("wapi-pki-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (ca_cert, ca_key) = ca("wayang test CA");
        let (srv, srv_key) = leaf("localhost", vec!["localhost".into()], &ca_cert, &ca_key);
        let (cli, cli_key) = leaf("ops client", vec![], &ca_cert, &ca_key);
        let (other_ca_cert, other_ca_key) = ca("some other CA");
        let (oc, oc_key) = leaf("stranger", vec![], &other_ca_cert, &other_ca_key);
        Pki {
            ca: write(&dir, "ca.pem", ca_cert.pem()),
            server_cert: write(&dir, "server.pem", srv.pem()),
            server_key: write(&dir, "server.key", srv_key.serialize_pem()),
            client_cert: write(&dir, "client.pem", cli.pem()),
            client_key: write(&dir, "client.key", cli_key.serialize_pem()),
            other_client_cert: write(&dir, "stranger.pem", oc.pem()),
            other_client_key: write(&dir, "stranger.key", oc_key.serialize_pem()),
            dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_good_pair_loads_with_and_without_a_client_ca() {
        let pki = testpki::make("load");
        assert!(server_config(&pki.server_cert, &pki.server_key, None).is_ok());
        assert!(server_config(&pki.server_cert, &pki.server_key, Some(&pki.ca)).is_ok());
        let _ = std::fs::remove_dir_all(&pki.dir);
    }

    #[test]
    fn bad_inputs_say_what_is_wrong() {
        let pki = testpki::make("bad");
        let e = server_config(Path::new("/nonexistent.pem"), &pki.server_key, None)
            .err()
            .unwrap();
        assert!(e.contains("/nonexistent.pem"), "{e}");
        // a key where a certificate belongs
        let e = server_config(&pki.server_key, &pki.server_key, None)
            .err()
            .unwrap();
        assert!(e.contains("no certificate"), "{e}");
        // a certificate where the key belongs
        let e = server_config(&pki.server_cert, &pki.server_cert, None)
            .err()
            .unwrap();
        assert!(e.contains("no private key"), "{e}");
        // a key that is not this certificate's
        let e = server_config(&pki.server_cert, &pki.client_key, None)
            .err()
            .unwrap();
        assert!(e.contains("do not match"), "{e}");
        let _ = std::fs::remove_dir_all(&pki.dir);
    }
}
