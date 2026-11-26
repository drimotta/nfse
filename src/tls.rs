//! TLS 1.2 client (OpenSSL) whose client certificate key lives on the token.
//!
//! Sefin asks for the client certificate only by renegotiating after it has
//! read the request, so the TLS library must support renegotiation (rustls
//! does not; OpenSSL does). TLS 1.3 is not used: it has no renegotiation and
//! needs RSA-PSS client signatures, which the ICP-Brasil Oberthur card does
//! not offer.
//!
//! The token key is an OpenSSL RSA key with the certificate's public key and
//! a custom RSA method whose private "encrypt" (the PKCS#1 v1.5 signature of
//! a DigestInfo) is done on the token.

use crate::dps::Signer;
use anyhow::{Context, Result, anyhow, bail};
use foreign_types::ForeignType;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use openssl::x509::X509;
use openssl_sys as ffi;
use std::collections::HashMap;
use std::ffi::{CString, c_int, c_uchar, c_void};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

pub type SharedSigner = Arc<dyn Signer + Send + Sync>;

const RSA_PKCS1_PADDING: c_int = 1;
const SSL_CTRL_SET_CLIENT_SIGALGS_LIST: c_int = 102;
/// Signature algorithms the client may use for its certificate: PKCS#1 v1.5
/// only, which is what the card can do.
const CLIENT_SIGALGS: &str = "RSA+SHA256:RSA+SHA384:RSA+SHA512";

type PrivEnc =
    unsafe extern "C" fn(c_int, *const c_uchar, *mut c_uchar, *mut ffi::RSA, c_int) -> c_int;

unsafe extern "C" {
    fn RSA_get_default_method() -> *const ffi::RSA_METHOD;
    fn RSA_meth_dup(meth: *const ffi::RSA_METHOD) -> *mut ffi::RSA_METHOD;
    fn RSA_meth_set1_name(meth: *mut ffi::RSA_METHOD, name: *const std::ffi::c_char) -> c_int;
    fn RSA_meth_set_priv_enc(meth: *mut ffi::RSA_METHOD, f: Option<PrivEnc>) -> c_int;
    fn RSA_set_method(rsa: *mut ffi::RSA, meth: *const ffi::RSA_METHOD) -> c_int;
}

/// The signer of each token-backed RSA key, by the key's address.
fn signers() -> &'static Mutex<HashMap<usize, SharedSigner>> {
    static SIGNERS: OnceLock<Mutex<HashMap<usize, SharedSigner>>> = OnceLock::new();
    SIGNERS.get_or_init(Default::default)
}

struct Method(*mut ffi::RSA_METHOD);
// SAFETY: the method table is created once and never changed afterwards.
unsafe impl Send for Method {}
unsafe impl Sync for Method {}

fn token_method() -> Result<*const ffi::RSA_METHOD> {
    static METHOD: OnceLock<Method> = OnceLock::new();
    let method = METHOD.get_or_init(|| unsafe {
        let meth = RSA_meth_dup(RSA_get_default_method());
        if !meth.is_null() {
            let name = CString::new("nfse PKCS#11 token").expect("no NUL");
            RSA_meth_set1_name(meth, name.as_ptr());
            RSA_meth_set_priv_enc(meth, Some(token_priv_enc));
        }
        Method(meth)
    });
    if method.0.is_null() {
        bail!("cannot create the OpenSSL RSA method");
    }
    Ok(method.0)
}

/// RSA private "encryption" with PKCS#1 type 1 padding is the PKCS#1 v1.5
/// signature of `from`, a DigestInfo: exactly what CKM_RSA_PKCS does.
unsafe extern "C" fn token_priv_enc(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut ffi::RSA,
    padding: c_int,
) -> c_int {
    if padding != RSA_PKCS1_PADDING || flen < 0 {
        log::warn!(target: "nfse::tls", "unsupported RSA padding {padding} requested from the token");
        return -1;
    }
    let Some(signer) = signers()
        .lock()
        .ok()
        .and_then(|s| s.get(&(rsa as usize)).cloned())
    else {
        return -1;
    };
    // SAFETY: OpenSSL passes `flen` readable bytes in `from` and a buffer of
    // RSA_size(rsa) bytes in `to`.
    let input = unsafe { std::slice::from_raw_parts(from, flen as usize) };
    let size = unsafe { ffi::RSA_size(rsa) } as usize;
    log::info!(target: "nfse::tls", "signing the TLS handshake on the token");
    match signer.sign_digest_info(input) {
        Ok(sig) if sig.len() <= size => {
            // Left-pad to the modulus size, as RSA outputs are fixed-length.
            let out = unsafe { std::slice::from_raw_parts_mut(to, size) };
            let pad = size - sig.len();
            out[..pad].fill(0);
            out[pad..].copy_from_slice(&sig);
            size as c_int
        }
        Ok(_) => -1,
        Err(e) => {
            log::error!(target: "nfse::tls", "token signature failed: {e:#}");
            -1
        }
    }
}

/// An OpenSSL key for the certificate's public key that signs on the token.
/// The signer stays registered until `unregister` is called with the key.
pub fn token_pkey(signer: SharedSigner, cert: &X509) -> Result<PKey<Private>> {
    let public = cert.public_key().context("certificate has no public key")?;
    let public = public.rsa().context("the certificate key is not RSA")?;
    let n = public.n().to_owned()?;
    let e = public.e().to_owned()?;
    let method = token_method()?;
    // SAFETY: a fresh RSA object gets the method and takes ownership of n and
    // e; Rsa::from_ptr owns the RSA object.
    let rsa = unsafe {
        let raw = ffi::RSA_new();
        if raw.is_null() {
            bail!("RSA_new failed");
        }
        let rsa: Rsa<Private> = Rsa::from_ptr(raw);
        if RSA_set_method(raw, method) != 1 {
            bail!("RSA_set_method failed");
        }
        if ffi::RSA_set0_key(raw, n.as_ptr(), e.as_ptr(), std::ptr::null_mut()) != 1 {
            bail!("RSA_set0_key failed");
        }
        std::mem::forget(n);
        std::mem::forget(e);
        rsa
    };
    signers()
        .lock()
        .map_err(|_| anyhow!("signer registry poisoned"))?
        .insert(rsa.as_ptr() as usize, signer);
    Ok(PKey::from_rsa(rsa)?)
}

fn unregister(addr: usize) {
    if let Ok(mut s) = signers().lock() {
        s.remove(&addr);
    }
}

/// The TLS client; dropping it releases the token.
pub struct TokenTls {
    pub connector: SslConnector,
    key_addr: usize,
}

impl Drop for TokenTls {
    fn drop(&mut self) {
        unregister(self.key_addr);
    }
}

/// A TLS 1.2 client that trusts the system roots (plus `ca_bundle`) and
/// authenticates with the token's key, including when the server asks for the
/// certificate by renegotiating.
pub fn connector(signer: SharedSigner, ca_bundle: Option<&Path>) -> Result<TokenTls> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    if let Some(path) = ca_bundle {
        builder
            .set_ca_file(path)
            .with_context(|| format!("cannot read CA bundle {}", path.display()))?;
    }
    let cert = X509::from_der(signer.certificate()).context("bad token certificate")?;
    let key = token_pkey(signer, &cert)?;
    let key_addr = key.rsa()?.as_ptr() as usize;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&key)?;
    let sigalgs = CString::new(CLIENT_SIGALGS).expect("no NUL");
    // SAFETY: SSL_CTX_set1_client_sigalgs_list copies the string.
    let ok = unsafe {
        ffi::SSL_CTX_ctrl(
            builder.as_ptr(),
            SSL_CTRL_SET_CLIENT_SIGALGS_LIST,
            0,
            sigalgs.as_ptr() as *mut c_void,
        )
    };
    if ok != 1 {
        bail!("cannot restrict the client signature algorithms");
    }
    Ok(TokenTls {
        connector: builder.build(),
        key_addr,
    })
}
