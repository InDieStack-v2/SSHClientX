//! Same-network QR vault-transfer protocol.
//!
//! The webview receives only the public QR ticket and SVG. Ticket validation,
//! LAN selection, state lifetime, and all eventual network I/O stay in Rust.

use crate::vault::Outcome;
use if_addrs::get_if_addrs;
use qrcode::render::svg;
use qrcode::QrCode;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use http_body_util::BodyExt;
use zeroize::Zeroizing;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TICKET_VERSION: &str = "v1";
pub const MAX_SESSION_SECONDS: u64 = 120;
pub const DEFAULT_SESSION_SECONDS: u64 = 90;
pub const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LABEL_BYTES: usize = 64;
const MAX_FAILED_ATTEMPTS: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferRole {
    Pull,
    Push,
}

impl TransferRole {
    fn parse(value: &str) -> Result<Self, Outcome> {
        match value {
            "pull" => Ok(Self::Pull),
            "push" => Ok(Self::Push),
            _ => Err(Outcome::QrBad),
        }
    }

    pub const fn wire(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QrTicket {
    pub address: SocketAddr,
    pub token: [u8; 16],
    pub kid: Option<[u8; 16]>,
    pub fingerprint: [u8; 32],
    pub expires_at: u64,
    pub role: TransferRole,
    pub sid: [u8; 16],
    pub host_label: Option<String>,
}

impl QrTicket {
    pub fn parse(text: &str, now: u64) -> Result<Self, Outcome> {
        let mut parts = text.split('|');
        if parts.next() != Some(TICKET_VERSION) {
            return Err(Outcome::QrBad);
        }
        let url = parts.next().ok_or(Outcome::QrBad)?;
        let mut fields = HashMap::new();
        for field in parts {
            let (key, value) = field.split_once('=').ok_or(Outcome::QrBad)?;
            if fields.insert(key, value).is_some() {
                return Err(Outcome::QrBad);
            }
        }
        let expected = ["tok", "fp", "exp", "role", "sid"];
        if expected.iter().any(|key| !fields.contains_key(key)) {
            return Err(Outcome::QrBad);
        }
        if fields.keys().any(|key| !matches!(*key, "tok" | "kid" | "fp" | "exp" | "role" | "sid" | "lbl")) {
            return Err(Outcome::QrBad);
        }

        let expires_at = fields["exp"].parse::<u64>().map_err(|_| Outcome::QrBad)?;
        if expires_at <= now || expires_at > now.saturating_add(MAX_SESSION_SECONDS) {
            return Err(Outcome::QrExpired);
        }

        let (address, url_sid) = parse_ticket_url(url)?;
        if !is_lan_address(address.ip()) {
            return Err(Outcome::QrIpForbidden);
        }

        let token = decode_fixed::<16>(fields["tok"])?;
        let kid = fields.get("kid").map(|value| decode_fixed::<16>(value)).transpose()?;
        let fingerprint = decode_fixed::<32>(fields["fp"])?;
        let sid = decode_fixed::<16>(fields["sid"])?;
        if url_sid != sid {
            return Err(Outcome::QrBad);
        }
        let host_label = fields.get("lbl").map(|value| {
            let bytes = hex::decode(value).map_err(|_| Outcome::QrBad)?;
            if bytes.is_empty() || bytes.len() > MAX_LABEL_BYTES {
                return Err(Outcome::QrBad);
            }
            String::from_utf8(bytes).map_err(|_| Outcome::QrBad)
        }).transpose()?;

        Ok(Self {
            address,
            token,
            kid,
            fingerprint,
            expires_at,
            role: TransferRole::parse(fields["role"] )?,
            sid,
            host_label,
        })
    }

    pub fn to_wire(&self) -> String {
        let host = match self.address.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let mut fields = vec![
            TICKET_VERSION.to_string(),
            format!("https://{host}:{}/s/{}", self.address.port(), hex::encode(self.sid)),
            format!("tok={}", hex::encode(self.token)),
        ];
        if let Some(kid) = self.kid {
            fields.push(format!("kid={}", hex::encode(kid)));
        }
        fields.extend([
            format!("fp={}", hex::encode(self.fingerprint)),
            format!("exp={}", self.expires_at),
            format!("role={}", self.role.wire()),
            format!("sid={}", hex::encode(self.sid)),
        ]);
        if let Some(label) = &self.host_label {
            fields.push(format!("lbl={}", hex::encode(label.as_bytes())));
        }
        fields.join("|")
    }

    pub fn verification_code(&self) -> String {
        let hex = hex::encode(self.fingerprint);
        format!("{} {} {}", &hex[0..2], &hex[2..4], &hex[4..6])
    }

    pub fn endpoint(&self, resource: &str) -> String {
        format!("https://{}/s/{}/{}", self.address, hex::encode(self.sid), resource)
    }
}

fn parse_ticket_url(url: &str) -> Result<(SocketAddr, [u8; 16]), Outcome> {
    let remainder = url.strip_prefix("https://").ok_or(Outcome::QrBad)?;
    let (authority, path) = remainder.split_once('/').ok_or(Outcome::QrBad)?;
    let sid_hex = path.strip_prefix("s/").filter(|value| !value.contains('/')).ok_or(Outcome::QrBad)?;
    let sid = decode_fixed::<16>(sid_hex)?;
    let address = authority.parse::<SocketAddr>().map_err(|_| Outcome::QrBad)?;
    Ok((address, sid))
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], Outcome> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Outcome::QrBad);
    }
    let mut bytes = [0u8; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Outcome::QrBad)?;
    Ok(bytes)
}

pub fn is_lan_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
    }
}

pub fn select_bind_address() -> Result<IpAddr, Outcome> {
    get_if_addrs()
        .map_err(|_| Outcome::NetUnreachable)?
        .into_iter()
        .map(|interface| interface.ip())
        .filter(|address| is_lan_address(*address))
        .min_by_key(|address| match address {
            IpAddr::V4(_) => 0u8,
            IpAddr::V6(_) => 1u8,
        })
        .ok_or(Outcome::NetUnreachable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenState {
    Unused,
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    Owned,
    NotHeld,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Advertising,
    Connected,
    Verified,
    Transferring,
    Completed,
    Failed,
    Expired,
    Cancelled,
}
#[derive(Clone, Debug)]
pub struct TransferSession {
    pub sid: [u8; 16],
    pub role: TransferRole,
    pub token: [u8; 16],
    pub token_state: TokenState,
    pub expires_at: u64,
    pub fail_count: u8,
    pub bind_addr: IpAddr,
    pub certificate_fingerprint: Option<[u8; 32]>,
    pub key_status: KeyStatus,
    pub status: SessionStatus,
    pub max_body_bytes: u64,
}

impl TransferSession {
    pub fn new(role: TransferRole, bind_addr: IpAddr, now: u64) -> Self {
        let mut sid = [0u8; 16];
        let mut token = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut sid);
        rand::thread_rng().fill_bytes(&mut token);
        Self {
            sid,
            role,
            token,
            token_state: TokenState::Unused,
            expires_at: now.saturating_add(DEFAULT_SESSION_SECONDS),
            fail_count: 0,
            bind_addr,
            certificate_fingerprint: None,
            key_status: if role == TransferRole::Pull { KeyStatus::Owned } else { KeyStatus::NotHeld },
            status: SessionStatus::Advertising,
            max_body_bytes: MAX_BODY_BYTES,
        }
    }

    pub fn is_live(&mut self, now: u64) -> bool {
        if now >= self.expires_at {
            self.teardown(SessionStatus::Expired);
            return false;
        }
        !matches!(self.status, SessionStatus::Completed | SessionStatus::Failed | SessionStatus::Expired | SessionStatus::Cancelled)
    }

    pub fn authenticate(&mut self, token: &[u8], now: u64) -> Result<(), Outcome> {
        if !self.is_live(now) {
            return Err(Outcome::TokUsed);
        }
        if self.token_state == TokenState::Consumed {
            return Err(Outcome::TokUsed);
        }
        if !constant_time_eq(&self.token, token) {
            self.fail_count = self.fail_count.saturating_add(1);
            if self.fail_count >= MAX_FAILED_ATTEMPTS {
                self.teardown(SessionStatus::Failed);
            }
            return Err(Outcome::QrBad);
        }
        self.status = SessionStatus::Connected;
        Ok(())
    }

    pub fn mark_verified(&mut self) -> Result<(), Outcome> {
        if self.status != SessionStatus::Connected {
            return Err(Outcome::QrBad);
        }
        self.status = SessionStatus::Verified;
        Ok(())
    }

    pub fn mark_transferring(&mut self) -> Result<(), Outcome> {
        if self.status != SessionStatus::Verified {
            return Err(Outcome::QrBad);
        }
        self.status = SessionStatus::Transferring;
        Ok(())
    }

    pub fn complete(&mut self) {
        self.teardown(SessionStatus::Completed);
    }

    pub fn cancel(&mut self) {
        self.teardown(SessionStatus::Cancelled);
    }

    fn teardown(&mut self, status: SessionStatus) {
        self.token_state = TokenState::Consumed;
        self.status = status;
    }
}

pub fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    let mut difference = expected.len() ^ actual.len();
    for index in 0..expected.len() {
        difference |= usize::from(expected[index] ^ actual.get(index).copied().unwrap_or(0));
    }
    difference == 0
}


#[derive(Clone)]
pub struct CertificateMaterial {
    pub config: Arc<rustls::ServerConfig>,
    pub fingerprint: [u8; 32],
}

impl std::fmt::Debug for CertificateMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateMaterial")
            .field("fingerprint", &hex::encode(self.fingerprint))
            .finish_non_exhaustive()
    }
}

pub fn generate_certificate(bind_addr: IpAddr) -> Result<CertificateMaterial, Outcome> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let certified = rcgen::generate_simple_self_signed(vec![bind_addr.to_string()]).map_err(|_| Outcome::TlsPin)?;
    let cert_der = certified.cert.der().clone();
    let fingerprint: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Outcome::TlsPin)?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], private_key)
        .map_err(|_| Outcome::TlsPin)?;
    Ok(CertificateMaterial { config: Arc::new(config), fingerprint })
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    fingerprint: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if constant_time_eq(&self.fingerprint, &actual) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("QR transfer certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn pinned_client(ticket: &QrTicket) -> Result<reqwest::Client, Outcome> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinnedCertificateVerifier {
        fingerprint: ticket.fingerprint,
        provider: provider.clone(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Outcome::TlsPin)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|_| Outcome::NetUnreachable)
}
pub async fn checked_response(response: reqwest::Response) -> Result<reqwest::Response, Outcome> {
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return if response.text().await.ok().as_deref() == Some("TOK_USED") {
            Err(Outcome::TokUsed)
        } else {
            Err(Outcome::QrBad)
        };
    }
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(Outcome::NetUnreachable)
    }
}

pub struct HostedSession {
    session: TransferSession,
    tls: CertificateMaterial,
    metadata: TransferMetadata,
    file: Option<Vec<u8>>,
    dek: Option<Zeroizing<[u8; 32]>>,
    app_handle: Option<tauri::AppHandle>,
    receive_password: Option<Zeroizing<String>>,
    receive_profile_name: Option<String>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

#[derive(Clone, Debug)]
pub struct TransferMetadata {
    pub kid: Option<[u8; 16]>,
    pub generation: Option<u64>,
    pub size: Option<u64>,
    pub sha256_prefix: Option<String>,
    pub needs_key: bool,
}

#[derive(Clone)]
pub struct QrTransferState {
    pub hosts: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<HostedSession>>>>>,
    pub guests: Arc<Mutex<HashMap<String, QrTicket>>>,
}

impl Default for QrTransferState {
    fn default() -> Self {
        Self {
            hosts: Arc::new(Mutex::new(HashMap::new())),
            guests: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl QrTransferState {
    pub fn stage_guest(&self, ticket: QrTicket) -> Result<String, Outcome> {
        let session_id = hex::encode(ticket.sid);
        self.guests.lock().map_err(|_| Outcome::QrBad)?.insert(session_id.clone(), ticket);
        Ok(session_id)
    }

    pub fn cancel_guest(&self, session_id: &str) -> Result<(), Outcome> {
        self.guests.lock().map_err(|_| Outcome::QrBad)?.remove(session_id);
        Ok(())
    }

    pub fn guest(&self, session_id: &str) -> Result<QrTicket, Outcome> {
        self.guests.lock().map_err(|_| Outcome::QrBad)?
            .get(session_id)
            .cloned()
            .ok_or(Outcome::TokUsed)
    }

    pub async fn start_host(
        &self,
        role: TransferRole,
        kid: Option<[u8; 16]>,
        metadata: TransferMetadata,
        host_label: Option<String>,
        file: Option<Vec<u8>>,
        dek: Option<Zeroizing<[u8; 32]>>,
        app_handle: Option<tauri::AppHandle>,
        receive_password: Option<String>,
        receive_profile_name: Option<String>,
    ) -> Result<QrTicket, Outcome> {
        let bind_addr = select_bind_address()?;
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind_addr, 0))
            .await
            .map_err(|_| Outcome::NetUnreachable)?;
        let tls = generate_certificate(bind_addr)?;
        let now = now_unix_seconds();
        let mut session = TransferSession::new(role, bind_addr, now);
        session.certificate_fingerprint = Some(tls.fingerprint);
        let ticket = QrTicket {
            address: listener.local_addr().map_err(|_| Outcome::NetUnreachable)?,
            token: session.token,
            kid,
            fingerprint: tls.fingerprint,
            expires_at: session.expires_at,
            role,
            sid: session.sid,
            host_label,
        };
        let session_id = hex::encode(session.sid);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let hosted = Arc::new(tokio::sync::Mutex::new(HostedSession {
            session,
            tls,
            metadata,
            file,
            dek,
            app_handle,
            receive_password: receive_password.map(Zeroizing::new),
            receive_profile_name,
            shutdown,
        }));
        self.hosts.lock().map_err(|_| Outcome::QrBad)?.insert(session_id.clone(), hosted.clone());
        let hosts = self.hosts.clone();
        tauri::async_runtime::spawn(run_accept_loop(listener, hosted, shutdown_rx, hosts, session_id));
        Ok(ticket)
    }

    pub async fn cancel_host(&self, session_id: &str) -> Result<(), Outcome> {
        let hosted = self.hosts.lock().map_err(|_| Outcome::QrBad)?.remove(session_id);
        if let Some(hosted) = hosted {
            let mut hosted = hosted.lock().await;
            hosted.session.cancel();
            let _ = hosted.shutdown.send(true);
        }
        Ok(())
    }
}

type ResponseBody = http_body_util::Full<hyper::body::Bytes>;

fn response(status: hyper::StatusCode, body: impl Into<hyper::body::Bytes>) -> hyper::Response<ResponseBody> {
    let body = body.into();
    let length = body.len().to_string();
    hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_LENGTH, length)
        .body(http_body_util::Full::new(body))
        .unwrap_or_else(|_| hyper::Response::new(http_body_util::Full::new(hyper::body::Bytes::new())))
}
fn typed_response(
    status: hyper::StatusCode,
    body: impl Into<hyper::body::Bytes>,
    content_type: &'static str,
) -> hyper::Response<ResponseBody> {
    let body = body.into();
    let length = body.len().to_string();
    hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_LENGTH, length)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(http_body_util::Full::new(body))
        .unwrap_or_else(|_| hyper::Response::new(http_body_util::Full::new(hyper::body::Bytes::new())))
}

async fn finalize_pushed_vault(hosted: &mut HostedSession) -> Result<(), String> {
    let (Some(app_handle), Some(password), Some(profile_name), Some(file), Some(dek)) = (
        hosted.app_handle.clone(),
        hosted.receive_password.as_ref(),
        hosted.receive_profile_name.as_deref(),
        hosted.file.as_ref(),
        hosted.dek.as_ref(),
    ) else {
        return Err("[VALIDATION] QR_RECEIVE_CONFIGURATION".into());
    };
    let sealed = crate::vault::SealedVaultFile::parse(file).map_err(|outcome| outcome.to_string())?;
    let key = **dek;
    let registry = move |_: &[u8; crate::vault::KID_LEN]| -> crate::vault::KeyLookup {
        crate::vault::KeyLookup::Unclaimed { key }
    };
    let decision = crate::vault::verify_and_import(file, &registry, true)
        .map_err(|outcome| outcome.to_string())?;
    let dir = crate::profiles_dir(&app_handle)?;
    crate::recovery::establish_unclaimed_key(&dir, dek, sealed.kid, password.as_str())
        .map_err(|outcome| outcome.to_string())?;
    match decision.disposition {
        crate::vault::Disposition::CreateProfile => {
            crate::claim_unclaimed_key_as_new_profile(&dir, sealed.kid, profile_name, false, file).await?;
        }
        crate::vault::Disposition::RestoreOver { profile } => {
            crate::land_as_restore_over_copy(&dir, &profile, file).await?;
        }
        crate::vault::Disposition::NoOp { .. } => {}
    }
    Ok(())
}

fn bearer_token(request: &hyper::Request<hyper::body::Incoming>) -> Option<[u8; 16]> {
    let value = request.headers().get(hyper::header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    decode_fixed::<16>(token).ok()
}

async fn route_request(
    request: hyper::Request<hyper::body::Incoming>,
    hosted: Arc<tokio::sync::Mutex<HostedSession>>,
) -> Result<hyper::Response<ResponseBody>, std::convert::Infallible> {
    let (method, path) = (request.method().clone(), request.uri().path().to_string());
    let mut hosted = hosted.lock().await;
    match hosted.session.authenticate(&bearer_token(&request).unwrap_or([0; 16]), now_unix_seconds()) {
        Ok(()) => {}
        Err(Outcome::TokUsed) => return Ok(response(hyper::StatusCode::UNAUTHORIZED, "TOK_USED")),
        Err(_) => return Ok(response(hyper::StatusCode::UNAUTHORIZED, "")),
    }
    let base = format!("/s/{}", hex::encode(hosted.session.sid));
    if method == hyper::Method::GET && path == format!("{base}/meta") {
        let metadata = &hosted.metadata;
        return Ok(response(
            hyper::StatusCode::OK,
            serde_json::json!({
                "kid": metadata.kid.map(hex::encode),
                "generation": metadata.generation,
                "size": metadata.size,
                "sha256_prefix": metadata.sha256_prefix,
                "needs_key": metadata.needs_key,
            }).to_string(),
        ));
    }
    if method == hyper::Method::POST && path == format!("{base}/done") {
        if hosted.session.role == TransferRole::Push {
            if let Err(error) = finalize_pushed_vault(&mut hosted).await {
                return Ok(response(hyper::StatusCode::UNPROCESSABLE_ENTITY, error));
            }
        }
        hosted.session.complete();
        let _ = hosted.shutdown.send(true);
        return Ok(response(hyper::StatusCode::NO_CONTENT, ""));
    }
    if method == hyper::Method::GET && path == format!("{base}/key") && hosted.session.role == TransferRole::Pull {
        if hosted.session.mark_verified().and_then(|_| hosted.session.mark_transferring()).is_err() {
            return Ok(response(hyper::StatusCode::FORBIDDEN, ""));
        }
        let Some(dek) = hosted.dek.as_ref() else {
            return Ok(response(hyper::StatusCode::NOT_FOUND, ""));
        };
        return Ok(response(hyper::StatusCode::OK, hyper::body::Bytes::copy_from_slice(&dek[..])));
    }
    if method == hyper::Method::GET && path == format!("{base}/file") && hosted.session.role == TransferRole::Pull {
        if hosted.session.status == SessionStatus::Connected
            && hosted.session.mark_verified().and_then(|_| hosted.session.mark_transferring()).is_err()
        {
            return Ok(response(hyper::StatusCode::FORBIDDEN, ""));
        }
        let Some(file) = hosted.file.as_ref() else {
            return Ok(response(hyper::StatusCode::NOT_FOUND, ""));
        };
        if file.len() as u64 > hosted.session.max_body_bytes {
            return Ok(response(hyper::StatusCode::PAYLOAD_TOO_LARGE, ""));
        }
        return Ok(typed_response(
            hyper::StatusCode::OK,
            hyper::body::Bytes::copy_from_slice(file),
            "application/x-sshclientx",
        ));
    }
    if method == hyper::Method::PUT && path == format!("{base}/key") && hosted.session.role == TransferRole::Push {
        let declared = request.headers().get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > 32) {
            return Ok(response(hyper::StatusCode::PAYLOAD_TOO_LARGE, ""));
        }
        let body = match request.into_body().collect().await {
            Ok(body) => body.to_bytes(),
            Err(_) => return Ok(response(hyper::StatusCode::BAD_REQUEST, "")),
        };
        if body.len() != 32 {
            return Ok(response(hyper::StatusCode::PAYLOAD_TOO_LARGE, ""));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&body);
        hosted.dek = Some(Zeroizing::new(raw));
        hosted.session.key_status = KeyStatus::Owned;
        hosted.session.mark_verified().ok();
        return Ok(response(hyper::StatusCode::NO_CONTENT, ""));
    }
    if method == hyper::Method::PUT && path == format!("{base}/file") && hosted.session.role == TransferRole::Push {
        let declared = request.headers().get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > hosted.session.max_body_bytes) {
            return Ok(response(hyper::StatusCode::PAYLOAD_TOO_LARGE, ""));
        }
        let body = match request.into_body().collect().await {
            Ok(body) => body.to_bytes(),
            Err(_) => return Ok(response(hyper::StatusCode::BAD_REQUEST, "")),
        };
        if body.len() as u64 > hosted.session.max_body_bytes {
            return Ok(response(hyper::StatusCode::PAYLOAD_TOO_LARGE, ""));
        }
        hosted.file = Some(body.to_vec());
        hosted.session.mark_transferring().ok();
        return Ok(response(hyper::StatusCode::NO_CONTENT, ""));
    }
    Ok(response(hyper::StatusCode::NOT_FOUND, ""))
}

async fn run_accept_loop(
    listener: tokio::net::TcpListener,
    hosted: Arc<tokio::sync::Mutex<HostedSession>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    hosts: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<HostedSession>>>>>,
    session_id: String,
) {
    let expires_at = hosted.lock().await.session.expires_at;
    let seconds = expires_at.saturating_sub(now_unix_seconds());
    let expiry = tokio::time::sleep(std::time::Duration::from_secs(seconds));
    tokio::pin!(expiry);
    loop {
        tokio::select! {
            _ = &mut expiry => {
                if let Ok(mut session) = hosted.try_lock() {
                    session.session.is_live(expires_at);
                    let _ = session.shutdown.send(true);
                }
                break;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break; };
                let hosted = hosted.clone();
                tauri::async_runtime::spawn(async move {
                    let config = { hosted.lock().await.tls.config.clone() };
                    let Ok(stream) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await else { return; };
                    let service = hyper::service::service_fn(move |request| route_request(request, hosted.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    }
    hosts.lock().ok().and_then(|mut hosts| hosts.remove(&session_id));
}

pub fn qr_svg(ticket: &QrTicket) -> Result<String, Outcome> {
    let code = QrCode::new(ticket.to_wire().as_bytes()).map_err(|_| Outcome::QrBad)?;
    Ok(code.render::<svg::Color>().min_dimensions(256, 256).build())
}

pub fn now_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> QrTicket {
        QrTicket {
            address: "192.168.1.7:8443".parse().unwrap(),
            token: [1; 16],
            kid: Some([2; 16]),
            fingerprint: [3; 32],
            expires_at: 10_000,
            role: TransferRole::Pull,
            sid: [4; 16],
            host_label: Some("workstation".into()),
        }
    }

    #[test]
    fn ticket_round_trips() {
        let ticket = ticket();
        assert_eq!(QrTicket::parse(&ticket.to_wire(), 9_900).unwrap(), ticket);
    }

    #[test]
    fn ticket_validation_preserves_error_precedence() {
        let mut text = ticket().to_wire();
        text = text.replacen("v1", "v2", 1);
        assert_eq!(QrTicket::parse(&text, 9_900), Err(Outcome::QrBad));
        let mut expired = ticket().to_wire();
        expired = expired.replace("exp=10000", "exp=1");
        assert_eq!(QrTicket::parse(&expired, 9_900), Err(Outcome::QrExpired));
        let public = ticket().to_wire().replace("192.168.1.7", "8.8.8.8");
        assert_eq!(QrTicket::parse(&public, 9_900), Err(Outcome::QrIpForbidden));
        let malformed = ticket().to_wire().replace("tok=01010101010101010101010101010101", "tok=zz");
        assert_eq!(QrTicket::parse(&malformed, 9_900), Err(Outcome::QrBad));
    }

    #[test]
    fn session_consumes_token_only_at_teardown() {
        let mut session = TransferSession::new(TransferRole::Pull, "192.168.1.7".parse().unwrap(), 1_000);
        let token = session.token;
        session.authenticate(&token, 1_001).unwrap();
        session.mark_verified().unwrap();
        session.mark_transferring().unwrap();
        session.complete();
        assert_eq!(session.authenticate(&token, 1_002), Err(Outcome::TokUsed));
    }

    #[test]
    fn session_tears_down_after_five_failures_and_expiry() {
        let mut session = TransferSession::new(TransferRole::Pull, "192.168.1.7".parse().unwrap(), 1_000);
        for _ in 0..5 {
            assert_eq!(session.authenticate(&[0; 16], 1_001), Err(Outcome::QrBad));
        }
        assert_eq!(session.status, SessionStatus::Failed);
        let mut expired = TransferSession::new(TransferRole::Pull, "192.168.1.7".parse().unwrap(), 1_000);
        assert!(!expired.is_live(expired.expires_at));
        assert_eq!(expired.status, SessionStatus::Expired);
    }

    #[test]
    fn constant_time_comparison_accepts_only_equal_bytes() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"tokens"));
        assert!(!constant_time_eq(b"token", b"taken"));
    }
}
