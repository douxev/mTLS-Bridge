//! Proxy HTTP/1.1 per-requête entre l'app cliente (en clair) et l'upstream
//! mTLS.
//!
//! Sens requête : le header `Host:` de *chaque* requête d'une connexion
//! keepalive est remplacé par le hostname réel de l'upstream. Indispensable
//! quand l'upstream est un reverse-proxy (Caddy, Nginx, Traefik) qui route
//! par Host header — sans cette réécriture, le RP voit `Host: 192.0.2.X:port`
//! et tombe sur son vhost par défaut → 404. Le token de path éventuel est
//! vérifié puis retiré, ou remplacé par le cookie de session (cf.
//! [`PathAuth`]).
//!
//! Sens réponse (mode loopback) : les URLs absolues de l'upstream sont
//! réécrites vers la base loopback dans `Location:` et dans les bodies
//! textuels de taille raisonnable.
//!
//! Les bodies sont transmis selon leur framing (Content-Length, chunked) pour
//! que la boucle reprenne pile sur le message suivant de la connexion.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

const MAX_HEADER_BUF: usize = 64 * 1024;

/// Longueur max d'une ligne de framing chunked (taille + extensions, ou
/// trailer). Borne la RAM face à un pair qui n'envoie jamais de CRLF.
const MAX_CHUNK_LINE: usize = MAX_HEADER_BUF;

/// Au-delà, un body réécrivable n'est plus bufferisé : il est streamé tel
/// quel, sans réécriture. Borne la RAM par connexion (process en
/// panic=abort : une allocation ratée tue toute l'app).
pub(crate) const MAX_REWRITE_BODY: usize = 4 * 1024 * 1024;

/// Traces HTTP détaillées (méthode, path sans query ni token, statut,
/// tailles) en `log::trace!`. Off par défaut. Ne jamais y ajouter de
/// cookies, de tokens, de `Location` ni d'extraits de body.
const HTTP_TRACE: bool = false;

const IO_BUF: usize = 16 * 1024;

/// Cherche `\r\n\r\n` dans `haystack` et renvoie l'index juste après.
fn find_headers_end(haystack: &[u8]) -> Option<usize> {
    haystack.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn unexpected_eof(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}

/// `Content-Length` strict : chiffres uniquement (pas de `+5`, pas de vide).
fn parse_content_length(value: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(value).ok()?.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn mentions_chunked(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

/// Taille d'un chunk : `1*HEXDIG [ ";" extensions ]`.
fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    let line = std::str::from_utf8(line).map_err(|_| invalid_data("taille de chunk non ASCII"))?;
    let size = line.split(';').next().unwrap_or("").trim();
    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid_data("taille de chunk invalide"));
    }
    u64::from_str_radix(size, 16).map_err(|_| invalid_data("taille de chunk hors limites"))
}

/// Détermine la longueur du body d'une requête HTTP/1.1 à partir des headers.
pub(crate) enum BodyLen {
    None,
    Fixed(u64),
    Chunked,
}

fn body_length(headers: &[httparse::Header<'_>]) -> BodyLen {
    let mut chunked = false;
    let mut len: Option<u64> = None;
    for h in headers {
        if h.name.is_empty() {
            break;
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked |= mentions_chunked(h.value);
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if let Some(n) = parse_content_length(h.value) {
                len = Some(n);
            }
        }
    }
    if chunked {
        BodyLen::Chunked
    } else if let Some(n) = len {
        BodyLen::Fixed(n)
    } else {
        BodyLen::None
    }
}

// ----- Lecture bufferisée + framing ------------------------------------------

/// Issue de l'accumulation des headers d'un message.
enum Head {
    /// Index juste après `\r\n\r\n` dans `BufIn::buf`.
    Complete(usize),
    TooLarge,
    Eof,
}

/// Body réécrivable lu en mémoire, ou abandonné en route parce qu'il
/// dépasse [`MAX_REWRITE_BODY`].
enum Collected {
    Complete(Vec<u8>),
    /// Début du body déjà lu (décodé). Pour un body chunked, le flux est
    /// arrêté pile sur la ligne de taille du chunk qui aurait fait déborder.
    Overflow(Vec<u8>),
}

/// Lecteur bufferisé : `buf` contient les octets déjà lus mais pas encore
/// consommés (fin des headers, début du body, message suivant en pipelining).
struct BufIn<R> {
    rd: R,
    buf: Vec<u8>,
    tmp: Box<[u8]>,
}

impl<R: AsyncRead + Unpin> BufIn<R> {
    fn new(rd: R) -> Self {
        Self::with_prefix(rd, Vec::with_capacity(IO_BUF))
    }

    /// `prefix` : octets déjà lus sur `rd`, consommés en premier.
    fn with_prefix(rd: R, prefix: Vec<u8>) -> Self {
        Self {
            rd,
            buf: prefix,
            tmp: vec![0u8; IO_BUF].into_boxed_slice(),
        }
    }

    /// Une lecture, ajoutée à `buf`. 0 = EOF.
    async fn fill(&mut self) -> io::Result<usize> {
        let n = self.rd.read(&mut self.tmp).await?;
        self.buf.extend_from_slice(&self.tmp[..n]);
        Ok(n)
    }

    /// Accumule jusqu'à la fin des headers (`\r\n\r\n`).
    async fn read_head(&mut self) -> io::Result<Head> {
        let mut scanned: usize = 0;
        loop {
            let from = scanned.saturating_sub(3);
            if let Some(p) = find_headers_end(&self.buf[from..]) {
                return Ok(Head::Complete(from + p));
            }
            scanned = self.buf.len();
            if self.buf.len() >= MAX_HEADER_BUF {
                return Ok(Head::TooLarge);
            }
            if self.fill().await? == 0 {
                return Ok(Head::Eof);
            }
        }
    }

    /// Renvoie l'index du prochain `\r\n` dans `buf` (la ligne est
    /// `buf[..idx]`, rien n'est consommé).
    async fn read_line(&mut self) -> io::Result<usize> {
        let mut scanned: usize = 0;
        loop {
            let from = scanned.saturating_sub(1);
            if let Some(p) = self.buf[from..].windows(2).position(|w| w == b"\r\n") {
                return Ok(from + p);
            }
            scanned = self.buf.len();
            if self.buf.len() > MAX_CHUNK_LINE {
                return Err(invalid_data("ligne de framing chunked trop longue"));
            }
            if self.fill().await? == 0 {
                return Err(unexpected_eof("EOF dans le framing chunked"));
            }
        }
    }

    /// Consomme le `\r\n` qui termine les données d'un chunk.
    async fn take_crlf(&mut self) -> io::Result<()> {
        while self.buf.len() < 2 {
            if self.fill().await? == 0 {
                return Err(unexpected_eof("EOF après les données d'un chunk"));
            }
        }
        if &self.buf[..2] != b"\r\n" {
            return Err(invalid_data("CRLF attendu après les données d'un chunk"));
        }
        self.buf.drain(..2);
        Ok(())
    }

    /// Transmet exactement `n` octets vers `dst` sans les accumuler.
    async fn forward_exact<W: AsyncWrite + Unpin>(&mut self, dst: &mut W, n: u64) -> io::Result<()> {
        let from_buf = (self.buf.len() as u64).min(n) as usize;
        if from_buf > 0 {
            dst.write_all(&self.buf[..from_buf]).await?;
            self.buf.drain(..from_buf);
        }
        let mut remaining = n - from_buf as u64;
        while remaining > 0 {
            // Jamais plus que le body : la suite appartient au message suivant.
            let want = (self.tmp.len() as u64).min(remaining) as usize;
            let r = self.rd.read(&mut self.tmp[..want]).await?;
            if r == 0 {
                return Err(unexpected_eof("EOF au milieu d'un body"));
            }
            dst.write_all(&self.tmp[..r]).await?;
            remaining -= r as u64;
        }
        Ok(())
    }

    /// Lit exactement `n` octets dans `out`.
    async fn read_exact_into(&mut self, out: &mut Vec<u8>, n: usize) -> io::Result<()> {
        let from_buf = self.buf.len().min(n);
        out.extend_from_slice(&self.buf[..from_buf]);
        self.buf.drain(..from_buf);
        let mut remaining = n - from_buf;
        while remaining > 0 {
            let want = self.tmp.len().min(remaining);
            let r = self.rd.read(&mut self.tmp[..want]).await?;
            if r == 0 {
                return Err(unexpected_eof("EOF au milieu d'un body"));
            }
            out.extend_from_slice(&self.tmp[..r]);
            remaining -= r;
        }
        Ok(())
    }

    /// Transmet un body chunked tel quel (tailles, extensions, trailers) et
    /// s'arrête pile à la fin du message.
    async fn forward_chunked<W: AsyncWrite + Unpin>(&mut self, dst: &mut W) -> io::Result<()> {
        loop {
            let end = self.read_line().await?;
            let size = parse_chunk_size(&self.buf[..end])?;
            dst.write_all(&self.buf[..end + 2]).await?;
            self.buf.drain(..end + 2);
            if size == 0 {
                // Trailers éventuels puis ligne vide finale.
                loop {
                    let end = self.read_line().await?;
                    dst.write_all(&self.buf[..end + 2]).await?;
                    self.buf.drain(..end + 2);
                    if end == 0 {
                        return Ok(());
                    }
                }
            }
            self.forward_exact(dst, size).await?;
            self.take_crlf().await?;
            dst.write_all(b"\r\n").await?;
        }
    }

    /// Décode un body chunked tant qu'il tient dans `cap` (trailers ignorés).
    async fn collect_chunked(&mut self, cap: usize) -> io::Result<Collected> {
        let mut body = Vec::new();
        loop {
            let end = self.read_line().await?;
            let size = parse_chunk_size(&self.buf[..end])?;
            if size == 0 {
                self.buf.drain(..end + 2);
                loop {
                    let end = self.read_line().await?;
                    self.buf.drain(..end + 2);
                    if end == 0 {
                        return Ok(Collected::Complete(body));
                    }
                }
            }
            if body.len() as u64 + size > cap as u64 {
                // Ligne de taille laissée dans `buf` : forward_chunked repart
                // de ce chunk.
                return Ok(Collected::Overflow(body));
            }
            self.buf.drain(..end + 2);
            self.read_exact_into(&mut body, size as usize).await?;
            self.take_crlf().await?;
        }
    }

    /// Lit jusqu'à EOF tant que ça tient dans `cap`.
    async fn collect_until_eof(&mut self, cap: usize) -> io::Result<Collected> {
        let mut body = std::mem::take(&mut self.buf);
        while body.len() <= cap {
            let r = self.rd.read(&mut self.tmp).await?;
            if r == 0 {
                return Ok(Collected::Complete(body));
            }
            body.extend_from_slice(&self.tmp[..r]);
        }
        Ok(Collected::Overflow(body))
    }

    /// Bascule en copie brute pour le reste de la connexion.
    async fn copy_rest<W: AsyncWrite + Unpin>(&mut self, dst: &mut W) -> io::Result<()> {
        if !self.buf.is_empty() {
            dst.write_all(&self.buf).await?;
            self.buf.clear();
        }
        tokio::io::copy(&mut self.rd, dst).await.map(|_| ())
    }
}

/// Parse les headers, renvoie (octets réécrits, longueur du body restant à
/// pomper depuis le client après l'éventuel chevauchement déjà bufferisé).
/// Résultat de rewrite_and_split : la traduction réussie OU une indication
/// que la requête a un token absent/invalide → la pipe doit close.
pub(crate) enum RewriteOutcome {
    Ok {
        rewritten: Vec<u8>,
        body_len: BodyLen,
        /// Requête `Connection: upgrade` + `Upgrade:` (WebSocket, h2c) : la
        /// suite de la connexion n'est plus du HTTP/1.1 si le serveur répond 101.
        upgrade: bool,
        /// Requête HEAD : sa réponse n'a jamais de body, quel que soit son
        /// Content-Length.
        is_head: bool,
        /// Acceptée grâce au token, sans cookie de session valide : la
        /// réponse doit poser le cookie.
        set_cookie: bool,
    },
    /// Parse échoué — caller fait un raw copy fallback.
    NotHttp,
    /// Ni token ni cookie de session valide alors qu'un token est exigé —
    /// caller close.
    BadToken,
}

// ----- Contrôle d'accès loopback : token de path + cookie de session --------
//
// Le token dans le path isole le proxy des autres apps du téléphone (le
// contrôle par UID est inopérant en loopback). Mais les webviews (jellyfin-web,
// Nextcloud) chargent aussi des chemins absolus `/web/…` qui perdent le
// préfixe `/<token>`. Une requête validée par le token reçoit donc un cookie
// de session ; les requêtes qui le portent sont acceptées sans le préfixe. Le
// secret est tiré au démarrage du proxy et ne vit qu'en mémoire : un
// redémarrage invalide les cookies posés, la prochaine URL avec token les
// renouvelle.

/// Préfixe du nom de nos cookies. Ils restent entre le client et le proxy :
/// jamais transmis à l'upstream (ceux des autres proxys loopback non plus —
/// les cookies de `127.0.0.1` sont partagés entre tous les ports).
const AUTH_COOKIE_PREFIX: &str = "mtlsb_";

/// Octets aléatoires du secret de cookie (256 bits).
const AUTH_COOKIE_SECRET_LEN: usize = 32;

/// Motif d'un refus du contrôle d'accès (token de path / cookie de session),
/// remonté dans l'audit. Ne porte volontairement ni le token, ni le cookie,
/// ni le chemin de la requête refusée.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TokenRejection {
    /// Requête HTTP sans token valide dans le path ni cookie de session valide.
    InvalidToken,
    /// Flux qui n'est pas du HTTP/1.1 alors qu'un token est exigé.
    NotHttp,
    /// Headers au-delà de la limite alors qu'un token est exigé.
    HeadersTooLarge,
}

impl std::fmt::Display for TokenRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidToken => "ni token ni cookie de session valide",
            Self::NotHttp => "non-HTTP + token requis",
            Self::HeadersTooLarge => "headers trop gros + token requis",
        })
    }
}

impl std::error::Error for TokenRejection {}

impl From<TokenRejection> for io::Error {
    fn from(r: TokenRejection) -> Self {
        io::Error::new(io::ErrorKind::PermissionDenied, r)
    }
}

/// Refus du contrôle d'accès porté par une erreur des pipes, s'il y en a un.
pub(crate) fn token_rejection(e: &io::Error) -> Option<TokenRejection> {
    e.get_ref()?.downcast_ref::<TokenRejection>().copied()
}

/// Token de path exigé par un proxy loopback, et cookie de session qui le
/// remplace une fois posé. Partagé par toutes les connexions du proxy.
pub struct PathAuth {
    token: String,
    cookie_name: String,
    cookie_secret: String,
    /// Valeur complète du header `Set-Cookie` à émettre.
    set_cookie: Arc<str>,
}

impl PathAuth {
    /// `cookie_id` (l'id de la config) donne un nom de cookie distinct par
    /// proxy : plusieurs proxys loopback tournent sur le même hôte
    /// `127.0.0.1`, donc dans le même espace de cookies.
    pub fn new(token: &str, cookie_id: &str) -> io::Result<Self> {
        let short: String = cookie_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(8)
            .collect();
        let cookie_name = format!("{AUTH_COOKIE_PREFIX}{short}");
        let cookie_secret = random_hex(AUTH_COOKIE_SECRET_LEN)?;
        let set_cookie =
            format!("{cookie_name}={cookie_secret}; HttpOnly; SameSite=Strict; Path=/").into();
        Ok(Self {
            token: token.to_string(),
            cookie_name,
            cookie_secret,
            set_cookie,
        })
    }

    /// Un header `Cookie:` de la requête porte-t-il notre cookie avec le bon
    /// secret ?
    fn has_valid_cookie(&self, headers: &[httparse::Header<'_>]) -> bool {
        let name = self.cookie_name.as_bytes();
        let mut found = false;
        for h in headers.iter().take_while(|h| !h.name.is_empty()) {
            if !h.name.eq_ignore_ascii_case("cookie") {
                continue;
            }
            for pair in h.value.split(|&b| b == b';') {
                if let Some((n, v)) = split_cookie_pair(pair) {
                    // Pas de court-circuit : temps indépendant de la position.
                    found |= n == name && ct_eq(v, self.cookie_secret.as_bytes());
                }
            }
        }
        found
    }
}

/// `nom=valeur` d'une paire de cookie, espaces autour retirés.
fn split_cookie_pair(pair: &[u8]) -> Option<(&[u8], &[u8])> {
    let pair = pair.trim_ascii();
    let eq = pair.iter().position(|&b| b == b'=')?;
    Some((pair[..eq].trim_ascii(), pair[eq + 1..].trim_ascii()))
}

/// Comparaison en temps constant (à longueur égale) : le secret ne fuit pas
/// par le temps de réponse.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `n` octets du CSPRNG (celui d'aws-lc, déjà embarqué par rustls), en hexa.
fn random_hex(n: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; n];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("générateur aléatoire indisponible"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Vérifie que `path` commence par `/<token>` suivi de `/`, `?` ou rien, et
/// renvoie le path strippé (= ce qu'on enverra à l'upstream). Renvoie None
/// si mismatch.
fn strip_path_token(path: &str, token: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?.strip_prefix(token)?;
    if rest.is_empty() {
        // /token → /
        Some("/".to_string())
    } else if rest.starts_with('/') {
        // /token/foo → /foo
        Some(rest.to_string())
    } else if rest.starts_with('?') {
        // /token?x=1 → /?x=1 (base réécrite `http://127.0.0.1:P/token` + query)
        Some(format!("/{rest}"))
    } else {
        // /tokenXYZ : pas le bon segment.
        None
    }
}

fn is_wildcard_etag(value: &[u8]) -> bool {
    value.trim_ascii() == b"*"
}

/// `rewrites_responses` : la réponse passera par le pipe de réécriture (cf.
/// [`http_request_pipe`]).
fn rewrite_and_split(
    headers_plus_maybe_body: &[u8],
    new_host: &str,
    headers_len: usize,
    auth: Option<&PathAuth>,
    rewrites_responses: bool,
) -> RewriteOutcome {
    let headers_bytes = &headers_plus_maybe_body[..headers_len];
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hbuf);
    if !matches!(req.parse(headers_bytes), Ok(httparse::Status::Complete(_))) {
        return RewriteOutcome::NotHttp;
    }
    let Some(method) = req.method else { return RewriteOutcome::NotHttp };
    let Some(path) = req.path else { return RewriteOutcome::NotHttp };
    let version = req.version.unwrap_or(1);
    let bl = body_length(req.headers);
    let upgrade = is_upgrade_request(req.headers);
    let is_head = method == "HEAD";
    let safe_method = is_head || method == "GET";

    // Si token configuré, vérifier ET stripper le préfixe avant tout. Sans
    // préfixe, le cookie de session fait foi (chemins absolus des webviews).
    let (effective_path, set_cookie): (std::borrow::Cow<'_, str>, bool) = match auth {
        Some(a) => {
            let cookie_ok = a.has_valid_cookie(req.headers);
            match strip_path_token(path, &a.token) {
                Some(stripped) => (std::borrow::Cow::Owned(stripped), !cookie_ok),
                None if cookie_ok => (std::borrow::Cow::Borrowed(path), false),
                None => return RewriteOutcome::BadToken,
            }
        }
        None => (std::borrow::Cow::Borrowed(path), false),
    };

    let mut out = Vec::with_capacity(headers_len + 64);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(effective_path.as_bytes());
    out.extend_from_slice(b" HTTP/1.");
    out.push(if version == 0 { b'0' } else { b'1' });
    out.extend_from_slice(b"\r\n");

    if HTTP_TRACE {
        // Path déjà débarrassé du token ; la query peut porter des secrets
        // (`api_key=` Jellyfin), on la coupe.
        let path_only = effective_path.split('?').next().unwrap_or("");
        log::trace!("req: {method} {path_only}");
    }
    let mut host_done = false;
    for h in req.headers.iter() {
        if h.name.is_empty() {
            break;
        }
        if h.name.eq_ignore_ascii_case("host") {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(new_host.as_bytes());
            out.extend_from_slice(b"\r\n");
            host_done = true;
        } else if h.name.eq_ignore_ascii_case("cookie") {
            // Retire nos cookies `mtlsb_*` et restaure les préfixes
            // `__Host-`/`__Secure-` qu'on avait masqués pour le browser (cf.
            // rewrite_set_cookie_outbound côté réponse). Plus rien : pas de
            // header vide.
            let forwarded = rewrite_cookie_inbound(h.value);
            if !forwarded.is_empty() {
                out.extend_from_slice(b"Cookie: ");
                out.extend_from_slice(&forwarded);
                out.extend_from_slice(b"\r\n");
            }
        } else if rewrites_responses && h.name.eq_ignore_ascii_case("accept-encoding") {
            // On *force* identity côté upstream pour que la pipe de réponse
            // puisse string-rewrite le body sans avoir à décompresser
            // gzip/brotli/zstd. Coût bande passante négligeable pour les
            // petits JSON/HTML d'auth ; les payloads volumineux (downloads
            // média) ne sont de toute façon pas rewrités. Sans réécriture
            // (VPN), la compression négociée par le client est gardée.
            continue;
        } else if rewrites_responses
            && safe_method
            && (h.name.eq_ignore_ascii_case("if-modified-since")
                || (h.name.eq_ignore_ascii_case("if-none-match") && !is_wildcard_etag(h.value)))
        {
            // Sur GET/HEAD seulement : pour que le serveur ne renvoie pas un
            // 304 qui ferait resservir au browser une copie en cache
            // antérieure à la réécriture. Sur PUT/MOVE/…, ces préconditions
            // protègent contre l'écrasement (`If-None-Match: *` de WebDAV
            // Nextcloud) : on les garde.
            continue;
        } else {
            out.extend_from_slice(h.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value);
            out.extend_from_slice(b"\r\n");
        }
    }
    if !host_done {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(new_host.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if rewrites_responses {
        out.extend_from_slice(b"Accept-Encoding: identity\r\n");
    }
    out.extend_from_slice(b"\r\n");
    RewriteOutcome::Ok {
        rewritten: out,
        body_len: bl,
        upgrade,
        is_head,
        set_cookie,
    }
}

/// `Upgrade:` présent ET `Connection:` contenant le token `upgrade`.
fn is_upgrade_request(headers: &[httparse::Header<'_>]) -> bool {
    let mut has_upgrade = false;
    let mut conn_upgrade = false;
    for h in headers {
        if h.name.is_empty() {
            break;
        }
        if h.name.eq_ignore_ascii_case("upgrade") {
            has_upgrade = true;
        } else if h.name.eq_ignore_ascii_case("connection") {
            conn_upgrade |= std::str::from_utf8(h.value)
                .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
                .unwrap_or(false);
        }
    }
    has_upgrade && conn_upgrade
}

/// Pipe per-requête : lit inbound, réécrit le Host header de CHAQUE requête
/// HTTP/1.1 keepalive, transmet à upstream. Boucle jusqu'à EOF inbound ou
/// erreur. Requêtes préparées pour une réponse réécrite (mode loopback).
pub async fn http_pipe_with_host_rewrite<R, W>(
    inbound: R,
    upstream: W,
    new_host: &str,
    path_token: Option<&str>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let auth = path_token.map(|t| PathAuth::new(t, "")).transpose()?;
    http_request_pipe(inbound, Vec::new(), upstream, new_host, auth.as_ref(), None, true).await
}

/// Ce que le pipe de réponse doit savoir de chaque requête, annoncé dans
/// l'ordre des requêtes.
#[derive(Debug, Default)]
pub(crate) struct RequestMeta {
    /// Requête HEAD : la réponse n'a jamais de body, quel que soit son
    /// Content-Length.
    pub is_head: bool,
    /// `Set-Cookie` de session à ajouter à la réponse.
    pub set_cookie: Option<Arc<str>>,
}

/// Lit la première requête d'une connexion et applique le contrôle d'accès
/// (token ou cookie de session) **sans rien transmettre**, pour que
/// l'appelant n'ouvre la connexion upstream qu'une fois le client accepté.
///
/// Renvoie les octets déjà lus, à rejouer en `prefix` de
/// [`http_request_pipe`] (qui revalide la requête), ou `None` si le client a
/// fermé avant une requête complète. Refus : `PermissionDenied` portant le
/// [`TokenRejection`] (cf. [`token_rejection`]).
pub(crate) async fn read_first_request<R>(
    inbound: &mut R,
    auth: Option<&PathAuth>,
) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut inb = BufIn::new(inbound);
    let rejection = match inb.read_head().await? {
        Head::Eof => return Ok(None),
        // Sans token, rien à contrôler : le pipe basculera en copie brute.
        Head::TooLarge => auth.map(|_| TokenRejection::HeadersTooLarge),
        // Seul le contrôle d'accès compte ici : la requête réécrite est jetée.
        Head::Complete(end) => match rewrite_and_split(&inb.buf, "", end, auth, false) {
            RewriteOutcome::Ok { .. } => None,
            RewriteOutcome::NotHttp => auth.map(|_| TokenRejection::NotHttp),
            RewriteOutcome::BadToken => Some(TokenRejection::InvalidToken),
        },
    };
    match rejection {
        None => Ok(Some(inb.buf)),
        Some(r) => Err(r.into()),
    }
}

/// Comme [`http_pipe_with_host_rewrite`], en reprenant les octets déjà lus
/// `prefix` et en annonçant sur `meta_tx`, dans l'ordre, ce que le pipe de
/// réponse doit savoir de chaque requête.
///
/// `rewrites_responses` : les réponses passent par [`http_response_pipe`]
/// (mode loopback). Sinon (mode VPN, copie brute), la requête garde son
/// `Accept-Encoding` et ses préconditions de cache, qui ne servent à rien
/// d'autre qu'à la réécriture.
pub(crate) async fn http_request_pipe<R, W>(
    inbound: R,
    prefix: Vec<u8>,
    mut upstream: W,
    new_host: &str,
    auth: Option<&PathAuth>,
    meta_tx: Option<mpsc::UnboundedSender<RequestMeta>>,
    rewrites_responses: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut inb = BufIn::with_prefix(inbound, prefix);
    loop {
        // 1. Accumuler jusqu'à \r\n\r\n (fin de headers).
        let headers_end = match inb.read_head().await? {
            Head::Complete(p) => p,
            Head::TooLarge => {
                // Headers trop gros — soit pas du HTTP, soit attaque. On forward
                // brut et on quitte le mode rewrite. Si token configuré, ne pas
                // fallback (l'attaque arrive depuis un client non autorisé).
                if auth.is_some() {
                    return Err(TokenRejection::HeadersTooLarge.into());
                }
                return inb.copy_rest(&mut upstream).await;
            }
            Head::Eof => {
                // EOF avant requête complète : on flush ce qu'il reste et on sort propre.
                if !inb.buf.is_empty() && auth.is_none() {
                    upstream.write_all(&inb.buf).await?;
                }
                upstream.flush().await?;
                return Ok(());
            }
        };

        // 2. Parser + réécrire les headers (+ strip token si présent).
        let outcome = rewrite_and_split(&inb.buf, new_host, headers_end, auth, rewrites_responses);
        let (rewritten_headers, body_len, upgrade, meta) = match outcome {
            RewriteOutcome::Ok { rewritten, body_len, upgrade, is_head, set_cookie } => {
                let set_cookie = auth.filter(|_| set_cookie).map(|a| Arc::clone(&a.set_cookie));
                (rewritten, body_len, upgrade, RequestMeta { is_head, set_cookie })
            }
            RewriteOutcome::BadToken => {
                log::warn!("http_pipe: token mismatch — close fail-closed");
                return Err(TokenRejection::InvalidToken.into());
            }
            RewriteOutcome::NotHttp => {
                if auth.is_some() {
                    // Token configuré mais payload pas du HTTP/1.1 valide →
                    // ne pas leaker vers l'upstream.
                    return Err(TokenRejection::NotHttp.into());
                }
                log::warn!("http_pipe: parse headers failed, fallback raw copy");
                return inb.copy_rest(&mut upstream).await;
            }
        };
        // Annoncée AVANT l'envoi : la réponse ne peut pas arriver avant.
        if let Some(tx) = &meta_tx {
            let _ = tx.send(meta);
        }
        upstream.write_all(&rewritten_headers).await?;
        inb.buf.drain(..headers_end);

        if upgrade {
            // Handshake WebSocket (ou h2c) validé (token compris) : tout ce qui
            // suit sont des trames, plus des requêtes HTTP/1.1. On ne cherche
            // plus de `\r\n\r\n`, sinon les trames restent coincées ici.
            return inb.copy_rest(&mut upstream).await;
        }

        // 3. Forward le body selon Content-Length / Transfer-Encoding, puis
        //    requête suivante.
        match body_len {
            BodyLen::None => {}
            BodyLen::Fixed(n) => inb.forward_exact(&mut upstream, n).await?,
            BodyLen::Chunked => inb.forward_chunked(&mut upstream).await?,
        }
        upstream.flush().await?;
    }
}

// ============================================================================
// Réponse upstream → client : réécriture des URLs absolues qui leakent depuis
// le serveur (Location: + corps JSON/HTML). Indispensable pour les flows OAuth
// type Nextcloud Login v2 où le serveur renvoie l'URL canonique upstream
// (`https://media.example.com/...`) dans le body et les redirects — sans cette
// réécriture, le navigateur de l'app cible tape directement sur le vrai
// domaine et bypasse complètement notre proxy mTLS.
// ============================================================================

/// Configuration de la réécriture de réponse. Liste de paires (canonique
/// upstream → loopback). On supporte une liste pour les cas où Nextcloud
/// émet plusieurs hostnames canoniques selon le contexte (ex. la valeur
/// `overwrite.cli.url` est utilisée pour certaines URLs même quand le Host
/// HTTP courant est différent).
#[derive(Clone, Debug)]
pub struct ResponseRewrite {
    pub from_urls: Vec<String>,
    pub to_url: String,
}

/// Content-types dont on accepte de buffer + réécrire le body. Tout le reste
/// (images, vidéos, octets, downloads) est streamé tel quel pour ne pas
/// exploser la RAM.
fn is_rewritable_content_type(ct: &str) -> bool {
    let main = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(
        main.as_str(),
        "application/json"
            | "application/javascript"
            | "application/xml"
            | "application/xhtml+xml"
            | "text/html"
            | "text/plain"
            | "text/xml"
            | "text/css"
            // text/javascript : indispensable pour Nextcloud, qui embarque
            // `OC.config.baseUrl="https://upstream"` dans son bundle JS — sans
            // réécriture, les XHR/fetch frontend tapent direct sur l'upstream
            // et déclenchent le prompt cert mTLS dans le navigateur.
            | "text/javascript"
    )
}

// ----- Cookie name <-> proxy-safe rewrite -----------------------------------
//
// Le browser refuse les cookies préfixés `__Host-` ou `__Secure-` si la
// réponse ne vient PAS d'un scheme « secure » (HTTPS). Notre downstream est
// `http://127.0.0.1:<port>` → tous les cookies de Nextcloud (qui set
// `__Host-nc_sameSiteCookielax` etc.) seraient silencieusement droppés par
// Chrome. Conséquence : la session côté serveur reste sans ses cookies anti-
// CSRF, et le `stateToken` du form de login ne matche jamais celui en session.
//
// Solution réversible : on **renomme** le préfixe avant émission vers le
// browser, et on le **restaure** dans la requête vers l'upstream. Le browser
// ne sait pas qu'il s'agissait d'un `__Host-`, l'upstream ne sait pas qu'on
// l'a touché.
const PFX_HOST_ORIG: &str = "__Host-";
const PFX_HOST_PROXY: &str = "nhx_";
const PFX_SECURE_ORIG: &str = "__Secure-";
const PFX_SECURE_PROXY: &str = "nsx_";

/// Transforme un header `Set-Cookie` upstream → downstream : renomme les
/// préfixes `__Host-`/`__Secure-` et supprime les attributs `Secure` et
/// `Domain=` (incompatibles avec http://127.0.0.1).
fn rewrite_set_cookie_outbound(value: &str) -> String {
    let (name_value, attrs) = match value.split_once(';') {
        Some((nv, rest)) => (nv, Some(rest)),
        None => (value, None),
    };
    let (name, val) = name_value.split_once('=').unwrap_or((name_value, ""));
    let name_trim = name.trim();
    let new_name = if let Some(rest) = name_trim.strip_prefix(PFX_HOST_ORIG) {
        format!("{PFX_HOST_PROXY}{rest}")
    } else if let Some(rest) = name_trim.strip_prefix(PFX_SECURE_ORIG) {
        format!("{PFX_SECURE_PROXY}{rest}")
    } else {
        name_trim.to_string()
    };
    let mut out = format!("{new_name}={val}");
    if let Some(rest) = attrs {
        for attr in rest.split(';') {
            let trimmed = attr.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if lower == "secure" || lower.starts_with("domain=") {
                continue;
            }
            out.push_str("; ");
            out.push_str(trimmed);
        }
    }
    out
}

/// Transforme un header `Cookie:` downstream → upstream : retire nos cookies
/// `mtlsb_*` (cf. [`PathAuth`]) et restaure les préfixes
/// `__Host-`/`__Secure-` qu'on avait masqués pour le browser. Travaille sur
/// les octets : une valeur non UTF-8 ne doit pas faire passer nos cookies.
fn rewrite_cookie_inbound(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for pair in value.split(|&b| b == b';') {
        let pair = pair.trim_ascii();
        if pair.is_empty() {
            continue;
        }
        let name = split_cookie_pair(pair).map_or(pair, |(n, _)| n);
        if name.starts_with(AUTH_COOKIE_PREFIX.as_bytes()) {
            continue;
        }
        if !out.is_empty() {
            out.extend_from_slice(b"; ");
        }
        if let Some(rest) = pair.strip_prefix(PFX_HOST_PROXY.as_bytes()) {
            out.extend_from_slice(PFX_HOST_ORIG.as_bytes());
            out.extend_from_slice(rest);
        } else if let Some(rest) = pair.strip_prefix(PFX_SECURE_PROXY.as_bytes()) {
            out.extend_from_slice(PFX_SECURE_ORIG.as_bytes());
            out.extend_from_slice(rest);
        } else {
            out.extend_from_slice(pair);
        }
    }
    out
}

/// Encode `:` et `/` en percent-encoding pour matcher les `redirect_uri=`
/// imbriqués dans une URL. On émet les variantes upper + lower pour couvrir
/// les serveurs qui n'utilisent pas la casse RFC 3986.
fn percent_encode_url(url: &str, upper: bool) -> String {
    let mut out = String::with_capacity(url.len() * 3);
    for c in url.chars() {
        match c {
            ':' => out.push_str(if upper { "%3A" } else { "%3a" }),
            '/' => out.push_str(if upper { "%2F" } else { "%2f" }),
            _ => out.push(c),
        }
    }
    out
}

/// Variantes de `from` → `to`, dans l'ordre d'application :
/// - forme nue (`https://host/path`)
/// - percent-encoded upper/lower (cas `redirect_uri=` imbriqué dans une URL),
/// - JSON-escaped (`https:\/\/host\/path`) — PHP `json_encode` escape les
///   slashes par défaut (sans `JSON_UNESCAPED_SLASHES`), c'est ce que renvoie
///   Nextcloud sur `/index.php/login/v2`.
fn url_variants(from: &str, to: &str) -> [(String, String); 4] {
    [
        (from.to_string(), to.to_string()),
        (percent_encode_url(from, true), percent_encode_url(to, true)),
        (percent_encode_url(from, false), percent_encode_url(to, false)),
        (from.replace('/', "\\/"), to.replace('/', "\\/")),
    ]
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let last_start = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        let p = haystack[i..=last_start].iter().position(|&b| b == needle[0])?;
        let s = i + p;
        if &haystack[s..s + needle.len()] == needle {
            return Some(s);
        }
        i = s + 1;
    }
    None
}

fn hex_digit(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Les octets qui suivent une URL de base trouvée dans un texte la
/// terminent-ils ? Faux s'ils prolongent l'autorité : `https://h` ne doit
/// matcher ni `https://h.autre.com`, ni `https://h:8443`, ni `https://hx`,
/// ni `https://h@ailleurs`, y compris en percent-encodé (`%3A8443`, `%2E`).
/// Tout le reste termine l'URL de base : fin du texte, `/`, `?`, `#`,
/// guillemets, espace, `&`, `<`, l'antislash de `\/` ou `\"` (JSON), les
/// formes encodées `%2F`, `%3F`, `%22`…
fn ends_authority(rest: &[u8]) -> bool {
    // Non réservés RFC 3986, `:` (port), `@` (userinfo), non-ASCII (IDN).
    fn continues(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'@') || !b.is_ascii()
    }
    match rest {
        [] => true,
        [b'%', hi, lo, ..] => match (hex_digit(*hi), hex_digit(*lo)) {
            (Some(hi), Some(lo)) => !continues((hi << 4) | lo),
            _ => true,
        },
        [b, ..] => !continues(*b),
    }
}

/// Remplace chaque occurrence de l'URL de base `from` qui n'est pas le début
/// d'une autre autorité (cf. [`ends_authority`]). `None` si aucune.
fn replace_base_url(input: &[u8], from: &[u8], to: &[u8]) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    // `input[..copied]` est déjà dans `out`.
    let mut copied = 0;
    let mut search = 0;
    while let Some(p) = find_bytes(&input[search..], from) {
        let start = search + p;
        let end = start + from.len();
        if ends_authority(&input[end..]) {
            let o = out.get_or_insert_with(|| Vec::with_capacity(input.len()));
            o.extend_from_slice(&input[copied..start]);
            o.extend_from_slice(to);
            copied = end;
            search = end;
        } else {
            search = start + 1;
        }
    }
    let mut out = out?;
    out.extend_from_slice(&input[copied..]);
    Some(out)
}

/// Réécrit toutes les variantes de chaque host canonique configuré
/// (typiquement l'upstream + tout host additionnel que Nextcloud émet via
/// `overwrite.cli.url` ou autre) vers `to`, au niveau des octets : un body
/// non UTF-8 ressort intact en dehors des URLs remplacées. Seules les
/// occurrences où l'autorité s'arrête sont remplacées (cf.
/// [`ends_authority`]) : `https://h` ne touche ni `https://h:8443` ni
/// `https://h.autre.com`, quel que soit l'ordre de `from_urls`. `None` si rien
/// n'a changé.
pub(crate) fn rewrite_url_variants_bytes(
    input: &[u8],
    from_urls: &[String],
    to: &str,
) -> Option<Vec<u8>> {
    let mut cur: Option<Vec<u8>> = None;
    for from in from_urls.iter().filter(|f| !f.is_empty()) {
        for (f, t) in url_variants(from, to) {
            if let Some(next) = replace_base_url(cur.as_deref().unwrap_or(input), f.as_bytes(), t.as_bytes()) {
                cur = Some(next);
            }
        }
    }
    cur.filter(|out| out.as_slice() != input)
}

/// Variante `&str` pour les tests.
#[cfg(test)]
pub(crate) fn rewrite_url_variants(input: &str, from: &str, to: &str) -> String {
    match rewrite_url_variants_bytes(input.as_bytes(), &[from.to_string()], to) {
        Some(b) => String::from_utf8(b).expect("remplacement UTF-8 dans de l'UTF-8"),
        None => input.to_string(),
    }
}

enum RespBodyLen {
    None,
    Fixed(u64),
    Chunked,
    /// Pas de Content-Length ni Transfer-Encoding : body jusqu'à EOF (HTTP/1.0
    /// ou `Connection: close` côté upstream).
    UntilEof,
}

/// Header HTTP en données owned, pour relâcher le borrow sur le buffer
/// d'origine quand on doit le drainer.
struct OwnedHeader {
    name: String,
    value: Vec<u8>,
}

struct ResponseHead {
    status: u16,
    reason: String,
    version: u8,
    headers: Vec<OwnedHeader>,
}

fn parse_response_head(bytes: &[u8]) -> Option<ResponseHead> {
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut hbuf);
    if !matches!(resp.parse(bytes), Ok(httparse::Status::Complete(_))) {
        return None;
    }
    Some(ResponseHead {
        status: resp.code.unwrap_or(0),
        reason: resp.reason.unwrap_or("").to_string(),
        version: resp.version.unwrap_or(1),
        headers: resp
            .headers
            .iter()
            .take_while(|h| !h.name.is_empty())
            .map(|h| OwnedHeader {
                name: h.name.to_string(),
                value: h.value.to_vec(),
            })
            .collect(),
    })
}

fn response_body_length_owned(
    status: u16,
    method_was_head: bool,
    headers: &[OwnedHeader],
) -> RespBodyLen {
    // RFC 9112 §6.3 : 1xx, 204, 304 et toutes les réponses à HEAD n'ont
    // jamais de body, quoi qu'en dise Content-Length.
    if method_was_head || matches!(status, 100..=199 | 204 | 304) {
        return RespBodyLen::None;
    }
    let mut chunked = false;
    let mut content_length: Option<u64> = None;
    for h in headers {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked |= mentions_chunked(&h.value);
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if let Some(n) = parse_content_length(&h.value) {
                content_length = Some(n);
            }
        }
    }
    if chunked {
        RespBodyLen::Chunked
    } else if let Some(n) = content_length {
        RespBodyLen::Fixed(n)
    } else {
        RespBodyLen::UntilEof
    }
}

/// Le body de cette réponse peut-il être bufferisé et réécrit ?
fn body_is_rewritable(head: &ResponseHead) -> bool {
    // 206 : réécrire décalerait les octets annoncés par Content-Range.
    if head.status == 206 {
        return false;
    }
    let mut ct_ok = false;
    for h in &head.headers {
        let value = std::str::from_utf8(&h.value).unwrap_or("").trim();
        if h.name.eq_ignore_ascii_case("content-type") {
            ct_ok = is_rewritable_content_type(value);
        } else if h.name.eq_ignore_ascii_case("content-encoding") {
            // Serveur qui ignore notre `Accept-Encoding: identity` : un
            // remplacement octet par octet corromprait le flux compressé.
            if !value.eq_ignore_ascii_case("identity") {
                return false;
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            // `gzip, chunked` & co : on ne sait décoder que `chunked` seul.
            if !value.eq_ignore_ascii_case("chunked") {
                return false;
            }
        }
    }
    ct_ok
}

enum HeadMode {
    /// Body transmis tel quel : framing et en-têtes de cache d'origine.
    Passthrough,
    /// Body bufferisé, ré-émis avec un `Content-Length` recalculé. Si
    /// `modified`, ses en-têtes de cache ne décrivent plus ce qu'on envoie.
    Buffered { len: usize, modified: bool },
}

fn push_header(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

/// `session_cookie` : valeur d'un `Set-Cookie` de session à ajouter (cf.
/// [`PathAuth`]).
fn build_response_head(
    head: &ResponseHead,
    rewrite: &ResponseRewrite,
    mode: HeadMode,
    session_cookie: Option<&str>,
) -> Vec<u8> {
    let (buffered_len, modified) = match mode {
        HeadMode::Passthrough => (None, false),
        HeadMode::Buffered { len, modified } => (Some(len), modified),
    };
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(
        format!(
            "HTTP/1.{} {} {}\r\n",
            if head.version == 0 { '0' } else { '1' },
            head.status,
            head.reason,
        )
        .as_bytes(),
    );
    for h in &head.headers {
        let name_lower = h.name.to_ascii_lowercase();
        match name_lower.as_str() {
            "location" => {
                let rewritten = rewrite_url_variants_bytes(&h.value, &rewrite.from_urls, &rewrite.to_url);
                push_header(&mut out, &h.name, rewritten.as_deref().unwrap_or(&h.value));
            }
            "set-cookie" => {
                // Renomme `__Host-X`/`__Secure-X` (rejetés par Chrome sur HTTP
                // loopback) et strip `Secure`/`Domain=` pour que le browser
                // accepte effectivement le cookie. Réinjecté tel quel dans le
                // Cookie: header de la requête suivante (rewrite_cookie_inbound).
                match std::str::from_utf8(&h.value) {
                    Ok(v) => push_header(&mut out, &h.name, rewrite_set_cookie_outbound(v).as_bytes()),
                    Err(_) => push_header(&mut out, &h.name, &h.value),
                }
            }
            // Framing remplacé par notre Content-Length.
            "content-length" | "transfer-encoding" if buffered_len.is_some() => {}
            // Body réécrit : ces validateurs/durées décrivent la version
            // upstream. Un asset réécrit mis en cache survivrait à un
            // changement de config et resservirait une URL obsolète.
            "cache-control" | "etag" | "last-modified" | "expires" | "pragma" if modified => {}
            _ => push_header(&mut out, &h.name, &h.value),
        }
    }
    if let Some(n) = buffered_len {
        out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    if modified {
        out.extend_from_slice(b"Cache-Control: no-store\r\n");
    }
    if let Some(cookie) = session_cookie {
        push_header(&mut out, "Set-Cookie", cookie.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Pipe de réponse upstream → client avec réécriture, sans information sur
/// les méthodes des requêtes (aucune réponse n'est traitée comme réponse à
/// HEAD). Voir [`http_response_pipe`].
pub async fn http_response_pipe_with_rewrite<R, W>(
    upstream: R,
    downstream: W,
    rewrite: &ResponseRewrite,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (_tx, meta_rx) = mpsc::unbounded_channel();
    http_response_pipe(upstream, downstream, rewrite, meta_rx).await
}

/// Pipe de réponse upstream → client avec réécriture optionnelle.
/// Boucle sur les réponses HTTP/1.1 keepalive. Pour chaque réponse :
/// - parse status + headers,
/// - consomme sur `meta_rx` les infos de la requête correspondante (réponse
///   finale uniquement) : une réponse à HEAD n'a pas de body, et le cookie
///   de session éventuel est posé,
/// - réécrit `Location:` value (string-replace from → to + percent-encoded),
/// - si content-type est rewritable et le body tient dans
///   [`MAX_REWRITE_BODY`], accumule le body, réécrit, recalcule
///   `Content-Length`, supprime `Transfer-Encoding`,
/// - sinon stream le body tel quel en respectant son framing.
pub(crate) async fn http_response_pipe<R, W>(
    upstream: R,
    mut downstream: W,
    rewrite: &ResponseRewrite,
    mut meta_rx: mpsc::UnboundedReceiver<RequestMeta>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut up = BufIn::new(upstream);
    loop {
        // 1. Accumuler les headers de réponse.
        let headers_end = match up.read_head().await? {
            Head::Complete(p) => p,
            Head::TooLarge => {
                // Pas du HTTP propre — passthrough pour pas casser la connexion.
                return up.copy_rest(&mut downstream).await;
            }
            Head::Eof => {
                if !up.buf.is_empty() {
                    downstream.write_all(&up.buf).await?;
                }
                downstream.flush().await?;
                return Ok(());
            }
        };

        // 2. Parse status + headers en données owned, puis retire les headers
        //    du buffer (il ne reste que le body et la suite).
        let Some(head) = parse_response_head(&up.buf[..headers_end]) else {
            // Parse fail → passthrough pour rester safe.
            log::warn!("http_response_pipe: parse fail, fallback raw copy");
            return up.copy_rest(&mut downstream).await;
        };
        up.buf.drain(..headers_end);

        // 3. Une entrée par requête, consommée par la réponse finale (pas par
        //    les 1xx intermédiaires). Réponse non sollicitée (408…) : file
        //    vide → pas HEAD, pas de cookie.
        let interim = (100..=199).contains(&head.status);
        let meta = if interim {
            RequestMeta::default()
        } else {
            meta_rx.try_recv().unwrap_or_default()
        };
        let is_head = meta.is_head;
        let session_cookie = meta.set_cookie.as_deref();
        let body_len = response_body_length_owned(head.status, is_head, &head.headers);

        // 4. Body réécrivable et de taille raisonnable : on l'accumule.
        let collected = if body_is_rewritable(&head) {
            match body_len {
                RespBodyLen::Fixed(n) if n <= MAX_REWRITE_BODY as u64 => {
                    let mut body = Vec::with_capacity(n as usize);
                    up.read_exact_into(&mut body, n as usize).await?;
                    Some(Collected::Complete(body))
                }
                RespBodyLen::Chunked => Some(up.collect_chunked(MAX_REWRITE_BODY).await?),
                RespBodyLen::UntilEof => Some(up.collect_until_eof(MAX_REWRITE_BODY).await?),
                // Pas de body (1xx/204/304/HEAD) ou trop gros : passthrough.
                RespBodyLen::None | RespBodyLen::Fixed(_) => None,
            }
        } else {
            None
        };
        if HTTP_TRACE {
            log::trace!(
                "resp: status={} head={} buffered={}",
                head.status,
                is_head,
                matches!(collected, Some(Collected::Complete(_))),
            );
        }

        match collected {
            Some(Collected::Complete(body)) => {
                let (body, modified) =
                    match rewrite_url_variants_bytes(&body, &rewrite.from_urls, &rewrite.to_url) {
                        Some(rewritten) => (rewritten, true),
                        None => (body, false),
                    };
                let mode = HeadMode::Buffered { len: body.len(), modified };
                downstream.write_all(&build_response_head(&head, rewrite, mode, session_cookie)).await?;
                downstream.write_all(&body).await?;
                downstream.flush().await?;
                if matches!(body_len, RespBodyLen::UntilEof) {
                    // Tout consommé jusqu'à EOF : la connexion est finie.
                    return Ok(());
                }
                continue;
            }
            Some(Collected::Overflow(prefix)) => {
                // Trop gros pour être réécrit : on ré-émet le début déjà lu
                // puis on streame la suite, framing d'origine.
                downstream
                    .write_all(&build_response_head(&head, rewrite, HeadMode::Passthrough, session_cookie))
                    .await?;
                if !matches!(body_len, RespBodyLen::Chunked) {
                    downstream.write_all(&prefix).await?;
                    return up.copy_rest(&mut downstream).await;
                }
                if !prefix.is_empty() {
                    downstream.write_all(format!("{:x}\r\n", prefix.len()).as_bytes()).await?;
                    downstream.write_all(&prefix).await?;
                    downstream.write_all(b"\r\n").await?;
                }
                up.forward_chunked(&mut downstream).await?;
                downstream.flush().await?;
                continue;
            }
            None => {}
        }

        // 5. Passthrough : headers (Location/Set-Cookie réécrits) puis body
        //    tel quel.
        downstream
            .write_all(&build_response_head(&head, rewrite, HeadMode::Passthrough, session_cookie))
            .await?;
        match body_len {
            RespBodyLen::None => {
                if head.status == 101 {
                    // Switching Protocols (WebSocket…) : la suite n'est plus
                    // du HTTP/1.1, on bascule en copie brute.
                    return up.copy_rest(&mut downstream).await;
                }
            }
            RespBodyLen::Fixed(n) => up.forward_exact(&mut downstream, n).await?,
            RespBodyLen::Chunked => up.forward_chunked(&mut downstream).await?,
            RespBodyLen::UntilEof => return up.copy_rest(&mut downstream).await,
        }
        downstream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Test E2E du pipe sur 2 requêtes keepalive consécutives.
    #[tokio::test]
    async fn rewrites_host_on_each_request_in_keepalive() {
        let req1 = b"GET /System/Info/Public HTTP/1.1\r\n\
                     Host: 192.0.2.1:5001\r\n\
                     User-Agent: Jellyfin/1.0\r\n\r\n";
        let req2 = b"GET /Items HTTP/1.1\r\n\
                     Host: 192.0.2.1:5001\r\n\
                     Content-Length: 0\r\n\r\n";
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(req1);
        input.extend_from_slice(req2);
        // Inutile de stocker `input` séparément — on l'écrit dans le duplex.
        let _ = input; // assert mémoire pré-construite, sert juste de doc
        let mut upstream: Vec<u8> = Vec::new();
        let (mut tx, rx) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(req1).await.unwrap();
            tx.write_all(req2).await.unwrap();
            drop(tx); // ferme côté écriture → EOF côté lecture
        });
        http_pipe_with_host_rewrite(rx, &mut upstream, "real.example.com", None)
            .await
            .unwrap();
        // upstream Vec<u8> holds the written bytes.
        let s = String::from_utf8(upstream).unwrap();
        // Les deux requêtes doivent être présentes avec Host réécrit.
        assert_eq!(s.matches("Host: real.example.com\r\n").count(), 2, "{s}");
        assert!(!s.contains("192.0.2.1:5001"));
        assert!(s.contains("GET /System/Info/Public HTTP/1.1\r\n"));
        assert!(s.contains("GET /Items HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn forwards_post_with_content_length() {
        let req = b"POST /x HTTP/1.1\r\n\
                    Host: a\r\nContent-Length: 4\r\n\r\nABCD";
        let (mut tx, rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(req).await.unwrap();
            drop(tx);
        });
        let mut upstream: Vec<u8> = Vec::new();
        http_pipe_with_host_rewrite(rx, &mut upstream, "b", None).await.unwrap();
        let s = String::from_utf8(upstream).unwrap();
        assert!(s.contains("Host: b\r\n"));
        assert!(s.ends_with("\r\n\r\nABCD"));
    }

    #[tokio::test]
    async fn rejects_request_without_token() {
        let req = b"GET /Items HTTP/1.1\r\nHost: 127.0.0.1:5001\r\n\r\n";
        let (mut tx, rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(req).await.unwrap();
            drop(tx);
        });
        let mut upstream: Vec<u8> = Vec::new();
        let err = http_pipe_with_host_rewrite(rx, &mut upstream, "b", Some("ABC123"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(upstream.is_empty(), "rien ne doit avoir été forwardé");
    }

    #[tokio::test]
    async fn strips_valid_token_from_path() {
        let req = b"GET /ABC123/Items HTTP/1.1\r\nHost: 127.0.0.1:5001\r\n\r\n";
        let (mut tx, rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(req).await.unwrap();
            drop(tx);
        });
        let mut upstream: Vec<u8> = Vec::new();
        http_pipe_with_host_rewrite(rx, &mut upstream, "real", Some("ABC123"))
            .await
            .unwrap();
        let s = String::from_utf8(upstream).unwrap();
        assert!(s.starts_with("GET /Items HTTP/1.1\r\n"), "got: {s}");
        assert!(s.contains("Host: real\r\n"));
    }

    #[test]
    fn strip_root_handles_no_trailing_slash() {
        assert_eq!(strip_path_token("/TOK/foo", "TOK"), Some("/foo".into()));
        assert_eq!(strip_path_token("/TOK/", "TOK"), Some("/".into()));
        assert_eq!(strip_path_token("/TOK", "TOK"), Some("/".into()));
        assert_eq!(strip_path_token("/wrong/x", "TOK"), None);
        assert_eq!(strip_path_token("/", "TOK"), None);
    }

    // Un test du `find_headers_end` direct, sans pipe.
    #[test]
    fn finds_headers_end_boundary() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        // \r\n\r\n termine à l'octet 27, body commence à 27.
        assert_eq!(find_headers_end(buf), Some(27));
        assert_eq!(&buf[27..], b"body");
    }

    // unused-but-handy import warning silencer
    #[allow(dead_code)]
    fn _read_at_least<R: AsyncReadExt>(_r: R) {}

    fn rw() -> ResponseRewrite {
        ResponseRewrite {
            from_urls: vec!["https://media.example.com".to_string()],
            to_url: "http://127.0.0.1:13873".to_string(),
        }
    }

    /// Cas typique Nextcloud Login v2 : réponse JSON avec Content-Length, deux
    /// URLs absolues à réécrire vers la base loopback.
    #[tokio::test]
    async fn rewrites_json_body_with_content_length() {
        let body = br#"{"poll":{"endpoint":"https://media.example.com/index.php/login/v2/poll","token":"x"},"login":"https://media.example.com/index.php/login/v2/flow/y"}"#;
        let header = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let (mut tx, rx) = tokio::io::duplex(8192);
        let h = header.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(h.as_bytes()).await.unwrap();
            tx.write_all(body).await.unwrap();
            drop(tx);
        });
        let mut downstream: Vec<u8> = Vec::new();
        http_response_pipe_with_rewrite(rx, &mut downstream, &rw())
            .await
            .unwrap();
        let s = String::from_utf8(downstream).unwrap();
        assert!(s.contains("http://127.0.0.1:13873/index.php/login/v2/poll"), "got: {s}");
        assert!(s.contains("http://127.0.0.1:13873/index.php/login/v2/flow/y"));
        assert!(!s.contains("https://media.example.com"));
        // Content-Length doit être recalculé (corps plus court car http vs https).
        let new_body = s.split("\r\n\r\n").nth(1).unwrap();
        let cl_line = s
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .unwrap();
        let cl: usize = cl_line.split(':').nth(1).unwrap().trim().parse().unwrap();
        assert_eq!(cl, new_body.len());
    }

    /// Cas OAuth Authentik : Location header avec `redirect_uri=` encodé.
    /// Vérifie qu'on rewrite à la fois la forme nue ET la forme percent-encoded.
    #[tokio::test]
    async fn rewrites_location_header_with_percent_encoded_url() {
        let resp = b"HTTP/1.1 302 Found\r\n\
                     Location: https://auth.example.com/application/o/authorize/?response_type=code&redirect_uri=https%3A%2F%2Fmedia.example.com%2Fcallback&state=abc\r\n\
                     Content-Length: 0\r\n\r\n";
        let (mut tx, rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(resp).await.unwrap();
            drop(tx);
        });
        let mut downstream: Vec<u8> = Vec::new();
        http_response_pipe_with_rewrite(rx, &mut downstream, &rw())
            .await
            .unwrap();
        let s = String::from_utf8(downstream).unwrap();
        // Le host Authentik n'est PAS touché (autre domaine).
        assert!(s.contains("https://auth.example.com/application/"), "got: {s}");
        // Le redirect_uri imbriqué (percent-encoded) doit être réécrit.
        assert!(s.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A13873%2Fcallback"), "got: {s}");
        assert!(!s.contains("media.example.com"));
    }

    /// Body chunked Caddy/Nginx : on accumule, rewrite, re-émet en Content-Length.
    #[tokio::test]
    async fn rewrites_chunked_html_body() {
        // On découpe le body en 2 chunks pour valider la concatenation correcte.
        let chunk1 = b"<a href=\"https://media.example";
        let chunk2 = b".com/foo\">click</a>";
        let mut response: Vec<u8> = Vec::new();
        response.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        );
        response.extend_from_slice(format!("{:x}\r\n", chunk1.len()).as_bytes());
        response.extend_from_slice(chunk1);
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(format!("{:x}\r\n", chunk2.len()).as_bytes());
        response.extend_from_slice(chunk2);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (mut tx, rx) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(&response).await.unwrap();
            drop(tx);
        });
        let mut downstream: Vec<u8> = Vec::new();
        http_response_pipe_with_rewrite(rx, &mut downstream, &rw())
            .await
            .unwrap();
        let s = String::from_utf8(downstream).unwrap();
        assert!(s.contains("http://127.0.0.1:13873/foo"), "got: {s}");
        assert!(!s.contains("media.example.com"));
        // Plus de Transfer-Encoding chunked en sortie.
        assert!(!s.to_lowercase().contains("transfer-encoding"), "got: {s}");
        assert!(s.contains("Content-Length:"));
    }

    /// Content-type binaire : on passe tel quel, aucune réécriture.
    #[tokio::test]
    async fn passthrough_binary_body() {
        let body: Vec<u8> = (0u8..255).collect();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let (mut tx, rx) = tokio::io::duplex(8192);
        let h = header.clone();
        let b = body.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(h.as_bytes()).await.unwrap();
            tx.write_all(&b).await.unwrap();
            drop(tx);
        });
        let mut downstream: Vec<u8> = Vec::new();
        http_response_pipe_with_rewrite(rx, &mut downstream, &rw())
            .await
            .unwrap();
        // On retrouve le body binaire intact à la fin.
        let split_pos = downstream.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert_eq!(&downstream[split_pos + 4..split_pos + 4 + body.len()], body.as_slice());
    }

    /// Force Accept-Encoding: identity côté requête pour ne pas avoir à
    /// décompresser les réponses qu'on veut rewrite.
    #[tokio::test]
    async fn forces_accept_encoding_identity_on_request() {
        let req = b"GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip, br\r\n\r\n";
        let (mut tx, rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(req).await.unwrap();
            drop(tx);
        });
        let mut upstream: Vec<u8> = Vec::new();
        http_pipe_with_host_rewrite(rx, &mut upstream, "b", None).await.unwrap();
        let s = String::from_utf8(upstream).unwrap();
        assert!(s.contains("Accept-Encoding: identity\r\n"), "got: {s}");
        assert!(!s.contains("gzip"));
        assert!(!s.contains("br\r\n"));
    }

    #[test]
    fn rewrite_url_variants_handles_lower_and_upper_pct() {
        let out = rewrite_url_variants(
            "x=https%3A%2F%2Fmedia.example.com&y=https%3a%2f%2fmedia.example.com&z=https://media.example.com",
            "https://media.example.com",
            "http://127.0.0.1:13873",
        );
        assert_eq!(
            out,
            "x=http%3A%2F%2F127.0.0.1%3A13873&y=http%3a%2f%2f127.0.0.1%3a13873&z=http://127.0.0.1:13873"
        );
    }

    /// Cas réel observé sur Nextcloud `/index.php/login/v2` : PHP `json_encode`
    /// escape les slashes par défaut → `https:\/\/host\/path` au lieu de
    /// `https://host/path`.
    #[test]
    fn rewrite_url_variants_handles_json_escaped_slashes() {
        let input = r#"{"endpoint":"https:\/\/intra.m.example.com\/login\/v2\/poll"}"#;
        let out = rewrite_url_variants(input, "https://intra.m.example.com", "http://127.0.0.1:28021");
        assert_eq!(
            out,
            r#"{"endpoint":"http:\/\/127.0.0.1:28021\/login\/v2\/poll"}"#
        );
    }

    /// Pompe la pipe de réponse sur `input` avec un timeout : une boucle
    /// infinie (réponse ré-émise sans fin) fait échouer le test au lieu de
    /// le bloquer.
    async fn run_response_pipe(input: Vec<u8>) -> String {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(&input).await.unwrap();
            drop(tx);
        });
        let mut downstream: Vec<u8> = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            http_response_pipe_with_rewrite(rx, &mut downstream, &rw()),
        )
        .await
        .expect("la pipe de réponse doit se terminer (pas de boucle infinie)")
        .unwrap();
        String::from_utf8(downstream).unwrap()
    }

    /// Régression Jellyfin : `POST /Sessions/Playing/Progress` répond 204
    /// sans body. La 204 doit être émise une seule fois et la réponse
    /// suivante sur la même connexion keepalive doit passer.
    #[tokio::test]
    async fn no_body_response_emitted_once_then_next_response_flows() {
        let mut input = Vec::new();
        input.extend_from_slice(b"HTTP/1.1 204 No Content\r\nServer: Kestrel\r\n\r\n");
        input.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        );
        let s = run_response_pipe(input).await;
        assert_eq!(s.matches("204 No Content").count(), 1, "got: {s}");
        assert_eq!(s.matches("200 OK").count(), 1, "got: {s}");
        assert!(s.ends_with("\r\n\r\n{}"), "got: {s}");
        // Pas de Content-Length injecté sur la 204 (interdit par la RFC).
        let head_204 = s.split("HTTP/1.1 200").next().unwrap();
        assert!(!head_204.to_ascii_lowercase().contains("content-length"), "got: {s}");
    }

    /// Même cas avec un content-type réécrivable sur la 204.
    #[tokio::test]
    async fn rewritable_no_body_response_emitted_once() {
        let mut input = Vec::new();
        input.extend_from_slice(
            b"HTTP/1.1 204 No Content\r\nContent-Type: application/json\r\n\r\n",
        );
        input.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let s = run_response_pipe(input).await;
        assert_eq!(s.matches("204 No Content").count(), 1, "got: {s}");
        assert!(s.ends_with("\r\n\r\nok"), "got: {s}");
    }

    /// 100 Continue intermédiaire puis réponse finale.
    #[tokio::test]
    async fn interim_100_continue_then_final_response() {
        let mut input = Vec::new();
        input.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        input.extend_from_slice(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
        let s = run_response_pipe(input).await;
        assert_eq!(s.matches("100 Continue").count(), 1, "got: {s}");
        assert_eq!(s.matches("201 Created").count(), 1, "got: {s}");
    }

    /// 101 Switching Protocols (WebSocket Jellyfin `/socket`) : la suite est
    /// transmise telle quelle, même sans `\r\n\r\n`.
    #[tokio::test]
    async fn switching_protocols_switches_to_raw_passthrough() {
        let frames: &[u8] = &[0x81, 0x05, b'h', b'e', b'l', b'l', b'o', 0x89, 0x00];
        let mut input = Vec::new();
        input.extend_from_slice(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        );
        input.extend_from_slice(frames);
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(&input).await.unwrap();
            drop(tx);
        });
        let mut downstream: Vec<u8> = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            http_response_pipe_with_rewrite(rx, &mut downstream, &rw()),
        )
        .await
        .unwrap()
        .unwrap();
        let head_end = downstream.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&downstream[..head_end]);
        assert_eq!(head.matches("101 Switching Protocols").count(), 1, "got: {head}");
        assert_eq!(&downstream[head_end..], frames);
    }

    /// Requête WebSocket : après le handshake, les trames client sont
    /// forwardées immédiatement (pas bufferisées en attente de `\r\n\r\n`).
    #[tokio::test]
    async fn upgrade_request_switches_to_raw_copy() {
        let frames: &[u8] = &[0x81, 0x85, 1, 2, 3, 4, 0x69, 0x67, 0x6f, 0x68, 0x6e];
        let mut input = Vec::new();
        input.extend_from_slice(
            b"GET /TOK/socket?api_key=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\
              Connection: Upgrade\r\nUpgrade: websocket\r\n\
              Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        );
        input.extend_from_slice(frames);
        let (mut tx, rx) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(&input).await.unwrap();
            drop(tx);
        });
        let mut upstream: Vec<u8> = Vec::new();
        http_pipe_with_host_rewrite(rx, &mut upstream, "real", Some("TOK"))
            .await
            .unwrap();
        let head_end = upstream.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&upstream[..head_end]);
        assert!(head.starts_with("GET /socket?api_key=x HTTP/1.1\r\n"), "got: {head}");
        assert!(head.contains("Host: real\r\n"), "got: {head}");
        assert_eq!(&upstream[head_end..], frames);
    }

    // ------------------------------------------------------------------
    // HEAD, logs, cache, framing chunked, mémoire, token, sessions.
    // ------------------------------------------------------------------

    use std::sync::Arc;
    use std::time::Duration;

    /// Pompe la pipe de requête (Host réécrit en `real`) avec un timeout.
    async fn pump_request(
        input: Vec<u8>,
        token: Option<&str>,
        meta_tx: Option<mpsc::UnboundedSender<RequestMeta>>,
    ) -> (Vec<u8>, io::Result<()>) {
        let auth = token.map(|t| PathAuth::new(t, "t").unwrap());
        pump_request_auth(input, auth.as_ref(), meta_tx).await
    }

    async fn pump_request_auth(
        input: Vec<u8>,
        auth: Option<&PathAuth>,
        meta_tx: Option<mpsc::UnboundedSender<RequestMeta>>,
    ) -> (Vec<u8>, io::Result<()>) {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = tx.write_all(&input).await;
            drop(tx);
        });
        let mut upstream = Vec::new();
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            http_request_pipe(rx, Vec::new(), &mut upstream, "real", auth, meta_tx, true),
        )
        .await
        .expect("la pipe de requête doit se terminer");
        (upstream, res)
    }

    /// Pompe la pipe de réponse, `heads` = méthodes annoncées par le pipe
    /// de requête (true = HEAD).
    async fn pump_response(input: Vec<u8>, heads: &[bool]) -> (Vec<u8>, io::Result<()>) {
        let metas = heads
            .iter()
            .map(|&is_head| RequestMeta { is_head, set_cookie: None })
            .collect();
        pump_response_meta(input, metas).await
    }

    async fn pump_response_meta(input: Vec<u8>, metas: Vec<RequestMeta>) -> (Vec<u8>, io::Result<()>) {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = tx.write_all(&input).await;
            drop(tx);
        });
        let (meta_tx, meta_rx) = mpsc::unbounded_channel();
        for m in metas {
            meta_tx.send(m).unwrap();
        }
        let mut downstream = Vec::new();
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            http_response_pipe(rx, &mut downstream, &rw(), meta_rx),
        )
        .await
        .expect("la pipe de réponse doit se terminer");
        (downstream, res)
    }

    fn response_with_body(head: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("{head}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn head_of(s: &str) -> &str {
        s.split("\r\n\r\n").next().unwrap()
    }

    /// Décode un body chunked ; renvoie (payload, octets consommés).
    fn decode_chunked(mut data: &[u8]) -> (Vec<u8>, usize) {
        let total = data.len();
        let mut body = Vec::new();
        loop {
            let eol = data.windows(2).position(|w| w == b"\r\n").unwrap();
            let size = parse_chunk_size(&data[..eol]).unwrap() as usize;
            data = &data[eol + 2..];
            if size == 0 {
                loop {
                    let eol = data.windows(2).position(|w| w == b"\r\n").unwrap();
                    data = &data[eol + 2..];
                    if eol == 0 {
                        return (body, total - data.len());
                    }
                }
            }
            body.extend_from_slice(&data[..size]);
            assert_eq!(&data[size..size + 2], b"\r\n");
            data = &data[size + 2..];
        }
    }

    fn dummy_cfg(host: &str, port: u16, token: Option<&str>) -> crate::config::ProxyConfig {
        use crate::config::{ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust};
        ProxyConfig {
            id: "t".into(),
            upstream_host: host.into(),
            upstream_port: port,
            sni: None,
            identity: ClientIdentity {
                cert_chain_pem: Arc::new(Vec::new()),
                key: PrivateKeyMaterial::InMemoryPem(Arc::new(Vec::new())),
            },
            server_trust: ServerTrust::Pinned(Arc::new(Vec::new())),
            path_token: token.map(str::to_string),
            extra_canonical_hosts: Vec::new(),
        }
    }

    // ----- 1. HEAD ------------------------------------------------------

    /// Une réponse à HEAD annonce un Content-Length sans body : la réponse
    /// suivante de la connexion keepalive ne doit pas être avalée comme body.
    #[tokio::test]
    async fn head_response_content_length_announces_no_body() {
        let mut input = Vec::new();
        input.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1234\r\n\r\n",
        );
        input.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        );
        let (out, res) = pump_response(input, &[true, false]).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.matches("200 OK").count(), 2, "got: {s}");
        assert!(s.contains("Content-Length: 1234\r\n"), "CL de HEAD transmis tel quel: {s}");
        assert!(s.ends_with("\r\n\r\n{}"), "got: {s}");
    }

    #[tokio::test]
    async fn request_pipe_reports_head_requests_in_order() {
        let input = b"HEAD /a HTTP/1.1\r\nHost: x\r\n\r\n\
                      GET /b HTTP/1.1\r\nHost: x\r\n\r\n\
                      POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
            .to_vec();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (_, res) = pump_request(input, None, Some(tx)).await;
        res.unwrap();
        let mut heads = Vec::new();
        while let Ok(m) = rx.try_recv() {
            heads.push(m.is_head);
        }
        assert_eq!(heads, [true, false, false]);
    }

    /// Câblage complet : HEAD puis GET sur la même connexion via la session.
    #[tokio::test]
    async fn session_handles_head_then_get_on_same_connection() {
        let (mut client, client_side) = tokio::io::duplex(64 * 1024);
        let (upstream_side, mut server) = tokio::io::duplex(64 * 1024);
        let session = tokio::spawn(async move {
            let rw = rw();
            crate::proxy::run_http_session(
                client_side,
                Vec::new(),
                upstream_side,
                "real",
                None,
                Some(&rw),
                Duration::from_secs(300),
                "t",
            )
            .await;
        });
        client
            .write_all(b"HEAD /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // Le faux upstream ne répond qu'une fois les deux requêtes reçues.
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        while seen.windows(4).filter(|w| *w == b"\r\n\r\n").count() < 2 {
            let n = server.read(&mut buf).await.unwrap();
            assert!(n > 0);
            seen.extend_from_slice(&buf[..n]);
        }
        server
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1234\r\n\r\n\
                  HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .await
            .unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !got.ends_with(b"{}") {
                let n = client.read(&mut buf).await.unwrap();
                assert!(n > 0, "EOF prématuré");
                got.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("la réponse au GET doit arriver");
        let s = String::from_utf8(got).unwrap();
        assert_eq!(s.matches("200 OK").count(), 2, "got: {s}");
        session.abort();
    }

    // ----- 2. Logs --------------------------------------------------------

    /// Logger de test : chaque thread capture ses propres lignes (les tests
    /// `#[tokio::test]` tournent sur un runtime current_thread).
    mod log_capture {
        use std::cell::RefCell;
        use std::sync::Once;

        thread_local! {
            static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        }

        struct Capture;

        impl log::Log for Capture {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &log::Record<'_>) {
                LINES.with(|l| l.borrow_mut().push(record.args().to_string()));
            }
            fn flush(&self) {}
        }

        static CAPTURE: Capture = Capture;

        pub(super) fn install() {
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                if log::set_logger(&CAPTURE).is_ok() {
                    log::set_max_level(log::LevelFilter::Trace);
                }
            });
        }

        pub(super) fn take() -> Vec<String> {
            LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
        }
    }

    #[tokio::test]
    async fn logs_never_contain_secrets() {
        log_capture::install();
        let _ = log_capture::take();

        let req = b"GET /SECRET-TOKEN/Items?api_key=SECRET-KEY HTTP/1.1\r\nHost: x\r\n\
                    Cookie: nhx_sess=SECRET-COOKIE\r\n\r\n\
                    GET /SECRET-BAD HTTP/1.1\r\nHost: x\r\n\r\n"
            .to_vec();
        let (_, res) = pump_request(req, Some("SECRET-TOKEN"), None).await;
        assert!(res.is_err(), "2e requête sans token refusée");

        let body = b"<a href=\"https://media.example.com/SECRET-BODY\">auth.example.com</a>";
        let resp = response_with_body(
            "HTTP/1.1 302 Found\r\nLocation: https://media.example.com/SECRET-LOCATION\r\n\
             Set-Cookie: __Host-sess=SECRET-SETCOOKIE; Secure\r\nContent-Type: text/html\r\n",
            body,
        );
        let (_, res) = pump_response(resp, &[false]).await;
        res.unwrap();

        for line in log_capture::take() {
            for secret in ["SECRET", "api_key", "auth.example", "media.example"] {
                assert!(!line.contains(secret), "log qui fuit `{secret}` : {line}");
            }
        }
    }

    // ----- 3. Cache -------------------------------------------------------

    #[tokio::test]
    async fn unmodified_body_keeps_cache_headers() {
        let input = response_with_body(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"v1\"\r\n\
             Cache-Control: max-age=60\r\n",
            br#"{"a":1}"#,
        );
        let (out, res) = pump_response(input, &[]).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        let head = head_of(&s);
        assert!(head.contains("ETag: \"v1\""), "got: {s}");
        assert!(head.contains("Cache-Control: max-age=60"), "got: {s}");
        assert!(!head.contains("no-store"), "got: {s}");
        assert!(s.ends_with(r#"{"a":1}"#), "got: {s}");
    }

    #[tokio::test]
    async fn rewritten_body_drops_cache_headers_and_adds_no_store() {
        let input = response_with_body(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"v1\"\r\n\
             Cache-Control: max-age=60\r\nLast-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
             Expires: Sun, 02 Jan 2000 00:00:00 GMT\r\nPragma: cache\r\n",
            br#"{"u":"https://media.example.com/x"}"#,
        );
        let (out, res) = pump_response(input, &[]).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        let head = head_of(&s);
        for gone in ["ETag", "max-age", "Last-Modified", "Expires", "Pragma"] {
            assert!(!head.contains(gone), "{gone} doit disparaître: {s}");
        }
        assert_eq!(head.matches("Cache-Control").count(), 1, "got: {s}");
        assert!(head.contains("Cache-Control: no-store"), "got: {s}");
        assert!(s.contains("http://127.0.0.1:13873/x"), "got: {s}");
    }

    #[tokio::test]
    async fn passthrough_body_keeps_cache_headers() {
        let input = response_with_body(
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nETag: \"img\"\r\n\
             Cache-Control: max-age=3600\r\n",
            b"\x89PNG",
        );
        let (out, res) = pump_response(input.clone(), &[]).await;
        res.unwrap();
        assert!(out == input, "réponse non réécrite transmise telle quelle");
    }

    #[tokio::test]
    async fn conditional_headers_only_stripped_on_get_and_head() {
        let input = b"GET /a HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"v1\"\r\n\
                      If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT\r\n\r\n\
                      HEAD /b HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"v2\"\r\n\r\n\
                      PUT /c HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nContent-Length: 2\r\n\r\nhi\
                      PUT /d HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"v3\"\r\n\
                      If-Modified-Since: Sun, 02 Jan 2000 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n\
                      GET /e HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n"
            .to_vec();
        let (out, res) = pump_request(input, None, None).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        let req = |path: &str| -> String {
            let after = s.split(&format!(" {path} HTTP/1.1\r\n")).nth(1).unwrap();
            after.split("\r\n\r\n").next().unwrap().to_string()
        };
        assert!(!req("/a").contains("If-None-Match"), "got: {s}");
        assert!(!req("/a").contains("If-Modified-Since"), "got: {s}");
        assert!(!req("/b").contains("If-None-Match"), "got: {s}");
        // WebDAV Nextcloud : `If-None-Match: *` protège contre l'écrasement.
        assert!(req("/c").contains("If-None-Match: *"), "got: {s}");
        assert!(req("/d").contains("If-None-Match: \"v3\""), "got: {s}");
        assert!(req("/d").contains("If-Modified-Since: Sun"), "got: {s}");
        assert!(req("/e").contains("If-None-Match: *"), "got: {s}");
    }

    // ----- 4. Framing chunked ----------------------------------------------

    /// Une réponse chunked non réécrivable est transmise octet pour octet
    /// (trailers compris) et la boucle reprend : la réponse suivante est
    /// encore réécrite.
    #[tokio::test]
    async fn chunked_passthrough_response_keeps_the_response_loop() {
        let first: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\n\r\n\
                             3\r\n\x89PN\r\n2;ext=1\r\nG\n\r\n0\r\nX-Trailer: t\r\n\r\n";
        let mut input = first.to_vec();
        input.extend_from_slice(&response_with_body(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
            br#"{"u":"https://media.example.com/a"}"#,
        ));
        let (out, res) = pump_response(input, &[]).await;
        res.unwrap();
        assert!(out.starts_with(first), "got: {:?}", String::from_utf8_lossy(&out));
        let rest = String::from_utf8(out[first.len()..].to_vec()).unwrap();
        assert!(rest.contains("http://127.0.0.1:13873/a"), "got: {rest}");
        assert!(!rest.contains("media.example.com"), "got: {rest}");
    }

    /// Après un body de requête chunked, les requêtes suivantes sont toujours
    /// réécrites et le token toujours exigé.
    #[tokio::test]
    async fn chunked_request_body_keeps_following_requests_rewritten() {
        let body: &[u8] = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: t\r\n\r\n";
        let mut input =
            b"POST /TOK/upload HTTP/1.1\r\nHost: 127.0.0.1:1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        input.extend_from_slice(body);
        input.extend_from_slice(b"GET /TOK/next HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n");
        input.extend_from_slice(b"GET /no-token HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n");
        let (out, res) = pump_request(input, Some("TOK"), None).await;
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("POST /upload HTTP/1.1\r\n"), "got: {s}");
        assert!(s.contains(std::str::from_utf8(body).unwrap()), "framing transmis tel quel: {s}");
        assert!(s.contains("GET /next HTTP/1.1\r\n"), "got: {s}");
        assert_eq!(s.matches("Host: real\r\n").count(), 2, "got: {s}");
        assert!(!s.contains("TOK") && !s.contains("no-token") && !s.contains("127.0.0.1:1"), "got: {s}");
    }

    #[tokio::test]
    async fn malformed_chunk_size_is_rejected() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\n\r\n\
                      zz\r\nxx\r\n0\r\n\r\n"
            .to_vec();
        let (_, res) = pump_response(input, &[]).await;
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    // ----- 5. Mémoire -------------------------------------------------------

    #[tokio::test]
    async fn oversized_rewritable_body_is_streamed_unmodified() {
        let mut body = b"https://media.example.com/x ".to_vec();
        body.resize(MAX_REWRITE_BODY + 1, b'a');
        let input = response_with_body("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n", &body);
        let (out, res) = pump_response(input.clone(), &[]).await;
        res.unwrap();
        assert!(out == input, "au-delà du plafond : transmis tel quel");
    }

    #[tokio::test]
    async fn oversized_chunked_rewritable_body_falls_back_to_streaming() {
        let small = b"<a href=\"https://media.example.com/x\">".to_vec();
        let big = vec![b'b'; MAX_REWRITE_BODY];
        let mut input =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for c in [&small, &big] {
            input.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
            input.extend_from_slice(c);
            input.extend_from_slice(b"\r\n");
        }
        input.extend_from_slice(b"0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n");
        let (out, res) = pump_response(input, &[]).await;
        res.unwrap();
        let head_end = find_headers_end(&out).unwrap();
        let head = String::from_utf8_lossy(&out[..head_end]);
        assert!(head.contains("Transfer-Encoding: chunked"), "got: {head}");
        let (decoded, used) = decode_chunked(&out[head_end..]);
        let mut expected = small.clone();
        expected.extend_from_slice(&big);
        assert!(decoded == expected, "body transmis sans réécriture");
        assert_eq!(&out[head_end + used..], b"HTTP/1.1 204 No Content\r\n\r\n");
    }

    #[tokio::test]
    async fn oversized_until_eof_rewritable_body_is_streamed_unmodified() {
        let mut input = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhttps://media.example.com/x ".to_vec();
        input.resize(input.len() + MAX_REWRITE_BODY, b'c');
        let (out, res) = pump_response(input.clone(), &[]).await;
        res.unwrap();
        assert!(out == input, "au-delà du plafond : transmis tel quel");
    }

    /// Content-Length géant venu du serveur : pas de pré-allocation (qui
    /// aborterait le process), streaming jusqu'à l'EOF prématuré.
    #[tokio::test]
    async fn huge_content_length_is_not_preallocated() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 18446744073709551615\r\n\r\n{}"
            .to_vec();
        let (out, res) = pump_response(input, &[]).await;
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Content-Length: 18446744073709551615\r\n"), "got: {s}");
        assert!(s.ends_with("\r\n\r\n{}"), "got: {s}");
    }

    #[tokio::test]
    async fn non_utf8_body_is_rewritten_bytewise() {
        let input = response_with_body(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
            b"\xff\xfe https://media.example.com/x \x80",
        );
        let (out, res) = pump_response(input, &[]).await;
        res.unwrap();
        let head_end = find_headers_end(&out).unwrap();
        assert_eq!(&out[head_end..], b"\xff\xfe http://127.0.0.1:13873/x \x80");
    }

    // ----- 6. Token dans la base réécrite -----------------------------------

    #[test]
    fn strip_accepts_query_right_after_token() {
        assert_eq!(strip_path_token("/TOK?x=1", "TOK"), Some("/?x=1".into()));
        assert_eq!(strip_path_token("/TOK/?x=1", "TOK"), Some("/?x=1".into()));
        assert_eq!(strip_path_token("/TOKEN", "TOK"), None);
        assert_eq!(strip_path_token("/TOKx?y", "TOK"), None);
    }

    #[test]
    fn loopback_rewrite_base_carries_path_token() {
        let cfg = dummy_cfg("media.example.com", 443, Some("TOK"));
        let rw = crate::loopback::loopback_response_rewrite(&cfg, 4242);
        assert_eq!(rw.to_url, "http://127.0.0.1:4242/TOK");
        // Chaque URL réécrite repasse le contrôle du token.
        for url in [
            "https://media.example.com/index.php/login?x=1",
            "https://media.example.com",
            "https://media.example.com?x=1",
        ] {
            let out = rewrite_url_variants_bytes(url.as_bytes(), &rw.from_urls, &rw.to_url).unwrap();
            let out = String::from_utf8(out).unwrap();
            let path = out.strip_prefix("http://127.0.0.1:4242").unwrap();
            assert!(strip_path_token(path, "TOK").is_some(), "{url} → {out}");
        }
        let rw = crate::loopback::loopback_response_rewrite(&dummy_cfg("h", 443, None), 4242);
        assert_eq!(rw.to_url, "http://127.0.0.1:4242");
    }

    // ----- 7. Sessions : idle timeout, fermeture ----------------------------

    #[tokio::test(start_paused = true)]
    async fn idle_session_is_closed_after_timeout() {
        let (mut client, client_side) = tokio::io::duplex(4096);
        let (upstream_side, mut server) = tokio::io::duplex(4096);
        let session = tokio::spawn(crate::proxy::run_http_session(
            client_side,
            Vec::new(),
            upstream_side,
            "real",
            None,
            None,
            Duration::from_secs(300),
            "t",
        ));
        let mut buf = [0u8; 1024];
        // Trafic toutes les 2 min : la session survit au-delà de 5 min cumulées.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(120)).await;
            client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
            assert!(server.read(&mut buf).await.unwrap() > 0);
        }
        assert!(!session.is_finished(), "session active fermée à tort");
        // Puis plus rien : fermeture après 5 min.
        tokio::time::sleep(Duration::from_secs(301)).await;
        tokio::time::timeout(Duration::from_secs(1), session)
            .await
            .expect("session inactive non fermée")
            .unwrap();
        assert_eq!(client.read(&mut buf).await.unwrap(), 0, "le client voit la fermeture");
    }

    /// Token refusé : la connexion client est fermée tout de suite, sans
    /// attendre que l'upstream (qui n'a rien reçu) ferme de son côté.
    #[tokio::test]
    async fn bad_token_closes_session_without_waiting_for_upstream() {
        let (mut client, client_side) = tokio::io::duplex(4096);
        let (upstream_side, _server) = tokio::io::duplex(4096);
        let session = tokio::spawn(async move {
            let rw = rw();
            let auth = PathAuth::new("TOK", "t").unwrap();
            crate::proxy::run_http_session(
                client_side,
                Vec::new(),
                upstream_side,
                "real",
                Some(&auth),
                Some(&rw),
                Duration::from_secs(300),
                "t",
            )
            .await
        });
        client.write_all(b"GET /wrong HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let rejected = tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("session non fermée sur token invalide")
            .unwrap();
        assert_eq!(rejected, Some(TokenRejection::InvalidToken), "refus remonté pour l'audit");
        let mut buf = [0u8; 16];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
    }

    // ----- 9. Cookie de session du token -------------------------------------

    fn cookie_of(auth: &PathAuth) -> String {
        format!("{}={}", auth.cookie_name, auth.cookie_secret)
    }

    fn drain_metas(rx: &mut mpsc::UnboundedReceiver<RequestMeta>) -> Vec<RequestMeta> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    #[test]
    fn path_auth_cookie_is_named_per_config_and_random() {
        let a = PathAuth::new("TOK", "3f2a9c1d-77e4-4b1a-9c3e-2d1f0a6b8e55").unwrap();
        let b = PathAuth::new("TOK", "3f2a9c1d-77e4-4b1a-9c3e-2d1f0a6b8e55").unwrap();
        assert_eq!(a.cookie_name, "mtlsb_3f2a9c1d");
        assert_eq!(a.cookie_secret.len(), 2 * AUTH_COOKIE_SECRET_LEN);
        assert!(a.cookie_secret.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.cookie_secret, b.cookie_secret, "secret tiré à chaque démarrage");
        assert_eq!(
            &*a.set_cookie,
            format!("{}; HttpOnly; SameSite=Strict; Path=/", cookie_of(&a)),
        );
    }

    /// Webview : première page avec token → cookie posé ; ses chemins
    /// absolus sans token passent grâce au cookie, qui n'atteint jamais
    /// l'upstream.
    #[tokio::test]
    async fn token_request_sets_cookie_then_cookie_alone_is_accepted() {
        let auth = PathAuth::new("TOK", "cfg1").unwrap();
        let cookie = cookie_of(&auth);
        let input = format!(
            "GET /TOK/web/index.html HTTP/1.1\r\nHost: x\r\n\r\n\
             GET /web/main.js HTTP/1.1\r\nHost: x\r\nCookie: nhx_sess=1; {cookie}; lang=fr\r\n\r\n\
             GET /TOK/api HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\n\r\n"
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (out, res) = pump_request_auth(input.into_bytes(), Some(&auth), Some(tx)).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("GET /web/index.html HTTP/1.1\r\n"), "got: {s}");
        assert!(s.contains("GET /web/main.js HTTP/1.1\r\n"), "got: {s}");
        assert!(s.contains("GET /api HTTP/1.1\r\n"), "got: {s}");
        // Cookie retiré, les autres transmis (préfixe __Host- restauré) ;
        // header supprimé quand il ne reste rien.
        assert!(s.contains("Cookie: __Host-sess=1; lang=fr\r\n"), "got: {s}");
        assert_eq!(s.matches("Cookie:").count(), 1, "got: {s}");
        assert!(!s.contains(&auth.cookie_secret) && !s.contains("mtlsb_"), "got: {s}");

        let metas = drain_metas(&mut rx);
        assert_eq!(metas.len(), 3);
        assert_eq!(metas[0].set_cookie.as_deref(), Some(&*auth.set_cookie));
        assert!(metas[1].set_cookie.is_none(), "cookie déjà valide");
        assert!(metas[2].set_cookie.is_none(), "token + cookie valide : rien à reposer");
    }

    #[tokio::test]
    async fn missing_wrong_or_foreign_cookie_is_rejected() {
        let auth = PathAuth::new("TOK", "cfg1").unwrap();
        let other = PathAuth::new("TOK", "cfg1").unwrap(); // proxy redémarré
        let other_cfg = PathAuth::new("TOK", "cfg2").unwrap();
        let cases = [
            String::new(),
            format!("Cookie: {}=\r\n", auth.cookie_name),
            format!("Cookie: {}={}x\r\n", auth.cookie_name, auth.cookie_secret),
            format!("Cookie: {}\r\n", cookie_of(&other)),
            format!("Cookie: {}={}\r\n", other_cfg.cookie_name, auth.cookie_secret),
            format!("Cookie: x{}\r\n", cookie_of(&auth)),
        ];
        for extra in cases {
            let input = format!("GET /web/main.js HTTP/1.1\r\nHost: x\r\n{extra}\r\n");
            let (out, res) = pump_request_auth(input.into_bytes(), Some(&auth), None).await;
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied, "{extra}");
            assert!(out.is_empty(), "rien ne doit partir vers l'upstream ({extra})");
        }
    }

    /// Cookie périmé (proxy redémarré) + URL avec token : accepté, et un
    /// cookie neuf est reposé.
    #[tokio::test]
    async fn stale_cookie_is_replaced_on_next_token_request() {
        let auth = PathAuth::new("TOK", "cfg1").unwrap();
        let stale = PathAuth::new("TOK", "cfg1").unwrap();
        let input = format!("GET /TOK/ HTTP/1.1\r\nHost: x\r\nCookie: {}\r\n\r\n", cookie_of(&stale));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (out, res) = pump_request_auth(input.into_bytes(), Some(&auth), Some(tx)).await;
        res.unwrap();
        assert!(String::from_utf8(out).unwrap().starts_with("GET / HTTP/1.1\r\n"));
        let metas = drain_metas(&mut rx);
        assert_eq!(metas[0].set_cookie.as_deref(), Some(&*auth.set_cookie));
    }

    /// Les cookies `mtlsb_*` (les nôtres, ou ceux d'un autre proxy loopback
    /// du même hôte 127.0.0.1) ne partent jamais vers l'upstream, même sans
    /// token configuré et même dans un header non UTF-8.
    #[test]
    fn proxy_cookies_are_stripped_from_forwarded_cookie_header() {
        assert_eq!(
            rewrite_cookie_inbound(b"mtlsb_abc=1; nhx_sess=2;a=b ; nsx_t=3"),
            b"__Host-sess=2; a=b; __Secure-t=3",
        );
        assert_eq!(rewrite_cookie_inbound(b" mtlsb_abc=1 ;mtlsb_def=2"), b"");
        assert_eq!(rewrite_cookie_inbound(b"x=\xff; mtlsb_a=s"), b"x=\xff");
    }

    #[tokio::test]
    async fn cookie_header_with_only_proxy_cookies_is_dropped() {
        let input = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: mtlsb_other=zz\r\nX-A: 1\r\n\r\n".to_vec();
        let (out, res) = pump_request(input, None, None).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("Cookie") && !s.contains("mtlsb_"), "got: {s}");
        assert!(s.contains("X-A: 1\r\n"), "got: {s}");
    }

    /// Le `Set-Cookie` de session va sur la réponse finale de la requête
    /// concernée (pas sur un 100 Continue), une seule fois, sans toucher
    /// aux cookies de l'upstream.
    #[tokio::test]
    async fn response_pipe_adds_session_cookie_to_matching_response() {
        let auth = PathAuth::new("TOK", "cfg1").unwrap();
        let mut input = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
        input.extend_from_slice(&response_with_body(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: __Host-sess=1; Secure; Path=/\r\n",
            b"<p>hi</p>",
        ));
        input.extend_from_slice(&response_with_body("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n", b"PNG"));
        let metas = vec![
            RequestMeta { is_head: false, set_cookie: Some(Arc::clone(&auth.set_cookie)) },
            RequestMeta::default(),
        ];
        let (out, res) = pump_response_meta(input, metas).await;
        res.unwrap();
        let s = String::from_utf8(out).unwrap();
        let line = format!("Set-Cookie: {}\r\n", auth.set_cookie);
        assert_eq!(s.matches(&line).count(), 1, "got: {s}");
        let (interim, rest) = s.split_once("HTTP/1.1 200").unwrap();
        assert!(!interim.contains("Set-Cookie"), "pas sur le 100 Continue: {s}");
        let (first, second) = rest.split_once("HTTP/1.1 200").unwrap();
        assert!(first.contains(&line), "got: {s}");
        assert!(first.contains("Set-Cookie: nhx_sess=1; Path=/\r\n"), "got: {s}");
        assert!(!second.contains("Set-Cookie"), "got: {s}");
    }

    // ----- 10. Première requête lue avant la connexion upstream ------------

    async fn first_request(input: &[u8], auth: Option<&PathAuth>) -> io::Result<Option<Vec<u8>>> {
        let (mut tx, mut rx) = tokio::io::duplex(64 * 1024);
        let input = input.to_vec();
        tokio::spawn(async move {
            let _ = tx.write_all(&input).await;
        });
        tokio::time::timeout(Duration::from_secs(5), read_first_request(&mut rx, auth))
            .await
            .expect("read_first_request doit se terminer")
    }

    #[tokio::test]
    async fn first_request_is_checked_before_any_upstream_traffic() {
        let auth = PathAuth::new("TOK", "cfg1").unwrap();
        let denied = |r: io::Result<Option<Vec<u8>>>, reason: TokenRejection| {
            let e = r.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(token_rejection(&e), Some(reason));
        };
        // Acceptées : les octets lus sont rendus tels quels (body compris).
        let ok = b"POST /TOK/x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(first_request(ok, Some(&auth)).await.unwrap().unwrap(), ok);
        let by_cookie = format!("GET /web HTTP/1.1\r\nCookie: {}\r\n\r\n", cookie_of(&auth));
        assert!(first_request(by_cookie.as_bytes(), Some(&auth)).await.unwrap().is_some());
        // Refusées.
        denied(
            first_request(b"GET /web HTTP/1.1\r\nHost: x\r\n\r\n", Some(&auth)).await,
            TokenRejection::InvalidToken,
        );
        denied(
            first_request(b"\x16\x03\x01garbage\r\n\r\n", Some(&auth)).await,
            TokenRejection::NotHttp,
        );
        let huge = vec![b'A'; MAX_HEADER_BUF + 10];
        denied(first_request(&huge, Some(&auth)).await, TokenRejection::HeadersTooLarge);
        // Client parti avant la fin des headers : rien.
        assert!(first_request(b"GET /TOK/x HTTP/1.1\r\nHo", Some(&auth)).await.unwrap().is_none());
        assert!(first_request(b"", None).await.unwrap().is_none());
        // Sans token, pas de contrôle : même un flux non HTTP passe.
        assert!(first_request(b"\x16\x03\x01garbage\r\n\r\n", None).await.unwrap().is_some());
    }

    /// La session rejoue la première requête déjà lue avant de lire la suite
    /// sur la socket client.
    #[tokio::test]
    async fn session_replays_pre_read_first_request() {
        let auth = PathAuth::new("TOK", "cfg1").unwrap();
        let (mut client, client_side) = tokio::io::duplex(64 * 1024);
        let (upstream_side, mut server) = tokio::io::duplex(64 * 1024);
        let prefix = b"GET /TOK/a HTTP/1.1\r\nHost: x\r\n\r\nGET /TOK/b HT".to_vec();
        let session = tokio::spawn(async move {
            let rw = rw();
            crate::proxy::run_http_session(
                client_side,
                prefix,
                upstream_side,
                "real",
                Some(&auth),
                Some(&rw),
                Duration::from_secs(300),
                "t",
            )
            .await;
        });
        client.write_all(b"TP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen.windows(4).filter(|w| *w == b"\r\n\r\n").count() < 2 {
                let n = server.read(&mut buf).await.unwrap();
                assert!(n > 0);
                seen.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("les deux requêtes doivent atteindre l'upstream");
        let s = String::from_utf8(seen).unwrap();
        assert!(s.starts_with("GET /a HTTP/1.1\r\n"), "got: {s}");
        assert!(s.contains("GET /b HTTP/1.1\r\n"), "got: {s}");
        session.abort();
    }

    // ----- 8. IPv6 ------------------------------------------------------------

    #[test]
    fn ipv6_literal_is_bracketed_in_urls() {
        assert_eq!(crate::proxy::url_host("::1"), "[::1]");
        assert_eq!(crate::proxy::url_host("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(crate::proxy::url_host("media.example.com"), "media.example.com");
        let rw = crate::loopback::loopback_response_rewrite(&dummy_cfg("::1", 8443, None), 1);
        assert_eq!(rw.from_urls[0], "https://[::1]:8443");
    }

    // ----- 11. Audit des refus de token ----------------------------------------

    /// Les refus en cours de session keepalive portent aussi leur motif, et
    /// une erreur d'E/S ordinaire n'est jamais prise pour un refus.
    #[tokio::test]
    async fn keepalive_rejection_carries_its_reason() {
        let input = b"GET /TOK/a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let (upstream, res) = pump_request(input, Some("TOK"), None).await;
        assert_eq!(token_rejection(&res.unwrap_err()), Some(TokenRejection::InvalidToken));
        let s = String::from_utf8(upstream).unwrap();
        assert!(s.starts_with("GET /a HTTP/1.1\r\n") && !s.contains("/b"), "got: {s}");

        let (_, res) = pump_request(b"\x16\x03\x01garbage\r\n\r\n".to_vec(), Some("TOK"), None).await;
        assert_eq!(token_rejection(&res.unwrap_err()), Some(TokenRejection::NotHttp));
        let other = io::Error::new(io::ErrorKind::PermissionDenied, "EACCES");
        assert_eq!(token_rejection(&other), None);
    }

    // ----- 12. Requête intacte sans réécriture de réponse (VPN) ---------------

    /// Sans réécriture de réponse (mode VPN), la compression négociée et les
    /// préconditions de cache du client partent telles quelles. Avec (mode
    /// loopback), `identity` est forcé et les préconditions des GET retirées.
    #[tokio::test]
    async fn request_encoding_untouched_when_responses_are_not_rewritten() {
        let req: &[u8] = b"GET /a HTTP/1.1\r\nHost: 192.0.2.1:5001\r\n\
                           Accept-Encoding: gzip, br\r\nIf-None-Match: \"v1\"\r\n\r\n";
        for rewrite in [false, true] {
            let (mut client, client_side) = tokio::io::duplex(64 * 1024);
            let (upstream_side, mut server) = tokio::io::duplex(64 * 1024);
            let session = tokio::spawn(async move {
                let rw = rw();
                crate::proxy::run_http_session(
                    client_side,
                    Vec::new(),
                    upstream_side,
                    "real",
                    None,
                    rewrite.then_some(&rw),
                    Duration::from_secs(300),
                    "t",
                )
                .await
            });
            client.write_all(req).await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            tokio::time::timeout(Duration::from_secs(5), async {
                while find_headers_end(&seen).is_none() {
                    let n = server.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    seen.extend_from_slice(&buf[..n]);
                }
            })
            .await
            .expect("la requête doit atteindre l'upstream");
            let s = String::from_utf8(seen).unwrap();
            assert!(s.contains("Host: real\r\n"), "got: {s}");
            if rewrite {
                assert!(s.contains("Accept-Encoding: identity\r\n"), "got: {s}");
                assert!(!s.contains("gzip") && !s.contains("If-None-Match"), "got: {s}");
            } else {
                assert!(s.contains("Accept-Encoding: gzip, br\r\n"), "got: {s}");
                assert!(s.contains("If-None-Match: \"v1\"\r\n"), "got: {s}");
                assert!(!s.contains("identity"), "got: {s}");
            }
            session.abort();
        }
    }

    // ----- 13. Frontière de l'autorité dans la réécriture d'URL ---------------

    #[test]
    fn base_url_only_matches_a_whole_authority() {
        let rewrite = |input: &str| rewrite_url_variants(input, "https://h.com", "http://L:1/T");
        // L'autorité s'arrête là : remplacé.
        for (input, expected) in [
            ("https://h.com", "http://L:1/T"),
            ("https://h.com/a", "http://L:1/T/a"),
            ("https://h.com?q=1", "http://L:1/T?q=1"),
            ("https://h.com#f", "http://L:1/T#f"),
            (r#"{"u":"https://h.com"}"#, r#"{"u":"http://L:1/T"}"#),
            ("href='https://h.com'", "href='http://L:1/T'"),
            ("voir https://h.com ici", "voir http://L:1/T ici"),
            ("a=https://h.com&b=1", "a=http://L:1/T&b=1"),
            ("<d:href>https://h.com</d:href>", "<d:href>http://L:1/T</d:href>"),
            (r#""<a href=\"https://h.com\">""#, r#""<a href=\"http://L:1/T\">""#),
            ("https://h.com%2Fa", "http://L:1/T%2Fa"),
        ] {
            assert_eq!(rewrite(input), expected, "{input}");
        }
        // Une autre autorité qui commence pareil : intact.
        for input in [
            "https://h.com.autre.com/a",
            "https://h.com:8443/a",
            "https://h.comx/a",
            "https://h.com-cdn.net/a",
            "https://h.com_x/a",
            "https://h.com@ailleurs.net/a",
            "https://h.comé.fr/a",
            "https://h.com%3A8443/a",
            "https://h.com%2eautre.com/a",
        ] {
            assert_eq!(rewrite(input), input, "{input}");
        }
    }

    #[test]
    fn base_url_boundary_applies_to_encoded_variants() {
        let rewrite = |input: &str| rewrite_url_variants(input, "https://h.com", "http://L:1/T");
        // Percent-encodé (`redirect_uri=` imbriqué), majuscules et minuscules.
        assert_eq!(rewrite("u=https%3A%2F%2Fh.com%2Fa&x"), "u=http%3A%2F%2FL%3A1%2FT%2Fa&x");
        assert_eq!(rewrite("u=https%3a%2f%2fh.com"), "u=http%3a%2f%2fL%3a1%2fT");
        assert_eq!(rewrite("u=https%3A%2F%2Fh.com%22"), "u=http%3A%2F%2FL%3A1%2FT%22");
        for input in [
            "u=https%3A%2F%2Fh.com%3A8443%2Fa",
            "u=https%3a%2f%2fh.com%3a8443",
            "u=https%3A%2F%2Fh.com.autre.com%2Fa",
        ] {
            assert_eq!(rewrite(input), input, "{input}");
        }
        // Slashes échappés JSON (PHP `json_encode`).
        assert_eq!(rewrite(r#"{"u":"https:\/\/h.com\/a"}"#), r#"{"u":"http:\/\/L:1\/T\/a"}"#);
        assert_eq!(rewrite(r#"{"u":"https:\/\/h.com"}"#), r#"{"u":"http:\/\/L:1\/T"}"#);
        for input in [r#""https:\/\/h.com:8443\/a""#, r#""https:\/\/h.com.autre.com\/a""#] {
            assert_eq!(rewrite(input), input, "{input}");
        }
    }

    /// Hosts canoniques qui se chevauchent (`https://h` de l'upstream sur 443
    /// et `https://h:8443` en host additionnel) : chaque URL n'est réécrite
    /// que par le sien, dans un ordre comme dans l'autre.
    #[test]
    fn overlapping_canonical_hosts_do_not_clobber_each_other() {
        let input = b"https://h:8443/a https://h/b https://h.autre/c";
        for from in [["https://h", "https://h:8443"], ["https://h:8443", "https://h"]] {
            let from: Vec<String> = from.iter().map(|f| f.to_string()).collect();
            let out = rewrite_url_variants_bytes(input, &from, "http://L").unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), "http://L/a http://L/b https://h.autre/c");
        }
    }
}
