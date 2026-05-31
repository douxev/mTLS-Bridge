//! Réécriture HTTP/1.1 minimaliste : on intercepte la *première* requête de
//! chaque connexion TCP cliente et on remplace son header `Host:` par le
//! hostname réel de l'upstream. Indispensable quand l'upstream est un
//! reverse-proxy (Caddy, Nginx, Traefik) qui route par Host header — sans
//! cette réécriture, le RP voit `Host: 192.0.2.X:port` et tombe sur son
//! vhost par défaut → 404.
//!
//! Limite assumée : seule la **première** requête de chaque connexion est
//! réécrite. Pour HTTP/1.1 keepalive avec plusieurs requêtes par socket,
//! les requêtes suivantes garderont leur Host d'origine. Si ça pose souci en
//! pratique (Caddy strict), on passera à un proxy HTTP per-request complet.

const MAX_HEADER_BUF: usize = 64 * 1024;

/// Cherche `\r\n\r\n` dans `haystack` et renvoie l'index juste après.
fn find_headers_end(haystack: &[u8]) -> Option<usize> {
    haystack.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Détermine la longueur du body d'une requête HTTP/1.1 à partir des headers.
enum BodyLen {
    None,
    Fixed(usize),
    Chunked,
}

fn body_length(headers: &[httparse::Header<'_>]) -> BodyLen {
    let mut chunked = false;
    let mut len: Option<usize> = None;
    for h in headers {
        if h.name.is_empty() {
            break;
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if std::str::from_utf8(h.value)
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
            {
                chunked = true;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if let Ok(s) = std::str::from_utf8(h.value) {
                if let Ok(n) = s.trim().parse::<usize>() {
                    len = Some(n);
                }
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

/// Parse les headers, renvoie (octets réécrits, longueur du body restant à
/// pomper depuis le client après l'éventuel chevauchement déjà bufferisé).
fn rewrite_and_split(
    headers_plus_maybe_body: &[u8],
    new_host: &str,
    headers_len: usize,
) -> Option<(Vec<u8>, BodyLen, usize)> {
    let headers_bytes = &headers_plus_maybe_body[..headers_len];
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hbuf);
    match req.parse(headers_bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    let method = req.method?;
    let path = req.path?;
    let version = req.version.unwrap_or(1);
    let bl = body_length(req.headers);

    let mut out = Vec::with_capacity(headers_len + 64);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.");
    out.push(if version == 0 { b'0' } else { b'1' });
    out.extend_from_slice(b"\r\n");

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
    out.extend_from_slice(b"\r\n");
    // Body bytes already in buffer (avant le prochain read)
    let buffered_body = &headers_plus_maybe_body[headers_len..];
    Some((out, bl, buffered_body.len()))
}

/// Pipe per-requête : lit inbound, réécrit le Host header de CHAQUE requête
/// HTTP/1.1 keepalive, transmet à upstream. Boucle jusqu'à EOF inbound ou
/// erreur. Pour la première requête en chunked encoding, on bascule en raw
/// copy (limitation MVP — l'usage Jellyfin/Nextcloud n'envoie pas de body
/// chunked côté requête en pratique).
pub async fn http_pipe_with_host_rewrite<R, W>(
    mut inbound: R,
    mut upstream: W,
    new_host: &str,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut leftover: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tmp = vec![0u8; 16 * 1024];

    'requests: loop {
        // 1. Accumuler jusqu'à \r\n\r\n (fin de headers).
        let headers_end = loop {
            if let Some(p) = find_headers_end(&leftover) {
                break p;
            }
            if leftover.len() >= MAX_HEADER_BUF {
                // Headers trop gros — soit pas du HTTP, soit attaque. On forward
                // brut et on quitte le mode rewrite.
                upstream.write_all(&leftover).await?;
                leftover.clear();
                return tokio::io::copy(&mut inbound, &mut upstream).await.map(|_| ());
            }
            let n = inbound.read(&mut tmp).await?;
            if n == 0 {
                // EOF avant requête complète : on flush ce qu'il reste et on sort propre.
                if !leftover.is_empty() {
                    upstream.write_all(&leftover).await?;
                }
                return Ok(());
            }
            leftover.extend_from_slice(&tmp[..n]);
        };

        // 2. Parser + réécrire les headers.
        let Some((rewritten_headers, body_len, body_in_buf)) =
            rewrite_and_split(&leftover, new_host, headers_end)
        else {
            // Pas du HTTP/1.1 parsable — on forward brut puis raw copy.
            log::warn!("http_pipe: parse headers failed, fallback raw copy");
            upstream.write_all(&leftover).await?;
            leftover.clear();
            return tokio::io::copy(&mut inbound, &mut upstream).await.map(|_| ());
        };
        upstream.write_all(&rewritten_headers).await?;

        // 3. Forward le body selon Content-Length / Transfer-Encoding.
        match body_len {
            BodyLen::None => {
                // Pas de body — les bytes après headers_end sont le début de
                // la prochaine requête.
                if body_in_buf > 0 {
                    leftover.drain(..headers_end);
                } else {
                    leftover.clear();
                }
                continue 'requests;
            }
            BodyLen::Fixed(n_total) => {
                // Forward les bytes déjà bufferisés (jusqu'à n_total).
                let already = body_in_buf.min(n_total);
                if already > 0 {
                    upstream
                        .write_all(&leftover[headers_end..headers_end + already])
                        .await?;
                }
                let leftover_extra = body_in_buf.saturating_sub(n_total);
                if leftover_extra > 0 {
                    // Le buffer contient déjà le début de la prochaine requête.
                    leftover.drain(..headers_end + n_total);
                } else {
                    leftover.clear();
                }
                let mut remaining = n_total - already;
                while remaining > 0 {
                    let chunk = tmp.len().min(remaining);
                    let r = inbound.read(&mut tmp[..chunk]).await?;
                    if r == 0 {
                        return Err(std::io::Error::other("EOF mid-body fixed"));
                    }
                    upstream.write_all(&tmp[..r]).await?;
                    remaining -= r;
                }
            }
            BodyLen::Chunked => {
                // MVP : on ne parse pas le framing chunked. On flush le body
                // déjà lu et on bascule en raw copy pour le reste de la session.
                // Conséquence : les requêtes suivantes ne sont plus réécrites.
                log::warn!(
                    "http_pipe: chunked request body — fallback raw copy pour la suite"
                );
                if body_in_buf > 0 {
                    upstream.write_all(&leftover[headers_end..]).await?;
                }
                leftover.clear();
                return tokio::io::copy(&mut inbound, &mut upstream).await.map(|_| ());
            }
        }
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
        http_pipe_with_host_rewrite(rx, &mut upstream, "real.example.com")
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
        http_pipe_with_host_rewrite(rx, &mut upstream, "b").await.unwrap();
        let s = String::from_utf8(upstream).unwrap();
        assert!(s.contains("Host: b\r\n"));
        assert!(s.ends_with("\r\n\r\nABCD"));
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
}
