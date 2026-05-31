use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::ProxyConfig;
use crate::error::{CoreError, Result};
use crate::http_rewrite::http_pipe_with_host_rewrite;
use crate::tls::build_client_config;

/// Durée max d'un TCP connect upstream. Sans ça, un backend injoignable
/// fait pendre la connexion ~75 s (timeout OS Linux) avant d'échouer —
/// l'app cliente abandonne avant et on n'a rien dans les logs.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Durée max d'un handshake TLS upstream. mTLS implique parfois plusieurs
/// allers-retours signés par Keystore → plus large que pour du TLS classique.
const UPSTREAM_TLS_TIMEOUT: Duration = Duration::from_secs(15);

/// Pont bidirectionnel entre une socket entrante (en clair) et un upstream mTLS.
///
/// Sémantique : on lit/écrit en streaming via [`tokio::io::copy_bidirectional`],
/// qui boucle jusqu'à FIN sur l'un des deux côtés. Pas de buffer applicatif,
/// pas d'inspection du contenu — l'app cible parle HTTP en clair côté entrée,
/// et c'est rustls qui chiffre en sortie avec le client cert.
///
/// Générique en `S` pour accepter `tokio::net::TcpStream` (mode loopback) et
/// `netstack_smoltcp::TcpStream` (mode VPN). Les deux implémentent
/// AsyncRead+AsyncWrite.
pub async fn bridge_to_mtls_upstream<S>(
    inbound: S,
    client_config: Arc<ClientConfig>,
    cfg: &ProxyConfig,
) -> Result<()>
where
    // Send + 'static : on spawn deux tâches qui possèdent chacune une moitié
    // du stream après tokio::io::split — il faut pouvoir les envoyer sur des
    // workers tokio. TcpStream et netstack_smoltcp::TcpStream satisfont déjà.
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sni = cfg.sni.clone().unwrap_or_else(|| cfg.upstream_host.clone());
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|e| CoreError::Config(format!("SNI invalide ({sni}): {e}")))?;

    let upstream_addr = format!("{}:{}", cfg.upstream_host, cfg.upstream_port);
    log::info!("bridge {}: TCP connect {}", cfg.id, upstream_addr);
    let tcp = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(&upstream_addr),
    )
    .await
    .map_err(|_| CoreError::Io(format!(
        "TCP connect timeout après {}s vers {upstream_addr}",
        UPSTREAM_CONNECT_TIMEOUT.as_secs(),
    )))??;
    // Pas de Nagle : on veut que les petits paquets HTTP partent immédiatement.
    tcp.set_nodelay(true)?;
    log::info!("bridge {}: TCP OK, TLS handshake (SNI={sni})", cfg.id);

    let connector = TlsConnector::from(client_config);
    let upstream = tokio::time::timeout(
        UPSTREAM_TLS_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| CoreError::Tls(format!(
        "TLS handshake timeout après {}s",
        UPSTREAM_TLS_TIMEOUT.as_secs(),
    )))??;
    log::info!("bridge {}: TLS OK, démarrage pipe per-request", cfg.id);

    // Split inbound/upstream pour piloter chaque sens séparément :
    // - inbound→upstream passe par http_pipe_with_host_rewrite (réécrit le
    //   Host header de CHAQUE requête HTTP/1.1 — indispensable derrière un
    //   reverse-proxy Caddy/Nginx qui route par Host, sinon les requêtes
    //   keepalive après le splash retombent en 404).
    // - upstream→inbound est un copy raw — les réponses n'ont rien à réécrire.
    let (in_rd, mut in_wr) = tokio::io::split(inbound);
    let (mut up_rd, up_wr) = tokio::io::split(upstream);

    let upstream_host = cfg.upstream_host.clone();
    let id_for_req = cfg.id.clone();
    let req_task = tokio::spawn(async move {
        if let Err(e) = http_pipe_with_host_rewrite(in_rd, up_wr, &upstream_host).await {
            if !is_benign_eof(&e) {
                log::warn!("bridge {id_for_req}: req pipe err: {e}");
            }
        }
    });
    let id_for_resp = cfg.id.clone();
    let resp_task = tokio::spawn(async move {
        match tokio::io::copy(&mut up_rd, &mut in_wr).await {
            Ok(_) => {
                let _ = in_wr.shutdown().await;
            }
            Err(e) if is_benign_eof(&e) => {}
            Err(e) => log::warn!("bridge {id_for_resp}: resp copy err: {e}"),
        }
    });
    // On attend que les deux sens s'éteignent — un EOF d'un côté ne suffit pas
    // à clore l'autre direction (cas réponse longue après FIN client).
    let _ = tokio::join!(req_task, resp_task);
    Ok(())
}

fn is_benign_eof(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
    )
}

/// Construit le `ClientConfig` rustls une fois pour toutes : le handshake TLS
/// rejouera à chaque connexion, mais la racine de confiance et la chaîne client
/// sont coûteuses à parser. L'appelant cache `Arc<ClientConfig>`.
pub fn precompile_client_config(cfg: &ProxyConfig) -> Result<Arc<ClientConfig>> {
    build_client_config(cfg)
}
