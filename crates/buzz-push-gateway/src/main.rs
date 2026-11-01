use buzz_push_gateway::{
    apns::ApnsTransport,
    app_attest::AppAttestVerifier,
    authority::AuthorityStore,
    config::Config,
    grant::{GrantKey, GrantKeyring},
    postgres::PostgresAuthorityStore,
    router_with_metrics,
    token::{TokenKey, TokenKeyring},
    AppState,
};
use std::{
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tracing_subscriber::EnvFilter;

fn build_profile(
    configured: &buzz_push_gateway::config::AppProfileConfig,
    app_attest_root: &[u8],
) -> Result<buzz_push_gateway::http::ProfileRuntime, Box<dyn std::error::Error>> {
    let app_attest = AppAttestVerifier::with_environment(
        configured.app_attest_app_id.clone(),
        app_attest_root.to_vec(),
        configured.app_attest_environment,
    )?;
    let transport = Arc::new(match &configured.apns_token {
        Some(credentials) => ApnsTransport::token(
            &fs::read(&credentials.key_path)?,
            &credentials.key_id,
            &credentials.team_id,
            configured.apns_topic.clone(),
            configured.apns_environment,
        )?,
        None => ApnsTransport::certificate(
            &fs::read(&configured.apns_cert_path)?,
            configured.apns_topic.clone(),
            configured.apns_environment,
        )?,
    });
    Ok(buzz_push_gateway::http::ProfileRuntime {
        app_attest: Arc::new(app_attest),
        transport,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    if std::env::args().nth(1).as_deref() == Some("--migrate-only") {
        let database_url = std::env::var("DATABASE_URL")?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        let runtime_role = std::env::var("BUZZ_PUSH_RUNTIME_DATABASE_ROLE")?;
        PostgresAuthorityStore::apply_migrations_and_grants(&pool, &runtime_role).await?;
        return Ok(());
    }
    let c = Config::from_env()?;
    let metrics_handle = buzz_push_gateway::metrics::install()?;
    let app_attest_root = fs::read(&c.app_attest_root_cert_path)?;
    let mut production_config = c.profile.clone();
    production_config.apns_environment = buzz_push_gateway::config::ApnsEnvironment::Production;
    if let Some(credentials) = &c.production_apns_token {
        production_config.apns_token = Some(credentials.clone());
    }
    let profile = Arc::new(build_profile(&c.profile, &app_attest_root)?);
    let production_profile = Arc::new(build_profile(&production_config, &app_attest_root)?);
    tracing::info!(
        environment = ?c.profile.app_attest_environment,
        "App Attest verifier configured"
    );
    let grant_keyring = GrantKeyring::new(
        c.grant_keys
            .iter()
            .map(|key| GrantKey::new(&key.id, &key.key))
            .collect::<Result<_, _>>()?,
    )?;
    let token_keyring = TokenKeyring::new(
        c.token_keys
            .iter()
            .map(|key| TokenKey::new(&key.id, &key.key))
            .collect::<Result<_, _>>()?,
    )?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .connect(&c.database_url)
        .await?;
    let authority = Arc::new(PostgresAuthorityStore::new(pool));
    authority
        .reap_expired(chrono::Utc::now().timestamp())
        .await?;
    let reaper_authority = Arc::clone(&authority);
    let reaper = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        interval.tick().await;
        loop {
            interval.tick().await;
            if reaper_authority
                .reap_expired(chrono::Utc::now().timestamp())
                .await
                .is_err()
            {
                buzz_push_gateway::metrics::record_reaper_failure();
                tracing::warn!("push gateway retention reaper failed");
            }
        }
    });
    let accepting = Arc::new(AtomicBool::new(true));
    let (public, health) = router_with_metrics(
        AppState {
            grant_keyring: Arc::new(grant_keyring),
            authority,
            token_keyring: Arc::new(token_keyring),
            profile,
            production_profile,
            max_grant_lifetime_seconds: c.max_grant_lifetime_seconds,
            max_installation_lifetime_seconds: c.max_installation_lifetime_seconds,
            endpoint_quota_window_seconds: c.endpoint_quota_window_seconds,
            endpoint_quota_max_deliveries: c.endpoint_quota_max_deliveries,
            now: || chrono::Utc::now().timestamp(),
            accepting: accepting.clone(),
        },
        Some(metrics_handle),
    );
    let pl = tokio::net::TcpListener::bind(c.bind_addr).await?;
    let hl = tokio::net::TcpListener::bind(c.health_addr).await?;
    let (ptx, prx) = tokio::sync::watch::channel(false);
    let (htx, hrx) = tokio::sync::watch::channel(false);
    let p = tokio::spawn(async move {
        axum::serve(pl, public)
            .with_graceful_shutdown(async move {
                let mut rx = prx;
                let _ = rx.changed().await;
            })
            .await
    });
    let h = tokio::spawn(async move {
        axum::serve(hl, health)
            .with_graceful_shutdown(async move {
                let mut rx = hrx;
                let _ = rx.changed().await;
            })
            .await
    });
    shutdown_signal().await?;
    accepting.store(false, Ordering::SeqCst);
    let _ = ptx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), p).await;
    let _ = htx.send(true);
    let _ = h.await;
    reaper.abort();
    Ok(())
}
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(())}
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
