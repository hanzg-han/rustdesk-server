//! Relay admission control shared by hbbs and hbbr.
//!
//! hbbs issues a short-lived record for every relay request it approves
//! (`relay_uuid`), and hbbr refuses any `RequestRelay` whose uuid is not in
//! that table. The table lives in the same sqlite file hbbs already uses, so
//! no new service is needed as long as both binaries share the data volume.
//!
//! Configuration (environment variables, parsed by `common::get_arg` style):
//!   RELAY_UUID_TTL         seconds a issued uuid stays valid (default 180)
//!   RELAY_WHITELIST_MODE   off | enforce (default off)
//!   RELAY_USAGE_LOG        on | off, record per-session usage (default on)
//!
//! Whitelist entries live in `relay_whitelist`. An entry is an exact peer id,
//! a prefix ending with `*`, or `*` for everything.

use hbb_common::log;
use std::{
    net::IpAddr,
    sync::atomic::{AtomicI64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use hbb_common::tokio::sync::Mutex;

type Pool = sqlx::SqlitePool;

lazy_static::lazy_static! {
    static ref POOL: Mutex<Option<Pool>> = Mutex::new(None);
    static ref WHITELIST: Mutex<WhitelistCache> = Mutex::new(WhitelistCache::default());
}

static LAST_WARN: AtomicI64 = AtomicI64::new(0);

const WHITELIST_CACHE_SECS: u64 = 10;
const WARN_INTERVAL_SECS: i64 = 60;

#[derive(Default)]
struct WhitelistCache {
    at: Option<Instant>,
    entries: Vec<String>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn ttl() -> i64 {
    env_or("RELAY_UUID_TTL", "180").parse().unwrap_or(180).max(30)
}

fn whitelist_enforced() -> bool {
    matches!(
        env_or("RELAY_WHITELIST_MODE", "off").to_lowercase().as_str(),
        "enforce" | "on" | "1" | "true"
    )
}

fn usage_enabled() -> bool {
    !matches!(
        env_or("RELAY_USAGE_LOG", "on").to_lowercase().as_str(),
        "off" | "0" | "false"
    )
}

/// Log at most one line per minute: a hostile client can drive this path.
fn warn_throttled(msg: &str) {
    let now = now_ts();
    let last = LAST_WARN.load(Ordering::Relaxed);
    if now - last >= WARN_INTERVAL_SECS && LAST_WARN.swap(now, Ordering::Relaxed) == last {
        log::warn!("{}", msg);
    }
}

fn db_path() -> String {
    let path = env_or("DB_URL", "./db_v2.sqlite3");
    for prefix in ["sqlite://", "sqlite:"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }
    path
}

async fn pool() -> Option<Pool> {
    let mut guard = POOL.lock().await;
    if let Some(pool) = guard.as_ref() {
        return Some(pool.clone());
    }
    let path = db_path();
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(3));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .map_err(|e| log::warn!("relay gate: cannot open {}: {}", path, e))
        .ok()?;
    for sql in [
        "CREATE TABLE IF NOT EXISTS relay_uuid (
            uuid TEXT PRIMARY KEY,
            peer_id TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_relay_uuid_exp ON relay_uuid(expires_at)",
        "CREATE TABLE IF NOT EXISTS relay_whitelist (
            id TEXT PRIMARY KEY,
            note TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL DEFAULT 0
        )",
        "CREATE TABLE IF NOT EXISTS relay_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT NOT NULL DEFAULT '',
            peer_id TEXT NOT NULL DEFAULT '',
            client_ip TEXT NOT NULL DEFAULT '',
            peer_ip TEXT NOT NULL DEFAULT '',
            started_at INTEGER NOT NULL DEFAULT 0,
            ended_at INTEGER NOT NULL DEFAULT 0,
            bytes_to_peer INTEGER NOT NULL DEFAULT 0,
            bytes_to_client INTEGER NOT NULL DEFAULT 0
        )",
        "CREATE INDEX IF NOT EXISTS idx_relay_usage_started ON relay_usage(started_at)",
    ] {
        if let Err(e) = sqlx::query(sql).execute(&pool).await {
            log::warn!("relay gate: schema init failed: {}", e);
        }
    }
    *guard = Some(pool.clone());
    Some(pool)
}

async fn load_whitelist() -> Vec<String> {
    let mut cache = WHITELIST.lock().await;
    if let Some(at) = cache.at {
        if at.elapsed().as_secs() < WHITELIST_CACHE_SECS {
            return cache.entries.clone();
        }
    }
    let mut entries = Vec::new();
    if let Some(pool) = pool().await {
        match sqlx::query_as::<_, (String,)>(
            "SELECT id FROM relay_whitelist WHERE enabled = 1",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => entries = rows.into_iter().map(|r| r.0).collect(),
            Err(e) => log::warn!("relay gate: cannot read whitelist: {}", e),
        }
    }
    cache.at = Some(Instant::now());
    cache.entries = entries.clone();
    entries
}

fn matches_rule(rule: &str, peer_id: &str) -> bool {
    match rule.strip_suffix('*') {
        Some(prefix) => peer_id.starts_with(prefix),
        None => rule == peer_id,
    }
}

/// Gate a relay request received by hbbs. `Err` carries the reason shown to
/// the controller (`RelayResponse::refuse_reason`), so it must stay short.
pub async fn authorize(peer_id: &str, ip: IpAddr) -> Result<(), String> {
    if !whitelist_enforced() {
        return Ok(());
    }
    let entries = load_whitelist().await;
    if entries.iter().any(|rule| matches_rule(rule, peer_id)) {
        return Ok(());
    }
    let msg = format!(
        "relay denied: peer {peer_id} from {ip} is not in the whitelist"
    );
    warn_throttled(&msg);
    Err("relay denied: peer id not allowed by server policy".to_owned())
}

/// Record a relay uuid hbbs has just approved. hbbr accepts only these.
pub async fn record_uuid(uuid: &str, peer_id: &str, ip: IpAddr) {
    if uuid.is_empty() {
        return;
    }
    let Some(pool) = pool().await else {
        warn_throttled("relay gate: no database, issued uuid not recorded");
        return;
    };
    let now = now_ts();
    let _ = sqlx::query("DELETE FROM relay_uuid WHERE expires_at < ?1")
        .bind(now)
        .execute(&pool)
        .await;
    if let Err(e) = sqlx::query(
        "INSERT OR REPLACE INTO relay_uuid (uuid, peer_id, ip, issued_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(uuid)
    .bind(peer_id)
    .bind(ip.to_string())
    .bind(now)
    .bind(now + ttl())
    .execute(&pool)
    .await
    {
        warn_throttled(&format!("relay gate: cannot record uuid: {e}"));
    }
}

/// Called by hbbr before pairing. Fails closed.
pub async fn uuid_issued(uuid: &str, addr: SocketAddrLike) -> bool {
    if uuid.is_empty() {
        return false;
    }
    let Some(pool) = pool().await else {
        warn_throttled("relay gate: no database, rejecting relay (fail closed)");
        return false;
    };
    match sqlx::query_as::<_, (i64,)>(
        "SELECT 1 FROM relay_uuid WHERE uuid = ?1 AND expires_at >= ?2",
    )
    .bind(uuid)
    .bind(now_ts())
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(_)) => true,
        Ok(None) => {
            warn_throttled(&format!(
                "relay gate: uuid {uuid} from {addr} was not issued by hbbs"
            ));
            false
        }
        Err(e) => {
            warn_throttled(&format!("relay gate: uuid lookup failed: {e}"));
            false
        }
    }
}

/// Convenience so callers can pass `addr.ip()` without extra imports.
pub type SocketAddrLike = IpAddr;

pub struct UsageRecord<'a> {
    pub uuid: &'a str,
    pub peer_id: &'a str,
    pub client_ip: &'a str,
    pub peer_ip: &'a str,
    pub started_at: i64,
    pub bytes_to_peer: u64,
    pub bytes_to_client: u64,
}

pub async fn record_usage(rec: UsageRecord<'_>) {
    if !usage_enabled() {
        return;
    }
    let Some(pool) = pool().await else {
        return;
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO relay_usage
           (uuid, peer_id, client_ip, peer_ip, started_at, ended_at, bytes_to_peer, bytes_to_client)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(rec.uuid)
    .bind(rec.peer_id)
    .bind(rec.client_ip)
    .bind(rec.peer_ip)
    .bind(rec.started_at)
    .bind(now_ts())
    .bind(rec.bytes_to_peer as i64)
    .bind(rec.bytes_to_client as i64)
    .execute(&pool)
    .await
    {
        warn_throttled(&format!("relay gate: cannot record usage: {e}"));
    }
}
