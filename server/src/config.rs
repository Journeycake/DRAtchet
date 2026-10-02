//! Server settings: `dratchet.cfg`, environment variables and command-line
//! flags, in that order of increasing precedence (`docs/adr/0001`).
//!
//! `dratchet.cfg` is TOML. Unknown keys are an error, so a mistyped
//! security setting can't be silently ignored. The mail store's key is
//! never read from it: the file only names where the key lives
//! (`mailbox_key_file`), or the key comes from `DRATCHETD_MAILBOX_KEY`, so
//! a shared or backed-up config file can't leak it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

pub const DEFAULT_CONFIG_FILE: &str = "dratchet.cfg";
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const DEFAULT_DIRECTORY_DB: &str = "dratchetd-directory.redb";
pub const DEFAULT_MAILBOX_INDEX_DB: &str = "dratchetd-mailbox-index.redb";
/// Default seconds between saves of queued mail when persistence is on.
pub const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 10;
/// Longest allowed save interval: a sender waits this long, plus its normal
/// timeout, for the single checkmark.
pub const MAX_FLUSH_INTERVAL_SECS: u64 = 15;
/// Below this much usable memory, persistence is on by default.
pub const SMALL_HOST_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Memory area used when usable memory can't be determined.
pub const FALLBACK_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;
pub const KEY_ENV: &str = "DRATCHETD_MAILBOX_KEY";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub bind: Option<String>,
    pub directory_db: Option<PathBuf>,
    pub trusted_proxies: Option<String>,
    pub persist_mailboxes: Option<bool>,
    pub fragment_dirs: Option<Vec<PathBuf>>,
    pub mailbox_index_db: Option<PathBuf>,
    pub flush_interval: Option<u64>,
    pub memory_limit: Option<u64>,
    pub mailbox_key_file: Option<PathBuf>,
}

/// Values from flags or the environment (clap merges those two); `None`
/// falls through to the file, then the default.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub bind: Option<String>,
    pub directory_db: Option<PathBuf>,
    pub trusted_proxies: Option<String>,
    pub persist_mailboxes: Option<bool>,
    pub fragment_dirs: Vec<PathBuf>,
    pub mailbox_index_db: Option<PathBuf>,
    pub flush_interval: Option<u64>,
    pub memory_limit: Option<u64>,
    pub mailbox_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct MailPersistence {
    pub fragment_dirs: Vec<PathBuf>,
    pub index_db: PathBuf,
    pub key: [u8; 32],
    pub flush_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: String,
    pub directory_db: PathBuf,
    pub trusted_proxies: String,
    pub memory_limit: u64,
    pub persistence: Option<MailPersistence>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("{0}")]
    Invalid(String),
}

/// Read `dratchet.cfg`. With `explicit` set (`--config` or
/// `DRATCHETD_CONFIG`), a missing file is an error; otherwise a missing
/// `./dratchet.cfg` just means defaults.
pub fn load_file(explicit: Option<&Path>) -> Result<FileConfig, ConfigError> {
    let path = explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE));
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if explicit.is_none() && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileConfig::default())
        }
        Err(source) => return Err(ConfigError::Read { path, source }),
    };
    parse_file(&path, &text)
}

pub fn parse_file(path: &Path, text: &str) -> Result<FileConfig, ConfigError> {
    toml::from_str(text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

/// Memory the relay can actually use: the smaller of the machine's total
/// RAM and the container's memory limit, if either can be read.
pub fn usable_memory() -> Option<u64> {
    let total = std::fs::read_to_string("/proc/meminfo").ok().and_then(|m| {
        m.lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    });
    let cgroup = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or_else(|| {
            std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                // cgroup v1 reports "unlimited" as a huge number.
                .filter(|v| *v < (1u64 << 60))
        });
    match (total, cgroup) {
        (Some(t), Some(c)) => Some(t.min(c)),
        (t, c) => t.or(c),
    }
}

fn parse_key_hex(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(key)
}

/// The mail store key: `DRATCHETD_MAILBOX_KEY` if set, else the key file.
/// A key file anyone but its owner can read is refused.
fn load_key(env_key: Option<&str>, key_file: Option<&Path>) -> Result<Option<[u8; 32]>, String> {
    if let Some(text) = env_key {
        return parse_key_hex(text)
            .map(Some)
            .ok_or_else(|| format!("{KEY_ENV} must be 64 hex characters (32 bytes)"));
    }
    let Some(path) = key_file else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot read mailbox_key_file {}: {e}", path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "mailbox_key_file {} is readable by other users; restrict it to its owner \
                 (chmod 600)",
                path.display()
            ));
        }
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read mailbox_key_file {}: {e}", path.display()))?;
    parse_key_hex(&text).map(Some).ok_or_else(|| {
        format!(
            "mailbox_key_file {} must contain 64 hex characters (32 bytes)",
            path.display()
        )
    })
}

/// Combine flags/environment, the file and the defaults, and check that
/// persistence, if on, has everything it needs. Every missing piece is
/// reported in one error.
pub fn resolve(
    overrides: Overrides,
    file: FileConfig,
    usable_memory: Option<u64>,
    env_key: Option<&str>,
) -> Result<Settings, ConfigError> {
    let bind = overrides
        .bind
        .or(file.bind)
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    let directory_db = overrides
        .directory_db
        .or(file.directory_db)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIRECTORY_DB));
    let trusted_proxies = overrides
        .trusted_proxies
        .or(file.trusted_proxies)
        .unwrap_or_default();

    let memory_limit = match overrides.memory_limit.or(file.memory_limit) {
        Some(0) => return Err(ConfigError::Invalid("memory_limit must be above 0".into())),
        Some(limit) => limit,
        None => usable_memory
            .map(|m| m / 10)
            .unwrap_or(FALLBACK_MEMORY_LIMIT),
    };

    let small_host = usable_memory.is_some_and(|m| m < SMALL_HOST_BYTES);
    let persist = overrides
        .persist_mailboxes
        .or(file.persist_mailboxes)
        .unwrap_or(small_host);

    let flush_secs = overrides
        .flush_interval
        .or(file.flush_interval)
        .unwrap_or(DEFAULT_FLUSH_INTERVAL_SECS);
    if flush_secs > MAX_FLUSH_INTERVAL_SECS {
        return Err(ConfigError::Invalid(format!(
            "flush_interval must be between 0 and {MAX_FLUSH_INTERVAL_SECS} seconds"
        )));
    }

    if !persist {
        return Ok(Settings {
            bind,
            directory_db,
            trusted_proxies,
            memory_limit,
            persistence: None,
        });
    }

    let mut missing = Vec::new();
    let key_file = overrides.mailbox_key_file.or(file.mailbox_key_file);
    let key = match load_key(env_key, key_file.as_deref()) {
        Ok(Some(key)) => Some(key),
        Ok(None) => {
            missing.push(format!(
                "a mail store key ({KEY_ENV}, or mailbox_key_file naming a file that holds 64 \
                 hex characters)"
            ));
            None
        }
        Err(e) => {
            missing.push(e);
            None
        }
    };
    let fragment_dirs = if overrides.fragment_dirs.is_empty() {
        file.fragment_dirs.unwrap_or_default()
    } else {
        overrides.fragment_dirs
    };
    let mut distinct = fragment_dirs.clone();
    distinct.sort();
    distinct.dedup();
    if distinct.len() < 2 || distinct.len() != fragment_dirs.len() {
        missing
            .push("at least two different fragment_dirs, ideally on different volumes".to_string());
    }
    if !missing.is_empty() {
        let why = if small_host {
            " (on by default because this host has under 2 GB of usable memory; set \
             persist_mailboxes = false to run without it)"
        } else {
            ""
        };
        return Err(ConfigError::Invalid(format!(
            "mailbox persistence is on{why} but needs: {}",
            missing.join("; ")
        )));
    }
    Ok(Settings {
        bind,
        directory_db,
        trusted_proxies,
        memory_limit,
        persistence: Some(MailPersistence {
            fragment_dirs,
            index_db: overrides
                .mailbox_index_db
                .or(file.mailbox_index_db)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_MAILBOX_INDEX_DB)),
            key: key.expect("checked above"),
            flush_interval: Duration::from_secs(flush_secs),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;
    const KEY_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    fn file(text: &str) -> Result<FileConfig, ConfigError> {
        parse_file(Path::new("dratchet.cfg"), text)
    }

    #[test]
    fn the_example_config_parses_with_every_key_set() {
        let uncommented: String = include_str!("../dratchet.cfg.example")
            .lines()
            .map(|l| {
                l.strip_prefix("# ")
                    .filter(|l| l.contains(" = "))
                    .unwrap_or(l)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let f = file(&uncommented).unwrap();
        assert!(f.persist_mailboxes.is_some() && f.mailbox_key_file.is_some());
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let err = file("persist_mailbox = true\n").unwrap_err().to_string();
        assert!(err.contains("persist_mailbox"), "{err}");
    }

    #[test]
    fn flags_override_the_file_and_the_file_overrides_defaults() {
        let f = file("bind = \"0.0.0.0:1\"\ndirectory_db = \"from-file.redb\"\n").unwrap();
        let s = resolve(
            Overrides {
                bind: Some("127.0.0.1:2".into()),
                ..Default::default()
            },
            f,
            Some(8 * GIB),
            None,
        )
        .unwrap();
        assert_eq!(s.bind, "127.0.0.1:2");
        assert_eq!(s.directory_db, PathBuf::from("from-file.redb"));
        assert!(s.persistence.is_none(), "off by default on a large host");
        assert_eq!(s.memory_limit, 8 * GIB / 10, "a tenth of usable memory");
    }

    #[test]
    fn a_save_interval_over_15_seconds_is_refused() {
        let f = file("flush_interval = 16\n").unwrap();
        assert!(resolve(Overrides::default(), f, Some(8 * GIB), None).is_err());
    }

    #[test]
    fn a_small_host_turns_persistence_on_and_reports_everything_missing_at_once() {
        let err = resolve(Overrides::default(), FileConfig::default(), Some(GIB), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("under 2 GB"), "{err}");
        assert!(err.contains("key"), "{err}");
        assert!(err.contains("fragment_dirs"), "{err}");
    }

    #[test]
    fn a_small_host_can_turn_persistence_off_explicitly() {
        let f = file("persist_mailboxes = false\n").unwrap();
        let s = resolve(Overrides::default(), f, Some(GIB), None).unwrap();
        assert!(s.persistence.is_none());
    }

    #[test]
    fn persistence_needs_two_different_fragment_directories() {
        let f = file("persist_mailboxes = true\nfragment_dirs = [\"a\", \"a\"]\n").unwrap();
        let err = resolve(Overrides::default(), f, Some(8 * GIB), Some(KEY_HEX))
            .unwrap_err()
            .to_string();
        assert!(err.contains("two different fragment_dirs"), "{err}");

        let f = file("persist_mailboxes = true\nfragment_dirs = [\"a\", \"b\"]\n").unwrap();
        let s = resolve(Overrides::default(), f, Some(8 * GIB), Some(KEY_HEX)).unwrap();
        let mail = s.persistence.unwrap();
        assert_eq!(mail.key, [0x42; 32]);
        assert_eq!(
            mail.flush_interval,
            Duration::from_secs(10),
            "default interval"
        );
    }

    #[test]
    fn the_key_is_never_taken_from_the_config_file() {
        let err = file(&format!("mailbox_key = \"{KEY_HEX}\"\n")).unwrap_err();
        assert!(err.to_string().contains("mailbox_key"));
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("key");
        std::fs::write(&key_file, KEY_HEX).unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let overrides = Overrides {
            persist_mailboxes: Some(true),
            fragment_dirs: vec!["a".into(), "b".into()],
            mailbox_key_file: Some(key_file.clone()),
            ..Default::default()
        };
        let err = resolve(
            overrides.clone(),
            FileConfig::default(),
            Some(8 * GIB),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("readable by other users"), "{err}");

        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let s = resolve(overrides, FileConfig::default(), Some(8 * GIB), None).unwrap();
        assert_eq!(s.persistence.unwrap().key, [0x42; 32]);
    }
}
