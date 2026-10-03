//! Bearer tokens with scopes.
//!
//! A token file holds one token per line:
//!
//! ```text
//! # scope  token                                                            label
//! ro       3f9a…                                                            dashboard
//! admin    a1b2…                                                            ops
//! 9c0d…                                    <- a bare token: scope rw (the pre-scope behaviour)
//! ```
//!
//! `ro` may read, `rw` may also change the configuration (when the server runs
//! with writes enabled), `admin` may also do the sensitive actions a tool
//! defines (an OS update, a reset). Scopes only ever restrict: a server started
//! read-only refuses writes whatever the token.

use std::io::Write;
use std::path::Path;

/// What a token may do. Ordered: `Ro < Rw < Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Ro,
    Rw,
    Admin,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "ro" => Some(Scope::Ro),
            "rw" => Some(Scope::Rw),
            "admin" => Some(Scope::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Ro => "ro",
            Scope::Rw => "rw",
            Scope::Admin => "admin",
        }
    }
}

/// Who a request is, once authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The token's label (`default` for a bare token, `anonymous` without auth).
    pub label: String,
    pub scope: Scope,
}

impl Principal {
    /// The principal of a server running without authentication (loopback dev
    /// only): read-only, whatever the server's write switch says.
    pub fn anonymous() -> Principal {
        Principal {
            label: "anonymous".into(),
            scope: Scope::Ro,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    scope: Scope,
    label: String,
    token: String,
}

#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    entries: Vec<Entry>,
}

/// Constant-time equality (the length is not secret here: tokens are 64 hex).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl TokenStore {
    pub fn parse(text: &str) -> Result<TokenStore, String> {
        let mut entries = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            let (scope, token, label) = match f.as_slice() {
                [token] => (Scope::Rw, *token, "default"),
                [scope, token] => (scope_of(scope, n)?, *token, "default"),
                [scope, token, label, ..] => (scope_of(scope, n)?, *token, *label),
                [] => continue,
            };
            if token.len() < 16 {
                return Err(format!(
                    "token line {}: a token shorter than 16 characters is not accepted",
                    n + 1
                ));
            }
            entries.push(Entry {
                scope,
                label: label.to_string(),
                token: token.to_string(),
            });
        }
        Ok(TokenStore { entries })
    }

    pub fn load(path: &Path) -> Option<TokenStore> {
        let text = std::fs::read_to_string(path).ok()?;
        TokenStore::parse(&text)
            .ok()
            .filter(|s| !s.entries.is_empty())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The principal of `presented`, if it is one of the tokens. Every entry is
    /// compared (no early exit), so the time taken says nothing about which
    /// token, or how many, matched.
    pub fn authenticate(&self, presented: &str) -> Option<Principal> {
        let mut found = None;
        for e in &self.entries {
            if ct_eq(presented.as_bytes(), e.token.as_bytes()) {
                found = Some(Principal {
                    label: e.label.clone(),
                    scope: e.scope,
                });
            }
        }
        found
    }

    /// A store with one token, for tests and in-process use.
    pub fn single(scope: Scope, label: &str, token: &str) -> TokenStore {
        TokenStore {
            entries: vec![Entry {
                scope,
                label: label.into(),
                token: token.into(),
            }],
        }
    }

    pub fn with(mut self, scope: Scope, label: &str, token: &str) -> TokenStore {
        self.entries.push(Entry {
            scope,
            label: label.into(),
            token: token.into(),
        });
        self
    }
}

fn scope_of(s: &str, line: usize) -> Result<Scope, String> {
    Scope::parse(s).ok_or_else(|| {
        format!(
            "token line {}: unknown scope '{s}' (ro, rw or admin)",
            line + 1
        )
    })
}

fn random_token() -> Result<String, String> {
    let mut b = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut f, &mut b).map_err(|e| e.to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Writes a fresh token to `path` (0600) and returns it. With `append` the
/// file's other tokens are kept; otherwise it is replaced. A bare token (scope
/// `rw`, label `default`) is written in the one-word form old servers read.
pub fn gen_token(path: &Path, scope: Scope, label: &str, append: bool) -> Result<String, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if label.is_empty() || label.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("a token label is one word".into());
    }
    let token = random_token()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let line = if scope == Scope::Rw && label == "default" && !append {
        format!("{token}\n")
    } else {
        format!("{} {token} {label}\n", scope.as_str())
    };
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).mode(0o600);
    if append {
        o.append(true);
    } else {
        o.truncate(true);
    }
    let mut f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    f.write_all(line.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const T2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const T3: &str = "cccccccccccccccccccccccccccccccc";

    #[test]
    fn scopes_are_ordered() {
        assert!(Scope::Ro < Scope::Rw && Scope::Rw < Scope::Admin);
        assert_eq!(Scope::parse("admin"), Some(Scope::Admin));
        assert_eq!(Scope::parse("root"), None);
    }

    #[test]
    fn a_bare_token_is_rw_and_labelled_lines_carry_their_scope() {
        let s = TokenStore::parse(&format!(
            "# tokens\n\n{T1}\nro {T2} dashboard\nadmin {T3}\n"
        ))
        .unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(
            s.authenticate(T1),
            Some(Principal {
                label: "default".into(),
                scope: Scope::Rw
            })
        );
        let p = s.authenticate(T2).unwrap();
        assert_eq!((p.label.as_str(), p.scope), ("dashboard", Scope::Ro));
        assert_eq!(s.authenticate(T3).unwrap().scope, Scope::Admin);
        assert_eq!(s.authenticate("nope"), None);
        assert_eq!(s.authenticate(""), None);
    }

    #[test]
    fn malformed_files_are_refused_not_half_read() {
        assert!(
            TokenStore::parse("root aaaaaaaaaaaaaaaaaaaaaaaa x")
                .unwrap_err()
                .contains("unknown scope")
        );
        assert!(
            TokenStore::parse("short")
                .unwrap_err()
                .contains("shorter than 16")
        );
        assert!(TokenStore::parse("# only comments\n").unwrap().is_empty());
    }

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn gen_token_writes_0600_and_appends() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wapi-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = dir.join("tokens");
        let a = gen_token(&f, Scope::Rw, "default", false).unwrap();
        assert_eq!(a.len(), 64);
        assert_eq!(
            std::fs::read_to_string(&f).unwrap().trim(),
            a,
            "the bare form"
        );
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let b = gen_token(&f, Scope::Ro, "dash", true).unwrap();
        let s = TokenStore::load(&f).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.authenticate(&a).unwrap().scope, Scope::Rw);
        assert_eq!(s.authenticate(&b).unwrap().label, "dash");
        // without --append the file is replaced
        let c = gen_token(&f, Scope::Admin, "ops", false).unwrap();
        let s = TokenStore::load(&f).unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.authenticate(&a).is_none());
        assert_eq!(s.authenticate(&c).unwrap().scope, Scope::Admin);
        assert!(gen_token(&f, Scope::Ro, "two words", true).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
