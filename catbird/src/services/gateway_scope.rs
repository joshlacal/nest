//! OAuth scope comparison for Nest's registered clients and existing grants.
//! Petrel handles standard AT Protocol families. Nest also accepts its existing
//! Space, OIDC and multi-audience RPC grants when checking an upgrade.
use std::collections::BTreeSet;

use petrel_oauth_scopes::{
    is_did, is_did_ref_absolute, is_nsid, is_record_key, AtProtoScope, ScopeParameterBag,
    ScopeParseError, ScopeStringSyntax, SingleLookup,
};

type Values = BTreeSet<String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Atproto,
    Standard(AtProtoScope),
    OpenId(&'static str),
    Rpc(RpcGrant),
    Space(SpaceGrant),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcGrant {
    methods: Values,
    audiences: Values,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceGrant {
    pub space_type: String,
    pub authority: String,
    pub skey: String,
    pub collections: Values,
    pub actions: Values,
    pub manage: Values,
}

const SPACE_ACTIONS: [&str; 4] = ["create", "delete", "read", "update"];

fn default_actions() -> Values {
    SPACE_ACTIONS.into_iter().map(String::from).collect()
}

fn parse_values(
    bag: &ScopeParameterBag,
    key: &'static str,
    valid: impl Fn(&str) -> bool,
) -> Result<Values, ScopeParseError> {
    bag.values(key)
        .into_iter()
        .map(|value| {
            valid(value)
                .then(|| value.to_owned())
                .ok_or(ScopeParseError::InvalidParameter { key })
        })
        .collect()
}

fn parse_selector(
    bag: &ScopeParameterBag,
    key: &'static str,
    default: &str,
    valid: impl Fn(&str) -> bool,
) -> Result<String, ScopeParseError> {
    match bag.single(key) {
        SingleLookup::Absent => Ok(default.to_owned()),
        SingleLookup::Present(v) if valid(v) => Ok(v.to_owned()),
        SingleLookup::Present(_) => Err(ScopeParseError::InvalidParameter { key }),
        SingleLookup::Repeated(_) => Err(ScopeParseError::RepeatedSingleValue { key }),
    }
}

fn known_parameters(
    syntax: &ScopeStringSyntax,
    family: &'static str,
    keys: &[&str],
) -> Result<(), ScopeParseError> {
    for (key, _) in syntax.parameters.entries() {
        if !keys.contains(&key.as_str()) {
            return Err(ScopeParseError::UnknownParameter {
                prefix: family,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn nsid_or_any(value: &str) -> bool {
    value == "*" || is_nsid(value)
}

impl SpaceGrant {
    fn parse(raw: &str) -> Result<Self, ScopeParseError> {
        let syntax = ScopeStringSyntax::parse(raw)?;
        known_parameters(
            &syntax,
            "space",
            &["authority", "skey", "action", "manage", "collection"],
        )?;
        let space_type = syntax
            .positional
            .filter(|v| nsid_or_any(v))
            .ok_or(ScopeParseError::InvalidPositional { key: "space" })?;
        let bag = &syntax.parameters;
        let authority = parse_selector(bag, "authority", "self", |v| {
            matches!(v, "*" | "self") || is_did(v)
        })?;
        let skey = parse_selector(bag, "skey", "*", |v| v == "*" || is_record_key(v))?;
        let collections = parse_values(bag, "collection", nsid_or_any)?;
        let mut actions = parse_values(bag, "action", |v| {
            SPACE_ACTIONS.contains(&v) || v == "read_self"
        })?;
        let manage = parse_values(bag, "manage", |v| {
            matches!(v, "create" | "update" | "delete")
        })?;
        if actions.is_empty() && manage.is_empty() {
            actions = default_actions();
        }
        Ok(Self {
            space_type,
            authority,
            skey,
            collections,
            actions,
            manage,
        })
    }

    fn grants(&self, other: &Self) -> bool {
        let covers = |grant: &str, need: &str| grant == "*" || grant == need;
        let writes = other
            .actions
            .iter()
            .any(|a| matches!(a.as_str(), "create" | "update" | "delete"));
        let collections_cover = !writes
            || self.collections.is_empty()
            || self.collections.contains("*")
            || (!other.collections.is_empty() && other.collections.is_subset(&self.collections));
        covers(&self.space_type, &other.space_type)
            && covers(&self.authority, &other.authority)
            && covers(&self.skey, &other.skey)
            && collections_cover
            && other.manage.is_subset(&self.manage)
            && other.actions.iter().all(|a| {
                self.actions.contains(a) || (a == "read_self" && self.actions.contains("read"))
            })
    }

    fn wire(&self) -> String {
        let mut bag = ScopeParameterBag::default();
        append_values(&mut bag, "action", &self.actions);
        if self.authority != "self" {
            bag.append("authority".into(), self.authority.clone());
        }
        append_values(&mut bag, "collection", &self.collections);
        append_values(&mut bag, "manage", &self.manage);
        if self.skey != "*" {
            bag.append("skey".into(), self.skey.clone());
        }
        format_wire("space", Some(self.space_type.clone()), bag)
    }
}

fn append_values(bag: &mut ScopeParameterBag, key: &str, values: &Values) {
    for v in values {
        bag.append(key.to_owned(), v.clone());
    }
}

fn format_wire(family: &str, positional: Option<String>, parameters: ScopeParameterBag) -> String {
    ScopeStringSyntax {
        prefix: family.into(),
        positional,
        parameters,
    }
    .wire_string()
    .expect("validated scope parameters encode as one scope token")
}

impl RpcGrant {
    fn parse(raw: &str) -> Result<Self, ScopeParseError> {
        let syntax = ScopeStringSyntax::parse(raw)?;
        known_parameters(&syntax, "rpc", &["lxm", "aud"])?;
        let mut methods = parse_values(&syntax.parameters, "lxm", nsid_or_any)?;
        if let Some(positional) = syntax.positional {
            if !methods.is_empty() {
                return Err(ScopeParseError::PositionalConflict { key: "lxm" });
            }
            if !nsid_or_any(&positional) {
                return Err(ScopeParseError::InvalidPositional { key: "lxm" });
            }
            methods.insert(positional);
        }
        let mut audiences = parse_values(&syntax.parameters, "aud", |v| {
            v == "*" || is_did(v) || is_did_ref_absolute(v)
        })?;
        // Legacy Nest registrations omit wildcard selectors.
        if methods.is_empty() {
            methods.insert("*".into());
        }
        if audiences.is_empty() {
            audiences.insert("*".into());
        }
        Ok(Self { methods, audiences })
    }

    fn wire(&self) -> String {
        if self.audiences.len() == 1 && self.audiences.contains("*") && self.methods.len() == 1 {
            return format!("rpc:{}", self.methods.first().expect("one RPC method"));
        }
        let mut bag = ScopeParameterBag::default();
        append_values(&mut bag, "aud", &self.audiences);
        append_values(&mut bag, "lxm", &self.methods);
        format_wire("rpc", None, bag)
    }
}

impl Scope {
    pub fn parse(raw: &str) -> Result<Self, ScopeParseError> {
        match raw {
            "atproto" => Ok(Self::Atproto),
            "openid" => Ok(Self::OpenId("openid")),
            "profile" => Ok(Self::OpenId("profile")),
            "email" => Ok(Self::OpenId("email")),
            _ if ScopeStringSyntax::is_scope_string(raw, "space") => {
                SpaceGrant::parse(raw).map(Self::Space)
            }
            _ if ScopeStringSyntax::is_scope_string(raw, "rpc") => {
                RpcGrant::parse(raw).map(Self::Rpc)
            }
            _ => AtProtoScope::parse(raw).map(Self::Standard),
        }
    }

    /// A server can omit the reference default actions even when manage is present.
    pub fn with_server_defaults(mut self) -> Self {
        if let Self::Space(space) = &mut self {
            if space.actions.is_empty() {
                space.actions = default_actions();
            }
        }
        self
    }

    pub fn to_string_normalized(&self) -> String {
        match self {
            Self::Atproto => "atproto".into(),
            Self::OpenId(raw) => (*raw).into(),
            Self::Space(space) => space.wire(),
            Self::Rpc(rpc) => rpc.wire(),
            Self::Standard(p) => p
                .wire_scope_string()
                .expect("parsed Petrel scope has a wire representation"),
        }
    }

    pub fn grants(&self, need: &Self) -> bool {
        use AtProtoScope as S;
        match (self, need) {
            (Self::Space(a), Self::Space(b)) => a.grants(b),
            (Self::Rpc(a), Self::Rpc(b)) => {
                (a.methods.contains("*") || b.methods.is_subset(&a.methods))
                    && (a.audiences.contains("*") || b.audiences.is_subset(&a.audiences))
            }
            (Self::Standard(S::Repo(a)), Self::Standard(S::Repo(b))) => {
                b.parameters().multiple("collection").iter().all(|c| {
                    b.parameters()
                        .multiple("action")
                        .iter()
                        .all(|act| a.matches(c, act))
                })
            }
            (Self::Standard(S::Account(a)), Self::Standard(S::Account(b))) => {
                b.parameters().single("attr").is_some_and(|attr| {
                    b.parameters()
                        .multiple("action")
                        .iter()
                        .all(|act| a.matches(attr, act))
                })
            }
            (Self::Standard(S::Identity(a)), Self::Standard(S::Identity(b))) => {
                b.parameters().single("attr").is_some_and(|attr| {
                    a.parameters().single("attr") == Some("*")
                        || a.parameters().single("attr") == Some(attr)
                })
            }
            (Self::Standard(S::Blob(a)), Self::Standard(S::Blob(b))) => {
                b.parameters().multiple("accept").iter().all(|need| {
                    a.parameters().multiple("accept").iter().any(|grant| {
                        grant == "*/*"
                            || grant.eq_ignore_ascii_case(need)
                            || grant
                                .strip_suffix("/*")
                                .zip(need.split_once('/'))
                                .is_some_and(|(g, (n, _))| g.eq_ignore_ascii_case(n))
                    })
                })
            }
            _ => self == need,
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_normalized())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    #[test]
    fn write_collections_and_read_self_are_directional() {
        let wide = scope("space:blue.catbird.circle?action=read&action=create&collection=*");
        let narrow = scope("space:blue.catbird.circle?collection=app.bsky.feed.post&action=create&action=read_self");
        assert!(wide.grants(&narrow));
        assert!(!narrow.grants(&wide));
        assert!(!wide.grants(&scope("space:blue.catbird.circle?authority=*&action=read")));
    }

    #[test]
    fn request_and_server_default_differ_for_manage_only() {
        let raw = "space:blue.catbird.circle?manage=create";
        let request = scope(raw);
        let grant = request.clone().with_server_defaults();
        assert!(!request.grants(&scope("space:blue.catbird.circle?action=read")));
        assert!(grant.grants(&scope("space:blue.catbird.circle?action=read")));
        assert_eq!(scope(&grant.to_string_normalized()), grant);
    }

    #[test]
    fn rpc_spelling_keeps_the_service_fragment_and_multiple_audiences() {
        let one = scope("rpc:*?aud=did:web:chat.example%23atproto_mls");
        let two =
            scope("rpc?aud=did:web:chat.example%23atproto_mls&aud=did:web:other.example&lxm=*");
        assert!(two.grants(&one));
        assert!(!one.grants(&two));
        assert!(!one.grants(&scope("rpc:*?aud=did:web:chat.example%23other")));
        assert_eq!(scope(&two.to_string_normalized()), two);
        assert_eq!(scope("rpc:*").to_string_normalized(), "rpc:*");
    }

    #[test]
    fn standard_grants_cover_only_their_requested_family_and_bounds() {
        let pairs = [
            ("identity:*", "identity:handle"),
            ("blob:image/*", "blob:image/jpeg"),
            ("repo:*", "repo:app.bsky.feed.post?action=create"),
            ("account:email?action=manage", "account:email"),
        ];
        for (grant, need) in pairs {
            assert!(scope(grant).grants(&scope(need)));
            assert!(!scope(need).grants(&scope(grant)));
        }
        assert!(!scope("transition:generic").grants(&scope("identity:handle")));
        assert!(!scope("openid").grants(&scope("profile")));
    }

    #[test]
    fn malformed_or_unknown_grants_do_not_acquire_an_implicit_wildcard() {
        for invalid in [
            "space:blue.catbird.circle?authority=self&authority=*",
            "space:blue.catbird.circle?action=wrong",
            "space:blue.catbird.circle?manag=create",
            "rpc?lxmm=app.bsky.feed.post",
            "rpc:app.bsky.feed.post?aud=",
            "unregistered:family",
        ] {
            assert!(Scope::parse(invalid).is_err(), "{invalid}");
        }
    }
}
