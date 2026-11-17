//! Rows read from MSI databases for the ownership index (M1b, contract C-OWNERSHIP).
//!
//! [`resolve`] turns the raw tables of one cached package ([`MsiTables`]) into rows with canonical
//! registry keys. It is the only resolver: the ownership index and the harvest (`MsiFacts.registry_rows`,
//! `services`) both call it.
//!
//! # What is resolved
//!
//! - `Registry`: `Key` and `Name` are `Formatted`. Only plain property references are substituted
//!   ([`format_text`]); any other `Formatted` syntax makes the row unresolved. `Root` -1 follows the
//!   product's context (machine: 2, user contexts: 1). The 64-bit attribute (bit 256) of the row's
//!   component selects the registry view; a component missing from the `Component` table makes the row
//!   unresolved.
//! - `Class` (`CLSID\{clsid}` and `CLSID\{clsid}\<Context>`), `Extension` (`.<ext>`), `ProgId`, `TypeLib`
//!   (`TypeLib\{libid}`), `AppId` (`AppID\{appid}`): keys under the classes root of the product's context.
//!   `ProgId`, `TypeLib` and `AppId` carry no component in [`MsiTables`], so their view is not known: they
//!   are looked up under both views.
//! - `ServiceInstall`: `Services\<Name>` under the current control set.
//!
//! An unresolved row is dropped and counted in [`ResolvedRows::unresolved`]; it never produces a broader
//! guess.
//!
//! # Views and the "any user" root
//!
//! Every key goes through `purge_guard::canon::canon_key` with the view the component selects; this module
//! has no list of redirected or shared keys. The guard redirects all of `HKLM\SOFTWARE` (and the classes
//! roots) for the 32-bit view, while Windows shares some keys below them between the views (most of
//! `SOFTWARE\Classes` other than `CLSID` and `Interface`, for example). A row of a 32-bit component is
//! therefore also looked up under its 64-bit spelling ([`ResolvedRow::keys`]): the extra spelling can
//! only add blocks, never remove one.
//!
//! A per-user row (`Root` 1) of a per-machine product has no user: it is written to every user who runs
//! the product. Its key is spelled with the literal user segment `HKU\*` ([`ANY_USER`]).

use std::collections::HashMap;

use purge_guard::canon::{GuardEnv, canon_key};
use purge_model::{MsiContext, MsiRegRow, MsiServiceRow, View};
use purge_source::sysobj::MsiTables;

/// The literal user segment of a per-user key of a per-machine product (`HKU\*\Software\...`).
pub const ANY_USER: &str = "*";

/// `msidbComponentAttributes64bit`.
pub const COMPONENT_64BIT: i32 = 256;

/// The SID whose hive stands in for "any user" when a key is canonicalised (its segment is then
/// replaced by [`ANY_USER`]).
const PLACEHOLDER_SID: &str = "S-1-5-18";

/// The product a package belongs to, as the resolver needs it.
#[derive(Debug, Clone, Copy)]
pub struct RowContext<'a> {
    /// ProductCode (`{GUID}`), used for `[ProductCode]` when the `Property` table has none.
    pub product_code: &'a str,
    /// The product's installation context.
    pub context: MsiContext,
    /// The user of a per-user product; `None` for a per-machine product. A per-user product without a
    /// SID leaves its per-user rows unresolved.
    pub user_sid: Option<&'a str>,
    /// `N` of `ControlSet00N`; zero leaves `ServiceInstall` rows unresolved.
    pub current_control_set: u32,
}

/// What a resolved row claims at its key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RowValue {
    /// The key only: no value of it (`Registry.Name` `+`, a `Registry` row with neither name nor value,
    /// and every row of the other tables).
    KeyOnly,
    /// The key and everything under it (`Registry.Name` `-` or `*` with a null `Value`).
    WholeKey,
    /// One value of the key; `None` is the default value.
    Value(Option<String>),
}

/// One resolved row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedRow {
    /// `Registry`, `Class`, `ProgId`, `Extension`, `TypeLib`, `AppId` or `ServiceInstall`.
    pub table: &'static str,
    /// The row's primary key in its table (`Registry`: the `Registry` column; `Class`: the CLSID;
    /// `ProgId`, `Extension`, `TypeLib`, `AppId`: their key column; `ServiceInstall`: the service name).
    pub row: String,
    /// The canonical keys the row is looked up under. The first is the key the row writes in the view
    /// its component selects; the others are the 64-bit spelling of a 32-bit row (see the module
    /// documentation) and, for a `Class` row, the `<Context>` subkey.
    pub keys: Vec<String>,
    /// What the row claims at its keys.
    pub value: RowValue,
    /// The row's component (the `Component` table key); `None` for the tables that carry none.
    pub component: Option<String>,
}

impl ResolvedRow {
    /// The first of [`keys`](Self::keys).
    pub fn key(&self) -> &str {
        self.keys.first().map_or("", String::as_str)
    }

    /// The key and everything under it is the row's.
    pub fn whole_key(&self) -> bool {
        self.value == RowValue::WholeKey
    }

    /// The row as a fingerprint fact: `Some` only for a `Registry` row that claims a value or its
    /// whole key. A key-only row claims nothing a scanner could offer, so it is not a fact.
    pub fn to_reg_row(&self) -> Option<MsiRegRow> {
        if self.table != "Registry" {
            return None;
        }
        let (name, whole_key) = match &self.value {
            RowValue::KeyOnly => return None,
            RowValue::WholeKey => (None, true),
            RowValue::Value(name) => (name.clone(), false),
        };
        Some(MsiRegRow {
            key: self.key().to_owned(),
            name,
            whole_key,
            component: self.component.clone().unwrap_or_default(),
            row: self.row.clone(),
        })
    }
}

/// Every row of one package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedRows {
    /// The resolved rows, in table order (`Registry`, `Class`, `ProgId`, `Extension`, `TypeLib`,
    /// `AppId`, `ServiceInstall`), each table in package order.
    pub rows: Vec<ResolvedRow>,
    /// The `ServiceInstall` rows with a resolved name.
    pub services: Vec<MsiServiceRow>,
    /// Rows that could not be resolved and were dropped.
    pub unresolved: u32,
}

/// The properties a package's `Formatted` strings can name: the `Property` table, plus `ProductCode`
/// from the product when the table has none. Names are case-sensitive, as in Windows Installer.
#[derive(Debug, Clone, Default)]
pub struct Properties {
    map: HashMap<String, String>,
}

impl Properties {
    /// The properties of `tables`, with `product_code` as `ProductCode` when the table has none.
    pub fn of(tables: &MsiTables, product_code: &str) -> Self {
        let mut map: HashMap<String, String> = HashMap::with_capacity(tables.properties.len() + 1);
        for (name, value) in &tables.properties {
            map.entry(name.clone()).or_insert_with(|| value.clone());
        }
        if !product_code.is_empty() {
            map.entry("ProductCode".to_owned())
                .or_insert_with(|| product_code.to_owned());
        }
        Self { map }
    }

    /// The value of one property.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.map.get(name).map(String::as_str)
    }
}

/// A property name as `Formatted` accepts it: a letter or `_`, then letters, digits, `_` and `.`.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Resolves a `Formatted` string, or `None` when it uses anything but plain property references and the
/// four bracket escapes.
///
/// - `[Name]` with `Name` a property of `props` is replaced by its value; a property that is not known
///   makes the string unresolved (Windows Installer would substitute an empty string, which changes the
///   key the row names).
/// - `[\[]`, `[\]]`, `[\{]`, `[\}]` give the bracket or brace.
/// - `[[`, `[#file]`, `[!file]`, `[$component]`, `[%ENV]`, `[~]`, any other `[\x]`, an empty or
///   unterminated `[`, and a `{...}` group that contains a `[` or `{` make the string unresolved. A
///   `{...}` group without them (a GUID such as `CLSID\{...}`) is literal text, braces included, as in
///   Windows Installer; an unterminated `{` is unresolved.
pub fn format_text(text: &str, props: &Properties) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        match c {
            '[' => {
                let after = &rest[1..];
                if let Some(escaped) = after.strip_prefix('\\') {
                    let mut it = escaped.chars();
                    let x = it.next()?;
                    if !matches!(x, '[' | ']' | '{' | '}') || it.next() != Some(']') {
                        return None;
                    }
                    out.push(x);
                    rest = &escaped[x.len_utf8() + 1..];
                    continue;
                }
                let end = after.find(']')?;
                let name = &after[..end];
                if !is_identifier(name) {
                    return None; // `[[`, `[]`, `[#..]`, `[!..]`, `[$..]`, `[%..]`, `[~]`, nested
                }
                out.push_str(props.get(name)?);
                rest = &after[end + 1..];
            }
            '{' => {
                let end = rest.find('}')?;
                let inner = &rest[1..end];
                if inner.contains(['[', '{']) {
                    return None;
                }
                out.push_str(&rest[..=end]);
                rest = &rest[end + 1..];
            }
            _ => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    Some(out)
}

/// The registry roots a row can name, after `Root` -1 is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    Classes,
    CurrentUser,
    Machine,
    Users,
}

/// Canonicalises keys for one product.
struct Keys<'a> {
    env: GuardEnv,
    ctx: &'a RowContext<'a>,
}

impl<'a> Keys<'a> {
    fn new(ctx: &'a RowContext<'a>) -> Self {
        Self {
            env: GuardEnv {
                current_control_set: ctx.current_control_set,
                ..GuardEnv::default()
            },
            ctx,
        }
    }

    fn machine(&self) -> bool {
        self.ctx.context == MsiContext::Machine
    }

    /// The canonical key of `rest` below `root` in `view`.
    fn key(&self, root: Root, rest: &str, view: View) -> Option<String> {
        let (input, any_user) = match root {
            Root::Machine => (format!("HKLM\\{rest}"), false),
            Root::Users => (format!("HKU\\{rest}"), false),
            Root::Classes if self.machine() => (format!("HKLM\\SOFTWARE\\Classes\\{rest}"), false),
            Root::Classes => (
                format!("HKU\\{}\\Software\\Classes\\{rest}", self.ctx.user_sid?),
                false,
            ),
            Root::CurrentUser if self.machine() => {
                (format!("HKU\\{PLACEHOLDER_SID}\\{rest}"), true)
            }
            Root::CurrentUser => (format!("HKU\\{}\\{rest}", self.ctx.user_sid?), false),
        };
        canon_with(&input, view, &self.env, any_user)
    }

    /// The key in the view the component selects, then its 64-bit spelling when that differs.
    fn keys(&self, root: Root, rest: &str, bit64: Option<bool>) -> Option<Vec<String>> {
        let primary_view = match bit64 {
            Some(false) => View::K32,
            Some(true) | None => View::K64,
        };
        let primary = self.key(root, rest, primary_view)?;
        let mut keys = vec![primary];
        let other = match bit64 {
            Some(false) => Some(View::K64),
            None => Some(View::K32),
            Some(true) => None,
        };
        if let Some(view) = other {
            let alias = self.key(root, rest, view)?;
            if !keys.iter().any(|k| purge_guard::prefix::is_same(k, &alias)) {
                keys.push(alias);
            }
        }
        Some(keys)
    }
}

/// `canon_key` of `input` in `view`, rendered; with `any_user`, the placeholder SID segment of the result
/// is replaced by [`ANY_USER`].
fn canon_with(input: &str, view: View, env: &GuardEnv, any_user: bool) -> Option<String> {
    let key = canon_key(input, Some(view), env, None).ok()?.key_path();
    if !any_user {
        return Some(key);
    }
    let rest = key.strip_prefix("HKU\\")?.strip_prefix(PLACEHOLDER_SID)?;
    Some(format!("HKU\\{ANY_USER}{rest}"))
}

/// Canonicalises a component key path's registry part for the user hive of `sid` (`None` = machine),
/// in the view given. Used by the component reader so that both readers share [`canon_with`].
pub(crate) fn component_registry_key(
    nn: u8,
    rest: &str,
    sid: Option<&str>,
    env: &GuardEnv,
) -> Option<String> {
    let view = if nn >= 20 { View::K64 } else { View::K32 };
    match nn % 20 {
        0 => match sid {
            None => canon_with(
                &format!("HKLM\\SOFTWARE\\Classes\\{rest}"),
                view,
                env,
                false,
            ),
            Some(sid) => canon_with(
                &format!("HKU\\{sid}\\Software\\Classes\\{rest}"),
                view,
                env,
                false,
            ),
        },
        1 => match sid {
            None => canon_with(&format!("HKU\\{PLACEHOLDER_SID}\\{rest}"), view, env, true),
            Some(sid) => canon_with(&format!("HKU\\{sid}\\{rest}"), view, env, false),
        },
        2 => canon_with(&format!("HKLM\\{rest}"), view, env, false),
        3 => canon_with(&format!("HKU\\{rest}"), view, env, false),
        _ => None,
    }
}

/// A single key name (CLSID, ProgId, extension, LibID, AppId, service name): non-empty, no separator,
/// no control character.
fn key_name(name: &str) -> Option<&str> {
    (!name.is_empty() && !name.contains('\\') && !name.chars().any(char::is_control))
        .then_some(name)
}

/// The key path of a `Registry` row: `Formatted`, leading and trailing separators trimmed, not empty.
fn registry_path(raw: &str, props: &Properties) -> Option<String> {
    let key = format_text(raw, props)?;
    let key = key.trim_matches('\\');
    (!key.is_empty()).then(|| key.to_owned())
}

/// Resolves every row of one package. See the module documentation.
pub fn resolve(tables: &MsiTables, ctx: &RowContext) -> ResolvedRows {
    let props = Properties::of(tables, ctx.product_code);
    let keys = Keys::new(ctx);
    let components: HashMap<&str, i32> = tables
        .components
        .iter()
        .map(|c| (c.component.as_str(), c.attributes))
        .collect();
    let bit64 = |component: &str| {
        components
            .get(component)
            .map(|attrs| attrs & COMPONENT_64BIT != 0)
    };
    let mut out = ResolvedRows::default();
    let push = |out: &mut ResolvedRows, row: Option<ResolvedRow>| match row {
        Some(row) => out.rows.push(row),
        None => out.unresolved += 1,
    };

    for raw in &tables.registry {
        let row = (|| {
            let bit64 = bit64(&raw.component)?;
            let root = match (raw.root, ctx.context) {
                (-1, MsiContext::Machine) | (2, _) => Root::Machine,
                (-1, _) | (1, _) => Root::CurrentUser,
                (0, _) => Root::Classes,
                (3, _) => Root::Users,
                _ => return None,
            };
            let path = registry_path(&raw.key, &props)?;
            let value = match (raw.name.as_deref(), raw.value.is_none()) {
                (Some("-" | "*"), true) => RowValue::WholeKey,
                (Some("+") | None, true) => RowValue::KeyOnly,
                (None, false) => RowValue::Value(None),
                (Some(name), _) => {
                    let name = format_text(name, &props)?;
                    RowValue::Value((!name.is_empty()).then_some(name))
                }
            };
            Some(ResolvedRow {
                table: "Registry",
                row: raw.row.clone(),
                keys: keys.keys(root, &path, Some(bit64))?,
                value,
                component: Some(raw.component.clone()),
            })
        })();
        push(&mut out, row);
    }

    for class in &tables.classes {
        let row = (|| {
            let bit64 = bit64(&class.component)?;
            let clsid = key_name(&class.clsid)?;
            let mut all = keys.keys(Root::Classes, &format!("CLSID\\{clsid}"), Some(bit64))?;
            if let Some(context) = key_name(&class.context) {
                all.extend(keys.keys(
                    Root::Classes,
                    &format!("CLSID\\{clsid}\\{context}"),
                    Some(bit64),
                )?);
            }
            Some(ResolvedRow {
                table: "Class",
                row: clsid.to_owned(),
                keys: all,
                value: RowValue::KeyOnly,
                component: Some(class.component.clone()),
            })
        })();
        push(&mut out, row);
    }

    let componentless = |table: &'static str, name: &str, prefix: &str| {
        let name = key_name(name)?;
        Some(ResolvedRow {
            table,
            row: name.to_owned(),
            keys: keys.keys(Root::Classes, &format!("{prefix}{name}"), None)?,
            value: RowValue::KeyOnly,
            component: None,
        })
    };
    for progid in &tables.progids {
        push(&mut out, componentless("ProgId", progid, ""));
    }

    for ext in &tables.extensions {
        let row = (|| {
            let bit64 = bit64(&ext.component)?;
            let name = key_name(&ext.extension)?;
            Some(ResolvedRow {
                table: "Extension",
                row: name.to_owned(),
                keys: keys.keys(Root::Classes, &format!(".{name}"), Some(bit64))?,
                value: RowValue::KeyOnly,
                component: Some(ext.component.clone()),
            })
        })();
        push(&mut out, row);
    }

    for libid in &tables.typelibs {
        push(&mut out, componentless("TypeLib", libid, "TypeLib\\"));
    }
    for appid in &tables.appids {
        push(&mut out, componentless("AppId", appid, "AppID\\"));
    }

    for svc in &tables.service_install {
        let row = (|| {
            bit64(&svc.component)?;
            let name = format_text(&svc.name, &props)?;
            let name = key_name(&name)?;
            let key = keys.key(
                Root::Machine,
                &format!("SYSTEM\\CurrentControlSet\\Services\\{name}"),
                View::K64,
            )?;
            Some(ResolvedRow {
                table: "ServiceInstall",
                row: name.to_owned(),
                keys: vec![key],
                value: RowValue::KeyOnly,
                component: Some(svc.component.clone()),
            })
        })();
        if let Some(row) = &row {
            out.services.push(MsiServiceRow {
                name: row.row.clone(),
                component: svc.component.clone(),
            });
        }
        push(&mut out, row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(pairs: &[(&str, &str)]) -> Properties {
        let tables = MsiTables {
            properties: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..MsiTables::default()
        };
        Properties::of(&tables, "{11111111-2222-3333-4444-555555555555}")
    }

    #[test]
    fn plain_text_and_known_properties() {
        let p = props(&[("Manufacturer", "Vendor"), ("ProductName", "App")]);
        assert_eq!(
            format_text(r"Software\[Manufacturer]\[ProductName]", &p).as_deref(),
            Some(r"Software\Vendor\App")
        );
        assert_eq!(
            format_text(r"x\[ProductCode]", &p).as_deref(),
            Some(r"x\{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(format_text("", &p).as_deref(), Some(""));
    }

    #[test]
    fn property_names_are_case_sensitive() {
        let p = props(&[("Manufacturer", "Vendor")]);
        assert_eq!(format_text("[MANUFACTURER]", &p), None);
    }

    #[test]
    fn bracket_escapes_resolve_and_other_escapes_do_not() {
        let p = props(&[]);
        assert_eq!(
            format_text(r"a[\[]b[\]]c[\{]d[\}]", &p).as_deref(),
            Some("a[b]c{d}")
        );
        assert_eq!(format_text(r"a[\n]", &p), None);
        assert_eq!(format_text(r"a[\]", &p), None);
        assert_eq!(format_text(r"a[\[", &p), None);
    }

    #[test]
    fn other_formatted_syntax_is_unresolved() {
        let p = props(&[("A", "x")]);
        for bad in [
            "[[A]]", "[#file]", "[!file]", "[$comp]", "[%PATH]", "[~]", "[]", "[A", "a[A b]",
            "{[A]}", "{{x}}", "{x", "[A.]x[", "[1A]",
        ] {
            assert_eq!(format_text(bad, &p), None, "{bad}");
        }
    }

    #[test]
    fn guid_braces_are_literal() {
        let p = props(&[]);
        assert_eq!(
            format_text(r"CLSID\{0000-1111}\InprocServer32", &p).as_deref(),
            Some(r"CLSID\{0000-1111}\InprocServer32")
        );
        assert_eq!(format_text("a]b}c", &p).as_deref(), Some("a]b}c"));
    }

    #[test]
    fn non_ascii_text_is_kept() {
        let p = props(&[("ProductName", "Ünï")]);
        assert_eq!(
            format_text("Ä\\[ProductName]\\ö", &p).as_deref(),
            Some("Ä\\Ünï\\ö")
        );
    }
}
