//! The vendor label of a URL (`URLInfoAbout`, `HelpLink`): the registrable domain's own label, e.g.
//! `mozilla` for `https://www.mozilla.org/en-US/`.
//!
//! There is no public-suffix list here. The label is the one left of the top-level domain, or one further
//! left when the top-level domain is a two-letter country code behind a common second-level label
//! (`example.co.uk`). Hosts that many unrelated projects share (code hosting, download sites, site builders,
//! cloud hosting, stores, social and chat sites) name no
//! vendor and give `None`, as do IP addresses, single-label hosts and anything that is not a host name.

/// Second-level labels used as public suffixes under two-letter country codes.
const SECOND_LEVEL: &[&str] = &[
    "ac", "co", "com", "edu", "go", "gob", "gov", "ne", "net", "nom", "or", "org",
];

/// Hosts shared by unrelated projects: their label is not a vendor.
const SHARED_HOSTS: &[&str] = &[
    "amazonaws",
    "appspot",
    "azurewebsites",
    "bitbucket",
    "blogspot",
    "cloudfront",
    "codeberg",
    "codeplex",
    "discord",
    "dropbox",
    "facebook",
    "fosshub",
    "gitee",
    "github",
    "githubusercontent",
    "gitlab",
    "googlecode",
    "herokuapp",
    "itch",
    "launchpad",
    "netlify",
    "sf",
    "softonic",
    "softpedia",
    "sourceforge",
    "sourcehut",
    "steamcommunity",
    "steampowered",
    "tinyurl",
    "tumblr",
    "twitter",
    "vercel",
    "weebly",
    "wixsite",
    "wordpress",
    "youtube",
];

/// The registrable-domain label of `url`, lower case; see the module documentation.
pub(crate) fn registrable_label(url: &str) -> Option<String> {
    let s = url.trim().trim_matches('"').trim();
    let rest = match s.find("://") {
        Some(i) => {
            let scheme = &s[..i];
            if !["http", "https", "ftp"]
                .iter()
                .any(|k| scheme.eq_ignore_ascii_case(k))
            {
                return None;
            }
            &s[i + 3..]
        }
        // Without a scheme only a bare host is accepted: an e-mail address or a file path names no site.
        None if s.contains(['@', ':']) => return None,
        None => s,
    };
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    let host = host.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let well_formed = |l: &&str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_alphanumeric() || c == '-')
    };
    if !labels.iter().all(well_formed) {
        return None;
    }
    let tld = labels[labels.len() - 1];
    // An IPv4 address, or anything else without an alphabetic top-level domain.
    if !tld.chars().any(char::is_alphabetic) {
        return None;
    }
    let mut idx = labels.len() - 2;
    if labels.len() >= 3 && tld.chars().count() == 2 && SECOND_LEVEL.contains(&labels[idx]) {
        idx -= 1;
    }
    let label = labels[idx];
    if SHARED_HOSTS.contains(&label) {
        return None;
    }
    Some(label.to_owned())
}

#[cfg(test)]
mod tests {
    use super::registrable_label as label;

    #[test]
    fn plain_hosts() {
        assert_eq!(
            label("https://www.mozilla.org/en-US/").as_deref(),
            Some("mozilla")
        );
        assert_eq!(
            label("HTTP://Notepad-Plus-Plus.org").as_deref(),
            Some("notepad-plus-plus")
        );
        assert_eq!(label("www.7-zip.org").as_deref(), Some("7-zip"));
        assert_eq!(
            label("https://code.visualstudio.com/").as_deref(),
            Some("visualstudio")
        );
        assert_eq!(
            label("https://user:pw@example.com:8443/x?y#z").as_deref(),
            Some("example")
        );
        assert_eq!(
            label("  \"https://example.com.\"  ").as_deref(),
            Some("example")
        );
    }

    #[test]
    fn country_code_second_level() {
        assert_eq!(
            label("https://www.example.co.uk/a").as_deref(),
            Some("example")
        );
        assert_eq!(label("http://example.com.tr").as_deref(), Some("example"));
        // Two labels only: the left one is the name even if it looks like a second-level label.
        assert_eq!(label("https://co.uk").as_deref(), Some("co"));
        // A generic top-level domain is never treated as a country code.
        assert_eq!(label("https://foo.com.info").as_deref(), Some("com"));
    }

    #[test]
    fn shared_hosts_name_no_vendor() {
        assert_eq!(label("https://github.com/some/project"), None);
        assert_eq!(label("https://someone.github.io/tool"), None);
        assert_eq!(label("http://tool.sourceforge.net"), None);
        assert_eq!(label("https://gitlab.com/x/y"), None);
        // Site builders, cloud hosts, stores and chat invites.
        assert_eq!(label("https://mytool.blogspot.com/"), None);
        assert_eq!(label("https://mytool.azurewebsites.net/help"), None);
        assert_eq!(label("https://store.steampowered.com/app/620"), None);
        assert_eq!(label("https://discord.gg/abcdef"), None);
    }

    #[test]
    fn not_a_host_name() {
        assert_eq!(label(""), None);
        assert_eq!(label("localhost"), None);
        assert_eq!(label("http://localhost:8080/"), None);
        assert_eq!(label("http://192.168.1.10/help"), None);
        assert_eq!(label("http://[::1]/help"), None);
        assert_eq!(label("C:\\Program Files\\App\\help.chm"), None);
        assert_eq!(label("file:///C:/App/help.html"), None);
        assert_eq!(label("mailto://support@example.com"), None);
        assert_eq!(label("mailto:support@example.com"), None);
        assert_eq!(label("support@example.com"), None);
        assert_eq!(label("https://exa mple.com"), None);
        assert_eq!(label("https://-bad-.com"), None);
        assert_eq!(label("https://a..com"), None);
    }
}
