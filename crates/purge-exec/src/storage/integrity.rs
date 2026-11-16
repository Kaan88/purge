//! The integrity verdict over the facts of one storage object, and the SDDL constants it checks
//! against. Pure: no I/O, so every rule is unit-tested over synthetic facts.

use purge_win::secure::Ace;
use purge_win::sid::{ADMINISTRATORS_SID, LOCAL_SYSTEM_SID, TRUSTED_INSTALLER_SID};

/// `C:\ProgramData\Purge` as `install.ps1` creates it (`install/README.md`, constant `DataRoot`).
pub const SDDL_DATA_ROOT: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100020;;;BU)";
/// `C:\ProgramData\Purge\sessions` (`install/README.md`, constant `Sessions`).
pub const SDDL_SESSIONS: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100020;;;BU)";
/// `Quarantine`, and every directory purge-exec creates: session and op directories, `reg`, `def`,
/// `X:\.purge-q` (`install/README.md`, constant `Store`).
pub const SDDL_STORE: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// `sessions\index.json` and the temporary file of its atomic rewrite (`install/README.md`, constant
/// `Index`): the one object standard users may read.
pub const SDDL_INDEX: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
/// Files purge-exec creates inside a session directory (journal, reports, backups). Not an installer
/// constant: the admin-only `Store` access without the inheritance flags, which a file has no use for.
pub const SDDL_STORE_FILE: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// `FILE_TRAVERSE | SYNCHRONIZE`: the traverse-only right Users hold on the data root and `sessions`.
const TRAVERSE_ONLY: u32 = 0x0010_0020;
/// `FILE_GENERIC_READ`: what Users hold on `index.json`.
const GENERIC_FILE_READ: u32 = 0x0012_0089;

/// Which object of the layout a check is about. Each kind has its constant and the rights principals
/// other than SYSTEM, Administrators and TrustedInstaller may hold on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// The data root, `C:\ProgramData\Purge`.
    DataRoot,
    /// `sessions`.
    Sessions,
    /// `Quarantine`, `X:\.purge-q`, and every directory below them or below `sessions`.
    Store,
    /// `sessions\index.json`.
    Index,
    /// A file inside a session directory.
    StoreFile,
}

impl ObjectKind {
    /// The SDDL the object is created with under the strict policy.
    pub fn sddl(self) -> &'static str {
        match self {
            ObjectKind::DataRoot => SDDL_DATA_ROOT,
            ObjectKind::Sessions => SDDL_SESSIONS,
            ObjectKind::Store => SDDL_STORE,
            ObjectKind::Index => SDDL_INDEX,
            ObjectKind::StoreFile => SDDL_STORE_FILE,
        }
    }

    /// Whether the object is a directory.
    pub fn is_dir(self) -> bool {
        matches!(
            self,
            ObjectKind::DataRoot | ObjectKind::Sessions | ObjectKind::Store
        )
    }

    /// The access mask an allow entry for any other principal may carry: the rights the install
    /// constant gives Users, and nothing more.
    pub fn foreign_mask(self) -> u32 {
        match self {
            ObjectKind::DataRoot | ObjectKind::Sessions => TRAVERSE_ONLY,
            ObjectKind::Index => GENERIC_FILE_READ,
            ObjectKind::Store | ObjectKind::StoreFile => 0,
        }
    }

    /// Whether the DACL must be protected. A file in a session directory may carry the entries it
    /// inherited from its admin-only parent; everything the installer or the store creates is protected.
    pub fn requires_protected_dacl(self) -> bool {
        !matches!(self, ObjectKind::StoreFile)
    }
}

/// What the integrity check reads from one handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFacts {
    /// Reparse tag of the object itself; 0 when it is not a reparse point.
    pub reparse_tag: u32,
    /// Whether the object is a directory.
    pub is_dir: bool,
    /// Hard link count.
    pub n_links: u32,
    /// Owner SID; `None` when the descriptor has none or it could not be decoded.
    pub owner: Option<String>,
    /// `SE_DACL_PROTECTED`.
    pub dacl_protected: bool,
    /// The DACL; `None` for a NULL DACL, which grants everyone everything.
    pub dacl: Option<Vec<Ace>>,
}

/// Why a storage object failed its integrity check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityFailure {
    /// The object is a reparse point (junction, symbolic link, mount point, any tag).
    #[error("is a reparse point (tag {tag:#010x})")]
    ReparsePoint {
        /// The reparse tag.
        tag: u32,
    },
    /// A file where a directory belongs, or the reverse.
    #[error("is not a {}", if *.expected_dir { "directory" } else { "file" })]
    WrongKind {
        /// Whether a directory was expected.
        expected_dir: bool,
    },
    /// A file with more than one name: a second name could live outside the store.
    #[error("has {n_links} hard links")]
    HardLinked {
        /// The link count.
        n_links: u32,
    },
    /// The owner is neither Administrators nor SYSTEM.
    #[error("owner is {}", .owner.as_deref().unwrap_or("unknown"))]
    Owner {
        /// The owner SID, when known.
        owner: Option<String>,
    },
    /// The DACL is NULL (everyone has full access).
    #[error("has a NULL DACL")]
    NullDacl,
    /// The DACL inherits from the parent.
    #[error("DACL is not protected")]
    UnprotectedDacl,
    /// An allow entry gives a principal other than SYSTEM, Administrators or TrustedInstaller rights
    /// beyond what the install constant gives Users.
    #[error("grants {mask:#010x} to {}", .sid.as_deref().unwrap_or("an undecodable SID"))]
    ForeignAccess {
        /// The trustee, when decodable.
        sid: Option<String>,
        /// The rights outside the allowed set.
        mask: u32,
    },
    /// The handle is not on the path the check expected: the path resolved elsewhere. Nothing is
    /// renamed, because the path does not name the object that was checked.
    #[error("resolves to {actual}, expected {expected}")]
    FinalPathMismatch {
        /// The path the parent chain implies.
        expected: String,
        /// The path the handle is on.
        actual: String,
    },
    /// A directory checked earlier in the same use is now another object. Nothing is renamed.
    #[error("was replaced by another object since it was opened")]
    IdentityChanged,
}

impl IntegrityFailure {
    /// Whether the failure is a definite verdict on the object at the path, so that the object is
    /// renamed aside. A path that resolved elsewhere or changed under the check is only refused.
    pub fn renames_aside(&self) -> bool {
        !matches!(
            self,
            IntegrityFailure::FinalPathMismatch { .. } | IntegrityFailure::IdentityChanged
        )
    }
}

/// The policy the store checks objects under.
///
/// Release builds have only [`IntegrityPolicy::strict`]. The relaxed policy, for unelevated tests in
/// temporary directories, exists only under `cfg(test)` or the `test-support` feature: it skips the
/// owner check (an unelevated process cannot own an object as Administrators) and treats the test
/// user like an administrator in the DACL check. Reparse, kind, link-count, protected-DACL and
/// foreign-access checks stay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityPolicy {
    /// SID of the test user under the relaxed policy; `None` under the strict policy.
    relaxed_user: Option<String>,
}

impl IntegrityPolicy {
    /// The policy of a real installation: owner Administrators or SYSTEM, admin-only write access.
    pub fn strict() -> IntegrityPolicy {
        IntegrityPolicy { relaxed_user: None }
    }

    /// The test policy for the unelevated user `user_sid`; see the type documentation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn relaxed(user_sid: String) -> IntegrityPolicy {
        IntegrityPolicy {
            relaxed_user: Some(user_sid),
        }
    }

    /// Whether this is the strict policy.
    pub fn is_strict(&self) -> bool {
        self.relaxed_user.is_none()
    }

    /// The SDDL objects of `kind` are created with. Strict: the constant. Relaxed: the constant
    /// without its owner part (an unelevated token cannot assign the Administrators owner) and with
    /// full control for the test user, inheritable on directories.
    pub fn sddl_for(&self, kind: ObjectKind) -> String {
        let strict = kind.sddl();
        match &self.relaxed_user {
            None => strict.to_owned(),
            Some(user) => {
                let body = strict.strip_prefix("O:BA").unwrap_or(strict);
                let inherit = if kind.is_dir() { "OICI" } else { "" };
                format!("{body}(A;{inherit};FA;;;{user})")
            }
        }
    }

    fn is_admin_sid(&self, sid: &str) -> bool {
        sid == LOCAL_SYSTEM_SID
            || sid == ADMINISTRATORS_SID
            || sid == TRUSTED_INSTALLER_SID
            || self.relaxed_user.as_deref() == Some(sid)
    }

    fn owner_ok(&self, owner: Option<&str>) -> bool {
        self.relaxed_user.is_some()
            || matches!(owner, Some(o) if o == ADMINISTRATORS_SID || o == LOCAL_SYSTEM_SID)
    }
}

/// The verdict on one object: `Ok` when it may be used as a `kind` object under `policy`.
///
/// Checked in this order, the first failure wins: reparse point, kind, hard links (files), owner, NULL
/// DACL, protected DACL, foreign access. Foreign access looks at every allow entry, inherit-only ones
/// included, because they decide what objects created below would grant.
pub fn verdict(
    policy: &IntegrityPolicy,
    kind: ObjectKind,
    facts: &ObjectFacts,
) -> Result<(), IntegrityFailure> {
    if facts.reparse_tag != 0 {
        return Err(IntegrityFailure::ReparsePoint {
            tag: facts.reparse_tag,
        });
    }
    if facts.is_dir != kind.is_dir() {
        return Err(IntegrityFailure::WrongKind {
            expected_dir: kind.is_dir(),
        });
    }
    if !facts.is_dir && facts.n_links != 1 {
        return Err(IntegrityFailure::HardLinked {
            n_links: facts.n_links,
        });
    }
    if !policy.owner_ok(facts.owner.as_deref()) {
        return Err(IntegrityFailure::Owner {
            owner: facts.owner.clone(),
        });
    }
    let Some(dacl) = &facts.dacl else {
        return Err(IntegrityFailure::NullDacl);
    };
    if kind.requires_protected_dacl() && !facts.dacl_protected {
        return Err(IntegrityFailure::UnprotectedDacl);
    }
    let allowed = kind.foreign_mask();
    for ace in dacl.iter().filter(|a| a.is_allow()) {
        if ace.sid.as_deref().is_some_and(|s| policy.is_admin_sid(s)) {
            continue;
        }
        let extra = ace.mask & !allowed;
        if extra != 0 {
            return Err(IntegrityFailure::ForeignAccess {
                sid: ace.sid.clone(),
                mask: extra,
            });
        }
    }
    Ok(())
}

/// Rights on a volume root that let a principal take `X:\.purge-q` away or give itself that right:
/// `FILE_DELETE_CHILD` (rename or delete any entry), `WRITE_DAC`, `WRITE_OWNER` and `GENERIC_ALL`.
pub const ROOT_TAKEOVER_RIGHTS: u32 = 0x40 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000;
/// `CREATOR OWNER`, whose entries apply only to objects created below.
const CREATOR_OWNER_SID: &str = "S-1-3-0";
/// `OWNER RIGHTS`, whose entries apply to the owner, checked separately.
const OWNER_RIGHTS_SID: &str = "S-1-3-4";
/// `LOCAL SERVICE`.
const LOCAL_SERVICE_SID: &str = "S-1-5-19";
/// `NETWORK SERVICE`. The Storage Management API formats volumes in a host process running as this
/// account, which then owns the new volume's root (`Format-Volume`: the M2 rig's `D:\` is owned by it).
const NETWORK_SERVICE_SID: &str = "S-1-5-20";

/// Whether `sid` may own a volume root or hold [`ROOT_TAKEOVER_RIGHTS`] on it: an administrator
/// principal of `policy`, or one of the two built-in service accounts. Those are not users anybody
/// logs on as; services under them are configured by administrators and hold the impersonation
/// privilege, which Windows does not treat as a boundary to SYSTEM. A standard user is never one of
/// them.
fn is_root_principal(policy: &IntegrityPolicy, sid: &str) -> bool {
    policy.is_admin_sid(sid) || sid == LOCAL_SERVICE_SID || sid == NETWORK_SERVICE_SID
}

/// The verdict on the root of a volume that is to hold `X:\.purge-q`: `Ok` when only
/// Administrators, SYSTEM, TrustedInstaller, LOCAL SERVICE and NETWORK SERVICE (and the test user
/// under the relaxed policy) own it or hold [`ROOT_TAKEOVER_RIGHTS`] on the root itself.
///
/// `.purge-q` refuses everyone else, but a principal with delete-child on the root can rename it
/// away and plant another; the store then rejects the planted one and the quarantined data is lost
/// for undo. Such a volume is not used for quarantine. Inherit-only entries do not apply to the
/// root and are ignored, as are deny entries; a NULL DACL fails.
pub fn volume_root_verdict(
    policy: &IntegrityPolicy,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
) -> Result<(), IntegrityFailure> {
    if !owner.is_some_and(|o| is_root_principal(policy, o)) {
        return Err(IntegrityFailure::Owner {
            owner: owner.map(str::to_owned),
        });
    }
    let Some(dacl) = dacl else {
        return Err(IntegrityFailure::NullDacl);
    };
    for ace in dacl.iter().filter(|a| a.is_allow() && a.is_effective()) {
        if ace.sid.as_deref().is_some_and(|s| {
            is_root_principal(policy, s) || s == CREATOR_OWNER_SID || s == OWNER_RIGHTS_SID
        }) {
            continue;
        }
        let rights = ace.mask & ROOT_TAKEOVER_RIGHTS;
        if rights != 0 {
            return Err(IntegrityFailure::ForeignAccess {
                sid: ace.sid.clone(),
                mask: rights,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = "S-1-5-32-545";

    #[test]
    fn volume_roots_that_let_others_take_the_quarantine_away_are_refused() {
        let strict = IntegrityPolicy::strict();
        let admin = admin_dacl();
        // A drive root as Windows sets it up: users may add folders and read, nothing more; inherit-only
        // entries (CREATOR OWNER, Users' Modify on what is created below) do not count.
        let mut drive = admin.clone();
        drive.push(ace("S-1-5-11", 0x0000_0004, 0));
        drive.push(ace(USERS, 0x0012_00A9, 0x03));
        drive.push(ace("S-1-5-11", 0x0013_01BF, 0x0B));
        drive.push(ace(CREATOR_OWNER_SID, 0x1000_0000, 0x0B));
        let ok = |owner: &str, dacl: &[Ace]| volume_root_verdict(&strict, Some(owner), Some(dacl));
        assert_eq!(ok(ADMINISTRATORS_SID, &drive), Ok(()));
        assert_eq!(ok(TRUSTED_INSTALLER_SID, &drive), Ok(()));
        // Modify on the root itself carries no delete-child.
        let mut modify = admin.clone();
        modify.push(ace("S-1-5-11", 0x0013_01BF, 0x03));
        assert_eq!(ok(LOCAL_SYSTEM_SID, &modify), Ok(()));

        for (mask, refused) in [
            (0x001F_01FF, 0x000C_0040),
            (0x40, 0x40),
            (0x0004_0000, 0x0004_0000),
            (0x1000_0000, 0x1000_0000),
        ] {
            let mut open = admin.clone();
            open.push(ace(USERS, mask, 0));
            assert_eq!(
                ok(ADMINISTRATORS_SID, &open),
                Err(IntegrityFailure::ForeignAccess {
                    sid: Some(USERS.to_owned()),
                    mask: refused
                }),
                "{mask:#x}"
            );
        }
        assert_eq!(
            ok(ME, &admin),
            Err(IntegrityFailure::Owner {
                owner: Some(ME.to_owned())
            })
        );
        assert_eq!(
            volume_root_verdict(&strict, Some(ADMINISTRATORS_SID), None),
            Err(IntegrityFailure::NullDacl)
        );
        // The relaxed policy treats the test user as an administrator, nobody else.
        let relaxed = IntegrityPolicy::relaxed(ME.to_owned());
        let mut mine = admin.clone();
        mine.push(ace(ME, 0x001F_01FF, 0x03));
        assert_eq!(volume_root_verdict(&relaxed, Some(ME), Some(&mine)), Ok(()));
        mine.push(ace(USERS, 0x40, 0));
        assert!(volume_root_verdict(&relaxed, Some(ME), Some(&mine)).is_err());
    }

    #[test]
    fn a_volume_root_formatted_by_the_storage_service_is_accepted() {
        // The M2 rig's `D:\` after `Format-Volume`: owner NETWORK SERVICE, the usual drive DACL.
        let strict = IntegrityPolicy::strict();
        let mut drive = admin_dacl();
        drive.push(ace("S-1-5-11", 0x0000_0004, 0));
        drive.push(ace(USERS, 0x0012_00A9, 0x03));
        drive.push(ace(CREATOR_OWNER_SID, 0x1000_0000, 0x0B));
        for service in [NETWORK_SERVICE_SID, LOCAL_SERVICE_SID] {
            assert_eq!(
                volume_root_verdict(&strict, Some(service), Some(&drive)),
                Ok(()),
                "{service}"
            );
            let mut granted = drive.clone();
            granted.push(ace(service, 0x001F_01FF, 0x03));
            assert_eq!(
                volume_root_verdict(&strict, Some(ADMINISTRATORS_SID), Some(&granted)),
                Ok(()),
                "{service}"
            );
        }
        // A user still may not own the root or take children away, whoever else owns it.
        assert!(volume_root_verdict(&strict, Some(ME), Some(&drive)).is_err());
        let mut open = drive.clone();
        open.push(ace(ME, 0x40, 0));
        assert_eq!(
            volume_root_verdict(&strict, Some(NETWORK_SERVICE_SID), Some(&open)),
            Err(IntegrityFailure::ForeignAccess {
                sid: Some(ME.to_owned()),
                mask: 0x40
            })
        );
        // Store objects themselves still need Administrators or SYSTEM as owner.
        let mut facts = dir_facts(admin_dacl());
        facts.owner = Some(NETWORK_SERVICE_SID.to_owned());
        assert!(matches!(
            verdict(&strict, ObjectKind::Store, &facts),
            Err(IntegrityFailure::Owner { .. })
        ));
    }
    const ME: &str = "S-1-5-21-1-2-3-1001";

    fn ace(sid: &str, mask: u32, flags: u8) -> Ace {
        Ace {
            ace_type: 0,
            flags,
            mask,
            sid: Some(sid.to_owned()),
        }
    }

    fn admin_dacl() -> Vec<Ace> {
        vec![
            ace(LOCAL_SYSTEM_SID, 0x1F_01FF, 0x03),
            ace(ADMINISTRATORS_SID, 0x1F_01FF, 0x03),
        ]
    }

    fn dir_facts(dacl: Vec<Ace>) -> ObjectFacts {
        ObjectFacts {
            reparse_tag: 0,
            is_dir: true,
            n_links: 1,
            owner: Some(ADMINISTRATORS_SID.to_owned()),
            dacl_protected: true,
            dacl: Some(dacl),
        }
    }

    #[test]
    fn install_shaped_objects_pass() {
        let strict = IntegrityPolicy::strict();
        let mut root = admin_dacl();
        root.push(ace(USERS, TRAVERSE_ONLY, 0));
        assert_eq!(
            verdict(&strict, ObjectKind::DataRoot, &dir_facts(root.clone())),
            Ok(())
        );
        assert_eq!(
            verdict(&strict, ObjectKind::Sessions, &dir_facts(root)),
            Ok(())
        );
        assert_eq!(
            verdict(&strict, ObjectKind::Store, &dir_facts(admin_dacl())),
            Ok(())
        );
        let mut system_owned = dir_facts(admin_dacl());
        system_owned.owner = Some(LOCAL_SYSTEM_SID.to_owned());
        assert_eq!(verdict(&strict, ObjectKind::Store, &system_owned), Ok(()));
        // TrustedInstaller may hold rights; deny entries never matter.
        let mut with_ti = admin_dacl();
        with_ti.push(ace(TRUSTED_INSTALLER_SID, 0x1F_01FF, 0));
        with_ti.push(Ace {
            ace_type: 1,
            flags: 0,
            mask: 0x1F_01FF,
            sid: Some(USERS.to_owned()),
        });
        assert_eq!(
            verdict(&strict, ObjectKind::Store, &dir_facts(with_ti)),
            Ok(())
        );

        let mut index = admin_dacl();
        index.push(ace(USERS, GENERIC_FILE_READ, 0));
        let index = ObjectFacts {
            is_dir: false,
            ..dir_facts(index)
        };
        assert_eq!(verdict(&strict, ObjectKind::Index, &index), Ok(()));
        // An inherited, unprotected DACL is fine for a file in a session directory only.
        let file = ObjectFacts {
            is_dir: false,
            dacl_protected: false,
            ..dir_facts(admin_dacl())
        };
        assert_eq!(verdict(&strict, ObjectKind::StoreFile, &file), Ok(()));
        assert_eq!(
            verdict(&strict, ObjectKind::Index, &file),
            Err(IntegrityFailure::UnprotectedDacl)
        );
    }

    #[test]
    fn each_rule_refuses() {
        let strict = IntegrityPolicy::strict();
        let good = dir_facts(admin_dacl());

        let junction = ObjectFacts {
            reparse_tag: 0xA000_0003,
            ..good.clone()
        };
        let failure = verdict(&strict, ObjectKind::Store, &junction).unwrap_err();
        assert_eq!(failure, IntegrityFailure::ReparsePoint { tag: 0xA000_0003 });
        assert!(failure.renames_aside());
        // The reparse verdict comes first, whatever else is wrong.
        let user_junction = ObjectFacts {
            owner: Some(ME.to_owned()),
            dacl: None,
            ..junction
        };
        assert!(matches!(
            verdict(&strict, ObjectKind::DataRoot, &user_junction),
            Err(IntegrityFailure::ReparsePoint { .. })
        ));

        assert_eq!(
            verdict(&strict, ObjectKind::Index, &good),
            Err(IntegrityFailure::WrongKind {
                expected_dir: false
            })
        );
        let file = ObjectFacts {
            is_dir: false,
            ..good.clone()
        };
        assert_eq!(
            verdict(&strict, ObjectKind::Store, &file),
            Err(IntegrityFailure::WrongKind { expected_dir: true })
        );
        let linked = ObjectFacts { n_links: 2, ..file };
        assert_eq!(
            verdict(&strict, ObjectKind::StoreFile, &linked),
            Err(IntegrityFailure::HardLinked { n_links: 2 })
        );

        for owner in [Some(ME.to_owned()), Some(USERS.to_owned()), None] {
            let facts = ObjectFacts {
                owner: owner.clone(),
                ..good.clone()
            };
            assert_eq!(
                verdict(&strict, ObjectKind::Store, &facts),
                Err(IntegrityFailure::Owner { owner })
            );
        }
        let null = ObjectFacts {
            dacl: None,
            ..good.clone()
        };
        assert_eq!(
            verdict(&strict, ObjectKind::Store, &null),
            Err(IntegrityFailure::NullDacl)
        );
        let unprotected = ObjectFacts {
            dacl_protected: false,
            ..good.clone()
        };
        assert_eq!(
            verdict(&strict, ObjectKind::Sessions, &unprotected),
            Err(IntegrityFailure::UnprotectedDacl)
        );
    }

    #[test]
    fn foreign_rights_beyond_the_constant_refuse() {
        let strict = IntegrityPolicy::strict();
        // (kind, foreign entry, refused bits); `None` means accepted.
        let cases: [(ObjectKind, Ace, Option<u32>); 9] = [
            // Users traverse is the most the data root and sessions give.
            (ObjectKind::DataRoot, ace(USERS, TRAVERSE_ONLY, 0), None),
            (ObjectKind::DataRoot, ace(USERS, 0x0010_0021, 0), Some(0x1)),
            // Delete-child on sessions.
            (ObjectKind::Sessions, ace(USERS, 0x40, 0), Some(0x40)),
            // Anything at all on Quarantine and below, inherit-only entries included.
            (
                ObjectKind::Store,
                ace(USERS, TRAVERSE_ONLY, 0),
                Some(TRAVERSE_ONLY),
            ),
            (ObjectKind::Store, ace(ME, 0x2, 0x0B), Some(0x2)),
            // Generic rights are refused bits too.
            (
                ObjectKind::Store,
                ace(USERS, 0x4000_0000, 0x0B),
                Some(0x4000_0000),
            ),
            // Users may read index.json, not write it.
            (ObjectKind::Index, ace(USERS, GENERIC_FILE_READ, 0), None),
            (ObjectKind::Index, ace(USERS, 0x0012_019F, 0), Some(0x116)),
            (
                ObjectKind::Index,
                ace("S-1-1-0", 0x0001_0000, 0),
                Some(0x0001_0000),
            ),
        ];
        for (kind, entry, refused) in cases {
            let mut dacl = admin_dacl();
            dacl.push(entry.clone());
            let facts = ObjectFacts {
                is_dir: kind.is_dir(),
                ..dir_facts(dacl)
            };
            let expected = refused.map_or(Ok(()), |mask| {
                Err(IntegrityFailure::ForeignAccess {
                    sid: entry.sid.clone(),
                    mask,
                })
            });
            assert_eq!(
                verdict(&strict, kind, &facts),
                expected,
                "{kind:?} {entry:?}"
            );
        }
        // An entry whose SID cannot be decoded is foreign.
        let mut dacl = admin_dacl();
        dacl.push(Ace {
            ace_type: 0x05,
            flags: 0,
            mask: 0x1,
            sid: None,
        });
        assert_eq!(
            verdict(&strict, ObjectKind::Store, &dir_facts(dacl)),
            Err(IntegrityFailure::ForeignAccess { sid: None, mask: 1 })
        );
    }

    #[test]
    fn relaxed_policy_skips_only_the_owner_and_admits_the_test_user() {
        let relaxed = IntegrityPolicy::relaxed(ME.to_owned());
        assert!(!relaxed.is_strict() && IntegrityPolicy::strict().is_strict());
        let mut dacl = admin_dacl();
        dacl.push(ace(ME, 0x1F_01FF, 0x03));
        let facts = ObjectFacts {
            owner: Some(ME.to_owned()),
            ..dir_facts(dacl)
        };
        assert_eq!(verdict(&relaxed, ObjectKind::Store, &facts), Ok(()));
        assert!(matches!(
            verdict(&IntegrityPolicy::strict(), ObjectKind::Store, &facts),
            Err(IntegrityFailure::Owner { .. })
        ));
        // Reparse, protection and foreign checks still apply.
        let junction = ObjectFacts {
            reparse_tag: 0xA000_000C,
            ..facts.clone()
        };
        assert!(verdict(&relaxed, ObjectKind::Store, &junction).is_err());
        let unprotected = ObjectFacts {
            dacl_protected: false,
            ..facts.clone()
        };
        assert_eq!(
            verdict(&relaxed, ObjectKind::Store, &unprotected),
            Err(IntegrityFailure::UnprotectedDacl)
        );
        let mut open = facts.dacl.clone().unwrap();
        open.push(ace(USERS, 0x2, 0));
        let open = ObjectFacts {
            dacl: Some(open),
            ..facts
        };
        assert!(matches!(
            verdict(&relaxed, ObjectKind::Store, &open),
            Err(IntegrityFailure::ForeignAccess { .. })
        ));
    }

    #[test]
    fn sddl_per_policy() {
        assert_eq!(
            IntegrityPolicy::strict().sddl_for(ObjectKind::Store),
            SDDL_STORE
        );
        let relaxed = IntegrityPolicy::relaxed(ME.to_owned());
        assert_eq!(
            relaxed.sddl_for(ObjectKind::Store),
            format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{ME})")
        );
        assert_eq!(
            relaxed.sddl_for(ObjectKind::Index),
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)(A;;FA;;;{ME})")
        );
        for kind in [
            ObjectKind::DataRoot,
            ObjectKind::Sessions,
            ObjectKind::Store,
            ObjectKind::Index,
            ObjectKind::StoreFile,
        ] {
            assert!(kind.sddl().starts_with("O:BAD:P("), "{kind:?}");
            assert!(!relaxed.sddl_for(kind).contains("O:"), "{kind:?}");
        }
        assert!(!IntegrityFailure::IdentityChanged.renames_aside());
        assert!(
            !IntegrityFailure::FinalPathMismatch {
                expected: "a".into(),
                actual: "b".into()
            }
            .renames_aside()
        );
    }

    #[test]
    fn constants_match_the_installer_readme() {
        let readme = include_str!("../../../../install/README.md");
        for (name, sddl) in [
            ("DataRoot", SDDL_DATA_ROOT),
            ("Sessions", SDDL_SESSIONS),
            ("Store", SDDL_STORE),
            ("Index", SDDL_INDEX),
        ] {
            let row = format!("| `{name}` |");
            let line = readme
                .lines()
                .find(|l| l.starts_with(&row))
                .unwrap_or_else(|| panic!("README has no row for {name}"));
            assert!(line.contains(&format!("`{sddl}`")), "{name}: {line}");
        }
    }
}
