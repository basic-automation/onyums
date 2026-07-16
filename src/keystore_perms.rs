//! Keystore filesystem-permission hardening (onyums ROADMAP Phase 2 — *enforce
//! filesystem permissions for keystore*).
//!
//! The persistent state directory (`./tor/onyums/state` by default) holds the onion
//! service's v3 identity key. Anyone who can read that key **is** the service: they
//! can impersonate the `.onion` address on the network. The address is the only
//! authenticator onyums has, so the key file's mode is a load-bearing security
//! control, not hygiene.
//!
//! This module enforces the Unix convention for private key material — `0700` on
//! directories, `0600` on files — over the whole state tree before arti opens it,
//! and **fails closed**: if a path in the tree is group/other-accessible and the mode
//! cannot be tightened, [`harden_state_tree`] returns an error rather than launching
//! a service whose identity is readable by other local users.
//!
//! # Design
//!
//! The *policy* (which modes are acceptable, and what to tighten them to) is pure
//! integer logic compiled and unit-tested on every platform ([`permission_bits`],
//! [`is_too_permissive`], [`tighten`]). Only the syscall layer that reads and writes
//! a real inode's mode is `#[cfg(unix)]`. That split keeps the security decision
//! testable on any host, and keeps this module dependency-free (`std` only) so it can
//! be compiled and run standalone against a real Unix filesystem.
//!
//! # Platforms
//!
//! Unix modes have no faithful Windows equivalent: Windows access control is ACL-based,
//! and `std` exposes only a read-only bit, which would neither express `0600` nor deny
//! another user in the Administrators group. Rather than pretend, the enforcement is a
//! documented no-op off Unix ([`harden_state_tree`] reports [`Hardening::Unsupported`]);
//! the caller logs it once so an operator is told the control is not in force rather
//! than being told a false "hardened".
//!
//! # Relationship to arti's `fs-mistrust`
//!
//! Arti performs its own `fs-mistrust` permission check when it opens the keystore and
//! refuses to start on a world-readable state directory. This module is complementary,
//! not redundant: it runs *before* arti and **repairs** the tree it owns, so the common
//! case (a state dir created by a previous run under a lax `umask`, or restored from a
//! backup/`tar` that carried `0755`) comes up hardened instead of failing arti's check
//! with an error the operator has to hand-fix.

use std::{fs, io, path::Path};

/// Target mode for directories in the state tree: owner-only `rwx`.
pub const STATE_DIR_MODE: u32 = 0o700;

/// Target mode for files in the state tree: owner-only `rw`.
pub const STATE_FILE_MODE: u32 = 0o600;

/// The mode bits that must never be set on identity material: any group or other
/// access (`rwx` for group, `rwx` for other).
const GROUP_OTHER_MASK: u32 = 0o077;

/// Mask selecting the permission bits of a raw `st_mode`, discarding the file-type
/// bits (`S_IFDIR`, `S_IFREG`, …) that `MetadataExt::mode` also carries.
const PERMISSION_MASK: u32 = 0o7777;

/// Extract the permission bits from a raw `st_mode`.
///
/// `MetadataExt::mode` returns the file type in the high bits (e.g. `0o40755` for a
/// directory); every policy decision here is about the low permission bits alone.
#[must_use]
pub const fn permission_bits(mode: u32) -> u32 {
	mode & PERMISSION_MASK
}

/// Is this mode too permissive for onion-service identity material?
///
/// True when *any* group or other bit is set. Deliberately stricter than
/// "world-readable": a group-readable key on a shared host leaks the identity just as
/// completely, and a group-*writable* state dir lets another user swap the key out.
#[must_use]
pub const fn is_too_permissive(mode: u32) -> bool {
	permission_bits(mode) & GROUP_OTHER_MASK != 0
}

/// The tightened form of `mode`: owner bits preserved, every group/other bit cleared.
///
/// Tightening rather than overwriting with a fixed constant keeps an operator's
/// deliberate *stricter* choice intact — a `0400` read-only key stays `0400` instead of
/// being widened to `0600`. `0755` becomes `0700` and `0644` becomes `0600`, which is
/// why one function serves both the directory and file targets.
#[must_use]
pub const fn tighten(mode: u32) -> u32 {
	permission_bits(mode) & !GROUP_OTHER_MASK
}

/// What [`harden_state_tree`] did to the state tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hardening {
	/// The tree was checked on a Unix host. `tightened` counts the paths whose mode was
	/// group/other-accessible and has been narrowed; zero means everything was already
	/// correct.
	Enforced {
		/// Number of paths whose mode this run narrowed.
		tightened: usize,
		/// Number of paths inspected (the directory itself plus its contents).
		inspected: usize,
	},
	/// The host has no Unix mode model, so no enforcement was attempted (see the module
	/// docs). The state tree's protection is whatever the platform's ACLs provide.
	Unsupported,
}

impl Hardening {
	/// Did this run actually narrow at least one path's mode?
	#[must_use]
	pub const fn repaired_something(&self) -> bool {
		matches!(*self, Self::Enforced { tightened, .. } if tightened > 0)
	}
}

/// Create the state directory if absent, then enforce `0700`/`0600` across the tree
/// (onyums ROADMAP Phase 2).
///
/// Creating the directory here — before arti does — is what lets onyums choose the
/// mode the identity key is born under instead of inheriting the process `umask`.
/// Existing trees are repaired in place: every directory is tightened toward
/// [`STATE_DIR_MODE`] and every file toward [`STATE_FILE_MODE`], preserving stricter
/// owner bits (see [`tighten`]).
///
/// # Errors
/// Fails closed. Returns an error if the directory cannot be created or walked, or if
/// any path in the tree remains group/other-accessible after tightening (for example a
/// file owned by another user, whose mode this process may not change) — rather than
/// letting a service launch with a locally-readable identity key.
pub fn harden_state_tree(dir: &Path) -> io::Result<Hardening> {
	create_state_dir(dir)?;

	#[cfg(unix)]
	{
		let mut inspected = 0;
		let mut tightened = 0;
		harden_recursive(dir, &mut inspected, &mut tightened)?;
		Ok(Hardening::Enforced { tightened, inspected })
	}
	#[cfg(not(unix))]
	{
		Ok(Hardening::Unsupported)
	}
}

/// Create the state directory (and any missing parents) owner-only from birth.
///
/// A plain [`fs::create_dir_all`] applies the process `umask`, so the directory would
/// exist as `0755` under a default `umask 022` until the hardening pass below narrowed
/// it. That window is small but real, and it is the window in which the identity key is
/// first written. `DirBuilder::mode` closes it: the directory never exists in a
/// group/other-accessible state at all.
#[cfg(unix)]
fn create_state_dir(dir: &Path) -> io::Result<()> {
	use std::os::unix::fs::DirBuilderExt;

	fs::DirBuilder::new().recursive(true).mode(STATE_DIR_MODE).create(dir)
}

#[cfg(not(unix))]
fn create_state_dir(dir: &Path) -> io::Result<()> {
	fs::create_dir_all(dir)
}

/// Tighten one path, then recurse into it if it is a directory.
///
/// Symlinks are not followed: the tree is walked with `symlink_metadata`, so a symlink
/// planted in the state dir cannot redirect a `chmod` at a file outside the tree.
#[cfg(unix)]
fn harden_recursive(path: &Path, inspected: &mut usize, tightened: &mut usize) -> io::Result<()> {
	use std::os::unix::fs::PermissionsExt;

	let meta = fs::symlink_metadata(path)?;
	*inspected += 1;

	// A symlink's own mode is meaningless on Linux (`chmod` follows the link), and its
	// target may be outside the tree. Refuse rather than chase it: identity material has
	// no reason to be reached through a link, so its presence is a misconfiguration to
	// surface, not repair.
	if meta.file_type().is_symlink() {
		return Err(io::Error::new(io::ErrorKind::InvalidData, format!("refusing to harden the symlink {}: the state tree must not contain links to identity material", path.display())));
	}

	let current = permission_bits(meta.permissions().mode());
	if is_too_permissive(current) {
		fs::set_permissions(path, fs::Permissions::from_mode(tighten(current)))?;
		*tightened += 1;

		// Fail closed: re-read rather than trust the write. `set_permissions` reporting
		// success does not prove the bits landed (a filesystem may not honour them), and
		// this is the check that stands between a lax mode and a launched service.
		let verified = permission_bits(fs::symlink_metadata(path)?.permissions().mode());
		if is_too_permissive(verified) {
			return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is group/other-accessible (mode {verified:04o}) and could not be tightened; refusing to launch with a locally-readable onion-service identity", path.display())));
		}
	}

	if meta.is_dir() {
		for entry in fs::read_dir(path)? {
			harden_recursive(&entry?.path(), inspected, tightened)?;
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	// ---- Policy layer: pure, and therefore tested on every host (including Windows). ----

	#[test]
	fn permission_bits_discards_the_file_type() {
		// `MetadataExt::mode` carries S_IFDIR/S_IFREG in the high bits; every policy
		// decision is about the low permission bits alone.
		assert_eq!(permission_bits(0o040_755), 0o755, "directory type bits must be masked off");
		assert_eq!(permission_bits(0o100_644), 0o644, "regular-file type bits must be masked off");
		assert_eq!(permission_bits(0o700), 0o700, "bare permission bits pass through");
	}

	#[test]
	fn is_too_permissive_flags_any_group_or_other_access() {
		// Stricter than "world-readable": a group-readable key leaks the identity just as
		// completely, and a group-writable dir lets another user swap the key out.
		assert!(is_too_permissive(0o755), "world-readable+executable dir");
		assert!(is_too_permissive(0o644), "world-readable file");
		assert!(is_too_permissive(0o640), "group-readable file");
		assert!(is_too_permissive(0o604), "other-readable file");
		assert!(is_too_permissive(0o660), "group-writable file");
		assert!(is_too_permissive(0o001), "a single other-execute bit still counts");
		assert!(is_too_permissive(0o040_755), "raw st_mode is handled, not just permission bits");
	}

	#[test]
	fn is_too_permissive_accepts_owner_only_modes() {
		assert!(!is_too_permissive(STATE_DIR_MODE));
		assert!(!is_too_permissive(STATE_FILE_MODE));
		assert!(!is_too_permissive(0o400), "an owner-read-only key is stricter, not looser");
		assert!(!is_too_permissive(0o000), "no access at all is not too permissive");
	}

	#[test]
	fn tighten_strips_group_and_other_while_keeping_owner_bits() {
		// The two canonical repairs the state tree needs.
		assert_eq!(tighten(0o755), STATE_DIR_MODE, "a umask-022 directory becomes 0700");
		assert_eq!(tighten(0o644), STATE_FILE_MODE, "a umask-022 key file becomes 0600");
		assert_eq!(tighten(0o777), STATE_DIR_MODE);
		assert_eq!(tighten(0o666), STATE_FILE_MODE);
	}

	#[test]
	fn tighten_preserves_a_stricter_operator_choice() {
		// Tightening, not overwriting with a constant: a deliberately read-only key stays
		// read-only rather than being widened to 0600.
		assert_eq!(tighten(0o400), 0o400, "0400 must not be widened to 0600");
		assert_eq!(tighten(0o500), 0o500);
		assert_eq!(tighten(0o000), 0o000);
	}

	#[test]
	fn tighten_output_is_never_too_permissive() {
		// The two policy halves must agree: tightening is a fixed point of the check, for
		// every possible permission-bit pattern.
		for mode in 0..=0o7777_u32 {
			assert!(!is_too_permissive(tighten(mode)), "tighten({mode:04o}) left group/other bits set");
		}
	}

	#[test]
	fn tighten_is_idempotent() {
		for mode in 0..=0o7777_u32 {
			assert_eq!(tighten(tighten(mode)), tighten(mode), "tighten must be a fixed point at {mode:04o}");
		}
	}

	#[test]
	fn hardening_reports_whether_it_repaired_anything() {
		assert!(Hardening::Enforced { tightened: 1, inspected: 3 }.repaired_something());
		assert!(!Hardening::Enforced { tightened: 0, inspected: 3 }.repaired_something(), "an already-correct tree repaired nothing");
		assert!(!Hardening::Unsupported.repaired_something(), "a no-op platform repairs nothing");
	}

	// ---- Syscall layer: real inodes, Unix only. ----

	#[cfg(unix)]
	mod unix {
		use std::os::unix::fs::PermissionsExt;

		use super::*;

		/// A unique scratch directory under the system temp tree.
		fn scratch(tag: &str) -> std::path::PathBuf {
			let unique = format!("onyums-perms-test-{}-{}-{:?}", std::process::id(), tag, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
			std::env::temp_dir().join(unique)
		}

		fn mode_of(path: &Path) -> u32 {
			permission_bits(fs::symlink_metadata(path).expect("stat").permissions().mode())
		}

		#[test]
		fn creates_a_missing_state_dir_already_hardened() {
			// The reason onyums creates the dir instead of letting arti do it: the identity
			// key is born under a mode onyums chose, not the process umask. `DirBuilder::mode`
			// (not `create_dir_all`, which applies the umask and would leave the dir 0755
			// until the repair pass ran) means it is never group/other-accessible even
			// momentarily — so the repair counter stays at zero.
			let dir = scratch("create");
			assert!(!dir.exists());
			let report = harden_state_tree(&dir).expect("create + harden");
			assert!(dir.exists(), "the state dir must be created");
			assert_eq!(mode_of(&dir), STATE_DIR_MODE, "a freshly created state dir must be 0700");
			assert!(!report.repaired_something(), "a dir born 0700 needs no repair: {report:?}");
			fs::remove_dir_all(&dir).ok();
		}

		#[test]
		fn creates_missing_parents_hardened_too() {
			// `./tor/onyums/state` is three levels deep and typically none of it exists on a
			// first run: an intermediate parent left at umask 0755 would expose the keystore
			// it contains just as effectively as a lax leaf.
			let base = scratch("parents");
			let leaf = base.join("tor").join("onyums").join("state");
			harden_state_tree(&leaf).expect("create nested + harden");
			for level in [base.as_path(), &base.join("tor"), &base.join("tor").join("onyums"), leaf.as_path()] {
				assert_eq!(mode_of(level), STATE_DIR_MODE, "every created level must be owner-only: {}", level.display());
			}
			fs::remove_dir_all(&base).ok();
		}

		#[test]
		fn repairs_a_world_readable_tree_in_place() {
			// The realistic case: a state tree restored from a tar or created under a lax
			// umask, carrying 0755/0644 over the identity key.
			let dir = scratch("repair");
			fs::create_dir_all(dir.join("keystore")).expect("create tree");
			let key = dir.join("keystore").join("hs_ed25519_secret_key");
			fs::write(&key, b"fake identity").expect("write key");
			fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod dir");
			fs::set_permissions(dir.join("keystore"), fs::Permissions::from_mode(0o755)).expect("chmod subdir");
			fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("chmod key");

			let report = harden_state_tree(&dir).expect("harden");

			assert_eq!(mode_of(&dir), STATE_DIR_MODE);
			assert_eq!(mode_of(&dir.join("keystore")), STATE_DIR_MODE);
			assert_eq!(mode_of(&key), STATE_FILE_MODE, "the identity key must end up owner-only");
			assert!(!is_too_permissive(mode_of(&key)));
			assert_eq!(report, Hardening::Enforced { tightened: 3, inspected: 3 }, "all three paths were lax and repaired");
			fs::remove_dir_all(&dir).ok();
		}

		#[test]
		fn leaves_an_already_correct_tree_untouched() {
			// An already-hardened tree reports zero repairs, so the caller can stay quiet
			// instead of logging a repair on every launch.
			let dir = scratch("clean");
			fs::create_dir_all(&dir).expect("create");
			let key = dir.join("hs_ed25519_secret_key");
			fs::write(&key, b"fake").expect("write");
			fs::set_permissions(&dir, fs::Permissions::from_mode(STATE_DIR_MODE)).expect("chmod dir");
			fs::set_permissions(&key, fs::Permissions::from_mode(STATE_FILE_MODE)).expect("chmod key");

			let report = harden_state_tree(&dir).expect("harden");

			assert_eq!(report, Hardening::Enforced { tightened: 0, inspected: 2 }, "nothing to repair: {report:?}");
			assert!(!report.repaired_something());
			fs::remove_dir_all(&dir).ok();
		}

		#[test]
		fn preserves_a_stricter_key_mode_on_a_real_file() {
			// The policy layer's "don't widen 0400" promise, enforced end-to-end.
			let dir = scratch("strict");
			fs::create_dir_all(&dir).expect("create");
			let key = dir.join("hs_ed25519_secret_key");
			fs::write(&key, b"fake").expect("write");
			fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).expect("chmod key");
			fs::set_permissions(&dir, fs::Permissions::from_mode(STATE_DIR_MODE)).expect("chmod dir");

			harden_state_tree(&dir).expect("harden");

			assert_eq!(mode_of(&key), 0o400, "a read-only key must not be widened to 0600");
			fs::remove_dir_all(&dir).ok();
		}

		#[test]
		fn hardens_every_level_of_a_nested_tree() {
			// Arti's keystore is nested; a lax mode at any depth exposes the key.
			let dir = scratch("nested");
			let deep = dir.join("keystore").join("client").join("inner");
			fs::create_dir_all(&deep).expect("create deep tree");
			let key = deep.join("secret");
			fs::write(&key, b"fake").expect("write");
			for p in [dir.as_path(), &dir.join("keystore"), &dir.join("keystore").join("client"), deep.as_path()] {
				fs::set_permissions(p, fs::Permissions::from_mode(0o777)).expect("chmod");
			}
			fs::set_permissions(&key, fs::Permissions::from_mode(0o666)).expect("chmod key");

			harden_state_tree(&dir).expect("harden");

			assert_eq!(mode_of(&deep), STATE_DIR_MODE, "the deepest directory must be hardened too");
			assert_eq!(mode_of(&key), STATE_FILE_MODE, "the deepest key must be hardened too");
			fs::remove_dir_all(&dir).ok();
		}

		#[test]
		fn refuses_a_symlink_in_the_state_tree() {
			// A symlink is neither followed nor chmod'ed: `chmod` would follow it and
			// retarget at a file outside the tree. Identity material has no reason to sit
			// behind a link, so this fails closed instead of repairing.
			let dir = scratch("symlink");
			fs::create_dir_all(&dir).expect("create");
			fs::set_permissions(&dir, fs::Permissions::from_mode(STATE_DIR_MODE)).expect("chmod dir");
			let outside = scratch("symlink-target");
			fs::write(&outside, b"someone else's file").expect("write target");
			fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).expect("chmod target");
			std::os::unix::fs::symlink(&outside, dir.join("link")).expect("symlink");

			let err = harden_state_tree(&dir).expect_err("a symlink in the state tree must fail closed");

			assert_eq!(err.kind(), io::ErrorKind::InvalidData);
			assert_eq!(mode_of(&outside), 0o644, "the symlink's target outside the tree must not be touched");
			fs::remove_file(&outside).ok();
			fs::remove_dir_all(&dir).ok();
		}

		#[test]
		fn is_idempotent_across_launches() {
			// Every restart re-runs this; the second run must be a clean no-op.
			let dir = scratch("idempotent");
			fs::create_dir_all(&dir).expect("create");
			fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");

			let first = harden_state_tree(&dir).expect("first harden");
			let second = harden_state_tree(&dir).expect("second harden");

			assert!(first.repaired_something(), "the first run repairs the lax dir");
			assert!(!second.repaired_something(), "the second run has nothing left to repair");
			fs::remove_dir_all(&dir).ok();
		}
	}
}
