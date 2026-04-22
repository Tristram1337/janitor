# Changelog

All notable changes to `janitor` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `info`: two-column grid now aligns the right column dynamically from
  the widest left cell, so `mode` / `size` / `mtime` stack at the same
  screen column even when user/group names expand (orphan UIDs like
  `#99999`, long names, etc.). Previously a fixed `col_w = 40` drifted.

### Changed
- Shell completions no longer list short-form flags (`-n`, `-j`, `-q`,
  `-h`, `-V`) or subcommand aliases (`g`, `rv`, `t`, `b`, `r`, `u`, `h`,
  `cp`, `ls`, `prune`, `i`, `a`, `w`, `p`, `e`, and the `-R` short alias
  on `compare --recursive`). The short forms remain fully functional on
  the CLI and are still documented in `--help` and in `janitor(1)`;
  they just don't clutter `janitor <TAB><TAB>` anymore. Implemented as a
  completion-only view of the command tree, so the parser is untouched.
- Dropped the unused `tabled` dependency (dead `simple_table` helper
  removed; all tables now go through the ANSI-aware `aligned_table`).

## [0.1.1] - 2026-04-22

Pre-1.0 polishing pass: UX triage, packaging, and correctness fixes. **Breaking
CLI changes** — see "Changed" below.

### Changed
- **Breaking:** `preset` is now a subcommand group.
  `janitor preset NAME PATH` ⇒ `janitor preset apply NAME PATH`, and the
  separate `presets` command ⇒ `janitor preset list`. Rationale: UX parity
  with `acl`, `policy`, `attr` (all verb-after-noun), and `presets` as a
  sibling top-level command duplicated the noun.
- **Breaking:** `seal` baseline is now POSIX-only by default. A plain
  `janitor seal DIR -B root:root:700 -R` issues `chown` + `chmod` only and
  writes no ACLs — it works on FAT, tmpfs, and any filesystem without
  `acl` support. ACLs are written only for explicit `--allow USER:PERM
  PATH` / `--allow-group GROUP:PERM PATH` pinholes (and the minimal
  `u:user:--x` / `g:group:--x` entries on the parent chain needed to
  reach them). If pinholes are requested on a filesystem without ACL
  support, `seal` fails fast with a clear error instead of silently
  producing an unreachable target.
- `audit` gained `--paths` and `-0` / `--print0` flags for pipe-pure output
  (one path per line, or NUL-separated). This replaces the old `janitor
  find -0 | janitor chmod --stdin0` pipeline. Both flags skip the ACL
  probe when the filter doesn't need it, keeping large scans fast.

### Removed
- **Breaking:** `janitor find` — its filter set was a subset of `audit`'s, and
  `audit --paths` / `audit -0` now covers the "produce a list of matching
  paths" use case it existed for.

### Fixed
- `who-can` now enumerates users via NSS (`setpwent` / `getpwent` / `endpwent`),
  so LDAP / SSSD / systemd-homed / FreeIPA directories are visible.
  Falls back to `/etc/passwd` if NSS yields nothing.
- `audit` / `find-orphans`: world-writable / world-readable / world-executable
  filters no longer false-positive on symlinks (whose own mode bits are a
  kernel artifact on Linux and carry no real meaning). The link target's
  mode is what governs access, so flagging the link itself was noise.
- `info`, `who-can`, `explain`, and friends now distinguish `EACCES` (you're
  not allowed to stat this) from `ENOENT` (it really doesn't exist) in
  their error messages.

### Packaging
- `.deb` and `.rpm` now install shell completions and the man page to
  standard locations:
  - `bash`: `/usr/share/bash-completion/completions/janitor`
  - `zsh`:  `/usr/share/zsh/vendor-completions/_janitor` (deb) or
    `/usr/share/zsh/site-functions/_janitor` (rpm)
  - `fish`: `/usr/share/fish/vendor_completions.d/janitor.fish`
  - `man`:  `/usr/share/man/man1/janitor.1.gz`
  No post-install hookup needed — bash-completion picks up the file lazily
  the next time the shell sees `janitor`. The deb package `Recommends`
  `bash-completion`.
- `scripts/package.sh` (new) drives the full pipeline: builds the release
  binary, invokes `janitor completions` / `janitor man` to generate
  assets into `target/assets/...`, then runs `cargo deb --no-build` /
  `cargo generate-rpm --no-build`. Subcommands: `deb`, `rpm`, `all`,
  `assets-only`.

## [0.1.0] - 2026-04-21

First public pre-release. API and CLI surface may still change before 1.0.0.

### Added
- `grant` / `revoke`: hierarchical permission management with automatic managed-group creation.
- `restore` / `list-backups` / `prune-backups` / `backup` / `diff` / `export`: full snapshot lifecycle.
- `chmod` (octal + symbolic) and `chown` (`user`, `user:group`, `:group`, `user:`, numeric) with auto-snapshot. `chmod` supports the full 4-digit octal range (setuid `4xxx`, setgid `2xxx`, sticky `1xxx`, combined `6xxx`/`7xxx`) and all symbolic `[ugoa][+-=][rwxXst]` clauses. Both commands accept `-F` / `--reference FILE` to copy the mode or owner from another path.
- `info` (alias `i`): one-shot summary of a path — type, owner (name + uid), group, mode (octal + symbolic, showing setuid/setgid/sticky), size, mtime, symlink target, ACLs, and optional effective `rwx` access for a user via `-U`.
- `undo` (alias `u`): one-shot restore of the most recent backup — an editor-style undo for any `grant` / `chmod` / `chown` / `acl` operation.
- `history` (alias `h`): list every backup whose target contains `PATH`, newest first, with optional `--json` for scripting.
- `copy-perms` (alias `cp`): atomically copy mode + owner + group (and optionally ACLs via `-A`) from `SRC` to `DST`, snapshotting `DST` first. `-R` walks recursively.
- `list-backups -p SUBSTR`: filter saved snapshots by target path.
- `acl grant|revoke|show|strip`: POSIX ACL management, including default ACLs and recursive application.
- `audit` with filters: world-writable (`-W`), world-readable (`-r`), world-executable (`-x`), setuid (`-s`), setgid (`-S`), sticky (`-t`), owner (`-o`), group (`-g`), mode (`-m`), has-acl (`-A`), `--no-owner`, `--no-group`.
- `find-orphans`: files with unresolvable UID or GID.
- `who-can`: reverse access query (parent-chain aware, honors group memberships).
- `tree` with per-user colorization, highlighting, parent chain, depth limit, and ACL marker.
- `preset` and `presets`: 19 named mode presets (`private`, `private-dir`, `private-file`, `group-shared`, `group-read`, `public-read`, `public-file`, `sticky-dir`, `setgid-dir`, `secret`, `secret-dir`, `exec-only`, `ssh-key`, `ssh-dir`, `config`, `log-file`, `systemd-unit`, `read-only`, `no-access`).
- `completions`: bash, zsh, fish, PowerShell, elvish.
- Positional `PATH` argument on every subcommand, matching `chmod(1)` / `chown(1)` conventions.
- Single-letter flags for every common option: `-n` (dry-run), `-j` (json), `-q` (quiet), `-u` (user), `-g` (group), `-a` (access string), `-r` / `-w` / `-x` (access bits, combinable in any order), `-R` (recursive), `-L` (max-level / max-depth), `-d` (default ACL), `-k` (keep), `-W` (world-writable), `-s` (setuid), `-S` (setgid), `-t` (sticky), `-o` (owner), `-m` (mode), `-A` (has-acl / capture-acl / acl marker), `-H` (highlight), `-P` (show-parents), `-U` (for-user), `-c` (color).
- Subcommand aliases: `g`, `rv`, `t`, `b`, `r`, `ls`, `prune`, `a`, `w`, `p`.
- Debian (`.deb`) and Red Hat (`.rpm`) packages for amd64 and arm64, plus portable and static (musl) tarballs. Dynamic builds link against glibc 2.35 and run on Debian 12+, Ubuntu 22.04+, and RHEL 9+; static tarballs cover Alpine, Debian 11, and minimal containers.
- Man page `janitor(1)` with workflows and examples.
- `chmod` / `chown` / `preset` accept **multiple `PATH`s** in one call (single snapshot). Paths can also be streamed via `--from-file FILE` (newline-separated) or `--stdin0` (NUL-separated, pairs with `find -print0` / `janitor find -0`). `-E` / `--exclude GLOB` (repeatable) skips paths by full-path or basename match.
- `audit`: new `-E` / `--exclude GLOB` filter and `--fix ACTION` (one-shot remediation). Supported actions: `chmod MODE`, `chown SPEC`, `preset NAME`, `strip-world-write`, `strip-setuid`, `strip-setgid`, `strip-sticky`. All matches mutate under a single backup.
- `find`: read-only permission-aware search (like coreutils `find`, but focused on mode bits, ownership, ACLs). `-0` NUL-separates output for piping into `janitor chmod --stdin0`.
- `explain` (alias `e`): human-readable read/write/exec verdict for a path, walking the parent chain and evaluating mode bits, group membership, and traversal bits, optionally `-U USER`.
- `compare A B`: side-by-side diff of mode / owner / group / ACL. Exit 1 on drift (CI-friendly). `-R` walks both trees.
- `lock PATH [-r REASON]` / `unlock PATH` / `locks`: persistent per-path mutation guard. Any janitor mutation targeting a locked path or a descendant of a locked directory fails with a clear error.
- `policy apply FILE` / `policy verify FILE`: declarative YAML policy (`path`, `mode`, `owner`, `group`, `preset`, `recursive`, `exclude`). `verify` exits 1 on drift.
- `batch FILE`: run many `chmod` / `chown` / `preset` operations in one transaction; `-` reads from stdin.
- `attr show|set-immutable|clear-immutable|set-append-only|clear-append-only`: thin wrapper around `chattr` / `lsattr` that refuses to run on locked paths.
- `history --since DUR`: filter backups by age (`30m`, `1h`, `2d`, `1w`).
- `copy-perms -E`: honors the same exclude filter as the other mass operations.
- Panic hook, SIGINT handler, advisory file lock, `0700` backup directory, world-readable-target warning.

[0.1.0]: https://github.com/Tristram1337/janitor/releases/tag/v0.1.0
