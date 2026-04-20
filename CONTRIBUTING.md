# Contributing to janitor

Thanks for your interest in improving `janitor`. This document describes the
development workflow, coding conventions, and how to add new subcommands.

## Development setup

Requirements:

- Rust 1.85+ (install via [rustup](https://rustup.rs)).
- A Linux host or VM (the code is Linux-only; uses `lchown`, `/etc/passwd`, `setfacl`).
- `docker` for the end-to-end test harness.
- `acl` package installed for local ACL testing: `sudo apt install acl`.

```sh
git clone https://github.com/Tristram1337/janitor
cd janitor
cargo build
cargo test
```

## Running the full test suite

```sh
# Unit tests.
cargo test --release

# End-to-end Docker smoke tests.
cargo build --release
docker build -f tests/Dockerfile -t janitor-test .
docker run --rm janitor-test
```

CI runs the same commands on every push and pull request.

## Coding conventions

- **`cargo fmt`** must be clean. `rustfmt.toml` pins the style.
- **`cargo clippy -- -D warnings`** must be clean.
- Every new subcommand MUST:
  1. Take an auto-snapshot before mutation.
  2. Honor the global `--dry-run` flag (print shell-equivalent actions).
  3. Refuse to follow symlinks for ownership changes (use `lchown(2)`).
  4. Have at least one smoke-test assertion in `tests/smoke-test.sh`.
- Errors go through `crate::errors::PmError`. No `unwrap()` on user input.
- All file paths are `Path`/`PathBuf`, never `String`, so non-UTF-8 paths work.

## Adding a subcommand

1. Add a variant to `Command` (or `AclCmd`) in [`src/cli.rs`](src/cli.rs).
2. Implement the logic in a new module under `src/` (or extend an existing one).
3. Wire the dispatch in [`src/main.rs`](src/main.rs).
4. Add smoke-test assertions in [`tests/smoke-test.sh`](tests/smoke-test.sh).
5. Document it in [`docs/janitor.1`](docs/janitor.1) and the README command table.
6. Run the full Docker test suite before opening the PR.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(audit): add --no-group filter
fix(acl): preserve mask when restoring default ACL
docs: clarify managed-group naming scheme
```

## Reporting bugs

Please include:

- `janitor --version`
- Kernel and distro (`uname -a`, `/etc/os-release`).
- Exact command and output.
- `janitor --json <cmd>` output if applicable.
- A minimal filesystem reproducer.

## Security issues

Security-sensitive reports should not be filed as public issues. Use GitHub's
"Report a vulnerability" feature under the Security tab.

## License

By contributing, you agree your contributions are licensed under the MIT license.
