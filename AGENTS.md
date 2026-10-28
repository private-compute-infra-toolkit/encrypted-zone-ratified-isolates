# Agent Guidelines for Encrypted Zone Ratified Isolates

This repository contains trusted Ratified Isolates for Encrypted Zone (EZ). Each isolate directory
is a standalone Bazel module (`MODULE.bazel`, `BUILD.bazel`, and `coverage/thresholds.json`).

## Building and Testing

Before uploading a new Gerrit CL or patchset, always verify that all build, test, and coverage
targets pass inside every modified Ratified Isolate Bazel repository (`cd <isolate_dir>`) using the
`../devkit` wrappers (never bare `bazel`):

```bash
../devkit/build bazel build //...
../devkit/build bazel test --config=run_all_tests //...
../devkit/coverage --lines 90 --thresholds-file coverage/thresholds.json
```

## Testing & Coverage

-   Write verified red-green unit tests covering real public behavioral contracts; never add
    artificial coverage-padding tests, trivial `Display` tests, or generated protobuf field
    assertions. Use real generated `prost` structs over hand-built byte stubs, and ratchet up or
    remove stale per-file exceptions in each crate's `coverage/thresholds.json` via small per-crate
    CLs once coverage exceeds 90%.
-   Assert explicit post-conditions (`assert!` / `assert_eq!`) in every test -- never rely solely on
    `.unwrap()` or permissive `a || b` checks. Wrap async stream reads in `tokio::time::timeout`,
    match `Some(Err(status))` explicitly instead of masking gRPC errors behind EOF panics, and
    verify concurrent multi-request isolation by recording mock calls in `Vec<...>` and pairing each
    request's metadata and payload to its exact output.
-   Place unit tests in `test/` (or `tests/`) directories with all `#[test]` / `#[tokio::test]`
    functions at the top of the file and helper/mock utilities at the bottom. Delete unused helpers,
    configure only the non-default options under test, never branch production code for test
    environments, and run timing-sensitive async tests repeatedly to confirm zero flakes.

## Rust Idioms, API Design & Performance

-   Keep fields, caches, and helpers private (or `pub(crate)`) -- never widen visibility to `pub`
    for tests -- and avoid `new_with_*` constructor proliferation by extending a single `new(...)`
    with `Option<T>`, a config struct, or `..Default::default()` struct update syntax. Name
    entry-consuming methods `pop` or `take` rather than `get`.
-   Eliminate unnecessary `.clone()` allocations on hot paths and streams: move owned buffers with
    `std::mem::take` / `Option::take()`, match `Option` by reference (`if let Some(v) = &opt`), wrap
    shared per-stream metadata and configs in `Arc` outside streaming closures, prefer `HashSet` and
    single-pass `HashMap::insert` over `Vec::contains` or `contains_key` + `insert`, and keep gRPC
    clients cheaply `Clone` via internal `Arc` fields.
-   Group `use` imports at the top of each `.rs` file, extract magic timeouts and strings into
    shared `const` definitions used by both production code and tests, refactor long inline loops
    into helper functions, and prefer vetted crates (`moka` TTLs, standard rate limiters, cloneable
    `mpsc::Sender` channels without `Mutex`) over custom primitives.

## Error Handling, Security & Isolate Boundaries

-   Never panic in Ratified Isolate runtime code (`unwrap`, `expect`, `assert!`, `debug_assert!`, or
    unchecked integer math). Validate wire and manifest inputs fail-fast before mutating state --
    enforcing bounded counts (`1..=MAX`), size caps, ID/slot uniqueness, path-traversal checks
    (rejecting empty, `/`, `.`, `..`), rollback on error, and canonicalization of stripped slices so
    suffix data cannot leak upstream; never interpolate raw caller-chosen tokens or secrets into
    exported traces or logs.
-   Keep open-source code, flags, protos, and comments strictly vendor-neutral -- never reference
    proprietary or internal deployment systems, service names, or infrastructure acronyms, and route
    external and cross-isolate communication through standard Encrypted Zone interfaces. Use private
    `0700` directories instead of world-writable `/dev/shm` `1777` paths when handling sensitive
    temporary files, and scope proto fields to the narrowest service or dependency message
    (`EzServiceSpec`, `EzBackendDependency`, or isolate-specific service messages).

## Comments, Documentation & BUILD.bazel

-   Keep inline comments and docstrings brief (1-2 lines) and strictly limited to non-obvious
    invariants; keep `README.md` docs high-level without internal Rust types (`Arc<RwLock<...>>`,
    crate names); and attach a concrete `TODO(b/...)` bug ID to every `TODO` or temporary flag.
-   Keep `BUILD.bazel` and `MODULE.bazel` minimal and explicit across all isolate workspaces:
    declare external dependencies in `MODULE.bazel` rather than legacy `WORKSPACE` /
    `WORKSPACE.bazel` files, set `testonly = True` on test helper targets (`genrule`, `pkg_files`,
    mock libraries), avoid parenthetical suffixes in target names, prune unused crate dependencies,
    list active `.pem` certs explicitly instead of `glob("**/*.pem")`, and verify feature-gated
    dependency exclusion with `bazel query 'somepath(...)'`.

## CL Hygiene, Scope & Commit Messages

-   Keep CLs small and single-purpose -- split independent features, refactors, and per-crate
    coverage additions into separate CLs. Use concise Conventional Commit titles (`<= 72` chars,
    using valid scopes from `.versionrc.json` when scoped), one blank line after the title,
    `<= 80`-char body lines updated when patchset scope shifts, strictly contiguous footers
    (`Bug: b/...`, `ORIGINAL_AUTHOR=<username>`, `Change-Id: ...`) with zero blank lines between
    trailers, and explicit human requester attribution.
