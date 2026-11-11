# Offline evidence bundles

Status: implementation design for public core issue 7; reviewed against the contributor and
security boundaries before code changes.

## Boundary and model

`acp evidence import` is an explicit host operation. It accepts a local JSON manifest and local
regular files, verifies their declared SHA-256 values, then copies them into a separate `.acp-evidence/<opaque namespace>/<bundle ID>` store outside
the repository's ACP state directory. With the default layout it is beside `~/.acp`, never inside
that control-plane tree. A custom state beneath a repository or ACP worker checkout moves the
evidence store beyond the outermost enclosing checkout; unsafe ancestor relationships with no
disjoint location are refused before anything is created. The namespace hashes both canonical
daemon repository and state paths; worker-facing
paths never include the state directory itself, its basename, or `acp.sock`. Private store directories
are owner-only, and installed files/directories are read-only. Core never fetches a URL and never changes a worker sandbox or network
permission. Imported text is untrusted reference data, never control-plane instructions.

Each source records a canonical `https` URL, retrieval timestamp, optional source date, relative
file name, SHA-256, and provenance (`installed_version` or `current_documentation`). A bundle ID is
the SHA-256 of ACP's compact canonical manifest representation, with sources sorted by name. The
ID therefore binds metadata and content hashes; updating any source or provenance creates a
different immutable bundle. Caller-chosen IDs are not accepted during import.

## Bounds and safe publication

The input manifest is at most 64 KiB, with at most 64 sources, 8 MiB per file and 32 MiB total.
Names and metadata fields have explicit byte limits. Relative names must contain only normal UTF-8
path components: no absolute paths, `.`/`..`, empty components, NULs, or duplicate names. Sources
must also have distinct canonical URLs. The importer walks from a held directory descriptor using
descriptor-relative, no-follow, nonblocking opens; it rejects non-regular files after `fstat`, then
hashes and bounds the bytes actually copied into a dedicated `files/` directory. This keeps
ACP's `manifest.json` namespace separate and permits a source itself to be named `manifest.json`.

Import is staged in the resolved ACP-owned external directory, with restrictive permissions. ACP serializes
the installed manifest compactly and verifies that the exact output is within the same 64 KiB load
limit before publishing it by rename. Existing IDs are loaded and revalidated rather than
overwritten. Loading uses the same descriptor boundary and rechecks every stored file's actual byte
count and digest. It also enumerates the bundle root, payload root, and every manifest-implied
nested directory through held descriptors, requiring the exact declared child set and rejecting
undeclared files or directories. Later tampering therefore fails closed. A successful import is
consequently guaranteed to remain loadable unless storage changes.

## Task reference and worker presentation

A task may contain one `evidence` reference: the immutable bundle ID plus its ACP-owned directory.
The socket validates the bundle immediately before creating a run and stores the reference in the
durable `run.created` task, so restart/replay retains exactly the same identity. Worker prompts list
the bundle ID, network state as `unverified_provider_controlled`, each source's provenance, date,
URL, hash, and read-only local path. An independent 8 KiB allowance preserves identity, capability
and the manifest link across all prompt routes; omitted source entries are counted explicitly.
They do not inline source text and state that the snapshots are
untrusted data. Supplying evidence never claims worker internet access.

Read-only POSIX modes and a non-writing role label are not the worker write boundary: providers run
as the same OS user. Before disclosing a bundle path, process admission checks the recorded
provider/role and the concrete checked argv on every fresh, resume, automatic-check and
restart-reissued route. A sandboxed writer or verifier keeps its existing worktree-only write
profile; an ordinary non-writing Codex process must positively carry its provider-enforced
`read-only` sandbox mode (including resume). The current Claude non-writing profile has no verified
filesystem read-only contract, so an evidence attachment to that profile is refused before
provider preflight or launch with a remedy to use a supported confined Codex worker or remove the
attachment. Ordinary tasks remain supported and no sandbox, tool, or directory permission is
widened. Catalog overrides cannot bypass this runtime check.

An evidence update is another import and another task reference. It does not mutate an old bundle
or an active attempt. For a resume, the actor resolves the effective run from the agent, rejects a
mismatched claimed run, and atomically refuses the new ID while an attempt or its preparation is
active. Before starting an idle continuation it appends `task.evidence_updated`; replay, retries,
and replacements therefore reconstruct the accepted reference from the authoritative task. Team,
checks, history, gates, and integration approval are unchanged.

## Compatibility and acceptance

Tasks without evidence retain their wire shape and behavior. References from unpublished drafts
that stored evidence beneath the daemon state directory are refused before prompt navigation or
provider admission; the host must reimport and explicitly attach the new reference. No existing
history is rewritten or silently migrated. Public CLI/socket support covers
import and inspection plus attaching an ID to new delegated/lead tasks. Tests use local fixtures
only and cover multiple documents, metadata/provenance distinction, traversal/symlinks, limits,
hash changes, tampering, immutable reuse, prompt navigation, and task serialization/replay. Source
publication is separate. Acceptance in the optional private Mac client remains pending.
