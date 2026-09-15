# ihc (i-hate-configuring)

A headless, proof-first maintenance loop for a flake-based NixOS or nix-darwin system plus
home-manager: bump flake inputs one at a time, prove the result (build, dry-activate, diff)
before ever switching, let an already-logged-in agent CLI fix whatever breaks, activate under a
safety policy, roll back on a health regression, and write an evidence bundle for every run. It
drives whichever of `claude`, `opencode`, or `codex` is both on `PATH` and actually answers a
login probe (tried in that order). There is no API-key path — `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, and related provider variables are stripped from the agent's environment
before it runs, so only a subscription login gets used.

## How it decides what matters

`ihc adopt` puts your live configuration trees under git (idempotent). Two documents in your
config repo drive everything else; neither is hand-written — `ihc docs regen` lets an agent mine
them from your actual configuration:

- **GOALS.md** — ranked priorities the configuration proves (each with a `path:line` citation),
  "Invariants" (things the agent must never change), and "Non-goals".
- **MAINTENANCE.md** — a methodology section, findings, a risk-tagged work queue (`- [ ] (risk:
  low|medium|high) <task> — <evidence path:line>`), and three machine-readable sections:

  ```
  ## Guarded units

  - docker.service
  - `postgresql.service`

  ## Health probes

  - ssh: systemctl is-active sshd
  - `web`: `curl -sf localhost:8080/health`

  ## Busy checks

  - build: pgrep -x make
  ```

  Each **Guarded units** line is a unit name (backticks optional, stripped); restarting one
  forces `boot`-mode activation instead of `switch`. Each **Health probes** / **Busy checks**
  line is `name: command` (backticks optional): a health probe must exit 0 after an activation,
  and a busy check that exits 0 means someone is mid-task, so `ihc` defers a switch to the next
  boot. `ihc facts` folds all three into `guarded_units`, `host_rules.health_probes`, and
  `host_rules.busy_checks`.

Every claim needs a `path:line` citation to a real, non-blank line — `ihc docs check` rejects a
document with a dead one, and `ihc docs regen` reverts its own change if the result fails that
check. `ihc run` regenerates automatically, but only when a fingerprint of the mined facts
(inputs, enabled options, kernel/hardware settings, drift, secrets, deprecated options) changed
since the last regeneration; `ihc docs regen` always regenerates. Docs live in `IHC_DOCS_DIR`
(default: the flake dir), not in this repository — they belong in yours (`IHC_SEED_DOCS` seeds
them from a template on first `ihc adopt`).

## Install

Add the flake input (`inputs.ihc.url = "github:<owner>/i-hate-configuring";`), then import a
module. As a home-manager unit (NixOS, nix-darwin, or home-manager-only):

```nix
{
  imports = [ inputs.ihc.homeModules.default ];
  services.ihc.enable = true;
  services.ihc.onCalendar = "*-*-* 03:00:00";        # default
  services.ihc.extraArgs = [ "--switch" "auto" "--improve" ];
  services.ihc.environment = { IHC_FLAKE = "/etc/nixos"; };
  services.ihc.extraPath = [ ];                       # extra packages on the unit's PATH
}
```

Or as a NixOS module (a system unit, running as a specific user):

```nix
{
  imports = [ inputs.ihc.nixosModules.default ];
  services.ihc.enable = true;
  services.ihc.user = "you";   # required
}
```

```console
$ nix run github:<owner>/i-hate-configuring -- status   # one-off, no checkout
$ nix run . -- status                                    # from a local checkout
$ uv run ihc status                                       # from a repo checkout
```

Both modules also expose `package` and `randomizedDelay` (default `20m`).

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `IHC_FLAKE` | flake directory | autodetected (`/etc/nixos`, `~/.config/nix-darwin`, `~/.config/home-manager`, ...) |
| `IHC_HM_ATTR` | `homeConfigurations` attribute name | picked from the flake (`user@host`, then `user`, then first) |
| `IHC_DOCS_DIR` | where `GOALS.md` / `MAINTENANCE.md` live | the flake dir |
| `IHC_STATE_DIR` | evidence bundles, history, pending decisions, docs fingerprint | `~/.local/state/ihc` |
| `IHC_SEED_DOCS` | dir to copy `GOALS.md`/`MAINTENANCE.md` from on `ihc adopt` if missing | (unset) |
| `IHC_AGENTS` | comma-separated agent try-order | `claude,opencode,codex` |
| `IHC_AGENT_TIMEOUT` | seconds before an agent invocation is killed | `2700` |
| `IHC_PROBE_TIMEOUT` | seconds allowed for the one-line login probe per agent CLI | `180` |
| `IHC_RUN_DEADLINE` | seconds after which a run starts no new bump/fix work | `21600` |
| `IHC_MIN_STORE_FREE_GIB` | `/nix/store` free-space floor before builds are refused | `10` |
| `IHC_GUARDED_UNITS` | comma-separated unit names added to the guarded-units list | (unset) |
| `IHC_NO_DESKTOP` | set to skip desktop notifications (still logged + printed to stderr) | (unset) |
| `IHC_CVE_DAYS` | days between nightly CVE scans; `0` disables them | `7` |
| `IHC_CVE_TIMEOUT` | seconds before a CVE scan is killed | `2400` |

## Verbs

| Verb | Flags | Does |
|---|---|---|
| `facts` | `--json`, `--static` | mine the system; `--static` skips runtime probes (including drift) |
| `status` | | drift, last run, blocked inputs, pending decisions |
| `adopt` | | put the live config trees under git (idempotent) |
| `check` | `--target all\|system\|hm`, `--eval-only`, `--force` | prove the current tree: build, dry-activate, diff (never switches) |
| `bump` | `[inputs...]`, `--max-attempts N` | update inputs one at a time; fix breakage with an agent; revert what can't be fixed |
| `fix` | `--target`, `--task TEXT`, `--max-attempts N`, `--eval-only` | let an agent repair the failing build (or do `--task`), then prove it |
| `switch` | `--target`, `--mode auto\|switch\|boot`, `--force`, `--no-review` | prove, then activate with the safety policy (rollback on health regression) |
| `review` | `--target hm\, `--activate` (re-activate home-manager if the review fixed something; never by default) |system`, `--since "YYYY-MM-DD HH:MM:SS"` | review an activation that already happened: what changed, is it healthy, fix if not |
| `run` | `--switch auto\|never\|hm-only\|system-only`, `--no-bump`, `--inputs`, `--max-attempts N`, `--improve`, `--improve-risk low\|medium\|high` | the scheduled pipeline |
| `docs check\|regen` | `--dir PATH` | check `GOALS.md`/`MAINTENANCE.md` citations, or regenerate them with an agent (unconditionally) |
| `notify` | `TITLE [BODY]`, `-u/--urgency`, `-q/--quiet` | send a desktop notification (and log it) |
| `pending list\|resolve` | `[ID]` | decisions that need you |
| `security` | `--json`, `--fix`, `--cve`, `--max-attempts N` | what grants privilege, exposes a credential, or is known-vulnerable; `--fix` pins unhashed remote fetches (the one class ihc will hand to an agent, and only when you ask), `--cve` for a vulnix closure scan |
| `mcp` | | serve a subset of the verbs over MCP stdio |

`--flake DIR` is a global flag on every verb (default: `$IHC_FLAKE` or autodetect).

## The `run` pipeline, in order

1. Take the run lock (one `ihc` process at a time) and mine facts.
2. Store/`/boot` gates: short `/nix/store` drops every proof to eval-only and disables
   activation; no passwordless sudo or a short `/boot` (after a stale-entry prune) disables
   *system* activation only — home-manager and proofs still run.
3. Adopt the live config trees into git, then commit any drift a human made directly in them.
4. Bump flake inputs one at a time (`nixpkgs` first); each break runs the fix loop and, failing
   that, reverts the lock change and any agent edits and records the input as blocked.
5. Optionally (`--improve`) take one item off the `MAINTENANCE.md` queue through the fix loop.
6. A final `check` — the last bump's verdict is reused when nothing invalidated it; otherwise
   (always when `--improve` changed something) a fresh proof runs, with a fix-loop attempt on
   failure.
7. Activate per the switch policy (home-manager first, then system). After a successful switch,
   an agent reviews it — what changed, unit/journal state, program checks — fixes a real
   regression, re-proves, and re-activates home-manager (a system-side fix is proved but left
   for the next run to activate).
8. Run the security report against the final tree, write it to `<run>/security.json`, and raise one
   pending decision if the set of high-severity findings changed. The run never edits anything
   security-related — not even the auto-remediable class — so a rolling channel it flagged cannot be
   pinned behind your back. A CVE scan runs here at most every `IHC_CVE_DAYS` days.
9. Record the system generation count; regenerate `GOALS.md`/`MAINTENANCE.md` if the mined-facts
   fingerprint changed since the last regeneration; write the report, append to history
   (telemetry), and send a notification.

## When you are needed

The run never asks. Whenever something needs you, it writes a pending decision (`ihc pending list`) and
sends a **critical** (persistent) desktop notification titled `ACTION NEEDED — …` with the next step:

- an agent CLI login is broken (`auth`);
- an agent fix or a post-activation fix touched a protected pattern (`policy`);
- the post-activation review found a regression the agent could not fix (`review`);
- an input has been blocked three runs in a row (`bump`);
- the store or `/boot` is too full to build or activate.

"Reboot when convenient" (system activated in boot mode) is a normal-urgency line, not a decision.
Resolve with `ihc pending resolve <id>` after you acted.

## Safety model

- **Store pressure**: `/nix/store` free space below `IHC_MIN_STORE_FREE_GIB` (default 10 GiB)
  drops every proof to `nix eval` only — options and packages still get verified, but nothing is
  downloaded, built, or activated. `/boot` free space below 2x the current kernel+initrd size
  blocks *system* activation only, after a stale boot-entry prune is tried first.
- **switch vs. boot**: activation mode is `boot` (applies at next reboot, current session
  untouched) instead of `switch` when the kernel, initrd, kernel modules, or a hardcoded GPU
  driver binary changed, or when dry-activate says a unit in the mined guarded-units list (your
  `## Guarded units` bullets plus `IHC_GUARDED_UNITS`) — or one matching a built-in set of
  unit-name patterns covering display managers, container runtimes, databases, and audio
  services (see `GUARDED_UNIT_PATTERNS` in `facts.py`) — would restart, or any `## Busy checks`
  command exits 0.
- **Health regression → rollback**: a snapshot (failed units, active units, listening ports,
  plus every `## Health probes` command, system and user scope) is taken before and after a
  system `switch`. A new failure, a unit going inactive, a port disappearing, or a probe flipping
  from passing to failing triggers an automatic rollback (`nix-env --rollback` +
  `switch-to-configuration switch`), recorded in `health.json`. There's no rollback path for
  home-manager; a regression there goes through the post-activation review instead. Fewer than 2
  kept system generations triggers a separate warning notification (no rollback target).
- **Diff policy**: every agent edit is checked against a hardcoded pattern/file denylist in
  `agent.py` — `stateVersion`, filesystem definitions, bootloader settings, swap devices, user
  accounts, `sops` (secrets wiring), sudo policy, ssh being turned off, nix's trusted-user
  settings, a commit-pinned input URL, `hardware-configuration.nix`, and secret-looking files,
  plus a few patterns hardcoded for one particular kernel/audio setup (read
  `FORBIDDEN_PATTERNS` for the exact list, or add your own — none of it is configurable from
  GOALS.md). A violation reverts the whole diff and writes a pending decision.
- **Pending decisions**: written instead of blocking, for a policy violation or when no agent
  CLI is logged in — `ihc pending list`, then `ihc pending resolve <id>` once you've handled it
  by hand.
- **Never**: `git push`, garbage collection (`nix-collect-garbage`, `nh clean`), or a reboot.

## Ask

`ihc ask "the calendar popup in my bar never updates the day"` — describe a problem in your own
words. The agent gets the mined system facts and both config trees, reads the generated files and
the journals to find the root cause, and fixes it with the smallest change it can. The harness
then proves the tree (eval, build), rejects policy breaks, commits on success, and reverts on
failure. The answer is one of three honest verdicts: `FIXED` (what and why, committed, applied at
the next activation), `BLOCKED` (cause found, why it cannot be fixed from the config), or
`UNSOLVED` (what was checked and ruled out). Also available as the `ask` MCP tool.

## Heavy builds

A bump of `nixpkgs` rebuilds from source every package no configured binary cache has (CUDA
variants, packages pinned to a commit, overrides). `ihc` measures that cost instead of paying it
every night: the `-L` build log it already captures gives per-derivation build time, kept in
`~/.local/state/ihc/build-ledger.json`. Before it proves a bump it runs `nix build --dry-run`;
when the local builds that bump forces add up to more than `IHC_HEAVY_MINUTES` (20) of known
cost, the bump is deferred, the lock restored, the notification and `ihc status` name the package
and its cost, and MAINTENANCE.md's queue gets an item for the agent: give the package its own
slow-moving input and take it from there, so `nixpkgs` moves daily while ihc bumps the slow input
every `IHC_HEAVY_DAYS` (7) days. Any input is allowed a heavy bump once its deferral is that old;
`ihc run --allow-heavy` / `ihc bump --allow-heavy` force one now.

## Drift

`ihc` commits whatever a human changed directly in the config repos before it starts work and
after every change it makes itself, so every diff it produces is isolated and revertible without
touching what you did by hand. If `flake.lock` is part of that drift (a `nix flake update` you ran,
or a bump a crashed run left behind), the commit message and the run notes name the inputs that moved.
Separately, `ihc facts` / `ihc status` report *imperative* drift
the configuration doesn't manage: regular `/etc` files where the current generation expects a
store symlink, home-manager backup files (`*.ihc-bak` and whatever `backupFileExtension` your
config sets) left behind by a conflicting activation, and packages sitting in the user's
`nix-env` profile outside the configuration. `ihc docs regen` lists these in MAINTENANCE.md's
findings and queues adopting or removing them. A local (`path:`/`git+file:`) input whose on-disk
content no longer matches `flake.lock` is detected from the resulting eval/build error and
re-locked automatically.

## Aesthetics

If the configuration has a theming source of truth — stylix, base16 references, nix-colors,
catppuccin, or a profile registry (an attribute set of profiles with an `image`) — `ihc`
treats a consistent look as a correctness property:

- `ihc aesthetics` reports the sources found, the palette (from the generation's
  `.config/stylix/palette.json` or the config's `colorScheme`/`base16Scheme`), every profile
  (missing fields, missing image), and every enabled surface: terminals, shells, tmux,
  editors, window managers, bars, launchers, notifiers, lock screens, GTK/Qt, browser, cursor,
  fonts. For each surface it says whether the source config derives from the palette
  (`themed`/`hardcoded`) and whether the *generated* file in the active or a built generation
  contains colours outside the palette (`consistent`/`drift`/`not_generated`).
- `ihc aesthetics --fix` hands the drift to the agent (make the surface derive from the
  palette in the config trees, never by editing generated files) and proves the result.
- The post-activation review of home-manager includes the same scan of the new generation.
- Extend the surface table per host in MAINTENANCE.md: `## Aesthetic surfaces` with
  `- <label>: <path relative to $HOME>` bullets.

## Security

`ihc security` answers one question: what in this configuration grants privilege, exposes a credential,
or ships a package that is known to be vulnerable?

It has two independent sources of evidence and says which one each finding came from.

- **Your files.** Every finding that comes from a grep carries a real `path:line` in your config trees,
  and comment-stripped: a commented-out `networking.firewall.enable = false;` is not a finding.
- **The effective values.** One batched `nix eval` reads what your configuration actually resolves to,
  including nixpkgs' own defaults. This is the half that matters: on a stock NixOS host
  `services.openssh.settings.PasswordAuthentication` is `true` because that is nixpkgs' default, and the
  string appears nowhere in your files. A grep-only tool reports nothing there.
  If that evaluation fails (a `path:` input whose checkout moved, a broken module), ihc prints the real
  nix error and marks those checks **unknown**. It never shows you a shorter list and calls it clean.

What it checks: password and root ssh login, the firewall being off, passwordless sudo for wheel,
`nix trusted-users` beyond root, `require-sigs` off, `accept-flake-config` on, users in a group that is
root-equivalent on this machine (docker/lxd/incus/libvirt, only when that daemon is actually enabled),
inline account passwords, autologin, `permittedInsecurePackages` and blanket insecure overrides,
remote fetches with no hash, credential literals in files that are part of the built configuration
(they end up world-readable in `/nix/store`) versus in files nothing imports, a home-manager ssh
client that has turned off host-key checking or turned on agent forwarding, and how old the nixpkgs
you pin and run actually is (medium past 45 days, high past 180; silent below that, so a host whose
nightly is working never sees it).

### What gets fixed and what does not

Exactly one class of finding is ever handed to an agent, by `ihc security --fix` and by the nightly:

- an unhashed `builtins.fetchTarball` / `fetchurl` / `fetchGit`, pinned to the content it already
  resolves to today, so a rebuild cannot silently execute different code. It runs under the normal
  proof harness (evaluate, build, dry-activate, closure diff) and is revertible; if the fix does not
  prove, the harness reverts it and the finding stays reported.

Everything else — ssh, the firewall, sudo, users, groups, secrets wiring, an insecure-package permit —
is reported and raises a pending decision, and is never edited for you. Those are the changes that can
lock you out of your own machine or quietly undo something you meant, so they stay yours to make.

Three gates stand between a finding and an unattended fix, because a rolling fetch is often deliberate
(a NUR-style overlay, a channel tarball):

1. **Never on first sight.** A new finding is reported and held for one run. You get a notification
   naming it before anything is touched.
2. **Exceptions win.** Anything listed under `## Security exceptions` in MAINTENANCE.md is neither
   fixed nor reported nor escalated. That is where a deliberately rolling fetch goes.
3. **A failed fix is not retried.** If the proof fails, the harness reverts, and ihc does not try that
   finding again for 30 days (`IHC_SECURITY_BACKOFF_DAYS`); the finding stays reported meanwhile. The
   grace period is `IHC_SECURITY_GRACE_DAYS`, one run by default.

The agent only ever sees findings the check table marks auto, never a file the agent policy protects,
and never one you have accepted.

`permittedInsecurePackages` entries are reported, one per entry with the line that permits it, and
never deleted for you. Whether an entry is still needed is not something ihc can know: nothing here
compares it against nixpkgs or the lock, and deleting a live one stops the whole tree evaluating.

Everything else is a decision, not a defect. Turning the firewall on drops every port you did not
enumerate. Disabling password auth without a working key is a permanent lockout. Removing someone from
the docker group breaks their containers. So ihc reports those, and raises **one** pending decision
listing the high-severity ones (`ihc pending list`). It does not raise it again unless the set changes.

### Accepting a finding

Record what you have decided to live with in `MAINTENANCE.md`:

    ## Security exceptions

    - sudo_passwordless_wheel: single-user laptop, full-disk encrypted
    - unpinned_remote_fetch: a NUR-style overlay I float on purpose

Ids come from `ihc security --json`. An accepted finding still shows up, marked accepted with your
reason — it just stops counting, stops escalating, and is never handed to the agent.

### CVE scanning

`ihc security --cve` scans the runtime closure for published vulnerabilities. It tries scanners in
order and reports which one answered:

1. [vulnxscan](https://github.com/tiiuae/sbomnix) (from `sbomnix`), which queries live OSV and grype
   data. This is the default because it works today.
2. [vulnix](https://github.com/nix-community/vulnix), kept as a fallback. Be aware that vulnix
   downloads NIST's legacy NVD JSON feeds, and NIST has retired them: those URLs now answer 401/404,
   so on a cold cache vulnix cannot build a database at all. ihc reports that failure with the real
   error rather than an empty list.

Either way ihc runs the scanner as a subprocess — from `PATH`, else from your own locked nixpkgs via
`nix shell --inputs-from`, else from the registry. The nightly run scans at most every `IHC_CVE_DAYS`
days (default 7) and skips it when the store is short on space or the run is out of time. It is not
nightly on purpose: a full closure scan takes many minutes and needs the network, so on a laptop that
wakes without one it simply fails, and a failure is reported as a failure.

Read the result as a triage order, not a verdict, and ihc says so in every report: a scanner matches
on package name and version, so a package that merely shares a name with something else inherits its
CVEs; a CVE with no score is reported as unscored, never as 0.0; and it scans what was built, not
necessarily what is running — ihc lists the exact store paths it scanned. It also reports how many
paths in the closure still have a deriver: if derivations have been garbage-collected, a scanner skips
those paths silently, and a "clean" scan would be a lie.

## Hygiene

`ihc` keeps its own footprint small (evidence bundles: newest 30 kept, and only the newest 3
keep the built system/home out-links that pin closures) and mines the rest for the docs:
generation retention, unused flake inputs, commit-pinned inputs, local inputs whose content
changed, configuration assets outside git, stale backup files, dead configuration files, and
`/boot` pressure (it re-installs the bootloader to drop entries of deleted generations). It
never garbage-collects, deletes profiles, or touches user data; those become queue items
with a recommended command. MAINTENANCE.md's "System hygiene" section is the method the
agent maintains for the host.

## Evidence bundles

Every run writes `~/.local/state/ihc/runs/<id>/` (override the base with `IHC_STATE_DIR`),
pruned to the most recent 30:

- `report.md`, `report.json` — the verdict and a table of every step; `notes.log` — narration.

While a run works, every note and every step start/finish is printed to stderr (`ihc: [09] build-system ...`),
so an interactive run and the journal both show progress; `ihc -v <verb>` (or `IHC_VERBOSE=1`) streams the full
command output too. The run directory keeps it either way.
- `NN-name.{cmd,out,err,exit}` — one set per command run.
- `system-diff.txt`, `hm-diff.txt` — closure diffs; `facts.json` — the mined facts for the run.
- `fix-N.diff`, `rejected-N.diff`, `review-fix.diff`, `review-rejected.diff` — agent diffs,
  applied or reverted; `prompt-N.md` — every prompt sent to an agent.
- `health.json` — before/after health snapshot and regressions, written on a system switch.
- `post-<kind>.md` — post-activation evidence (touched units, health probes, failed units,
  journal, closure diff) for the review step.

## MCP

`ihc mcp` serves `status`, `facts`, `check`, `bump`, `fix`, and `docs_check` over stdio
(newline-delimited JSON-RPC 2.0); `switch` and `review` are CLI-only for now. Register it with
Claude Code: `claude mcp add ihc -- ihc mcp`.

## Exit codes and development

`0` ok, `1` a proof, activation, or preflight step failed, `75` another `ihc` run holds the lock
(a concurrent run, not a failure).

```console
$ uv run python -m unittest discover -s tests
$ nix build
$ nix flake check
```

nix-darwin is implemented via the same code paths (`darwinConfigurations.<host>.system`,
`activate`) but is untested, as is rollback after a real (not simulated) health regression.
