# Code Signing & Hash Publication

## Threat model

The defended-against attack: a user installs a repackaged `raidio-bot.exe`
that has been modified — most plausibly to add a cryptocurrency miner or
exfiltrate user-trained voices — and believes it to be the genuine
Creative Mayhem build. Distribution channels for such a repackage include
torrents, third-party "free download" sites, and SEO-poisoned mirrors.

Two independent mechanisms address this. Phase 1 is live today; Phase 2
is deferred behind hardware procurement.

## Phase 1 — GitHub-hosted hash publication (LIVE)

Every Steam release publishes the sha256 of the shipped exe to
[`github.com/rAIdio-bot/sbom`](https://github.com/rAIdio-bot/sbom)
under `releases/<tag>/`. Two artefacts:

- `hashes.json` — machine-readable: tag, AppID, depot ID, raw BuildID,
  `files[]` with filename + sha256 + size, generated_at timestamp.
- `SHA256SUMS` — Linux-distro-style plain text, one line per file:
  `<sha256>  *<filename>`. Compatible with `sha256sum -c`.

Both are committed alongside the existing `rAIdio.bot-<tag>.cdx.json`
SBOM. Single commit on the public repo means a user has *one* URL to
trust per release.

### How it's wired

`steam\push.ps1` — Step 4 ("Publish SBOM + hashes"). Runs after
`steamcmd` succeeds; hashes the staged exe at
`D:\staging\rAIdio.bot\app\raidio-bot.exe` (the bytes that just went
into Depot 4600001) and writes both files into the sbom repo. The
operator commits and pushes in a single `git push` with the SBOM.

### What it covers

A user can independently confirm the bytes they have on disk match the
bytes published by Creative Mayhem at release time:

```powershell
(Get-FileHash 'C:\Program Files (x86)\Steam\steamapps\common\rAIdio.bot\raidio-bot.exe' -Algorithm SHA256).Hash.ToLower()
```

Compared against:
`https://raw.githubusercontent.com/rAIdio-bot/sbom/main/releases/<tag>/SHA256SUMS`

If the values differ, the binary on disk is not the released build —
either the install is corrupted, an update is in flight, or the binary
has been replaced.

### What it does *not* cover

- **No cryptographic identity.** Anyone can compute a sha256 of any file
  and host it on a GitHub repo they control. The hash file proves only
  that a published-and-installed pair match — not that the publisher is
  the legitimate vendor. Defense against that is Phase 2 (Authenticode).
- **No SmartScreen / Defender warning suppression.** Windows still flags
  unsigned binaries. Phase 2 fixes this.
- **No protection against compromise of the rAIdio-bot org GitHub
  account.** An attacker with push access to the sbom repo could rewrite
  hashes alongside a malicious binary. GitHub commit history (audit log,
  immutable releases) is the substitute defense; signed-commits-only on
  the sbom repo is a planned hardening step.

## Phase 2 — Authenticode signing with HSM (DEFERRED)

When hardware is acquired and operationalised, the build pipeline will
additionally sign `raidio-bot.exe` with a hardware-backed EV code-signing
certificate. This adds:

- Windows SmartScreen reputation accrual.
- An identifiable "Creative Mayhem UG" publisher in the file properties.
- Cryptographic chain-of-custody from a public CA root to the binary.

### Deferred procurement

- **HSM**: YubiHSM 2 or equivalent. Required for storing the EV cert
  private key.
- **EV code-signing certificate**: from DigiCert, Sectigo, or equivalent.
  Multi-day vetting; ~€300–500/yr for a 1-year EV cert. Must be issued
  to "Creative Mayhem UG" matching the legal entity on file.
- **Signing agent**: a build host with no inbound internet exposure, not
  reachable from developer workstations, with the HSM physically
  attached. Outbound limited to the timestamp authority.

### Build-pipeline integration plan

`build.ps1` adds a gated `signtool sign /v /sha1 <thumbprint> /fd
sha256 /tr http://timestamp.digicert.com /td sha256` step that runs
when `RAIDIO_SIGN_HSM=1` is set in the environment. Default off so
developer builds remain unsigned.

### Key rotation

- **Default cadence**: annual. Cert renewal triggers a key rotation —
  the new cert generates a new key in the HSM, the previous key is
  retained inside the HSM for verification of historical builds only,
  never for new signing.
- **On suspected exposure**: immediate rotation. Notify users via the
  same `releases/` channel (a `revocations.md` note beside the affected
  RC's `hashes.json`). Re-sign the latest unaffected RC with the new
  cert and ship as a hotfix RC.
- **Recovery**: HSM is offline-air-gap-backed-up to a sealed envelope
  in the founder's bank deposit box. The recovery procedure assumes
  total loss of the active HSM and re-issuance of the EV cert from the
  CA.

### Identity continuity through Phase 1 → Phase 2

The sha256 hashes published in Phase 1 will continue to be published
under Phase 2. They remain a valid independent verification path —
Authenticode adds a second mechanism, doesn't replace the first.

## Per-release operator checklist

Already enforced by `push.ps1`; documented here for audit:

- [ ] HEAD is tagged with the RC tag.
- [ ] `prepare_depots.ps1` ran and `D:\staging\rAIdio.bot\app\raidio-bot.exe`
      exists.
- [ ] `push.ps1` completed with `[4/4] Publish SBOM + hashes` printed.
- [ ] `git status` in `C:\dev2\sbom` shows `releases/<tag>/` with three
      new files: `*.cdx.json`, `hashes.json`, `SHA256SUMS`.
- [ ] Single `git commit` and `git push` lands all three.
- [ ] Verify-command sanity check from a different machine succeeds
      against the just-published file.

## See also

- [docs/security/transparency.md](./transparency.md) — pointer to all
  publicly-published security artefacts.
- [SECURITY.md](../../SECURITY.md) — researcher contact and scope.
- `steam/push.ps1` — implementation of Phase 1.
- `RELEASE.md` §8 — full Steam push flow.
