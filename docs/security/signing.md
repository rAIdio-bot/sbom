# Binary Hash Publication

## What is published

Every release of `raidio-bot.exe` is hashed and the hash committed to
this repository at `releases/<tag>/`. Two formats:

- `hashes.json` — machine-readable: tag, AppID, depot ID, raw BuildID,
  `files[]` with filename, sha256, size, and a UTC timestamp.
- `SHA256SUMS` — plain text, one line per file: `<sha256>  *<filename>`.
  Compatible with `sha256sum -c`.

Both files ship alongside the CycloneDX SBOM
(`rAIdio.bot-<tag>.cdx.json`) in the same directory and the same git
commit, so a researcher fetches the SBOM and the hashes from a single
URL.

## What the hashes prove

The bytes a user has on disk match the bytes that were committed to
this public repository at release time. Verify with:

```powershell
$tag = 'RC1-UAT1.16'   # change to your installed RC (see About dialog)
$exe = Join-Path ${env:ProgramFiles(x86)} 'Steam\steamapps\common\rAIdio.bot\raidio-bot.exe'
$local     = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
$published = (Invoke-RestMethod "https://raw.githubusercontent.com/rAIdio-bot/sbom/main/releases/$tag/SHA256SUMS").Split(' ')[0]
if ($local -eq $published) { 'OK — matches release' } else { "MISMATCH — local $local vs published $published" }
```

A `MISMATCH` indicates the binary on disk is not the released build —
the install is corrupted, an update is in flight, or the binary was
replaced. Re-install from Steam or report via
[SECURITY.md](../../SECURITY.md).

## What the hashes do not prove

A sha256 hosted on a repository proves only that a published-and-
installed pair match; it does not prove the publisher is the
legitimate vendor. Defense against a hypothetical repository
compromise is the public audit log on GitHub commits and the public
attention of users actually checking.

## See also

- [transparency.md](./transparency.md) — full list of published artefacts.
- [SECURITY.md](../../SECURITY.md) — researcher contact and scope.
