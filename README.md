# OronBox personal build relay

This dedicated public repository compiles private `dian-sen/OronBox` source on a standard `ubuntu-24.04` runner, uploads only an encrypted signing input, then requests signing on a separate private runner. Publish these files to the public repository's default branch `main`; both workflow files must already exist there. Local preparation does not create secrets or dispatch a run.

## Credentials

Configure these **two secrets only in this public repository**:

| Secret | Fine-grained PAT repository selection | Repository permission |
| --- | --- | --- |
| `ORONBOX_SOURCE_READ_TOKEN` | Only private `dian-sen/OronBox` | Contents: read |
| `PRIVATE_SIGN_DISPATCH_TOKEN` | Only private `dian-sen/OronBox` | Actions: write; no private Contents read/write |

Configure `PUBLIC_RELAY_DISPATCH_TOKEN` **only in private `dian-sen/OronBox`**, selected for public `dian-sen/oronbox-personal-builder`: Contents: write (repository dispatch) and Actions: read (run/artifact verification). GitHub adds Metadata: read automatically. Repository Actions policies must allow the SHA-pinned actions. No signing keys, passwords or persistent signing certificates belong in the public repository.

`build.yml` grants its `GITHUB_TOKEN` only Contents: read for the public checkout; the source PAT is passed solely to private checkout with `persist-credentials: false`. `notify.yml` starts on another runner, checks out only this public repository at the trusted notification workflow SHA, and grants its own token Contents: read and Actions: read. The callback PAT is present only in the final dispatch request step. Private source and build dependencies never execute with it.

## Dispatch contract

`build.yml` accepts **only** `repository_dispatch`, action/type `build-oronbox-personal`. Its run title is exactly `Relay {request_id}`. POST `/repos/dian-sen/oronbox-personal-builder/dispatches` with `event_type` and `client_payload`. The payload has exactly these nine fields, all JSON strings:

| Field | Accepted value |
| --- | --- |
| `request_id` | 32 lowercase hexadecimal characters; fresh per request |
| `source_sha` | 40 lowercase hexadecimal characters; exact private commit |
| `abi` | `arm64-v8a`, `armeabi-v7a`, `x86_64` or `all` |
| `certificate` | One RSA X.509 PEM certificate, RSA >= 2048 bits, not expired |
| `certificate_sha256` | Lowercase SHA-256 hex of the **exact UTF-8 PEM bytes**, including line endings/trailing newline |
| `parent_run_id` | Positive decimal string, at most 20 digits |
| `parent_run_attempt` | Positive decimal string, at most 10 digits |
| `version` | `major.minor.patch` with optional `-prerelease`; matches private pubspec |
| `build_number` | Positive decimal string <= 2100000000; matches private pubspec |

The private request generator retains the one-time RSA private key privately. Relay never receives it. The source is checked out recursively at `source_sha` with `fetch-depth: 0`; `HEAD` must match. By default it must be an ancestor of the already-fetched `origin/main`. Set public repository variable `REQUIRE_SOURCE_ON_MAIN=false` only to permit exact commits outside main; no later unauthenticated fetch occurs. `.fvmrc` must pin Flutter `3.47.9`, and the actual pubspec version/build number must equal the request. The public SDK submodule is `OrPudding/XMS_Wearable_SDK_CleanRoom`, checked recursively at its recorded gitlink.

The toolchain uses JDK 17, setup-dart, FVM `4.3.2`, Flutter `3.47.9` and Rust stable with Android targets. All third-party Actions are pinned to commit SHAs. No Actions source, Gradle, Dart, Flutter or Rust dependency cache is restored or saved. Disk cleanup is guarded for GitHub-hosted runners and removes only unneeded CI preinstalls, system images and NDK versions other than `28.2.13676358`.

Both normal and `ORONBOX_PERSONAL_BUILD=true` Flutter tests cover `test/personal` and `test/core/providers/clean_settings_test.dart`. Compilation uses `PERSONAL_ABI` plus the mapped Flutter `--target-platform`; `all` creates the universal APK. The release intermediate can carry a disposable debug signature: it is **private signing input**, not a claim of an unsigned APK. Persistent private signing and final verification belong in the private workflow.

## Artifact and private consumer contract

The only public artifact is `relay-{request_id}`, retained for **1 day**, containing exactly:

- `payload.cms`: standard OpenSSL CMS DER AuthEnvelopedData, AES-256-GCM, RSA-OAEP with SHA-256 / MGF1-SHA-256. Encryption fails closed if unsupported.
- `callback.json`: exactly `request_id`, `parent_run_id`, `parent_run_attempt`, all strings. It contains no certificate, source details, APK metadata or tokens.

The encrypted plaintext is a ZIP containing exactly `app-release.apk` and `metadata.json`. Metadata has exactly ten keys: `request_id`, `source_sha`, `abi`, `certificate_sha256`, `parent_run_id`, `parent_run_attempt`, `version`, `build_number`, `apk_sha256`, `bytes`. The first eight are request strings, `apk_sha256` is lowercase SHA-256 hex, and `bytes` is a JSON integer. The PEM content is excluded. No plaintext APK, ZIP, source tree or build log is uploaded. Hosted build logs remain public; avoid printing private source or credentials from the source project's build hooks.

The private helper must verify the parent request/attempt binding, expected relay repository/event/main/workflow/success/title and exact artifact name before consumption. Decrypt using the privately retained certificate and key:

```sh
openssl cms -decrypt -binary -inform DER -in payload.cms \
  -recip one-time-certificate.pem -inkey one-time-private-key.pem -out payload.zip
```

Check the OpenSSL exit status **before reading or extracting** `payload.zip`: authentication failure can still leave partial output. Reject duplicates, unexpected ZIP entries, schema changes, mismatching request fields, APK length or SHA-256; only then forward the APK to private signing. Do not restore a private request key from any public artifact. The private request key/certificate is retained privately for one day and expires with that temporary material.

`notify.yml` reacts only to successful `Encrypted personal APK build` runs from `repository_dispatch`, `main`, and this same repository. It re-reads authoritative run metadata, downloads the unique artifact from exactly that run using its own Actions-read token, never extracts or executes it, validates the three callback strings, and correlates the request with `display_title` and artifact name. It then sends exactly:

```json
{"ref":"main","inputs":{"parent_run_id":"<decimal>","parent_run_attempt":"<decimal>","request_id":"<32hex>","relay_run_id":"<decimal>"}}
```

to `POST /repos/dian-sen/OronBox/actions/workflows/personal-relay-sign.yml/dispatches` with API version `2022-11-28`; success is HTTP 204. The private workflow treats these inputs as untrusted, authenticates the parent/request binding, and independently verifies/decrypts the artifact. Public callback delivery does not authorize signing by itself. There is currently no consumption marker or duplicate-dispatch suppression: signing the same verified artifact again with the same signing certificate preserves the same trusted content. A consumption marker can be added later. Use a fresh request ID for a new build; artifacts are not overwritten.

## Local checks

Requires Python 3.9+, OpenSSL 3.x with CMS GCM and RSA-OAEP, Bash and actionlint. Tests are offline and use disposable test keys:

```sh
actionlint .github/workflows/build.yml .github/workflows/notify.yml
bash -n scripts/ci.sh
python3 -c 'import ast,pathlib; [ast.parse(p.read_text()) for p in pathlib.Path(".").rglob("*.py")]'
python3 -m unittest discover -s tests -v
```

No full Flutter build or GitHub dispatch is part of these checks. Initial repository publication, Secrets configuration and end-to-end validation are separate deployment steps.
