# envlock

A tiny envchain-like tool: stores environment variables in the macOS
Keychain and injects them **only** into the environment of a single
child process. ~300 lines of Rust, a 15-minute read.

## Build (on Mac)

```sh
cargo build --release
cp target/release/envlock /usr/local/bin/   # or ~/.local/bin
```

Dependencies: `security-framework` (Apple's official Rust bindings for
Security.framework), `rpassword` (hidden input), `serde_json`.

## Usage

```sh
# Store a value (typed hidden, never touches history/argv)
envlock set ddsc MONGO_URI

# Multiple variables in one namespace
envlock set ddsc MONGO_URI REDIS_URL

# Run a command with secrets in its env — one Keychain prompt per run
envlock run ddsc -- mongosh
envlock run ddsc -- ./backup.sh --out /tmp/dump
envlock run aws ddsc -- terraform apply   # multiple namespaces

# List variable NAMES (values are never printed)
envlock list ddsc

# Remove a variable / a whole namespace
envlock unset ddsc REDIS_URL
envlock delete ddsc
```

## How it works

* All variables of a namespace live in **one** Keychain item (generic
  password, service = `envlock-<ns>`, account = `$USER`) as a single
  JSON object. One item = one access prompt per run (once its ACL is
  set to ask — see Security notes below).
* `run` uses `exec(2)` — the child process *replaces* envlock, so no
  intermediate process holding secrets lingers around.
* Values never pass through argv, stdout, files, or shell history.

## Security notes (the honest ones)

1. **`envlock set` silently trusts itself — you must revoke that by
   hand.** When `set` creates a Keychain item, macOS gives the
   *creating binary* automatic "Always Allow" access with no dialog
   ever shown — this is default Keychain ACL behavior, not something
   envlock asks for. So the first `envlock run` after a `set` will
   read the secret **without prompting**, which looks like the control
   model isn't working. It is — it just started in the wrong state.
   After each `set`, open Keychain Access.app, find `envlock-<ns>`,
   go to **Access Control**, remove envlock from the trusted-apps list,
   and select "Confirm before allowing access." Only then does `run`
   show a real Allow/Always Allow/Deny dialog per invocation.
2. **Never click "Always Allow"** in that dialog once it does appear.
   The entire control model rests on every access requiring your
   confirmation. "Allow" — yes, "Always Allow" — never (it puts you
   right back into the silent-trust state from note 1).
3. The child process sees the secrets in its own environment. Any
   process able to run `env` can read them — that's a property of any
   secret injector, not just this one.
4. Secrets live briefly in envlock's memory between the Keychain read
   and the exec. Memory isn't zeroed (no `zeroize`) — an acceptable
   trade-off for a local machine; add zeroize if you want a more
   paranoid mode.
5. The Keychain item is created with the default ACL. Inspect or
   tighten it in Keychain Access.app (search for `envlock-<ns>`).

## Testing

`cargo test` — serialization/validation logic is covered by tests and
builds on any OS (the Keychain layer is a stub on non-macOS).
