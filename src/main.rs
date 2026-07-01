//! envlock — store env vars in the macOS Keychain and inject them
//! only into the environment of a single child process.
//!
//!   envlock set    [--require-passphrase] <ns> VAR [VAR...]
//!                                         store values (hidden prompt)
//!   envlock run    <ns> [<ns>...] -- CMD [ARGS...]
//!   envlock list   <ns>                  print variable NAMES only
//!   envlock unset  <ns> VAR [VAR...]     remove variables
//!   envlock delete <ns>                  remove the whole namespace
//!
//! Design notes:
//! * Values never touch argv, stdout, shell history or files.
//! * `run` uses exec(2): the child REPLACES envlock, so no wrapper
//!   process lingers holding secrets.
//! * Secrets exist in this process's memory between Keychain read and
//!   exec — same as any secret manager; see README for what that means.

mod keychain;
mod store;

use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};
use store::{service_name, valid_namespace, valid_var_name, Vars};

const USAGE: &str = "\
usage:
  envlock set    [--require-passphrase] <namespace> VAR [VAR...]
  envlock run    <namespace> [<namespace>...] -- <command> [args...]
  envlock list   <namespace>
  envlock unset  <namespace> VAR [VAR...]
  envlock delete <namespace>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("set") => cmd_set(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("list") => cmd_list(&args[1..]),
        Some("unset") => cmd_unset(&args[1..]),
        Some("delete") => cmd_delete(&args[1..]),
        Some("-h") | Some("--help") | None => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        Some(other) => Err(format!("unknown command: {other}\n{USAGE}")),
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("envlock: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn check_namespace(ns: &str) -> Result<(), String> {
    if valid_namespace(ns) {
        Ok(())
    } else {
        Err(format!(
            "invalid namespace {ns:?} (allowed: letters, digits, . _ -)"
        ))
    }
}

fn load_vars(ns: &str) -> Result<Option<Vars>, String> {
    match keychain::read(&service_name(ns))? {
        Some(blob) => Ok(Some(store::parse(&blob)?)),
        None => Ok(None),
    }
}

// ---------- set ----------

fn cmd_set(args: &[String]) -> Result<ExitCode, String> {
    let require_passphrase = args.first().map(String::as_str) == Some("--require-passphrase");
    let args = if require_passphrase { &args[1..] } else { args };

    let (ns, names) = args
        .split_first()
        .ok_or(format!("set: namespace required\n{USAGE}"))?;
    check_namespace(ns)?;
    if names.is_empty() {
        return Err(format!("set: at least one VAR required\n{USAGE}"));
    }
    for name in names {
        if !valid_var_name(name) {
            return Err(format!("set: invalid variable name {name:?}"));
        }
    }

    let mut vars = load_vars(ns)?.unwrap_or_default();
    for name in names {
        let value = rpassword::prompt_password(format!("{ns}.{name}: "))
            .map_err(|e| format!("failed to read value: {e}"))?;
        if value.is_empty() {
            return Err(format!("set: empty value for {name}, aborting"));
        }
        vars.insert(name.clone(), value);
    }
    keychain::write(&service_name(ns), &store::serialize(&vars), require_passphrase)?;
    if require_passphrase {
        eprintln!(
            "envlock: stored {} variable(s) in {ns} (Touch ID / passcode required on every read)",
            names.len()
        );
    } else {
        eprintln!("envlock: stored {} variable(s) in {ns}", names.len());
    }
    Ok(ExitCode::SUCCESS)
}

// ---------- run ----------

fn cmd_run(args: &[String]) -> Result<ExitCode, String> {
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or(format!("run: missing `--` before command\n{USAGE}"))?;
    let (namespaces, rest) = args.split_at(sep);
    let command = &rest[1..]; // skip the "--"

    if namespaces.is_empty() {
        return Err(format!("run: at least one namespace required\n{USAGE}"));
    }
    if command.is_empty() {
        return Err(format!("run: missing command after `--`\n{USAGE}"));
    }
    for ns in namespaces {
        check_namespace(ns)?;
    }

    let mut merged = Vars::new();
    for ns in namespaces {
        let vars = load_vars(ns)?
            .ok_or_else(|| format!("namespace {ns:?} not found (use `envlock set`)"))?;
        merged.extend(vars); // later namespaces win on conflicts
    }

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]).envs(&merged);

    // exec(2): on success this never returns — the command replaces us.
    let err = child.exec();
    Err(format!("failed to exec {:?}: {err}", command[0]))
}

// ---------- list ----------

fn cmd_list(args: &[String]) -> Result<ExitCode, String> {
    let [ns] = args else {
        return Err(format!("list: exactly one namespace required\n{USAGE}"));
    };
    check_namespace(ns)?;
    let vars = load_vars(ns)?.ok_or_else(|| format!("namespace {ns:?} not found"))?;
    for name in vars.keys() {
        println!("{name}"); // names only, never values
    }
    Ok(ExitCode::SUCCESS)
}

// ---------- unset ----------

fn cmd_unset(args: &[String]) -> Result<ExitCode, String> {
    let (ns, names) = args
        .split_first()
        .ok_or(format!("unset: namespace required\n{USAGE}"))?;
    check_namespace(ns)?;
    if names.is_empty() {
        return Err(format!("unset: at least one VAR required\n{USAGE}"));
    }
    let mut vars = load_vars(ns)?.ok_or_else(|| format!("namespace {ns:?} not found"))?;
    for name in names {
        if vars.remove(name).is_none() {
            eprintln!("envlock: warning: {name} was not set in {ns}");
        }
    }
    if vars.is_empty() {
        keychain::remove(&service_name(ns))?;
        eprintln!("envlock: namespace {ns} is now empty and was deleted");
    } else {
        // false: never touch an existing ACL — a plain `unset` must not
        // silently undo a namespace hardened with `set --require-passphrase`.
        keychain::write(&service_name(ns), &store::serialize(&vars), false)?;
    }
    Ok(ExitCode::SUCCESS)
}

// ---------- delete ----------

fn cmd_delete(args: &[String]) -> Result<ExitCode, String> {
    let [ns] = args else {
        return Err(format!("delete: exactly one namespace required\n{USAGE}"));
    };
    check_namespace(ns)?;
    match keychain::remove(&service_name(ns)) {
        Ok(()) => {
            eprintln!("envlock: deleted namespace {ns}");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) if e == keychain::NOT_FOUND => Err(format!("namespace {ns:?} not found")),
        Err(e) => Err(e),
    }
}
