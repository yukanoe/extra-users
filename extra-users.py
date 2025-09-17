#!/usr/bin/env python3

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
import logging
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import shutil


DEFAULT_CONFIG_PATH = "/etc/extra-users.json"
ENV_CONFIG_KEY = "EXTRA_USERS_CONFIGURE_FILE"
DEFAULT_LOG_PATH = "/var/log/extra-users.log"
LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3

logger = logging.getLogger("extra-users")


@dataclass
class UserSpec:
    username: str
    group: Optional[str]
    home: Optional[str]
    shell: Optional[str]
    password: Optional[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="extra-users",
        description=(
            "Ensure users from a JSON config exist on the system. "
            "Creates groups/users if missing and applies shell/home when provided."
        ),
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        default=None,
        help=(
            f"Path to config file. If omitted, search order: "
            f"${ENV_CONFIG_KEY} > CWD (./extra-users/extra-users.json, ./extra-users.json) > "
            f"script dir equivalents > {DEFAULT_CONFIG_PATH}"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without applying changes",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--no-create-missing-group",
        action="store_true",
        help="Do not create missing primary groups; fail instead",
    )
    return parser.parse_args()


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_config_path(cli_path: Optional[str], verbose: bool) -> Optional[str]:
    # Priority: CLI > ENV > CWD (+ ./extra-users) > script dir (+ ./extra-users) > /etc/extra-users.json
    candidates: List[str] = []

    if cli_path:
        candidates.append(cli_path)
    env_path = os.environ.get(ENV_CONFIG_KEY)
    if env_path and env_path not in candidates:
        candidates.append(env_path)

    cwd = os.getcwd()
    candidates.extend(
        [
            os.path.join(cwd, "extra-users", "extra-users.json"),
            os.path.join(cwd, "extra-users.json"),
        ]
    )

    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates.extend(
        [
            os.path.join(script_dir, "extra-users", "extra-users.json"),
            os.path.join(script_dir, "extra-users.json"),
            DEFAULT_CONFIG_PATH,
        ]
    )

    for path in candidates:
        if os.path.exists(path):
            if verbose:
                print(f"Using config: {path}")
            return path
        else:
            if verbose:
                print(f"Config not found (skipped): {path}")
    return None


def validate_config(raw: Dict[str, Any]) -> List[UserSpec]:
    if not isinstance(raw, dict):
        raise ValueError("Config root must be an object")
    users = raw.get("users")
    if not isinstance(users, list):
        raise ValueError("Config must contain 'users' as an array")

    specs: List[UserSpec] = []
    for idx, item in enumerate(users):
        if not isinstance(item, dict):
            raise ValueError(f"users[{idx}] must be an object")

        username = item.get("username")
        if not isinstance(username, str) or not username:
            raise ValueError(f"users[{idx}].username must be a non-empty string")

        group = item.get("group")
        if group is not None and not isinstance(group, str):
            raise ValueError(f"users[{idx}].group must be string or null")

        home = item.get("home")
        if home is not None and not isinstance(home, str):
            raise ValueError(f"users[{idx}].home must be string or null")

        shell = item.get("shell")
        if shell is not None and not isinstance(shell, str):
            raise ValueError(f"users[{idx}].shell must be string or null")
        password = item.get("password")
        if password is not None and not isinstance(password, str):
            raise ValueError(f"users[{idx}].password must be string or null")

        specs.append(
            UserSpec(
                username=username,
                group=group,
                home=home,
                shell=shell,
                password=password,
            )
        )

    return specs


def run(cmd: List[str], verbose: bool = False, dry_run: bool = False) -> Tuple[int, str, str]:
    if verbose or dry_run:
        print("$", " ".join(shlex.quote(c) for c in cmd))
    logger.debug("RUN: %s", " ".join(shlex.quote(c) for c in cmd))
    if dry_run:
        return 0, "", ""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.debug("RET[%s] ERR: %s", proc.returncode, (proc.stderr or "").strip())
    else:
        logger.debug("RET[%s] OUT: %s", proc.returncode, (proc.stdout or "").strip())
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def command_exists(cmd_name: str) -> bool:
    return shutil.which(cmd_name) is not None


def exists_in_getent(database: str, name: str, verbose: bool, dry_run: bool) -> bool:
    code, out, _ = run(["getent", database, name], verbose=verbose, dry_run=dry_run)
    # In dry-run, assume not existing to show intended actions; do not block creation
    if dry_run:
        return False
    return code == 0 and bool(out)


def group_exists(group: str, verbose: bool, dry_run: bool) -> bool:
    return exists_in_getent("group", group, verbose, dry_run)


def user_exists(username: str, verbose: bool, dry_run: bool) -> bool:
    return exists_in_getent("passwd", username, verbose, dry_run)


def user_in_group(username: str, group: str, verbose: bool, dry_run: bool) -> bool:
    # Returns True if user is a member of group. In dry-run, assume False to show intended actions.
    if dry_run:
        return False
    code, out, _ = run(["id", "-nG", username], verbose=verbose, dry_run=False)
    if code != 0 or not out:
        return False
    groups = out.split()
    return group in groups


def ensure_group(group: str, create_if_missing: bool, verbose: bool, dry_run: bool) -> None:
    if group_exists(group, verbose, dry_run):
        if verbose:
            print(f"Group exists: {group}")
        logger.info("Group exists: %s", group)
        return
    if not create_if_missing:
        raise RuntimeError(f"Primary group missing and creation disabled: {group}")
    # Prefer shadow-utils 'groupadd'; fall back to Alpine/BusyBox 'addgroup'
    if command_exists("groupadd"):
        cmd = ["groupadd", group]
    elif command_exists("addgroup"):
        cmd = ["addgroup", group]
    else:
        raise RuntimeError("Neither 'groupadd' nor 'addgroup' found on PATH")

    code, _, err = run(cmd, verbose=verbose, dry_run=dry_run)
    if code != 0:
        logger.error("Failed to create group '%s': %s", group, err)
        raise RuntimeError(f"Failed to create group '{group}': {err}")
    if verbose:
        print(f"Created group: {group}")
    logger.info("Created group: %s", group)


def get_current_user_info(username: str, verbose: bool, dry_run: bool) -> Tuple[Optional[str], Optional[str]]:
    # Returns (home, shell)
    if dry_run:
        return None, None
    code, out, err = run(["getent", "passwd", username], verbose=verbose, dry_run=False)
    if code != 0 or not out:
        return None, None
    # passwd format: name:passwd:uid:gid:gecos:directory:shell
    parts = out.split(":")
    if len(parts) < 7:
        return None, None
    home = parts[5] or None
    shell = parts[6] or None
    return home, shell


def ensure_user(user: UserSpec, create_missing_group: bool, verbose: bool, dry_run: bool) -> None:
    if user.group:
        ensure_group(user.group, create_if_missing=create_missing_group, verbose=verbose, dry_run=dry_run)

    if not user_exists(user.username, verbose, dry_run):
        # Prefer shadow-utils 'useradd'; fall back to Alpine/BusyBox 'adduser'
        if command_exists("useradd"):
            cmd = ["useradd", user.username]
            if user.group:
                cmd.extend(["-g", user.group])
            if user.home:
                cmd.extend(["-d", user.home, "-m"])  # create home directory if missing
            if user.shell:
                cmd.extend(["-s", user.shell])
        elif command_exists("adduser"):
            # BusyBox adduser: create with defaults then adjust
            cmd = ["adduser", "-D"]
            if user.home:
                cmd.extend(["-h", user.home])
            if user.shell:
                cmd.extend(["-s", user.shell])
            cmd.append(user.username)
        else:
            raise RuntimeError("Neither 'useradd' nor 'adduser' found on PATH")

        code, _, err = run(cmd, verbose=verbose, dry_run=dry_run)
        if code != 0:
            logger.error("Failed to create user '%s': %s", user.username, err)
            raise RuntimeError(f"Failed to create user '{user.username}': {err}")
        if verbose:
            print(f"Created user: {user.username}")
        logger.info("Created user: %s", user.username)

        # If created via BusyBox adduser and a primary group was requested, ensure group exists
        # and add the user to that group (supplementary group on BusyBox).
        if command_exists("adduser") and not command_exists("useradd") and user.group:
            ensure_group(user.group, create_if_missing=create_missing_group, verbose=verbose, dry_run=dry_run)
            if command_exists("addgroup"):
                if not user_in_group(user.username, user.group, verbose=verbose, dry_run=dry_run):
                    code, _, err = run(["addgroup", user.username, user.group], verbose=verbose, dry_run=dry_run)
                    if code != 0:
                        logger.error("Failed to add user '%s' to group '%s': %s", user.username, user.group, err)
                        raise RuntimeError(f"Failed to add user '{user.username}' to group '{user.group}': {err}")
                    if verbose:
                        print(f"Added {user.username} to group: {user.group}")
                    logger.info("Added %s to group %s", user.username, user.group)
                else:
                    if verbose:
                        print(f"User already in group: {user.username} -> {user.group}")
                    logger.info("User already in group: %s -> %s", user.username, user.group)

        # Set password if provided
        if user.password:
            if verbose or dry_run:
                print(f"$ echo '<redacted>' | chpasswd")
            logger.debug("Setting password via chpasswd for user: %s", user.username)
            if not dry_run:
                proc = subprocess.run(["chpasswd"], input=f"{user.username}:{user.password}", text=True, capture_output=True)
                if proc.returncode != 0:
                    logger.error("Failed to set password for '%s': %s", user.username, (proc.stderr or '').strip())
                    raise RuntimeError(f"Failed to set password for '{user.username}': {(proc.stderr or '').strip()}")
            logger.info("Password set for user: %s", user.username)
        return

    # User exists; align properties when specified
    current_home, current_shell = get_current_user_info(user.username, verbose, dry_run)
    modify_needed = False
    if command_exists("usermod"):
        cmd = ["usermod"]
        if user.group:
            cmd.extend(["-g", user.group])
            modify_needed = True
        if user.home and (current_home is None or user.home != current_home):
            cmd.extend(["-d", user.home])
            modify_needed = True
        if user.shell and (current_shell is None or user.shell != current_shell):
            cmd.extend(["-s", user.shell])
            modify_needed = True

        if modify_needed:
            cmd.append(user.username)
            code, _, err = run(cmd, verbose=verbose, dry_run=dry_run)
            if code != 0:
                logger.error("Failed to modify user '%s': %s", user.username, err)
                raise RuntimeError(f"Failed to modify user '{user.username}': {err}")
            if verbose:
                print(f"Updated user: {user.username}")
            logger.info("Updated user: %s", user.username)
        else:
            if verbose:
                print(f"User up-to-date: {user.username}")
            logger.info("User up-to-date: %s", user.username)
    else:
        # Without usermod (e.g., Alpine BusyBox), we can only adjust group membership via addgroup
        changed = False
        if user.group and command_exists("addgroup"):
            # Ensure group exists then add user to it as a supplementary group (if not already a member)
            ensure_group(user.group, create_if_missing=True, verbose=verbose, dry_run=dry_run)
            if not user_in_group(user.username, user.group, verbose=verbose, dry_run=dry_run):
                code, _, err = run(["addgroup", user.username, user.group], verbose=verbose, dry_run=dry_run)
                if code != 0:
                    logger.error("Failed to add user '%s' to group '%s': %s", user.username, user.group, err)
                    raise RuntimeError(f"Failed to add user '{user.username}' to group '{user.group}': {err}")
                changed = True
                if verbose:
                    print(f"Ensured {user.username} is in group: {user.group}")
                logger.info("Ensured %s is in group %s", user.username, user.group)
            else:
                if verbose:
                    print(f"User already in group: {user.username} -> {user.group}")
                logger.info("User already in group: %s -> %s", user.username, user.group)

        # Home and shell updates are skipped on systems without usermod
        if changed:
            logger.info("User updated with limited changes (no usermod available): %s", user.username)
        else:
            if verbose:
                print(f"User up-to-date (no usermod available for further changes): {user.username}")
            logger.info("User up-to-date (no usermod available): %s", user.username)

    # If password provided, set (for existing users)
    if user.password:
        if verbose or dry_run:
            print(f"$ echo '<redacted>' | chpasswd")
        logger.debug("Setting password via chpasswd for user: %s", user.username)
        if not dry_run:
            proc = subprocess.run(["chpasswd"], input=f"{user.username}:{user.password}", text=True, capture_output=True)
            if proc.returncode != 0:
                logger.error("Failed to set password for '%s': %s", user.username, (proc.stderr or '').strip())
                raise RuntimeError(f"Failed to set password for '{user.username}': {(proc.stderr or '').strip()}")
        logger.info("Password set for user: %s", user.username)


def check_platform(verbose: bool) -> None:
    if os.name != "posix":
        raise SystemExit(
            "This tool must be run on a POSIX/Linux system for actual changes. "
            "Use --dry-run on non-Linux hosts."
        )
    if verbose:
        print(f"Platform: {platform.system()} {platform.release()}")
    logger.debug("Platform: %s %s", platform.system(), platform.release())


def setup_logging(verbose: bool, log_path: str = DEFAULT_LOG_PATH) -> None:
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    # Ensure directory exists
    log_dir = os.path.dirname(log_path)
    try:
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    except Exception as exc:
        # Fall back to stdout if cannot create directory
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
        logger.warning("Cannot create log directory '%s': %s. Falling back to stdout logging.", log_dir, exc)
        return

    try:
        fh = RotatingFileHandler(log_path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception as exc:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
        logger.warning("Cannot open log file '%s': %s. Falling back to stdout logging.", log_path, exc)


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    # Allow non-posix for dry-run only
    if os.name != "posix" and not args.dry_run:
        print("Non-POSIX system detected. Use --dry-run or run on Linux.", file=sys.stderr)
        return 2

    if os.name == "posix" and not args.dry_run:
        check_platform(args.verbose)

    # Resolve config path per search order; if none found, no-op success
    cfg_path = resolve_config_path(args.config_path, args.verbose)
    if cfg_path is None:
        if args.verbose:
            print("No config found. Exiting without changes.")
        logger.info("No config found. No-op exit.")
        return 0

    try:
        raw = load_config(cfg_path)
        specs = validate_config(raw)
    except Exception as exc:
        print(f"Invalid configuration: {exc}", file=sys.stderr)
        logger.error("Invalid configuration: %s", exc)
        return 2

    create_missing_group = not args.no_create_missing_group

    errors: List[str] = []
    for spec in specs:
        try:
            ensure_user(
                spec,
                create_missing_group=create_missing_group,
                verbose=args.verbose,
                dry_run=args.dry_run,
            )
        except Exception as exc:
            errors.append(f"{spec.username}: {exc}")
            print(f"Error: {spec.username}: {exc}", file=sys.stderr)
            logger.error("Error processing user %s: %s", spec.username, exc)

    if errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


