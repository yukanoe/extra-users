
# Extra Users

A small Linux utility that ensures system users defined in a JSON file exist with the desired primary group, home directory, and shell. Missing groups/users are created; existing users can be updated to match the configuration.

## Features

- Reads configuration from a JSON file (path resolved by CLI/env/search order).
- Creates missing primary groups and users; updates shell/home when specified.
- Can run from anywhere (Python script or PyInstaller binary).
- Portable build via PyInstaller.
- Logs actions and errors to `/var/log/extra-users.log` with rotation.

## System requirements

- Linux (Debian/Ubuntu/CentOS/Alpine, etc.). Requires `root` or sudo.
- For the `.py` version: Python 3.8+ and system tools: `getent`, `groupadd`, `useradd`, `usermod`.

## Configuration

Config path resolution order:
1. `--config` argument (if provided)
2. Env `EXTRA_USERS_CONFIGURE_FILE`
3. Current working directory: `./extra-users/extra-users.json`, then `./extra-users.json`
4. Script directory (or binary dir): `extra-users/extra-users.json`, then `extra-users.json`
5. Default: `/etc/extra-users.json`

If none of the above exist, the tool exits successfully and does nothing (no-op).

Example configuration:
```json
{
  "users": [
    {
      "username": "user_a",
      "group": "group_a",
      "home": null,
      "shell": "/usr/sbin/nologin",
      "password": null
    }
  ]
}
```

Notes:
- `home: null` lets the system choose a default (e.g. `/home/<username>`). You can provide an explicit path.
- If `group` does not exist, the tool will create it (unless disabled via `--no-create-missing-group`).
- `password`: if provided (plaintext), the tool will set it via `chpasswd`. Consider using other mechanisms (e.g., `chage`, SSH keys, or shadow management) for production security.

## Usage

Run with Python:
```bash
sudo EXTRA_USERS_CONFIGURE_FILE=/etc/extra-users.json python3 extra-users.py --verbose
```

Run the PyInstaller binary:
```bash
sudo ./extra-users
```

## Install prebuilt binary

Download and install the public binary to `/usr/local/bin/extra-users`:
```bash
sudo wget -O /usr/local/bin/extra-users \
  https://github.com/yukanoe/extra-users/releases/download/1.0.0/extra-users-linux-x86_64
sudo chmod +x /usr/local/bin/extra-users
```

Alternatively, using curl:
```bash
sudo curl -L -o /usr/local/bin/extra-users \
  https://github.com/yukanoe/extra-users/releases/download/1.0.0/extra-users-linux-x86_64
sudo chmod +x /usr/local/bin/extra-users
```

Then run:
```bash
sudo extra-users --verbose
```

### Logging

- Logs to `/var/log/extra-users.log` with rotation (1MB, keep 3 files). The directory is created if missing.
- If the log file cannot be opened, logging falls back to stdout and the program continues.

Expected behavior:
- Ensures all users in the list exist.
- Does not remove users that are not in the list.

## Build with PyInstaller

Create a single-file binary:
```bash
pip install pyinstaller
pyinstaller --onefile --name extra-users extra-users.py
```

After building, run:
```bash
chmod +x dist/extra-users
sudo dist/extra-users
```

## Security notes

- Run with sufficient privileges (`root`) to create users and groups.
- Review logs and changes according to your internal policies.

## License

MIT
