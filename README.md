# secrets-web

**Secure** and simple passwords manager written in [Go](https://golang.org/). It aims to be *NYAPM* (Not Yet Another Password Manager), but tries to be different from others by following UNIX philosophy of doing only one thing and doing it well.

This repository is for self-hosted web solution. There exists also a [command-line client](https://github.com/jarmo/secrets-cli). Read more about [secrets](https://github.com/jarmo/secrets) in here.

![screen.png](assets/img/screen.png)

## Installation

Download the latest binary from [releases](https://github.com/jarmo/secrets-web/releases). Use [secrets-cli](https://github.com/jarmo/secrets-cli) to initialize vaults and manage members, then start the web server.

*Of course, you're free to compile your own version of binary to be 100% sure that it has not been tampered with, since this is an open-source project after all.*

## Usage

Here's an output from `secrets-web --help` command.

```
$ secrets-web COMMAND [OPTIONS]

Usage:
  secrets-web serve --cert=CERT_PATH --cert-priv-key=CERT_PRIVATE_KEY_PATH [--config=CONFIG_PATH] [--host=HOST] [--port=PORT] [--pid=PID_PATH] [--members-dir=MEMBERS_DIR]

Options:
  --config CONFIG_PATH                      Vault configuration file (defaults to the CLI configuration).
  --cert CERT_PATH                          HTTPS certificate path.
  --cert-priv-key CERT_PRIVATE_KEY_PATH     HTTPS certificate private key path.
  --host HOST                               Host to bind to. Defaults to 0.0.0.0.
  --port PORT                               Port to listen on. Defaults to 9090.
  --pid PID_PATH                            Save PID to file.
  --members-dir MEMBERS_DIR                 Member account directory (defaults to the CLI member directory).
  -h --help                                 Show this screen.
  -v --version                              Show version.
```

### Initializing vaults

Initialize vaults with [secrets-cli](https://github.com/jarmo/secrets-cli):

```
secrets initialize --path /path/to/production.json --alias production
```

By default, the CLI and web app use `~/.config/secrets/config.json` (or
`$XDG_CONFIG_HOME/secrets/config.json` when set).

### Starting the Server

Starting the server **requires a certificate** for serving over HTTPS! It is
required even when using Nginx/Apache as a proxy-pass to avoid moving private
data as unencrypted in the server. It is safe to run server on a custom open
port directly avoiding any proxy-pass.

You can get a free valid SSL certificates from [Let's Encrypt](https://letsencrypt.org) or
use a self-signed certificates if that's not possible.

Start the server:

```
$ secrets-web serve --cert cert.crt --cert-priv-key cert.key
```

Now open browser at [https://localhost:9090](https://localhost:9090) to be greeted with a login form.

Log in with your activated member username and password. There is no password
recovery, so keep your password safe.

## Member activation

Members are created by an administrator using `secrets member-create NAME`.
The administrator shares the one-time setup code securely. The member opens
`/activate` in the web app, enters the code, and chooses their own password.
This creates their account; vault access is granted separately by the administrator.

The CLI and web app default to `~/.config/secrets/members` (or
`$XDG_CONFIG_HOME/secrets/members` when set). Use `--config` and `--members-dir`
to override the web paths if needed. The web server must be able to read the same
vault and member files as the CLI, including when running under a different OS user.

### Member login

Members log in using their username and password at `/`. The vault list shows
only vaults they can access, granted through the CLI `member-add` command.
Members can view and manage secrets in each authorized vault. Settings allows
members to change their password for all vaults and logs out their web sessions
afterward. Existing vault alias and password login remains available temporarily
for legacy compatibility.

## Using multiple vaults

Initialize additional vaults using `secrets initialize`. Grant members access
with `secrets member-add MEMBER --alias VAULT` to make vaults available after login.

## But how do I sync vault between different devices?!

One way to sync would be to use any already existing syncing platforms like Dropbox, Microsoft OneDrive or Google Drive.
Since you can specify vault storage location then it is up to you how (or if even) you sync.

## Running on a publicly-accessible server

There should be no problems with running on a publicly-accessible server, but
if you're not syncing vault(s) then don't forget to backup them to some offsite
location!

## Development

1. Clone repository and run tests (assets are generated automatically):

```
git clone https://github.com/jarmo/secrets-web.git
cd secrets-web
make test
```

2. Set up an isolated development vault and member with the CLI:

```
export XDG_CONFIG_HOME="$(pwd)/tmp"
secrets initialize --path "$(pwd)/tmp/secrets-dev.json" --alias dev
secrets member-create dev
secrets member-activate dev
secrets member-add dev --alias dev
```

3. Install [fswatch](https://emcrisostomo.github.io/fswatch/) for watching file-system changes used for development:

macOS:
```
$ brew install fswatch
```

Linux:
```
$ sudo apt install fswatch
```

4. Run server with automatic restarts on code changes:

```
$ make dev
```

5. Open browser at [http://localhost:8080](http://localhost:8080)

6. Log in as `dev` with the member password you chose.

7. Change code as needed

8. Build and install binaries to `$GOPATH/bin/`

```
make
make install
```

PS! Don't forget to send me a [PR](https://github.com/jarmo/secrets-web/pulls)!
