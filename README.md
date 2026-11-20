# secrets-web

**Secure** and simple passwords manager written in [Go](https://golang.org/). It aims to be *NYAPM* (Not Yet Another Password Manager), but tries to be different from others by following UNIX philosophy of doing only one thing and doing it well.

This repository is for self-hosted web solution. There exists also a [command-line client](https://github.com/jarmo/secrets-cli). Read more about [secrets](https://github.com/jarmo/secrets) in here.

![screen.png](assets/img/screen.png)

## Installation

Download latest binary from [releases](https://github.com/jarmo/secrets-web/releases), extract it, initialize a vault configuration and start the server. That's it.

*Of course, you're free to compile your own version of binary to be 100% sure that it has not been tampered with, since this is an open-source project after all.*

## Usage

Here's an output from `secrets-web --help` command.

```
$ secrets-web COMMAND [OPTIONS]

Usage:
  secrets-web initialize --config=CONFIG_PATH --path=VAULT_PATH --alias=VAULT_ALIAS
  secrets-web serve --config=CONFIG_PATH --cert=CERT_PATH --cert-priv-key=CERT_PRIVATE_KEY_PATH [--host=HOST] [--port=PORT] [--pid=PID_PATH] [--members-dir=MEMBERS_DIR]

Options:
  --config CONFIG_PATH                      Configuration path for vaults.
  --alias VAULT_ALIAS                       Vault alias.
  --path VAULT_PATH                         Vault path.
  --cert CERT_PATH                          HTTPS certificate path.
  --cert-priv-key CERT_PRIVATE_KEY_PATH     HTTPS certificate private key path.
  --host HOST                               Host to bind to. Defaults to 0.0.0.0.
  --port PORT                               Port to listen on. Defaults to 9090.
  --pid PID_PATH                            Save PID to file.
  --members-dir MEMBERS_DIR                 Member account directory.
  -h --help                                 Show this screen.
  -v --version                              Show version.
```

### Initializing Vault

Initializing a vault stores its file path and alias in the configuration file. Repeat this for each vault.

When using [command-line client](https://github.com/jarmo/secrets-cli) then it is possible to reuse the same configuration file.

```
$ secrets-web initialize --config ~/vault-conf.json --path ~/vault.json --alias my-user
Vault successfully initialized!
```

### Starting the Server

Starting the server **requires a certificate** for serving over HTTPS! It is
required even when using Nginx/Apache as a proxy-pass to avoid moving private
data as unencrypted in the server. It is safe to run server on a custom open
port directly avoiding any proxy-pass.

You can get a free valid SSL certificates from [Let's Encrypt](https://letsencrypt.org) or
use a self-signed certificates if that's not possible.

Start the server:

```
$ secrets-web serve --config ~/vault-conf.json --cert cert.crt --cert-priv-key cert.key
```

Now open browser at [https://localhost:9090](https://localhost:9090) to be greeted with a login form.

Log in with your activated member username and password. There is no password
recovery, so keep your password safe.

## Member activation

Members are created by an administrator using `secrets member-create NAME`.
The administrator shares the one-time setup code securely. The member opens
`/activate` in the web app, enters the code, and chooses their own password.
This creates their account; vault access is granted separately by the administrator.

The web app and CLI must use the same member directory. Pass `--members-dir`
to both commands when using different defaults (for the web app, the default
is `members/` next to the vault configuration file).

### Member login

Members log in using their username and password at `/`. The vault list shows
only vaults they can access, granted through the CLI `member-add` command.
Members can view and manage secrets in each authorized vault. Existing vault alias
and password login remains available temporarily for legacy compatibility.

## Using multiple vaults

To add support for other user/vault, then just execute `initialize` command
again and repeat the steps above.

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

2. Initialize vault configuration:

```
$ echo '[{"Path": "tmp/secrets-dev.json", "Alias": "user"}]' > tmp/conf-dev.json
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

6. Login with **user** and whatever password

7. Add some secret to create a vault encrypted with previously entered password

8. Change code as needed

9. Build and install binaries to `$GOPATH/bin/`

```
make
make install
```

PS! Don't forget to send me a [PR](https://github.com/jarmo/secrets-web/pulls)!
