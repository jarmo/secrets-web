# secrets-cli

**Secure** and simple passwords manager written in [Go](https://golang.org/). It aims to be *NYAPM* (Not Yet Another Password Manager), but tries to be different from others by following UNIX philosophy of doing only one thing and doing it well.

This repository is for self-hosted web solution. There exists also a [command-line client](https://github.com/jarmo/secrets-cli). Read more about [secrets](https://github.com/jarmo/secrets) in here.

## Installation

Download latest binary from [releases](https://github.com/jarmo/secrets-web/releases), extract it, initialize a vault configuration file and start the server. That's it.

*Of course, you're free to compile your own version of binary to be 100% sure that it has not been tampered with, since this is an open-source project after all.*

## Usage

Here's an output from `secrets-web --help` command.

```
$ secrets-web COMMAND [OPTIONS]

Usage:
  secrets-web initialize --config=CONFIG_PATH --path=VAULT_PATH --alias=VAULT_ALIAS
  secrets-web serve --config=CONFIG_PATH --cert=CERT_PATH --cert-priv-key=CERT_PRIVATE_KEY_PATH [--host=HOST] [--port=PORT]

Options:
  --config CONFIG_PATH                      Configuration path for vaults.
  --alias VAULT_ALIAS                       Vault alias.
  --path VAULT_PATH                         Vault path.
  --cert CERT_PATH                          HTTPS certificate path.
  --cert-priv-key CERT_PRIVATE_KEY_PATH     HTTPS certificate private key path.
  --host HOST                               Host to bind to. Defaults to 0.0.0.0.
  --port PORT                               Port to listen on. Defaults to 9090.
  -h --help                                 Show this screen.
  -v --version                              Show version.
```

### Initializing Vault

Vault needs to be initialized for each user. Initializing vault just stores location and alias to your vault into a configuration file. Alias will be used for logging in from the login form.
When using [command-line client](https://github.com/jarmo/secrets-cli) then it is possible to reuse the same configuration file.

```
$ secrets-web initialize --config ~/vault-conf.json --path ~/vault.json --alias my-user
Vault successfully initialized!
```

### Starting the Server

Starting the server requires a certificate for serving over https! It is
required even when using Nginx/Apache as a proxy-pass to avoid moving private
data as unencrypted in the server. It is safe to run server on a custom open
port directly avoiding any proxy-pass.

You can get valid SSL certificates from [Let's Encrypt](https://letsencrypt.org) or
use self-signed certificates if that's not possible.

Start the server:

```
$ secrets-web serve --config ~/vault-conf.json --cert cert.crt --cert-priv-key cert.key
```

Now open browser at [https://localhost:9090](https://localhost:9090) to be greeted with a login form.

Log-in with previously created alias and enter some strong passphrase! It is
recommended to write that password somewhere for the first login and then
copy-paste it to the login form so that there would be no typos.

Add some secret via *Add* button to actually create your vault!

*PS!* Remember that passphrase since there is no "forgot my password"
functionality (and if there would be then it would defeat the purpose) and it
is impossible to retrieve any of your secrets in case you should forget it.

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

* Clone repository, retrieve dependencies and run tests:

```
git clone https://github.com/jarmo/secrets-cli.git
cd secrets-web
make test
```

* Create a self-signed certificate:

```
$ openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out certs/self-signed.crt -keyout certs/self-signed.key
```

* Initialize vault as described above.

* Install file-system watcher used for development:

```
$ npm install -g chokidar-cli
```

* Run server with file-system changes detection:

```
$ make dev
```

* Open browser at [https://localhost:8080](https://localhost:8080)

* Build and install binaries to `$GOPATH/bin/`

```
make
make install
```
