# GostHashedAuth

A loopback HTTP authentication plugin for [GOST v3](https://gost.run/en/concepts/auth/#plugin).
Only salted password hashes are stored on the proxy host. The Go service uses the standard
library, without third-party dependencies.

Download a binary for your Linux architecture from [Releases](https://github.com/andre487/GostHashedAuth/releases)
and verify it against `SHA256SUMS`. Run `gost-hashed-auth -help` for server options.

## Prepare users

On a trusted administration machine, supply a JSON map of usernames to passwords through stdin:

```sh
umask 077
gost-hashed-auth hash < plaintext-users.json > users.json
```

Remove the plaintext input when no longer needed. Never put passwords in command-line arguments.
The output maps each username to `$pbkdf2-sha256$600000$<salt-hex>$<key-hex>`:
PBKDF2-HMAC-SHA256, random 16-byte salt, 32-byte key. Passwords use exact UTF-8 bytes,
without normalization or bcrypt's 72-byte truncation. See the current
[OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

```sh
gost-hashed-auth -check -users users.json
gost-hashed-auth -users users.json
```

The service accepts numeric loopback listen addresses only. Protect the users file with OS
permissions, run the service as a dedicated unprivileged user, and restart it after atomically
replacing the file. Empty or invalid files prevent startup. Two simultaneous password checks
bound CPU use; a bounded queue absorbs bursts. Requests exceeding the queue or its wait limit
receive HTTP 503 and GOST denies authentication.

## Connect GOST

```yaml
authers:
  - name: hashed-users
    plugin:
      type: http
      addr: http://127.0.0.1:18083/auth
```

Reference `hashed-users` in each relevant handler's `auther` field. GOST must share the host
network namespace, or otherwise reach the loopback listener. Start the plugin before GOST.
A POST with GOST's `username`, `password` and optional metadata returns `{"ok":true,"id":"username"}`
or `{"ok":false}`. Missing users and incorrect passwords both perform password derivation.
The plugin never logs request bodies, usernames or passwords. It has no plaintext fallback.

This removes plaintext credentials from incoming authentication storage. A client or an outgoing
proxy-chain connector still needs the actual password to authenticate to its destination.
Loopback HTTP also means passwords exist in transit inside the host and in process memory;
host administrator or hypervisor compromise is outside this storage protection.

## Develop and release

Go must support `crypto/pbkdf2`; see `go.mod` for the minimum version.

```sh
go test -race ./...
go vet ./...
go build .
```

Push a `v*` tag to run checks, build static Linux amd64/arm64 binaries and publish their checksums
in a GitHub release. MegaProxyServer pins the release and checksum before installation.
