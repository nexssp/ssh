# Nexss SSH

<small>Nexss Flow 🌀 ready</small>

A local-first SSH command and SFTP adapter for NFlow. The NCP/NFlow runtime connects outward to a VPS; the VPS does not need Flow or this Go module installed.

The repository keeps three concerns separate:

- `nexssflow/` is the Flow `@require` entry point.
- `bundles/ssh/` provides SSH profile validation, OpenSSH config alias listing and command preparation, key generation, host-key fingerprint/trust, connection testing, and strict time-bounded SSH execution.
- `bundles/sftp/` provides bounded SFTP upload and download over the same SSH profile contract.

There is no FTP support. Remote command and SFTP actions select a local profile instead of accepting credentials. Setup actions accept only the values needed for that setup step; host-key trust is an explicit operation and is never a side effect of a failed connection.

## Requirements

- Go 1.27.3 or newer.
- Nexss Flow `v0.70.0` and Kernel `v0.37.0` (the compatible versions used by this module).
- A local OpenSSH identity or a running `ssh-agent`.
- An OpenSSH `known_hosts` file containing the expected host key.

## Configure local profiles

By default, profiles are loaded from `os.UserConfigDir()/nexss/ssh/profiles.yml` (for example, `~/.config/nexss/ssh/profiles.yml` on Linux). Start from the tracked [`examples/profiles.example.yml`](examples/profiles.example.yml) and copy it to the default location:

```sh
mkdir -p ~/.config/nexss/ssh
cp examples/profiles.example.yml ~/.config/nexss/ssh/profiles.yml
```

The file looks like this; replace the example hosts, username, and paths with your own:

```yaml
profiles:
  staging:
    host: staging.example.net
    port: 22
    username: deploy
    identity_file: ~/.ssh/id_ed25519
    known_hosts_file: ~/.ssh/known_hosts

  production:
    host: production.example.net
    port: 22
    username: deploy
    use_agent: true
    known_hosts_file: ~/.ssh/known_hosts
```

Edit the local copy to replace the placeholder hosts and usernames, and select the authentication method you use. The example includes one identity-file profile and one `ssh-agent` profile; it contains no keys or real host details. Set `profiles_file` in `@require` to use a different location. Relative `identity_file` and `known_hosts_file` paths are resolved relative to the YAML file; `~` expands to the current user's home directory.

Each profile must set exactly one of `identity_file` or `use_agent: true`, plus a `known_hosts_file`. The host key is always checked against that file; unknown, malformed, and changed host keys fail closed. There is no trust-on-first-use prompt or insecure fallback. For encrypted private keys, use a local agent and `use_agent: true`; set `SSH_AUTH_SOCK` in the environment running NFlow. Agent authentication currently requires `SSH_AUTH_SOCK` to point to a Unix-domain socket; Windows OpenSSH named-pipe agents are not supported yet. An identity file works on all supported Go platforms, but it must be unencrypted. The local agent is not forwarded to the VPS.

## Flow usage

`@require` loads this external Flow extension; `@include` composes reusable NFlow workflows. The `profiles` value selects a local profile name, not a host or credential.

```nflow
@require github.com/nexssp/ssh/nexssflow v0.2.0 {
  profiles_file: "~/.config/nexss/ssh/profiles.yml",
  timeout: "2m",
  max_bytes: 268435456
}
@include "./modules/ssh_command.nflow" AS remote

@assert result.exit_code == 0
{ profile: "staging", command: "uname -s" } -> remote.pipeline.run
```

See [`examples/`](examples/README.md) for SSH execution and separate SFTP workflows.

The bundle exposes:

| Action | Request fields | Behavior |
|---|---|---|
| `ssh.config` | none | Lists concrete aliases from the local OpenSSH config. It follows bounded `Include` directives but does not evaluate all OpenSSH options or make an alias an authenticated profile. |
| `ssh.keygen` | optional `name` | Generates an unencrypted Ed25519 key pair locally, never overwrites an existing path, and returns only the private-key path and public key. Set `key_dir` in `@require` to choose the output folder. |
| `ssh.fingerprint` | `host`, optional `port` | Captures and fingerprints a presented host key without authenticating a user or modifying `known_hosts`. |
| `ssh.trust` | `host`, optional `port`, `keys` | Appends only valid key lines for that exact host and port. Call only after the user explicitly approves the displayed fingerprint. Set `known_hosts_file` in `@require` to choose the trust file. |
| `ssh.test` | `host`, optional `port`, `user`, `key` | Runs a bounded, batch-mode authentication test using OpenSSH with strict host-key checking. If `key` is empty, OpenSSH's normal local key/agent discovery is used. |
| `ssh.run` | `profile`, `command` | Runs one remote shell command. Returns bounded `stdout`, `stderr`, `exit_code`, and duration. A non-zero remote exit code is returned as data; connection, timeout, host-key, and output-limit failures are errors. |
| `ssh.sftp.upload` | `profile`, `local_path`, `remote_path` | Streams a bounded local regular file to a remote staging name and publishes it by rename after success. Existing remote targets are replaced only when the server supports OpenSSH's `posix-rename` extension; otherwise a rename error is returned. New-file permissions follow the SFTP server's create mode and umask. |
| `ssh.sftp.download` | `profile`, `remote_path`, `local_path` | Streams a bounded remote regular file into a private local staging file and replaces the destination only after success. |

Both transfer operations use SFTP over SSH, not FTP. The `timeout` bundle option applies to all three actions and is limited to at most 10 minutes. The `max_bytes` option sets the SFTP limit (default 256 MiB; maximum 1 GiB). SSH command stdout and stderr are independently limited to 1 MiB each.

The SSH bundle can use a host application's existing profile store instead of a second YAML store. Attach a request-scoped `nexssflow.ProfileProvider` with `nexssflow.WithProfileProvider(ctx, provider)`; when present, it takes precedence over `profiles_file` and provider failures do not fall back to another store. NexssTerm uses this adapter to read its saved SSH profiles from its existing SQLite database.

Commands are remote shell text. Only run trusted NFlow source, and do not interpolate untrusted values into the command string. SFTP paths are interpreted by the remote server; this adapter does not claim to confine them to a remote directory.

## Go API

```go
import (
    "context"
    "time"

    sftptransfer "github.com/nexssp/ssh/bundles/sftp"
    sshx "github.com/nexssp/ssh/bundles/ssh"
)

func run(ctx context.Context) error {
    profiles, err := sshx.LoadProfiles(sshx.DefaultProfilesPath())
    if err != nil {
        return err
    }
    _, err = sshx.RunCommand(ctx, profiles["staging"], "uname -s", 30*time.Second)
    if err != nil {
        return err
    }
    _, err = sftptransfer.Upload(ctx, profiles["staging"], "./release.tar.gz", "/srv/releases/release.tar.gz", 0, 2*time.Minute)
    if err != nil {
        return err
    }
    return nil
}
```

The Go packages are `github.com/nexssp/ssh/bundles/ssh` and `github.com/nexssp/ssh/bundles/sftp`. A zero transfer limit selects the package default. A zero command/transfer timeout selects a 30-second API default; Flow sets its default timeout to two minutes. Every operation is bounded even when the parent context has no deadline.

The SSH package also exports `PrepareOpenSSHArgs`, `GenerateEd25519Key`, `FingerprintHostKey`, `TrustHostKeys`, `TestOpenSSHConnection`, `ReadOpenSSHConfigAliases`, `ValidateProfile`, and `PrepareWindowsPrivateKey`. The Windows-only permission helper verifies that the current user owns the private-key file, then applies a protected DACL with read access for that user only; it does not change ownership or elevate privileges. Command preparation returns arguments rather than a shell string so the host can apply its own shell quoting and process lifecycle. The host application remains responsible for asking the user before calling `TrustHostKeys`.

Agent authentication for Go `Dial`, `RunCommand`, and SFTP currently requires `SSH_AUTH_SOCK` to name a Unix-domain socket; Windows OpenSSH named-pipe agents are not supported for those Go operations. The `ssh.test` setup action invokes the local OpenSSH client, so Windows OpenSSH's own agent integration remains available for that check. Identity-file authentication through the Go SSH client requires an unencrypted key; encrypted keys can be used through the local OpenSSH test/interactive client.

## Local development

The project uses go-task's `Taskfile.yml` instead of a Makefile to keep its named development commands in one declarative task runner. Install [Task](https://taskfile.dev/installation/), `golangci-lint` v2, and the Flow `nflow` CLI v0.70.0, then run `task ci` to execute the full local check sequence. Individual tasks are available as `task fmt-check`, `task test`, `task race`, `task vet`, and `task lint`.

No live VPS is needed for the unit suite.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
