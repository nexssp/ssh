# NFlow examples

Each example loads the Flow bundle with a local `@require` path, includes a small reusable workflow module with `@include`, and selects only a profile name from the local profiles file. Start from [`profiles.example.yml`](profiles.example.yml), which contains placeholders only; copy it to your user config location, replace its host and authentication settings, and keep the resulting `profiles.yml` and private keys outside the repository.

- [`ssh_command.nflow`](ssh_command.nflow) runs a remote command and asserts a successful exit code.
- [`sftp_upload.nflow`](sftp_upload.nflow) uploads a local release file.
- [`sftp_download.nflow`](sftp_download.nflow) downloads a remote log file.
- [`modules/`](modules/) contains the included action workflows.

Run an example from this directory with the `nflow` CLI compatible with Flow `v0.70.0`. The local `@require ../nexssflow` works from this repository checkout. After publishing the module, consumers can replace it with `@require github.com/nexssp/ssh/nexssflow v0.1.0` and keep the same profile option block. Adjust the local profile name and file paths for your machine.

The command example sends remote shell text and should only be run from trusted NFlow source. SFTP is a separate file-transfer subsystem; no FTP action is provided.
