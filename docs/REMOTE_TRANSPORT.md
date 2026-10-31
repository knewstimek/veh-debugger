# Authenticated remote backend transport

MCP can select a registered TCP backend through the existing `backend` argument.
The frontend runs on the analyst workstation. `veh-remote-runner` runs beside the
backend executable on the analysis Windows VM. For VirtualBox/WHPX, put the runner
and bridge on the analysis **host VM**, never in the inner analyzed guest.
No guest helper, service, or injected agent is required by this transport.

The runner owns backend processes, their named pipes, and host target creation.
The frontend does not call local CreateProcess/OpenProcess/Toolhelp for a remote
target. Existing VEH IPC command and event frames travel unchanged inside TLS.
Local named-pipe connections remain available.

## Private configuration

Keep both profiles and the shared secret outside Git, for example under ignored
`private/`. Paths are resolved relative to the profile containing them. Use numeric
IPv4/IPv6 addresses; DNS resolution is deliberately excluded from connection deadlines.

On the analysis VM, create a TLS server certificate with a private key in the
runner account's CurrentUser MY certificate store. Pin the SHA-256 digest of its
DER certificate (64 hexadecimal characters), rather than its usual SHA-1 thumbprint.
Provision the same 32 random bytes as 64 hex characters in a separate token file
on each endpoint. An optional LF or CRLF is accepted. Its owner and sensitive
allow permissions must be restricted to the account, SYSTEM, and Administrators.
Never pass the token as a CLI argument or put it in either JSON profile.

Runner profile, with neutral backend names:

```json
{
  "listen": {"address": "192.0.2.10", "port": 4765},
  "certificate_sha256": "<64-hex-sha256>",
  "token_file": "remote.key",
  "backends": {
    "driver": {
      "path": "driver-backend.exe",
      "args": [],
      "target_scope": "host",
      "allow_launch": true
    },
    "vm-guest": {
      "path": "vm-bridge.exe",
      "args": ["--host-owner", "1"],
      "target_scope": "guest",
      "allow_launch": false
    }
  }
}
```

Supply the bridge's existing VM-selection and Windows context arguments in its
registered `args`. Use a separate entry per VM/scope. Backend executable and
startup arguments are chosen by the resident profile; callers cannot override
them over the network. Do not put credentials in backend arguments.

Start the runner under its configured Windows account:

```text
veh-remote-runner --profile private/runner.json
```

Frontend `veh-backends.json` (or the file selected by `VEH_BACKENDS`):

```json
{
  "remote-driver": {
    "target_scope": "host",
    "remote": {
      "address": "192.0.2.10",
      "port": 4765,
      "certificate_sha256": "<64-hex-sha256>",
      "token_file": "remote.key",
      "backend": "driver",
      "timeout_ms": 20000
    }
  }
}
```

For the bridge use `target_scope: "guest"` and `remote.backend: "vm-guest"`.
A VM-wide entry instead uses `target_scope: "vm"` in both profiles; attach without
a PID. Profiles cannot combine `path` with `remote` or override remote `agent_args`.

Use `veh_attach(pid=1234, backend="remote-driver")` or
`veh_launch(program="C:/Lab/sample.exe", backend="remote-driver")`.
The program, working directory, and environment belong to the **remote** analysis
VM. Host launch starts suspended; continue releases its owned initial thread.
`veh_launch` returns `addressBits` (32 or 64) and, when known, `mainThreadId`.
The latter is the initial target thread ID captured at creation, not an agent thread
or a promise that the thread is still alive after execution resumes. The runner's
optional OpenWork `main_thread_id` field is forwarded without opening a local
thread handle. Older runners omit it and remain compatible. `stopOnEntry` holds
the newly created main thread; it does not run the loader to the PE entry point.
VirtualBox/WHPX **guest process launch is unsupported**: attach to an existing
guest PID. Whole-VM attach does not create a process either.

## Authentication and work lifetime

TLS 1.2 encrypts the stream and the client verifies the pinned server certificate
and its validity interval. One application authentication exchange follows TLS:
the server supplies a fresh 32-byte nonce and verifies an HMAC-SHA256 proof over
`VEH-REMOTE-CLIENT-v1 || nonce`. The token itself is never transmitted. Captured
proofs cannot authenticate another connection. No tokens or proofs are attached
to IPC commands; TLS renegotiation and repeated authentication on an established
work connection are rejected. Runner diagnostics contain fixed statuses, without
request bodies, token values, or exception strings.

After authentication, a failed work open can report a fixed startup stage plus
the agent's actual exit code (unsigned decimal and eight-digit hex) and a numeric
Windows API error when available. For example:
`Remote backend agent exited during startup [stage=agent_pipe, agent_exit_code=37 (0x00000025)]`.
Stages distinguish process creation, pipe connection, Ready, capabilities and
target metadata. Exit codes are captured before cleanup, so an agent still running
at failure is not misreported with the cleanup termination code. Exit code zero
also counts as an early exit when startup has not completed. Backend stdout,
stderr, arguments, environment and private paths stay on the analysis host.
Both runner and frontend must be updated to show these optional diagnostics;
older peers retain the existing generic error text.

Optional structured startup diagnostics use `src/common/startup_diagnostics.h`,
independently of target IPC, backend names and process exit-code conventions.
The resident supplies a private anonymous-pipe writer using
`VEH_STARTUP_DIAGNOSTIC_HANDLE` in the child environment. No new command-line
argument is required. Its explicit Windows handle list inherits only this writer;
it does not pass resident sockets, token-file handles or work handles.

An agent can report one early failure before its normal IPC Ready event:

```cpp
// Capture the original API error before logging or cleanup.
const DWORD osError = GetLastError();
veh::ReportStartupFailure(veh::StartupError::BackendUnavailable,
                          veh::StartupDetail::DriverOpenFailed, osError);
return existingExitCode;
```

The helper is optional and best effort, preserves GetLastError, removes its
environment entry, disables inheritance and closes its writer. It changes neither
the normal agent exit code nor the backend's detailed local logs. An old runner
does not supply the channel; an old agent ignores it and still reports its actual
exit code. Using the same numeric exit code in two backends implies no shared
meaning. Both the resident and frontend must support the structured fields, and
each real backend must call the helper to provide them.

| Common error (wire ID) | Detail (wire ID) |
| --- | --- |
| `backend_unavailable` (1) | `driver_open_failed` (1), `hypervisor_not_running` (2) |
| `version_mismatch` (2) | `abi_mismatch` (3) |
| `target_unavailable` (3) | `target_open_failed` (4) |
| `ipc_setup_failed` (4) | `pipe_create_failed` (5) |
| `invalid_configuration` (5) | `invalid_arguments` (6) |

Version 1 is a single 24-byte little-endian record: magic u32 `0x31534456`,
version u16 `1`, size u16 `24`, common error u32, detail u32, original Win32
error u32 (zero if absent), reserved u32 `0`. Record layout is fixed on x86/x64.
Only the listed error/detail pairs are valid. Short, oversized, unknown-version,
unknown-ID and inconsistent records are discarded without interpreting an exit
code as a substitute. The resident checks available bytes and never waits for
diagnostic EOF or an agent-supplied length. No strings, raw logs, arguments, paths
or credentials are accepted through this record.

On authenticated failed OpenWork replies, the optional diagnostic fields are
`startup_error`, `startup_detail` and `backend_system_error` (uint32).
The frontend validates the pair again and renders only its own fixed identifiers,
alongside the original stage, process exit code and resident Win32 error.
These fields do not add an IPC command or advertise a backend capability.


After attachment, a closed backend connection reports that the remote target's
state is unknown; it does not establish a target crash. Thread/module list and
dynamic trace errors preserve backend rejection status and distinguish incomplete
replies from successful empty lists or no-hit traces.

The runner bounds simultaneous connections to 8, retained jobs to 32, and tracked
peer addresses with pending or failed authentication to 128. Each peer address
gets at most five failed/pending authentication attempts in its one-minute failure
window. Successful authentication releases its pending slot, consumes no connection
quota, and does not reset earlier failures. Repeated valid attach/detach is not
subject to a per-minute connection count. Authentication and control exchanges use
bounded local monotonic deadlines. A synchronous command keeps its connection
through idle input intervals while its bounded backend command deadline runs;
the 15-second input wait does not cut a longer active operation short.

Unexpected disconnection retains the backend and its events for up to 60 seconds.
Attach again with the same backend, scope, and PID to resume that work; the returned
`backend.remote.work_id` remains stable. One connection owns a work at a time.
Reconnect refuses while an accepted command remains in flight. Commands are
never automatically replayed. `backend.remote.outcome_unknown` reports uncertain
delivery/effects; inspect target state before issuing another mutating command.
The frontend reuses a launch request identity when retrying the same uncertain
launch during this window, instead of creating a second process. A failure before any OpenWork delivery or
an explicit resident rejection clears a new pending launch, so correcting a
missing program does not require restarting MCP. Lost replies, existing-work
busy replies, and replies from older runners without an explicit outcome remain
uncertain and retain duplicate-launch protection.

Agent process exit is detected through its retained process handle and cancels the
work connection. Attach to the same PID opens a fresh backend; ending/dead work is
never reused while the cleanup thread waits for another agent. Detach retires work
even if its acknowledgement is missing or late. An already-published host target
survives backend death; a still-owned initial suspension is released during cleanup.
Failed startup before work publication still cleans up its newly created target.
Retired launch identities are retained for two minutes (at most 128 active/retired
launch identities) so a late retry cannot duplicate a target after agent death.
The VEH DLL preserves its final Detach/Shutdown acknowledgement until peer close
or a bounded three-second drain deadline, including clients that do not read it.

Explicit detach ends the resident work and releases an owned host target, including
its initial suspended thread. The frontend stops its reader, sends Detach, and
waits up to five seconds for resident connection closure before reporting success.
A repeated attach to the same registered endpoint/backend/scope/PID performs that
confirmed detach first; other target selections retain staged connection behavior.
If closure cannot be confirmed, detach reports an error rather than racing a new
connection against the old owner. Lease expiry or runner shutdown tears down owned
agents and targets. An attached pre-existing host target is never put in the
runner's kill-on-close job. VM lifetime remains governed by the bridge's existing
host-owner semantics.

## Supported boundaries

Capabilities still come from the backend. The host runner additionally implements
host target metadata from its retained process handle; guest/VM metadata must
come from the bridge. This transport does not invent guest launch or debugger
commands that a backend has not implemented.

Frontend conditional breakpoint evaluation and target-side trace data pipes
(`code_output="file"`, `events_output="file"`) are explicitly unsupported remotely.
Process trace results still default to a generated file on the MCP frontend host,
with a compact receipt; `output_file` selects a new host path and
`output_mode="inline"` explicitly returns full JSON. Backend event collection
remains bounded inline unless a supported local file stream is explicitly selected.
Result-file export does not add remote target-side data-pipe support. Registered
backend selection adds no eager MCP tools or per-command authentication fields;
direct, toolbox, batch, and breakpoint-action calls share the existing dispatcher.

`test/test_remote_transport.py` exercises this boundary with local TLS and
synthetic backend fixtures, missing/late detach replies, forced owned-agent exit,
rapid reconnection, preserved host target lifetime and delayed reads of real VEH
DLL lifecycle acknowledgements. It does not prove live driver or VirtualBox/WHPX VM
operation. Run the backend repository's full
`mcp_remote.py --via-tcp <private-backends.json>` regression against each configured
analysis VM before operational deployment. `--tcp-profile` runs only its explicitly
listed checks and must not be treated as the full backend suite. Backend agents
must acknowledge Detach/Shutdown and preserve the reply until the reader consumes
it or closes. Stop and step delivery must also be scoped to the owning backend
handle, so a detached agent still being cleaned up cannot consume a new agent's
stop merely because both target the same PID; a successful transport fixture run cannot establish that contract
for a different agent implementation.

The adapter's existing DAP TCP listener and kernel-debug TCP transport are separate
interfaces. They do not acquire the runner's authentication by sharing a port type.
