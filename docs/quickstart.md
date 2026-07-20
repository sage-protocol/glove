# Glove quickstart

## Prerequisites

| Platform | Requirements |
|---|---|
| macOS | Xcode Command Line Tools; CMake 3.28+; Ninja; Clang 18+; optional `yams` integration tests |
| Linux | CMake 3.28+; Ninja; Clang 18+; libseccomp headers, or Docker |

CMake fetches Glaze during configuration.

## Build and verify

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Run all repository gates before committing:

```sh
./scripts/preflight.sh
```

The preflight runs actionlint, formatting, clang-tidy, ASan/UBSan tests, and
TSan tests.

To exercise Linux namespace and mount behavior in Docker:

```sh
docker build -f dockerfiles/Dockerfile.linux -t glove-linux .
docker run --rm --privileged --security-opt seccomp=unconfined glove-linux
```

The elevated Docker flags permit nested namespace creation, `clone3`, and
`pivot_root`. They are not required on a suitable bare-metal Linux host.

## Contained MCP agent

The synthetic agent verifies initialization, tool discovery, policy, dispatch,
and response handling:

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --allow yams.mcp.echo \
  -- ./build/dev/src/container/glove_synthetic_agent --mode=client
```

Multiple stdio MCP servers may be registered:

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --upstream local=python3,-m,my_mcp_server \
  --allow yams.mcp.echo \
  --allow local.read \
  --audit-log /tmp/glove-audit.jsonl \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent
```

The agent sees qualified tool names such as `yams.mcp.echo`. An upstream server
runs as a host process and is not contained by the agent sandbox.

## Direct agent

`glove exec` contains an agent without connecting the MCP kernel:

```sh
mkdir -p /tmp/glove-work
./build/dev/src/glove exec \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent --version
```

Exposure is opt-in:

- `--workspace PATH` grants the working tree.
- `--read PATH` grants a read-only file or directory.
- `--write PATH` grants write access.
- `--env NAME` copies one host environment variable.
- `--egress-allow HOST:PORT` permits an exact macOS HTTPS destination.

Without `--workspace`, Glove starts in a private empty directory. Linux direct
execution is offline because proxy transport into the isolated network namespace
is not implemented.

## Audit output

`--audit-log PATH` appends one JSON object per event:

```sh
tail -f /tmp/glove-audit.jsonl | jq .
```

The audit path must be outside every agent-visible path. Glove rejects unsafe
placement. The general JSONL log prevents contained-agent access but is not
authenticated against a same-user host process.

## Gloved control service

`gloved` requires an existing owner-only runtime directory and protected key,
journal, policy, and session-store paths:

```sh
./build/dev/src/gloved \
  --runtime-dir /absolute/owner-only/runtime \
  --audit-key /absolute/owner-only/audit.key \
  --journal /absolute/owner-only/receipts.journal \
  --session-policy /absolute/owner-only/session-policy.json \
  --session-store /absolute/owner-only/sessions.journal \
  --path-exposure-policy /absolute/owner-only/path-exposure-policy.json \
  --path-exposure-journal /absolute/owner-only/path-exposures.journal
```

Linux managed-session configuration may also provide
`--materialization-root` and `--library-bundle-root`. This enables the local
session lifecycle, but does not by itself make Sage remote launch production
ready. Retained-write preparation additionally requires `mkfs.ext4`,
`/dev/loop-control`, loop devices, and mount capability. See
[session-policy.md](session-policy.md).

### Sage-triggered user service

Sage can start `gloved` through the current user's service manager before it
negotiates capabilities. Substitute absolute paths in the platform template,
install it under the standard per-user service directory, and load or enable
it without starting it:

- systemd: `packaging/systemd/sage-gloved.service.in`
- launchd: `packaging/launchd/org.sage-protocol.gloved.plist.in`

Then configure `saged`:

```toml
[daemon]
fleet_execution_host_enabled = true
glove_activation_mode = "user_service"
glove_service_name = "org.sage-protocol.gloved" # macOS
# glove_service_name = "sage-gloved.service"    # Linux
glove_runtime_dir = "/absolute/owner-only/runtime"
glove_session_policy_path = "/absolute/owner-only/session-policy.json"
```

Activation invokes only `/bin/launchctl` or `/usr/bin/systemctl` with a bounded
service label. Neither a Glove binary path nor a service label is accepted from
P2P. The service manager owns restart and shutdown policy; Sage waits for the
socket and per-start credential, then performs its normal health and capability
checks.

This user-service profile retains the existing same-UID control contract and
cannot activate host apply. A future system-service profile must use a distinct
Glove identity, peer-credential policy, and group-readable control socket while
keeping the apply-signing key unavailable to Sage.

## Troubleshooting

| Error | Cause and action |
|---|---|
| `clone3: Function not implemented` | Use Linux 5.3+ and allow `clone3` in the outer container. |
| `mount: Operation not permitted` | Grant mount capability to the outer test container. |
| `posix_spawnp: No such file or directory` | Check that agent and upstream paths exist and are executable. |
| JSON-RPC version or frame error | Run the upstream directly and verify MCP stdio framing. |
| Missing yams tests | Install `yams` and reconfigure the build directory. |

For security boundaries and deployment assumptions, read
[threat-model.md](threat-model.md).
