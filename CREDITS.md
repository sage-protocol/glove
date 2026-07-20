# Credits and references

## Runtime dependencies

| Project | Use | License |
|---|---|---|
| [Glaze](https://github.com/stephenberry/glaze), v7.5.0 | C++23 JSON and JSON-RPC encoding | MIT |
| [libseccomp](https://github.com/seccomp/libseccomp) | Linux seccomp-bpf filter construction | LGPL-2.1 |

Glaze is fetched by CMake and linked privately. libseccomp is a Linux system
dependency linked privately by the container module. Their licenses are
compatible with GPLv3; they remain governed by their own terms.

## Platform and protocol references

- [Bubblewrap](https://github.com/containers/bubblewrap) informed the Linux
  user-namespace, UID/GID mapping, private-mount propagation, `pivot_root`, and
  detached-old-root sequence. Glove neither links to nor copies Bubblewrap.
- [Model Context Protocol](https://modelcontextprotocol.io) defines the
  JSON-RPC tool protocol implemented by the MCP module.
- Apple's Sandbox Profile Language is used for the macOS deny-default process
  profile. The underlying API is deprecated and may require replacement if
  removed by Apple.
- [Yams](https://github.com/yams-stack/yams) is the external MCP server used by
  integration tests.

## Research context

The following work informs the threat model and evaluation backlog:

- Debenedetti et al., “CaMeL: Defeating Prompt Injections by Design,” 2025.
- Wu et al., [“IsolateGPT: An Execution Isolation Architecture for LLM-Based
  Agentic Systems,”](https://arxiv.org/abs/2403.04960) 2024.
- Ruan et al., “Toolemu: Identifying the Risks of LM Agents with an LM-Emulated
  Sandbox,” ICLR 2024.
- Debenedetti et al., “AgentDojo: A Dynamic Environment to Evaluate
  Prompt-Injection Attacks and Defenses for LLM Agents,” NeurIPS 2024.
- Zhan et al., “InjecAgent: Benchmarking Indirect Prompt Injections in
  Tool-Integrated Large Language Model Agents,” ACL 2024.

These works are references, not bundled code or evidence that Glove provides
the same guarantees.

## License

Glove is licensed under [GPL-3.0-only](LICENSE).
