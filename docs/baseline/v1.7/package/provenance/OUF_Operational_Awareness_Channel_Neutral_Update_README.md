# OUF Operational Awareness — Channel-Neutral Normative Update

This package supersedes the immediately preceding Operational Awareness normative update for new implementation work.

Revised documents:
- MCP Server PET v1.4 — channel-neutral Operational Awareness and private MCP owner API.
- Urban API Gateway PET v1.5 — common mediation for MCP/UI/CLI channels.
- Cross-Module Alignment Matrix v1.7 — human-facing capabilities are channel-neutral and Gateway-mediated.

Unchanged documents from the previous package remain included for completeness.

Key correction: `ouf.system.status` must not use a local MCP datastore dispatch shortcut. MCP is one presentation/client channel. The governed path is MCP/UI/CLI -> Gateway capability -> MCP private owner API.
