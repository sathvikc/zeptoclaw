# ZeptoClaw vs Hermes Agent — deep architecture review

- **Date:** 2026-09-06 (codex exec, gpt-5.6-sol, read-only sandbox)
- **ZeptoClaw reviewed at:** `6c74d59` (origin/main tip)
- **Hermes Agent reviewed at:** `9dd6634c56` (origin/main tip)
- **Token usage:** 838,974

Effort scale: **S** = a few days, **M** = roughly 1–3 weeks, **L** = multi-sprint/RFC work.

## Executive summary

1. **Critical impact / S — Fail closed on invalid `agent_mode`:** ZeptoClaw currently converts an unrecognized mode into `Autonomous`, reversing the safe default.
2. **Critical impact / M — Centralize child-process environment scrubbing:** native shell, binary plugins, stdio MCP, and channel plugins currently appear to inherit the host environment.
3. **Very high impact / L — Establish a byte-stable prompt assembly contract:** live time and query-selected memory are rebuilt inside the system prompt, defeating exact-prefix prompt caching across turns.
4. **High impact / L — Complete the channel-plugin protocol:** the current adapter is outbound-only and fire-and-forget despite the README presenting plugin channels as supported.
5. **High impact / L — Finish the Agent Pipeline migration:** production still runs through the 5,227-line `AgentLoop`; the middleware pipeline explicitly remains a future `CoreLoop`.
6. **High impact / M — Make delegated-agent capabilities inherit safely:** ZeptoClaw already has parallel isolated delegates, but their hard-coded toolset and forced native shell can diverge from parent safety policy.
7. **High impact / M, then L — Introduce Cron Job v2:** first add delivery acknowledgement, update/pause/resume, repeats, and per-job model; then add execution ledgers, chaining, and confined script pre-runs.
8. **High impact / M — Add durable cross-session recall and transactional memory writes:** preserve ZeptoClaw's low-cost selective retrieval while adding Hermes-style atomic mutation, content deduplication, consolidation, and session search.
9. **Medium-high impact / M — Adopt a Footprint Ladder and registry-owned extension metadata:** new tools and channels should not keep widening central registrar/factory files.
10. **Medium-high impact / M — Add hermetic seam-level integration tests:** exercise the real agent factory, local HTTP provider, channel bus, plugin protocol, persistence, and safety gates without live credentials.

## Per-area analysis

### 1. Extensibility model

**Hermes approach.** Hermes treats "new core code" as the final rung of a documented Footprint Ladder: extend existing behavior, add CLI plus skill, add a service-gated tool, create a plugin, use MCP, and only then add a core tool. Its narrow-waist rubric explicitly protects the core from optional integrations (`AGENTS.md:132–148`). Plugins can register tools, commands, slash commands, memory/context hooks, lifecycle tasks, approvals, and platform adapters through `PluginContext` (`hermes_cli/plugins.py:214–281`, `hermes_cli/plugins.py:384–491`, `hermes_cli/plugins.py:637–799`). Discovery reads metadata before importing code, supports external directories, applies compatibility gates, and lazy-loads platform implementations (`hermes_cli/plugins_discovery.py:27–68`, `hermes_cli/plugins_discovery.py:173–218`).

Hermes skills also have an authoring contract rather than merely a parser: required frontmatter, naming and path rules, body validation, cross-platform checks, and scope/sprawl warnings (`skills/AGENTS.md:16–59`, `tools/skill_linter.py:79–184`).

**ZeptoClaw today.** ZeptoClaw already has genuine equivalents worth retaining:

- OpenClaw-compatible skill metadata precedence and requirement checking (`src/skills/types.rs:50–110`, `src/skills/loader.rs:228–247`).
- Workspace-over-built-in skill resolution, summaries, full loading, and availability filters (`src/skills/loader.rs:28–179`).
- Command-template and JSON-RPC binary tools in the plugin manifest (`src/plugins/types.rs:24–146`).
- Dynamic trait-object tool registration and collision handling (`src/tools/registry.rs:48–87`).

The limitation is breadth. The general plugin manifest primarily describes tools and their execution; it is not an extension host for providers, channels, prompt hooks, lifecycle work, or CLI commands. Meanwhile `register_all_tools()` remains a central manual catalogue containing nineteen groups of built-ins and integration-specific gating (`src/kernel/registrar.rs:203–215`, `src/kernel/registrar.rs:225–706`). Malformed skill frontmatter is generally warned about and defaulted rather than checked as an authoring contract (`src/skills/loader.rs:302–309`).

**Gap.** ZeptoClaw's core is operationally growing too wide—not because Rust needs dynamic Python imports, but because each optional capability tends to add another compile-time module, config field, registrar branch, and binary-size liability. The existing plugin/tool mechanism proves the narrow waist is possible, but it is not yet the default contribution path.

**Recommendation.**

- **S:** Add `zeptoclaw skill lint`, separating strict authoring validation from tolerant runtime loading.
- **S:** Document a ZeptoClaw Footprint Ladder in `AGENTS.md`, including explicit binary-size and feature-gating criteria for admitting a core tool.
- **M:** Move tool availability, setup metadata, feature requirements, dangerousness, and CLI hints into registry descriptors; generate or self-register the central inventory.
- **L:** Design Plugin ABI v2 as a versioned, out-of-process protocol with typed extension kinds—tool, channel, provider, lifecycle, prompt/context hook, and CLI contribution. That transfers Hermes's narrow-waist pattern without importing Python's in-process plugin risks.

### 2. Memory and learning system

**Hermes approach.** Hermes maintains compact declarative memories in `MEMORY.md` and `USER.md`. The memory tool supports add, replace, remove, and batch mutation, with a session-frozen snapshot returned after successful writes (`tools/memory_tool.py:1–5`, `tools/memory_tool.py:81–158`). The store adds poisoning checks, bounded prompt budgets, unique-match replacement, re-read-under-lock drift detection, exact-content deduplication, batch atomicity, and temp-file replacement (`tools/memory_tool_store.py:19–28`, `tools/memory_tool_store.py:190–227`, `tools/memory_tool_store.py:303–344`, `tools/memory_tool_store.py:383–390`).

Hermes separates declarative memory from procedural memory: reusable workflows become skills and can be curated through the learning path (`agent/learn_prompt.py:1–6`, `skills/AGENTS.md:61–75`). Its `session_search` provides FTS-backed recall with source filtering, lineage deduplication, result demotion, and selective hydration (`tools/session_search_tool.py:1–29`, `tools/session_search_tool.py:261–326`).

**ZeptoClaw today.** ZeptoClaw's memory-write guidance is already strong and should not be copied from Hermes: `longterm_memory` clearly states when durable information should and should not be stored and exposes explicit mutations (`src/tools/longterm_memory.rs:43–70`, `src/tools/longterm_memory.rs:139–201`).

Retrieval is cheaper than Hermes's always-present profile: ZeptoClaw injects pinned entries followed by at most five query-matched memories, within a 2,000-character budget (`src/memory/mod.rs:34–35`, `src/memory/mod.rs:279–340`). The default searcher is lexical, with optional alternative feature paths elsewhere in the project (`src/memory/builtin_searcher.rs:10–16`, `src/memory/builtin_searcher.rs:42–71`). Entries are keyed and upserted, but the persistence path is a direct filesystem write rather than an atomic transaction (`src/memory/longterm.rs:34–68`, `src/memory/longterm.rs:349–371`).

**Gap.** ZeptoClaw wins on nominal injection cost but loses on:

- Paraphrase and cross-session recall quality.
- Content-level deduplication and consolidation.
- Concurrent-writer/drift protection.
- Atomic durability.
- Prompt-cache compatibility, because query-specific memory changes the system prompt each turn.

There is no need to replace selective retrieval with Hermes's full-profile model. The useful transfer is the mutation discipline and session-search layer.

**Recommendation.**

- **S:** Make memory writes atomic and re-read state under a lock before mutation; deduplicate exact normalized content across keys.
- **S:** Return budget/consolidation guidance when memory approaches its injection cap.
- **M:** Add `session_search` over persisted sessions using FTS/BM25, with exclusions for tool payloads, cron noise, and child-agent transcripts.
- **M:** Freeze selected memory for a session or move query-selected memory into a per-turn user/context envelope rather than the system message.
- **L:** Add a conservative "promote repeated procedure to skill" workflow only after the declarative memory and search contracts are stable.

### 3. Context and prompt-cache management

**Hermes approach.** Hermes makes byte stability an explicit invariant: the system prompt and tool prefix remain constant for the lifetime of a conversation; volatile content belongs in user or tool messages; role alternation remains canonical (`agent/AGENTS.md:53–69`). Context compression is the only sanctioned cache invalidation (`agent/AGENTS.md:71–79`). Request assembly deep-copies conversation state, appends volatile material request-locally, canonicalizes roles, and applies cache boundaries last (`agent/turn_request_assembly.py:106–183`, `agent/turn_request_assembly.py:188–216`). Anthropic cache markers are also planned request-locally rather than persisted in session messages (`agent/prompt_caching.py:1–6`, `agent/prompt_caching.py:243–270`).

Commands that affect skills or prompt structure default to deferred invalidation, with explicit immediate application as an opt-in (`hermes_cli/skills_hub.py:1396–1442`, `gateway/slash_commands.py:1003–1041`).

**ZeptoClaw today.** ZeptoClaw already covers the correctness half:

- Normal/emergency/critical compaction tiers (`src/agent/context_monitor.rs:87–121`, `src/agent/context_monitor.rs:229–247`).
- Repair of orphan tool results, duplicates, empty messages, and alternation errors (`src/session/repair.rs:27–65`, `src/session/repair.rs:89–123`).
- An exact-response cache keyed by model, system prompt, and user prompt—but that is not provider prompt-prefix caching (`src/config/types.rs:318–345`).

The cache-hostile behavior is in prompt construction. Normal CLI creation installs runtime context (`src/cli/common.rs:308–311`); runtime context renders current time into the system prompt (`src/agent/context.rs:207–241`); and query-selected memory is inserted into the same system message (`src/agent/context.rs:437–493`). The agent performs memory selection per incoming message and reconstructs the system prompt before provider calls, including tool-loop continuations (`src/agent/loop.rs:757–770`, `src/agent/loop.rs:1061–1106`, `src/agent/loop.rs:1809–1824`). Tool definitions are also collected from a `HashMap` without a stable ordering contract (`src/tools/registry.rs:206–253`).

**Gap.** This is ZeptoClaw's largest architectural performance gap. Under ordinary exact-prefix cache semantics, a changing timestamp near the beginning of the system prompt invalidates reuse of the entire subsequent conversation prefix. Query-specific memory produces another early divergence. Rebuilding during the tool loop can cause misses even within one user turn.

That conclusion is an inference from the assembled bytes, not a measured provider bill. I found no explicit `cache_control` implementation in the provider paths, but adding markers alone would not fix an unstable prefix.

**Recommendation — L.** Introduce a Prompt Envelope contract:

1. Freeze persona, policy, static runtime facts, skill summaries, and ordered tool schemas when a session starts.
2. Put current time, current workspace status, query-retrieved memory, and ephemeral notices in a separate per-turn user/context message.
3. Sort tool definitions deterministically.
4. Apply provider-specific cache markers only to the request copy.
5. Defer prompt/toolset mutations until the next conversation unless the user explicitly requests immediate invalidation.
6. Add invariant tests that capture two successive requests and assert identical stable-prefix bytes.
7. Keep compaction as the documented, observable cache-breaking event.

### 4. Scheduling and background work

**Hermes approach.** Hermes jobs support one-shot, interval, and cron schedules plus update, pause, resume, manual run, and removal. Job records include delivery, repeat and execution fields (`cron/AGENTS.md:8–15`). The tool surface includes delivery grammar, repeat limits, skills, script/no-agent operation, monitoring, working directory, toolsets, continuity, and `context_from` (`tools/cronjob_tools.py:900–970`). Chained context is assembled separately from the stable prompt, while script output and requested skills are injected in controlled positions (`cron/scheduler_prompt.py:66–114`, `cron/scheduler_prompt.py:192–264`). Script execution includes path confinement, environment reduction, timeouts, process-tree cleanup, and redaction (`cron/scheduler_script.py:256–293`, `cron/scheduler_script.py:316–390`).

**ZeptoClaw today.** ZeptoClaw supports `At`, `Every`, and cron expressions, raw channel/chat routing, missed-run policy, dispatch timeout, exponential error backoff, persistence, and delete-after-success (`src/cron/mod.rs:17–56`, `src/cron/mod.rs:83–118`, `src/cron/mod.rs:223–232`, `src/cron/mod.rs:524–566`). Its public tool surface is deliberately small: add, list, and remove (`src/tools/cron.rs:27–103`).

The important semantic weakness is that "success" currently means publishing an inbound message to the bus, not completed agent execution or outbound delivery (`src/cron/mod.rs:463–506`). A one-shot job can therefore be deleted before the resulting task or channel delivery is known to have succeeded.

**Gap.** Basic scheduling and routing already exist. Missing capabilities are operational control, completion acknowledgement, structured origin/local/platform delivery semantics, repeats, per-job model/provider, chaining, and confined pre-run scripts.

**Recommendation.**

- **M — Job v2 core:** stable job/run IDs, update, pause/resume, bounded repeat count, per-job model/provider, structured delivery target, atomic persistence, and a run ledger.
- **M:** Define completion as terminal agent-plus-delivery acknowledgement; keep bus-enqueue state separate.
- **L:** Add `context_from`, continuity, and script pre-runs after the run ledger and sanitized subprocess environment exist.
- **L:** Treat cron execution as a shared background-task substrate that can later serve reminders, monitors, and durable spawned agents rather than adding parallel schedulers.

### 5. Subagents and delegation

**Hermes approach.** Hermes's `delegate_task` supports isolated child context, terminal, and toolsets, batch/parallel execution, depth-aware nesting, background execution, and lifecycle operations such as list, steer, and stop (`tools/delegate_tool.py:105–166`, `tools/delegate_tool.py:348–460`). A registry tracks ownership and lineage and provides interruption and steering (`tools/delegate_tool_registry.py:92–218`). Child toolsets are derived from the parent, include MCP inheritance, and remove orchestrator-sensitive tools explicitly (`tools/delegate_tool_toolsets.py:13–23`, `tools/delegate_tool_toolsets.py:68–114`).

**ZeptoClaw today.** ZeptoClaw is not missing subagents. `DelegateTool` creates fresh child loops and sessions, executes multiple tasks concurrently, aggregates results, and blocks recursive delegation (`src/tools/delegate.rs:32–53`, `src/tools/delegate.rs:153–250`, `src/tools/delegate.rs:254–358`). A separate `spawn` tool provides process-local background work (`src/tools/spawn.rs:63–131`).

The gaps are in policy inheritance:

- Delegate tools are registered through a hard-coded child list rather than a capability snapshot of the resolved parent registry (`src/tools/delegate.rs:110–137`).
- Delegated shell execution explicitly constructs `NativeRuntime`, so a Docker/Landlock/Bubblewrap parent can yield a less-isolated child (`src/tools/delegate.rs:110–120`).
- Delegate uses the same provider rather than a configured per-role or cost-aware provider (`src/tools/delegate.rs:205–216`).
- `SwarmConfig.max_depth` is described as supporting nested agents, but current delegate execution unconditionally blocks recursion; `max_depth` therefore does not express runtime behavior (`src/config/types.rs:2299–2321`, `src/tools/delegate.rs:345–358`).
- Background spawn lacks durable IDs, inspection, steering, cancellation, and restart recovery.

**Gap.** The real gap is not "add subagents"; it is capability-safe orchestration and lifecycle management.

**Recommendation.**

- **M:** Create a child-agent factory that inherits the resolved runtime, safety scanner, approvals, tool registry, plugin/MCP tools, timeouts, and audit context, then applies an explicit deny/capability filter.
- **M:** Add child IDs, status/list, cancel, bounded steering, deadlines, and per-child provider/model override.
- **S:** Enforce or remove the currently ineffective `max_depth` setting and correct the "cost-aware routing" documentation until provider selection exists.
- **L:** Enable nested orchestration only after lineage, capability inheritance, and cumulative concurrency/depth budgets are enforceable.

### 6. Configuration and setup UX

**Hermes approach.** Hermes makes `config.yaml` the canonical behavior surface and treats `.env` as credential storage. Its contribution rules reject adding new non-secret behavioral environment variables (`AGENTS.md:74–82`, `hermes_cli/AGENTS.md:46–65`). Setup covers model providers and tools, with express and full flows (`hermes_cli/setup.py:368`, `hermes_cli/setup.py:536`, `hermes_cli/setup.py:624`). Platform registry metadata includes passive checks, installers, setup callbacks, environment requirements, and delivery hooks, so setup does not need a separate hard-coded knowledge base (`gateway/platform_registry.py:41–99`).

Hermes still retains environment compatibility bridges internally, so "secrets only" is a design direction and admission rule, not proof that every historical behavior variable has disappeared.

**ZeptoClaw today.** ZeptoClaw has a respectable first-run baseline: provider/key/model onboarding, express and full wizards, configuration validation, endpoint SSRF checks, and actionable diagnostics (`src/cli/onboard.rs:14–110`, `src/cli/onboard.rs:280–360`, `src/cli/config.rs:18–116`). Configuration is JSON, not TOML, and loading combines file values with an extensive environment-override layer (`src/config/mod.rs:1–5`, `src/config/mod.rs:50–124`, `src/config/mod.rs:139–235`).

The generic config CLI only exposes check and reset (`src/cli/config.rs:10–15`). Channel setup is another hard-coded switch and does not cover all active or plugin channels (`src/cli/channel.rs:130–168`).

**Gap.** JSON versus YAML is not the issue. The problem is source opacity and duplicated setup metadata: users can set the same behavior in a file or environment without an easy "effective value came from here" view, while newly supported integrations need separate edits in config types, validation, onboarding, and channel setup.

**Recommendation.**

- **S:** Add `config effective --sources --redact`, showing default/file/environment origin for every resolved field.
- **S:** Stop documenting new non-secret environment variables; establish a deprecation path for existing behavioral overrides rather than breaking them abruptly.
- **M:** Add schema-backed `config get/set/unset` with validation and secret redaction.
- **M:** Use provider/channel/tool/plugin descriptors as the single source for setup prompts, health checks, required secrets, optional dependencies, and documentation hints.
- Keep JSON unless maintainers independently want YAML; format migration produces little architectural value.

### 7. Channel and gateway architecture

**Hermes approach.** Hermes has a rich platform contract covering capabilities, connection lifecycle, sending, delivery behavior, and platform-specific setup (`gateway/platforms/base.py:1853–1885`, `gateway/platforms/base.py:2469–2499`). Platform registration is metadata-driven rather than a hard-coded construction chain and supports scoped/lazy loading (`gateway/platform_registry.py:1–8`, `gateway/platform_registry.py:41–123`, `gateway/platform_registry.py:271–288`). The gateway contract also documents stream phases, token locking, scoped secrets, and adapter-level tests (`gateway/AGENTS.md:30–57`, `gateway/AGENTS.md:82–108`).

**ZeptoClaw today.** ZeptoClaw's built-in channel runtime is strong: a small `Channel` trait, shared message bus, centralized manager, restart cooldowns, and health supervision (`src/channels/types.rs:62–109`, `src/channels/manager.rs:206–288`, `src/channels/manager.rs:291–429`). That existing supervisor should be retained.

Adding a built-in channel is nevertheless expensive because construction is a long static chain tied to concrete config fields and feature gates; some recognized configurations currently end in "not implemented" warnings (`src/channels/factory.rs:20–213`). Plugin channel discovery exists (`src/channels/factory.rs:312–331`), but its protocol is incomplete:

- The process is started with piped stdout/stderr, but only stdin is taken for normal operation (`src/channels/plugin.rs:184–245`).
- `send()` serializes a request and flushes stdin but never reads a correlated response or enforces an acknowledgement timeout (`src/channels/plugin.rs:279–332`).
- The adapter has no inbound event path into `MessageBus`.
- Its script test proves that writing succeeds, but does not consume or validate the echo response (`src/channels/plugin.rs:899–945`).

**Gap.** ZeptoClaw does not yet have a usable general channel-plugin surface. It is effectively an outbound command sink. Unconsumed stdout/stderr also creates a process-stall risk if a plugin emits enough output. This is more important than adding another built-in channel.

**Recommendation — L overall.**

- **M:** Version the protocol and add framed inbound events, correlated send acknowledgements, request timeouts, continuous stdout/stderr draining, redacted logs, and child-exit health reporting.
- **M:** Provide a contract-test harness that any external channel plugin must pass.
- **M:** Replace hard-coded factory and setup switches with channel descriptors registered by built-ins and plugins alike.
- **S:** Until that lands, qualify the README's plugin-channel claim as outbound/experimental rather than complete.
- No recommendation to replace the existing message bus, supervisor, or panic isolation; those already cover the common gateway core well.

### 8. Security posture

**Hermes approach.** Hermes defaults to a "smart" approval posture and applies stricter defaults in unattended, cron, and query contexts; explicit user-deny rules remain effective even in permissive modes (`hermes_cli/config_defaults.py:1493–1530`). Unknown approval modes fail to a safe/manual interpretation, and unattended binary execution defaults to denial (`tools/approval_context.py:197–214`, `tools/approval_context.py:260–284`). Approval evaluation accounts for container isolation and preserves hard safety floors (`tools/approval.py:852–885`, `tools/approval.py:978–1038`). Local execution has an explicit environment policy and centralized sanitizer (`tools/environments/local_env_policy.py:1–82`, `tools/environments/local.py:315–341`).

**ZeptoClaw today.** ZeptoClaw is stronger in several areas:

- Six local isolation choices with opt-in degradation to native execution (`src/runtime/mod.rs:1–29`).
- Docker defaults including no network and resource controls (`src/runtime/docker.rs:31–42`, `src/runtime/docker.rs:119–190`).
- Shared safety, taint checks, execution, output scanning, metrics, and audit routing through the kernel gate (`src/kernel/gate.rs:119–210`).
- Default dangerous-tool approval policy (`src/tools/approval.rs:49–81`, `src/tools/approval.rs:104–137`).
- A SHA-256-linked audit chain with verification and bounded in-memory retention (`src/audit.rs:74–115`, `src/audit.rs:117–183`, `src/audit.rs:187–235`).

Two findings need urgent correction:

1. An invalid agent-mode string explicitly falls back to `Autonomous`, not `Assistant` or an error (`src/security/agent_mode.rs:147–160`).
2. I could not verify the documented inherited-environment scrubbing. Native shell, binary plugins, stdio MCP, and channel plugins construct child commands without calling `env_clear()` (`src/runtime/native.rs:35–60`, `src/tools/binary_plugin.rs:149–170`, `src/tools/mcp/transport.rs:102–122`, `src/channels/plugin.rs:206–217`). Under Rust's process API, that means ambient inheritance unless sanitization occurred earlier; a repository-wide static search found no central `env_clear` path.

The audit chain is tamper-evident only for the current process lifetime. Its bounded in-memory storage does not establish evidence across restart. Apple Container is also documented as experimental and less validated than the other runtime paths (`src/runtime/apple.rs:6–16`).

**Gap and recommendations.**

- **S / P0:** Reject invalid agent modes during config validation or fall back to `Assistant`; add a regression test for every unknown value.
- **M / P0:** Introduce `sanitized_child_env(purpose)` and require it for all agent-controlled subprocesses. Begin with an empty environment and allow only purpose-specific essentials and explicitly configured secrets.
- **S:** Add contract tests proving representative secret-shaped variables do not reach shell, plugin, MCP, channel, or delegated child processes.
- **M:** Persist and rotate audit-chain segments with a cross-restart tip/genesis record and verifiable export.
- Do not add more sandbox backends now. Coverage consistency and child-policy inheritance are higher-value than a seventh runtime.

### 9. Code organization

**Hermes approach.** Hermes's rubric promotes stable public facades with sibling implementation modules and recommends splitting files above roughly 2,000 lines, functions above 300 lines, or highly complex control flow (`AGENTS.md:223–255`). Per-area `AGENTS.md` files provide local routing and invariants. Hermes is not itself free of large files—several platform adapters and CLI/gateway modules exceed 5,000 lines—so its useful lesson is deliberate ownership and invariant extraction, not "all files must be small."

**ZeptoClaw today.** Measured largest Rust files under `src/`:

| File | Lines | Assessment |
|---|---:|---|
| `src/agent/loop.rs` | 5,227 | Genuine orchestration god-file; highest priority |
| `src/config/types.rs` | 3,418 | Large data aggregation; split by domain, preserve re-exports |
| `src/config/mod.rs` | 2,606 | Loading, migration, secrets, defaults, and environment resolution are coupled |
| `src/tools/web.rs` | 2,412 | Candidate for transport/search/extraction separation |
| `src/channels/telegram.rs` | 2,412 | Size alone is not sufficient; protocol state may justify cohesion |
| `src/channels/discord.rs` | 2,172 | Same caveat as Telegram |
| `src/providers/openai.rs` | 2,032 | Preset normalization, wire format, streaming, and provider state are split candidates |

The principal architecture mismatch is already documented in code: `Pipeline` says its production terminal "will be `CoreLoop` (Phase 4a)," while current uses of `Pipeline::builder()` are confined to pipeline/middleware tests rather than the live `AgentLoop` (`src/agent/pipeline.rs:18–45`). The context middleware still contains extraction TODOs (`src/agent/middleware/context_build.rs:57–61`). Production therefore continues through the monolithic loop, including parallel non-streaming and streaming control paths.

**Gap.** This is not primarily a documentation problem. ZeptoClaw has a target decomposition that has not become the production execution architecture, leaving two sources of truth: tested middleware pieces and the real monolithic loop.

**Recommendation.**

- **L:** Complete the pipeline migration as a behavior-preserving project. Use one shared core tool loop with an output strategy for buffered versus streaming delivery.
- **M:** Split configuration into domain modules—providers, channels, security, runtime, memory, agents—while re-exporting existing public types to avoid API churn.
- **S:** Add advisory file/function complexity reporting and require a short ownership justification for new growth above the thresholds.
- **S:** Update architecture documentation to state whether middleware is production, experimental, or test scaffolding.
- Do not split protocol adapters solely to satisfy line counts; split where state machines, transport, formatting, and setup logic have independent invariants.

### 10. Testing strategy

**Hermes approach.** Hermes explicitly prefers real resolution/import paths against a temporary `HERMES_HOME`, because mock-only tests miss integration defects (`AGENTS.md:65–67`, `AGENTS.md:270–276`). Its prescribed runner removes credentials, fixes timezone and locale, redirects homes, and isolates files in subprocesses (`AGENTS.md:311–317`, `tests/conftest.py:457–522`). The rubric also bans tests that merely detect expected source/catalog changes instead of asserting behavior contracts (`AGENTS.md:375–386`). A concrete example loads a real plugin from temporary `HERMES_HOME` and exercises its hook (`tests/test_transform_tool_result_hook.py:136–139`).

**ZeptoClaw today.** ZeptoClaw has substantial test volume and useful real-component coverage. The project snapshot reports 3,512 library tests passing plus doc tests, although I did not rerun them under the read-only constraint (`AGENTS.md:58`). Integration tests use real message buses, session managers, filesystem/shell safety paths, native runtime creation, and actual cron dispatch (`tests/integration.rs:84–90`, `tests/integration.rs:965–1023`, `tests/integration.rs:1025–1064`). Some provider onboarding tests exercise local TCP endpoints rather than mocking method returns (`src/cli/common.rs:802–875`).

The weakness is at system seams:

- The nominal E2E suite declares that it uses mock providers (`tests/e2e.rs:1–14`).
- Its useful agent/tool test runs a real `AgentLoop` but still replaces the provider (`tests/e2e.rs:341–387`).
- The timeout test acknowledges that it does not exercise the production `start()` timeout; it wraps `process_message()` in a separate Tokio timeout and accepts several outcomes (`tests/e2e.rs:411–440`).
- Several "End-to-End Integration Tests" manually reproduce the flow instead of invoking the real agent/channel orchestration (`tests/integration.rs:787–870`).
- Delegate integration coverage mainly tests recursion/config/schema registration rather than a child running through its inherited runtime and tool policy (`tests/integration.rs:1345–1438`).

**Gap.** ZeptoClaw has depth at the unit/component level, but fewer tests prove that registry resolution, provider wire formats, channel adapters, persistence, subprocess policy, and the full agent loop compose correctly. This is exactly where its recent hardening work is most vulnerable to regression.

**Recommendation.**

- **M:** Build a hermetic integration harness with temporary config/workspace/home, scrubbed environment, deterministic time, and local fake HTTP/WebSocket servers.
- **M:** Test the real path: `create_agent` → local provider wire protocol → tool execution → session persistence → outbound bus/channel acknowledgement.
- **M:** Add real plugin discovery and process-protocol tests, including malformed frames, stderr flooding, timeout, crash, inbound messages, and version mismatch.
- **S:** Add invariant tests for stable prompt bytes, invalid-mode fail-closed behavior, child environment scrubbing, and delegated capability non-escalation.
- **S:** Rewrite or rename the current timeout test so its name matches what it actually verifies.
- Do not add credentialed live-provider tests to ordinary CI; local wire-contract tests provide the desired integration coverage without external flakiness.

## Quick wins

- **S:** Change unknown `agent_mode` from `Autonomous` fallback to validation failure or `Assistant` (`src/security/agent_mode.rs:147–160`).
- **S:** Sort tool definitions by name before provider request assembly (`src/tools/registry.rs:206–253`).
- **S:** Add a stable-prefix regression test using two turns with different wall-clock times.
- **S:** Make LTM replacement atomic and deduplicate normalized content (`src/memory/longterm.rs:349–371`).
- **S:** Add `config effective --sources --redact`; existing CLI currently stops at check/reset (`src/cli/config.rs:10–15`).
- **S:** Implement or remove the misleading `swarm.max_depth` behavior claim (`src/config/types.rs:2299–2321`).
- **S:** Qualify README claims for plugin channels and cost-aware delegation until those paths are operational.
- **S:** Add strict `skill lint` while leaving runtime loading tolerant.
- **S:** Make the existing channel-plugin test wait for and validate a response; this immediately exposes the absent acknowledgement path (`src/channels/plugin.rs:899–945`).
- **S:** Replace the simulated agent-timeout test with one that invokes the production `start()` loop (`tests/e2e.rs:411–440`).

## Structural recommendations

### Prompt Envelope and Cache Contract RFC

Define stable, turn-volatile, tool-volatile, and compaction-invalidated prompt regions. Make byte stability observable through hashes and metrics before introducing provider-specific cache controls.

### Extension Host v2 RFC

Unify built-in and external capability descriptors while keeping executable plugins out of process. Cover tools, channels, providers, lifecycle tasks, CLI/setup contributions, compatibility negotiation, and health reporting.

### Unified Agent Pipeline RFC

Complete the existing middleware direction rather than beginning another abstraction. The target should be one production `CoreLoop` with buffered and streaming output strategies, shared hooks, shared convergence logic, and shared policy enforcement.

### Background Execution and Job Model RFC

Create a durable run ledger and acknowledgement model used by cron, reminders, monitors, and spawned agents. Chaining and scripts should build on this substrate, not remain cron-only features.

### Child Capability Model RFC

Represent an agent's effective provider, runtime, tool registry, approvals, secrets, limits, and audit lineage as a capability snapshot. Delegation should only subtract or deliberately substitute capabilities; it must never accidentally gain native execution.

### State Durability RFC

Standardize lock/re-read/atomic-replace/version patterns for memory, cron state, sessions, plugin state, and audit segments. Hermes's store discipline is more transferable than any particular Python storage implementation.

## Verification level

**Read directly:**

- Both root orientation documents: `AGENTS.md`, `CLAUDE.md`, and `README.md`.
- Hermes's area-specific architecture instructions for agent, cron, gateway, CLI, plugins, skills, tools, and TUI/gateway.
- The cited prompt assembly, memory, scheduler, delegation, plugin, channel, configuration, security, runtime, audit, pipeline, and test paths.
- Static file inventory and line counts for ZeptoClaw's `src/`.
- Repository-wide searches for prompt-cache markers, session search, pipeline production use, `env_clear`, subprocess construction, and swarm-depth use.

**Repository state verified:**

- ZeptoClaw HEAD: `6c74d59fc2853cd81df191fb1da02fa514573c8a`.
- Hermes HEAD: `9dd6634c5635321cf38840cc30e9b51226689128`.
- Both worktrees were clean at review start.
- No files were modified, staged, committed, fetched, or generated.

**Inferred rather than measured:**

- The prompt-cache cost conclusion follows from live time and query memory changing the early system-prompt bytes. I did not measure provider cache-hit telemetry or billing.
- Ambient-secret inheritance follows from the cited `Command` construction paths and absence of `env_clear`; I did not launch a child process to inspect its environment.
- The channel-plugin stall risk follows from piping but not draining child output; it was not reproduced dynamically.
- "No equivalent found" statements are based on code and symbol searches, not exhaustive semantic review of all 154,000 Rust lines.

**Not performed:**

- No builds, tests, benchmarks, package installation, network research, provider calls, or external platform validation.
- GitHub issue enumeration was attempted as required by the repository instructions but was unavailable because network access was blocked.
- The deep-research skill normally requests a report artifact, but the read-only constraint prohibited creating one; this response is the complete report.
