# IRify SAST Skill

AI agent skill for deep static analysis using [IRify](https://github.com/yaklang/yaklang)'s SSA compiler and SyntaxFlow query engine.

## What It Does

Gives your AI coding agent the ability to:

- **Compile** source code into SSA (Static Single Assignment) IR
- **Query** data flow paths using SyntaxFlow DSL
- **Detect** vulnerabilities: SQL injection, command injection, XXE, and more
- **Track** taint propagation across function boundaries
- **Incrementally recompile** after code changes (only diff files)

Supported languages: Java, PHP, JavaScript, Go, Python, C, Yak

## Install

### Via [npx skills](https://github.com/vercel-labs/skills)

```bash
npx skills add yaklang/irify-sast-skill
```

### Manual

Copy `skills/irify-sast/SKILL.md` to your agent's skill directory:

| Agent | Path |
|-------|------|
| Claude Code | `.claude/skills/irify-sast/` |
| Codex | `.agents/skills/irify-sast/` |
| Cursor | `.agents/skills/irify-sast/` |
| Others | See [supported agents](https://github.com/vercel-labs/skills#supported-agents) |

## Prerequisites

1. Install [yaklang](https://github.com/yaklang/yaklang) (`yak` binary in PATH)
2. Configure MCP server in your agent:

**Codex** (`~/.codex/config.toml`):
```toml
[mcp_servers.yaklang-ssa]
command = "yak"
args = ["mcp", "-t", "ssa"]
```

**Claude Code / Cursor / others**:
```json
{ "command": "yak", "args": ["mcp", "-t", "ssa"] }
```

## Quick Example

```
You: "Check if there's command injection in this Java project"

Agent:
1. ssa_compile(target="/path/to/project", language="java", program_name="myapp")
2. ssa_query(program_name="myapp", rule=`
     Runtime.getRuntime().exec(* #-> * as $source) as $sink;
     check $source then "found taint source";
     alert $sink;
   `)
→ Reports: exec() at line 97 receives user input from @RequestParam("cmd")
```

## License

MIT
