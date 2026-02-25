---
name: irify-sast
description: >
  IRify SAST — AI-powered static application security testing.
  Compile source code into SSA IR, then use SyntaxFlow DSL to trace data flow across function boundaries,
  detect vulnerabilities (SQLi, RCE, XXE), and answer questions like "where does user input go?".
  Supports 7 languages (Java, PHP, JS, Go, Python, C, Yak) and incremental compilation via ProgramOverLay.
  Requires yaklang MCP server: yak mcp -t ssa
allowed-tools:
  - mcp__yaklang-ssa__ssa_compile
  - mcp__yaklang-ssa__ssa_query
  - Read
  - Glob
  - Grep
---

# IRify SAST

Deep static analysis skill powered by IRify's SSA compiler and SyntaxFlow query engine.

## Prerequisites

This skill requires the yaklang MCP server. Configure it in your agent's MCP settings:

```toml
# Codex: ~/.codex/config.toml
[mcp_servers.yaklang-ssa]
command = "yak"
args = ["mcp", "-t", "ssa"]
```

```json
// Claude Code / Cursor / others
{ "command": "yak", "args": ["mcp", "-t", "ssa"] }
```

## Workflow

### Step 1: Compile (once per project)

```
ssa_compile(target="/path/to/project", language="java", program_name="MyProject")
→ full compilation, returns program_name
```

### Step 2: Query (unlimited, no recompile needed)

```
ssa_query(program_name="MyProject", rule="<SyntaxFlow rule>")
```

### Step 3: Code Changed — Incremental Compile

```
ssa_compile(target="/path/to/project", language="java", base_program_name="MyProject")
→ only changed files recompiled, ProgramOverLay merges base + diff layers
→ returns NEW program_name for subsequent queries
```

**IMPORTANT**: Use `base_program_name` for incremental compilation. `re_compile=true` is a full recompile that discards all data — only use it to start completely fresh.

## When to Use

| Scenario | Tool |
|---|---|
| Data flow: "where does user input go?" | **IRify (SSA + SyntaxFlow)** |
| Cross-procedure taint tracking | **IRify (SSA + SyntaxFlow)** |
| Vulnerability detection (SQLi, RCE, XXE) | **IRify (SSA + SyntaxFlow)** |
| Simple text search | grep |
| Go-to-definition, find-references | LSP |

## SyntaxFlow Language Reference

### Search & Match

```
documentBuilder          // variable name
.parse                   // method name (dot prefix)
documentBuilder.parse    // chain
*config*                 // glob pattern
/(get[A-Z].*)/           // regex pattern
```

### Function Call & Parameters

```
.exec()                           // match any call
.exec(* as $params)               // capture all params
.parse(*<slice(index=1)> as $a1)  // capture by index
```

### Data Flow Operators

| Operator | Direction | Use |
|----------|-----------|-----|
| `#>` | Up 1 level | Direct definition |
| `#->` | Up recursive | **Trace to origin** — "where does this COME FROM?" |
| `->` | Down 1 level | Direct usage |
| `-->` | Down recursive | **Trace to final usage** — "where does this GO TO?" |

```
.exec(* #-> * as $source)            // trace param origin
$userInput --> as $sinks              // trace where value goes
$sink #{depth: 5}-> as $source       // depth-limited trace
$req -{
  hook: `*.getParameter() as $params`
}->;                                  // capture intermediates
$val #{
  include: `*?{opcode: const}`
}-> as $constSources                  // filter during trace
```

### Filters `?{...}`

```
$vals?{opcode: call}                // by opcode: call/const/param/phi/function/return
$vals?{have: 'password'}            // by string content
$vals?{!opcode: const}              // negation
$vals?{opcode: call && have: 'sql'} // combined
$factory?{!(.setFeature)}           // method NOT called on value
```

### Variable, Check & Alert

```
.exec() as $sink;                                      // assign
check $sink then "found" else "not found";             // assert
alert $sink for { title: "RCE", level: "high" };       // mark finding
```

## Common Patterns

### Command Injection (RCE)

```
Runtime.getRuntime().exec(* #-> * as $source) as $sink;
check $source then "found taint source";
alert $sink;
```

### SQL Injection

```
*sql*.append(*<slice(start=1)> as $params);
$params?{!opcode: const}#{
    hook: `*?{opcode: const && have: 'WHERE'}<show> as $flag`,
}->
alert $flag;
```

### Missing Security Config (XXE)

```
DocumentBuilderFactory() as $factory;
$factory?{!(.setFeature)} as $unsafe;
alert $unsafe for { message: "XML parser without security features" };
```

### Cross-Procedure Taint Tracking

```
GroovyShell().evaluate(* as $cmd)
$cmd #-> * as $source
check $source then "found source" else "no source found"
```

## Tips

1. `#->` = "where does this come from?", `-->` = "where does this go?"
2. Use `*` for params, don't hardcode names
3. SSA resolves assignments: `a = getRuntime(); a.exec(cmd)` = `getRuntime().exec(cmd)`
4. Use `opcode` filters to distinguish constants / parameters / calls
5. Combine `check` + `alert` for actionable results
6. After code changes, use `base_program_name` (not `re_compile`) for fast incremental updates
