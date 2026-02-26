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

### Step 4: Self-Healing Query (auto-retry on syntax error)

When `ssa_query` returns a SyntaxFlow parsing error:
1. **DO NOT** apologize to the user or ask for help
2. Read the error message carefully — it contains the exact parse error position and expected tokens
3. Fix the SyntaxFlow rule based on the error
4. Re-invoke `ssa_query` with the corrected rule
5. Repeat up to **3 times** before reporting failure to the user
6. If all retries fail, show the user: the original rule, each attempted fix, and the final error

This is critical — SyntaxFlow has strict syntax and minor mistakes (missing semicolons, wrong operator) are common. The agent should self-correct silently.

## When to Use

| Scenario | Tool |
|---|---|
| Data flow: "where does user input go?" | **IRify (SSA + SyntaxFlow)** |
| Cross-procedure taint tracking | **IRify (SSA + SyntaxFlow)** |
| Vulnerability detection (SQLi, RCE, XXE) | **IRify (SSA + SyntaxFlow)** |
| Simple text search | grep |
| Go-to-definition, find-references | LSP |

## Data Flow Visualization

After obtaining query results, present data flow paths visually to the user.

### Default View: Source → Sink Summary

Show a clean summary first — one line per taint path, no noise:

```
🔴 Taint Path #1
   Source: request.getParameter("cmd")        → CommandController.java:42
   Sink:   Runtime.getRuntime().exec(cmd)     → CommandController.java:97

🔴 Taint Path #2
   Source: request.getParameter("query")      → UserDAO.java:15
   Sink:   stmt.executeQuery(sql)             → UserDAO.java:38
```

Rules:
- Show **Source** (where data enters) and **Sink** (where data is consumed dangerously)
- Include **file:line** for each
- If >5 paths, group by sink type and show count: `"exec() — 3 paths, executeQuery() — 2 paths"`
- Omit intermediate nodes by default

### Progressive Disclosure: Expand on Request

When the user asks for details on a specific path (e.g. "show me path #1"), expand to full trace:

```
🔴 Taint Path #1 — Full Trace

   ① [SOURCE]  request.getParameter("cmd")          CommandController.java:42
       ↓
   ② [ASSIGN]  String cmd = request.getParameter..   CommandController.java:42
       ↓
   ③ [CALL]    processCommand(cmd)                   CommandController.java:45
       ↓
   ④ [PARAM]   processCommand(String input)          CommandService.java:12
       ↓
   ⑤ [CALL]    Runtime.getRuntime().exec(input)      CommandService.java:18
       ↓
   ⑥ [SINK]    exec(input)                           CommandService.java:18
```

Rules:
- Number each step
- Tag each node: `[SOURCE]`, `[ASSIGN]`, `[CALL]`, `[PARAM]`, `[SINK]`
- Show cross-procedure jumps clearly (file changes)
- If the trace is >10 steps, collapse middle steps with `... (3 intermediate steps)` and offer to expand

## Proactive Security Insights

After running a query and finding results, **proactively** raise follow-up questions and suggestions. Do NOT just dump results and stop.

### When vulnerabilities are found:

1. **Suggest fix**: "This exec() call receives unsanitized user input. Consider using a whitelist or ProcessBuilder with explicit argument separation."
2. **Ask related questions**:
   - "Should I check if there are other endpoints that also call `Runtime.exec()`?"
   - "Want me to trace whether any input validation/sanitization exists between the source and sink?"
   - "Should I look for similar patterns in other controllers?"
3. **Cross-reference**: If one vulnerability type is found, proactively scan for related types:
   - Found RCE → "I also checked for SSRF and found 2 potential issues. Want details?"

### When no results are found:

1. Don't just say "no results" — explain WHY:
   - "No direct `exec()` calls found, but I see `ProcessBuilder` usage. Want me to check those instead?"
   - "The query matched 0 sinks. This could mean the code uses a framework abstraction — want me to search for framework-specific patterns?"
2. Suggest alternative queries

### When results are ambiguous:

1. Ask for clarification: "I found 8 data flow paths to `executeQuery()`, but 5 use parameterized queries (safe). Want me to filter to only the 3 using string concatenation?"

## Companion Reference Files

This skill includes detailed reference documents. **Read them when needed** using the `Read` tool:

| File | When to Read | Path (relative to this file) |
|---|---|---|
| **Built-in Rules** | When writing rules — lists all 71 `<include('name')>` lib rules by language, with descriptions. **Read this first** to find existing source/sink/filter rules you can reuse | `builtin-rules.md` |
| **NativeCall Reference** | When writing rules that need `<nativeCallName()>` functions — contains all 40+ NativeCall functions with syntax, parameters, and examples | `nativecall-reference.md` |
| **SyntaxFlow Examples** | When writing new rules — contains 20+ production rules from IRify's built-in library covering Java/Go/PHP/C, organized by vulnerability type | `syntaxflow-examples.md` |

**How to use**: Before writing a SyntaxFlow rule, read the relevant companion files:
- Need to detect SQL injection? → Read `builtin-rules.md` to find include names, then `syntaxflow-examples.md` for rule patterns
- Need `<getMembers>` or `<typeName>`? → Read `nativecall-reference.md` for function details
- Need to know what sources/sinks exist for a language? → Read `builtin-rules.md`

## SyntaxFlow Quick Reference

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
$val #{
  include: `*?{opcode: const}`
}-> as $constSources                  // filter during trace
$sink #{
  until: `* & $source`,              // stop when reaching source
}-> as $reachable
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
$a + $b as $merged;                                    // union
$all - $safe as $vuln;                                 // difference
```

### NativeCall (40+ built-in functions)

Most commonly used — see `nativecall-reference.md` for full list:

```
<include('rule-name')>         // import lib rule
<typeName()>                   // get short type name
<fullTypeName()>               // get full qualified type name
<getReturns>                   // function return values
<getFormalParams>              // function parameters
<getFunc>                      // enclosing function
<getCall>                      // find call sites
<getCallee>                    // get called function
<getObject>                    // parent object
<getMembers>                   // object members
<name>                         // get name
<slice(index=N)>               // extract by index
<mybatisSink>                  // MyBatis SQL injection sinks
<dataflow(include=`...`)>      // filter data flow paths
```

## Tips

1. `#->` = "where does this come from?", `-->` = "where does this go?"
2. Use `*` for params, don't hardcode names
3. SSA resolves assignments: `a = getRuntime(); a.exec(cmd)` = `getRuntime().exec(cmd)`
4. Use `opcode` filters to distinguish constants / parameters / calls
5. Combine `check` + `alert` for actionable results
6. After code changes, use `base_program_name` (not `re_compile`) for fast incremental updates
7. Before writing a new rule, **read `syntaxflow-examples.md`** to find similar patterns
8. When unsure about a NativeCall, **read `nativecall-reference.md`** for usage and examples
