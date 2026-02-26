# SyntaxFlow Real-World Rule Examples

Production rules extracted from IRify's built-in rule library (`sfbuildin`). Use these as templates when writing new rules.

## Rule Structure

A complete `.sf` rule has two parts: metadata (`desc(...)`) and the rule logic. For AI-generated on-the-fly queries, only the rule logic is needed. The `desc` block is for persisted rules.

```syntaxflow
// Optional: metadata (only for persisted rules)
desc(
    title: "Rule Title"
    type: vuln       // audit | vuln
    level: high      // info | low | mid | middle | high | critical
    lib: 'rule-name' // makes this rule importable via <include('rule-name')>
)

// Rule logic: search → filter → trace → alert
Runtime.getRuntime().exec(,* as $params);
alert $params for { level: "high", title: "RCE Detected" };
```

---

## Java Rules

### Source: Spring MVC User Input (lib rule)

This is the foundation rule imported by most Java vulnerability rules.

```syntaxflow
// Find all Spring MVC controller method parameters as user input sources
*Mapping.__ref__?{opcode: function} as $start;
$start<getFormalParams>?{opcode: param && !have: this} as $params;
$params?{!<typeName>?{have:'javax.servlet.http'}} as $output;

// Also capture HttpServletRequest.get*() calls
$params?{<typeName>?{have:'javax.servlet.http.HttpServletRequest'}} as $request;
$request.get*() as $output;

alert $output;
```

### RCE: Runtime.exec() Command Injection

```syntaxflow
Runtime.getRuntime().exec(,* as $output);
alert $output for { level: "high", title: "Java Command Execution" };
```

### RCE: Source → Sink with Data Flow

```syntaxflow
<include('java-servlet-param')> as $source;
<include('java-spring-param')> as $source;
check $source;
<include('java-runtime-exec-sink')> as $sink;
<include('java-command-exec-sink')> as $sink;
check $sink;

$sink #{
    include: `<self> & $source`,
    exclude: `<self>?{opcode:call}?{!<self> & $source}`
}->as $high;

alert $high for { message: "Command injection, no filter", level: high };
```

### SQL Injection: StringBuilder.append()

```syntaxflow
*sql*.append(*<slice(start=1)> as $params);
check $params;

$params?{!opcode: const}#{
    hook: `*?{opcode: const && have: 'WHERE'}<show> as $flag`,
}->
alert $flag for { level: "low", title: "SQL String Append" };
```

### SQL Injection: Statement.executeQuery()

```syntaxflow
.createStatement().executeQuery(,* as $params);
check $params;

$params<getCallee>?{<name>?{have:toString}}<getObject>.append(,* as $appendParams)
$params<getFunc><getFormalParams> as $limited
$params + $appendParams as $params

$params?{opcode: param} as $directly
$params?{!opcode: param} #{include: `*?{opcode:param && <self> & $limited}`}-> as $indirectly

$directly + $indirectly as $vuln
alert $vuln for { level: "high", title: "Java SQL Injection" };
```

### SQL Injection: MyBatis ${} with Source-Sink-Filter

```syntaxflow
<include('java-spring-mvc-param')> as $source;
<include("java-common-filter")>() as $filter
<mybatisSink> as $sink

// Trace from sink to source
$sink#{
    until: `* & $source`,
}-> as $result

// Exclude safe primitive types
$result?{<typeName>?{!any: Long,Integer,Boolean,Double}} as $all

// Separate filtered vs unfiltered paths
$all<dataflow(include=`* & $filter`)> as $mid
alert $mid for { level: "mid", message: "MyBatis SQLi, filter exists" };

$all - $mid as $high
alert $high for { level: "high", message: "MyBatis SQLi, NO filter" };
```

### SpEL Expression Injection

```syntaxflow
<include('java-spring-mvc-param')> as $source;
check $source;

SpelExpressionParser()?{<typeName>?{have:'org.springframework.expression.spel'}} as $context;
$context.parseExpression(*<slice(index=1)> as $sink);
$sink #{
    until: `* & $source`,
    exclude: `*?{opcode:call}?{!* & $source}?{!* & $sink}`,
}-> as $mid;

alert $mid for { level: "middle", title: "Spring SpEL Injection" };
```

### Groovy Shell Code Injection

```syntaxflow
<include('java-spring-mvc-param')> as $source;
<include('java-groovy-lang-shell-sink')> as $sink;

$sink #{
    include: `* & $source`,
    exclude: `*?{opcode:call}?{!<self> & $source}?{!<self> & $sink}`,
    exclude: `*?{opcode:phi}`,
}-> as $high;

alert $high for { level: "high", title: "Groovy Shell Code Injection" };
```

### SSRF: Spring → HTTP Client

```syntaxflow
<include('java-spring-param')> as $source;
<include("java-http-sink")> as $sink;

$sink #{
    include: `<self> & $source`,
    exclude: `<self>?{opcode:call}?{!<self> & $source}?{!<self> & $sink}`,
}->as $mid;

alert $mid for { message: "SSRF detected", risk: ssrf, level: mid };
```

### XXE: Missing Security Config

```syntaxflow
DocumentBuilderFactory() as $factory;
$factory?{!(.setFeature)} as $unsafe;
alert $unsafe for { message: "XML parser without security features" };
```

### URL Redirect Detection

```syntaxflow
Controller.__ref__<getMembers>?{.annotation.*Mapping && !.annotation.ResponseBody} as $entryMethods;
$entryMethods<getReturns>?{<typeName>?{have: String}}?{have:'redirect:'} as $sink;
alert $sink for { level: "mid", title: "URL Redirect" };
```

### FreeMarker SSTI

```syntaxflow
*Mapping.__ref__<getFunc><getReturns>?{<typeName>?{have:'String'}}<freeMarkerSink> as $sink
alert $sink;
```

---

## Golang Rules

### Source: HTTP Handler User Input (lib rule)

```syntaxflow
// Gin framework
.Query() as $output;
.PostForm() as $output;
.Param() as $output;
.GetHeader() as $output;

// net/http
.FormValue() as $output;
*.URL.Query().Get() as $output;
alert $output;
```

### SSRF: User Input → http.Get/Do/Post

```syntaxflow
<include('golang-user-input')> as $input;

*.Do(<slice(index=0)>* as $client)
*.Get(<slice(index=0)>* as $client)
*.Post(<slice(index=0)>* as $client)

$client?{* #{until: `*<fullTypeName()>?{have: "net/http"}`}->} as $func
$func.Get(* #-> as $param);

$param #{
    until: "* & $input"
}-> as $mid

alert $mid for { level: "mid", title: "Golang HTTP SSRF" };
```

### XXE: XML Parser Audit

```syntaxflow
xml?{<fullTypeName>?{have: 'encoding/xml'}} as $entry;
$entry.NewDecoder() as $output;

alert $output for { level: "mid", title: "Golang XML XXE Risk" };
```

### SQL Injection: database/sql

```syntaxflow
<include('golang-user-input')> as $input;
<include('golang-database-net-sql-sink')> as $sink;

$sink #{
    until: `* & $input`,
}-> as $result

alert $result for { level: "high", title: "Golang SQL Injection" };
```

---

## PHP Rules

### Source: User Input Parameters

```syntaxflow
// Superglobals
$_GET as $output;
$_POST as $output;
$_REQUEST as $output;
$_COOKIE as $output;
$_FILES as $output;
$_SERVER as $output;
alert $output;
```

### RCE: Dangerous Functions

```syntaxflow
/^(eval|exec|assert|system|shell_exec|pcntl_exec|popen|ob_start)$/ as $output
alert $output for { level: "info", title: "PHP Command Execution Functions" };
```

### Command Injection: Source → Sink

```syntaxflow
<include('php-custom-param')> as $source;
<include('php-os-exec')> as $sink;

$sink #{
    until: `* & $source`,
}-> as $result

alert $result for { level: "high", title: "PHP Command Injection" };
```

### SQL Injection: MySQL

```syntaxflow
<include('php-custom-param')> as $source;

// MySQL query functions as sinks
mysql_query(* as $sink);
mysqli_query(,* as $sink);

$sink #{
    until: `* & $source`,
}-> as $result

alert $result for { level: "high", title: "PHP MySQL Injection" };
```

### XXE: DOMDocument

```syntaxflow
<include('php-custom-param')> as $params;

DOMDocument().loadXML(* as $sink);
DOMDocument().load(* as $sink);

$sink #{
    until: `* & $params`,
}-> as $result

alert $result for { level: "high", title: "PHP DOMDocument XXE" };
```

### File Inclusion

```syntaxflow
<include('php-custom-param')> as $source;

include(* as $sink);
require(* as $sink);
include_once(* as $sink);
require_once(* as $sink);

$sink #{
    until: `* & $source`,
}-> as $result

alert $result for { level: "high", title: "PHP File Inclusion" };
```

---

## C Rules

### Buffer Overflow

```syntaxflow
// Dangerous functions without bounds checking
strcpy(,* as $sink);
strcat(,* as $sink);
gets(* as $sink);
sprintf(,* as $sink);

alert $sink for { level: "high", title: "C Buffer Overflow Risk" };
```

---

## Common Patterns & Techniques

### Pattern 1: Source-Sink with Filter Detection

The standard three-layer pattern: find source, find sink, check if filter exists.

```syntaxflow
<include('java-spring-mvc-param')> as $source;
<include("java-common-filter")>() as $filter;
<some-sink> as $sink;

$sink #{until: `* & $source`}-> as $all
$all<dataflow(include=`* & $filter`)> as $filtered
$all - $filtered as $unfiltered

alert $filtered for { level: "mid", message: "Vuln found but filter exists" };
alert $unfiltered for { level: "high", message: "Vuln found, NO filter" };
```

### Pattern 2: Include + Exclude Traversal

```syntaxflow
$sink #{
    include: `<self> & $source`,                              // must reach source
    exclude: `<self>?{opcode:call}?{!<self> & $source}?{!<self> & $sink}`,  // skip unrelated calls
}-> as $result;
```

### Pattern 3: Variable Arithmetic

```syntaxflow
$a + $b as $merged;     // union: combine results from multiple sources
$all - $safe as $vuln;  // difference: remove safe results to get vulnerable ones
```

### Pattern 4: Type-Based Filtering

```syntaxflow
// Exclude safe primitive types from SQL injection results
$result?{<typeName>?{!any: Long,Integer,Boolean,Double}} as $nonPrimitive

// Check if value belongs to specific framework
$val?{<fullTypeName>?{have:'javax.servlet'}} as $servletTypes
```

### Pattern 5: SCA (Software Composition Analysis)

```syntaxflow
__dependency__.*fastjson.version as $ver;
$ver?{version_in:(0.1.0,1.2.83]} as $vuln
alert $vuln for { level: "high", title: "Vulnerable fastjson version" };
```

### Pattern 6: Cookie Security Check

```syntaxflow
// Check if setcookie() has enough parameters for security flags
setcookie?(*<len>?{<6}) as $insecureCookie
alert $insecureCookie for { level: "mid", title: "Insecure Cookie" };
```

---

## Built-in Include Libraries

For the **complete list** of all 71 `<include('name')>` rules with descriptions, see `builtin-rules.md`.
