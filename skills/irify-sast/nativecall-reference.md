# SyntaxFlow NativeCall Reference

NativeCall is SyntaxFlow's extension mechanism — built-in functions invoked with `<name(args)>` syntax for advanced SSA IR analysis.

## Syntax

```
<nativeCallName(arg1, key="value", ...)>
```

## Quick Reference Table

| NativeCall | Input | Output | Description |
|---|---|---|---|
| `<include>` | — | Values | Import a reusable lib rule by name |
| `<typeName>` | Any value | Strings | Get short type name (without package path) |
| `<fullTypeName>` | Any value | Strings | Get full qualified type name (with package path + version) |
| `<name>` | Any value | Strings | Get name of function/variable/method/field |
| `<string>` | Any value | Strings | Get string representation |
| `<getReturns>` | Function | Values | Get function return values |
| `<getFormalParams>` | Function | Params | Get function formal parameters |
| `<getFunc>` | Any instruction | Function | Get the function containing this instruction |
| `<getCall>` | Function | Call instructions | Get call sites of a function |
| `<getCallee>` | Call instruction | Function | Get the called function from a call instruction |
| `<searchFunc>` | Any value | Functions | Search all call sites of a function across the program |
| `<getObject>` | Member | Object | Get parent object of a member |
| `<getMembers>` | Object | Members | Get all members of an object/class |
| `<getMemberByKey>` | Object | Member | Get specific member by key name |
| `<getSiblings>` | Member | Members | Get sibling members of the same parent object |
| `<getUsers>` | Any value | Instructions | Get all instructions that USE this value |
| `<getPredecessors>` | Any value | Values | Get predecessor nodes (reverse data flow) |
| `<getActualParams>` | Call instruction | Values | Get actual arguments of a call |
| `<getActualParamLen>` | Call instruction | Number | Get number of actual arguments |
| `<slice>` | Container | Subset | Extract element(s) by index/range |
| `<regexp>` | String | Strings | Regex match with group extraction |
| `<strlower>` | String | String | Convert to lowercase |
| `<strupper>` | String | String | Convert to uppercase |
| `<const>` | — | Values | Search constant values in the program |
| `<eval>` | String | Values | Dynamically execute a SyntaxFlow rule string |
| `<fuzztag>` | Template | String | Evaluate a yaklang fuzztag template |
| `<show>` | Any | Same | Debug: print value without side effects |
| `<self>` | Any | Same | Return self (for chaining) |
| `<var>` | Any | Same | Store value into variable table |
| `<delete>` | — | — | Delete a variable |
| `<forbid>` | Any | — | Mark as forbidden; error if value exists |
| `<dataflow>` | After `-->` or `#->` | Values | Extract data flow information with filter |
| `<sourceCode>` | Any instruction | String | Get source code text (with optional context lines) |
| `<opcodes>` | Any value | Strings | Get all opcode types in the containing function |
| `<scanNext>` | Instruction | Instruction | Get next instruction in sequence |
| `<scanPrevious>` | Instruction | Instruction | Get previous instruction in sequence |
| `<scanInstruction>` | Any value | Instructions | Get all instructions in current basic block |
| `<len>` | Container | Number | Get length of array/list/params |
| `<root>` | Any member/call chain | Value | Get root object of a call chain |
| `<versionIn>` | Version string | Boolean | Check if version is in a range |
| `<mybatisSink>` | — | Values | Find MyBatis unsafe `${}` SQL injection sinks |
| `<freeMarkerSink>` | — | Values | Find FreeMarker template injection sinks |
| `<javaUnescapeOutput>` | — | Values | Find unescaped output in JSP/Thymeleaf (XSS) |
| `<isSanitizeName>` | Function/Call | Boolean | Check if name matches sanitizer patterns |
| `<getCurrentBlueprint>` | Function | Blueprint | Get current function's class blueprint |
| `<getBluePrint>` | Any value | Blueprint | Get type blueprint (class structure) |
| `<getParentsBlueprint>` | Class | Blueprints | Get parent class blueprints |
| `<getInterfaceBlueprint>` | Class | Blueprints | Get implemented interface blueprints |
| `<getRootParentBlueprint>` | Class | Blueprint | Get root ancestor class blueprint |
| `<extendsBy>` | Class | Boolean | Check if class extends another |
| `<FilenameByContent>` | Any value | String | Get filename where value is defined |
| `<getFullFileName>` | — | Strings | Find files by glob pattern |
| `<foreach_function_inst>` | Function | Values | Iterate all instructions in a function with hook |

---

## Detailed Usage & Examples

### include — Import Reusable Rules

The most frequently used NativeCall. Import a lib rule declared with `lib: 'rule-name'` in its `desc`.

```syntaxflow
// Import Spring MVC user input sources
<include('java-spring-mvc-param')> as $source;

// Import common filter/sanitizer functions
<include("java-common-filter")>() as $filter

// Import command execution sinks
<include('java-runtime-exec-sink')> as $sink;

// Import Go HTTP handler input sources
<include('golang-user-input')> as $input;
```

**Combining includes for vulnerability detection:**

```syntaxflow
<include('java-spring-param')> as $source;
<include("java-http-sink")> as $sink;

$sink #{
    include: `<self> & $source`,
    exclude: `<self>?{opcode:call}?{!<self> & $source}?{!<self> & $sink}`,
}->as $mid;
alert $mid for { message: "SSRF detected", level: mid };
```

### typeName / fullTypeName — Type Inspection

```syntaxflow
// Short type name (class name + simple names)
JSON.parse<typeName()> as $name
// Results: ["JSON", "com.alibaba.fastjson.JSON"]

// Full qualified name (with package path, version info)
JSON.parse<fullTypeName()> as $name
// Results: ["com.alibaba.fastjson.JSON"]

// Filter by type in conditions
$vals?{<typeName>?{have:'String'}} as $strings
$vals?{<fullTypeName>?{have:'javax.servlet'}} as $servletTypes
$result?{<typeName>?{!any: Long,Integer,Boolean,Double}} as $nonPrimitive
```

### getReturns — Function Return Values

```syntaxflow
// Get return values of a function
HHHHH<getReturns> as $returnVals;

// Real-world: URL redirect detection
Controller.__ref__<getMembers>?{.annotation.*Mapping && !.annotation.ResponseBody} as $entryMethods;
$entryMethods<getReturns>?{<typeName>?{have: String}}?{have:'redirect:'} as $sink;

// FreeMarker SSTI detection
*Mapping.__ref__<getFunc><getReturns>?{<typeName>?{have:'String'}}<freeMarkerSink> as $sink
```

### getFormalParams — Function Parameters

```syntaxflow
// Get formal parameters (excluding 'this')
$start<getFormalParams>?{opcode: param && !have: this} as $params;

// Servlet parameters
/(do(Get|Post|Delete|Filter|[A-Z]\w+))|(service)/<getFormalParams>?{!have: this && opcode: param} as $req;

// Spring MVC annotated method parameters
*Mapping.__ref__<getFormalParams>?{opcode: param && !have: this} as $ref
```

### getFunc — Enclosing Function

```syntaxflow
// Get the function containing a value
$sink?{<getFunc><getCurrentBlueprint><fullTypeName>?{any: "Controller","controller"}} as $output

// Check function return type
$params?{<getFunc><getReturns><typeName>?{have: ResponseEntity}} as $entry;
```

### getCall / getCallee — Call Graph Navigation

```syntaxflow
// getCall: Find call sites using this function
$entry.Open<getCall> as $db;

// getCallee: Get the called function from a call instruction
$params<getCallee>?{<name>?{have:toString}}<getObject>.append(,* as $appendParams)

// Chain for function name extraction
aArgs<getCall><getCallee><name> as $funcName
```

### getObject / getMembers / getMemberByKey

```syntaxflow
// getObject: Navigate to parent object
.b<getObject>.c as $sibling;
.readObject?{<typeName>?{have:'java.beans.XMLDecoder'}}<getObject()> as $decoder;

// getMembers: Get all members of a class
Controller.__ref__<getMembers>?{.annotation.*Mapping} as $entryMethods;
$entry.Open()<getMembers> as $client;

// getMemberByKey: Get specific member
$sink<getMemberByKey(key="password")> as $obj
```

### slice — Parameter Extraction

```syntaxflow
// By index
hijackHTTPRequest<slice(index=0)> as $param0
.parse(*<slice(index=1)> as $firstArg)

// From index (inclusive)
*sql*.append(*<slice(start=1)> as $params);
ldap_bind(*<slice(start=2)>?{opcode: const} as $pass)
```

### regexp — Regex on Strings

```syntaxflow
// Extract MyBatis ${} parameter names
.annotation.Select.value<regexp(\$\{\s*(\w+)\s*\}, group=1)> as $entry;

// Extract groups from strings
"abc123def"<regexp(`(\d+)`, group: 1)> as $numbers;
```

### const — Search Constants

```syntaxflow
// Glob match
<const(g="127*")> as $output           // matches "127.0.0.1"

// Regex match
<const(r="^\d+\.\d+\.\d+\.\d+$")> as $ips

// Exact match
<const(e="127.0.0.1")> as $exact

// Sugar syntax
"127*" as $glob       // glob match
e"127.0.0.1" as $ex   // exact match
```

### getUsers — Who Uses This Value

```syntaxflow
// Check if return value is actually used
$toCheck?{!<getUsers>} as $unusedReturn;

// Check if null check exists (with depth)
$val?{!<getUsers(depth=2)>?{opcode:if}} as $unchecked

// Lock check: is tryLock() result checked?
.tryLock()?{!<getUsers>} as $weak;
```

### getPredecessors — Reverse Data Flow

```syntaxflow
// Get data predecessor
a.b as $b
$b<getPredecessors> as $origin   // traces back to source
```

### dataflow — Data Flow Filtering

Used after `-->` or `#->` to filter data flow paths:

```syntaxflow
// Check if filter exists in the data flow path
$result<dataflow(include=`* & $filter`)> as $filtered
$result - $filtered as $unfiltered   // truly vulnerable paths
```

### sourceCode — Get Source Text

```syntaxflow
bb1<sourceCode> as $code;                  // just the statement
bb2<sourceCode(context=3)> as $withCtx;    // with 3 lines context
```

### len — Container Length

```syntaxflow
// Filter calls by argument count
a?(*<len>?{==2}) as $twoArgCalls
setcookie?(*<len>?{<6}) as $insecureCookie
```

### root — Call Chain Root

```syntaxflow
// a.b().c.d() → root is "a"
.d<root> as $rootObj
```

### versionIn — Dependency Version Check

```syntaxflow
__dependency__.*fastjson.version as $ver;
$ver?{version_in:(0.1.0,1.3.0]} as $vuln       // open-closed range
$ver?{version_in:[1.0,2.0)} as $vuln            // closed-open range
$ver?{version_in:(1.0,2.0]||(3.0,4.0]} as $vuln // union ranges
```

### foreach_function_inst — Iterate Function Instructions

```syntaxflow
main<foreach_function_inst(hook=<<<CODE
*?{opcode: const} as $output
CODE)>
```

### mybatisSink — MyBatis SQL Injection Sinks

```syntaxflow
<mybatisSink> as $sink;   // finds all ${} usages in MyBatis XML/annotations
```

### javaUnescapeOutput — XSS Detection in Templates

```syntaxflow
<javaUnescapeOutput> as $sink;   // finds ${expr} in JSP / <%= expr %> / th:utext
```

### extendsBy — Inheritance Check

```syntaxflow
Dog<extendsBy($Animal)> as $isDog;    // checks if Dog extends Animal
```

### searchFunc — Global Function Search

```syntaxflow
aArgs<getCall><searchFunc> as $allCalls;   // find all calls to the same function
```

### FilenameByContent / getFullFileName — File Location

```syntaxflow
A<FilenameByContent> as $file;                      // "a.java"
<getFullFileName(filename="*/a*")> as $files;       // glob file search
```
