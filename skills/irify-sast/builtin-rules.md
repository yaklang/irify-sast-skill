# SyntaxFlow Built-in Include Rules

All available `<include('rule-name')>` lib rules shipped with IRify. Use these to avoid writing source/sink/filter detection from scratch.

**Usage:**

```syntaxflow
<include('rule-name')> as $variable;
```

---

## Java (49 rules)

### User Input Sources

| Include Name | Description |
|---|---|
| `java-spring-mvc-param` | Spring MVC controller parameters: @RequestParam, @PathVariable, @RequestHeader, @CookieValue, @RequestBody, @ModelAttribute + HttpServletRequest.get*() |
| `java-servlet-param` | Servlet doGet/doPost/doFilter formal parameters (HttpServletRequest, HttpServletResponse) |

### Command Execution Sinks

| Include Name | Description |
|---|---|
| `java-runtime-exec-sink` | `Runtime.getRuntime().exec()` calls |
| `java-process-builder-sink` | `ProcessBuilder` command execution |
| `java-command-exec-sink` | Third-party command execution: Apache Commons Exec, etc. |

### Code Execution Sinks

| Include Name | Description |
|---|---|
| `java-groovy-lang-shell-sink` | `GroovyShell.evaluate()`, `.parse()`, `.run()` |
| `java-js-sink` | `ScriptEngineManager` / `ScriptEngine.eval()` (JavaScript engine) |

### SQL Sinks

| Include Name | Description |
|---|---|
| `java-jdbc-raw-execute-sink` | `Statement.executeQuery()`, `.execute()`, `.executeUpdate()` (raw JDBC) |
| `java-jdbc-prepared-execute-sink` | `PreparedStatement` execution (parameterized, generally safe) |

### HTTP Client Sinks (SSRF)

| Include Name | Description |
|---|---|
| `java-http-sink` | **Aggregated**: includes all HTTP client sinks below |
| `java-apache-http-request-url` | Apache HttpComponents `HttpGet`, `HttpPost`, etc. |
| `java-apache-commons-httpclient` | Apache Commons HttpClient |
| `java-okhttpclient-request-execute` | OkHttp `Request.Builder` → `client.newCall().execute()` |
| `java-net-url-connect` | `java.net.URL.openConnection()` |
| `java-image-io-read-url` | `ImageIO.read(URL)` |
| `java-http-fluent-request` | Apache HttpClient Fluent API |
| `java-alibaba-druid-httpclientutil` | Alibaba Druid `HttpClientUtil` |
| `java-spring-rest-template-request-params` | Spring `RestTemplate` request parameters |

### File Operation Sinks

| Include Name | Description |
|---|---|
| `java-read-filename-sink` | File read operations: `FileInputStream`, `FileReader`, `Files.readAllBytes()`, etc. |
| `java-write-filename-sink` | File write operations: `FileOutputStream`, `FileWriter`, `Files.write()`, etc. |
| `java-delete-filename-sink` | File delete operations: `File.delete()`, `Files.delete()`, etc. |

### Spring Framework

| Include Name | Description |
|---|---|
| `java-spring-multipartfile-transferTo-target` | Spring `MultipartFile.transferTo()` target path (file upload) |

### Filters & Sanitizers

| Include Name | Description |
|---|---|
| `java-common-filter` | Common sanitization/filter functions (escape, encode, sanitize, validate, etc.) |
| `java-escape-method` | Escape/encoding methods (htmlEscape, urlEncode, etc.) |
| `java-filter-hostname-prefix` | Hostname prefix filtering (SSRF mitigation) |
| `is-contain-sanitizer` | General sanitizer detection by name pattern |

### Logging

| Include Name | Description |
|---|---|
| `java-log-record` | Log recording sinks: `logger.info()`, `.warn()`, `.error()`, etc. |

### NativeCall (not `<include>`, invoked directly)

| NativeCall | Description |
|---|---|
| `<mybatisSink>` | MyBatis `${}` unsafe parameter sinks (XML mapper + annotations) |
| `<freeMarkerSink>` | FreeMarker template injection sinks |
| `<javaUnescapeOutput>` | JSP `${expr}`, `<%= expr %>`, Thymeleaf `th:utext` unescaped output (XSS) |

---

## Golang (28 rules)

### User Input Sources

| Include Name | Description |
|---|---|
| `golang-user-input` | **Aggregated**: includes all Go input sources below |
| `golang-http-source` | `r.URL.Query().Get()`, `r.FormValue()`, `r.Header.Get()` (net/http) |
| `golang-http-gin` | Gin framework: `c.Query()`, `c.PostForm()`, `c.Param()`, `c.GetHeader()` |
| `golang-http-net` | net/http `HandleFunc` handler parameters |
| `golang-gin-context` | Gin `*gin.Context` parameter extraction |

### HTTP Client Sinks (SSRF)

| Include Name | Description |
|---|---|
| `golang-http-sink` | `http.Get()`, `http.Post()`, `client.Do()` |

### Command Execution Sinks

| Include Name | Description |
|---|---|
| `golang-os-exec` | `exec.Command()`, `os/exec` package |

### SQL Database Sinks

| Include Name | Description |
|---|---|
| `golang-database-sink` | **Aggregated**: includes all Go DB sinks below |
| `golang-database-sql` | `database/sql` package: `db.Query()`, `db.Exec()` |
| `golang-database-sqlx` | `sqlx` package |
| `golang-database-gorm` | GORM ORM |
| `golang-database-pop` | Pop ORM |
| `golang-database-reform` | Reform ORM |

### File Operation Sinks

| Include Name | Description |
|---|---|
| `golang-file-read-sink` | **Aggregated**: all file read sinks |
| `golang-file-read-path-sink` | **Aggregated**: file read path parameter sinks |
| `golang-file-read-os` | `os.Open()`, `os.ReadFile()` |
| `golang-file-read-ioutil` | `ioutil.ReadFile()`, `ioutil.ReadAll()` |
| `golang-file-read-bufio` | `bufio.NewReader()` file reading |
| `golang-file-read-path-os` | File read path via os package |
| `golang-file-read-path-ioutil` | File read path via ioutil package |
| `golang-file-read-path-bufio` | File read path via bufio package |
| `golang-file-write-sink` | **Aggregated**: all file write sinks |
| `golang-file-write-path-sink` | **Aggregated**: file write path parameter sinks |
| `golang-file-write-os` | `os.Create()`, `os.WriteFile()` |
| `golang-file-write-ioutil` | `ioutil.WriteFile()` |
| `golang-file-write-bufio` | `bufio.NewWriter()` file writing |
| `golang-file-write-path-os` | File write path via os package |
| `golang-file-write-path-ioutil` | File write path via ioutil package |
| `golang-file-write-path-bufio` | File write path via bufio package |

### Other Sinks

| Include Name | Description |
|---|---|
| `golang-xml-sink` | `encoding/xml` NewDecoder (XXE risk) |
| `golang-ldap-sink` | LDAP query sinks |
| `golang-ftp-sink` | FTP operation sinks |
| `golang-os-sink` | `os` package file operations |
| `golang-file-path` | File path manipulation |
| `golang-fmt-print` | `fmt.Print/Println/Fprintf` output sinks |

---

## PHP (8 rules)

### User Input Sources

| Include Name | Description |
|---|---|
| `php-param` | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` superglobals |
| `php-tp-all-extern-variable-param-source` | ThinkPHP framework `input()`, `Request::param()` |

### Sinks

| Include Name | Description |
|---|---|
| `php-os-exec` | `eval`, `exec`, `assert`, `system`, `shell_exec`, `pcntl_exec`, `popen`, `ob_start` |
| `php-file-read` | File read functions: `file_get_contents`, `fread`, `readfile`, etc. |
| `php-file-write` | File write functions: `file_put_contents`, `fwrite`, etc. |
| `php-file-unlink` | File delete: `unlink()` |
| `php-xss-method` | XSS output sinks: `echo`, `print`, `printf`, etc. |

### Filters

| Include Name | Description |
|---|---|
| `php-filter-function` | PHP filter/sanitize functions: `htmlspecialchars`, `addslashes`, `filter_var`, etc. |

---

## C (2 rules)

| Include Name | Description |
|---|---|
| `c-user-input` | C user input functions: `scanf`, `gets`, `fgets`, `getenv`, etc. |
| `c-file-path` | File path parameters in C file operations |

---

## Aggregated Rules

Some rules are "aggregators" — they `<include()>` multiple sub-rules into one. Use these for broad detection:

| Language | Aggregated Rule | Includes |
|---|---|---|
| Java | `java-http-sink` | All 8 Java HTTP client libraries |
| Golang | `golang-user-input` | `golang-http-source` + `golang-http-gin` + `golang-http-net` |
| Golang | `golang-database-sink` | `golang-database-sql` + `sqlx` + `gorm` + `pop` + `reform` |
| Golang | `golang-file-read-sink` | All `golang-file-read-*` sub-rules |
| Golang | `golang-file-write-sink` | All `golang-file-write-*` sub-rules |
| Golang | `golang-file-read-path-sink` | All `golang-file-read-path-*` sub-rules |
| Golang | `golang-file-write-path-sink` | All `golang-file-write-path-*` sub-rules |

**Tip**: Prefer aggregated rules for broad scans. Use specific sub-rules when you only need one library.

---

## Usage Patterns

### Basic Source-Sink

```syntaxflow
<include('java-spring-mvc-param')> as $source;
<include('java-runtime-exec-sink')> as $sink;

$sink #{until: `* & $source`}-> as $vuln
alert $vuln for { level: "high", title: "RCE" };
```

### Source-Sink with Filter

```syntaxflow
<include('java-spring-mvc-param')> as $source;
<include('java-common-filter')>() as $filter;
<include('java-jdbc-raw-execute-sink')> as $sink;

$sink #{until: `* & $source`}-> as $all
$all<dataflow(include=`* & $filter`)> as $filtered
$all - $filtered as $unfiltered

alert $unfiltered for { level: "high", title: "SQLi (no filter)" };
alert $filtered for { level: "mid", title: "SQLi (filter exists)" };
```

### Multiple Sources / Multiple Sinks

```syntaxflow
<include('java-servlet-param')> as $source;
<include('java-spring-mvc-param')> as $source;
check $source;

<include('java-runtime-exec-sink')> as $sink;
<include('java-command-exec-sink')> as $sink;
check $sink;

$sink #{include: `<self> & $source`}-> as $result;
alert $result;
```
