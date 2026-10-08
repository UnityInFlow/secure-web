# Configuration contract v1

File: `secure-web.yaml` (search order: `--config <path>`, `./secure-web.yaml`, `~/.secure-web/config.yaml`,
built-in defaults). Env override: `SECURE_WEB__<SECTION>__<KEY>` (double underscore), e.g.
`SECURE_WEB__FETCH__MAX_PAGE_BYTES=2MB`. Unknown keys are a **hard error** (deny unknown fields).

Durations accept `5s`, `250ms`, `2m` (strings only); sizes accept `5MB`, `512KB`, plain bytes.
`KB`/`MB`/`GB` are decimal (`5MB` = 5 000 000 bytes); `KiB`/`MiB`/`GiB` are binary.
Env override values are typed as YAML booleans, numbers or `[a, b]` lists when they parse as such,
otherwise taken as plain strings. An override naming an unknown key is a hard error, like the file.

```yaml
server:
  listen: 127.0.0.1:8787          # MCP streamable HTTP endpoint at /mcp; refuse non-loopback unless server.allowRemote=true
  allowRemote: false
  workspace: ~/.secure-web        # runs/ and private-audit/ live here

fetch:
  userAgent: "SecureWeb/0.1 (+https://github.com/UnityInFlow/secure-web)"
  connectTimeout: 5s
  requestTimeout: 20s
  maxRedirects: 5
  allowRedirectDowngrade: false
  maxPageBytes: 5MB               # decompressed
  maxJsonBytes: 1MB
  perHostConcurrency: 4
  minDelayPerHost: 0ms
  respectRetryAfter: true

extract:
  maxSecurityTextBytes: 2MB
  maxLinksPerPage: 2000
  maxDisplayBytes: 1MB

crawl:
  maxDepth: 2                     # hard max 5
  maxPages: 100                   # hard max 1000
  maxTotalBytes: 100MB
  maxDuration: 120s
  concurrency: 8
  maxFrontier: 10000
  scope: SAME_ORIGIN              # SAME_ORIGIN | ALLOWLIST
  allowedHosts: []
  stripQueryParams: [utm_source, utm_medium, utm_campaign, utm_term, utm_content, fbclid, gclid]
  robots:                         # v0.2
    enabled: true
    cacheTtl: 1h

security:
  scanner:
    executable: injection-scanner # resolved on PATH or absolute
    timeout: 2s
    failurePolicy: block          # only accepted value
  injection:
    critical: block
    high: block
    medium: warn
    low: allow
  warnHandling: store             # store | quarantine
  network:
    blockPrivateAddresses: true   # cannot be set to false in v0.1 (config error)
    blockLinkLocal: true          # same
    validateRedirects: true       # same
    extraBlockedCidrs: []         # "addr/prefix" (v4 or v6); an invalid entry fails startup
    extraBlockedHosts: []         # blocks the host and all its subdomains; normalized like a URL
                                  # host (IDNA to ASCII, lower case, trailing dots ignored). IP
                                  # literals, ports, wildcards, a leading dot or empty labels
                                  # fail startup: put IPs in extraBlockedCidrs

search:                           # v0.2
  provider: none                  # none | brave | searxng
  maxResults: 10

debug:
  retainRaw: false
  logLevel: info

```

Startup validation (`secure-web-core::config::validate`):
- reject `security.scanner.failurePolicy != block`, `security.injection.critical` or `.high` other
  than `block` (CRITICAL/HIGH always block, `docs/security-policy.md` §5), any `security.network.*`
  boolean set to false, `crawl.maxDepth > 5`, `crawl.maxPages > 1000`, a zero `crawl.maxPages`,
  `crawl.maxDuration`, `crawl.concurrency`, `crawl.maxFrontier` or `crawl.maxTotalBytes` (a budget
  is honoured exactly or refused, never silently raised), `server.listen` non-loopback
  without `allowRemote`, `server.listen` a wildcard address (`0.0.0.0`, `::`) even with
  `allowRemote` (the transport accepts only the listen IP as a remote `Host`); all violations are reported together and the process exits 2;
- warn (not fail) if `security.scanner.executable` is not found — but every scan then fails closed;
- print the effective config with `secure-web config --effective` (secrets redacted; none exist in v0.1).

`policyVersion` = first 12 hex chars of sha256 over canonical JSON of the `security` block.
