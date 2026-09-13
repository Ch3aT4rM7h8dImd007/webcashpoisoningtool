# Cache Poisoning Checker (V1-V80)
A command-line tool for detecting Web Cache Poisoning vulnerabilities on web applications. It runs automated scanning across 80 attack vectors, performs cache-buster verification, and can optionally replay confirmed attacks against the target.

---

## Table of Contents
1. Overview
2. Features
3. Requirements
4. Installation
5. How the Tool Works
6. Command-Line Options
7. Usage Examples
8. Attack Vectors (V1-V80)
9. Output Files
10. Attack Report
11. Architecture and Code Walkthrough
12. Detection Logic
13. Safety and Legal Notes
14. Troubleshooting
15. Disclaimer

---

## 1. Overview
This tool automates the discovery of Web Cache Poisoning issues. It sends crafted HTTP requests with suspicious headers and query parameters, observes whether responses are cached, and determines whether those responses can be poisoned.

The workflow is:
1. Base cache check - determine if the target caches responses.
2. Static asset discovery - extract static asset URLs from the HTML (when the base page is not cacheable).
3. Cache status check for each discovered static asset.
4. Run 80 attack vectors against each cacheable URL.
5. Generate reports.
6. Optionally replay confirmed attacks as a proof of concept.

---

## 2. Features
- 80 pre-defined attack vectors covering unkeyed headers, unkeyed parameters, cache deception, DoS via cache, and response header manipulation.
- Automatic cache-buster handling so scanning does not poison real user traffic on the tested URL.
- Live progress output in the terminal with per-vector timing.
- Automatic per-target folder creation under scan_results/.
- Reports generated automatically:  
  - Advanced report (all vectors)  
  - Vulnerability-only report  
  - Attack report (replayed PoCs)
- Handles multiple targets via a file input.
- Detects cache indicators from popular CDNs including Cloudflare, Fastly, Varnish, and Akamai.
- Safe write helper that avoids PermissionError by writing to a _new suffixed file when the original is not writable.

---

## 3. Requirements
- Python 3.8 or later
- pip (Python package manager)
- Internet access to reach the target
- Linux, macOS, or Windows with WSL

Python dependencies:
- requests
- urllib3

Standard library modules used: argparse, json, re, os, sys, time, uuid, socket, ssl, dataclasses, concurrent.futures, urllib.parse.

---

## 4. Installation

### Step 1: Clone or copy the script
Save the script as scr.py on your system.

### Step 2: Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
# On Windows: venv\Scripts\activate

### Step 3: Install dependencies
pip install requests urllib3

### Step 4: Verify installation
python3 scr.py --help
If the help output appears, the tool is ready.

---

## 5. How the Tool Works

### 5.1 Base Cache Check
The tool sends two requests to the target URL:
- First request: check initial cache state.
- Wait 0.6 seconds.
- Second request: check if the response is now served from cache.

Cache indicators checked:
- cf-cache-status (Cloudflare)
- x-cache
- x-cache-status
- age
- via
- cache-control

A response is considered cacheable if:
- Any of the cache status headers contains hit, stale, updating, or revalidated.
- The Age header is greater than zero.
- The Via header contains varnish or cache.
- Cache-Control contains public along with max-age or s-maxage.

If Cache-Control contains no-store, no-cache, or private, the response is not cacheable.

### 5.2 Static Asset Discovery
If the base URL is not cacheable, the tool fetches the HTML and extracts URLs matching these patterns:
- /_next/static/...
- /_nuxt/...
- /static/...
- /assets/...
- /build/...

Extracted URLs are saved to static_urls.txt inside the per-target folder.

### 5.3 Static Asset Cache Check
For each extracted URL, the tool sends a request and analyzes cache headers. URLs marked as cacheable are collected for advanced testing.

### 5.4 Advanced Vector Testing
The tool runs 80 attack vectors against each cacheable URL. Each vector sends a crafted request and checks:
- Whether the injected value is reflected in the response body or headers.
- Whether the response is cached.
- Whether both reflection and caching occur together (indicating a vulnerability).

Live progress output shows the vector name, the number of vulnerable findings, and elapsed time.

### 5.5 Report Generation
The tool automatically generates:
- auto_report.txt - complete output of all vectors.
- auto_report_vulnerabilities.txt - only confirmed vulnerabilities.
- attack_report.txt - detailed log of replayed attacks.

### 5.6 Attack Replay
For each confirmed vulnerability, the tool reconstructs the original attack request and sends it again. The response is analyzed to produce a verdict:
- POISON-CONFIRMED - reflection and cache hit both present.
- CACHED - response served from cache.
- OK - request succeeded but no cache hit.
- SKIPPED - no automatic proof of concept available for the vector.
- FAILED - the request could not be completed.

---

## 6. Command-Line Options
-u, --url          Single target URL
-f, --file         File containing one URL per line
-o, --output       Save JSON output for the base check
--poison           Run unkeyed header injection tests on the base URL
--threads          Number of threads for base check (default 5)
--advanced         Run all 80 vectors directly without the auto flow
--report           Save the advanced report to a specific path
--auto             Full pipeline: base check -> static discovery -> vectors -> reports
--txt              Filename for discovered static URLs (default static_urls.txt)
--auto-report      Filename for the auto mode report (default auto_report.txt)
--attack           Enable attack replay (default enabled)
--no-attack        Disable attack replay

---

## 7. Usage Examples

Example 1: Single target auto mode
python3 scr.py -u [https://example.com](https://example.com) --auto
Output is written to scan_results/example_com_1/.

Example 2: Multiple targets  
Create a file targets.txt:
[https://example.com](https://example.com)
[https://testsite.com](https://testsite.com)

Then run:
python3 scr.py -f targets.txt --auto
Each target is scanned and stored in its own folder.

Example 3: Advanced mode only
python3 scr.py -u [https://example.com](https://example.com) --advanced --report my_report.txt
Skips the auto pipeline and runs all vectors against the base URL.

Example 4: Disable attack replay
python3 scr.py -u [https://example.com](https://example.com) --auto --no-attack
Reports are generated but no attacks are replayed.

Example 5: Base check only
python3 scr.py -u [https://example.com](https://example.com)
Only performs a cache check on the base URL.

---

## 8. Attack Vectors (V1-V80)

### 8.1 Header-Based Poisoning (V1-V7)
- V1: X-Forwarded-Host injection
- V2: X-Forwarded-Scheme downgrade to HTTP
- V3: X-Forwarded-Port mismatch
- V4: X-Original-URL routing override
- V5: X-Rewrite-URL path override
- V6: X-Host injection
- V7: X-Forwarded-Server host override

### 8.2 Request Manipulation (V8-V10)
- V8: Fat GET (GET with request body)
- V9: Parameter cloaking using encoded separators
- V10: Cache-key normalization with case changes, trailing slashes, matrix params

### 8.3 Unkeyed Input (V11-V20)
- V11: Unkeyed cookie poisoning
- V12: Unkeyed query string (tracking parameters such as utm_*, fbclid)
- V13: Unkeyed query parameter (debug, test, callback, etc.)
- V14: Multiple unkeyed headers combined
- V15/16: DOM-based cache poisoning via query parameters
- V17: Resource import reflection
- V18: Canonical tag hijacking
- V19: Open redirect chain caching
- V20: Stored XSS via cached response

### 8.4 Cache-Poisoned DoS (V21-V24)
- V21: HTTP header oversize
- V22: HTTP meta character injection
- V23: HTTP method override
- V24: Cache-poisoned DoS with malformed values

### 8.5 Redirects and Routing (V25-V27)
- V25: Wrong port reflection in redirect
- V26: Scheme downgrade in redirect
- V27: Routing override via internal headers

### 8.6 Parameter and Cache-Key Issues (V28-V30)
- V28: Parameter pollution
- V29: Cache-key confusion
- V30: Vary header abuse

### 8.7 Encoding and Delimiters (V31-V36)
- V31: Large header poisoning
- V32: Invalid encoding handling
- V33: Semicolon delimiters
- V34: Dot delimiters
- V35: Null byte truncation
- V36: Newline byte handling

### 8.8 Static Extension and Deception (V37-V44)
- V37: Static extension abuse (.css, .js, etc.)
- V38: Cache deception via path manipulation
- V39: Path confusion
- V40: Delimiter discrepancy
- V41: Normalization discrepancy
- V42: Cacheable 4xx errors
- V43: Cloudflare 4xx cacheable responses
- V44: ATS fragment poisoning

### 8.9 CDN-Specific Vectors (V45-V50)
- V45: Fastly host poisoning
- V46: Request body poisoning via GET
- V47: Header bruteforce
- V48: CDN normalization bug
- V49: Cache-key discrepancy
- V50: Edge case cache poisoning

### 8.10 Request Header Poisoning Extended (V51-V68)
- V51: Content-Type confusion
- V52: Accept-Encoding abuse
- V53: Accept-Language poisoning
- V54: User-Agent poisoning
- V55: Referer poisoning
- V56: Cookie poisoning
- V57: Host header poisoning
- V58: X-Forwarded-For poisoning
- V59: X-Forwarded-Proto poisoning
- V60: X-HTTP-Method-Override
- V61: Forwarded header poisoning
- V62: X-Forwarded-Prefix injection
- V63: X-Original-Host
- V64: X-Backend-Server
- V65: X-Cache-Key manipulation
- V66: X-Cache-Hits manipulation
- V67: X-Served-By manipulation
- V68: X-Timer manipulation

### 8.11 Response Header Reflection (V69-V80)
- V69: Via header poisoning
- V70: Warning header poisoning
- V71: Retry-After poisoning
- V72: Location header poisoning
- V73: Refresh header poisoning
- V74: Content-Security-Policy abuse
- V75: Strict-Transport-Security abuse
- V76: X-Frame-Options abuse
- V77: X-Content-Type-Options abuse
- V78: Public-Key-Pins abuse
- V79: Expect-CT abuse
- V80: Feature-Policy abuse

---

## 9. Output Files
For each target, a folder is created under scan_results/ using the format <domain>_<N> where N is an incrementing integer (1, 2, 3, ...).

Inside the folder:

File | Contents
--- | ---
static_urls.txt | Discovered static asset URLs from HTML
auto_report.txt | Full report of all vectors
auto_report_vulnerabilities.txt | Only confirmed vulnerabilities
attack_report.txt | Detailed log of replayed attacks

The folder naming avoids overwriting previous results. Each run creates a new folder.

---

## 10. Attack Report
The attack_report.txt contains:
- Overall counters (total, hits, skipped, failed).
- Verdict summary.
- Header usage summary.
- URL usage summary.
- Per-target section with detailed entries for each attack, including:
  - Attack type
  - Verdict
  - HTTP method
  - Target URL
  - Header names and values
  - Host manipulation details
  - URL breakdown (scheme, host, path, query)
  - Request body (if any)
  - Response status
  - Cache hit indicator
  - Reflection indicator
  - Notes

---

## 11. Architecture and Code Walkthrough

### 11.1 Module Structure
The script is a single-file Python program. The main sections are:
- Configuration block - lists of headers, parameters, and payloads for each vector.
- Helper functions - URL normalization, HTTP fetching, raw socket requests.
- Cache analysis - analyze_cache_headers() and is_cacheable().
- Individual vector functions - one function per vector or vector group.
- Master runner - run_advanced_vectors() which calls all vector functions in order.
- Reporters - save_advanced_report(), save_vulnerabilities_report(), save_attack_report().
- Attack executor - auto_run_attacks().
- Auto pipeline - auto_pipeline() orchestrates all steps.
- Main entry point - main() with argument parsing.

### 11.2 The Vector Function Pattern
Every vector function follows the same pattern:
1. Iterate over the payload list.
2. Send a request with the payload.
3. Check for reflection in body or headers.
4. Check if the response is cacheable.
5. Mark as vulnerable if both conditions are met.
6. Append the finding as a dictionary.

### 11.3 Caching Detection Flow
Response received    
       |    
       v
Check Cache-Control    
       |    
       +-- no-store/no-cache/private -> NOT cacheable    
       |    
       v
Check cf-cache-status    
       |    
       +-- dynamic/bypass/expired -> NOT cacheable    
       +-- hit/miss/revalidated -> cacheable    
       |    
       v
Check x-cache    
       |    
       +-- contains "hit" -> cacheable    
       |    
       v
Check Age header    
       |    
       +-- age > 0 -> cacheable    
       |    
       v
Check Via header    
       |    
       +-- contains "varnish" -> cacheable    
       |    
       v
Check Cache-Control public + max-age    
       |    
       +-- present -> cacheable    
       |    
       v
Default: NOT cacheable

### 11.4 Cache Buster Usage
During scanning, a cache buster parameter is appended to URLs to prevent poisoning real user caches. The parameter name used depends on the vector. Values are generated as random tokens.

### 11.5 Reflection Check
The reflection check searches for a unique random token inside the response body. If the token appears, the response is considered reflected.

### 11.6 Vulnerability Decision
A vector is marked vulnerable when:
- Reflection is detected AND the response is cached.
- Or, in the case of redirect vectors: The Location header contains the token AND the response is cached.
- Or, in the case of DoS vectors: The response has an error status (4xx or 5xx) AND the error response is cached.

---

## 12. Detection Logic

### 12.1 Cache Indicators

Header | Cacheable Value
--- | ---
cf-cache-status | hit, miss, revalidated
x-cache | contains hit
x-cache-status | contains hit
age | value greater than 0
via | contains varnish or cache
cache-control | contains public with max-age or s-maxage

### 12.2 Non-Cacheable Indicators

Header | Non-Cacheable Value
--- | ---
cache-control | no-store, no-cache, private
cf-cache-status | dynamic, bypass, expired

### 12.3 Verification Strategy
1. Send request with payload.
2. Check if payload is reflected.
3. Check if response is cacheable.
4. If both are true, the vector is confirmed vulnerable.

The tool also uses a second-request verification for the base cache check to reduce false negatives.

---

## 13. Safety and Legal Notes
- Only scan targets you own or have written permission to test.
- Never run this tool against third-party sites without authorization.
- The tool does not perform destructive actions, but cache poisoning can affect production users.
- Always use the cache-buster parameter during testing to avoid affecting real users.
- The attack replay feature sends real requests to the target. Confirm you are allowed to do this before enabling it.

---

## 14. Troubleshooting

### PermissionError when writing reports
The script writes to scan_results/<domain>_<N>/. If a previous run created the folder as root, you may not have write permissions. Solutions:
Delete the old folder:
sudo rm -rf scan_results/

Or change ownership:
sudo chown -R $USER:$USER scan_results/

Or let the script write to a _new suffixed file automatically.

### No cacheable URLs found
The target may not cache responses. Try:
- Running without --auto to only test the base URL.
- Reviewing the Cache-Control and cf-cache-status headers manually with curl -I <url>.

### All static assets show MISS
The CDN or reverse proxy may not cache static assets for the tested paths. This can happen when:
- The site uses a unique query string for cache-busting.
- The assets are private or authenticated.

### HTTP request timeout
Increase the timeout in the fetch() function if the target is slow.

### Requests library warns about SSL
The tool disables certificate verification by default. This is intentional for testing. Do not rely on it for production.

---

## 15. Disclaimer
This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users are solely responsible for complying with all applicable laws and regulations.

Always obtain explicit permission from the target owner before performing any security testing. Unauthorized scanning and exploitation of systems you do not own is illegal in most jurisdictions.

---

## Appendix A: Example Command Sequence
# Step 1: Create a fresh environment
python3 -m venv venv
source venv/bin/activate
pip install requests urllib3

# Step 2: Save the script
# Save the code as scr.py

# Step 3: Run a full scan
python3 scr.py -u [https://example.com](https://example.com) --auto

# Step 4: Review the output
ls scan_results/example_com_1/
cat scan_results/example_com_1/auto_report_vulnerabilities.txt
cat scan_results/example_com_1/attack_report.txt

---

## Appendix B: Common Cache Header Reference

Header | Meaning
--- | ---
cf-cache-status | Cloudflare cache result: HIT, MISS, DYNAMIC, BYPASS, EXPIRED, REVALIDATED
x-cache | Generic cache status: HIT, MISS, or descriptive string
x-cache-status | Alias for x-cache on some servers
age | Seconds since the response was cached
via | Proxy chain information, useful for detecting Varnish or Squid
cache-control | Directives such as public, private, no-cache, no-store, max-age
vary | Headers that affect the cache key

---

## Appendix C: Vector Payload Categories

Category | Vectors | Purpose
--- | --- | ---
Host override | V1, V6, V7, V45, V57, V61, V63 | Inject false host into cache
Scheme/port manipulation | V2, V3, V25, V26, V59 | Force HTTP downgrade or wrong port
Path override | V4, V5, V27, V38, V39, V40 | Internal path exposure via cached response
Body manipulation | V8, V46 | Fat GET body or body poisoning
Parameter manipulation | V9, V12, V13, V28, V29 | Unkeyed parameters or cache key confusion
Cache deception | V37, V38 | Static-looking URL serving dynamic content
DoS via cache | V21, V22, V23, V24, V42, V43 | Cache error or oversized responses
Reflection abuse | V17, V18, V19, V20, V55, V65, V67, V68 | Reflection of unkeyed input
Vary header | V30, V52, V53, V54, V56 | Missing or incorrect Vary directives
Response header manipulation | V69-V80 | Manipulation of security headers via reflection
Encoding edge cases | V31-V36 | Malformed URLs or headers

---

## Appendix D: File Naming Convention
Target [https://www.example.com/path](https://www.example.com/path) produces:
- Folder name: example_com_1 (first scan), example_com_2 (second scan), and so on.
- The domain is normalized: dots are replaced with underscores.
- Port numbers are removed.
- If the domain cannot be extracted, unknown_<N> is used.

---

## Appendix E: Common Errors and Fixes

Error | Cause | Fix
--- | --- | ---
PermissionError on report write | Previous run created root-owned file | Delete scan_results/ or run with appropriate permissions
ConnectionError | Target unreachable | Verify URL and network connectivity
SSLError | Certificate issue | The tool disables verification by default; if it still fails, check firewall
Timeout | Slow target | Increase timeout in fetch()
Empty static URL list | HTML does not contain standard asset paths | Try a different entry URL or run only --advanced

---

## Appendix F: Extending the Tool
To add a new attack vector:
1. Define the payload list in the configuration section.
2. Write a new function following the existing pattern.
3. Register the function in run_advanced_vectors().
4. Add the key to ALL_VECTOR_KEYS.
5. Add the reporting section in save_advanced_report().
6. Add the attack request builder in _build_attack_request() if applicable.
