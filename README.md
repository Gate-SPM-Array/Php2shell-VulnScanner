# PHP Vuln Scanner v1.11

**English** · [Italiano](README.it.md)

Portable Windows scanner that detects **from outside**, in a few seconds per target, the exposure to the two PHP runtime vulnerabilities published on 21 October 2026 (**PHP2Shell**, CVE-2026-109618 and CVE-2026-109619) and recognises upstream **WAFs, CDNs, reverse proxies and load balancers**. Graphical interface, full log, HTML report, CSV/JSON export.

> **Responsible use.** Scan only your own systems or with the owner's written authorisation. The program names itself in the `User-Agent`. It contains and runs no exploit code, does not change the state of servers and sends no request that drives PHP into memory exhaustion.

> **Language:** the program speaks English and Italian (**🌐 Language** button, applied on restart). On first start it follows the Windows language.

## 1. What it does

| Feature | Detail |
|---|---|
| Targets | IPs, CIDR networks (`192.0.2.0/24`), ranges (`192.0.2.10-20`), names (FQDN); one per line or separated by comma/space |
| Ports | Multiple TCP ports, default 443; port 80 = HTTP, other ports HTTPS when the TLS handshake succeeds |
| Alive check | ICMP (no privileges on Windows), TCP (even an RST counts), UDP (reply or ICMP port unreachable only), configurable timeout and "skip targets not alive" |
| Level 1, passive | PHP version from `X-Powered-By`, `Server`, exposed phpinfo pages, easter egg; `PHPSESSID` cookie; PHP errors in the body. Compared with 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Level 2, barriers | Minimal multipart vs url-encoded, eight Content-Type variants, `PHP_SESSION_UPLOAD_PROGRESS` field without cookie, size limit (413) |
| WAF / proxy | Signatures on headers, cookies, block pages and TLS certificate; behavioural test with inert hostile parameters; repeated requests for load balancers |
| Verdicts | Vulnerable by version · Likely vulnerable · Mitigated at the edge · Undetermined · Fixed by version · PHP not detected · Not reachable, each with its reason and evidence; remediation **priority** derived from verdict, SAPI and barrier |
| Passive context | **SAPI** (mod_php / FPM / LSAPI / CGI) and **operating system** from the banner, recognised **application** (WordPress, Joomla, Drupal, phpMyAdmin, Nextcloud, Laravel, Moodle, GLPI, TYPO3…) linked to the [NCSC-NL](https://github.com/NCSC-NL/php2shell) inventory |
| PHP surface | Missing-`.php` probe (`File not found.` = PHP-FPM, `No input file specified.` = php-cgi), about forty common entry points with HEAD only, `.php` files linked from the pages; level 2 uses the best discovered `.php` |
| Discovered names | DNS names from the certificate (CN/SAN) and `Location`, with an optional second pass on the same IPs with `Host`/SNI = name (`name @ IP`): scanning by IP only shows the default vhost |
| Advanced | Extra read-only tests, one checkbox each: HEAD vs GET and OPTIONS, Composer (declared minimum PHP version, libraries), status pages (server-info = SAPI for sure, FPM status), application version files compared with NCSC-NL, FastCGI 9000 probe, PHP behaviours (PATH_INFO, xmlrpc, exposed sources), level 2 on every .php, browser User-Agent, component inventory, exposures (.env, .git, backups), more names (PTR, Certificate Transparency); TCP port pre-check; names with the same content as the default vhost get no row; pure number on an EOL branch = vulnerable by version |
| Pause and merge | Pause / Resume without losing anything; **Merge sessions** (even from different versions) with a differences report; **Update data** from GitHub |
| Hints and talkativeness (v1.5) | Three-state **PHP** column (yes / **maybe** / no): "maybe" = weighted passive hints without proof (fixed Expires of session_start, cookie with a PHP session id, framework cookies, headers, paths, panels); **settings from the phpinfo page** (upload_progress, serialize_handler, Server API) with the note on **CVE-2026-115560** (no fixed release); **talkativeness index** 0-5 per host; names with the **same outcome** without a duplicate row (every name in the compact report); **filters** with multi-select and a text syntax (AND, `|`, `-`, quotes, `field:value`, `*` `?` wildcards, CIDR and ranges) |
| Continuous alive sweeper, known hosts (v1.11) | A separate task retries unconfirmed hosts for the whole cycle and feeds those that answer into the running cycle; **Known hosts** file from previous sessions (`--known-hosts`), silent known hosts flagged; routed CT names remembered across cycles |
| CT names verified by DNS, config files, analysis bundle (v1.10) | Certificate Transparency names enter only if they resolve to the IP under test (80% of the thread time on the reference /20 went to names hosted elsewhere); second chance on 16 lanes and, from cycle 2, only for hosts seen alive; "connection closed by the perimeter" outcome; names one per line in the compact report; regenerated CSVs suffixed like the reports; **Save/Load config** and `--config`/`--save-config`; **analysis bundle** without response bodies (`--analysis-bundle`) |
| Second chance tuned (v1.9) | Second chance starts as soon as the host queue is empty, on half the threads with 1.5× timeout (v1.8: 4 lanes, double timeout, after the cycle: 11.5 min per cycle on the /22) |
| Alive cap, second chance, field merge, Excel list (v1.8) | Separate cap for the alive check and a **second chance** at the end of the cycle for unconfirmed hosts; workers with a priority queue (names before new hosts); **field-by-field consolidation** across cycles; **list for Excel** in the compact report and `elenco_vX.Y.csv`; CT on the most specific subdomain |
| Names in parallel, PHP maybe (v1.7) | Second pass on discovered names on the thread pool instead of sequentially per host (the cycle tail was a single thread); IP rows previewed before the name pass; catch-all 5xx also when `/` redirects; **PHP maybe** highlighted (lilac rows, tile as filter, section near the top of the compact report) |
| Certificates, inventory, budget (v1.6) | **TLS certificate status** (expired, self-signed, chain, name, key); **cache in front of the origin**; versions declared in the body; **reconciled CSV/JSON inventory** (owner next to every service, different versions, declared but not observed, observed but not inventoried); **session-id adoption** (optional); **per-service budget** and stop on dead backends (catch-all 5xx); session files written outside the thread lock |
| Cycles | N cycles with pause; one session per cycle or consolidation (the most informative result wins, cycle history, `Δ` on changed verdicts); random order, random delay between requests and requests/s cap; cycle-end and loop-end estimate on the last 5 minutes' rate |
| Interface | Separate **Target** (IP) and **Name** (FQDN) columns; summary tiles as filters counting **services and hosts** (including **Alive hosts**), filter bar (text, verdict, priority, alive, barrier), IP-numbering sort, ISO start time with milliseconds, log with local and UTC time |
| Command line | `PhpVulnScanner.exe --scan <file> …` without a window, with exit codes for scripts and scheduled tasks (see §4) |
| Outputs | `scan.log`, `results.json`, `results.jsonl` (one line per observation), `results.csv`, `tests.csv`, `session.json`, **compact report** `report_vX.Y.html` (only what has something to say) and `report_completo_vX.Y.html` (everything, with the per-cycle section), `host_attivi_vX.Y.txt` / `host_http_vX.Y.txt` / `nomi_scoperti_vX.Y.txt` (one IP per line, for OpenVAS); anonymised `samples.json` in debug mode; log/CSV/JSON export; reopening of sessions |

**Why there is no exploitability test.** No external scanner proves PHP2Shell exploitability: tests that drive PHP into memory exhaustion answer the same way on a fixed and on a vulnerable PHP (issue #1 of the Assetnote scanner) and, on an unfixed worker, they are the first half of the attack chain. By choice the scanner stops at the advertised version and the barriers: without a version the verdict stays "Undetermined" and the proof must be sought on the host (`php -v`, package changelog).

## 2. Requirements and start

- Windows 10/11 x64 or Windows Server 2016 or later. No installation: the exe is self-contained.
- Extract `PhpVulnScanner_v1.4_win-x64.zip` anywhere and run `PhpVulnScanner.exe`. Full guide with **F1**.

## 3. Portable program

```
PhpVulnScanner\
  PhpVulnScanner.exe
  lang\en.json                      English translation (also embedded in the exe; this file takes precedence)
  data\                             technology signatures (webappanalyzer) and NCSC-NL inventory, with extraction date
  PhpVulnScanner.settings.json      last configuration and language
  Guide_PhpVulnScanner_v1.4.html    guide (F1); Guida_… in Italian
  Sessioni\                         one folder per scan
```

When the folder is read-only, settings and sessions go to `%LOCALAPPDATA%\PhpVulnScanner` and `Documents\PhpVulnScanner\Sessioni`.

## 4. Command line

```
PhpVulnScanner.exe --scan targets.txt --ports 443,8443 --out D:\scans --label customer --quiet
PhpVulnScanner.exe --scan 192.0.2.10,www.example.org --no-alive --light --json result.json
PhpVulnScanner.exe --scan 192.0.2.0/22 --cycles 4 --cycle-pause 300 --random --delay 50-250 --rate 20 --threads 8 --advanced all
PhpVulnScanner.exe --merge D:\scans\20261023_224732_phpscan D:\scans\20261024_023528_phpscan --out D:\scans
PhpVulnScanner.exe --help
```

Same scan, same session files and report, no window. Exit codes: **0** none vulnerable, **1** at least one "vulnerable by version" or "likely vulnerable", **2** invalid arguments, **3** "undetermined" only, **4** scan stopped or failed. From a script: `& .\PhpVulnScanner.exe --scan ... ; if ($LASTEXITCODE -eq 1) { ... }`.

## 5. Building from source

```
dotnet build -c Release            # .NET 10 SDK; on Linux EnableWindowsTargeting is already set for the WPF app
dotnet test -c Release             # includes full scans against a fake PHP server on loopback
dotnet publish src/PhpVulnScanner.App -c Release -r win-x64 -o publish -p:DebugType=none
```

Layout: `src/PhpVulnScanner.Core` (targets, alive check, HTTP/TLS, PHP tests, WAF detection, engine, files, report; no UI), `src/PhpVulnScanner.App` (WPF), `tests/PhpVulnScanner.Tests` (xunit), `lang/` (translations).

## 6. Translations

Every text goes through the `lang\<code>.json` files: copy `en.json`, set `code`, `language`, `culture`, translate the values (keys are the Italian texts and must not change, placeholders `{0}` must stay identical), restart and pick the language.

## 7. Licence and credits

[MIT](LICENSE) licence; third-party components in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Developed by [Gate-SPM-Array](https://github.com/Gate-SPM-Array) with [Claude](https://claude.com) (Anthropic) from the maintainer's requirements and design choices. Technical references: PHP advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp, CERT-EU 2026-018, Datadog Security Labs, Wiz, Assetnote, Blue-B/php2shell-guard.
