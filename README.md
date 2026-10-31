# ACESHRUG

**Application Capability Enforcement + SHRUG**: a self-declared security boundary for PHP applications.

> The application declares what it does. The runtime locks it to that declaration. Everything else gets a shrug.

[Srpski / Serbian](README.sr.md)

Status: **v0.3.6, experimental.** Monitor mode has been tested on a production PHP application (Apache + mod_php, PHP 8.3). Enforcement mode is not production-ready yet.

---

## The idea

| Part | Meaning | What it limits |
|---|---|---|
| **ACE** | The application declares its world up front: routes, methods, parameters, files. The runtime is locked to that declaration. | what an attacker can **do** |
| **SHRUG** | Anything outside the declaration gets the same null response: no error, no 403/404/500 distinction, no information. | what an attacker can **learn** |
| **SHRUG signal** | Silent outside, fully aware inside. Every attempt outside the contract is recorded. A legitimate client never steps outside the contract, so this is a tripwire with almost no false positives. | nothing goes unseen |

ACESHRUG is a strategy, not a single tool: it does not depend on the language, the size of the application, or the protocol. This implementation targets PHP.

The full concept and workflow are in [docs/ACESHRUG-workflow.md](docs/ACESHRUG-workflow.md) (Serbian).

---

## How it works

```
            ┌──────────────────── /etc/aceshrug/<app>/ ─────────────────────┐
 HTTP ───▶  │ gate.php ◀── manifest.php (contract: routes, schemas, hashes) │
 request    └─────┬─────────────────────────────────────────────────────────┘
                  │ auto_prepend_file (php_admin_value, cannot be overridden)
                  ▼
            /var/www/html/<app>/  ◀── application code, UNTOUCHED
```

1. The **builder** (`builder/aceshrug_build.py`) analyzes the application and generates `gate.php`, `manifest.php`, `pool.conf` and `REPORT.md` in a directory **outside the webroot**.
2. The gate is enabled through `auto_prepend_file`. **Application code is never modified.**
3. Before every request the gate checks the route, SAPI, method, entry-file hash, include integrity and parameter schema.
4. **Monitor** mode records contract violations without blocking. **Enforcement** blocks, and only for items a human has confirmed (`status: confirmed`) or rejected (`status: rejected`). An invalid manifest or configuration is fatal in both modes.
5. Human decisions live in a separate file (`<output>.decisions.json`) that the builder never overwrites, so confirmations survive rebuilds. If a confirmed file changes, its decision goes back to review automatically (and in enforcement mode the build stops until it is reviewed). A rejected item stays rejected.

---

## What it does and does not protect against

**In enforcement mode, ACESHRUG prevents:**
- direct execution of PHP files that are not declared in the manifest (for example a webshell uploaded **after** the build);
- execution of declared files modified after the build;
- requests whose method or parameters fall outside the declared schema, for confirmed routes and parameters.

**It does not prevent:**
- a malicious file that already existed when the build ran: the builder inventories what it finds, so always build from a trusted release and review the routes;
- code execution through a vulnerability in a legitimate route (local file inclusion, `unserialize`, `eval` in application code);
- vulnerabilities in the PHP engine itself, such as php2shell (CVE-2026-109618 / CVE-2026-109619), because they trigger while PHP parses the request, before the gate is loaded. The only protection there is an up-to-date PHP.

Requires **PHP 7.0+** on the server (the gate uses `??` and an immediately invoked closure). `mbstring` is optional.

---

## Related work: October CMS

While developing the idea, the author found that October CMS already ships something similar: its `.htaccess` allows direct access only to whitelisted directories and sends everything else to `index.php`. That confirms the direction, but it is a different layer:

| | October CMS `.htaccess` | ACESHRUG |
|---|---|---|
| What it checks | the URL path (which directory may be reached) | the file that actually executes, its hash, methods and parameters |
| Modified `index.php` or plugin | not noticed | `file_tampered` / blocked |
| Webshell dropped into an allowed directory | depends on the rule for that directory | unregistered route, SHRUG |
| Who can change it | `.htaccess` is itself a file in the webroot: anyone with write access can override it | `php_admin_value` in the Apache configuration, out of the application's reach |
| Signal | none, just a 404 | every attempt is logged |
| Applies to | October CMS only | any PHP application, including ones with no such rules |

In short: `.htaccess` says which paths exist; ACESHRUG says what may execute and whether it is still the same code. The two can be used together.

### Other related approaches

Individual parts of ACESHRUG have well-known predecessors:

| Approach | Examples | Relation to ACESHRUG |
|---|---|---|
| Positive security model (allow only what is declared) | ModSecurity in allowlist mode, OpenAPI schema validation | the per-route parameter schema is the same idea, enforced inside PHP |
| File integrity monitoring | Tripwire, AIDE | they hash files periodically and report after the fact; ACESHRUG checks the hash before every execution and can block |
| PHP hardening extensions | Snuffleupagus, Suhosin | harden PHP itself (function bans, `eval`, uploads); complementary |
| PHP runtime restrictions | php-fpm `security.limit_extensions`, `open_basedir`, `disable_functions` | coarse limits at the PHP level; complementary |

What is new in ACESHRUG is the combination: the application declares itself, the runtime is locked to that declaration, everything outside it gets the same empty response (SHRUG), and the signal stays inside. And the rule that this is a strategy, independent of language.

---

## Quick start (monitor mode, Apache + mod_php)

```bash
# 1. build outside the webroot
sudo mkdir -p /etc/aceshrug && sudo chmod 755 /etc/aceshrug
sudo python3 builder/aceshrug_build.py \
    --input  /var/www/html/app \
    --output /etc/aceshrug/app \
    --php-user www-data --php-group www-data
# exit code 3 = activated in monitor mode (all items are "auto")

# 2. log directory
sudo mkdir -p /var/log/aceshrug && sudo chown www-data:www-data /var/log/aceshrug

# 3. Apache: see examples/apache/aceshrug-app.conf
sudo cp examples/apache/aceshrug-app.conf /etc/apache2/conf-available/
sudo a2enconf aceshrug-app && sudo apache2ctl configtest && sudo systemctl reload apache2

# disable at any time
sudo a2disconf aceshrug-app && sudo systemctl reload apache2
```

Detailed guide, including how to read signals and switch to enforcement: [docs/BUILDER-UPUTSTVO.md](docs/BUILDER-UPUTSTVO.md) (Serbian).

Human review workflow:
```bash
# after reviewing signals: confirm / reject routes (status + current sha256 go to app.decisions.json)
sudo python3 builder/aceshrug_build.py --input /var/www/html/app --output /etc/aceshrug/app \
    --confirm login.php --reject an1.php --reload apache
# switch to enforcement: set "mode": "enforcement" in /etc/aceshrug/app.decisions.json, then rebuild
```

After every deploy of the application, rebuild with `--reload apache` (or `--reload fpm:<service>`). The entry-file hash is the proof that reviewed code is running, so intentional changes need a new build. The reload makes PHP pick up the new version immediately.

---

## Repository contents

| Path | What it is |
|---|---|
| `builder/aceshrug_build.py` | builder: analysis, generation, smoke test, activation via symlink, rollback |
| `tools/aceshrug_gen.py` | parser-based manifest analyzer (tree-sitter-php): include graph, reachable functions, `filter_input`, schema hints from HTML forms, SQL → column-level GRANT |
| `docs/ACESHRUG-workflow.md` | concept, architecture, workflow |
| `docs/BUILDER-UPUTSTVO.md` | builder guide |
| `docs/ROADMAP.md` | field requirements and plan for next versions |
| `examples/` | Apache and logrotate configuration |
| `tests/fixtures/` | deliberately bad PHP for blocker checks |

---

## Requirements

- Python 3.8+ (builder), PHP CLI of the same version as the server
- PHP 7.0+ on the server
- root, for `root:<php-group>` ownership and the read check via `sudo -u <php-user>`
- `tools/aceshrug_gen.py`: `pip install tree-sitter tree-sitter-php pyyaml`

---

## License

**GPL-3.0-or-later**, with the [ACESHRUG Generated Output Exception](LICENSE-EXCEPTION.md).

- ACESHRUG itself (builder, tools, documentation) is under the GNU General Public License v3 or later. Modified versions that are distributed must remain open.
- **Generated output** (`gate.php`, `manifest.php`, generated configuration) may be used with any application, under any license. Using ACESHRUG does not make your application GPL.

See [LICENSE](LICENSE) and [LICENSE-EXCEPTION.md](LICENSE-EXCEPTION.md).

---

## Authors

- **Srećko Jovančević**: idea and concept of ACESHRUG (name, SHRUG principle, strategy), field testing of the solution ([github.com/sreckojovancevic](https://github.com/sreckojovancevic))

## Acknowledgments

- **Gemini (Google)**: base code of the builder and the gatekeeper
- **ChatGPT (OpenAI)**: review and suggestions
- **Perplexity**: code review (monitor/enforcement semantics, preserving human decisions across rebuilds, UTF-8 safe logging, concurrent activation, decision and activation policy)
- **Claude (Anthropic)**: elaboration of the concept and architecture, code review and testing (smoke matrix, tests with deliberately broken gates), `tools/aceshrug_gen.py`, documentation
