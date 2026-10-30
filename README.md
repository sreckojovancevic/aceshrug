# ACESHRUG

**Application Capability Enforcement + SHRUG**: a self-declared security boundary for PHP applications.

> The application declares what it does. The runtime locks it to that declaration. Everything else gets a shrug.

[Srpski / Serbian](README.sr.md)

Status: **v0.3.2, experimental.** Monitor mode has been tested on a production PHP application (Apache + mod_php, PHP 8.3). Enforcement mode is not production-ready yet.

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
# after reviewing signals, record decisions (edit the JSON, or export from an edited manifest)
sudo python3 builder/aceshrug_build.py --output /etc/aceshrug/app --export-decisions
sudoedit /etc/aceshrug/app.decisions.json      # status: confirmed / rejected, mode: enforcement
sudo python3 builder/aceshrug_build.py --input /var/www/html/app --output /etc/aceshrug/app
```

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
