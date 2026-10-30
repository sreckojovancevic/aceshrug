# ACESHRUG

**Application Capability Enforcement + SHRUG**: a self-declared security boundary for PHP applications.

> The application declares what it does. The runtime locks it to that declaration. Everything else gets a shrug.

*Aplikacija deklariše šta radi. Runtime je zaključava na tu deklaraciju. Na sve ostalo aplikacija samo slegne ramenima.*

Status: **v0.2.16, eksperimentalno.** Monitor režim je proveren na produkcionoj PHP aplikaciji (Apache + mod_php, PHP 8.3). Enforcement režim još nije za produkciju.

---

## Ideja

| Deo | Značenje | Šta ograničava |
|---|---|---|
| **ACE** | Aplikacija unapred deklariše svoj svet: rute, metode, parametre, fajlove. Runtime je zaključan na tu deklaraciju. | šta napadač može da **uradi** |
| **SHRUG** | Sve van deklaracije dobija isti nulti odgovor: bez greške, bez razlike 403/404/500, bez informacije. | šta napadač može da **sazna** |
| **SHRUG signal** | Spolja tišina, iznutra svest. Svaki pokušaj van ugovora se beleži. Legitiman klijent nikad ne izlazi van ugovora, pa je to tripwire skoro bez lažnih uzbuna. | ništa ne ostaje neviđeno |

ACESHRUG je strategija, a ne vezan alat: ne zavisi od jezika, veličine aplikacije ni protokola. Ova implementacija je za PHP.

Ceo koncept, sa radnim tokom: [docs/ACESHRUG-workflow.md](docs/ACESHRUG-workflow.md).

---

## Kako radi

```
            ┌───────────────── /etc/aceshrug/<app>/ ──────────────────┐
 HTTP ───▶  │ gate.php  ◀── manifest.php (ugovor: rute, šeme, hash-evi) │
 zahtev     └─────┬───────────────────────────────────────────────────┘
                  │ auto_prepend_file (php_admin_value, ne može se pregaziti)
                  ▼
            /var/www/html/<app>/  ◀── kod aplikacije, NETAKNUT
```

1. **Builder** (`builder/aceshrug_build.py`) analizira aplikaciju i generiše `gate.php`, `manifest.php`, `pool.conf` i `REPORT.md` u direktorijum **van webroot-a**.
2. Gate se uključuje preko `auto_prepend_file`. **Kod aplikacije se ne menja.**
3. Gate pre svakog zahteva proverava rutu, SAPI, metodu, hash ulaznog fajla, integritet include-ova i šemu parametara.
4. **Monitor** režim samo beleži. **Enforcement** blokira, i to samo stavke koje je čovek potvrdio (`status: confirmed`).

---

## Brzi početak (monitor režim, Apache + mod_php)

```bash
# 1. build van webroot-a
sudo mkdir -p /etc/aceshrug && sudo chmod 755 /etc/aceshrug
sudo python3 builder/aceshrug_build.py \
    --input  /var/www/html/app \
    --output /etc/aceshrug/app \
    --php-user www-data --php-group www-data
# izlazni kod 3 = aktivirano u monitor režimu (sve stavke su "auto")

# 2. log
sudo mkdir -p /var/log/aceshrug && sudo chown www-data:www-data /var/log/aceshrug

# 3. Apache: vidi examples/apache/aceshrug-app.conf
sudo cp examples/apache/aceshrug-app.conf /etc/apache2/conf-available/
sudo a2enconf aceshrug-app && sudo apache2ctl configtest && sudo systemctl reload apache2

# isključivanje u svakom trenutku
sudo a2disconf aceshrug-app && sudo systemctl reload apache2
```

Detaljno uputstvo, sa tumačenjem signala i prelaskom na enforcement: [docs/BUILDER-UPUTSTVO.md](docs/BUILDER-UPUTSTVO.md).

> **Poznat problem u v0.2.16:** smoke fixture čita `$_ENV`, koji je prazan uz podrazumevani `variables_order=GPCS`, pa build pada na testu statusa. Privremeno rešenje: u `run_smoke_test` zameniti `isset($_ENV['SIM_GET'])` / `$_ENV['SIM_GET']` sa `getenv('SIM_GET')!==false` / `getenv('SIM_GET')`, i isto za `SIM_POST`. Vidi [CHANGELOG.md](CHANGELOG.md).

---

## Sadržaj repozitorijuma

| Putanja | Šta je |
|---|---|
| `builder/aceshrug_build.py` | builder: analiza, generisanje, smoke test, aktivacija preko symlink-a, rollback |
| `tools/aceshrug_gen.py` | analizator manifesta zasnovan na parseru (tree-sitter-php): include graf, dostižne funkcije, `filter_input`, HTML nagoveštaji šeme, SQL → column-level GRANT |
| `docs/ACESHRUG-workflow.md` | koncept, arhitektura, radni tok |
| `docs/BUILDER-UPUTSTVO.md` | uputstvo za builder |
| `docs/ROADMAP.md` | zahtevi sa terena i plan sledećih verzija |
| `examples/` | Apache i logrotate konfiguracija |
| `tests/fixtures/` | namerno loš PHP za proveru blokera |

---

## Zahtevi

- Python 3.8+ (builder), PHP CLI iste verzije kao na serveru
- PHP 7.4+ na serveru
- root, za vlasništvo `root:<php-group>` i proveru čitljivosti preko `sudo -u <php-user>`
- `tools/aceshrug_gen.py`: `pip install tree-sitter tree-sitter-php pyyaml`

---

## Authors

- **Srećko Jovančević**: ideja i koncept ACESHRUG (ime, SHRUG princip, strategija), testiranje rešenja na terenu ([github.com/sreckojovancevic](https://github.com/sreckojovancevic))

## Acknowledgments

- **Gemini (Google)**: osnova koda builder-a i gatekeeper-a
- **Claude (Anthropic)**: elaboracija koncepta i arhitekture, pregled i testiranje koda (smoke matrica, testovi sa namerno pokvarenim gate-om), `tools/aceshrug_gen.py`, dokumentacija
