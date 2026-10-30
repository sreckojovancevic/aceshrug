# ACESHRUG

**Application Capability Enforcement + SHRUG**: a self-declared security boundary for PHP applications.

> The application declares what it does. The runtime locks it to that declaration. Everything else gets a shrug.

*Aplikacija deklariše šta radi. Runtime je zaključava na tu deklaraciju. Na sve ostalo aplikacija samo slegne ramenima.*

[English](README.md)

Status: **v0.3.5, eksperimentalno.** Monitor režim je proveren na produkcionoj PHP aplikaciji (Apache + mod_php, PHP 8.3). Enforcement režim još nije za produkciju.

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
            ┌──────────────────── /etc/aceshrug/<app>/ ───────────────────┐
 HTTP ───▶  │ gate.php ◀── manifest.php (ugovor: rute, šeme, hash-evi)    │
 zahtev     └─────┬───────────────────────────────────────────────────────┘
                  │ auto_prepend_file (php_admin_value, ne može se pregaziti)
                  ▼
            /var/www/html/<app>/  ◀── kod aplikacije, NETAKNUT
```

1. **Builder** (`builder/aceshrug_build.py`) analizira aplikaciju i generiše `gate.php`, `manifest.php`, `pool.conf` i `REPORT.md` u direktorijum **van webroot-a**.
2. Gate se uključuje preko `auto_prepend_file`. **Kod aplikacije se ne menja.**
3. Gate pre svakog zahteva proverava rutu, SAPI, metodu, hash ulaznog fajla, integritet include-ova i šemu parametara.
4. **Monitor** režim beleži kršenja ugovora bez blokiranja. **Enforcement** blokira, i to samo stavke koje je čovek potvrdio (`status: confirmed`) ili odbio (`status: rejected`). Neispravan manifest ili konfiguracija su fatalni u oba režima.
5. Ljudske odluke se čuvaju u posebnom fajlu (`<output>.decisions.json`), koji builder nikad ne prepisuje, pa potvrde preživljavaju rebuild. Ako se potvrđen fajl promeni, njegova odluka se automatski vraća na pregled (a u enforcement režimu build staje dok se izmena ne pregleda). Odbijena stavka ostaje odbijena.

---

## Od čega štiti, a od čega ne

**U enforcement režimu ACESHRUG sprečava:**
- direktno izvršavanje PHP fajlova koji nisu deklarisani u manifestu (npr. webshell podmetnut **posle** build-a);
- izvršavanje deklarisanih fajlova koji su izmenjeni posle build-a;
- zahteve sa metodom ili parametrima van deklarisane šeme, za potvrđene rute i parametre.

**Ne sprečava:**
- zlonameran fajl koji je već postojao u trenutku build-a: builder popisuje zatečeno stanje, pa build uvek treba praviti iz pouzdanog release-a i pregledati rute;
- izvršavanje koda kroz ranjivost u legitimnoj ruti (LFI, `unserialize`, `eval` u kodu aplikacije);
- ranjivosti u samom PHP engine-u, npr. php2shell (CVE-2026-109618 / CVE-2026-109619). One se aktiviraju dok PHP parsira zahtev, pre nego što se gate učita. Tu je jedina zaštita ažuran PHP.

Na serveru je potreban **PHP 7.0+** (gate koristi `??` i odmah pozvanu closure funkciju). `mbstring` nije obavezan.

---

## Srodna rešenja: October CMS

Tokom razvoja ideje autor je došao do zaključka da October CMS već ima slično rešenje: njegov `.htaccess` dozvoljava direktan pristup samo određenim direktorijumima, a sve ostalo šalje na `index.php`. To potvrđuje pravac, ali je u pitanju drugi sloj:

| | October CMS `.htaccess` | ACESHRUG |
|---|---|---|
| Šta proverava | URL putanju (koji direktorijum sme) | fajl koji se stvarno izvršava, njegov hash, metode i parametre |
| Izmenjen `index.php` ili plugin | ne primećuje | `file_tampered` / blokada |
| Webshell ubačen u dozvoljeni direktorijum | zavisi od pravila za taj direktorijum | neregistrovana ruta, SHRUG |
| Ko može da ga promeni | sam `.htaccess` je fajl u webroot-u: ko ima upis, može da ga pregazi | `php_admin_value` u Apache konfiguraciji, van domašaja aplikacije |
| Signal | nema, samo 404 | svaki pokušaj u logu |
| Važi za | samo October CMS | bilo koju PHP aplikaciju, i onu bez ikakvih sličnih pravila |

Ukratko: `.htaccess` kaže koje putanje postoje, a ACESHRUG kaže šta sme da se izvrši i da li je to i dalje isti kod. Mogu se koristiti zajedno.

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

Tok ljudskog pregleda:
```bash
# posle pregleda signala: potvrdi / odbij rute (status + trenutni sha256 idu u app.decisions.json)
sudo python3 builder/aceshrug_build.py --input /var/www/html/app --output /etc/aceshrug/app \
    --confirm login.php --reject an1.php --reload apache
# prelazak na enforcement: "mode": "enforcement" u /etc/aceshrug/app.decisions.json, pa rebuild
```

Posle svakog deploy-a aplikacije ponovi build sa `--reload apache` (ili `--reload fpm:<servis>`). Hash ulaznog fajla je dokaz da radi pregledani kod, pa namerna izmena traži novi build. Reload čini da PHP odmah koristi novu verziju.

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
- PHP 7.0+ na serveru
- root, za vlasništvo `root:<php-group>` i proveru čitljivosti preko `sudo -u <php-user>`
- `tools/aceshrug_gen.py`: `pip install tree-sitter tree-sitter-php pyyaml`

---

## Licenca

**GPL-3.0-or-later**, uz [ACESHRUG izuzetak za generisani izlaz](LICENSE-EXCEPTION.md).

- Sam ACESHRUG (builder, alati, dokumentacija) je pod GNU GPL v3 ili novijom. Izmenjene verzije koje se distribuiraju moraju ostati otvorene.
- **Generisani izlaz** (`gate.php`, `manifest.php`, generisana konfiguracija) sme da se koristi uz bilo koju aplikaciju, pod bilo kojom licencom. Korišćenje ACESHRUG-a ne čini vašu aplikaciju GPL-om.

Vidi [LICENSE](LICENSE) i [LICENSE-EXCEPTION.md](LICENSE-EXCEPTION.md).

---

## Authors

- **Srećko Jovančević**: ideja i koncept ACESHRUG (ime, SHRUG princip, strategija), testiranje rešenja na terenu ([github.com/sreckojovancevic](https://github.com/sreckojovancevic))

## Acknowledgments

- **Gemini (Google)**: osnova koda builder-a i gatekeeper-a
- **ChatGPT (OpenAI)**: pregled i predlozi
- **Perplexity**: pregled koda (semantika monitor/enforcement, čuvanje ljudskih odluka kroz rebuild, UTF-8 bezbedno logovanje, konkurentna aktivacija, politika odluka i aktivacije)
- **Claude (Anthropic)**: elaboracija koncepta i arhitekture, pregled i testiranje koda (smoke matrica, testovi sa namerno pokvarenim gate-om), `tools/aceshrug_gen.py`, dokumentacija
