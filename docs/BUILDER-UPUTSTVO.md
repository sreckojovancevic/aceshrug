# ACESHRUG builder: uputstvo (v0.3.7)

Builder analizira PHP aplikaciju i u direktorijumu **van webroot-a** pravi gatekeeper (`gate.php`), ugovor (`manifest.php`), šablon php-fpm pool-a (`pool.conf`) i izveštaj (`REPORT.md`). **Kod aplikacije ostaje netaknut**: gate se uključuje preko `auto_prepend_file`.

Režim i potvrde dolaze iz **fajla sa ljudskim odlukama** (`<output>.decisions.json`), koji builder nikad ne prepisuje. Bez tog fajla sve je `auto`, a režim je **monitor**.

---

## 1. Preduslovi

| Šta | Zašto |
|---|---|
| Python 3.8+ | builder |
| `php` CLI, iste verzije kao na serveru | `php -l`, provera manifesta, smoke test |
| PHP 7.4+ na serveru | gate |
| root + `sudo` | vlasništvo `root:<grupa>`; provera čitljivosti kao `--php-user` |
| APCu (opciono) | ograničavanje broja signala po IP-u; bez njega nema limita |

---

## 2. Pokretanje

```bash
sudo mkdir -p /etc/aceshrug && sudo chmod 755 /etc/aceshrug
sudo python3 builder/aceshrug_build.py \
    --input  /var/www/html/app \
    --output /etc/aceshrug/app \
    --php-user  www-data \
    --php-group www-data
```

| Opcija | Značenje |
|---|---|
| `--input` | koren aplikacije; builder ga samo čita |
| `--output` | putanja **symlink-a** na aktivnu verziju; verzije se čuvaju u `<output>.d/<vreme>_<sufiks>/`. Mora biti van webroot-a. |
| `--php-user`, `--php-group` | korisnik i grupa PHP procesa (`pool.conf`, vlasništvo, provera čitljivosti) |
| `--allow-blocker KOD` / `--allow-blocker fajl.php:KOD` | ručno odobrenje blokera (vidi tačku 6); zastavica se ponavlja za svaku vrednost |
| `--keep N` | koliko verzija se čuva (podrazumevano 5) |
| `--rollback` | vraća symlink na verziju pre aktivne |
| `--decisions PATH` | fajl sa ljudskim odlukama (podrazumevano `<output>.decisions.json`) |
| `--confirm FAJL` | potvrđuje rutu: upisuje `confirmed` + trenutni `sha256` u decisions fajl (posle uspešne aktivacije, uz `.bak`); ponavlja se |
| `--reject FAJL` | isto, sa statusom `rejected` |
| `--reload apache` / `--reload fpm:SERVIS` | posle uspešne aktivacije ili rollback-a: `apache2ctl graceful`, odnosno `systemctl reload SERVIS` (npr. `fpm:php8.3-fpm`) |
| `--exclude PUTANJA` | direktorijum ili fajl (relativno na `--input`) koji ne ulazi u manifest; ponavlja se |
| `--include-unreadable` | ne preskače fajlove koje `--php-user` ne može da pročita (podrazumevano se preskaču) |
| `--log-file PUTANJA` | gate piše signale u ovaj fajl (apsolutna putanja, van `--input`), odvojeno od grešaka aplikacije; bez nje signali idu u `error_log` |
| `--export-decisions` | pravi decisions fajl iz trenutno aktivnog manifesta i izlazi (`--input` nije potreban) |
| `--strict` | odbija aktivaciju dok postoji ijedna `auto` stavka |
| `--accept-reclassified` | u enforcement režimu ipak aktivira kada se odluka za rutu odnosi na fajl koji je sada include |
| `--accept-stale` | u enforcement režimu ipak aktivira kada su neke potvrde zastarele (te rute prelaze u `auto`) |

### Šta builder radi, redom
1. Pravi spisak PHP fajlova bez `--exclude` stabala, pa izbacuje one koje **`--php-user` ne može da pročita**. Provera se radi kao taj korisnik (`sudo -u`), znači istim pogledom kao gate. Ako sama provera ne uspe, build staje.
   Analizira kod: rute, include-ove, parametre, blokere.
2. **Ako ima blokera, staje (kod 2) i ništa ne pravi.**
3. Pravi novu verziju u `<output>.d/<vreme>_<sufiks>/`.
4. Pokreće `php -l` nad `gate.php` i `manifest.php`, a zatim proverava strukturu manifesta (format v2).
5. Pokreće **smoke test** nad izolovanom probnom aplikacijom (tačka 8).
6. Postavlja vlasništvo `root:<php-group>`, `0750`/`0640`.
7. Proverava čitljivost **kao `--php-user`** (`sudo -u`).
8. Atomski prebacuje symlink na novu verziju i briše najstarije verzije preko `--keep`, uz marker; aktivnu nikad.

### Izlazni kodovi
| Kod | Značenje |
|---|---|
| `0` | aktivirano, sve stavke potvrđene |
| `1` | greška; aktivna verzija nije dirana |
| `2` | blokeri u kodu; ništa nije napravljeno |
| `3` | aktivirano u monitor režimu; postoje `auto` stavke (uobičajeno posle svakog build-a) |
| `5` | nova verzija je aktivna, ali `--reload` nije uspeo; uradi reload ručno |
| `4` | enforcement, a odluke traže pregled (promenjena potvrđena ruta ili ruta koja je postala include); aktivna verzija nije dirana (vidi tačku 7) |

---

## 3. Uključivanje na serveru

### Apache + mod_php
`examples/apache/aceshrug-app.conf` → `/etc/apache2/conf-available/`:
```apache
<Directory /var/www/html/app>
    php_admin_value auto_prepend_file /etc/aceshrug/app/gate.php
</Directory>
```
Signale gate piše u fajl iz `--log-file` (od v0.3.6), pa greške aplikacije ostaju u Apache error logu i ne mešaju se sa signalima. Ranija varijanta sa `php_admin_value error_log /var/log/aceshrug/app.log` i dalje radi bez `--log-file`, ali tada u isti fajl idu i `PHP Deprecated`/`Warning` poruke aplikacije.
```bash
sudo mkdir -p /var/log/aceshrug && sudo chown www-data:www-data /var/log/aceshrug
# build sa: --log-file /var/log/aceshrug/app.log
sudo a2enconf aceshrug-app && sudo apache2ctl configtest && sudo systemctl reload apache2
```
Vhost se ne dira. `php_admin_*` ne mogu da pregaze ni aplikacija ni `.htaccess`.

### php-fpm
Prilagoditi generisani `pool.conf` (`php_admin_value[auto_prepend_file]`, `php_admin_value[error_log]`), zatim `php-fpm -t && systemctl reload php*-fpm`.

### Rotacija loga
`examples/logrotate/aceshrug` → `/etc/logrotate.d/aceshrug`.

### Isključivanje
```bash
sudo a2disconf aceshrug-app && sudo systemctl reload apache2
```

---

## 4. Provera posle uključivanja

```bash
sudo grep -c 'ACESHRUG-EVENT' /var/log/aceshrug/app.log
sudo grep -c '"fatal_block"'  /var/log/aceshrug/app.log
```
U monitor režimu `fatal_block` mora biti **0**.

**Ako sajt vrati prazan 404 u monitor režimu**, odmah isključi konfiguraciju i pogledaj poslednji događaj u logu. U monitor režimu blokira samo neispravan manifest ili konfiguracija (`manifest_*`, `fatal_block`).

Česta pojava bila je `include_missing_or_outside`: builder (root) vidi fajl koji PHP korisnik ne može da pročita, najčešće direktorijum sa pravima `000` (namerno isključen modul). Od v0.3.5 builder takve fajlove sam preskače (provera kao `--php-user`) i navodi ih u REPORT-u pod "Preskočeno", pa ručna izmena manifesta više nije potrebna.

---

## 5. Monitor: tumačenje signala

```bash
sudo grep -h 'ACESHRUG-EVENT' /var/log/aceshrug/app.log | sed 's/.*\[ACESHRUG-EVENT\] //' \
  | python3 -c "import sys,json,collections; c=collections.Counter((j['event'],j['detail']) for j in map(json.loads,sys.stdin)); [print(n,e,d) for (e,d),n in c.most_common(40)]"
```

| Događaj | Najčešći uzrok |
|---|---|
| `unknown_parameter COOKIE: PHPSESSID` | sesijski kolačić nije u šemi |
| `unknown_parameter COOKIE: _ga*` | kolačići analitike sa domena |
| `unknown_parameter POST/GET: <polje>` | parametar čitan preko `filter_input` ili u uključenom fajlu |
| `unregistered_route` | fajl koji builder nije video kao rutu, ili stvarno direktan pristup include fajlu |
| `method_not_allowed`, `sapi_mismatch` | heuristika metode ili SAPI-ja je pogrešila |
| `file_tampered` / `include_tampered` | deploy bez ponovnog build-a, **ili napad** |
| `max_length_exceeded`, `type_mismatch_*`, `regex_mismatch` | legitimna vrednost van šeme, ili napad |

**Cilj:** legitiman saobraćaj daje nula signala.

---

### Kolačići (od v0.3.6)
- **Sesijski kolačić** (`session.name`, obično `PHPSESSID`) je uvek poznat i ne daje signal. Proverava se samo oblik ID-a (`[A-Za-z0-9,-]`, do 256 znakova); drugačiji daje `session_cookie_invalid` (u enforcement režimu, na potvrđenoj ruti, blokada).
- **Kolačići za praćenje** se tiho ignorišu po prefiksu. Podrazumevano: `_ga`, `_gid`, `_gat`, `_gcl`, `_fbp`. Lista se menja u decisions fajlu: `"ignore_cookie_prefixes": ["_ga", "_gid"]` (prazna lista = ništa se ne ignoriše).
- Na terenu su `PHPSESSID` i `_ga*` činili 84% svih signala.

### Polja događaja
Svaki signal sadrži i `route` (relativna putanja fajla) i `method` (`GET`, `POST`, ..., `CLI`), pa se vidi koji fajl je napadnut.

### Metode
`HEAD` je dozvoljen svuda gde je dozvoljen `GET` (monitoring, provera linkova).

## 6. Blokeri

| Kod | Šta je nađeno |
|---|---|
| `eval` | `eval(` |
| `extract` | `extract(` (napomena: hvata i `->extract(`) |
| `varvar` | `$$var` |
| `dyninclude` | `include $x` / `require $x` |
| `parse_str` | `parse_str()` sa jednim argumentom |

Analiza je regex, pa može da uhvati i vendor kod, komentare i JS. Odobrenje:
```bash
--allow-blocker vendor/neka/biblioteka/Fajl.php:extract   # samo taj fajl
--allow-blocker varvar                                    # globalno (oprezno)
```

---

## 7. Ljudske odluke i enforcement

Manifest v2 ima `status` po ruti i parametru:

| Status | Monitor | Enforcement |
|---|---|---|
| `auto` | signal | signal (builder uvek predlaže `auto`) |
| `confirmed` | signal | **blokada** pri prekršaju |
| `rejected` | signal | **blokada** uvek |

**Odluke se ne upisuju u manifest, nego u `<output>.decisions.json`.** Manifest se generiše pri svakom build-u, a decisions fajl je trajan i builder ga samo čita. Primer:

```json
{
  "mode": "enforcement",
  "unknown_policy": { "COOKIE": "null" },
  "routes": {
    "login.php": {
      "status": "confirmed",
      "sha256": "<hash fajla u trenutku potvrde>",
      "methods": ["GET", "POST"],
      "params": {
        "POST": {
          "username": { "type": "string", "max": 20, "regex": "/^[a-zA-Z0-9_]{4,20}$/", "status": "confirmed" },
          "password": { "type": "string", "max": 128, "status": "confirmed" }
        }
      }
    },
    "an1.php": { "status": "rejected" }
  }
}
```

Postupak:
1. pustiti monitor i pregledati signale (tačka 5);
2. potvrditi ili odbiti rute: `--confirm login.php --reject an1.php` (builder sam upisuje status i trenutni `sha256`), ili napraviti početni fajl sa `--export-decisions` i urediti ga ručno;
3. za parametre: potvrditi ih u decisions fajlu, ručno dodati parametre koje analiza ne vidi (npr. one koji se čitaju preko `filter_input`), postaviti `mode`;
4. ponovo pokrenuti builder. On validira fajl (statusi, tipovi, regex kroz PHP) i spaja odluke sa analizom.

**`confirmed` ruta mora imati `sha256`.** Potvrda važi samo za sadržaj koji je pregledan; bez hash-a builder odbija decisions fajl.

**Zastarele odluke:** ako se fajl potvrđene rute promenio (drugi hash), builder tu rutu i njene parametre vraća na `auto` i navodi ih u REPORT-u pod "Zastarele odluke". Tako izmenjen kod nikad ne nasleđuje staru potvrdu bez pregleda.
- **`rejected` ostaje `rejected`** i posle izmene fajla (ruta i parametri). Promena koda može tražiti novo odobrenje, ali nikad ne pretvara zabranu u propuštanje.
- **U enforcement režimu zastarela potvrda zaustavlja build** (kod 4) i aktivna verzija ostaje. Rešenje: pregledati izmenu i upisati novi `sha256`, ili svesno pokrenuti sa `--accept-stale`.

**Šta znači odluka za rutu:** `confirmed`/`rejected` u `routes` odnosi se na fajl kao **entrypoint** (direktan poziv). Ne zabranjuje izvršavanje tog fajla kroz `include`/`require`. Ako analiza fajl sa odlukom za rutu sada vidi kao include (na primer neko je dodao `require 'blocked.php'`), to je **reklasifikacija**: u monitor režimu upozorenje i sekcija u REPORT-u, a u enforcement režimu build staje (kod 4) dok se ne pregleda ili ne pokrene sa `--accept-reclassified`.

**Dve garancije, dve zastavice:**

| | Podrazumevano | `--strict` |
|---|---|---|
| promenjena potvrđena ruta | enforcement ne aktivira (kod 4) | ne aktivira |
| ruta postala include | enforcement ne aktivira (kod 4) | ne aktivira |
| **nov fajl bez odluke** | aktivira kao `auto` (samo signal), upozorenje + lista u REPORT-u | **ne aktivira** (kod 3) |

Podrazumevano ponašanje dozvoljava postepeno uvođenje enforcement-a. Za potpuno zaključan ugovor, gde nijedan nepregledan fajl ne sme da prođe, obavezan je `--strict`.

**Politika `null` za nepoznate parametre:** u monitor režimu samo signal (`logged_allow_would_drop`), ulaz se ne menja. U enforcement režimu, na potvrđenoj ruti, parametar se uklanja iz svog izvora, a `$_REQUEST[ključ]` se ponovo izvodi iz preostalih izvora istim redosledom kao PHP (`request_order`, inače `variables_order`). Ako ključ nema nijedan izvor, uklanja se. Tako `$_REQUEST` nikad ne zadržava odbačenu vrednost.

Enforcement se može uvoditi postepeno: rute koje ostanu `auto` i dalje samo daju signal.

---

## 8. Smoke test

Pre aktivacije builder pravi izolovanu probnu aplikaciju i pokreće stvarni `gate.php` preko `php -d auto_prepend_file`, sa sopstvenim `error_log`-om:

| # | Scenario | Očekivano |
|---|---|---|
| 1 | monitor, registrovana ruta | izlaz, kod 0, bez događaja |
| 2 | monitor, neregistrovana ruta | izlaz, kod 0, `unregistered_route` |
| 3 | enforcement, registrovana ruta | izlaz, kod 0, bez događaja |
| 4 | enforcement, neregistrovana ruta | prazno, kod 1, `unregistered_route` |
| 5 | enforcement, izmenjen ulazni fajl | prazno, kod 1, `file_tampered` |
| 6 | enforcement, izmenjen include | prazno, kod 1, `include_tampered` |
| 7 | neispravan manifest | prazno, kod 1, `manifest_structure_invalid` |
| 7a | `rejected` ruta, monitor | izlaz, kod 0, `rejected_route_accessed` |
| 7b | `rejected` ruta, enforcement | prazno, kod 1, `rejected_route_accessed` |
| 8 | `auto` parametar sa prekršajem, enforcement | izlaz, kod 0, `max_length_exceeded` |
| 9 | `confirmed` parametar sa prekršajem, enforcement | prazno, kod 1, `max_length_exceeded` |
| 10 | skripta koja upisuje fajl, ispravan parametar | upis se desio (dokaz da je test živ) |
| 11 | ista skripta, prekršaj `confirmed` parametra | prazno, kod 1, upis se **nije** desio |
| 12 | `null` politika, monitor | parametar ostaje, `logged_allow_would_drop` |
| 13 | `null` politika, enforcement, `auto` ruta | parametar ostaje, `logged_allow_would_drop` |
| 14 | `null` politika, enforcement, `confirmed` ruta | parametar uklonjen iz `$_GET` i `$_REQUEST`, `unknown_parameter_dropped` |
| 15 | kolizija: GET `x` deklarisan, POST `x` odbačen | `$_REQUEST['x']` = GET vrednost |
| 16 | kolizija: POST `x` deklarisan, GET `x` odbačen | `$_REQUEST['x']` = POST vrednost |
| 17 | `request_order=PGC`, `x` u GET i POST, COOKIE `x` odbačen | `$_REQUEST['x']` = GET vrednost (poslednja po redosledu) |
| 18 | kolačići: sesijski + `_ga*` | bez događaja |
| 19 | nepoznat kolačić | `unknown_parameter`, bez signala za `PHPSESSID` |
| 20 | loš session ID (monitor / enforcement) | `session_cookie_invalid` / blokada |
| 21 | događaj | sadrži `"route":"probe.php"` |
| 22 | `--log-file` | događaj u log fajlu, ne u `error_log` |

**Round-trip serijalizatora** (od v0.3.7): pre matrice, vrednosti i ključevi sa `'`, `\`, završnim `\`, novim redom, NUL bajtom i UTF-8 prolaze put Python → `manifest.php` → PHP → JSON i moraju se vratiti nepromenjeni. Isto radi i `python3 tests/test_php_escape.py`.

**HTTP smoke** (od v0.3.6, ugrađeni `php -S`, enforcement, potvrđena ruta sa `GET`):

| Zahtev | Očekivano |
|---|---|
| `GET /probe.php` | 200, telo |
| `HEAD /probe.php` | 200, bez signala |
| `PUT /probe.php` | 404, prazno, `Content-Length: 0`, `method_not_allowed` sa `"method":"PUT"` |
| `GET /other.php` | 404, prazno, `Content-Length: 0`, `unregistered_route` |

Provereno je da build odbija gate sa namerno ubačenim kvarovima: bez signala, bez prepoznavanja ruta, bez provere hash-a, monitor koji blokira, `rejected` koji blokira u monitoru, ignorisanje statusa, nikad ne blokira, `null` koji briše u monitoru, `null` koji nikad ne briše, `$_REQUEST` koji ostaje netaknut, `$_REQUEST` koji gleda samo prisustvo ključa (stara v0.3.2 logika), obrnut redosled izvora, ignorisan `request_order`, parametarski prekršaj bez blokade, bez `HEAD` pravila, sesijski kolačić kao nepoznat, bez ignorisanih prefiksa, svi kolačići ignorisani, bez provere session ID-a, bez rute u događaju, bez log fajla, bez `Content-Length: 0`, sve metode dozvoljene.

---

## 9. Održavanje

- **Posle svakog deploy-a aplikacije ponovo pokreni builder, sa `--reload`.** Hash je dokaz da se izvršava pregledani kod, pa svaka namerna izmena traži novi build. Reload je neophodan: gate učitava manifest preko pravog direktorijuma verzije, a PHP kešira razrešene putanje (`realpath_cache_ttl`, podrazumevano 120 s), pa bi procesi do dva minuta koristili staru verziju. `graceful` ne prekida zahteve u toku.

  ```bash
  # 1. kopiraj novi kod  2. build + reload
  sudo python3 builder/aceshrug_build.py --input /var/www/html/app --output /etc/aceshrug/app \
      --php-user www-data --php-group www-data --reload apache
  # kod 4 (enforcement, promenjena potvrđena ruta): pregledaj izmenu, pa
  sudo python3 builder/aceshrug_build.py ... --confirm login.php --reload apache
  ```
- **Namerno zaključani direktorijumi** (npr. prava `000`): builder radi kao root i vidi ih, ali gate radi kao `--php-user` i ne vidi. Zato ih builder od v0.3.5 sam preskače i navodi u REPORT-u ("Preskočeno"). Ranije je jedan takav include u manifestu oborio ceo sajt. Šta to znači: direktan poziv takvog fajla je neregistrovana ruta (u enforcement režimu SHRUG), a include se ne proverava hash-om.
- **`--exclude`** služi za delove koje svesno ne želiš u ugovoru (npr. `--exclude vendor --exclude push/moded`). Važi isto: nisu rute, a include-ovi iz njih nemaju proveru hash-a. Nepostojeća putanja ili putanja van `--input` je greška.
- Bez rebuild-a izmena izgleda kao napad: dobija se `file_tampered` (u monitor režimu) ili blokada (u enforcement režimu, za potvrđene rute; za izmenjen include, na svim rutama koje ga koriste).
- Povratak na prethodnu verziju: `sudo python3 builder/aceshrug_build.py --output /etc/aceshrug/app --rollback --reload apache`.
- Potpuno isključivanje: `a2disconf` + reload. Aplikacija radi kao pre, jer njen kod nikad nije menjan.
