# ACESHRUG builder: uputstvo (v0.2.16)

Builder analizira PHP aplikaciju i u direktorijumu **van webroot-a** pravi gatekeeper (`gate.php`), ugovor (`manifest.php`), šablon php-fpm pool-a (`pool.conf`) i izveštaj (`REPORT.md`). **Kod aplikacije ostaje netaknut**: gate se uključuje preko `auto_prepend_file`.

Builder uvek aktivira **monitor** režim. **Enforcement** se uključuje ručno, i to blokira samo stavke koje je čovek potvrdio.

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

### Šta builder radi, redom
1. Analizira kod: rute, include-ove, parametre, blokere.
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

---

## 3. Uključivanje na serveru

### Apache + mod_php
`examples/apache/aceshrug-app.conf` → `/etc/apache2/conf-available/`:
```apache
<Directory /var/www/html/app>
    php_admin_value auto_prepend_file /etc/aceshrug/app/gate.php
    php_admin_value error_log /var/log/aceshrug/app.log
    php_admin_flag  log_errors on
</Directory>
```
```bash
sudo mkdir -p /var/log/aceshrug && sudo chown www-data:www-data /var/log/aceshrug
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

**Ako sajt vrati prazan 404**, odmah isključi konfiguraciju i pogledaj poslednji događaj u logu. Najčešći uzrok je `include_missing_or_outside`: builder (root) je video fajl koji PHP korisnik ne može da pročita, najčešće direktorijum sa pravima `000` (namerno isključen modul). Privremeno rešenje dok builder ne dobije proveru prava (vidi ROADMAP):

```bash
# 1. spisak stavki koje PHP korisnik ne vidi
sudo -u www-data php -r '
$m = require "/etc/aceshrug/app/manifest.php"; $r = $m["app_root"];
foreach (["includes","routes"] as $s) foreach ($m[$s] as $k => $v)
  if (!is_readable("$r/$k")) echo "$s\t$k\n";' > /tmp/ace_unreadable.txt

# 2. uklanjanje iz manifesta (original ostaje kao .bak)
M=$(readlink -f /etc/aceshrug/app)/manifest.php
sudo cp -p "$M" "$M.bak"
sudo php -r '$f=$argv[1]; $m=require $f;
foreach (file("/tmp/ace_unreadable.txt", FILE_IGNORE_NEW_LINES) as $l) { [$s,$k]=explode("\t",$l); unset($m[$s][$k]); }
file_put_contents($f, "<?php\nreturn ".var_export($m,true).";\n");' "$M"
sudo chown root:www-data "$M" && sudo chmod 640 "$M" && sudo -u www-data php -l "$M"
```

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

## 7. Status stavki i enforcement

Manifest v2 ima `status` po ruti i parametru:

| Status | Enforcement |
|---|---|
| `auto` | samo signal (builder uvek piše `auto`) |
| `confirmed` | blokada pri prekršaju |
| `rejected` | SHRUG uvek |

Za prelazak na enforcement treba:
1. pregledati monitor signale i popraviti šeme;
2. u `manifest.php` za proverene rute i parametre postaviti `'status' => 'confirmed'`, a zatim `'mode' => 'enforcement'`;
3. pokrenuti `php -l` nad manifestom i ponovo učitati Apache, jer opcache kešira manifest;
4. pratiti log; `"action":"blocked"` za legitimnog korisnika znači povratak u monitor.

Rute i parametri koji ostanu `auto` i dalje samo daju signal, pa se enforcement može uključivati postepeno.

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
| 8 | `auto` parametar sa prekršajem, enforcement | izlaz, kod 0, `max_length_exceeded` |
| 9 | `confirmed` parametar sa prekršajem, enforcement | prazno, kod 1, `max_length_exceeded` |

Provereno je da build odbija gate sa namerno ubačenim kvarovima: bez signala, bez prepoznavanja ruta, bez provere hash-a, monitor koji blokira, ignorisanje statusa, nikad ne blokira.

---

## 9. Održavanje

- **Posle svakog deploy-a aplikacije ponovo pokreni builder.** U suprotnom se dobija `file_tampered` (u monitor režimu) ili blokada (u enforcement režimu, za potvrđene rute).
- Povratak na prethodnu verziju: `sudo python3 builder/aceshrug_build.py --input x --output /etc/aceshrug/app --rollback`.
- Potpuno isključivanje: `a2disconf` + reload. Aplikacija radi kao pre, jer njen kod nikad nije menjan.
