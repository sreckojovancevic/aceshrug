# Roadmap

## Zahtevi sa terena (prva proba, oktobar 2026)

Prva proba u monitor režimu na produkcionoj PHP aplikaciji (~1.300 PHP fajlova, Apache + mod_php, PHP 8.3) dala je sledeće zahteve:

| # | Zahtev | Zašto |
|---|---|---|
| 1 | `getenv()` umesto `$_ENV` u smoke fixture-u | uz `variables_order=GPCS` build uvek pada |
| 2 | **provera čitljivosti svakog fajla i direktorijuma kao `--php-user`** pre generisanja; nečitljivo se izostavlja iz manifesta i prijavljuje | builder radi kao root i vidi direktorijume sa pravima `000` (namerno isključene module), a gate radi kao www-data; jedan takav include je oborio ceo sajt |
| 3 | `include_missing_or_outside` u monitor režimu = **signal**, ne blokada | monitor po definiciji ne sme da blokira |
| 4 | odbiti `--output` unutar webroot-a | REPORT i konfiguracija ne smeju biti dostupni preko URL-a |
| 5 | `--vendor <dir>`: include-only, sa hash-om, bez skeniranja blokera i bez statusa rute | vendor kod je dao 15 lažnih blokera i ~1.200 "ruta" |
| 6 | regex za `extract` ne sme da hvata `->extract(` ni `function extract(` | lažni nalazi u ZIP bibliotekama |
| 7 | kolačići: politika `null` koja se sprovodi; sesijski kolačić automatski u šemi | `PHPSESSID` i `_ga*` daju signal na svakom zahtevu |
| 8 | kreiranje direktorijuma verzije unutar `try`, sa urednom porukom | traceback pri koliziji imena |

## Nove funkcije

### Provera prava pre generisanja
Pre analize builder prolazi kroz ulazni direktorijum i za svaki poddirektorijum proverava da li `--php-user` može da uđe u njega:
- direktorijum sa pravima `000`, ili bez prava `x`, tretira se kao **namerno isključen**, a sve ispod njega se izostavlja iz manifesta;
- REPORT dobija sekciju "Isključeni direktorijumi" (putanja, prava, broj preskočenih fajlova);
- čitljiv fajl koji uključuje nešto iz isključenog direktorijuma daje upozorenje, jer je kod verovatno mrtav.

### Interaktivni čarobnjak (`--wizard`, ili pokretanje bez argumenata)
1. Putanja do aplikacije.
2. Lokacija ACESHRUG-a: podrazumevano `/etc/aceshrug/<app>`, ili po izboru. Proverava se da nije u webroot-u niti u ulazu.
3. Prepoznavanje web servera: `apache2ctl -M` (`php_module` / `proxy_fcgi`) i `php*-fpm` servis.
4. "Da li želite da sada podesim Apache?" Ako da: `conf-available/aceshrug-<app>.conf` → `a2enconf` → `configtest`, pa "Uključiti sada?". Posle reload-a builder sam pošalje probni zahtev. Ako dobije prazan 404, odmah radi `a2disconf` + reload i ispisuje razlog iz loga (automatski rollback).
5. "Da li želite da podesim log?" Ako da: `/var/log/aceshrug/<app>.log` i `/etc/logrotate.d/aceshrug`.
6. Rezime: šta je urađeno, kako se isključuje, gde je REPORT.

Neinteraktivni režim ostaje za CI: svako pitanje ima i odgovarajuću opciju (`--output`, `--setup-apache`, `--setup-log`, `--yes`).

## Kasnije

- Integracija `tools/aceshrug_gen.py` u builder (parser umesto regex-a; `filter_input`, `__DIR__` include, parametri kroz include lanac).
- Korak potvrđivanja (`--confirm`): prelazak `auto` → `confirmed` po stavkama.
- Odvojiti "fajl sme biti uključen" od "fajl sme biti direktno pozvan" (sada je fajl ili ruta ili include, po heuristici), i graf zavisnosti po ruti.
- HTTP smoke test (status, telo, zaglavlja, metode) uz postojeći CLI test.
- `disable_functions` (allowlist) i `open_basedir` u generisanoj konfiguraciji.
- Hash include-a van puta zahteva (cron ili reload), umesto na svakom zahtevu.
- SHRUG sa izjednačenim vremenom odgovora.
- Signal ka kolektoru van mašine (UDP syslog).
- Fini kavez po ruti: C ekstenzija sa Zend hookovima.
