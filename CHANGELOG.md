# Changelog

Verzije builder-a (`builder/aceshrug_build.py`). Svaka verzija je pregledana i pokrenuta. Od v0.2.11 nadalje provera uključuje i testove sa namerno pokvarenim gate-om, koji proveravaju da smoke test zaista hvata kvar.

## v0.2.16 (trenutna)
- Ime verzije je vreme + nasumični heks sufiks, uz `exist_ok=False`. Kolizija imena više ne može da prepiše niti obriše aktivnu verziju.
- `except` nikad ne briše direktorijum na koji pokazuje aktivni symlink.
- Smoke test dobija fixture prepend koji puni `$_GET`/`$_POST`. Testira se i status `auto` (prekršaj → samo signal) i `confirmed` (prekršaj → blokada).
- Vraćen REPORT.md, sa listom ruta po statusu.
- **Poznat problem:** fixture čita `$_ENV`. Uz `variables_order=GPCS` (podrazumevano na Debian-u i Ubuntu-u) build pada. Rešenje: `getenv()`.

## v0.2.15
- `abspath` umesto `realpath` za putanju symlink-a, pa drugi i svaki naredni build rade.
- Rollback ide korak po korak unazad, od aktivne verzije.
- Ispravno vlasništvo glavnog direktorijuma verzije. Greška je postojala od v0.2.6: gate nije bio čitljiv za PHP korisnika.
- Ispravljen SyntaxError (backslash u f-stringu).

## v0.2.14
- **Format manifesta v2**: `status` po ruti i parametru (`auto` / `confirmed` / `rejected`). Enforcement blokira samo potvrđene stavke.
- Verzionisani direktorijumi `<output>.d/<vreme>/` i atomska aktivacija preko symlink-a; `--keep`, `--rollback`.
- Regex se kompajlira pre upotrebe, pa neispravan regex znači grešku konfiguracije, a ne napad.
- Neuspeh `chown` prekida build; provera čitljivosti kao `--php-user`.

## v0.2.13
- Smoke test čita događaje iz sopstvenog `error_log`-a (`-d error_log=`), nezavisno od php.ini-ja servera.

## v0.2.12
- Smoke test proverava i **događaje**: registrovana ruta ne sme da proizvede signal, a prekršaji moraju.

## v0.2.11
- Pravi smoke test: izolovan probni app i manifest. Matrica od 5 scenarija (monitor/enforcement × registrovana/neregistrovana ruta + izmenjen fajl).

## v0.2.10
- Monitor režim više ne blokira pri `path_boundary_violation` ni pri `path_resolution_failed`.
- U CLI-ju blokada vraća izlazni kod 1.

## v0.2.9
- Gate čita `manifest.php` (ranije `manifest.json`).
- Vlasnik je uvek root; `int` validacija prihvata `0`.

## v0.2.8
- Tipovi `int` i `email`; nepoznat tip u šemi je fatalna greška manifesta.
- Stabilni kodovi blokera za `--allow-blocker`.

## v0.2.7
- Generisanje manifesta u ispravnoj PHP sintaksi; `php -l` pre aktivacije.
- Provera blokera pre aktivacije.
- Gate sprovodi `type` i `max`.

## v0.2.6 i ranije
- `auto_prepend_file` umesto ubacivanja koda u fajlove aplikacije.
- Izlaz van ulaza; atomska zamena sa backup-om i markerom.
- Include graf umesto klasifikacije po imenu fajla.
