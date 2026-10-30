# Changelog

Verzije builder-a (`builder/aceshrug_build.py`). Svaka verzija je pregledana i pokrenuta. Od v0.2.11 nadalje provera uključuje i testove sa namerno pokvarenim gate-om, koji proveravaju da smoke test zaista hvata kvar.

## v0.3.2 (trenutna)
Politika odluka i aktivacije, bez novih funkcija. Pravilo: promena koda može tražiti novo odobrenje, ali ne sme neprimetno pretvoriti zabranu u propuštanje.
- **`rejected` ostaje `rejected`** posle izmene fajla (ruta i parametri). U v0.3.1 zastarela `rejected` ruta postajala je `auto`, pa se u enforcement režimu propuštala.
- **`confirmed` ruta mora imati `sha256`.** Bez hash-a potvrda bi važila i za buduće izmene koda.
- **Enforcement sa zastarelim potvrdama ne aktivira se** (izlazni kod 4, aktivna verzija ostaje). Opt-out: `--accept-stale`.
- **`null` politika:** u monitor režimu samo signal (`logged_allow_would_drop`); uklanjanje samo u enforcement režimu na potvrđenoj ruti, i iz `$_REQUEST`.
- Validacija decisions fajla: `routes`/`unknown_policy`/`params` moraju biti objekti (ranije `AttributeError`); `max: true` se odbija (`bool` je u Python-u podtip `int`).
- Provera regex-a je fail-closed: pad PHP procesa ili neispravan izlaz zaustavlja build (ranije je prazan izlaz značio "svi regex-i ispravni").
- Smoke test: parametarski sentinel sa skriptom koja stvarno pokušava upis (uz kontrolni slučaj koji dokazuje da test radi); tri scenarija za `null` politiku.
- Provereno sa 4 nova namerno pokvarena gate-a: svi odbijeni.

## v0.3.1
- **Ljudske odluke u posebnom fajlu** `<output>.decisions.json`, koji builder nikad ne prepisuje. Spaja se sa analizom pri svakom build-u: odluka ima prednost (status, `mode`, `unknown_policy`, metode, SAPI, pravila parametara uključujući `regex` i ručno dodate parametre).
- **Zastarele odluke:** ako se fajl potvrđene rute promeni (drugi hash), ruta i njeni parametri vraćaju se na `auto`, uz sekciju u REPORT-u.
- `--export-decisions`: pravi decisions fajl iz trenutno aktivnog manifesta. `--decisions PATH` zadaje drugu lokaciju.
- Validacija decisions fajla (režim, politike, statusi, tipovi, `max`, hash, SAPI, metode) i provera svih regex-a kroz PHP pre build-a.
- `rejected` u monitor režimu samo beleži, a blokira u enforcement režimu.
- Gate: whitelist statusa (`auto`/`confirmed`/`rejected`); UTF-8 bezbedno skraćivanje bez obavezne mbstring ekstenzije; JSON flag kompatibilan sa PHP < 7.2.
- Smoke test: `getenv()` umesto `$_ENV`; novi scenariji za `rejected` u oba režima.
- Provereno testovima sa namerno pokvarenim gate-om (ignorisanje statusa, `rejected` koji blokira u monitoru, bez signala, nikad ne blokira): svi odbijeni.

## v0.3.0
- `flock` zaključavanje build-a i rollback-a; `--keep` ≥ 1; odbijanje prazne aplikacije; `--strict`.
- Include greška u monitor režimu je signal, a ne blokada.
- Politika `null` stvarno uklanja nepoznat parametar.
- Sentinel test (blokirana skripta ne sme da napravi fajl).
- Bolji regex za dinamički `include`/`require` (i `_once` i oblik sa zagradom).
- Poznato: `$_ENV` u smoke fixture-u; nasleđivanje potvrda iz generisanog manifesta gubilo je `mode`, `regex` i ručno dodate parametre (rešeno u v0.3.1).

## v0.2.16
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
