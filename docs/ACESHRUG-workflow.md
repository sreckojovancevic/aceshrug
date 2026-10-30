# ACESHRUG: koncept i radni tok

**ACESHRUG** = **A**pplication **C**apability **E**nforcement + **SHRUG**

> Aplikacija deklariše šta radi. Runtime je zaključava na tu deklaraciju. Na sve ostalo aplikacija samo slegne ramenima.

Status: ideja i strategija, sa radnim generatorom manifesta (`aceshrug_gen.py`). Oktobar 2026.

---

## 1. Princip

| Deo | Šta znači | Šta ograničava |
|---|---|---|
| **ACE** | Aplikacija unapred deklariše svoj svet: fajlove, funkcije, ulaze i resurse. Runtime je zaključan na tu deklaraciju. | Šta napadač može da **uradi** |
| **SHRUG** | Sve van deklaracije dobija isti nulti odgovor: bez greške, bez razlike (403/404/500), bez informacije. | Šta napadač može da **sazna** |
| **SHRUG signal** | Spolja tišina, iznutra potpuna svest. Svaki pokušaj van ugovora se beleži. | Ništa ne ostaje neviđeno |

**Analogija sa lopticama.** Ping-pong, tenis, golf i fudbal su različiti, ali svaka loptica deklariše "služim da me udaraš", i to specifično: čime i gde. Aplikacija je loptica (deklaracija), a runtime je sudija (sprovođenje).

**Analogija sa Rustom.** Cargo.toml je manifest, Cargo.lock je ledger, a cargo/rustc je sudija. Princip je isti, razlika je samo u tome šta se deklariše i kada se sprovodi.

| | Rust | ACESHRUG |
|---|---|---|
| Deklaracija | Cargo.toml | ACE manifest |
| Ledger | Cargo.lock (verzije, checksumi) | hash fajlova, brojači |
| Sudija | cargo / rustc | runtime (gate, engine, kernel) |
| Van deklaracije | build pada | SHRUG |
| Šta se deklariše | zavisnosti | mogućnosti |
| Kada se sprovodi | build | runtime |

**Opseg.** ACESHRUG je strategija, ne alat. Ne zavisi od jezika (PHP, Node.js, Python...), od veličine aplikacije ni od protokola. HTTP je samo transport, a nove metode (npr. QUERY) su nedeklarisane dok ih aplikacija sama ne prihvati.

**Granica tvrdnje.** ACE ograničava mogućnosti, ali ne ispravlja nameru. Greška u logici unutar dozvoljenog prostora (npr. IDOR) ostaje. Snaga zaštite je obrnuto srazmerna širini deklaracije.

**Pravilo dizajna.** Aplikacija mora biti napisana tako da se može deklarisati. Dinamički pozivi i generisani kod su prepreka, a ne detalj.

---

## 2. Četiri stuba arhitekture

1. **Ugovor (manifest)**: rute, metode, šeme parametara, fajlovi sa hash-om, dozvoljene funkcije, DB, FS i mreža.
2. **Kavez u dva stepena**:
   - **fini**, u engine-u (PHP: Zend hookovi `zend_compile_file`, hook na pozive funkcija, stream/fopen). Može da radi **po ruti**.
   - **čvrsti**, u kernelu (Landlock, seccomp, AppArmor) i u engine konfiguraciji po pool-u (`disable_functions`, `open_basedir`). Radi samo **po klasi**, jer php-fpm worker opslužuje mnogo različitih zahteva, a kernel profil može samo da se sužava.
3. **Šema vrednosti**: tip, dužina, opseg, regex i enum. To je **validacija, ne sanitizacija.**
4. **SHRUG + signal**: spolja uniforman nulti odgovor, iznutra brojač i događaj van mašine.

Ključna podela: **SHRUG je za oblik, poruke su za ishod.**
- Zahtev ispravnog oblika sa negativnim ishodom (pogrešna lozinka, zaključan nalog, istekao CSRF token) dobija normalnu poruku.
- Zahtev van ugovora (nepoznat parametar, vrednost van šeme, nedeklarisana ruta ili metoda) dobija SHRUG.

---

## 3. Radni tok

```
 [1] ANALIZA ──► [2] PREGLED ──► [3] ŠEMA ──► [4] KAVEZ ──► [5] MONITOR ──► [6] ENFORCE ──► [7] ODRŽAVANJE
   generator      blokeri         čovek        pool/DB        samo signal     SHRUG uključen    svaki deploy
```

### Korak 1: Analiza (automatski)

Generator pokrećeš nad svakim ulaznim fajlom (rutom ili CLI skriptom):

```bash
pip install tree-sitter tree-sitter-php pyyaml
python3 aceshrug_gen.py /var/www/html/app/login.php ~/scripts/cli_tool.php \
    --root /var/www/html --out manifesti
```

Generator izvodi sledeće:
- graf `include`/`require` i SHA-256 svakog fajla;
- **dostižne** pozive: korisničke funkcije ulaze tek kad su pozvane, ne samim tim što su definisane;
- allowlist ugrađenih funkcija, uz meru smanjenja površine (na test aplikaciji: 6 do 13 od 1.859, odnosno oko 99,3 do 99,7%);
- kostur šeme ulaza, sa nagoveštajima iz HTML forme i iz `switch` grana za argv;
- DB tabele, operacije i kolone, uz nacrt **column-level GRANT**-a;
- capability-je (exec, fs, net);
- **blokere** i **SHRUG kandidate**.

Izlazni kod je `2` ako postoji bar jedan bloker.

### Korak 2: Pregled blokera (čovek)

Manifest ne sme biti zaključan dok postoji ijedan bloker. Tipični blokeri:

| Bloker | Rešenje |
|---|---|
| fajl nije pronađen (`db.php`, `config.php`) | uključiti fajl u analizu |
| dinamički `include` | zameniti literalom ili mapom ruta |
| `$f()`, `call_user_func($x)` | zameniti eksplicitnim pozivom ili allowlist mapom |
| `$$var`, `extract()` | eksplicitne promenljive |
| `eval`, backtick | ukloniti |
| SQL koji nije literal | prepared statement sa literal upitom |
| dinamički ključ ulaza `$_GET[$k]` | eksplicitni ključevi |

Profilisanje (snimanje ponašanja tokom testa) je dozvoljeno kao pomoć, uz dve zamke:
- **trovanje**: napad tokom snimanja postaje "legitiman";
- **retke putanje** (godišnji izveštaj, recovery) koje se ne pojave u snimanju kasnije dobijaju SHRUG.

Zato je ručni pregled obavezan.

### Korak 3: Šema (čovek)

Svako `schema: TODO` dobija konkretnu šemu. Primer za login:

```yaml
POST:
  csrf_token: { type: string, regex: '^[0-9a-f]{64}$' }
  username:   { type: string, regex: '^[a-zA-Z0-9_]{4,20}$' }
  password:   { type: string, min: 8, max: 128 }
COOKIE:
  PHPSESSID:  { type: string, regex: '^[A-Za-z0-9,-]{1,128}$' }
```

Pravila za šemu:
- HTML `pattern` važi samo u browseru, a server ga **mora** proveravati.
- Svaki string ima **gornju granicu**.
- `FILTER_SANITIZE_*` menja ulaz, pa se zamenjuje validacijom.
- Polje za slobodan tekst šema samo **sužava**. Prepared statements i output encoding ostaju obavezni.

Politika za nepoznate ključeve:

| Izvor | Nepoznat ključ |
|---|---|
| GET / POST / FILES | SHRUG |
| COOKIE | nullovati (browser šalje i tuđe kolačiće sa istog domena) |

### Korak 4: Kavez (konfiguracija)

**Po klasi (pool):** aplikaciju svrstaj u 3 do 5 capability klasa, na primer `public-ro`, `auth-ro`, `auth-rw`, `admin`, `upload`. Svaka klasa dobija sledeće:
- zaseban php-fpm pool i zaseban sistemski user;
- `disable_functions` = sve ugrađene funkcije **osim** unije allowlist-a te klase (allowlist, nikad blacklist);
- `open_basedir` = samo direktorijum aplikacije, session path i tmp;
- AppArmor/Landlock profil;
- zaseban DB user sa **samo** grantovima iz nacrta. Primer za login:

```sql
GRANT SELECT (attempted_at, ip, username) ON app.login_attempts TO ace_login;
GRANT INSERT (ip, username)              ON app.login_attempts TO ace_login;
GRANT DELETE                             ON app.login_attempts TO ace_login;
GRANT SELECT (id, username, password_hash, is_active) ON app.users TO ace_login;
```

Login tada ne može da pročita ništa drugo, čak ni uz SQLi.

**Po ruti (gate):** prvo se izvršava gatekeeper, pre koda aplikacije, a uključuje se preko `auto_prepend_file`, koji aplikacija ne može da isključi. Proverava redom:
1. da li je ruta (ulazni fajl) deklarisana;
2. da li SAPI (web ili cli) odgovara;
3. da li je HTTP metoda dozvoljena;
4. da li su svi ulazi u šemi;
5. da li hash ulaznog fajla odgovara manifestu.

Fajlovi koji se samo uključuju (`functions.php`, `db.php`) nisu rute, pa direktan pristup njima dobija SHRUG.

**Fini kavez (budućnost):** C ekstenzija sa Zend hookovima za compile, pozive funkcija i stream. Samo ona daje allowlist funkcija i fajlova **po ruti** i zaštitu od izvršavanja nedeklarisanog koda.

### Korak 5: Monitor režim

Gate radi, ali **ne blokira**, samo beleži prekršaje. Trajanje je od nekoliko dana do nekoliko nedelja, zavisno od toga koliko je saobraćaj raznovrstan.
- Svaki signal iz legitimnog saobraćaja znači da je ugovor preuzak i da ga treba dopuniti.
- Signal iz nelegitimnog saobraćaja je potvrda da tripwire radi.
- Cilj: nula signala od legitimnih korisnika.

### Korak 6: Enforce režim

Prebacivanje je ručno (`mode: enforce`). Od tada:
- svaki prekršaj dobija **SHRUG**, uniforman odgovor (fiksni status, prazno telo, bez zaglavlja aplikacije);
- vreme odgovora je **izjednačeno** (padding do minimalnog trajanja), da se ne bi napravio timing side-channel;
- iz php-fpm-a nema pravog TCP blackhole-a (RST/444). Prazan odgovor je praktično ekvivalentan.

### Korak 7: Održavanje

- Svaki deploy menja hash-eve, pa se generator pokreće u **build/CI koraku**, ne ručno. Ako nije automatizovano, ljudi to isključe.
- Promenjen kod daje novi nacrt, pa sledi pregled razlike (diff ugovora) i potpis.
- Ugovor se čuva van domašaja aplikacije, nepromenljiv posle učitavanja.

---

## 4. SHRUG signal

Ključno svojstvo: **legitiman klijent nikad ne izlazi van ugovora.** Zato je svaki signal napad, izviđanje ili bug u klijentu. To je tripwire skoro bez lažnih uzbuna.

| Zahtev | Rešenje |
|---|---|
| bez timing razlike | logovanje van puta odgovora (asinhrono) |
| bez punjenja diska | lokalno samo **brojači i agregacija** (izvor, razlog, broj, prvi i poslednji put) |
| audit trail | append-only, ali **van mašine** (UDP syslog, SIEM, kolektor) |
| zaštita od log injection-a | escape, ograničena dužina, podatak se tretira kao nepoverljiv |
| zaštita od preplavljivanja | limit događaja po izvoru u minuti, preko limita samo brojač |

Signal može da hrani druge slojeve, npr. automatsku blokadu IP-a na firewall-u. Aplikacija ostaje nema, a sistem oko nje reaguje.

---

## 5. Granica poverenja: ko čuva čuvara

| Napad | Šta drži |
|---|---|
| zahtev van ugovora | gate (userland), dovoljno |
| RCE na PHP nivou (webshell, eval) | engine nivo (`disable_functions`, buduća ekstenzija); PHP kod ne može da isključi ekstenziju niti da dosegne `mprotect` (uz isključen FFI) |
| nativni RCE (memory corruption) | samo **kernel** (Landlock/seccomp) i **DB grantovi**; napadač ostaje zarobljen u mogućnostima **klase** |
| greška u logici unutar ugovora | ništa od ovoga; ostaju dobra praksa i pregled koda |

Precizna formulacija: **kernel ograničava štetu na klasu, ne čini je nemogućom.** Iz `auth-rw` klase napadač i dalje može da piše u bazu.

---

## 6. Plan PoC-a

| Faza | Cilj | Šta se meri |
|---|---|---|
| 1. mala CLI skripta | bez HTTP-a; testira se samo kavez | allowlist ugrađenih funkcija, DB grant, rad u enforcement režimu |
| 2. login stranica | HTTP ulaz, šema, SHRUG | broj signala u monitor režimu, overhead po zahtevu |
| 3. cela aplikacija | izdrži li generator stvarnu aplikaciju | broj blokera, broj klasa, vreme održavanja ugovora po deploy-u |

---

## 7. Postojeći srodni mehanizmi (pozicioniranje)

| Nivo | Postojeće | Razlika u odnosu na ACESHRUG |
|---|---|---|
| PHP | `disable_functions`, `open_basedir`, Snuffleupagus | generička pravila, a ne ugovor izveden iz konkretne aplikacije |
| Proces | OpenBSD `pledge`/`unveil` | isti duh, ali na nivou procesa |
| Platforma | Android manifest, Deno `--allow-*` | deklaracija dozvola, bez SHRUG-a i signala |
| Rust | cackle (`cargo acl`) | capability po crate-u, u vreme kompajliranja |
| WAF | positive security model, OpenAPI validacija | spoljni sloj, ne deo same aplikacije |

Novina nije nijedan sloj pojedinačno, nego **samodeklarisana granica po aplikaciji, izvedena iz nje same**, uz SHRUG kao princip neinformisanja i signal bez lažnih uzbuna.

---

## Authors

- **Srećko Jovančević**: ideja i koncept ACESHRUG (ime, SHRUG princip, analogije, strategija), test primeri ([github.com/sreckojovancevic](https://github.com/sreckojovancevic))
- **Claude (Anthropic)**: razrada arhitekture, kritička analiza i generator manifesta
