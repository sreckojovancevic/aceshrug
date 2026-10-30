# ACESHRUG Generated Output Exception

ACESHRUG is licensed under the GNU General Public License, version 3 or (at your option) any later version (see `LICENSE`), with the following additional permission under section 7 of the GPL.

## Additional permission

**Generated output** means the files that the ACESHRUG builder writes for a target application, including:
- the gatekeeper (`gate.php`),
- the manifest (`manifest.php`),
- generated configuration (`pool.conf`, Apache configuration, logrotate configuration),
- the report (`REPORT.md`),

including any portions of ACESHRUG source code that the builder copies verbatim into these files.

As a special exception, you may use generated output, and run it together with any application (for example via PHP `auto_prepend_file`), and you may distribute a larger work that contains part or all of generated output under terms of your choice. Using generated output with an application does not, by itself, cause that application to be covered by the GNU General Public License.

This exception does not apply to a work that is itself a tool for generating such output (for example, a modified or derived ACESHRUG builder). Such a work remains under the GNU General Public License.

If you modify ACESHRUG itself, you may, at your option, remove this exception from your modified version. Your modified version and its generated output are then licensed under the GNU General Public License without this exception.

---

*Ovaj izuzetak je po uzoru na izuzetak koji koristi GNU Bison za generisani parser. Svrha: izmene samog ACESHRUG-a ostaju otvorene (GPL-3.0), a aplikacije koje ga koriste nisu obuhvaćene GPL-om.*
