#!/usr/bin/env python3
"""
aceshrug-gen — ACESHRUG manifest generator (draft) za PHP aplikacije.

Analizira PHP kod od ulaznog fajla (entry), prati include/require graf,
računa dostižne pozive i pravi NACRT manifesta:
  - fajlovi + sha256
  - dostižne ugrađene funkcije (allowlist za Zend nivo)
  - ulazi (GET/POST/COOKIE/argv) kao kostur šeme, sa nagoveštajima iz HTML forme
  - DB tabele / operacije / kolone (osnova za GRANT)
  - capability-ji (exec / fs / net)
  - BLOKERI: sve dinamičko što onemogućava zaključavanje
  - SHRUG kandidati: odgovori koji otkrivaju postojanje ili razlog odbijanja

Generator NIKAD ne zaključava manifest. Status je uvek DRAFT;
zaključavanje (potpis) je ručni korak posle pregleda.

Upotreba:
  python3 aceshrug_gen.py ENTRY.php [ENTRY2.php ...] [--out DIR]
         [--cwd DIR] [--map /deploy/path=/local/path ...] [--php php]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

import tree_sitter_php as tsp
from tree_sitter import Language, Parser

PARSER = Parser(Language(tsp.language_php()))

# --- klasifikacije -----------------------------------------------------------

CONSTRUCTS = {"isset", "empty", "exit", "die", "list", "unset", "array",
              "print", "echo"}
DYNAMIC_EXEC = {"eval", "create_function", "assert"}
CALLBACK_INVOKERS = {"call_user_func", "call_user_func_array",
                     "forward_static_call", "forward_static_call_array"}
# funkcije koje primaju callback: ime -> indeks argumenta
CALLBACK_ARGS = {"array_map": 0, "array_filter": 1, "array_walk": 1,
                 "usort": 1, "uasort": 1, "uksort": 1, "array_reduce": 1,
                 "preg_replace_callback": 1, "register_shutdown_function": 0,
                 "spl_autoload_register": 0, "set_error_handler": 0,
                 "set_exception_handler": 0, "iterator_apply": 1}
SCOPE_POLLUTERS = {"extract", "parse_str", "import_request_variables"}
EXEC_FUNCS = {"exec", "system", "passthru", "shell_exec", "proc_open",
              "popen", "pcntl_exec", "pcntl_fork", "mail"}
FS_FUNCS = {"fopen", "file_get_contents", "file_put_contents", "file",
            "readfile", "unlink", "rename", "copy", "mkdir", "rmdir",
            "touch", "chmod", "chown", "move_uploaded_file", "opendir",
            "scandir", "glob", "tempnam", "fwrite", "parse_ini_file"}
NET_FUNCS = {"curl_init", "curl_exec", "fsockopen", "pfsockopen",
             "stream_socket_client", "socket_create", "socket_connect",
             "ftp_connect", "ldap_connect", "get_headers", "dns_get_record"}
WARN_FUNCS = {"unserialize": "unserialize() nad spoljnim podatkom je klasičan put do RCE (gadget chains)",
              "ffi_cdef": "FFI omogućava nativni kod iz PHP-a",
              "ini_set": "ini_set() menja runtime konfiguraciju u hodu",
              "set_include_path": "menja razrešavanje include-a u hodu",
              "dl": "učitavanje ekstenzija u hodu"}
SQL_METHODS = {"prepare", "query", "exec"}
SQL_FUNCS = {"mysqli_query": 1, "mysqli_prepare": 1, "pg_query": 1,
             "pg_prepare": 2}
INPUT_SUPERGLOBALS = {"_GET": "GET", "_POST": "POST", "_COOKIE": "COOKIE",
                      "_REQUEST": "REQUEST", "_FILES": "FILES"}
FILTER_INPUT_TYPES = {"INPUT_GET": "GET", "INPUT_POST": "POST",
                      "INPUT_COOKIE": "COOKIE", "INPUT_SERVER": "SERVER",
                      "INPUT_ENV": "ENV"}


def txt(node):
    return node.text.decode("utf-8", "replace")


def lit(node, ctx=None, cur_file=None):
    """Vrati literal string vrednost izraza ili None ako je dinamičan."""
    if node is None:
        return None
    t = node.type
    if t in ("string", "encapsed_string"):
        out = []
        for c in node.named_children:
            if c.type == "string_content":
                out.append(txt(c))
            elif c.type == "escape_sequence":
                out.append({"\\n": "\n", "\\t": "\t", "\\\\": "\\",
                            "\\'": "'", '\\"': '"', "\\$": "$"}.get(txt(c), txt(c)))
            else:
                return None  # interpolacija promenljive
        return "".join(out)
    if t == "integer":
        return txt(node)
    if t == "name" and txt(node) == "__DIR__" and cur_file:
        return os.path.dirname(cur_file)
    if t == "name" and txt(node) == "__FILE__" and cur_file:
        return cur_file
    if t == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and txt(op) == ".":
            a = lit(node.child_by_field_name("left"), ctx, cur_file)
            b = lit(node.child_by_field_name("right"), ctx, cur_file)
            if a is not None and b is not None:
                return a + b
        return None
    if t == "parenthesized_expression" and node.named_children:
        return lit(node.named_children[0], ctx, cur_file)
    if t == "function_call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and txt(fn).lower() == "dirname":
            args = call_args(node)
            if len(args) == 1:
                v = lit(args[0], ctx, cur_file)
                if v is not None:
                    return os.path.dirname(v)
    return None


def call_args(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    out = []
    for a in args.named_children:
        if a.type == "argument" and a.named_children:
            out.append(a.named_children[-1])
        elif a.type != "comment":
            out.append(a)
    return out


def superglobal_name(node):
    """Za subscript_expression vrati (ime_promenljive, kljuc_node)."""
    if node.type != "subscript_expression" or not node.named_children:
        return None, None
    base = node.named_children[0]
    key = node.named_children[1] if len(node.named_children) > 1 else None
    if base.type == "variable_name":
        return txt(base).lstrip("$"), key
    return None, None


def loc(cur_file, node, root):
    return f"{os.path.relpath(cur_file, root)}:{node.start_point[0] + 1}"


# --- SQL ----------------------------------------------------------------------

SQL_KW = {"select", "from", "where", "and", "or", "not", "null", "is", "in",
          "like", "limit", "order", "by", "group", "having", "as", "on",
          "join", "left", "right", "inner", "outer", "desc", "asc", "values",
          "set", "into", "interval", "second", "minute", "hour", "day", "now",
          "count", "sum", "max", "min", "avg", "distinct", "between", "case",
          "when", "then", "else", "end", "true", "false"}


def split_top(s):
    """Podeli po zarezima van zagrada."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def parse_sql(sql):
    """Gruba analiza: vrati listu (op, tabela, kolone, napomena)."""
    s = re.sub(r"\s+", " ", sql.strip())
    low = s.lower()
    res = []
    m = re.match(r"^(select|insert|update|delete|replace)\b", low)
    if not m:
        return [("?", None, set(), f"nepoznat SQL: {s[:60]}")]
    op = m.group(1).upper()
    note = None
    tables = []
    if op == "SELECT":
        tables = re.findall(r"\b(?:from|join)\s+`?([a-z_][a-z0-9_]*)`?", low)
    elif op in ("INSERT", "REPLACE"):
        tables = re.findall(r"\binto\s+`?([a-z_][a-z0-9_]*)`?", low)
    elif op == "UPDATE":
        tables = re.findall(r"^update\s+`?([a-z_][a-z0-9_]*)`?", low)
    elif op == "DELETE":
        tables = re.findall(r"\bfrom\s+`?([a-z_][a-z0-9_]*)`?", low)
    cols = set()
    aliases = set()
    if op == "SELECT":
        sel = re.search(r"^select\s+(?:distinct\s+)?(.*?)\s+from\b", low)
        if sel:
            if re.search(r"(^|,)\s*\*\s*(,|$)", sel.group(1)):
                note = "SELECT * — column-level GRANT nije moguć dok se kolone ne navedu"
            for part in split_top(sel.group(1)):
                part = part.strip()
                am = re.match(r"^(.*?)\s+(?:as\s+)?`?([a-z_][a-z0-9_]*)`?$", part)
                if am and (("(" in am.group(1)) or re.match(r"^[a-z_][\w.]*$", am.group(1))):
                    aliases.add(am.group(2))
                    part = am.group(1)
                for ident in re.findall(r"\b([a-z_][a-z0-9_]*)\b(?!\s*\()", part):
                    if ident not in SQL_KW:
                        cols.add(ident.split(".")[-1])
    if op in ("INSERT", "REPLACE"):
        cm = re.search(r"into\s+`?[a-z_][a-z0-9_]*`?\s*\(([^)]*)\)", low)
        if cm:
            cols |= {c.strip(" `") for c in cm.group(1).split(",") if c.strip()}
    if op == "UPDATE":
        sm = re.search(r"\bset\s+(.*?)(\bwhere\b|$)", low)
        if sm:
            cols |= set(re.findall(r"`?([a-z_][a-z0-9_]*)`?\s*=", sm.group(1)))
    # kolone u WHERE / GROUP / ORDER traže SELECT privilegiju
    tail = re.search(r"\b(where|group by|order by)\b(.*)$", low)
    if tail:
        for ident in re.findall(r"\b([a-z_][a-z0-9_]*)\b", tail.group(2)):
            if ident not in SQL_KW and ident not in aliases and not ident.isdigit():
                cols.add(ident)
    for t in tables or [None]:
        res.append((op, t, cols, note))
    return res


# --- HTML forma (nagoveštaji šeme) ---------------------------------------------

def html_hints(src):
    hints = {}
    methods = set()
    for fm in re.finditer(r"<form\b[^>]*\bmethod\s*=\s*[\"']?(\w+)", src, re.I):
        methods.add(fm.group(1).upper())
    for im in re.finditer(r"<(input|textarea|select)\b([^>]*)>", src, re.I):
        attrs = dict((k.lower(), v) for k, _, v in
                     re.findall(r"([\w-]+)\s*=\s*([\"'])(.*?)\2", im.group(2)))
        name = attrs.get("name")
        if not name:
            continue
        h = {k: attrs[k] for k in ("type", "pattern", "minlength", "maxlength",
                                   "min", "max") if k in attrs}
        if re.search(r"\brequired\b", im.group(2), re.I):
            h["required"] = True
        if im.group(1).lower() != "input":
            h["type"] = im.group(1).lower()
        hints[name] = h
    return hints, methods


# --- analiza ------------------------------------------------------------------

class Ctx:
    def __init__(self, entry, root, maps, cwd):
        self.entry = entry
        self.root = root
        self.maps = maps
        self.cwd = cwd
        self.files = {}            # path -> sha256
        self.trees = {}            # path -> tree
        self.user_funcs = {}       # name.lower -> (file, node)
        self.user_methods = {}     # name.lower -> [(file, node)]
        self.user_classes = {}     # name.lower -> (file, node)
        self.expanded = set()
        self.called = {}           # name.lower -> first loc
        self.methods = set()
        self.static_calls = set()
        self.classes = set()
        self.new_classes = set()
        self.inputs = {}           # src -> {key: {...}}
        self.server_keys = set()
        self.session_keys = set()
        self.argv = {}             # idx -> {}
        self.argv_vars = {}        # $var -> idx
        self.http_methods = set()
        self.sapi = set()
        self.db = {}               # table -> {ops:set, cols:set, notes:set}
        self.exec_caps = set()
        self.fs = set()
        self.net = set()
        self.globals = set()
        self.blockers = []
        self.warnings = []
        self.shrug = []
        self.html = {}
        self.form_methods = set()

    # mapiranje deploy putanja na lokalne
    def map_path(self, p):
        for a, b in self.maps:
            if p == a or p.startswith(a.rstrip("/") + "/"):
                return b + p[len(a):]
        return p

    def L(self, f, n):
        return loc(f, n, self.root)

    def block(self, f, n, msg):
        self.blockers.append(f"{self.L(f, n)}  {msg}")

    def warn(self, f, n, msg):
        self.warnings.append(f"{self.L(f, n)}  {msg}")


def load_file(ctx, path):
    path = os.path.normpath(path)
    if path in ctx.trees:
        return False
    with open(path, "rb") as fh:
        data = fh.read()
    ctx.files[path] = hashlib.sha256(data).hexdigest()
    tree = PARSER.parse(data)
    ctx.trees[path] = tree
    # registracija definicija (PHP hoisting)
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            nm = n.child_by_field_name("name")
            if nm is not None:
                ctx.user_funcs[txt(nm).lower()] = (path, n)
        elif n.type == "method_declaration":
            nm = n.child_by_field_name("name")
            if nm is not None:
                ctx.user_methods.setdefault(txt(nm).lower(), []).append((path, n))
        elif n.type in ("class_declaration", "trait_declaration"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                ctx.user_classes[txt(nm).lower()] = (path, n)
        stack.extend(n.children)
    # HTML nagoveštaji
    src = data.decode("utf-8", "replace")
    h, m = html_hints(src)
    ctx.html.update(h)
    ctx.form_methods |= m
    return True


def resolve_include(ctx, cur_file, p):
    p = ctx.map_path(p)
    cands = []
    if os.path.isabs(p):
        cands = [p]
    elif p.startswith("./") or p.startswith("../"):
        cands = [os.path.join(ctx.cwd, p)]
    else:  # include_path '.' (cwd), pa direktorijum pozivajućeg fajla
        cands = [os.path.join(ctx.cwd, p), os.path.join(os.path.dirname(cur_file), p)]
    for c in cands:
        if os.path.isfile(c):
            return os.path.normpath(c), cands
    return None, cands


def walk(ctx, node, cur_file):
    """Obilazi izvršni kod; ne ulazi u tela funkcija/metoda (to radi expand)."""
    stack = [node]
    while stack:
        n = stack.pop()
        t = n.type
        if t in ("function_definition", "method_declaration"):
            continue
        if t in ("class_declaration", "trait_declaration", "interface_declaration"):
            continue
        handle(ctx, n, cur_file)
        if t in ("include_expression", "include_once_expression",
                 "require_expression", "require_once_expression"):
            continue  # include obrađen u handle
        stack.extend(reversed(n.children))


def handle(ctx, n, f):
    t = n.type

    if t in ("include_expression", "include_once_expression",
             "require_expression", "require_once_expression"):
        arg = n.named_children[0] if n.named_children else None
        p = lit(arg, ctx, f)
        if p is None:
            ctx.block(f, n, f"dinamički {t.split('_')[0]}: {txt(n)[:70]}")
            return
        target, cands = resolve_include(ctx, f, p)
        if target is None:
            ctx.block(f, n, f"fajl nije pronađen: '{p}' (traženo: {', '.join(dict.fromkeys(os.path.relpath(c, ctx.root) for c in cands))})")
            return
        if load_file(ctx, target):
            walk(ctx, ctx.trees[target].root_node, target)
        return

    if t == "function_call_expression":
        fn = n.child_by_field_name("function")
        args = call_args(n)
        if fn is None or fn.type not in ("name", "qualified_name"):
            ctx.block(f, n, f"dinamički poziv funkcije: {txt(n)[:70]}")
            return
        name = txt(fn).split("\\")[-1]
        low = name.lower()
        ctx.called.setdefault(low, ctx.L(f, n))
        if low in DYNAMIC_EXEC:
            if low == "assert" and args and args[0].type not in ("string", "encapsed_string"):
                pass
            else:
                ctx.block(f, n, f"{name}() izvršava kod iz stringa")
        if low in CALLBACK_INVOKERS:
            cb = lit(args[0], ctx, f) if args else None
            if cb is None:
                ctx.block(f, n, f"{name}() sa dinamičkim callback-om")
            else:
                ctx.called.setdefault(cb.lower(), ctx.L(f, n))
        if low in CALLBACK_ARGS:
            i = CALLBACK_ARGS[low]
            if len(args) > i:
                a = args[i]
                if a.type in ("anonymous_function", "arrow_function",
                              "anonymous_function_creation_expression"):
                    pass  # closure se obilazi normalno
                else:
                    cb = lit(a, ctx, f)
                    if cb is None:
                        ctx.block(f, n, f"{name}() sa dinamičkim callback-om")
                    else:
                        ctx.called.setdefault(cb.lower(), ctx.L(f, n))
        if low in SCOPE_POLLUTERS and not (low == "parse_str" and len(args) >= 2):
            ctx.block(f, n, f"{name}() pravi promenljive iz podataka")
        if low in EXEC_FUNCS:
            ctx.exec_caps.add(name)
            ctx.warn(f, n, f"exec capability: {name}()")
        if low in FS_FUNCS:
            p = lit(args[0], ctx, f) if args else None
            ctx.fs.add(f"{name}({p!r})" if p else f"{name}(<dinamička putanja>)")
            if p is None:
                ctx.warn(f, n, f"{name}() sa dinamičkom putanjom — FS allowlist nepotpun")
        if low in NET_FUNCS:
            ctx.net.add(name)
        if low in ("file_get_contents", "fopen") and args:
            p = lit(args[0], ctx, f)
            if p and re.match(r"^[a-z]+://", p):
                ctx.net.add(f"{name}({p})")
        if low in WARN_FUNCS:
            ctx.warn(f, n, WARN_FUNCS[low])
        if low == "chdir" and args:
            p = lit(args[0], ctx, f)
            if p is None:
                ctx.block(f, n, "chdir() sa dinamičkom putanjom — razrešavanje include-a nepouzdano")
            else:
                ctx.cwd = ctx.map_path(p)
        if low == "filter_input" and len(args) >= 2:
            src = FILTER_INPUT_TYPES.get(txt(args[0]), txt(args[0]))
            key = lit(args[1], ctx, f)
            if key is None:
                ctx.block(f, n, "filter_input() sa dinamičkim ključem")
            elif src == "SERVER":
                ctx.server_keys.add(key)
            else:
                d = ctx.inputs.setdefault(src, {}).setdefault(key, {})
                if len(args) >= 3:
                    d.setdefault("filters", set()).add(txt(args[2]))
        if low in SQL_FUNCS and len(args) > SQL_FUNCS[low] - 1:
            sql_arg(ctx, f, n, args[SQL_FUNCS[low] - 1])
        if low == "http_response_code" and args:
            code = lit(args[0], ctx, f)
            if code and code.isdigit() and int(code) >= 400:
                ctx.shrug.append(f"{ctx.L(f, n)}  http_response_code({code}) otkriva razlog odbijanja")
        if low == "header" and args:
            h = lit(args[0], ctx, f) or ""
            m = re.match(r"^HTTP/\S+\s+(\d{3})", h)
            if m and int(m.group(1)) >= 400:
                ctx.shrug.append(f"{ctx.L(f, n)}  header('{h}') otkriva razlog odbijanja")
        return

    if t in ("member_call_expression", "nullsafe_member_call_expression"):
        nm = n.child_by_field_name("name")
        if nm is None or nm.type != "name":
            ctx.block(f, n, f"dinamički poziv metode: {txt(n)[:70]}")
            return
        mname = txt(nm)
        ctx.methods.add(mname)
        if mname.lower() in SQL_METHODS:
            args = call_args(n)
            if args:
                sql_arg(ctx, f, n, args[0])
        return

    if t == "scoped_call_expression":
        sc = n.child_by_field_name("scope")
        nm = n.child_by_field_name("name")
        if nm is None or nm.type != "name" or sc is None or sc.type not in ("name", "qualified_name", "relative_scope"):
            ctx.block(f, n, f"dinamički statički poziv: {txt(n)[:70]}")
            return
        ctx.static_calls.add(f"{txt(sc)}::{txt(nm)}")
        ctx.methods.add(txt(nm))
        return

    if t == "object_creation_expression":
        kids = [c for c in n.named_children if c.type != "arguments"]
        if kids and kids[0].type in ("name", "qualified_name"):
            ctx.new_classes.add(txt(kids[0]).split("\\")[-1])
        elif kids and kids[0].type in ("anonymous_class", "declaration_list"):
            pass
        else:
            ctx.block(f, n, f"new sa dinamičkim imenom klase: {txt(n)[:70]}")
        return

    if t == "class_constant_access_expression" and n.named_children:
        c = n.named_children[0]
        if c.type in ("name", "qualified_name"):
            ctx.classes.add(txt(c).split("\\")[-1])
        return

    if t == "dynamic_variable_name":
        ctx.block(f, n, f"promenljiva promenljiva: {txt(n)[:50]}")
        return

    if t == "shell_command_expression":
        ctx.exec_caps.add("`backtick`")
        ctx.block(f, n, "backtick izvršava shell komandu")
        return

    if t == "global_declaration":
        for v in n.named_children:
            ctx.globals.add(txt(v).lstrip("$"))
        return

    if t == "subscript_expression":
        var, key = superglobal_name(n)
        if var is None:
            return
        k = lit(key, ctx, f) if key is not None else None
        if var in INPUT_SUPERGLOBALS:
            if k is None:
                ctx.block(f, n, f"${var} sa dinamičkim ključem: {txt(n)[:50]}")
            else:
                ctx.inputs.setdefault(INPUT_SUPERGLOBALS[var], {}).setdefault(k, {})
        elif var == "_SERVER" and k:
            ctx.server_keys.add(k)
        elif var == "_SESSION" and k:
            ctx.session_keys.add(k)
        elif var == "argv" and k and k.isdigit():
            ctx.argv.setdefault(int(k), {})
        return

    if t == "variable_name":
        nm = txt(n).lstrip("$")
        par = n.parent
        if nm in INPUT_SUPERGLOBALS and par is not None and par.type != "subscript_expression":
            ctx.warn(f, n, f"ceo ${nm} se koristi bez ključa — šema ne može da se izvede")
        return

    if t == "assignment_expression":
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        if left is not None and left.type == "variable_name" and right is not None:
            for sub in iter_nodes(right):
                v, key = superglobal_name(sub)
                if v == "argv" and key is not None and txt(key).isdigit():
                    ctx.argv_vars[txt(left)] = int(txt(key))
        return

    if t == "binary_expression":
        l = n.child_by_field_name("left")
        r = n.child_by_field_name("right")
        for a, b in ((l, r), (r, l)):
            if a is None or b is None:
                continue
            v, key = superglobal_name(a)
            if v == "_SERVER" and key is not None and lit(key) == "REQUEST_METHOD":
                s = lit(b)
                if s:
                    ctx.http_methods.add(s.upper())
            if (a.type == "function_call_expression" and
                    txt(a.child_by_field_name("function") or a).lower() == "php_sapi_name") or \
                    (a.type == "name" and txt(a) == "PHP_SAPI"):
                s = lit(b)
                if s:
                    ctx.sapi.add(s)
        return

    if t == "switch_statement":
        cond = n.child_by_field_name("condition")
        inner = cond.named_children[0] if cond is not None and cond.named_children else None
        if inner is None:
            return
        cases = []
        body = n.child_by_field_name("body")
        for c in (body.named_children if body is not None else []):
            if c.type == "case_statement":
                v = c.child_by_field_name("value")
                s = lit(v) if v is not None else None
                if s is not None:
                    cases.append(s)
        if inner.type == "variable_name" and txt(inner) in ctx.argv_vars:
            ctx.argv.setdefault(ctx.argv_vars[txt(inner)], {})["observed_values"] = cases
        v, key = superglobal_name(inner)
        if v == "_SERVER" and key is not None and lit(key) == "REQUEST_METHOD":
            ctx.http_methods |= {c.upper() for c in cases}
        return


def iter_nodes(n):
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(x.children)


def sql_arg(ctx, f, n, a):
    sql = lit(a, ctx, f)
    if sql is None:
        ctx.block(f, n, f"SQL nije literal — tabele/operacije se ne mogu izvesti: {txt(a)[:60]}")
        return
    for op, table, cols, note in parse_sql(sql):
        if table is None:
            ctx.warn(f, n, note or f"SQL bez tabele: {sql[:60]}")
            continue
        d = ctx.db.setdefault(table, {"ops": {}, "notes": set()})
        d["ops"].setdefault(op, set()).update(cols)
        if note:
            d["notes"].add(note)


def expand(ctx):
    """Fixed-point: obiđi tela dostižnih korisničkih funkcija i metoda."""
    changed = True
    while changed:
        changed = False
        for low in list(ctx.called):
            if low in ctx.user_funcs and ("f", low) not in ctx.expanded:
                ctx.expanded.add(("f", low))
                fpath, node = ctx.user_funcs[low]
                body = node.child_by_field_name("body")
                if body is not None:
                    walk(ctx, body, fpath)
                changed = True
        names = {m.lower() for m in ctx.methods}
        names |= {"__construct"} if any(c.lower() in ctx.user_classes for c in ctx.new_classes) else set()
        for m in names:
            for fpath, node in ctx.user_methods.get(m, []):
                key = ("m", fpath, node.start_point)
                if key not in ctx.expanded:
                    ctx.expanded.add(key)
                    body = node.child_by_field_name("body")
                    if body is not None:
                        walk(ctx, body, fpath)
                    changed = True


def internal_functions(php):
    try:
        out = subprocess.run([php, "-r", 'echo json_encode(get_defined_functions()["internal"]);'],
                             capture_output=True, text=True, timeout=20)
        return {x.lower() for x in json.loads(out.stdout)}
    except Exception:
        return None


def build_manifest(ctx, internals):
    user = set(ctx.user_funcs)
    builtins, undefined = set(), set()
    for low in ctx.called:
        if low in CONSTRUCTS or low in user or low == "eval":
            continue
        if internals is None or low in internals:
            builtins.add(low)
        else:
            undefined.add(low)
    for u in sorted(undefined):
        ctx.warnings.append(f"{ctx.called[u]}  {u}() nije definisana ni kao korisnička ni kao ugrađena (nedostaje fajl ili ekstenzija?)")

    reachable_user = sorted(x for x in user if ("f", x) in ctx.expanded)
    is_cli = "cli" in ctx.sapi or (ctx.argv and not ctx.inputs)
    methods = set(ctx.http_methods) | set(ctx.form_methods)
    if "POST" in ctx.inputs:
        methods.add("POST")
    if not is_cli:
        methods.add("GET")

    # HTTP ulazi
    params = {}
    for src, keys in sorted(ctx.inputs.items()):
        params[src] = {}
        for k, d in sorted(keys.items()):
            e = {"schema": "TODO"}
            if d.get("filters"):
                e["observed_filter"] = sorted(d["filters"])
                if any("SANITIZE" in x for x in d["filters"]):
                    ctx.warnings.append(f"{os.path.relpath(ctx.entry, ctx.root)}  '{k}': sanitizacija menja ulaz umesto da ga odbije — ACE zahteva validaciju po šemi")
            if k in ctx.html:
                e["hint_from_html"] = ctx.html[k]
            params[src][k] = e
    # polja forme koja kod ne čita
    read_keys = {k for keys in ctx.inputs.values() for k in keys}
    for k in ctx.html:
        if k not in read_keys:
            ctx.warnings.append(f"forma ima polje '{k}' koje kod nikad ne čita — izostavlja se iz ugovora")

    db, grants = {}, []
    for t, d in sorted(ctx.db.items()):
        e = {op: sorted(c) for op, c in sorted(d["ops"].items())}
        if d["notes"]:
            e["notes"] = sorted(d["notes"])
        db[t] = e
        # DELETE/UPDATE sa WHERE traže i SELECT nad kolonama uslova
        need_select = set()
        for op, c in d["ops"].items():
            if op in ("SELECT", "DELETE"):
                need_select |= c
        for op, c in sorted(d["ops"].items()):
            if op == "DELETE":
                grants.append(f"GRANT DELETE ON <db>.{t} TO <ace_user>;")
            elif op in ("INSERT", "UPDATE", "REPLACE") and c:
                grants.append(f"GRANT {op} ({', '.join(sorted(c))}) ON <db>.{t} TO <ace_user>;")
            elif op != "SELECT":
                grants.append(f"GRANT {op} ON <db>.{t} TO <ace_user>;")
        if need_select:
            if d["notes"]:
                grants.append(f"GRANT SELECT ON <db>.{t} TO <ace_user>;   -- SELECT *: suziti ručno")
            else:
                grants.append(f"GRANT SELECT ({', '.join(sorted(need_select))}) ON <db>.{t} TO <ace_user>;")

    if len([g for g in ctx.globals if g in ("pdo", "conn", "db", "mysqli", "link")]) > 1:
        ctx.warnings.append(f"više DB handle-ova u upotrebi ({', '.join(sorted(ctx.globals))}) — verovatno više kredencijala")

    n_int = len(internals) if internals else None
    metrics = {
        "builtins_used": len(builtins),
        "builtins_available": n_int,
        "surface_reduction": (f"{100 * (1 - len(builtins) / n_int):.2f}%" if n_int else None),
        "user_functions_defined": len(user),
        "user_functions_reachable": len(reachable_user),
        "files": len(ctx.files),
    }

    status = "DRAFT_BLOCKED" if ctx.blockers else "DRAFT"
    m = {
        "aceshrug_manifest": "0.1",
        "status": status,
        "entry": os.path.relpath(ctx.entry, ctx.root),
        "sapi": ["cli"] if is_cli else ["web"],
    }
    if not is_cli:
        m["http"] = {
            "methods": sorted(methods),
            "params": params,
            "server_vars_read": sorted(ctx.server_keys),
            "session_keys": sorted(ctx.session_keys),
        }
    else:
        argv = {}
        for i, d in sorted(ctx.argv.items()):
            e = {"schema": "TODO"}
            if d.get("observed_values"):
                e["observed_values"] = d["observed_values"]
            argv[i] = e
        m["cli"] = {"argv": argv}
        if params:
            m["cli"]["note"] = "CLI skripta čita HTTP superglobale"
            m["http_params_read"] = params
    m["files"] = [{"path": os.path.relpath(p, ctx.root), "sha256": h} for p, h in ctx.files.items()]
    m["builtins"] = sorted(builtins)
    m["methods_called"] = sorted(ctx.methods)
    if ctx.static_calls:
        m["static_calls"] = sorted(ctx.static_calls)
    m["classes_referenced"] = sorted(ctx.classes | ctx.new_classes)
    m["user_functions_reachable"] = reachable_user
    m["db"] = {"tables": db, "grant_draft": grants} if db else "none"
    m["capabilities"] = {
        "exec": sorted(ctx.exec_caps) or "none",
        "fs": sorted(ctx.fs) or "none",
        "net": sorted(ctx.net) or "none",
    }
    m["metrics"] = metrics
    m["blockers"] = ctx.blockers
    m["warnings"] = ctx.warnings
    m["shrug_candidates"] = ctx.shrug
    m["lock"] = "Generator nikad ne zaključava. Posle ručnog pregleda: popuni schema: TODO, razreši blokere, potpiši."
    return m


def analyze(entry, root, maps, cwd, internals):
    entry = os.path.abspath(entry)
    ctx = Ctx(entry, root, maps, os.path.abspath(cwd) if cwd else os.path.dirname(entry))
    load_file(ctx, entry)
    walk(ctx, ctx.trees[entry].root_node, entry)
    expand(ctx)
    return build_manifest(ctx, internals)


def dump(m, fmt):
    if fmt == "yaml" and yaml is not None:
        return yaml.safe_dump(m, sort_keys=False, allow_unicode=True, width=120)
    return json.dumps(m, indent=2, ensure_ascii=False)


def summary(m):
    met = m["metrics"]
    lines = [f"== {m['entry']}  [{m['status']}]  sapi={','.join(m['sapi'])}",
             f"   fajlova: {met['files']}  builtins: {met['builtins_used']}"
             + (f"/{met['builtins_available']} (smanjenje površine {met['surface_reduction']})" if met['builtins_available'] else ""),
             f"   korisničke funkcije: {met['user_functions_reachable']}/{met['user_functions_defined']} dostižno",
             f"   blokeri: {len(m['blockers'])}  upozorenja: {len(m['warnings'])}  SHRUG kandidati: {len(m['shrug_candidates'])}"]
    for b in m["blockers"]:
        lines.append(f"   [BLOKER] {b}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="ACESHRUG manifest generator (nacrt) za PHP")
    ap.add_argument("entries", nargs="+", help="ulazni PHP fajlovi (rute / CLI skripte)")
    ap.add_argument("--root", default=".", help="koren za relativne putanje u izveštaju")
    ap.add_argument("--cwd", help="radni direktorijum pri izvršavanju (podrazumevano: dir ulaznog fajla)")
    ap.add_argument("--map", action="append", default=[], metavar="DEPLOY=LOCAL",
                    help="mapiranje deploy putanje na lokalnu, npr. /var/www/html/app=./app")
    ap.add_argument("--php", default="php", help="php binarni za listu ugrađenih funkcija")
    ap.add_argument("--out", help="direktorijum za manifeste (podrazumevano: stdout)")
    ap.add_argument("--format", choices=["yaml", "json"], default="yaml")
    a = ap.parse_args()

    root = os.path.abspath(a.root)
    maps = []
    for mp in a.map:
        d, _, l = mp.partition("=")
        maps.append((d.rstrip("/"), os.path.abspath(l)))
    internals = internal_functions(a.php)
    if internals is None:
        print("upozorenje: php nije dostupan — ugrađene i nedefinisane funkcije se ne razlikuju", file=sys.stderr)

    rc = 0
    for e in a.entries:
        m = analyze(e, root, maps, a.cwd, internals)
        print(summary(m), file=sys.stderr)
        out = dump(m, a.format)
        if a.out:
            os.makedirs(a.out, exist_ok=True)
            name = re.sub(r"[^\w.-]", "_", m["entry"]) + ".manifest." + a.format
            with open(os.path.join(a.out, name), "w", encoding="utf-8") as fh:
                fh.write(out)
        else:
            print(out)
        if m["blockers"]:
            rc = 2
    sys.exit(rc)


if __name__ == "__main__":
    main()
