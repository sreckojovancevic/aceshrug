#!/usr/bin/env python3
import os
import sys
import hashlib
import json
import argparse
import shutil
import re
import tempfile
import pwd
import grp
import subprocess
import uuid
import fcntl
from datetime import datetime, timezone

# --- GATEKEEPER STUB (v0.3.2 - Enterprise Hardened RASP) ---
GATE_PHP_STUB = """<?php
/**
 * ACESHRUG Gatekeeper v0.3.2 (Enterprise Hardened Runtime)
 * Učitava se preko auto_prepend_file. Koristi keširani manifest.php.
 */
if (defined('ACESHRUG_GATE')) {
    return;
}
define('ACESHRUG_GATE', true);

(function() {
    $manifest_path = __DIR__ . '/manifest.php';
    if (!is_file($manifest_path) || !is_readable($manifest_path)) {
        aceshrug_event("manifest_missing", "Manifest not found or unreadable", "fatal", "fatal_block");
        aceshrug_block();
    }
    
    $manifest = require $manifest_path;
    
    if (!is_array($manifest) || 
        ($manifest['format_version'] ?? 0) !== 2 ||
        !isset($manifest['app_root'], $manifest['routes'], $manifest['includes'], $manifest['mode'], $manifest['unknown_policy']) ||
        !is_array($manifest['routes']) || !is_array($manifest['includes']) || !is_array($manifest['unknown_policy'])) {
        aceshrug_event("manifest_structure_invalid", "Invalid schema or missing mandatory keys v2", "fatal", "fatal_block");
        aceshrug_block();
    }
    
    $mode = $manifest['mode'];
    if (!in_array($mode, ['monitor', 'enforcement'], true)) {
        aceshrug_event("manifest_invalid_mode", "Unknown mode specified", "fatal", "fatal_block");
        aceshrug_block();
    }
    
    foreach ($manifest['unknown_policy'] as $src => $pol) {
        if (!in_array($pol, ['allow_with_signal', 'block', 'null'], true)) {
            aceshrug_event("manifest_structure_invalid", "Invalid unknown_policy", "fatal", "fatal_block");
            aceshrug_block();
        }
    }
    
    $app_root = realpath($manifest['app_root'] ?? '');
    $script_filename = realpath($_SERVER['SCRIPT_FILENAME'] ?? '');
    
    if (!$app_root || !$script_filename) {
        $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
        aceshrug_event("path_resolution_failed", "App root or script filename invalid", "critical", $action);
        if ($mode === 'enforcement') { aceshrug_block(); }
        return;
    }
    
    $prefix = rtrim($app_root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if ($script_filename !== $app_root && strpos($script_filename, $prefix) !== 0) {
        $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
        aceshrug_event("path_boundary_violation", $script_filename, "critical", $action);
        if ($mode === 'enforcement') { aceshrug_block(); }
        return;
    }
    
    $rel_path = ltrim(substr($script_filename, strlen($app_root)), DIRECTORY_SEPARATOR);
    $rel_path = str_replace(DIRECTORY_SEPARATOR, '/', $rel_path);
    
    foreach ($manifest['includes'] as $inc_path => $inc_meta) {
        if (!is_string($inc_path) || trim($inc_path) === '' || strpos($inc_path, '..') !== false) {
            aceshrug_event("manifest_invalid_include_path", $inc_path, "fatal", "fatal_block");
            aceshrug_block();
        }
        if (!isset($inc_meta['sha256']) || !preg_match('/^[a-f0-9]{64}$/i', $inc_meta['sha256'])) {
            aceshrug_event("manifest_invalid_hash_format", $inc_path, "fatal", "fatal_block");
            aceshrug_block();
        }
        
        $clean_inc = str_replace(['/', chr(92)], DIRECTORY_SEPARATOR, $inc_path);
        $full_inc_path = realpath($app_root . DIRECTORY_SEPARATOR . $clean_inc);
        
        $include_is_valid = ($full_inc_path !== false && strpos($full_inc_path, $prefix) === 0 && is_file($full_inc_path));
        
        if (!$include_is_valid) {
            $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
            aceshrug_event("include_missing_or_outside", $inc_path, "critical", $action);
            if ($mode === 'enforcement') { aceshrug_block(); }
            continue;
        }
        
        if (hash_file('sha256', $full_inc_path) !== $inc_meta['sha256']) {
            $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
            aceshrug_event("include_tampered", $inc_path, "critical", $action);
            if ($mode === 'enforcement') { aceshrug_block(); }
        }
    }
    
    if (!isset($manifest['routes'][$rel_path])) {
        $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
        aceshrug_event("unregistered_route", $rel_path, "warning", $action);
        if ($mode === 'enforcement') { aceshrug_block(); }
        return;
    }
    
    $route_meta = $manifest['routes'][$rel_path];
    $route_status = $route_meta['status'] ?? 'auto';
    if (!in_array($route_status, ['auto', 'confirmed', 'rejected'], true)) {
        aceshrug_event("manifest_structure_invalid", "Invalid route status", "fatal", "fatal_block");
        aceshrug_block();
    }
    if ($route_status === 'rejected') {
        $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
        aceshrug_event("rejected_route_accessed", $rel_path, "critical", $action);
        if ($mode === 'enforcement') { aceshrug_block(); }
    }
    
    if (!isset($route_meta['sha256']) || !preg_match('/^[a-f0-9]{64}$/i', $route_meta['sha256'])) {
        aceshrug_event("manifest_invalid_hash_format", $rel_path, "fatal", "fatal_block");
        aceshrug_block();
    }
    
    $current_sapi = (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') ? 'cli' : 'web';
    $expected_sapi = $route_meta['sapi'] ?? 'web';
    if (!in_array($expected_sapi, ['web', 'cli'], true)) {
        aceshrug_event("manifest_structure_invalid", "Invalid SAPI definition", "fatal", "fatal_block");
        aceshrug_block();
    }
    
    if ($expected_sapi !== $current_sapi) {
        $enforce_action = ($mode === 'enforcement' && $route_status === 'confirmed') ? 'blocked' : 'logged_allow';
        aceshrug_event("sapi_mismatch", "Expected: $expected_sapi, Got: $current_sapi", "warning", $enforce_action);
        if ($mode === 'enforcement' && $route_status === 'confirmed') { aceshrug_block(); }
    }
    
    if ($current_sapi === 'web') {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $methods = $route_meta['methods'] ?? [];
        if (!is_array($methods)) {
            aceshrug_event("manifest_structure_invalid", "Invalid methods array", "fatal", "fatal_block");
            aceshrug_block();
        }
        if (!in_array($method, $methods, true)) {
            $enforce_action = ($mode === 'enforcement' && $route_status === 'confirmed') ? 'blocked' : 'logged_allow';
            aceshrug_event("method_not_allowed", "$rel_path [$method]", "warning", $enforce_action);
            if ($mode === 'enforcement' && $route_status === 'confirmed') { aceshrug_block(); }
        }
    }
    
    $current_hash = hash_file('sha256', $script_filename);
    if ($current_hash !== $route_meta['sha256']) {
        $enforce_action = ($mode === 'enforcement' && $route_status === 'confirmed') ? 'blocked' : 'logged_allow';
        aceshrug_event("file_tampered", $rel_path, "critical", $enforce_action);
        if ($mode === 'enforcement' && $route_status === 'confirmed') { aceshrug_block(); }
    }
    
    aceshrug_validate_inputs($route_meta['params'] ?? [], $manifest['unknown_policy'] ?? [], $mode, $route_status);
    
})();

function aceshrug_validate_inputs($allowed_params, $policy, $mode, $route_status) {
    $sources = ['GET' => &$_GET, 'POST' => &$_POST, 'COOKIE' => &$_COOKIE];
    
    foreach ($sources as $src_name => &$data) {
        $schema = $allowed_params[$src_name] ?? [];
        if (!is_array($schema)) {
            aceshrug_event("manifest_structure_invalid", "Invalid param schema", "fatal", "fatal_block");
            aceshrug_block();
        }
        
        foreach ($data as $key => $val) {
            if (!array_key_exists($key, $schema)) {
                $action_policy = $policy[$src_name] ?? 'allow_with_signal';
                if ($action_policy === 'null') {
                    if ($mode === 'enforcement' && $route_status === 'confirmed') {
                        unset($data[$key]);
                        $elsewhere = false;
                        foreach (['GET' => $_GET, 'POST' => $_POST, 'COOKIE' => $_COOKIE] as $o_name => $o_data) {
                            if ($o_name !== $src_name && is_array($o_data) && array_key_exists($key, $o_data)) { $elsewhere = true; }
                        }
                        if (!$elsewhere && isset($_REQUEST) && is_array($_REQUEST)) { unset($_REQUEST[$key]); }
                        aceshrug_event("unknown_parameter_dropped", "$src_name: $key", "info", "dropped");
                    } else {
                        aceshrug_event("unknown_parameter", "$src_name: $key", "info", "logged_allow_would_drop");
                    }
                } else {
                    $enforce_action = ($action_policy === 'block' && $mode === 'enforcement' && $route_status === 'confirmed') ? 'blocked' : 'logged_allow';
                    aceshrug_event("unknown_parameter", "$src_name: $key", "info", $enforce_action);
                    if ($action_policy === 'block' && $mode === 'enforcement' && $route_status === 'confirmed') {
                        aceshrug_block();
                    }
                }
            } else {
                $rule = $schema[$key];
                $type = $rule['type'] ?? 'string';
                $max = $rule['max'] ?? 4096;
                $p_status = $rule['status'] ?? 'auto';
                
                if (!in_array($p_status, ['auto', 'confirmed', 'rejected'], true)) {
                    aceshrug_event("manifest_structure_invalid", "Invalid parameter status", "fatal", "fatal_block");
                    aceshrug_block();
                }
                if ($p_status === 'rejected') {
                    $action = ($mode === 'enforcement') ? 'blocked' : 'logged_allow';
                    aceshrug_event("rejected_parameter_accessed", "$src_name.$key", "critical", $action);
                    if ($mode === 'enforcement') { aceshrug_block(); }
                    continue;
                }
                
                if (!in_array($type, ['string', 'int', 'email', 'array'], true) || !is_int($max)) {
                    aceshrug_event("manifest_structure_invalid", "Invalid type or max in schema", "fatal", "fatal_block");
                    aceshrug_block();
                }
                
                $should_block = ($mode === 'enforcement' && $route_status === 'confirmed' && $p_status === 'confirmed');
                $enforce_action = $should_block ? 'blocked' : 'logged_allow';
                
                if ($type === 'string') {
                    if (!is_string($val)) {
                        aceshrug_event("type_mismatch_expected_string", "$src_name.$key", "warning", $enforce_action);
                        if ($should_block) { aceshrug_block(); }
                    } else if (strlen($val) > $max) {
                        aceshrug_event("max_length_exceeded", "$src_name.$key", "warning", $enforce_action);
                        if ($should_block) { aceshrug_block(); }
                    }
                } elseif ($type === 'array') {
                    if (!is_array($val)) {
                        aceshrug_event("type_mismatch_expected_array", "$src_name.$key", "warning", $enforce_action);
                        if ($should_block) { aceshrug_block(); }
                    }
                } elseif ($type === 'int') {
                    if (!is_scalar($val) || filter_var($val, FILTER_VALIDATE_INT) === false) {
                        aceshrug_event("type_mismatch_expected_int", "$src_name.$key", "warning", $enforce_action);
                        if ($should_block) { aceshrug_block(); }
                    }
                } elseif ($type === 'email') {
                    if (!is_string($val) || filter_var($val, FILTER_VALIDATE_EMAIL) === false) {
                        aceshrug_event("type_mismatch_expected_email", "$src_name.$key", "warning", $enforce_action);
                        if ($should_block) { aceshrug_block(); }
                    }
                }
                
                if (isset($rule['regex']) && is_string($rule['regex'])) {
                    $regex = $rule['regex'];
                    $test_preg = @preg_match($regex, '');
                    if ($test_preg === false) {
                        aceshrug_event("manifest_invalid_regex", "$src_name.$key", "fatal", "fatal_block");
                        aceshrug_block();
                    }
                    if (is_string($val) && !preg_match($regex, $val)) {
                        aceshrug_event("regex_mismatch", "$src_name.$key", "warning", $enforce_action);
                        if ($should_block) { aceshrug_block(); }
                    }
                }
            }
        }
    }
}

function aceshrug_event($reason, $detail, $severity, $action) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'CLI';
    $cache_key = 'aceshrug_' . md5($ip . $reason);
    
    if (function_exists('apcu_fetch')) {
        $count = apcu_fetch($cache_key);
        if ($count === false) {
            apcu_store($cache_key, ['count' => 1, 'suppressed' => 0], 60);
        } else {
            $count['count']++;
            if ($count['count'] > 50) {
                $count['suppressed']++;
                apcu_store($cache_key, $count, 60);
                return;
            }
            apcu_store($cache_key, $count, 60);
        }
    }

    // UTF-8 bezbedno skracivanje; radi i bez mbstring ekstenzije
    $detail = (string)$detail;
    if (function_exists('mb_strcut')) {
        $safe_detail = mb_strcut($detail, 0, 128, 'UTF-8');
    } else {
        $safe_detail = substr($detail, 0, 128);
        if (function_exists('iconv')) {
            $tmp = @iconv('UTF-8', 'UTF-8//IGNORE', $safe_detail);
            if ($tmp !== false) { $safe_detail = $tmp; }
        }
    }

    $entry = [
        'timestamp' => gmdate('c'),
        'component' => 'ACESHRUG',
        'event' => $reason,
        'severity' => $severity,
        'action' => $action,
        'ip' => $ip,
        'detail' => $safe_detail
    ];

    $json_flags = defined('JSON_INVALID_UTF8_SUBSTITUTE') ? constant('JSON_INVALID_UTF8_SUBSTITUTE') : 0;
    $log_entry = json_encode($entry, $json_flags);
    if ($log_entry === false) {
        $log_entry = '{"component":"ACESHRUG","event":"log_encoding_failed"}';
    }
    error_log("[ACESHRUG-EVENT] " . $log_entry);
}

function aceshrug_block() {
    if (!headers_sent()) {
        header_remove();
        http_response_code(404);
        header("Content-Length: 0");
    }
    if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
        exit(1);
    }
    exit;
}
"""

def php_escape(val_str):
    return str(val_str).replace("\\", "\\\\").replace("'", "\\'")

def python_to_php_array(obj, indent=4):
    spaces = " " * indent
    if isinstance(obj, dict):
        if not obj:
            return "[]"
        items = []
        for k, v in obj.items():
            key_str = "'" + php_escape(k) + "'"
            val_str = python_to_php_array(v, indent + 4)
            items.append(f"{spaces}{key_str} => {val_str}")
        return "[\n" + ",\n".join(items) + "\n" + " " * (indent - 4) + "]"
    elif isinstance(obj, list):
        if not obj:
            return "[]"
        items = []
        for v in obj:
            val_str = python_to_php_array(v, indent + 4)
            items.append(f"{spaces}{val_str}")
        return "[\n" + ",\n".join(items) + "\n" + " " * (indent - 4) + "]"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif obj is None:
        return "null"
    elif isinstance(obj, (int, float)):
        return str(obj)
    else:
        return "'" + php_escape(obj) + "'"

def analyze_codebase(input_dir, prev_manifest=None, allowed_blockers=None):
    if allowed_blockers is None:
        allowed_blockers = []
    
    php_files = {}
    included_targets = set()
    file_contents = {}
    blockers = []
    has_todos = False
    has_auto_items = False

    blocker_patterns = [
        (r'\beval\s*\(', "eval", "eval() upotrebljen"),
        (r'\bextract\s*\(', "extract", "extract() upotrebljen"),
        (r'\$\s*\{?\s*\$[a-zA-Z_]\w*\s*\}?', "varvar", "Variable variables ($$var) upotrebljen"),
        (r'\b(?:include|require)(?:_once)?\s*\$|\b(?:include|require)(?:_once)?\s*\(\s*\$', "dyninclude", "Dinamički include/require sa promenljivom"),
        (r'\bparse_str\s*\([^,)]+\)', "parse_str", "parse_str() sa jednim argumentom")
    ]

    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".php"):
                fullpath = os.path.join(root, file)
                relpath = os.path.relpath(fullpath, input_dir).replace("\\", "/")
                
                with open(fullpath, "rb") as f:
                    content_bytes = f.read()
                
                file_hash = hashlib.sha256(content_bytes).hexdigest()
                php_files[relpath] = file_hash

                try:
                    content_text = content_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    content_text = ""
                
                file_contents[relpath] = content_text

                for pattern, bcode, desc in blocker_patterns:
                    if re.search(pattern, content_text):
                        if bcode not in allowed_blockers and f"{relpath}:{bcode}" not in allowed_blockers:
                            blockers.append({"file": relpath, "code": bcode, "issue": desc})

                # Comprehensive include/require path matching
                matches = re.findall(r'\b(?:include|require)(?:_once)?\s*\(?\s*[\'"]([^\'"]+)[\'"]\s*\)?', content_text)
                for m in matches:
                    norm_inc = os.path.normpath(os.path.join(os.path.dirname(relpath), m)).replace("\\", "/")
                    included_targets.add(norm_inc)

    routes = {}
    includes = {}
    findings = {"critical": [], "warning": [], "info": []}

    analysis_patterns = [
        (r'\beval\s*\(', "eval() upotrebljen", "critical"),
        (r'`[^`]*`', "Backtick izvršavanje komandi", "critical"),
        (r'\bextract\s*\(', "extract() upotrebljen", "warning")
    ]

    prev_routes = prev_manifest.get("routes", {}) if prev_manifest else {}
    prev_includes = prev_manifest.get("includes", {}) if prev_manifest else {}

    for relpath, fhash in php_files.items():
        content_text = file_contents[relpath]

        for pattern, desc, severity in analysis_patterns:
            if re.search(pattern, content_text):
                findings[severity].append({"file": relpath, "issue": desc})

        get_params = {}
        post_params = {}
        for match in re.finditer(r'\$_GET\s*\[\s*[\'"]([a-zA-Z0-9_]+)[\'"]\s*\]', content_text):
            pname = match.group(1)
            get_params[pname] = {"type": "string", "max": 4096, "status": "auto", "todo": True}
            has_todos = True
            has_auto_items = True
        for match in re.finditer(r'\$_POST\s*\[\s*[\'"]([a-zA-Z0-9_]+)[\'"]\s*\]', content_text):
            pname = match.group(1)
            post_params[pname] = {"type": "string", "max": 4096, "status": "auto", "todo": True}
            has_todos = True
            has_auto_items = True

        if relpath in included_targets:
            inc_status = "auto"
            if relpath in prev_includes and prev_includes[relpath].get("sha256") == fhash:
                # include metadata preserve if needed
                pass
            includes[relpath] = {
                "type": "INCLUDE",
                "sha256": fhash
            }
        else:
            sapi_type = "cli" if "cli" in relpath.lower() or "artisan" in relpath.lower() else "web"
            methods = ["GET", "POST"] if post_params or "POST" in content_text or "form" in content_text.lower() else ["GET"]
            
            # Ljudske odluke se NE nasledjuju iz generisanog manifesta, vec iz decisions fajla (apply_decisions)
            r_status = "auto"
            r_params = {"GET": get_params, "POST": post_params, "COOKIE": {}}
            has_auto_items = True

            routes[relpath] = {
                "type": "ENTRYPOINT",
                "status": r_status,
                "sapi": sapi_type,
                "methods": methods,
                "sha256": fhash,
                "params": r_params
            }

    return routes, includes, php_files, blockers, findings, has_todos, has_auto_items

VALID_STATUS = ("auto", "confirmed", "rejected")
VALID_MODE = ("monitor", "enforcement")
VALID_POLICY = ("allow_with_signal", "block", "null")
VALID_TYPE = ("string", "int", "email", "array")


def load_decisions(path):
    """Ucitava i validira fajl sa ljudskim odlukama. Vraca (dict, greske)."""
    if not os.path.exists(path):
        return {}, []
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        return None, [f"decisions fajl nije ispravan JSON: {e}"]
    errs = []
    if not isinstance(d, dict):
        return None, ["decisions fajl mora biti JSON objekat"]
    if d.get("mode", "monitor") not in VALID_MODE:
        errs.append(f"mode mora biti jedno od {VALID_MODE}")
    for key in ("unknown_policy", "routes"):
        if key in d and not isinstance(d[key], dict):
            return None, [f"{key} mora biti JSON objekat"]
    for src, pol in (d.get("unknown_policy") or {}).items():
        if pol not in VALID_POLICY:
            errs.append(f"unknown_policy.{src}: '{pol}' nije dozvoljeno")
    for rp, rd in (d.get("routes") or {}).items():
        if not isinstance(rd, dict):
            errs.append(f"routes.{rp}: mora biti objekat"); continue
        if rd.get("status", "auto") not in VALID_STATUS:
            errs.append(f"routes.{rp}.status: '{rd.get('status')}' nije dozvoljen {VALID_STATUS}")
        if "sha256" in rd and not re.fullmatch(r"[a-f0-9]{64}", str(rd["sha256"])):
            errs.append(f"routes.{rp}.sha256: nije ispravan (64 mala heks znaka)")
        if rd.get("status") == "confirmed" and "sha256" not in rd:
            errs.append(f"routes.{rp}: confirmed ruta mora imati sha256 (potvrda vazi samo za konkretan sadrzaj fajla)")
        if "params" in rd and not isinstance(rd["params"], dict):
            errs.append(f"routes.{rp}.params: mora biti objekat"); continue
        if "sapi" in rd and rd["sapi"] not in ("web", "cli"):
            errs.append(f"routes.{rp}.sapi: mora biti web ili cli")
        if "methods" in rd and (not isinstance(rd["methods"], list) or not all(isinstance(m, str) for m in rd["methods"])):
            errs.append(f"routes.{rp}.methods: mora biti lista stringova")
        for src, pd in (rd.get("params") or {}).items():
            if src not in ("GET", "POST", "COOKIE"):
                errs.append(f"routes.{rp}.params.{src}: nepoznat izvor"); continue
            if pd is not None and not isinstance(pd, dict):
                errs.append(f"routes.{rp}.params.{src}: mora biti objekat"); continue
            for pk, rule in (pd or {}).items():
                if not isinstance(rule, dict):
                    errs.append(f"routes.{rp}.params.{src}.{pk}: mora biti objekat"); continue
                if rule.get("status", "auto") not in VALID_STATUS:
                    errs.append(f"routes.{rp}.params.{src}.{pk}.status: '{rule.get('status')}' nije dozvoljen")
                if rule.get("type", "string") not in VALID_TYPE:
                    errs.append(f"routes.{rp}.params.{src}.{pk}.type: '{rule.get('type')}' nije podrzan")
                if "max" in rule and (type(rule["max"]) is not int or rule["max"] < 0):
                    errs.append(f"routes.{rp}.params.{src}.{pk}.max: mora biti ceo broj >= 0")
    return d, errs


def check_regexes(routes):
    """Proverava sve regex-e kroz PHP (isti PCRE kao u gate-u)."""
    rx = []
    for rp, r in routes.items():
        for src, pd in r.get("params", {}).items():
            for pk, rule in pd.items():
                if "regex" in rule:
                    rx.append((f"{rp}:{src}.{pk}", rule["regex"]))
    if not rx:
        return []
    code = '$bad=[]; foreach (json_decode(stream_get_contents(STDIN), true) as $x) { if (!is_string($x[1]) || @preg_match($x[1], "") === false) $bad[] = $x[0]; } echo json_encode($bad);'
    res = subprocess.run(['php', '-r', code], input=json.dumps(rx).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        return [f"PHP provera regex-a nije uspela (kod {res.returncode}): {res.stderr.decode(errors='replace').strip()[:300]}"]
    try:
        result = json.loads(res.stdout.decode())
    except Exception:
        return ["PHP provera regex-a vratila je neispravan izlaz"]
    if not isinstance(result, list):
        return ["PHP provera regex-a vratila je neocekivan rezultat"]
    return result


def apply_decisions(routes, decisions):
    """Spaja analizu sa ljudskim odlukama. Odluka ima prednost; promenjen fajl vraca rutu na 'auto'."""
    applied, stale, missing = [], [], []
    for rp, rd in (decisions.get("routes") or {}).items():
        if rp not in routes:
            missing.append(rp)
            continue
        r = routes[rp]
        is_stale = "sha256" in rd and rd["sha256"] != r["sha256"]
        prev_st = rd.get("status", r["status"])
        if is_stale and prev_st != "rejected":
            stale.append(rp)
        prev = rd.get("status", r["status"])
        # zabrana nikad ne slabi zbog promene koda; potvrda vazi samo za sadrzaj koji je pregledan
        r["status"] = "rejected" if prev == "rejected" else ("auto" if is_stale else prev)
        for k in ("methods", "sapi"):
            if k in rd:
                r[k] = rd[k]
        for src, pd in (rd.get("params") or {}).items():
            dst = r["params"].setdefault(src, {})
            for pk, rule in (pd or {}).items():
                merged = dict(dst.get(pk, {}))
                merged.update(rule)
                merged.pop("todo", None)
                if is_stale and merged.get("status") != "rejected":
                    merged["status"] = "auto"
                dst[pk] = merged
        if not is_stale:
            applied.append(rp)
    has_auto = any(
        r["status"] == "auto" or any(rule.get("status", "auto") == "auto" for pd in r["params"].values() for rule in pd.values())
        for r in routes.values())
    return applied, stale, missing, has_auto


def export_decisions(active_manifest_path, decisions_path):
    """Pravi decisions fajl iz trenutno aktivnog manifesta (rute i parametri koji nisu 'auto', plus rezim)."""
    res = subprocess.run(['php', '-r', '$m = require $argv[1]; echo json_encode($m);', active_manifest_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        raise RuntimeError(f"aktivni manifest nije moguce ucitati: {res.stderr.decode()}")
    m = json.loads(res.stdout.decode())
    out = {"mode": m.get("mode", "monitor"), "unknown_policy": m.get("unknown_policy", {}), "routes": {}}
    for rp, r in (m.get("routes") or {}).items():
        params = {src: {pk: rule for pk, rule in (pd or {}).items() if rule.get("status", "auto") != "auto"}
                  for src, pd in (r.get("params") or {}).items()}
        params = {src: pd for src, pd in params.items() if pd}
        if r.get("status", "auto") != "auto" or params:
            out["routes"][rp] = {"status": r.get("status", "auto"), "sha256": r.get("sha256"),
                                 "sapi": r.get("sapi", "web"), "methods": r.get("methods", []), "params": params}
    if os.path.exists(decisions_path):
        shutil.copy2(decisions_path, decisions_path + ".bak")
    with open(decisions_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return len(out["routes"])


def run_smoke_test(temp_output_path):
    """Proširena smoke matrica (v0.3.2) sa sentinel testom i proverom statusa."""
    test_dir = tempfile.mkdtemp(prefix="aceshrug_smoke_")
    try:
        app_dir = os.path.join(test_dir, "app")
        ace_dir = os.path.join(test_dir, "ace")
        os.makedirs(app_dir)
        os.makedirs(ace_dir)
        
        probe_code = b"<?php echo 'BODY-OK';"
        probe_path = os.path.join(app_dir, "probe.php")
        with open(probe_path, "wb") as f:
            f.write(probe_code)
        probe_hash = hashlib.sha256(probe_code).hexdigest()
        
        other_path = os.path.join(app_dir, "other.php")
        with open(other_path, "wb") as f:
            f.write(b"<?php echo 'OTHER-OK';")

        inc_path = os.path.join(app_dir, "include.php")
        with open(inc_path, "wb") as f:
            f.write(b"<?php // include file")
        inc_hash = hashlib.sha256(b"<?php // include file").hexdigest()
        
        src_gate = os.path.join(temp_output_path, "gate.php")
        dst_gate = os.path.join(ace_dir, "gate.php")
        shutil.copy(src_gate, dst_gate)
        
        events_log_path = os.path.join(test_dir, "events.log")
        
        fixture_prepend = os.path.join(test_dir, "fixture_prepend.php")
        with open(fixture_prepend, "w") as f:
            f.write("<?php\nif(getenv('SIM_GET')!==false) { parse_str(getenv('SIM_GET'), $_GET); }\nif(getenv('SIM_POST')!==false) { parse_str(getenv('SIM_POST'), $_POST); }\n$_REQUEST = array_merge($_GET, $_POST);\nrequire_once '" + dst_gate + "';\n")

        def execute_test(mode, script_path, expected_output, expected_code, expected_event=None, route_status="confirmed", param_schema=None, custom_manifest=None, sim_get="", expect_sentinel_artifact=None, policy=None, expect_sentinel_created=None, route_file="probe.php"):
            if custom_manifest:
                manifest_data = custom_manifest
            else:
                manifest_data = {
                    "format_version": 2,
                    "engine_version": "0.3.2",
                    "application_id": "smoke_test",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "mode": mode,
                    "app_root": app_dir,
                    "unknown_policy": policy or {"GET": "allow_with_signal", "POST": "block", "COOKIE": "allow_with_signal"},
                    "routes": {
                        route_file: {
                            "type": "ENTRYPOINT",
                            "status": route_status,
                            "sapi": "cli",
                            "methods": ["GET", "POST"],
                            "sha256": hashlib.sha256(open(os.path.join(app_dir, route_file), "rb").read()).hexdigest(),
                            "params": param_schema or {"GET": {}, "POST": {}, "COOKIE": {}}
                        }
                    },
                    "includes": {
                        "include.php": {
                            "type": "INCLUDE",
                            "sha256": inc_hash
                        }
                    }
                }
            manifest_content = "<?php\nreturn " + python_to_php_array(manifest_data) + ";\n"
            with open(os.path.join(ace_dir, "manifest.php"), "w") as f:
                f.write(manifest_content)
            
            if os.path.exists(events_log_path):
                os.remove(events_log_path)
            for sf in (expect_sentinel_artifact, expect_sentinel_created):
                if sf and os.path.exists(sf):
                    os.remove(sf)
            
            env = os.environ.copy()
            env.pop("SIM_GET", None)
            env.pop("SIM_POST", None)
            if sim_get:
                env["SIM_GET"] = sim_get
            
            cmd = ['php', f'-dauto_prepend_file={fixture_prepend}', f'-derror_log={events_log_path}', script_path]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            stdout = res.stdout.decode()
            
            log_content = ""
            if os.path.exists(events_log_path):
                with open(events_log_path, "r", encoding="utf-8", errors="ignore") as lf:
                    log_content = lf.read()
            
            if res.returncode != expected_code:
                print(f"[-] Smoke test fail [{mode}, {os.path.basename(script_path)}]: expected code {expected_code}, got {res.returncode}")
                return False
            if expected_output and expected_output not in stdout:
                print(f"[-] Smoke test fail [{mode}, {os.path.basename(script_path)}]: expected output '{expected_output}', got '{stdout}'")
                return False
            if not expected_output and stdout.strip() != "":
                print(f"[-] Smoke test fail [{mode}, {os.path.basename(script_path)}]: expected empty output, got '{stdout}'")
                return False
            
            if expected_event is None:
                if "[ACESHRUG-EVENT]" in log_content:
                    print(f"[-] Smoke test fail [{mode}, {os.path.basename(script_path)}]: expected NO event, but got log: {log_content}")
                    return False
            else:
                if expected_event not in log_content:
                    print(f"[-] Smoke test fail [{mode}, {os.path.basename(script_path)}]: expected event '{expected_event}' not found in log: {log_content}")
                    return False

            if expect_sentinel_artifact is not None:
                exists = os.path.exists(expect_sentinel_artifact)
                if exists:
                    print(f"[-] Sentinel test fail: artifact '{expect_sentinel_artifact}' was created despite block!")
                    return False
            if expect_sentinel_created is not None and not os.path.exists(expect_sentinel_created):
                print(f"[-] Sentinel test fail: aplikacija nije izvrsila upis '{expect_sentinel_created}' (test nije validan)")
                return False

            return True

        # Test matrica
        if not execute_test("monitor", probe_path, "BODY-OK", 0, expected_event=None): return False
        if not execute_test("monitor", other_path, "OTHER-OK", 0, expected_event="unregistered_route"): return False
        if not execute_test("enforcement", probe_path, "BODY-OK", 0, expected_event=None): return False
        if not execute_test("enforcement", other_path, "", 1, expected_event="unregistered_route"): return False
        
        # Tamper test sa Sentinel proverom da fajl nije nastao
        sentinel_file = os.path.join(test_dir, "sentinel_artifact.txt")
        tamper_script = os.path.join(app_dir, "tamper_test.php")
        with open(tamper_script, "wb") as f:
            f.write(f"<?php file_put_contents('{sentinel_file}', 'should_not_exist'); echo 'TAMPERED';".encode())
        tamper_hash = hashlib.sha256(b"<?php echo 'BODY-OK';").hexdigest() # Mismatch sa manifestom

        bad_route_manifest = {
            "format_version": 2, "engine_version": "0.3.2", "application_id": "smoke_test",
            "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "enforcement", "app_root": app_dir,
            "unknown_policy": {"GET": "allow_with_signal", "POST": "block", "COOKIE": "allow_with_signal"},
            "routes": {"tamper_test.php": {"type": "ENTRYPOINT", "status": "confirmed", "sapi": "cli", "methods": ["GET"], "sha256": tamper_hash, "params": {"GET": {}, "POST": {}, "COOKIE": {}}}},
            "includes": {"include.php": {"type": "INCLUDE", "sha256": inc_hash}}
        }
        if not execute_test("enforcement", tamper_script, "", 1, expected_event="file_tampered", custom_manifest=bad_route_manifest, expect_sentinel_artifact=sentinel_file): return False

        # Scenario 6: include_tampered
        bad_manifest = {
            "format_version": 2, "engine_version": "0.3.2", "application_id": "smoke_test",
            "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "enforcement", "app_root": app_dir,
            "unknown_policy": {"GET": "allow_with_signal", "POST": "block", "COOKIE": "allow_with_signal"},
            "routes": {"probe.php": {"type": "ENTRYPOINT", "status": "confirmed", "sapi": "cli", "methods": ["GET"], "sha256": probe_hash, "params": {"GET": {}, "POST": {}, "COOKIE": {}}}},
            "includes": {"include.php": {"type": "INCLUDE", "sha256": "0" * 64}}
        }
        if not execute_test("enforcement", probe_path, "", 1, expected_event="include_tampered", custom_manifest=bad_manifest): return False

        # Test statusa: auto parametar u enforcementu propušta prekršaj uz signal
        auto_schema = {"GET": {"id": {"type": "string", "max": 3, "status": "auto"}}, "POST": {}, "COOKIE": {}}
        if not execute_test("enforcement", probe_path, "BODY-OK", 0, expected_event="max_length_exceeded", route_status="confirmed", param_schema=auto_schema, sim_get="id=toolongvalue"): return False

        # rejected ruta: monitor samo belezi, enforcement blokira
        if not execute_test("monitor", probe_path, "BODY-OK", 0, expected_event="rejected_route_accessed", route_status="rejected"): return False
        if not execute_test("enforcement", probe_path, "", 1, expected_event="rejected_route_accessed", route_status="rejected"): return False

        # Test statusa: confirmed parametar u enforcementu blokira prekršaj
        conf_schema = {"GET": {"id": {"type": "string", "max": 3, "status": "confirmed"}}, "POST": {}, "COOKIE": {}}
        if not execute_test("enforcement", probe_path, "", 1, expected_event="max_length_exceeded", route_status="confirmed", param_schema=conf_schema, sim_get="id=toolongvalue", expect_sentinel_artifact=sentinel_file): return False

        # Parametarski sentinel: skripta STVARNO pokusava upis; gate mora da ga spreci
        side_sentinel = os.path.join(test_dir, "side_effect.txt")
        side_script = os.path.join(app_dir, "side.php")
        with open(side_script, "wb") as f:
            f.write(f"<?php file_put_contents('{side_sentinel}', 'x'); echo 'SIDE-OK';".encode())
        # kontrola: bez prekrsaja upis se desava (dokaz da je test ziv)
        if not execute_test("enforcement", side_script, "SIDE-OK", 0, expected_event=None, param_schema=conf_schema, sim_get="id=ok", expect_sentinel_created=side_sentinel, route_file="side.php"): return False
        # prekrsaj potvrdjenog parametra: upis se ne sme desiti
        if not execute_test("enforcement", side_script, "", 1, expected_event="max_length_exceeded", param_schema=conf_schema, sim_get="id=toolongvalue", expect_sentinel_artifact=side_sentinel, route_file="side.php"): return False

        # null politika: monitor ne menja ulaz, enforcement+confirmed uklanja (i iz $_REQUEST)
        echo_script = os.path.join(app_dir, "echo.php")
        with open(echo_script, "wb") as f:
            f.write(b"<?php echo 'G:', isset($_GET['x']) ? 'Y' : 'N', ' R:', isset($_REQUEST['x']) ? 'Y' : 'N';")
        null_pol = {"GET": "null", "POST": "null", "COOKIE": "allow_with_signal"}
        if not execute_test("monitor", echo_script, "G:Y R:Y", 0, expected_event="logged_allow_would_drop", policy=null_pol, sim_get="x=1", route_file="echo.php"): return False
        if not execute_test("enforcement", echo_script, "G:Y R:Y", 0, expected_event="logged_allow_would_drop", route_status="auto", policy=null_pol, sim_get="x=1", route_file="echo.php"): return False
        if not execute_test("enforcement", echo_script, "G:N R:N", 0, expected_event="unknown_parameter_dropped", policy=null_pol, sim_get="x=1", route_file="echo.php"): return False

        return True
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def main():
    parser = argparse.ArgumentParser(description="ACESHRUG Universal Builder v0.3.2")
    parser.add_argument("--input", help="Ulazni direktorijum aplikacije (read-only)")
    parser.add_argument("--output", required=True, help="Izlazni ACESHRUG direktorijum (symlink baza)")
    parser.add_argument("--php-user", default="www-data", help="Sistemski korisnik za pool.conf")
    parser.add_argument("--php-group", default="www-data", help="Sistemska grupa za pool.conf")
    parser.add_argument("--allow-blocker", action="append", default=[], help="Ručno odobrenje")
    parser.add_argument("--keep", type=int, default=5, help="Broj verzija koje se čuvaju (minimum 1)")
    parser.add_argument("--rollback", action="store_true", help="Vrati symlink na prethodnu verziju")
    parser.add_argument("--strict", action="store_true", help="Odbij aktivaciju ako postoje auto rute ili parametri")
    parser.add_argument("--accept-stale", action="store_true", help="U enforcement rezimu dozvoli aktivaciju iako su neke potvrde zastarele (promenjen fajl)")
    parser.add_argument("--decisions", help="Fajl sa ljudskim odlukama (podrazumevano: <output>.decisions.json)")
    parser.add_argument("--export-decisions", action="store_true", help="Napravi decisions fajl iz trenutno aktivnog manifesta i izadji")

    args = parser.parse_args()

    if args.keep < 1:
        print("[-] Greška: Parametar --keep mora biti najmanje 1.")
        sys.exit(1)

    output_path = os.path.abspath(args.output)
    versions_parent = output_path + ".d"
    os.makedirs(versions_parent, exist_ok=True)
    lock_file_path = output_path + ".lock"

    # Konkurentno zaključavanje build-a (flock)
    with open(lock_file_path, "w") as lock_f:
        try:
            fcntl.flock(lock_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("[-] Greška: Drugi build je već u toku. Pokušajte ponovo kasnije.")
            sys.exit(1)

        if args.rollback:
            current_link = output_path
            if not os.path.islink(current_link):
                print(f"[-] Greška: '{current_link}' nije simlink, rollback nije moguć.")
                sys.exit(1)
            active_target = os.path.realpath(current_link)
            subdirs = sorted([os.path.join(versions_parent, d) for d in os.listdir(versions_parent) if os.path.isdir(os.path.join(versions_parent, d))])
            try:
                idx = subdirs.index(active_target)
                if idx > 0:
                    prev_version = subdirs[idx - 1]
                else:
                    print(f"[-] Greška: Nema starijih verzija od trenutne.")
                    sys.exit(1)
            except ValueError:
                if len(subdirs) >= 2:
                    prev_version = subdirs[-2]
                else:
                    print(f"[-] Greška: Nema dovoljno prethodnih verzija.")
                    sys.exit(1)
            
            temp_link = output_path + ".tmp_link"
            if os.path.islink(temp_link):
                os.unlink(temp_link)
            os.symlink(prev_version, temp_link)
            os.replace(temp_link, current_link)
            print(f"[✔] Uspešno izvršen pametan rollback na verziju: {prev_version}")
            sys.exit(0)

        decisions_path = os.path.abspath(args.decisions) if args.decisions else output_path + ".decisions.json"

        if args.export_decisions:
            active_manifest = os.path.join(output_path, "manifest.php")
            if not os.path.exists(active_manifest):
                print(f"[-] Greška: aktivni manifest '{active_manifest}' ne postoji.")
                sys.exit(1)
            try:
                n = export_decisions(active_manifest, decisions_path)
            except Exception as e:
                print(f"[-] Greška: {e}")
                sys.exit(1)
            print(f"[✔] Decisions fajl napravljen: {decisions_path} ({n} ruta sa odlukama)")
            sys.exit(0)

        if not args.input:
            print("[-] Greška: --input je obavezan.")
            sys.exit(1)
        input_path = os.path.realpath(args.input)
        if not os.path.isdir(input_path):
            print(f"[-] Greška: Ulazni direktorijum '{input_path}' ne postoji.")
            sys.exit(1)

        decisions, derrs = load_decisions(decisions_path)
        if derrs:
            print(f"[-] Greška u decisions fajlu {decisions_path}:")
            for e in derrs:
                print(f"    - {e}")
            sys.exit(1)

        print(f"[*] Analiziram aplikaciju...")
        routes, includes, all_files, blockers, findings, has_todos, has_auto_items = analyze_codebase(input_path, None, args.allow_blocker)

        if not all_files:
            print(f"[-] Greška: U ulaznom direktorijumu nije pronađen nijedan PHP fajl.")
            sys.exit(1)

        if blockers:
            print(f"[-] Greška: Pronađeno je {len(blockers)} neodobrenih blokera u kodu. Aktivacija prekinuta.")
            for b in blockers:
                print(f"    - {b['file']} [kod: {b['code']}]: {b['issue']}")
            sys.exit(2)

        applied, stale, missing, has_auto_items = apply_decisions(routes, decisions)
        bad_rx = check_regexes(routes)
        if bad_rx:
            print("[-] Greška: neispravan regex u pravilima:")
            for b in bad_rx:
                print(f"    - {b}")
            sys.exit(1)

        if stale and decisions.get("mode") == "enforcement" and not args.accept_stale:
            print(f"[-] Greška: enforcement režim, a {len(stale)} potvrđenih ruta je promenjeno od pregleda:")
            for sp in stale[:20]:
                print(f"    - {sp}")
            print("    Aktivni manifest ostaje nepromenjen. Pregledaj izmene i obnovi potvrde (sha256), ili pokreni sa --accept-stale (te rute prelaze u auto).")
            sys.exit(4)

        if args.strict and has_auto_items:
            print(f"[-] Greška: Režim --strict je uključen, ali postoje rute ili parametri sa 'auto' statusom.")
            sys.exit(3)

        timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:6]
        temp_output_path = os.path.join(versions_parent, timestamp_tag)
        os.makedirs(temp_output_path, exist_ok=False)
        os.chmod(temp_output_path, 0o750)

        try:
            marker_file = os.path.join(temp_output_path, ".aceshrug-generated")
            with open(marker_file, "w") as m:
                m.write("aceshrug-managed-directory\n")

            report_path = os.path.join(temp_output_path, "REPORT.md")
            with open(report_path, "w", encoding="utf-8") as rep:
                rep.write("# ACESHRUG Universal Analysis Report (v0.3.2)\n\n")
                rep.write(f"- **Scan Date:** {datetime.now(timezone.utc).isoformat()}\n")
                rep.write(f"- **Ukupno PHP fajlova:** {len(all_files)}\n")
                rep.write(f"- **Entrypoint ruta:** {len(routes)}\n")
                rep.write(f"- **Include fajlova:** {len(includes)}\n")
                rep.write(f"- **Decisions fajl:** `{decisions_path}` {'(ucitan)' if decisions else '(ne postoji; sve je auto)'}\n")
                rep.write(f"- **Rezim:** {decisions.get('mode', 'monitor')}\n")
                rep.write(f"- **Primenjene odluke:** {len(applied)} ruta\n")
                rep.write(f"- **Zastarele odluke (fajl promenjen, vraceno na auto):** {len(stale)}\n")
                rep.write(f"- **Odluke za rute kojih vise nema:** {len(missing)}\n")
                rep.write(f"- **Auto stavke prisutne:** {'Da' if has_auto_items else 'Ne'}\n\n")

                if stale:
                    rep.write("## ⚠ Zastarele odluke (potreban ponovni pregled)\n")
                    for x in stale:
                        rep.write(f"- `{x}`\n")
                    rep.write("\n")
                if missing:
                    rep.write("## ⚠ Odluke za rute koje vise ne postoje\n")
                    for x in missing:
                        rep.write(f"- `{x}`\n")
                    rep.write("\n")
                rep.write("## 📋 Rute po statusu\n")
                for r_path, r_meta in routes.items():
                    rep.write(f"- `{r_path}` [status: {r_meta.get('status', 'auto')}, sapi: {r_meta.get('sapi')}]\n")

            manifest_data = {
                "format_version": 2,
                "engine_version": "0.3.2",
                "application_id": os.path.basename(input_path),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "mode": decisions.get("mode", "monitor"),
                "app_root": input_path,
                "unknown_policy": dict({
                    "GET": "allow_with_signal",
                    "POST": "block",
                    "COOKIE": "allow_with_signal"
                }, **(decisions.get("unknown_policy") or {})),
                "routes": routes,
                "includes": includes
            }

            manifest_php_content = "<?php\nreturn " + python_to_php_array(manifest_data) + ";\n"
            manifest_file = os.path.join(temp_output_path, "manifest.php")
            with open(manifest_file, "w", encoding="utf-8") as f:
                f.write(manifest_php_content)

            gate_file = os.path.join(temp_output_path, "gate.php")
            with open(gate_file, "w", encoding="utf-8") as f:
                f.write(GATE_PHP_STUB)

            final_gate_path = os.path.join(output_path, "gate.php")
            pool_conf = os.path.join(temp_output_path, "pool.conf")
            with open(pool_conf, "w", encoding="utf-8") as f:
                f.write(f"""[aceshrug_pool]
user = {args.php_user}
group = {args.php_group}
listen = /run/php/php-fpm-aceshrug.sock
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35

php_admin_value[auto_prepend_file] = {final_gate_path}
php_admin_flag[allow_url_include] = Off
php_admin_flag[expose_php] = Off
""")

            for php_f in ['manifest.php', 'gate.php']:
                fpath = os.path.join(temp_output_path, php_f)
                res = subprocess.run(['php', '-l', fpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if res.returncode != 0:
                    raise RuntimeError(f"Sintaksna greška u generisanom fajlu {php_f}:\n{res.stderr.decode()}")

            test_script = f'$m = require "{manifest_file}"; var_dump(is_array($m) && ($m["format_version"] ?? 0) === 2);'
            test_res = subprocess.run(['php', '-r', test_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if b"bool(true)" not in test_res.stdout:
                raise RuntimeError(f"Manifest v2 nije validan po strukturi:\n{test_res.stderr.decode()}")

            if not run_smoke_test(temp_output_path):
                raise RuntimeError("Smoke test neuspešan.")

            if os.geteuid() == 0:
                try:
                    root_uid = pwd.getpwnam("root").pw_uid
                    group_gid = grp.getgrnam(args.php_group).gr_gid
                    
                    os.chown(temp_output_path, root_uid, group_gid)
                    os.chmod(temp_output_path, 0o750)
                    
                    for root, dirs, files in os.walk(temp_output_path):
                        for d in dirs:
                            os.chown(os.path.join(root, d), root_uid, group_gid)
                            os.chmod(os.path.join(root, d), 0o750)
                        for f in files:
                            os.chown(os.path.join(root, f), root_uid, group_gid)
                            os.chmod(os.path.join(root, f), 0o640)
                except Exception as e:
                    raise RuntimeError(f"Neuspešno postavljanje vlasništva/prava: {e}")
            else:
                print("[!] Upozorenje: Builder se ne pokreće kao root.")

            chk_gate = os.path.join(temp_output_path, "gate.php")
            chk_manifest = os.path.join(temp_output_path, "manifest.php")
            read_chk_cmd = ['sudo', '-u', args.php_user, 'php', '-r', f'exit(is_readable("{chk_gate}") && is_readable("{chk_manifest}") ? 0 : 1);']
            rc_res = subprocess.run(read_chk_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if rc_res.returncode != 0:
                raise RuntimeError(f"Greška prava pristupa: PHP korisnik '{args.php_user}' ne može da pročita generisane fajlove.")

            temp_link = output_path + ".tmp_link"
            if os.path.islink(temp_link):
                os.unlink(temp_link)
            os.symlink(temp_output_path, temp_link)
            os.replace(temp_link, output_path)

            all_versions = sorted([os.path.join(versions_parent, d) for d in os.listdir(versions_parent) if os.path.isdir(os.path.join(versions_parent, d))])
            if len(all_versions) > args.keep:
                for old_v in all_versions[:-args.keep]:
                    active_target = os.path.realpath(output_path) if os.path.islink(output_path) else ""
                    if old_v != active_target and os.path.exists(os.path.join(old_v, ".aceshrug-generated")):
                        shutil.rmtree(old_v)

            print(f"[✔] ACESHRUG v0.3.2 uspešno generisan i aktiviran preko symlink-a: {output_path}")

            if stale:
                print(f"[!] Upozorenje: {len(stale)} odluka je zastarelo (fajl promenjen) i vraceno na auto. Vidi REPORT.md.")
            if missing:
                print(f"[!] Upozorenje: {len(missing)} odluka se odnosi na rute kojih vise nema.")
            if has_auto_items:
                print(f"[!] Postoje stavke sa statusom auto (samo signal). Rezim: {decisions.get('mode', 'monitor')}.")
                sys.exit(3)
            sys.exit(0)

        except Exception as e:
            active_target = os.path.realpath(output_path) if os.path.islink(output_path) else ""
            if 'temp_output_path' in locals() and os.path.exists(temp_output_path) and temp_output_path != active_target:
                shutil.rmtree(temp_output_path, ignore_errors=True)
            print(f"[-] Kritična greška: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()