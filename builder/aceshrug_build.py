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
from datetime import datetime, timezone

# --- GATEKEEPER STUB (v0.2.16 - Production Hardened & Status Tested) ---
GATE_PHP_STUB = """<?php
/**
 * ACESHRUG Gatekeeper v0.2.16 (Production Hardened Runtime)
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
        if ($full_inc_path === false || strpos($full_inc_path, $prefix) !== 0 || !is_file($full_inc_path)) {
            aceshrug_event("include_missing_or_outside", $inc_path, "fatal", "fatal_block");
            aceshrug_block();
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
    if ($route_status === 'rejected') {
        aceshrug_event("rejected_route_accessed", $rel_path, "critical", "blocked");
        aceshrug_block();
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
    $sources = ['GET' => $_GET, 'POST' => $_POST, 'COOKIE' => $_COOKIE];
    
    foreach ($sources as $src_name => $data) {
        $schema = $allowed_params[$src_name] ?? [];
        if (!is_array($schema)) {
            aceshrug_event("manifest_structure_invalid", "Invalid param schema", "fatal", "fatal_block");
            aceshrug_block();
        }
        
        foreach ($data as $key => $val) {
            if (!array_key_exists($key, $schema)) {
                $action_policy = $policy[$src_name] ?? 'allow_with_signal';
                $enforce_action = ($action_policy === 'block' && $mode === 'enforcement' && $route_status === 'confirmed') ? 'blocked' : 'logged_allow';
                aceshrug_event("unknown_parameter", "$src_name: $key", "info", $enforce_action);
                if ($action_policy === 'block' && $mode === 'enforcement' && $route_status === 'confirmed') {
                    aceshrug_block();
                }
            } else {
                $rule = $schema[$key];
                $type = $rule['type'] ?? 'string';
                $max = $rule['max'] ?? 4096;
                $p_status = $rule['status'] ?? 'auto';
                
                if ($p_status === 'rejected') {
                    aceshrug_event("rejected_parameter_accessed", "$src_name.$key", "critical", "blocked");
                    aceshrug_block();
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

    $log_entry = json_encode([
        'timestamp' => gmdate('c'),
        'component' => 'ACESHRUG',
        'event' => $reason,
        'severity' => $severity,
        'action' => $action,
        'ip' => $ip,
        'detail' => substr($detail, 0, 128)
    ]);
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

def analyze_codebase(input_dir, allowed_blockers=None):
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
        (r'\binclude\s*\$|\brequire\s*\$', "dyninclude", "Dinamički include/require sa promenljivom"),
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
            includes[relpath] = {
                "type": "INCLUDE",
                "sha256": fhash
            }
        else:
            sapi_type = "cli" if "cli" in relpath.lower() or "artisan" in relpath.lower() else "web"
            methods = ["GET", "POST"] if post_params or "POST" in content_text or "form" in content_text.lower() else ["GET"]
            routes[relpath] = {
                "type": "ENTRYPOINT",
                "status": "auto",
                "sapi": sapi_type,
                "methods": methods,
                "sha256": fhash,
                "params": {
                    "GET": get_params,
                    "POST": post_params,
                    "COOKIE": {}
                }
            }
            has_auto_items = True

    return routes, includes, php_files, blockers, findings, has_todos, has_auto_items

def run_smoke_test(temp_output_path):
    """Proširena smoke matrica (v0.2.16) sa pokrivanjem auto vs confirmed status logike preko env fixture-a."""
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
        
        # Fixture prepend za punjenje $_GET / $_POST iz environment varijabli (za testiranje statusa)
        fixture_prepend = os.path.join(test_dir, "fixture_prepend.php")
        with open(fixture_prepend, "w") as f:
            f.write("<?php\nif(isset($_ENV['SIM_GET'])) { parse_str($_ENV['SIM_GET'], $_GET); }\nif(isset($_ENV['SIM_POST'])) { parse_str($_ENV['SIM_POST'], $_POST); }\nrequire_once '" + dst_gate + "';\n")

        def execute_test(mode, script_path, expected_output, expected_code, expected_event=None, route_status="confirmed", param_schema=None, custom_manifest=None, sim_get=""):
            if custom_manifest:
                manifest_data = custom_manifest
            else:
                manifest_data = {
                    "format_version": 2,
                    "engine_version": "0.2.16",
                    "application_id": "smoke_test",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "mode": mode,
                    "app_root": app_dir,
                    "unknown_policy": {"GET": "allow_with_signal", "POST": "block", "COOKIE": "allow_with_signal"},
                    "routes": {
                        "probe.php": {
                            "type": "ENTRYPOINT",
                            "status": route_status,
                            "sapi": "cli",
                            "methods": ["GET", "POST"],
                            "sha256": probe_hash,
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
            
            env = os.environ.copy()
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
            return True

        # Test matrica
        if not execute_test("monitor", probe_path, "BODY-OK", 0, expected_event=None): return False
        if not execute_test("monitor", other_path, "OTHER-OK", 0, expected_event="unregistered_route"): return False
        if not execute_test("enforcement", probe_path, "BODY-OK", 0, expected_event=None): return False
        if not execute_test("enforcement", other_path, "", 1, expected_event="unregistered_route"): return False
        
        # Tamper test
        with open(probe_path, "wb") as f: f.write(b"<?php echo 'TAMPERED';")
        if not execute_test("enforcement", probe_path, "", 1, expected_event="file_tampered"): return False
        with open(probe_path, "wb") as f: f.write(probe_code)
        
        # Scenario 6: include_tampered
        bad_manifest = {
            "format_version": 2, "engine_version": "0.2.16", "application_id": "smoke_test",
            "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "enforcement", "app_root": app_dir,
            "unknown_policy": {"GET": "allow_with_signal", "POST": "block", "COOKIE": "allow_with_signal"},
            "routes": {"probe.php": {"type": "ENTRYPOINT", "status": "confirmed", "sapi": "cli", "methods": ["GET"], "sha256": probe_hash, "params": {"GET": {}, "POST": {}, "COOKIE": {}}}},
            "includes": {"include.php": {"type": "INCLUDE", "sha256": "0" * 64}}
        }
        if not execute_test("enforcement", probe_path, "", 1, expected_event="include_tampered", custom_manifest=bad_manifest): return False

        # Scenario 10: neispravan manifest
        invalid_manifest = {"format_version": 99}
        if not execute_test("monitor", probe_path, "", 1, expected_event="manifest_structure_invalid", custom_manifest=invalid_manifest): return False

        # Test statusa: auto parametar u enforcementu propušta prekršaj uz signal (max_length_exceeded)
        auto_schema = {"GET": {"id": {"type": "string", "max": 3, "status": "auto"}}, "POST": {}, "COOKIE": {}}
        if not execute_test("enforcement", probe_path, "BODY-OK", 0, expected_event="max_length_exceeded", route_status="confirmed", param_schema=auto_schema, sim_get="id=toolongvalue"): return False

        # Test statusa: confirmed parametar u enforcementu blokira prekršaj
        conf_schema = {"GET": {"id": {"type": "string", "max": 3, "status": "confirmed"}}, "POST": {}, "COOKIE": {}}
        if not execute_test("enforcement", probe_path, "", 1, expected_event="max_length_exceeded", route_status="confirmed", param_schema=conf_schema, sim_get="id=toolongvalue"): return False

        return True
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def main():
    parser = argparse.ArgumentParser(description="ACESHRUG Universal Builder v0.2.16")
    parser.add_argument("--input", required=True, help="Ulazni direktorijum aplikacije (read-only)")
    parser.add_argument("--output", required=True, help="Izlazni ACESHRUG direktorijum (symlink baza)")
    parser.add_argument("--php-user", default="www-data", help="Sistemski korisnik za pool.conf")
    parser.add_argument("--php-group", default="www-data", help="Sistemska grupa za pool.conf")
    parser.add_argument("--allow-blocker", action="append", default=[], help="Ručno odobrenje")
    parser.add_argument("--keep", type=int, default=5, help="Broj verzija koje se čuvaju")
    parser.add_argument("--rollback", action="store_true", help="Vrati symlink na prethodnu verziju")
    parser.add_argument("--force", action="store_true", help="Zameni izlazni direktorijum uz proveru markera")

    args = parser.parse_args()

    output_path = os.path.abspath(args.output)

    if args.rollback:
        versions_dir = output_path + ".d"
        current_link = output_path
        if not os.path.islink(current_link):
            print(f"[-] Greška: '{current_link}' nije simlink, rollback nije moguć.")
            sys.exit(1)
        active_target = os.path.realpath(current_link)
        subdirs = sorted([os.path.join(versions_dir, d) for d in os.listdir(versions_dir) if os.path.isdir(os.path.join(versions_dir, d))])
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

    input_path = os.path.realpath(args.input)
    if not os.path.isdir(input_path):
        print(f"[-] Greška: Ulazni direktorijum '{input_path}' ne postoji.")
        sys.exit(1)

    print(f"[*] Analiziram aplikaciju...")
    routes, includes, all_files, blockers, findings, has_todos, has_auto_items = analyze_codebase(input_path, args.allow_blocker)

    if blockers:
        print(f"[-] Greška: Pronađeno je {len(blockers)} neodobrenih blokera u kodu. Aktivacija prekinuta.")
        for b in blockers:
            print(f"    - {b['file']} [kod: {b['code']}]: {b['issue']}")
        sys.exit(2)

    versions_parent = output_path + ".d"
    os.makedirs(versions_parent, exist_ok=True)
    
    # Jedinstveno ime verzije sa timestamp-om i uuid-om, sprečavanje race condition-a (Tačka 1)
    timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:6]
    temp_output_path = os.path.join(versions_parent, timestamp_tag)
    os.makedirs(temp_output_path, exist_ok=False)
    os.chmod(temp_output_path, 0o750)

    try:
        marker_file = os.path.join(temp_output_path, ".aceshrug-generated")
        with open(marker_file, "w") as m:
            m.write("aceshrug-managed-directory\n")

        # Generisanje REPORT.md (Povraćeno prema C07)
        report_path = os.path.join(temp_output_path, "REPORT.md")
        with open(report_path, "w", encoding="utf-8") as rep:
            rep.write("# ACESHRUG Universal Analysis Report (v0.2.16)\n\n")
            rep.write(f"- **Scan Date:** {datetime.now(timezone.utc).isoformat()}\n")
            rep.write(f"- **Ukupno PHP fajlova:** {len(all_files)}\n")
            rep.write(f"- **Entrypoint ruta:** {len(routes)}\n")
            rep.write(f"- **Include fajlova:** {len(includes)}\n")
            rep.write(f"- **Todo šeme prisutne:** {'Da (Monitor režim obavezan)' if has_todos else 'Ne'}\n")
            rep.write(f"- **Auto stavke prisutne:** {'Da' if has_auto_items else 'Ne'}\n\n")

            rep.write("## 📋 Rute po statusu\n")
            for r_path, r_meta in routes.items():
                rep.write(f"- `{r_path}` [status: {r_meta.get('status', 'auto')}, sapi: {r_meta.get('sapi')}]\n")

        manifest_data = {
            "format_version": 2,
            "engine_version": "0.2.16",
            "application_id": os.path.basename(input_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "monitor",
            "app_root": input_path,
            "unknown_policy": {
                "GET": "allow_with_signal",
                "POST": "block",
                "COOKIE": "allow_with_signal"
            },
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

        print(f"[✔] ACESHRUG v0.2.16 uspešno generisan i aktiviran preko symlink-a: {output_path}")

        if has_todos or has_auto_items:
            print("[!] Upozorenje: Postoje stavke sa statusom auto. Sistem je u Monitor režimu.")
            sys.exit(3)
        sys.exit(0)

    except Exception as e:
        # Sigurnosna provera: nikada ne brisi aktivni symlink target u except bloku (Tačka 1)
        active_target = os.path.realpath(output_path) if os.path.islink(output_path) else ""
        if 'temp_output_path' in locals() and os.path.exists(temp_output_path) and temp_output_path != active_target:
            shutil.rmtree(temp_output_path, ignore_errors=True)
        print(f"[-] Kritična greška: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
