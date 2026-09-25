import pytest

tree_sitter = pytest.importorskip("tree_sitter")

from kodand.codeanalysis.js_ast import analyze_js_file  # noqa: E402


def _analyze(tmp_path, source, name="sample.js"):
    f = tmp_path / name
    f.write_text(source)
    return analyze_js_file(f, tmp_path)


def _ids(matches):
    return {m.template_id for m in matches}


def test_eval_and_new_function_flagged(tmp_path):
    assert "AST04-JS-EVAL-EXEC" in _ids(_analyze(tmp_path, "eval(x);\n"))
    assert "AST04-JS-EVAL-EXEC" in _ids(_analyze(tmp_path, "new Function('return 1');\n"))


def test_dynamic_require_flagged_literal_is_not(tmp_path):
    assert "AST04-JS-DYNAMIC-IMPORT" in _ids(_analyze(tmp_path, "require(pkg);\n"))
    assert "AST04-JS-DYNAMIC-IMPORT" not in _ids(_analyze(tmp_path, "require('fs');\n"))


def test_shell_injection_exec_vs_spawn(tmp_path):
    assert "AST01-JS-SHELL-INJECTION" in _ids(_analyze(tmp_path, "child_process.exec(cmd);\n"))
    assert "AST01-JS-SHELL-INJECTION" not in _ids(_analyze(tmp_path, "child_process.exec('ls -l');\n"))
    cp = "const cp = require('child_process');\n"
    assert "AST01-JS-SHELL-INJECTION" in _ids(_analyze(tmp_path, cp + "cp.spawn(cmd, {shell: true});\n"))
    assert "AST01-JS-SHELL-INJECTION" not in _ids(_analyze(tmp_path, cp + "cp.spawn(cmd);\n"))


def test_exec_on_other_objects_is_not_shell(tmp_path):
    source = ("db.exec(`CREATE TABLE t (id INTEGER)`);\n"
              "const m = /a(b)/.exec(input);\n"
              "db.exec(sqlFromUser);\n")
    assert "AST01-JS-SHELL-INJECTION" not in _ids(_analyze(tmp_path, source))


def test_child_process_bindings_are_followed(tmp_path):
    lines = {
        "const { exec: run } = require('node:child_process');\nrun(cmd);\n": True,
        "require('child_process').execSync(userCmd);\n": True,
        "const cp = require('child_process');\ncp.exec(`ls ${dir}`);\n": True,
        "const cp = require('child_process');\ncp.exec(`ls -l`);\n": False,
    }
    for source, flagged in lines.items():
        assert ("AST01-JS-SHELL-INJECTION" in _ids(_analyze(tmp_path, source))) is flagged, source
    esm = "import { execSync } from 'child_process';\nimport * as proc from 'child_process';\nexecSync(`rm ${t}`);\nproc.exec(command);\n"
    hits = [m.line for m in _analyze(tmp_path, esm, name="sample.mjs") if m.template_id == "AST01-JS-SHELL-INJECTION"]
    assert hits == [3, 4]


def test_hardcoded_credential_flagged_and_redacted(tmp_path):
    matches = _analyze(tmp_path, "const apiKey = 'sk-abcdefgh12345678';\n")
    hits = [m for m in matches if m.template_id == "AST03-JS-HARDCODED-CREDENTIAL"]
    assert hits
    assert "sk-abcdefgh12345678" not in hits[0].matched_value


def test_env_read_then_network_send_flagged(tmp_path):
    source = "function leak(){ const t = process.env.TOKEN; fetch(url, {body: t}); }\n"
    assert "AST01-JS-EXFIL" in _ids(_analyze(tmp_path, source))
    assert "AST01-JS-EXFIL" not in _ids(_analyze(tmp_path, "function fine(){ fetch(url); }\n"))


def test_obfuscated_packer_shape_flagged(tmp_path):
    source = "eval(function(p,a,c,k,e,d){return p}('x',1,1,'a'.split('|'),0,{}))\n"
    assert "AST04-JS-OBFUSCATED-CODE" in _ids(_analyze(tmp_path, source))


def test_typescript_extension_supported(tmp_path):
    assert "AST04-JS-EVAL-EXEC" in _ids(_analyze(tmp_path, "eval(x);\n", name="sample.ts"))


def test_oversized_file_returns_empty(tmp_path, monkeypatch):
    import kodand.codeanalysis.js_ast as mod

    monkeypatch.setattr(mod, "MAX_JS_SOURCE_BYTES", 5)
    assert _analyze(tmp_path, "eval(x);\n") == []


def test_unparsable_input_does_not_raise(tmp_path):
    # tree-sitter is error-tolerant (partial tree with ERROR nodes), so this
    # mainly proves analyze_js_file never raises on garbage input
    _analyze(tmp_path, "function( this is not valid js {{{\n")
