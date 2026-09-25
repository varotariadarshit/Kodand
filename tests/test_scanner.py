from kodand.scanner import inventory_repository


def _skill(tmp_path, name="skill-1"):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text("---\nname: t\ndescription: d\n---\nSay hello.\n")
    return d


def test_clean_repo_has_no_coverage_gap_warning(tmp_path):
    _skill(tmp_path)
    inv = inventory_repository(str(tmp_path))
    assert len(inv.extensions) == 1
    assert not any(w.code == "ENTRYPOINT_COVERAGE_GAP" for w in inv.warnings)


def test_coverage_gap_fires_for_instructions_md_outside_required_path(tmp_path):
    # copilot's matcher requires .github/instructions/*.instructions.md — one sitting
    # anywhere else is never recognized as an entrypoint, but still looks like one by name
    (tmp_path / "somewhere-else").mkdir()
    (tmp_path / "somewhere-else" / "foo.instructions.md").write_text("not under .github/instructions/")
    inv = inventory_repository(str(tmp_path))
    assert len(inv.extensions) == 0
    gap = next(w for w in inv.warnings if w.code == "ENTRYPOINT_COVERAGE_GAP")
    assert "somewhere-else/foo.instructions.md" in gap.message


def test_coverage_gap_fires_for_mdc_outside_cursor_rules_dir(tmp_path):
    (tmp_path / "bar.mdc").write_text("not under .cursor/rules/")
    inv = inventory_repository(str(tmp_path))
    gap = next(w for w in inv.warnings if w.code == "ENTRYPOINT_COVERAGE_GAP")
    assert "bar.mdc" in gap.message


def test_coverage_gap_does_not_fire_for_generic_settings_json(tmp_path):
    # settings.json/settings.local.json are deliberately excluded from the name-hint set —
    # too generic (common in unrelated JS/web projects) to name-match without heavy noise
    (tmp_path / "settings.json").write_text('{"unrelated": true}')
    inv = inventory_repository(str(tmp_path))
    assert not any(w.code == "ENTRYPOINT_COVERAGE_GAP" for w in inv.warnings)


def test_coverage_gap_lists_many_misses_with_a_truncation_note(tmp_path):
    for i in range(12):
        (tmp_path / f"d{i}").mkdir()
        (tmp_path / f"d{i}" / f"r{i}.mdc").write_text("not under .cursor/rules/")
    inv = inventory_repository(str(tmp_path))
    gap = next(w for w in inv.warnings if w.code == "ENTRYPOINT_COVERAGE_GAP")
    assert "12 file(s)" in gap.message and "2 more" in gap.message
