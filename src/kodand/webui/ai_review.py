"""Calls a configured AI provider to get a second opinion on a finding (stdlib HTTP only)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

_TIMEOUT = 40


def _post_json(url: str, headers: dict, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                  headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{e.code} {e.reason}: {e.read().decode(errors='replace')[:500]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(str(e.reason)) from e


def build_prompt(finding: dict, file_contents: dict | None = None) -> str:
    occ = finding.get("occurrences", [])[:5]
    evidence = "\n".join(f"- {o['file']}:{o['line']} `{o['matched_value']}` — {o['excerpt']}" for o in occ) or "(no occurrences)"
    context_block = ""
    if file_contents:
        # full content of the affected files, not just the matched line — lets the model judge
        # real context (e.g. inside a comment/example vs. code that actually executes) and
        # cross-reference other files, instead of just re-confirming the regex matched
        parts = [f"--- {path} ---\n{content}" for path, content in file_contents.items()]
        context_block = "\nFull content of affected file(s), for contextual and cross-file analysis:\n\n" + "\n\n".join(parts) + "\n"
    return (
        "You are a security analyst reviewing a static-analysis finding from an AI agent skill scanner. "
        "Assess whether this looks like a true positive or false positive, and give a short remediation opinion."
        + (" Use the full file content below to judge real context, not just the matched excerpt." if file_contents else "") +
        "\n\n"
        f"Title: {finding.get('title')}\n"
        f"Category: {finding.get('category')} {finding.get('category_name')}\n"
        f"Severity: {finding.get('severity')} | Confidence: {finding.get('confidence')} ({finding.get('confidence_score')}/100)\n"
        f"Description: {finding.get('description')}\n"
        f"Technical root cause: {finding.get('technical_root_cause')}\n"
        f"Attack scenario: {finding.get('attack_scenario')}\n"
        f"Capabilities: {', '.join(finding.get('capabilities', [])) or 'none inferred'}\n\n"
        f"Evidence:\n{evidence}\n"
        f"{context_block}\n"
        "Reply in under 200 words: verdict (True Positive / False Positive / Needs More Context), reasoning, and one concrete next step."
    )


def _oai_messages(turns: list) -> list:
    return [{"role": t["role"], "content": t["content"]} for t in turns]


def _gemini_contents(turns: list) -> list:
    return [{"role": "model" if t["role"] == "assistant" else "user", "parts": [{"text": t["content"]}]} for t in turns]


def _complete(provider: str, cfg: dict, turns: list) -> str:
    """turns: [{"role": "user"|"assistant", "content": str}, ...], oldest first."""
    cfg = cfg or {}
    if provider == "openai":
        if not cfg.get("api_key"): raise RuntimeError("ChatGPT (OpenAI) API key not configured")
        data = _post_json("https://api.openai.com/v1/chat/completions",
                           {"Authorization": f"Bearer {cfg['api_key']}"},
                           {"model": cfg.get("model") or "gpt-4o-mini", "messages": _oai_messages(turns)})
        return data["choices"][0]["message"]["content"].strip()
    if provider == "claude":
        if not cfg.get("api_key"): raise RuntimeError("Claude API key not configured")
        data = _post_json("https://api.anthropic.com/v1/messages",
                           {"x-api-key": cfg["api_key"], "anthropic-version": "2023-06-01"},
                           {"model": cfg.get("model") or "claude-sonnet-5", "max_tokens": 700,
                            "messages": _oai_messages(turns)})
        return "".join(b.get("text", "") for b in data.get("content", [])).strip()
    if provider == "gemini":
        if not cfg.get("api_key"): raise RuntimeError("Gemini API key not configured")
        model = cfg.get("model") or "gemini-2.0-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={cfg['api_key']}"
        data = _post_json(url, {}, {"contents": _gemini_contents(turns)})
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    if provider == "custom":
        # OpenAI-compatible chat-completions shape — matches OpenRouter, vLLM, Ollama's
        # OpenAI-compat mode, LM Studio, and most self-hosted gateways.
        if not cfg.get("endpoint"): raise RuntimeError("Custom AI agent endpoint not configured")
        if not cfg.get("model"): raise RuntimeError("Custom AI agent model not configured (required, e.g. 'openai/gpt-4o-mini' for OpenRouter)")
        headers = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg.get("api_key") else {}
        data = _post_json(cfg["endpoint"], headers,
                           {"model": cfg["model"], "messages": _oai_messages(turns)})
        choices = data.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            return (msg.get("content") or choices[0].get("text") or "").strip()
        return str(data.get("response") or data.get("text") or data.get("output") or data)
    raise RuntimeError(f"Unknown AI provider '{provider}'")


def call_provider(provider: str, cfg: dict, finding: dict, file_contents: dict | None = None) -> str:
    return _complete(provider, cfg, [{"role": "user", "content": build_prompt(finding, file_contents)}])


def test_connection(provider: str, cfg: dict) -> str:
    return _complete(provider, cfg, [{"role": "user", "content": "Reply with exactly: Kodand connection OK"}])


def chat_reply(provider: str, cfg: dict, finding: dict, history: list, message: str, file_contents: dict | None = None) -> str:
    """Continue the review discussion for a finding. `history` is the finding's existing
    comments in chronological order (each {"kind": "ai"|"user", "text": str, ...}); AI-authored
    comments become assistant turns so the model sees its own prior replies."""
    turns = [{"role": "user", "content": build_prompt(finding, file_contents)}]
    for c in history:
        turns.append({"role": "assistant" if c.get("kind") == "ai" else "user", "content": c["text"]})
    turns.append({"role": "user", "content": message})
    return _complete(provider, cfg, turns)


# --- Agentic verification (Claude only): the model decides which files/finding detail to pull
# via tool-use, instead of Kodand pre-selecting context into one static prompt. Runs in-process —
# no MCP wire protocol involved, just the same store functions the MCP server's tools call. ---

_AGENT_TOOLS = [
    {"name": "list_scan_files", "description": "List every file Kodand scanned for this finding's scan (path + size).",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_file_content", "description": "Read the full current content of one scanned file by its relative path.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "get_finding", "description": "Re-fetch this finding's full detail (all occurrences, remediation, etc).",
     "input_schema": {"type": "object", "properties": {}}},
]


def _run_agent_tool(name: str, tool_input: dict, project_id: str, scan_id: str, finding_id: str) -> str:
    from kodand.webui import store
    try:
        if name == "list_scan_files":
            return json.dumps(store.list_scan_files(project_id, scan_id))
        if name == "get_file_content":
            return store.get_file_content(project_id, scan_id, tool_input.get("path", ""))
        if name == "get_finding":
            return json.dumps(store.find_finding(project_id, scan_id, finding_id))
        return f"Unknown tool: {name}"
    except Exception as e:
        return f"Error: {e}"


def agentic_verify(cfg: dict, finding: dict, project_id: str, scan_id: str, max_rounds: int = 4) -> str:
    if not cfg.get("api_key"):
        raise RuntimeError("Claude API key not configured")
    finding_id = finding["finding_id"]
    model = cfg.get("model") or "claude-sonnet-5"
    messages = [{"role": "user", "content": build_prompt(finding) +
                 "\n\nYou have tools to read the actual scanned files and finding detail — use them before giving your verdict."}]
    for _ in range(max_rounds):
        data = _post_json("https://api.anthropic.com/v1/messages",
                           {"x-api-key": cfg["api_key"], "anthropic-version": "2023-06-01"},
                           {"model": model, "max_tokens": 1024, "tools": _AGENT_TOOLS, "messages": messages})
        content = data.get("content", [])
        messages.append({"role": "assistant", "content": content})
        tool_uses = [b for b in content if b.get("type") == "tool_use"]
        if not tool_uses:
            return "".join(b.get("text", "") for b in content if b.get("type") == "text").strip()
        results = []
        for tu in tool_uses:
            result_text = _run_agent_tool(tu["name"], tu.get("input", {}), project_id, scan_id, finding_id)
            results.append({"type": "tool_result", "tool_use_id": tu["id"], "content": result_text[:8000]})
        messages.append({"role": "user", "content": results})
    return "Reached the tool-use round limit without a final verdict — try standard AI review instead."


if __name__ == "__main__":
    p = build_prompt({"title": "Test", "category": "AST01", "category_name": "Malicious Skills",
                       "severity": "high", "confidence": "medium", "confidence_score": 60,
                       "description": "d", "technical_root_cause": "t", "attack_scenario": "a",
                       "capabilities": ["network-access"], "occurrences": [{"file": "SKILL.md", "line": 1, "matched_value": "x", "excerpt": "x"}]})
    assert "Title: Test" in p and "SKILL.md:1" in p
    try:
        call_provider("openai", {}, {})
        raise AssertionError("expected missing-key error")
    except RuntimeError as e:
        assert "API key" in str(e)
    try:
        test_connection("custom", {"endpoint": "https://example.invalid"})
        raise AssertionError("expected missing-model error")
    except RuntimeError as e:
        assert "model" in str(e)
    try:
        chat_reply("openai", {}, {"title": "Test"}, [{"kind": "ai", "text": "prior reply"}], "follow-up question")
        raise AssertionError("expected missing-key error")
    except RuntimeError as e:
        assert "API key" in str(e)
    print("ai_review self-check OK")
