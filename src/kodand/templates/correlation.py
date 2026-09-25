from __future__ import annotations


def correlate_capabilities(capabilities: list) -> list:
    findings = []; s = set(capabilities)
    if "credential-access" in s and "network-access" in s: findings.append("credential-exfiltration-risk")
    if "shell-execution" in s and ("network-access" in s or "external-instruction" in s): findings.append("remote-code-execution-risk")
    if "credential-access" in s and "data-exfiltration" in s: findings.append("credential-exfiltration-risk")
    if "isolation-escape" in s and "shell-execution" in s: findings.append("host-compromise-risk")
    if "identity-tampering" in s or ("filesystem-read" in s and "identity-tampering" in s): findings.append("agent-identity-hijack-risk")
    if "approval-bypass" in s and ("filesystem-write" in s or "code-execution" in s): findings.append("unauthorized-change-risk")
    if "scanner-evasion" in s and "code-execution" in s: findings.append("stealth-payload-risk")
    return sorted(set(findings))
