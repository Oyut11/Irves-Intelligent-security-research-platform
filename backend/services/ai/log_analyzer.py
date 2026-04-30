"""IRVES — Log Analyzer & Thinking Engine"""
import re, logging
from typing import List, Dict, Any, Optional
from collections import Counter

logger = logging.getLogger(__name__)

ERROR_PATTERNS = {
    "timeout": {
        "patterns": [r"timeout\s*(?:was\s*)?reached", r"timed\s*out", r"deadline\s*exceeded"],
        "severity": "critical",
        "meaning": "Frida cannot attach within timeout. App may be protected or device overloaded.",
        "action": "Check frida-server, try spawn mode, or verify anti-debug.",
    },
    "syntax_error": {
        "patterns": [r"SyntaxError", r"unexpected\s*token", r"Unexpected\s*identifier"],
        "severity": "high",
        "meaning": "Script has JS syntax error and never ran.",
        "action": "Fix syntax before re-injecting.",
    },
    "java_bridge_failed": {
        "patterns": [r"Java\s*Bridge\s*failed", r"java\.lang\.", r"Java\s*is\s*unavailable"],
        "severity": "high",
        "meaning": "App Java runtime unhookable. May be native-only or anti-Frida.",
        "action": "Switch to native Interceptor or verify class names.",
    },
    "process_crashed": {
        "patterns": [r"Process\s*crashed", r"FATAL\s*EXCEPTION", r"SIGSEGV", r"SIGABRT"],
        "severity": "critical",
        "meaning": "Target crashed. Script too aggressive or app has anti-tamper.",
        "action": "Use stealth cloak, try lighter hooks.",
    },
    "symbol_not_found": {
        "patterns": [r"could\s*not\s*resolve", r"module\s*not\s*found", r"undefined\s*symbol", r"\bopenat\b.*\bnot\s*resolved\b", r"\breadlink\b.*\bnot\s*resolved\b", r"\bnot\s*resolved\b"],
        "severity": "medium",
        "meaning": "Native symbol referenced does not exist in the target process.",
        "action": "Enumerate modules with Module.enumerateModules() and check available exports.",
    },
    "java_unavailable": {
        "patterns": [r"Java\s*not\s*available", r"Java\s*is\s*unavailable", r"skipping\s*.*Java.*", r"no\s*Java\s*runtime"],
        "severity": "high",
        "meaning": "The target process has no Java runtime (native-only app, or Java bridge failed). Zymbiote/Java hooks cannot be applied.",
        "action": "Switch to native-only Interceptor hooks. Use Module.enumerateImports() to find native functions to hook.",
    },
    "permission_denied": {
        "patterns": [r"permission\s*denied", r"access\s*denied", r"EPERM", r"EACCES"],
        "severity": "medium",
        "meaning": "Insufficient privileges or SELinux blocking.",
        "action": "Verify root, check SELinux.",
    },
    "hook_failure": {
        "patterns": [r"\d+\s*ok,\s*\d+\s*failed", r"hooks?\s*failed", r"hook.*failed", r"Stealth\s*hooks.*failed", r"loaded:\s*\d+\s*ok\s*,\s*\d+\s*failed"],
        "severity": "medium",
        "meaning": "Some hooks in a script failed to load while others succeeded. Usually means missing symbols, wrong module names, or anti-tamper protection blocking specific hooks.",
        "action": "Check which hooks failed and why. Enumerate modules to verify symbol names. Consider using lighter or alternative hooks.",
    },
    "attach_failed": {
        "patterns": [r"failed\s*to\s*attach", r"ptrace\s*attach\s*failed", r"spawning\s*failed"],
        "severity": "critical",
        "meaning": "Cannot attach/spawn target. Anti-debug or missing frida-server.",
        "action": "Restart frida-server, try spawn-gating.",
    },
    "script_destroyed": {
        "patterns": [r"Script\s*destroyed"],
        "severity": "high",
        "meaning": "Script unloaded. Process likely crashed or session ended.",
        "action": "Re-attach with stable hooks.",
    },
    "reference_error": {
        "patterns": [r"ReferenceError", r"is\s*not\s*defined"],
        "severity": "high",
        "meaning": "Script references undefined variable/function.",
        "action": "Fix undefined reference.",
    },
    "type_error": {
        "patterns": [r"TypeError", r"is\s*not\s*a\s*function"],
        "severity": "medium",
        "meaning": "Value used incorrectly (null/undefined object).",
        "action": "Check types of passed values.",
    },
}


def categorize_error(text: str) -> Optional[str]:
    text_lower = text.lower()
    for cat, info in ERROR_PATTERNS.items():
        for p in info["patterns"]:
            if re.search(p, text_lower, re.IGNORECASE):
                return cat
    return None


def analyze_logs_for_thinking(
    logs: str,
    script_history: Optional[str] = None,
    active_hooks: Optional[List[str]] = None,
    rt_errors: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    result = {
        "categories": set(),
        "counts": Counter(),
        "repeated": {},
        "warnings": [],
        "should_inject": True,
        "recommendation": "",
        "assessment": "",
        "snippets": [],
    }
    all_text = logs or ""
    if rt_errors:
        for rte in rt_errors:
            all_text += "\n" + rte.get("error", "")
            if rte.get("stack"):
                all_text += "\n" + rte.get("stack", "")
    if not all_text.strip():
        result["should_inject"] = False
        result["assessment"] = "No logs/errors. Suggest recon first."
        result["recommendation"] = "Ask user to run app and capture logs."
        return result

    lines = all_text.splitlines()
    err_lines = [l.strip() for l in lines if any(k in l.lower() for k in ["error", "failed", "exception", "crash", "timeout", "denied", "fatal"])]
    for line in err_lines[:20]:
        cat = categorize_error(line)
        if cat:
            result["categories"].add(cat)
            result["counts"][cat] += 1
            result["snippets"].append(f"[{cat}] {line[:150]}")

    # Repeated failures
    for cat, cnt in result["counts"].items():
        if cnt >= 3:
            result["repeated"][cat] = cnt
            result["warnings"].append(f"REPEATED {cnt}x: {cat}")

    # History check
    if script_history and "failed" in script_history.lower():
        fail_types = re.findall(r"(\w+).*\[failed\]", script_history, re.IGNORECASE)
        if fail_types:
            result["warnings"].append(f"Previously failed: {', '.join(set(fail_types))}")

    # Active hook check
    if active_hooks:
        for cat in list(result["categories"]):
            if cat == "java_bridge_failed" and any("zymbiote" in h.lower() for h in active_hooks):
                result["warnings"].append("Stealth already active but Java bridge still failing — target may be native-only.")
            if cat == "timeout" and len(active_hooks) > 2:
                result["warnings"].append(f"{len(active_hooks)} hooks active + timeouts — device may be overloaded.")

    # Decision logic
    if result["repeated"]:
        top = result["counts"].most_common(1)[0]
        result["should_inject"] = False
        result["assessment"] = f"Same error '{top[0]}' repeated {top[1]} times. Blind scripts won't help."
        result["recommendation"] = f"Diagnose root cause of {top[0]} before trying new scripts."
    elif "process_crashed" in result["categories"] or "attach_failed" in result["categories"]:
        result["should_inject"] = False
        result["assessment"] = "Critical failure detected. Process-level issues need manual investigation."
        result["recommendation"] = "Check device state, app stability, and frida-server health first."
    elif "syntax_error" in result["categories"] or "reference_error" in result["categories"]:
        result["assessment"] = "Script-level error. Fix before re-injecting."
        result["recommendation"] = "Provide corrected script based on exact error."
    elif "timeout" in result["categories"]:
        result["should_inject"] = False
        result["assessment"] = "Timeout pattern suggests environment issue, not script logic."
        result["recommendation"] = "Check frida-server, device load, and try spawn mode."
    elif result["categories"]:
        result["assessment"] = f"Errors found: {', '.join(result['categories'])}. Proceed carefully."
    else:
        result["assessment"] = "No recognizable errors. Proceed with targeted hook."

    return result


def build_thinking_context(analysis: Dict[str, Any]) -> str:
    parts = ["## AI THINKING PHASE — Log Analysis\n"]
    parts.append(f"**Assessment:** {analysis['assessment']}\n")
    if analysis["counts"]:
        parts.append("**Error Breakdown:**")
        for cat, cnt in analysis["counts"].most_common():
            info = ERROR_PATTERNS.get(cat, {})
            parts.append(f"- {cat}: {cnt} occurrence(s) | {info.get('meaning', '')}")
        parts.append("")
    if analysis["repeated"]:
        parts.append("**REPEATED FAILURES (STOP):**")
        for cat, cnt in analysis["repeated"].items():
            parts.append(f"- {cat}: {cnt}x — {ERROR_PATTERNS[cat]['action']}")
        parts.append("")
    if analysis["warnings"]:
        parts.append("**Warnings:**")
        for w in analysis["warnings"]:
            parts.append(f"- {w}")
        parts.append("")
    if not analysis["should_inject"]:
        parts.append("**MANDATORY HOLD:** Do NOT suggest a new script. " + analysis["recommendation"] + "\n")
    else:
        parts.append("**Proceed:** " + analysis["recommendation"] + "\n")
    if analysis["snippets"]:
        parts.append("**Log Snippets:**")
        for s in analysis["snippets"][:8]:
            parts.append(f"- {s}")
        parts.append("")
    return "\n".join(parts)
