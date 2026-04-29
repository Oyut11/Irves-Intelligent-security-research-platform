"""
IRVES — Network Routes: Intercept
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging
import time
import uuid
from services.network_service import network_service
from services.root_wrapper import root_wrapper
from services.ebpf_service import ebpf_service
from services.frida_service import frida_service
from services.ai_service import ai_service
from services.security_analyzer import security_analyzer
from services.ct_monitor import ct_monitor
from services.fritap_capture import fritap_service

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/intercept-rules")
async def get_intercept_rules():
    """Get all active intercept rules for the mitmproxy addon."""
    return {"status": "success", "rules": _intercept_rules}


@router.post("/intercept-rules")
async def create_intercept_rule(request: Request):
    """Create a new intercept rule."""
    try:
        rule = await request.json()
        rule["id"] = rule.get("id") or str(uuid.uuid4())
        rule["enabled"] = rule.get("enabled", True)
        rule["created_at"] = time.time()
        
        # Update existing or add new
        existing_idx = next((i for i, r in enumerate(_intercept_rules) if r.get("id") == rule["id"]), None)
        if existing_idx is not None:
            _intercept_rules[existing_idx] = rule
        else:
            _intercept_rules.append(rule)
        
        logger.info(f"[Network] Intercept rule created/updated: {rule['id']}")
        return {"status": "success", "rule": rule}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.delete("/intercept-rules/{rule_id}")
async def delete_intercept_rule(rule_id: str):
    """Delete an intercept rule."""
    global _intercept_rules
    original_len = len(_intercept_rules)
    _intercept_rules = [r for r in _intercept_rules if r.get("id") != rule_id]
    
    if len(_intercept_rules) < original_len:
        logger.info(f"[Network] Intercept rule deleted: {rule_id}")
        return {"status": "success", "message": "Rule deleted"}
    return {"status": "error", "message": "Rule not found"}


@router.post("/flow/{flow_id}/modify")
async def modify_flow(flow_id: str, request: Request):
    """Store a modified response for a flow (for replay/editing)."""
    try:
        modification = await request.json()
        
        # Get original flow
        flow = network_service.flows.get(flow_id)
        if not flow:
            return {"status": "error", "message": "Flow not found"}
        
        original_response = flow.get("response", {})
        modified_response = modification.get("response", {})
        
        # Store the modification
        _modified_flows[flow_id] = {
            "original": original_response,
            "modified": modified_response,
            "modified_at": time.time(),
            "modification_type": modification.get("type", "manual"),
        }
        
        # Generate diff
        diff = _generate_response_diff(original_response, modified_response)
        
        logger.info(f"[Network] Flow {flow_id} modified and stored for diff")
        return {
            "status": "success",
            "flow_id": flow_id,
            "diff": diff,
        }
    except Exception as e:
        logger.error(f"[Network] Flow modification error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/flow/{flow_id}/diff")
async def get_flow_diff(flow_id: str):
    """Get the diff between original and modified response for a flow."""
    try:
        flow = network_service.flows.get(flow_id)
        if not flow:
            return {"status": "error", "message": "Flow not found"}
        
        original = flow.get("original_response") or flow.get("response", {})
        
        # Check if we have a stored modification
        if flow_id in _modified_flows:
            modified = _modified_flows[flow_id]["modified"]
        else:
            modified = flow.get("response", {})
        
        diff = _generate_response_diff(original, modified)
        
        return {
            "status": "success",
            "flow_id": flow_id,
            "original": original,
            "modified": modified,
            "diff": diff,
            "has_modification": flow_id in _modified_flows,
        }
    except Exception as e:
        logger.error(f"[Network] Diff generation error: {e}")
        return {"status": "error", "message": str(e)}


def _generate_response_diff(original: dict, modified: dict) -> dict:
    """Generate a structured diff between original and modified responses."""
    import difflib
    
    diff = {
        "status_changed": original.get("status_code") != modified.get("status_code"),
        "status_diff": {
            "original": original.get("status_code"),
            "modified": modified.get("status_code"),
        },
        "headers_added": [],
        "headers_removed": [],
        "headers_modified": [],
        "body_changes": [],
        "body_diff_type": "text",
    }
    
    orig_headers = original.get("headers", {})
    mod_headers = modified.get("headers", {})
    
    # Header diff
    all_header_keys = set(orig_headers.keys()) | set(mod_headers.keys())
    for key in all_header_keys:
        if key not in orig_headers:
            diff["headers_added"].append({"key": key, "value": mod_headers[key]})
        elif key not in mod_headers:
            diff["headers_removed"].append({"key": key, "value": orig_headers[key]})
        elif orig_headers[key] != mod_headers[key]:
            diff["headers_modified"].append({
                "key": key,
                "original": orig_headers[key],
                "modified": mod_headers[key],
            })
    
    # Body diff
    orig_body = original.get("body", "")
    mod_body = modified.get("body", "")
    
    if orig_body != mod_body:
        # Try JSON diff first
        try:
            orig_json = json.loads(orig_body) if orig_body else {}
            mod_json = json.loads(mod_body) if mod_body else {}
            diff["body_changes"] = _json_diff(orig_json, mod_json)
            diff["body_diff_type"] = "json"
        except (json.JSONDecodeError, TypeError):
            # Fall back to text diff
            diff_lines = list(difflib.unified_diff(
                str(orig_body).splitlines(),
                str(mod_body).splitlines(),
                fromfile="original",
                tofile="modified",
                lineterm=""
            ))
            diff["body_changes"] = diff_lines
            diff["body_diff_type"] = "text"
    
    return diff


def _json_diff(original, modified, path: str = "") -> list:
    """Recursively diff JSON structures."""
    changes = []
    
    if isinstance(original, dict) and isinstance(modified, dict):
        for key in set(original.keys()) | set(modified.keys()):
            current_path = f"{path}.{key}" if path else key
            
            if key not in original:
                changes.append({
                    "type": "added",
                    "path": current_path,
                    "value": modified[key]
                })
            elif key not in modified:
                changes.append({
                    "type": "removed",
                    "path": current_path,
                    "value": original[key]
                })
            elif type(original[key]) != type(modified[key]):
                changes.append({
                    "type": "type_changed",
                    "path": current_path,
                    "original_type": type(original[key]).__name__,
                    "modified_type": type(modified[key]).__name__,
                    "original": original[key],
                    "modified": modified[key],
                })
            elif isinstance(original[key], dict):
                changes.extend(_json_diff(original[key], modified[key], current_path))
            elif isinstance(original[key], list):
                changes.extend(_json_array_diff(original[key], modified[key], current_path))
            elif original[key] != modified[key]:
                changes.append({
                    "type": "modified",
                    "path": current_path,
                    "original": original[key],
                    "modified": modified[key],
                })
    elif isinstance(original, list) and isinstance(modified, list):
        changes.extend(_json_array_diff(original, modified, path))
    elif original != modified:
        changes.append({
            "type": "modified",
            "path": path or "root",
            "original": original,
            "modified": modified,
        })
    
    return changes


def _json_array_diff(original: list, modified: list, path: str) -> list:
    """Diff JSON arrays."""
    changes = []
    max_len = max(len(original), len(modified))
    
    for i in range(max_len):
        item_path = f"{path}[{i}]"
        
        if i >= len(original):
            changes.append({"type": "added", "path": item_path, "value": modified[i]})
        elif i >= len(modified):
            changes.append({"type": "removed", "path": item_path, "value": original[i]})
        elif original[i] != modified[i]:
            if isinstance(original[i], dict) and isinstance(modified[i], dict):
                changes.extend(_json_diff(original[i], modified[i], item_path))
            elif isinstance(original[i], list) and isinstance(modified[i], list):
                changes.extend(_json_array_diff(original[i], modified[i], item_path))
            else:
                changes.append({
                    "type": "modified",
                    "path": item_path,
                    "original": original[i],
                    "modified": modified[i],
                })
    
