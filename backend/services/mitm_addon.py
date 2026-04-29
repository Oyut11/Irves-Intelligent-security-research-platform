"""
IRVES mitmproxy addon — runs inside the mitmdump subprocess.
On every completed HTTP/S flow it POST-s a compact JSON summary
to the IRVES FastAPI server at /internal/network/flow.

The target port is read from the IRVES_INGEST_PORT env var (default 8765).
"""

import json
import os
import re
import time
import base64
import urllib.request
import urllib.error

INGEST_PORT = int(os.environ.get("IRVES_INGEST_PORT", "8765"))
INGEST_URL = f"http://127.0.0.1:{INGEST_PORT}/api/network/internal/flow"

# Known secrets patterns for passive scanning
SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token": r"xoxp-[0-9A-Za-z\-]+",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "JWT Token": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
}

# SSL Pinning detection indicators
PINNING_INDICATORS = [
    "certificate pinning",
    "ssl pinning",
    "trustmanager",
    "x509trustmanager",
    "pinningtrustmanager",
    "certificatepinner",
    "okhostnameverifier",
    "networksecurityconfig",
]

# Common SSL pinning error patterns
PINNING_ERROR_PATTERNS = [
    r"certificate verify failed",
    r"ssl handshake failed",
    r"unable to get local issuer certificate",
    r"self signed certificate in certificate chain",
    r"certificate pinning",
    r"pin mismatch",
    r"pin verification failed",
    r"untrusted certificate",
    r"sslpeerunverifiedException",
    r"certificatepinningexception",
]


def _safe_decode(content, limit: int = 65536) -> str:
    if not content:
        return ""
    try:
        return content[:limit].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _detect_secrets(text: str) -> list:
    found = []
    for name, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            found.append(name)
    return found


def _detect_pinning_error(error_msg: str) -> dict:
    """Analyze SSL errors to detect certificate pinning."""
    if not error_msg:
        return {"is_pinning_error": False}
    
    msg_lower = error_msg.lower()
    detected_indicators = []
    
    for indicator in PINNING_INDICATORS:
        if indicator in msg_lower:
            detected_indicators.append(indicator)
    
    is_pinning = False
    confidence = "low"
    
    for pattern in PINNING_ERROR_PATTERNS:
        if re.search(pattern, msg_lower):
            is_pinning = True
            confidence = "high" if detected_indicators else "medium"
            break
    
    return {
        "is_pinning_error": is_pinning,
        "confidence": confidence,
        "indicators": detected_indicators,
        "error_message": error_msg[:200],
    }


class IRVESAddon:
    def __init__(self):
        self.original_responses = {}  # Store originals for diff comparison
        self.intercept_rules = []     # Rules loaded from IRVES backend
        self.modified_flows = {}      # Track which flows were modified
    
    def load_intercept_rules(self):
        """Fetch intercept rules from IRVES backend."""
        try:
            url = f"http://127.0.0.1:{INGEST_PORT}/api/network/intercept-rules"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    self.intercept_rules = data.get("rules", [])
        except Exception:
            pass  # Silent fail - rules will be empty
    
    def _match_intercept_rule(self, flow):
        """Check if flow matches any intercept rule."""
        if not self.intercept_rules:
            return None
        
        url = flow.request.pretty_url
        method = flow.request.method
        
        for rule in self.intercept_rules:
            if rule.get("enabled", False) is False:
                continue
            
            # Check method match
            methods = rule.get("methods", ["*"])
            if "*" not in methods and method not in methods:
                continue
            
            # Check URL pattern match
            patterns = rule.get("url_patterns", [])
            for pattern in patterns:
                try:
                    if re.search(pattern, url):
                        return rule
                except re.error:
                    continue
        
        return None
    
    def response(self, flow):
        try:
            req = flow.request
            resp = flow.response

            req_body = _safe_decode(req.content)
            resp_body = _safe_decode(resp.content if resp else None)

            # Passive secret scanning
            secrets = _detect_secrets(req_body) + _detect_secrets(resp_body)
            auth_header = req.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                secrets.append("Bearer Token (captured)")

            # Check if this flow was modified
            flow_id = str(flow.id)
            is_modified = flow_id in self.modified_flows
            
            # Get original response if modified
            original_response = None
            if is_modified and flow_id in self.original_responses:
                original_response = self.original_responses[flow_id]

            # Check for intercept rule match (for UI indication)
            matched_rule = self._match_intercept_rule(flow)
            intercept_match = matched_rule is not None
            
            # Detect WebSocket upgrade
            is_websocket = False
            upgrade_header = req.headers.get("Upgrade", "").lower()
            connection_header = req.headers.get("Connection", "").lower()
            if upgrade_header == "websocket" or "upgrade" in connection_header:
                is_websocket = True
            
            # Detect gRPC
            is_grpc = False
            content_type = resp.headers.get("Content-Type", "") if resp else ""
            if any(ct in content_type for ct in ["application/grpc", "application/grpc+", "grpc-web"]):
                is_grpc = True
            
            # Detect protobuf in request body
            is_protobuf = False
            if req_body and not req_body.isprintable():
                # Simple heuristic: high ratio of non-printable chars suggests binary/protobuf
                non_printable = sum(1 for c in req_body if ord(c) < 32 and c not in '\n\r\t')
                if len(req_body) > 0 and non_printable / len(req_body) > 0.3:
                    is_protobuf = True

            payload = {
                "id": flow_id,
                "method": req.method,
                "host": req.host,
                "path": req.path,
                "url": req.pretty_url,
                "status_code": resp.status_code if resp else 0,
                "content_length": len(resp.content) if resp and resp.content else 0,
                "timestamp": req.timestamp_start,
                "request": {
                    "method": req.method,
                    "url": req.pretty_url,
                    "headers": dict(req.headers),
                    "body": req_body,
                },
                "response": {
                    "status_code": resp.status_code if resp else 0,
                    "headers": dict(resp.headers) if resp else {},
                    "body": resp_body,
                },
                "secrets": secrets,
                "is_modified": is_modified,
                "intercept_match": intercept_match,
                "matched_rule_id": matched_rule.get("id") if matched_rule else None,
                "is_websocket": is_websocket,
                "is_grpc": is_grpc,
                "is_protobuf": is_protobuf,
                "protocol_type": "websocket" if is_websocket else ("grpc" if is_grpc else "http"),
            }
            
            # Include original response for diff if modified
            if original_response:
                payload["original_response"] = original_response

            data = json.dumps(payload).encode("utf-8")
            req_obj = urllib.request.Request(
                INGEST_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req_obj, timeout=2)
        except urllib.error.URLError:
            pass  # IRVES server not yet ready — silently skip
        except Exception as e:
            print(f"[IRVES addon] Error: {e}")

    def websocket_start(self, flow):
        """Called when WebSocket connection starts."""
        try:
            req = flow.request
            payload = {
                "id": str(flow.id),
                "type": "websocket_start",
                "method": req.method,
                "host": req.host,
                "path": req.path,
                "url": req.pretty_url,
                "headers": dict(req.headers),
                "timestamp": req.timestamp_start,
                "is_websocket": True,
            }
            
            data = json.dumps(payload).encode("utf-8")
            req_obj = urllib.request.Request(
                INGEST_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req_obj, timeout=2)
        except Exception:
            pass

    def websocket_message(self, flow):
        """Called for each WebSocket message."""
        try:
            message = flow.message
            if not message:
                return
            
            # Decode content
            content = message.content
            text_content = ""
            is_binary = False
            
            try:
                text_content = content.decode("utf-8", errors="replace")
            except:
                is_binary = True
                text_content = base64.b64encode(content).decode()[:500] if content else ""
            
            payload = {
                "id": str(flow.id),
                "type": "websocket_message",
                "direction": "from_client" if message.from_client else "from_server",
                "content": text_content[:1000],  # Limit size
                "is_text": not is_binary and message.is_text,
                "is_binary": is_binary,
                "timestamp": time.time(),
                "is_websocket": True,
                "message_length": len(content) if content else 0,
            }
            
            data = json.dumps(payload).encode("utf-8")
            req_obj = urllib.request.Request(
                INGEST_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req_obj, timeout=2)
        except Exception:
            pass

    def websocket_end(self, flow):
        """Called when WebSocket closes."""
        try:
            payload = {
                "id": str(flow.id),
                "type": "websocket_end",
                "timestamp": time.time(),
                "is_websocket": True,
            }
            
            data = json.dumps(payload).encode("utf-8")
            req_obj = urllib.request.Request(
                INGEST_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req_obj, timeout=2)
        except Exception:
            pass

    def error(self, flow):
        """Catches broken requests (e.g. SSL Pinning failures, dropped connections)"""
        try:
            req = flow.request
            msg = flow.error.msg if flow.error else "Unknown Error"
            
            pinning_info = _detect_pinning_error(msg)

            payload = {
                "id": str(flow.id),
                "method": req.method,
                "host": req.host,
                "path": req.path,
                "url": req.pretty_url,
                "status_code": 0,
                "content_length": 0,
                "timestamp": req.timestamp_start,
                "request": {
                    "method": req.method,
                    "url": req.pretty_url,
                    "headers": dict(req.headers),
                    "body": "",
                },
                "response": {
                    "status_code": 0,
                    "headers": {},
                    "body": f"PROXY ERROR: {msg}",
                },
                "secrets": ["SSL/Connection Error"],
                "error_type": "ssl_pinning" if pinning_info["is_pinning_error"] else "connection",
                "pinning_detected": pinning_info["is_pinning_error"],
                "pinning_confidence": pinning_info.get("confidence"),
                "pinning_indicators": pinning_info.get("indicators", []),
            }

            data = json.dumps(payload).encode("utf-8")
            req_obj = urllib.request.Request(
                INGEST_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req_obj, timeout=2)
        except urllib.error.URLError:
            pass
        except Exception as e:
            print(f"[IRVES addon] Error in error hook: {e}")


addons = [IRVESAddon()]
