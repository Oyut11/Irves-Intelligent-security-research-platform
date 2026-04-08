"""
IRVES — mitmproxy Runner
HTTP/HTTPS traffic interception and analysis.
"""

import asyncio
import json
import socket
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List
import logging
import shutil
import time

from services.tool_runner import ToolRunner, ToolResult
from config import settings

logger = logging.getLogger(__name__)


# Default mitmproxy script for capturing traffic
DEFAULT_CAPTURE_SCRIPT = """
from mitmproxy import ctx, http, tcp
import json
import time

class TrafficCapture:
    def __init__(self):
        self.flows = []
        self.start_time = time.time()

    def request(self, flow: http.HTTPFlow) -> None:
        # Capture request details
        entry = {
            "type": "request",
            "timestamp": time.time() - self.start_time,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "content_length": len(flow.request.content) if flow.request.content else 0,
            "content_type": flow.request.headers.get("Content-Type", ""),
        }

        # Capture body for non-binary content
        if flow.request.content:
            try:
                content = flow.request.content.decode('utf-8', errors='replace')
                if len(content) < 10000:  # Limit captured size
                    entry["body"] = content
            except:
                entry["body_binary"] = True

        self.flows.append(entry)
        ctx.log(f"[IRVES] REQUEST: {flow.request.method} {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Update last entry with response
        if self.flows:
            entry = self.flows[-1]
            entry["response"] = {
                "status_code": flow.response.status_code,
                "reason": flow.response.reason,
                "headers": dict(flow.response.headers),
                "content_length": len(flow.response.content) if flow.response.content else 0,
                "content_type": flow.response.headers.get("Content-Type", ""),
            }

            # Capture response body
            if flow.response.content:
                try:
                    content = flow.response.content.decode('utf-8', errors='replace')
                    if len(content) < 50000:  # Limit captured size
                        entry["response"]["body"] = content
                except:
                    entry["response"]["body_binary"] = True

            ctx.log(f"[IRVES] RESPONSE: {flow.response.status_code} ({len(flow.response.content)} bytes)")

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        # Capture TCP messages
        message = flow.messages[-1]
        entry = {
            "type": "tcp",
            "timestamp": time.time() - self.start_time,
            "from_client": message.from_client,
            "content": message.content.decode('utf-8', errors='replace')[:1000],
        }
        self.flows.append(entry)
        ctx.log(f"[IRVES] TCP: {len(message.content)} bytes from {'client' if message.from_client else 'server'}")

addons = [TrafficCapture()]
"""

# Script for detecting sensitive data in traffic
SENSITIVE_DATA_SCRIPT = """
from mitmproxy import ctx, http
import re
import json

class SensitiveDataDetector:
    def __init__(self):
        self.findings = []
        self.patterns = {
            "api_key": [
                r"(api[_-]?key|apikey)[\"']?\\s*[=:\"']\\s*[\"']?[a-zA-Z0-9_-]{20,}",
                r"Bearer\\s+[a-zA-Z0-9_-]{20,}",
            ],
            "token": [
                r"(token|auth|jwt)[\"']?\\s*[=:\"']\\s*[\"']?[a-zA-Z0-9_.-]{20,}",
                r"Authorization:\\s*Bearer\\s+[a-zA-Z0-9_.-]+",
            ],
            "password": [
                r"(password|passwd|pwd)[\"']?\\s*[=:\"']\\s*[\"'][^\"']+[\"']",
            ],
            "credit_card": [
                r"\\b[0-9]{13,16}\\b",
            ],
            "email": [
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            ],
            "phone": [
                r"\\+?[1-9][0-9]{6,14}",
            ],
            "ssn": [
                r"\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b",
            ],
        }

    def check_content(self, content: str, context: str, flow: http.HTTPFlow) -> None:
        if not content:
            return

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    finding = {
                        "category": category,
                        "context": context,
                        "url": flow.request.pretty_url,
                        "method": flow.request.method,
                        "matches": matches[:5],  # Limit to first 5
                    }
                    self.findings.append(finding)
                    ctx.log(f"[IRVES] SENSITIVE: {category} found in {context}")

    def request(self, flow: http.HTTPFlow) -> None:
        # Check request headers
        self.check_content(str(flow.request.headers), "request_headers", flow)
        # Check request body
        if flow.request.content:
            try:
                self.check_content(flow.request.content.decode('utf-8', errors='replace'), "request_body", flow)
            except:
                pass

    def response(self, flow: http.HTTPFlow) -> None:
        # Check response headers
        self.check_content(str(flow.response.headers), "response_headers", flow)
        # Check response body
        if flow.response.content:
            try:
                self.check_content(flow.response.content.decode('utf-8', errors='replace'), "response_body", flow)
            except:
                pass

    def done(self) -> None:
        # Output findings as JSON
        if self.findings:
            ctx.log(f"[IRVES] SENSITIVE DATA SUMMARY:")
            ctx.log(json.dumps(self.findings, indent=2))

addons = [SensitiveDataDetector()]
"""


class MitmproxyRunner(ToolRunner):
    """
    mitmproxy runner for traffic interception and analysis.

    Supports:
    - HTTP/HTTPS traffic capture
    - Sensitive data detection
    - Custom flow scripts
    - Certificate management
    """

    def __init__(self):
        super().__init__()
        self._proxy_process: Optional[asyncio.subprocess.Process] = None
        self._port = 8080
        self._web_port = 8081

    @property
    def name(self) -> str:
        return "mitmproxy"

    async def run(
        self,
        target: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
        port: int = 8080,
        web_port: Optional[int] = None,
        capture_duration: int = 60,
        script: str = "capture",
        target_app: Optional[str] = None,
    ) -> ToolResult:
        """
        Run mitmproxy to capture traffic.

        Args:
            target: Path to APK (for reference/metadata)
            output_dir: Directory for output
            port: Proxy port (default 8080)
            web_port: Web interface port (optional)
            capture_duration: Duration to capture in seconds
            script: Script to use: "capture", "sensitive", or path to custom script
            target_app: Optional app package to filter

        Returns:
            ToolResult with captured traffic
        """
        self._port = port
        self._web_port = web_port or 8081

        if not shutil.which("mitmproxy") and not shutil.which("mitmdump"):
            return ToolResult(
                success=False,
                output="",
                error="mitmproxy not found. Install with: pip install mitmproxy",
                duration_ms=0,
            )

        output_path = self._ensure_output_dir(output_dir / "mitmproxy")
        capture_file = output_path / "capture.json"
        flows_file = output_path / "flows.txt"

        # Determine script to use
        script_content = self._get_script(script)

        # Write script file
        script_file = output_path / "addon.py"
        with open(script_file, "w") as f:
            f.write(script_content)

        if progress_callback:
            progress_callback(f"Starting mitmproxy on port {port}...")

        try:
            # Use mitmdump for headless operation
            cmd = [
                "mitmdump",
                "-p", str(port),
                "-s", str(script_file),
                "--set",
                f"hardump={capture_file}",
                "-q",  # Quiet mode
            ]

            if target_app:
                # Add app filter if specified
                cmd.extend(["--set", f"filter=dns:{target_app}"])

            self._start_time = time.time()

            # Run mitmdump
            self._proxy_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if progress_callback:
                progress_callback(f"Proxy started on 127.0.0.1:{port}")
                progress_callback(f"Configure client to use this proxy")
                progress_callback(f"Certificate: ~/.mitmproxy/mitmproxy-ca-cert.pem")
                progress_callback(f"Capturing for {capture_duration} seconds...")

            # Capture output for duration
            stdout_chunks = []
            stderr_chunks = []

            async def read_output(
                stream: asyncio.StreamReader,
                chunks: List[str],
                callback: Optional[Callable],
            ):
                while True:
                    try:
                        line = await stream.readline()
                        if not line:
                            break
                        decoded = line.decode("utf-8", errors="replace").strip()
                        chunks.append(decoded)
                        if callback and decoded:
                            callback(decoded)
                    except Exception:
                        break

            # Run for specified duration
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        read_output(self._proxy_process.stdout, stdout_chunks, progress_callback),
                        read_output(self._proxy_process.stderr, stderr_chunks, None),
                    ),
                    timeout=capture_duration,
                )
            except asyncio.TimeoutError:
                # Expected - capture duration reached
                pass

            # Stop the proxy
            await self.cancel()

            duration_ms = self._elapsed_ms()

            # Read captured flows
            captured_flows = []
            if capture_file.exists():
                try:
                    with open(capture_file, "r") as f:
                        content = f.read()
                        if content.strip():
                            # Try to parse as JSON lines
                            for line in content.strip().split("\n"):
                                if line.strip():
                                    try:
                                        captured_flows.append(json.loads(line))
                                    except json.JSONDecodeError:
                                        pass
                except Exception as e:
                    logger.warning(f"[{self.name}] Could not read capture file: {e}")

            # Parse findings from output
            findings = self._parse_findings(stderr_chunks + stdout_chunks)

            # Save flows log
            with open(flows_file, "w") as f:
                f.write("\n".join(stdout_chunks))

            # Generate summary
            summary = {
                "flows_captured": len(captured_flows),
                "findings_count": len(findings),
                "duration_seconds": capture_duration,
                "port": port,
            }

            # Save summary
            summary_file = output_path / "summary.json"
            with open(summary_file, "w") as f:
                json.dump(summary, f, indent=2)

            if progress_callback:
                progress_callback(f"Captured {len(captured_flows)} flows")
                progress_callback(f"Found {len(findings)} potential issues")

            return ToolResult(
                success=True,
                output=json.dumps(captured_flows, indent=2),
                error="",
                duration_ms=duration_ms,
                artifacts_path=output_path,
                findings_count=len(findings),
                metrics=summary,
            )

        except Exception as e:
            logger.exception(f"[{self.name}] Error during execution")
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                duration_ms=self._elapsed_ms(),
            )
        finally:
            await self.cancel()

    def _get_script(self, script: str) -> str:
        """Get script content based on selection."""
        if script == "capture":
            return DEFAULT_CAPTURE_SCRIPT
        elif script == "sensitive":
            return SENSITIVE_DATA_SCRIPT
        elif Path(script).exists():
            return Path(script).read_text()
        else:
            # Default to capture
            return DEFAULT_CAPTURE_SCRIPT

    def _parse_findings(self, output_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse findings from mitmproxy output."""
        findings = []

        for line in output_lines:
            # Look for SENSITIVE markers
            if "[IRVES] SENSITIVE:" in line:
                findings.append({
                    "type": "sensitive_data",
                    "message": line,
                    "source": "mitmproxy",
                })
            # Look for error conditions
            elif "error" in line.lower() or "exception" in line.lower():
                findings.append({
                    "type": "error",
                    "message": line,
                    "source": "mitmproxy",
                })

        return findings

    async def cancel(self) -> None:
        """Stop the mitmproxy process."""
        if self._proxy_process:
            try:
                self._proxy_process.terminate()
                await asyncio.wait_for(self._proxy_process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._proxy_process.kill()
                await self._proxy_process.wait()
            except ProcessLookupError:
                pass
            finally:
                self._proxy_process = None

    async def _get_version(self) -> Optional[str]:
        """Get mitmproxy version."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "mitmproxy",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            # Version is typically on first line
            return stdout.decode().strip().split("\n")[0]
        except Exception:
            return None

    async def check_certificate_status(self) -> Dict[str, Any]:
        """Check mitmproxy CA certificate status."""
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        cert_installed = cert_path.exists()

        return {
            "certificate_exists": cert_installed,
            "certificate_path": str(cert_path) if cert_installed else None,
            "instructions": (
                "Run 'mitmproxy' once to generate certificates, "
                "then install ~/.mitmproxy/mitmproxy-ca-cert.pem on the target device"
                if not cert_installed
                else "Certificate available at ~/.mitmproxy/"
            ),
        }

    async def get_intercept_setup_instructions(self, platform: str = "android") -> Dict[str, Any]:
        """Get platform-specific setup instructions."""
        instructions = {
            "android": {
                "wifi_proxy": "Settings > Wi-Fi > Long press network > Modify > Advanced > Proxy",
                "proxy_host": "127.0.0.1 (or host IP)",
                "proxy_port": str(self._port),
                "certificate": "Install mitmproxy-ca-cert.cer from device browser at mitm.it",
                "adb_reverse": f"adb reverse tcp:{self._port} tcp:{self._port}",
            },
            "ios": {
                "wifi_proxy": "Settings > Wi-Fi > Network > Configure Proxy > Manual",
                "proxy_host": "Host machine IP",
                "proxy_port": str(self._port),
                "certificate": "Install profile from mitm.it, then Settings > General > About > Certificate Trust Settings",
            },
        }

        return instructions.get(platform, instructions["android"])


class MitmproxyScript:
    """Helper class to generate custom mitmproxy scripts."""

    @staticmethod
    def generate_api_intercept_script(api_host: str) -> str:
        """Generate a script to intercept specific API host."""
        return f"""
from mitmproxy import ctx, http
import json

class APIInterceptor:
    def __init__(self):
        self.api_host = "{api_host}"
        self.flows = []

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.host == self.api_host:
            ctx.log(f"[IRVES] API Request: {{flow.request.method}} {{flow.request.path}}")

            # Log headers
            headers = dict(flow.request.headers)
            if "Authorization" in headers:
                ctx.log(f"[IRVES] Auth header: {{headers['Authorization'][:20]}}...")

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.host == self.api_host:
            ctx.log(f"[IRVES] API Response: {{flow.response.status_code}}")

            # Try to parse JSON response
            try:
                if flow.response.headers.get("Content-Type", "").startswith("application/json"):
                    data = json.loads(flow.response.content)
                    ctx.log(f"[IRVES] Response data: {{json.dumps(data)[:200]}}...")
            except:
                pass

addons = [APIInterceptor()]
"""

    @staticmethod
    def generate_websocket_capture_script() -> str:
        """Generate a script to capture WebSocket traffic."""
        return """
from mitmproxy import ctx, websocket
import json

class WebSocketCapture:
    def __init__(self):
        self.messages = []

    def websocket_message(self, flow: websocket.WebSocketFlow) -> None:
        message = flow.messages[-1]
        entry = {
            "from_client": message.from_client,
            "content": message.content.decode('utf-8', errors='replace')[:1000],
            "type": message.type,
        }
        self.messages.append(entry)
        ctx.log(f"[IRVES] WS {'Client' if message.from_client else 'Server'}: {entry['content'][:100]}")

addons = [WebSocketCapture()]
"""