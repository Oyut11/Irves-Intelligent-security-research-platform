import asyncio
import logging
import json
from mitmproxy import options, master
from mitmproxy.addons import core

logger = logging.getLogger(__name__)

class InterceptorApp:
    """Mitmproxy addon to capture HTTP traffic."""
    def __init__(self, callback, flow_cache):
        self.callback = callback
        self.flow_cache = flow_cache

    def response(self, flow):
        fid = str(flow.id)
        self.flow_cache[fid] = flow
        # Cap memory usage
        if len(self.flow_cache) > 2000:
            self.flow_cache.pop(next(iter(self.flow_cache)))

        # Notify callback immediately upon receiving a response
        data = {
            "id": fid,
            "method": flow.request.method,
            "host": flow.request.host,
            "path": flow.request.path,
            "url": flow.request.pretty_url,
            "status_code": flow.response.status_code if flow.response else 0,
            "content_length": len(flow.response.content) if flow.response and flow.response.content else 0,
            "timestamp": flow.request.timestamp_start
        }
        self.callback(data)
        
        # Phase 4: Scanner Synergy - Passive analysis
        asyncio.create_task(self.passive_scan(flow))
        
    async def passive_scan(self, flow):
        # Basic passive heuristic scanning for leaked tokens
        import re
        try:
            req_content = flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else ""
            res_content = flow.response.content.decode('utf-8', errors='ignore') if flow.response and flow.response.content else ""
            
            # Simple Bearer token detection
            auth_header = flow.request.headers.get("Authorization", "")
            if "Bearer " in auth_header:
                logger.warning(f"[NetworkScanner] Captured Bearer Token to {flow.request.host}")
                
            # Regex for Google API Key or similar
            patterns = {
                "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
                "AWS Access Key": r'AKIA[0-9A-Z]{16}',
                "Stripe Key": r'sk_live_[0-9a-zA-Z]{24}',
                "Slack Token": r'xoxp-[0-9A-Za-z\-]+'
            }
            
            for provider, pattern in patterns.items():
                if re.search(pattern, req_content) or re.search(pattern, res_content):
                    logger.warning(f"🚨 [NetworkScanner] CRITICAL LEAK: Found {provider} in traffic! Host: {flow.request.host}")
                    # Could log to database as a Finding here
        except Exception as e:
            logger.error(f"Passive scan error: {e}")

class NetworkService:
    def __init__(self):
        self.listeners = []
        self.flows = {}
        self.m = None
        self.port = 8080
        self.is_running = False
        
    def add_listener(self, listener):
        self.listeners.append(listener)
        
    def remove_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def _on_request(self, data):
        for listener in self.listeners:
            try:
                # Dispatch async if it's a coroutine, or just call if sync
                if asyncio.iscoroutinefunction(listener):
                    asyncio.create_task(listener(data))
                else:
                    listener(data)
            except Exception as e:
                logger.error(f"Error in proxy listener: {e}")
                
    async def start(self, host="0.0.0.0", port=8080):
        if self.is_running:
            return
        self.port = port
        opts = options.Options(listen_host=host, listen_port=port)
        
        # mitigate asyncio collision by instantiating Master safely
        self.m = master.Master(opts)
        # Avoid standard addons that interfere with terminal UI, just load core
        # self.m.addons.add(*mitmproxy.addons.default_addons()) 
        # Using a stripped down addon list
        from mitmproxy.addons import core, proxyserver
        self.m.addons.add(core.Core())
        self.m.addons.add(proxyserver.Proxyserver())
        self.m.addons.add(InterceptorApp(self._on_request, self.flows))
        
        logger.info(f"Starting Network Proxy on {host}:{port}")
        self.is_running = True
        
        async def run_server():
            try:
                await self.m.run()
            except Exception as e:
                logger.error(f"Proxy stopped: {e}")
            finally:
                self.is_running = False

        self._task = asyncio.create_task(run_server())

    async def stop(self):
        if self.m and self.is_running:
            self.m.shutdown()
            self.is_running = False

network_service = NetworkService()
