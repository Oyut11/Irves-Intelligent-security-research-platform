"""
IRVES — Network Proxy Routes
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json
import asyncio
import logging
from services.network_service import network_service

logger = logging.getLogger(__name__)

router = APIRouter()

@router.on_event("startup")
async def startup_event():
    # Start the proxy server automatically on startup
    await network_service.start()

@router.on_event("shutdown")
async def shutdown_event():
    await network_service.stop()

@router.post("/proxy/enable/{serial}")
async def enable_proxy(serial: str):
    """Command ADB to route traffic to the proxy."""
    try:
        proc1 = await asyncio.create_subprocess_shell(
            f"adb -s {serial} reverse tcp:8080 tcp:8080",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc1.communicate()
        
        proc2 = await asyncio.create_subprocess_shell(
            f"adb -s {serial} shell settings put global http_proxy 127.0.0.1:8080",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc2.communicate()
        return {"status": "success", "message": "Proxy enabled via ADB reverse."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/proxy/disable/{serial}")
async def disable_proxy(serial: str):
    """Remove ADB proxy settings."""
    try:
        proc1 = await asyncio.create_subprocess_shell(
            f"adb -s {serial} shell settings put global http_proxy :0",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc1.communicate()
        
        proc2 = await asyncio.create_subprocess_shell(
            f"adb -s {serial} reverse --remove tcp:8080",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc2.communicate()
        return {"status": "success", "message": "Proxy disabled."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/flow/{flow_id}")
async def get_flow(flow_id: str):
    """Retrieve full headers and body for a specific flow."""
    flow = network_service.flows.get(flow_id)
    if not flow:
        return {"status": "error", "message": "Flow not found"}
        
    req_headers = dict(flow.request.headers)
    res_headers = dict(flow.response.headers) if flow.response else {}
    
    req_content = ""
    try: req_content = flow.request.content.decode('utf-8', errors='replace') if flow.request.content else ""
    except: pass
    
    res_content = ""
    try: res_content = flow.response.content.decode('utf-8', errors='replace') if flow.response and flow.response.content else ""
    except: pass

    return {
        "status": "success",
        "request": {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": req_headers,
            "content": req_content
        },
        "response": {
            "status_code": flow.response.status_code if flow.response else 0,
            "headers": res_headers,
            "content": res_content
        }
    }

@router.post("/replay")
async def replay_request(data: dict):
    """Simple repeater to replay a manually modified request via httpx."""
    import httpx
    try:
        url = data.get("url")
        if not url: return {"status": "error", "message": "URL missing"}
        method = data.get("method", "GET")
        headers = data.get("headers", {})
        content = data.get("content", "")
        
        # Don't send host header directly if it conflicts with httpx logic, httpx sets it from URL
        filtered_headers = {k: v for k, v in headers.items() if k.lower() not in ('host', 'content-length', 'accept-encoding')}
        
        async with httpx.AsyncClient(verify=False) as client:
            res = await client.request(
                method=method,
                url=url,
                headers=filtered_headers,
                content=content.encode('utf-8') if content else None
            )
            
            return {
                "status": "success",
                "response": {
                    "status_code": res.status_code,
                    "headers": dict(res.headers),
                    "content": res.text
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.websocket("/ws")
async def network_websocket(websocket: WebSocket):
    """Stream live proxy traffic."""
    await websocket.accept()
    
    # Store queue for this connection
    queue = asyncio.Queue()
    
    async def proxy_listener(data):
        await queue.put(data)
        
    network_service.add_listener(proxy_listener)
    
    try:
        while True:
            # Send initial message to confirm connection
            data = await queue.get()
            await websocket.send_json({"type": "request", "data": data})
    except WebSocketDisconnect:
        logger.info("Proxy websocket disconnected")
    except Exception as e:
        logger.error(f"Proxy websocket error: {e}")
    finally:
        network_service.remove_listener(proxy_listener)
