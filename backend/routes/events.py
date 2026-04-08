from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import asyncio
import json

from database import crud
from database.connection import get_db

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[asyncio.Queue]] = {}
    
    def connect(self, scan_id: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(queue)
        return queue
    
    def disconnect(self, scan_id: str, queue: asyncio.Queue):
        if scan_id in self.active_connections:
            if queue in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(queue)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
    
    async def broadcast(self, scan_id: str, event: dict):
        if scan_id in self.active_connections:
            # Create tasks to put events to prevent blocking
            await asyncio.gather(*[q.put(event) for q in self.active_connections[scan_id]])

manager = ConnectionManager()

@router.get("/scan/{scan_id}/stream")
async def scan_stream(scan_id: str):
    """SSE endpoint for live scan updates."""
    
    async def event_generator():
        queue = manager.connect(scan_id)
        try:
            # Send initial state
            async with get_db() as db:
                scan = await crud.get_scan(db, scan_id)
                if scan:
                    init_data = {
                        "type": "init",
                        "status": scan.status.value,
                        "progress": scan.progress
                    }
                    yield f"event: init\ndata: {json.dumps(init_data)}\n\n"
            
            # Stream updates
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    event_type = event.get("type", "message")
                    yield f"event: {event_type}\ndata: {json.dumps(event)}\n\n"
                    
                    if event.get("type") == "complete":
                        break
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
        finally:
            manager.disconnect(scan_id, queue)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
