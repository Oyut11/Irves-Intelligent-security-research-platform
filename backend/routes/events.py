from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import asyncio
import json

from database import crud
from database.connection import get_db
from services.events import event_bus

router = APIRouter()

@router.get("/scan/{scan_id}/stream")
async def scan_stream(scan_id: str):
    """SSE endpoint for live scan updates."""
    
    async def event_generator():
        # Subscribe to the global bus
        queue = event_bus.subscribe(scan_id)
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
            event_bus.unsubscribe(scan_id, queue)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
