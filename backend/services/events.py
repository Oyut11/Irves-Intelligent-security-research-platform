import asyncio
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class EventBus:
    """
    Intelligent Event Bus for real-time scan updates.
    Handles SSE connection management and multi-stage event fan-out.
    """
    def __init__(self):
        # scan_id -> list of subscriber queues
        self.subscribers: Dict[str, List[asyncio.Queue]] = {}

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Create a new subscription queue for a scan."""
        queue = asyncio.Queue()
        if scan_id not in self.subscribers:
            self.subscribers[scan_id] = []
        self.subscribers[scan_id].append(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue):
        """Clean up a subscription."""
        if scan_id in self.subscribers:
            if queue in self.subscribers[scan_id]:
                self.subscribers[scan_id].remove(queue)
            if not self.subscribers[scan_id]:
                del self.subscribers[scan_id]

    async def emit(self, scan_id: str, event_type: str, data: Dict[str, Any]):
        """
        Broadcast an event to all subscribers of a scan.
        Automatically wraps data with the event type.
        """
        if scan_id not in self.subscribers:
            return

        payload = {
            "type": event_type,
            **data
        }

        # Fan-out to all queues
        # We use gather to ensure all subscribers get the message without one blocking the others
        queues = self.subscribers[scan_id]
        if not queues:
            return

        await asyncio.gather(
            *[q.put(payload) for q in queues],
            return_exceptions=True
        )

# Global singleton
event_bus = EventBus()
