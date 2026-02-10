import json
import logging

from fastapi import WebSocket, WebSocketDisconnect, APIRouter

log = logging.getLogger(__name__)
ws_router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections and broadcasts messages to all clients."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        log.info("ws client connected (%d total)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        log.info("ws client disconnected (%d total)", len(self.active_connections))

    async def broadcast(self, data: dict) -> None:
        disconnected: list[WebSocket] = []
        for conn in self.active_connections:
            try:
                await conn.send_json(data)
            except Exception:
                disconnected.append(conn)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@ws_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            # Parse incoming messages for intercept decisions
            try:
                msg = json.loads(raw)
                if msg.get("type") == "intercept_decision":
                    from api.routes import get_intercept_state

                    state = get_intercept_state()
                    if state:
                        ok = state.resolve(
                            msg.get("flow_id"),
                            msg.get("decision", "forward"),
                            msg.get("modifications"),
                        )
                        if not ok:
                            log.warning("intercept resolve failed for flow_id=%s", msg.get("flow_id"))
            except json.JSONDecodeError:
                pass  # keep-alive or malformed
            except Exception:
                log.exception("error handling WS message")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
