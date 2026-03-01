import socketio
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
import os

# ─────────────────────────────────────────────────────────────
#  App + Socket.io
# ─────────────────────────────────────────────────────────────

app = FastAPI(title="LocSync API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)

# uvicorn serves THIS object (wraps FastAPI + socket.io)
socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

OSRM_URL = os.getenv("OSRM_URL", "http://osrm:5000")

# ─────────────────────────────────────────────────────────────
#  In-Memory State
# ─────────────────────────────────────────────────────────────

connected_users: dict[str, str] = {}   # user_id  -> socket_id
socket_to_user: dict[str, str] = {}    # socket_id -> user_id
sharing_sessions: dict[str, str] = {}  # sharer_id -> watcher_id
last_locations: dict[str, dict] = {}   # user_id  -> { lat, lon, timestamp, ... }


# ─────────────────────────────────────────────────────────────
#  Pydantic Models
# ─────────────────────────────────────────────────────────────

class StartSharing(BaseModel):
    sharer_id: str
    watcher_id: str

class StopSharing(BaseModel):
    sharer_id: str

class LocationUpdate(BaseModel):
    user_id: str
    latitude: float
    longitude: float

class RouteRequest(BaseModel):
    from_lat: float
    from_lon: float
    to_lat: float
    to_lon: float


# ─────────────────────────────────────────────────────────────
#  OSRM Helpers
# ─────────────────────────────────────────────────────────────

async def snap_to_road(lat: float, lon: float) -> dict:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OSRM_URL}/nearest/v1/driving/{lon},{lat}")
            data = r.json()
            if data.get("code") == "Ok":
                loc = data["waypoints"][0]["location"]
                return {"lat": loc[1], "lon": loc[0]}
    except Exception:
        pass
    return {"lat": lat, "lon": lon}


async def get_route(from_lat, from_lon, to_lat, to_lon) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        url = (
            f"{OSRM_URL}/route/v1/driving/"
            f"{from_lon},{from_lat};{to_lon},{to_lat}"
            f"?overview=full&geometries=geojson"
        )
        r = await client.get(url)
        data = r.json()
    if data.get("code") != "Ok":
        raise HTTPException(status_code=502, detail=f"OSRM error: {data.get('code')}")
    route = data["routes"][0]
    return {
        "distance_km": round(route["distance"] / 1000, 2),
        "duration_mins": round(route["duration"] / 60, 1),
        "geometry": route["geometry"],
    }


# ─────────────────────────────────────────────────────────────
#  REST Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "osrm": OSRM_URL}


@app.get("/api/status")
def status():
    return {
        "connected_users": list(connected_users.keys()),
        "active_sessions": sharing_sessions,
        "total_connected": len(connected_users),
    }


@app.post("/api/start-sharing")
def start_sharing(data: StartSharing):
    sharing_sessions[data.sharer_id] = data.watcher_id
    return {"status": "ok", "message": f"{data.sharer_id} sharing with {data.watcher_id}"}


@app.post("/api/stop-sharing")
def stop_sharing(data: StopSharing):
    sharing_sessions.pop(data.sharer_id, None)
    return {"status": "ok"}


@app.post("/api/share-location")
async def share_location(data: LocationUpdate):
    snapped = await snap_to_road(data.latitude, data.longitude)

    last_locations[data.user_id] = {
        "lat": snapped["lat"],
        "lon": snapped["lon"],
        "raw_lat": data.latitude,
        "raw_lon": data.longitude,
        "timestamp": datetime.utcnow().isoformat(),
    }

    watcher_id = sharing_sessions.get(data.user_id)
    if not watcher_id:
        return {"status": "ok", "note": "nobody watching"}

    watcher_socket = connected_users.get(watcher_id)
    if not watcher_socket:
        return {"status": "ok", "note": "watcher offline"}

    await sio.emit(
        "location_update",
        {
            "userId": data.user_id,
            "lat": snapped["lat"],
            "lon": snapped["lon"],
            "timestamp": last_locations[data.user_id]["timestamp"],
        },
        to=watcher_socket,
    )
    return {"status": "ok", "snapped_lat": snapped["lat"], "snapped_lon": snapped["lon"]}


@app.get("/api/last-location/{user_id}")
def get_last_location(user_id: str):
    loc = last_locations.get(user_id)
    if not loc:
        raise HTTPException(status_code=404, detail="No location on record")
    return {"user_id": user_id, **loc}


@app.post("/api/route")
async def route(data: RouteRequest):
    return await get_route(data.from_lat, data.from_lon, data.to_lat, data.to_lon)


# ─────────────────────────────────────────────────────────────
#  Socket.io Events
# ─────────────────────────────────────────────────────────────

@sio.on("connect")
async def on_connect(sid, environ, auth):
    user_id = (auth or {}).get("userId") or (auth or {}).get("user_id")
    if not user_id:
        return False  # reject

    connected_users[user_id] = sid
    socket_to_user[sid] = user_id
    print(f"[WS] + {user_id} ({sid})")

    # Replay cached location for whoever this user is watching
    for sharer_id, watcher_id in sharing_sessions.items():
        if watcher_id == user_id and sharer_id in last_locations:
            await sio.emit("location_update", {"userId": sharer_id, **last_locations[sharer_id]}, to=sid)


@sio.on("disconnect")
async def on_disconnect(sid):
    user_id = socket_to_user.pop(sid, None)
    if user_id:
        connected_users.pop(user_id, None)
        print(f"[WS] - {user_id}")


@sio.on("ping_location")
async def on_ping_location(sid, data):
    sharer_id = (data or {}).get("sharer_id")
    if sharer_id and sharer_id in last_locations:
        await sio.emit("location_update", {"userId": sharer_id, **last_locations[sharer_id]}, to=sid)


# ─────────────────────────────────────────────────────────────
#  Serve frontend (fallback if not using Nginx)
# ─────────────────────────────────────────────────────────────

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")