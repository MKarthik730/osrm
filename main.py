import socketio
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
import os

app = FastAPI(title="LocSync API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://rotten-snails-love.loca.lt"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)

socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

OSRM_URL = os.getenv("OSRM_URL", "http://osrm:5000")

connected_users: dict[str, str] = {}
socket_to_user: dict[str, str] = {}
sharing_sessions: dict[str, set] = {}
last_locations: dict[str, dict] = {}
user_display_names: dict[str, str] = {}


class StartSharing(BaseModel):
    sharer_id: str
    watcher_id: str | None = None

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


@app.get("/api/health")
def health():
    return {"status": "ok", "osrm": OSRM_URL}


@app.get("/api/status")
def status():
    sessions_info = {k: list(v) for k, v in sharing_sessions.items()}
    return {
        "connected_users": list(connected_users.keys()),
        "active_sessions": sessions_info,
        "total_connected": len(connected_users),
        "last_locations": {
            uid: {**loc, "is_sharing": uid in sharing_sessions}
            for uid, loc in last_locations.items()
        }
    }


@app.get("/api/active-sharers")
def active_sharers():
    result = []
    for sharer_id in sharing_sessions:
        loc = last_locations.get(sharer_id)
        if loc:
            result.append({
                "user_id": sharer_id,
                "display_name": user_display_names.get(sharer_id, sharer_id),
                **loc,
                "watcher_count": len(sharing_sessions[sharer_id]),
            })
    return {"sharers": result}


@app.post("/api/start-sharing")
def start_sharing(data: StartSharing):
    if data.sharer_id not in sharing_sessions:
        sharing_sessions[data.sharer_id] = set()
    if data.watcher_id:
        sharing_sessions[data.sharer_id].add(data.watcher_id)
    return {
        "status": "ok",
        "message": f"{data.sharer_id} sharing",
        "watchers": list(sharing_sessions[data.sharer_id]),
        "broadcast": data.watcher_id is None,
    }


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

    if data.user_id not in sharing_sessions:
        return {"status": "ok", "note": "not sharing"}

    watchers = sharing_sessions[data.user_id]
    payload = {
        "userId": data.user_id,
        "displayName": user_display_names.get(data.user_id, data.user_id),
        "lat": snapped["lat"],
        "lon": snapped["lon"],
        "timestamp": last_locations[data.user_id]["timestamp"],
    }

    sent_count = 0
    if len(watchers) == 0:
        for uid, sid in connected_users.items():
            if uid != data.user_id:
                await sio.emit("location_update", payload, to=sid)
                sent_count += 1
    else:
        for watcher_id in watchers:
            watcher_socket = connected_users.get(watcher_id)
            if watcher_socket:
                await sio.emit("location_update", payload, to=watcher_socket)
                sent_count += 1

    return {"status": "ok", "sent_to": sent_count, "snapped_lat": snapped["lat"], "snapped_lon": snapped["lon"]}


@app.get("/api/last-location/{user_id}")
def get_last_location(user_id: str):
    loc = last_locations.get(user_id)
    if not loc:
        raise HTTPException(status_code=404, detail="No location on record")
    return {"user_id": user_id, **loc}


@app.post("/api/route")
async def route(data: RouteRequest):
    return await get_route(data.from_lat, data.from_lon, data.to_lat, data.to_lon)


@sio.on("connect")
async def on_connect(sid, environ, auth):
    user_id = (auth or {}).get("userId") or (auth or {}).get("user_id")
    if not user_id:
        return False

    connected_users[user_id] = sid
    socket_to_user[sid] = user_id
    display_name = (auth or {}).get("displayName", user_id)
    user_display_names[user_id] = display_name
    print(f"[WS] + {user_id} ({sid})")

    await sio.emit("user_joined", {
        "userId": user_id,
        "displayName": display_name,
        "connected_users": list(connected_users.keys()),
    })

    await sio.emit("room_state", {
        "connected_users": list(connected_users.keys()),
        "active_sharers": [
            {
                "userId": uid,
                "displayName": user_display_names.get(uid, uid),
                **last_locations[uid],
            }
            for uid in sharing_sessions
            if uid in last_locations
        ],
    }, to=sid)

    for sharer_id, watchers in sharing_sessions.items():
        should_send = (len(watchers) == 0) or (user_id in watchers)
        if should_send and sharer_id in last_locations:
            await sio.emit("location_update", {
                "userId": sharer_id,
                "displayName": user_display_names.get(sharer_id, sharer_id),
                **last_locations[sharer_id],
            }, to=sid)


@sio.on("disconnect")
async def on_disconnect(sid):
    user_id = socket_to_user.pop(sid, None)
    if user_id:
        connected_users.pop(user_id, None)
        sharing_sessions.pop(user_id, None)
        print(f"[WS] - {user_id}")
        await sio.emit("user_left", {
            "userId": user_id,
            "connected_users": list(connected_users.keys()),
        })


@sio.on("ping_location")
async def on_ping_location(sid, data):
    sharer_id = (data or {}).get("sharer_id")
    if sharer_id and sharer_id in last_locations:
        await sio.emit("location_update", {
            "userId": sharer_id,
            "displayName": user_display_names.get(sharer_id, sharer_id),
            **last_locations[sharer_id],
        }, to=sid)


FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")