# 🗺 Live Location Sharing — OSRM + FastAPI + Leaflet.js

A real-time location sharing web app that lets users share their live GPS coordinates with others on an interactive map. Built with **FastAPI**, **python-socketio**, **Leaflet.js**, and **OSRM** for route rendering.

> Deployed on **Render** | Map tiles via **OpenStreetMap** | Routing via **OSRM**

---

## Features

- **Live location sharing** — broadcast your GPS position in real time via WebSockets
- **Interactive map** — Leaflet.js frontend with OSM tile rendering
- **WebSocket-based updates** — instant location sync across connected clients
- **OSRM routing** — compute turn-by-turn routes between locations
- **Session management** — in-memory sessions for active users
- **Render-ready** — includes `Procfile` for one-click cloud deployment

---

## Project Structure

```
osrm/
├── backend/          # FastAPI app + Socket.IO server
├── frontend/         # HTML/JS frontend (Leaflet.js map)
├── map-files/        # OSRM map data files
├── void/             # Void protocol integration (device discovery)
├── .env              # Environment variables
├── Procfile          # Render deployment config
└── requirements.txt  # Python dependencies
```

---

## Tech Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Backend   | FastAPI, python-socketio, Uvicorn   |
| Frontend  | HTML, JavaScript, Leaflet.js        |
| Routing   | OSRM (Open Source Routing Machine)  |
| Map Tiles | OpenStreetMap                       |
| Geo Tools | Google S2 / Geohash (optional)      |
| Deploy    | Render (via Procfile)               |

---

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### 1. Clone the repository

```bash
git clone https://github.com/MKarthik730/osrm.git
cd osrm
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set up environment variables

Create a `.env` file (or edit the existing one):

```env
PORT=8000
```

### 4. Run the server

```bash
uvicorn backend.main:app --reload --port 8000
```

Then open `http://localhost:8000` in your browser.

---

## How It Works

1. User opens the app and grants location permission.
2. The frontend sends GPS coordinates to the FastAPI backend via WebSocket (Socket.IO).
3. The server broadcasts updated positions to all connected clients.
4. Leaflet.js renders live markers on the OSM map.
5. OSRM calculates and draws routes between locations.

---

## Deployment (Render)

The `Procfile` configures the app for Render:

```
web: uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

Push to GitHub → connect repo on [Render](https://render.com) → deploy.

---

## OSRM Map Files

Pre-processed map files are stored in `map-files/`. To use custom map data:

1. Download a `.osm.pbf` file from [Geofabrik](https://download.geofabrik.de/)
2. Process with OSRM backend tools
3. Replace files in `map-files/`

---

## Contributing

Pull requests welcome! For major changes, open an issue first.

---

## License

MIT License © [MKarthik730](https://github.com/MKarthik730)
