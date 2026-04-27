# osrm — Real-Time Location Sharing

A real-time location sharing web app built with FastAPI, WebSockets (python-socketio), Leaflet.js, and the OSRM routing engine. Supports live location broadcasting between multiple users with route rendering on an interactive map.

## Features

- Live location sharing via WebSockets using python-socketio
- Interactive map powered by Leaflet.js with OpenStreetMap tiles
- Route rendering between users via the OSRM public routing API
- Multi-user session support
- Public tunnel support via Cloudflare Tunnel (`cloudflared`)
- Deployed on Render

## Project Structure

```
osrm/
├── mediflow/
│   ├── frontend/         # Leaflet.js map UI (HTML/JS)
│   ├── models/           # Data models
│   ├── backend/          # FastAPI + socketio server logic
│   ├── .gitignore
│   ├── .python-version
│   ├── package-lock.json
│   ├── pyproject.toml
│   └── README.md
├── map-view/             # OSRM map data or config files
├── void/                 # Additional module / experimental code
├── .env                  # Environment variables
├── .gitignore
├── Procfile              # Render deployment entry point
├── cloudflared.exe       # Cloudflare Tunnel binary for public URL
└── requirements.txt      # Python dependencies
```

## Tech Stack

- **Backend**: FastAPI, python-socketio, Uvicorn, httpx
- **Frontend**: Vanilla JS, Leaflet.js, OpenStreetMap
- **Routing**: OSRM (Open Source Routing Machine) public API
- **Tunneling**: Cloudflare Tunnel (`cloudflared`)
- **Deployment**: Render

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/MKarthik730/osrm.git
cd osrm
pip install -r requirements.txt
```

### Environment Variables

Copy `.env` and fill in any required values:

```bash
cp .env .env.local
```

### Run Locally

```bash
uvicorn main:socket_app --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000` in your browser and allow location access.

### Expose Publicly via Cloudflare Tunnel

```bash
./cloudflared.exe tunnel --url http://localhost:8000
```

Share the generated `*.trycloudflare.com` URL with others to start a live session.

## How It Works

1. User opens the app in a browser and grants location permission.
2. The browser sends GPS coordinates to the FastAPI backend over a WebSocket (python-socketio).
3. The server broadcasts updated coordinates to all connected clients in the session.
4. Each client plots other users as markers on the Leaflet map.
5. The OSRM API computes the road route between two points and draws it as a polyline overlay.

## Deployment (Render)

The `Procfile` defines the start command:

```
web: uvicorn main:socket_app --host 0.0.0.0 --port $PORT
```

Push to main and Render will auto-deploy.

## Dependencies

```
fastapi
uvicorn
python-socketio
httpx
python-multipart
```

## Acknowledgements

- [OSRM](http://project-osrm.org/) — Open Source Routing Machine
- [Leaflet.js](https://leafletjs.com/) — Interactive maps
- [OpenStreetMap](https://www.openstreetmap.org/) — Map tile data
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) — Public URL tunneling
