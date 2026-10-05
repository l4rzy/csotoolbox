# Architecture

CSO Toolbox has two processes with separate responsibilities.

## Desktop client

The Avalonia client runs on Windows and Linux. It extracts indicators from user input, clipboard text, and selected report content. It stores preferences and analysis history on the local machine. `Client/Lib/CsoWorker.cs` sends service requests to the configured backend and parses the returned response models.

## Python server

The FastAPI application in `Server/app.py` exposes health, update, and analysis routes. Service implementations in `Server/services/` perform upstream lookups. Shared HTTP, DNS, cache, API key rotation, GeoIP, and response helpers live in `Server/infrastructure/`.

The server API requires the CSO Toolbox client user agent and applies request size and rate limits. These controls are not user authentication; deploy the service behind appropriate network controls and only expose it to intended clients.

## Request flow

1. The client classifies an indicator and selects an analyzer.
2. The client posts the query to its configured server over HTTPS.
3. The server validates and dispatches the request to a service.
4. The service may send the indicator to an external provider.
5. The server returns a normalized response for the client to render.

## Data files

- `Server/data/ipdb.csv` contains generic example private network ranges. Replace them with ranges you are authorized to document.
- `Server/data/config.example.yaml` documents server credential configuration. The active `config.yaml`, TLS keys, certificates, and downloaded GeoIP databases are local deployment files and are ignored by Git.

The repository does not include generated server bundles or release packages. Build those for a release after configuring the deployment and reviewing the release contents.
