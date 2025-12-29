# HIBP Password Checker Server

HTTP server for checking if password hashes exist in the HaveIBeenPwned database.

## Quick Start

### Option 1: Download on Startup (Recommended)

```bash
# Download tiny dataset on startup (~2 seconds)
HIBP_DOWNLOAD_ON_START=tiny cargo run --release

# Or sample dataset (~5 minutes, recommended for production)
HIBP_DOWNLOAD_ON_START=sample cargo run --release
```

### Option 2: Load from Local Files

```bash
# First, download data using the CLI tool
cd ../hibp
cargo run --features cli -- tiny ../data/ranges

# Then start the server
cd ../server
HIBP_DATA_DIR=../data/ranges cargo run --release
```

## API Endpoints

### GET /health

Health check endpoint with database statistics.

**Response:**

```json
{
  "status": "ok",
  "ranges_loaded": 256,
  "total_hashes": 504680
}
```

### POST /check

Check if a SHA-1 password hash exists in the database.

**Request:**

```json
{
  "hash": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
}
```

**Response:**

```json
{
  "pwned": true,
  "count": 12345
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HIBP_DOWNLOAD_ON_START` | *(unset)* | Download data on startup: `tiny`, `sample`, or `full` |
| `HIBP_DATA_DIR` | `./data/ranges` | Path to HIBP range files (used if `HIBP_DOWNLOAD_ON_START` not set) |
| `PORT` | `3000` | HTTP server port |
| `HIBP_MEMORY_MODE` | `true` | Load all data into memory for fast lookups |
| `RUST_LOG` | `info` | Log level |

### Download Size Options

| Size | Ranges | Data Size | Download Time | Memory Usage |
|------|--------|-----------|---------------|--------------|
| `tiny` | 256 | ~20MB | ~2 seconds | ~50MB |
| `sample` | 65,536 | ~2.5GB | ~5 minutes | ~2GB |
| `full` | 1,048,576 | ~38GB | ~15 minutes | ~20-40GB |

## Memory Usage

- **Download on startup**: Data is downloaded directly into memory, no disk needed
- **Disk mode** (`HIBP_MEMORY_MODE=false`): Minimal RAM, reads from disk per query
- **Memory mode** (`HIBP_MEMORY_MODE=true`): Fast lookups, uses RAM proportional to dataset

## Docker

Build and run with Docker:

```bash
# From the password-demo directory
docker build -t hibp-server .

# Run with download on startup (recommended)
docker run -p 3000:3000 -e HIBP_DOWNLOAD_ON_START=sample hibp-server

# Or run with local data
docker run -p 3000:3000 -v /path/to/data:/app/data/ranges hibp-server
```

## Example Usage

```bash
# Check the password "password" (SHA-1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8)
curl -X POST http://localhost:3000/check \
  -H "Content-Type: application/json" \
  -d '{"hash": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}'
```

## Logging

The server logs download progress and startup information:

```
INFO hibp_server: Starting HIBP server...
INFO hibp_server: HIBP_DOWNLOAD_ON_START=sample
INFO hibp_server: Downloading sample (65,536 ranges, ~2.5GB) dataset...
INFO hibp::downloader: Download progress: 1000/65536 ranges (1.5%)
INFO hibp::downloader: Download progress: 2000/65536 ranges (3.1%)
...
INFO hibp_server: Download completed successfully!
INFO hibp_server:   Ranges: 65536
INFO hibp_server:   Total hashes: 128117217
INFO hibp_server:   Time: 312.4s
INFO hibp_server: Server listening on 0.0.0.0:3000
```

## Attribution

Password data provided by [Have I Been Pwned](https://haveibeenpwned.com).
