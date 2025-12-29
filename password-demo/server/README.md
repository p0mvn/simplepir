# HIBP Password Checker Server

HTTP server for checking if password hashes exist in the HaveIBeenPwned database.

## Quick Start

```bash
# Download sample data (tiny sample for testing)
cd ../scripts && bash download-hibp-tiny.sh

# Run the server
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
| `HIBP_DATA_DIR` | `./data/ranges` | Path to HIBP range files |
| `PORT` | `3000` | HTTP server port |
| `HIBP_MEMORY_MODE` | `true` | Load all data into memory for fast lookups |
| `RUST_LOG` | `info` | Log level |

## Memory Usage

- **Disk mode** (`HIBP_MEMORY_MODE=false`): Minimal RAM, reads from disk per query
- **Memory mode** (`HIBP_MEMORY_MODE=true`): ~20-40GB RAM for full database, sub-ms lookups

For testing with the tiny sample (256 files), memory mode uses ~50MB.

## Docker

Build and run with Docker:

```bash
# From the password-demo directory
docker build -t hibp-server -f server/Dockerfile .
docker run -p 3000:3000 -v /path/to/data:/app/data hibp-server
```

## Example Usage

```bash
# Check the password "password" (SHA-1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8)
curl -X POST http://localhost:3000/check \
  -H "Content-Type: application/json" \
  -d '{"hash": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}'
```

## Attribution

Password data provided by [Have I Been Pwned](https://haveibeenpwned.com).
