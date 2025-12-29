# Deployment Guide

This guide covers deploying the HIBP Password Checker to production.

## Architecture

```
┌─────────────┐     ┌─────────────┐
│   Vercel    │────▶│   Railway   │
│  (Next.js)  │     │(Rust Server)│
└─────────────┘     └─────────────┘
```

## Prerequisites

- GitHub repository connected to both Vercel and Railway
- Railway account
- Vercel account

---

## Deploy UI to Vercel

### Option 1: Vercel Dashboard (Recommended)

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import your GitHub repository: `p0mvn/simplepir`
3. Configure the project:
   - **Framework Preset**: Next.js
   - **Root Directory**: `password-demo/ui`
   - **Build Command**: `npm run build`
   - **Output Directory**: `.next`

4. Add environment variable:
   ```
   NEXT_PUBLIC_API_URL = https://your-railway-app.railway.app
   ```
   (You'll get this URL after deploying to Railway)

5. Click **Deploy**

### Option 2: Vercel CLI

```bash
cd password-demo/ui
npm i -g vercel
vercel login
vercel --prod
```

---

## Deploy Server to Railway

### Step 1: Create Railway Project

1. Go to [railway.app/new](https://railway.app/new)
2. Click **Deploy from GitHub repo**
3. Select `p0mvn/simplepir`

### Step 2: Configure Build Settings

In the Railway service settings:

- **Root Directory**: `password-demo`
- **Builder**: Dockerfile
- **Dockerfile Path**: `Dockerfile`
- **Watch Paths**: `password-demo/server/**`, `password-demo/hibp/**`

### Step 3: Set Environment Variables

Set these environment variables in the Railway dashboard:

```
PORT=3000
HIBP_DOWNLOAD_ON_START=sample
RUST_LOG=info
```

**`HIBP_DOWNLOAD_ON_START` options:**

| Value | Ranges | Data Size | Download Time | Memory Usage |
|-------|--------|-----------|---------------|--------------|
| `tiny` | 256 | ~20MB | ~2 seconds | ~50MB |
| `sample` | 65,536 | ~2.5GB | ~5 minutes | ~2GB |
| `full` | 1,048,576 | ~38GB | ~15 minutes | ~20-40GB |

> **Recommended**: Use `sample` for most deployments. It covers ~6% of all password hashes which is sufficient for demo purposes. Use `full` only if you need complete coverage and have 40GB+ RAM available.

### Step 4: Generate Domain

In Railway settings, go to **Settings** → **Networking** → **Generate Domain**

Copy the URL (e.g., `hibp-server-production.up.railway.app`)

### Step 5: Update Vercel

Go back to Vercel and update the environment variable:
```
NEXT_PUBLIC_API_URL = https://hibp-server-production.up.railway.app
```

Redeploy if needed.

---

## Alternative: Local Files with Volume (Advanced)

If you prefer to use pre-downloaded data files instead of downloading on startup:

### Step 1: Create Volume

Configure a volume in Railway:
- **Mount Path**: `/app/data/ranges`
- **Name**: `hibp-data`

Increase the size to ~50GB for the full dataset.

### Step 2: Set Environment Variables

```
PORT=3000
HIBP_DATA_DIR=/app/data/ranges
HIBP_MEMORY_MODE=true
RUST_LOG=info
```

Note: Do NOT set `HIBP_DOWNLOAD_ON_START` when using local files.

### Step 3: Populate the Volume

Use Railway shell to download data:
```bash
cd /app/data/ranges
# Download tiny sample
for prefix in {0..9} {A..F}; do
  for suffix in {0..9} {A..F}; do
    curl -s "https://api.pwnedpasswords.com/range/000${prefix}${suffix}" -o "000${prefix}${suffix}"
  done
done
```

---

## Verify Deployment

### Check Server Health
```bash
curl https://your-railway-app.railway.app/health
# Expected: {"status":"ok","ranges_loaded":65536,"total_hashes":...}
```

### Check Password
```bash
curl -X POST https://your-railway-app.railway.app/check \
  -H "Content-Type: application/json" \
  -d '{"hash":"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}'
# Expected: {"pwned":true,"count":...}
```

### Test UI
Visit your Vercel deployment URL and try checking a password.

---

## Cost Estimates

| Service | Free Tier | Production |
|---------|-----------|------------|
| Vercel | ✅ Hobby tier works | $20/mo Pro |
| Railway | ~$5-20/mo | ~$20-50/mo |

**Railway breakdown (sample dataset):**
- Compute: ~$5-10/mo (2GB RAM)
- Egress: $0.10/GB after 100GB free

**Railway breakdown (full dataset):**
- Compute: ~$20-40/mo (40GB RAM)
- Egress: $0.10/GB after 100GB free

---

## Troubleshooting

### Server shows 0 hashes
- Check `HIBP_DOWNLOAD_ON_START` is set correctly
- Check Railway logs for download progress/errors
- Verify the server has enough memory for the dataset size

### Download fails or times out
- Try a smaller dataset (`tiny` or `sample`)
- Check Railway service has network access
- Review logs for specific error messages

### UI shows "Server Offline"
- Verify `NEXT_PUBLIC_API_URL` is set correctly
- Check Railway service is running
- Verify CORS is enabled (it is by default)

### Slow cold starts
- This is expected when using `HIBP_DOWNLOAD_ON_START`
- Consider using `sample` instead of `full` for faster startups
- Railway: Enable "Always On" to prevent cold starts

---

## Local Development

```bash
# Terminal 1: Start server (downloads tiny dataset on startup)
cd password-demo/server
HIBP_DOWNLOAD_ON_START=tiny cargo run --release

# Or load from local files
cd password-demo/server
HIBP_DATA_DIR=../data/ranges cargo run --release

# Terminal 2: Start UI
cd password-demo/ui
NEXT_PUBLIC_API_URL=http://localhost:3000 npm run dev
```

---

## Docker

```bash
# Build
cd password-demo
docker build -t hibp-server .

# Run with download on startup
docker run -p 3000:3000 -e HIBP_DOWNLOAD_ON_START=sample hibp-server

# Or run with local data
docker run -p 3000:3000 -v /path/to/data:/app/data/ranges hibp-server
```
