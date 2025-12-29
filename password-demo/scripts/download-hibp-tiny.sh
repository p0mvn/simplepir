#!/bin/bash
#
# Download a TINY sample of the HaveIBeenPwned Pwned Passwords database
# For quick testing - downloads only 256 files (prefixes 000XX)
# ~100MB of data, completes in seconds
#
# Attribution: Password data from https://haveibeenpwned.com
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
RANGES_DIR="${DATA_DIR}/ranges"

GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

mkdir -p "$RANGES_DIR"
cd "$RANGES_DIR"

log "Downloading HIBP tiny sample (prefixes 000XX only)..."
log "This downloads ~100MB of data (256 files)"
log "Output: $RANGES_DIR"
echo ""

# Download only prefixes 00000 to 000FF (256 files)
curl --retry 3 \
     --retry-all-errors \
     --remote-name-all \
     --parallel \
     --parallel-max 50 \
     --progress-bar \
     "https://api.pwnedpasswords.com/range/000{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}"

log "Tiny sample download complete!"
log "Files: $(find "$RANGES_DIR" -type f | wc -l | tr -d ' ')"
log "Size: $(du -sh "$RANGES_DIR" | cut -f1)"

# Show a sample of the data format
log ""
log "Sample data format (first file):"
head -5 "$(ls "$RANGES_DIR" | head -1)"

