#!/bin/bash
#
# Download a SAMPLE of the HaveIBeenPwned Pwned Passwords database
# For development/testing - downloads only prefixes starting with "00"
# This is 65,536 files (~2.5GB) instead of the full 1,048,576 files (~38GB)
#
# Attribution: Password data from https://haveibeenpwned.com
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
RANGES_DIR="${DATA_DIR}/ranges"
PARALLEL_CONNECTIONS=100

GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

mkdir -p "$RANGES_DIR"
cd "$RANGES_DIR"

log "Downloading HIBP sample (prefixes 00XXX only)..."
log "This downloads ~2.5GB of data (65,536 files)"
log "Output: $RANGES_DIR"
echo ""

# Download only prefixes starting with "00" (00000 to 00FFF)
# This gives us 16^3 = 4,096 files per first two chars
# For "00", that's 4,096 files
# Actually let's do 00-0F for more coverage: 16 * 4096 = 65,536 files

curl --retry 5 \
     --retry-all-errors \
     --remote-name-all \
     --parallel \
     --parallel-max "$PARALLEL_CONNECTIONS" \
     --progress-bar \
     "https://api.pwnedpasswords.com/range/0{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}"

log "Sample download complete!"
log "Files: $(find "$RANGES_DIR" -type f | wc -l | tr -d ' ')"
log "Size: $(du -sh "$RANGES_DIR" | cut -f1)"

