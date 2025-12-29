#!/bin/bash
#
# Download the full HaveIBeenPwned Pwned Passwords database
# Uses curl URL globbing with parallel connections for fast downloads
#
# The HIBP API serves password hashes via a k-anonymity model:
# - Request: GET https://api.pwnedpasswords.com/range/{5-char-prefix}
# - Response: Lines of "SUFFIX:COUNT" where full hash = PREFIX + SUFFIX
#
# There are 16^5 = 1,048,576 possible prefixes (00000 to FFFFF)
# Total download size: ~38GB
# Time: ~15 minutes with good connection and 150 parallel connections
#
# Source: https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/issues/79
# Attribution: Password data from https://haveibeenpwned.com
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
RANGES_DIR="${DATA_DIR}/ranges"
PARALLEL_CONNECTIONS=150
LOG_FILE="${DATA_DIR}/download.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

# Check curl version supports parallel downloads
check_curl_version() {
    local curl_version
    curl_version=$(curl --version | head -1 | awk '{print $2}')
    local major_version
    major_version=$(echo "$curl_version" | cut -d. -f1)
    local minor_version
    minor_version=$(echo "$curl_version" | cut -d. -f2)
    
    # Parallel support added in curl 7.66.0 (Sep 2019)
    if [[ "$major_version" -lt 7 ]] || [[ "$major_version" -eq 7 && "$minor_version" -lt 66 ]]; then
        error "curl version $curl_version does not support parallel downloads"
        error "Please upgrade to curl 7.66.0 or later"
        exit 1
    fi
    
    log "Using curl version $curl_version"
}

# Check available disk space
check_disk_space() {
    local required_gb=45  # ~38GB data + buffer
    local available_kb
    available_kb=$(df -k "$DATA_DIR" | tail -1 | awk '{print $4}')
    local available_gb=$((available_kb / 1024 / 1024))
    
    if [[ "$available_gb" -lt "$required_gb" ]]; then
        error "Insufficient disk space: ${available_gb}GB available, ${required_gb}GB required"
        exit 1
    fi
    
    log "Disk space check passed: ${available_gb}GB available"
}

# Download all HIBP range files
download_ranges() {
    log "Starting download of HIBP Pwned Passwords database..."
    log "Output directory: $RANGES_DIR"
    log "Parallel connections: $PARALLEL_CONNECTIONS"
    log "This will download ~38GB of data. Estimated time: 10-20 minutes."
    echo ""
    
    cd "$RANGES_DIR"
    
    # The magic curl command with URL globbing
    # {0,1,2,...,F} repeated 5 times generates all hex prefixes from 00000 to FFFFF
    local start_time
    start_time=$(date +%s)
    
    curl --retry 10 \
         --retry-all-errors \
         --remote-name-all \
         --parallel \
         --parallel-max "$PARALLEL_CONNECTIONS" \
         --progress-bar \
         "https://api.pwnedpasswords.com/range/{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}" \
         2>&1 | tee -a "$LOG_FILE"
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log "Download completed in ${minutes}m ${seconds}s"
}

# Verify download integrity
verify_download() {
    log "Verifying download..."
    
    local expected_files=1048576  # 16^5
    local actual_files
    actual_files=$(find "$RANGES_DIR" -type f -name '[0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]' | wc -l | tr -d ' ')
    
    if [[ "$actual_files" -ne "$expected_files" ]]; then
        warn "Expected $expected_files files, found $actual_files"
        warn "Some files may be missing. Consider re-running the download."
        return 1
    fi
    
    # Check for empty files
    local empty_files
    empty_files=$(find "$RANGES_DIR" -type f -empty | wc -l | tr -d ' ')
    
    if [[ "$empty_files" -gt 0 ]]; then
        warn "Found $empty_files empty files"
        return 1
    fi
    
    # Calculate total size
    local total_size
    total_size=$(du -sh "$RANGES_DIR" | cut -f1)
    
    log "Verification passed: $actual_files files, total size: $total_size"
    return 0
}

# Generate stats about the downloaded data
generate_stats() {
    log "Generating statistics..."
    
    local stats_file="${DATA_DIR}/stats.txt"
    
    {
        echo "HIBP Pwned Passwords Download Statistics"
        echo "========================================="
        echo "Download date: $(date)"
        echo ""
        echo "File count: $(find "$RANGES_DIR" -type f | wc -l | tr -d ' ')"
        echo "Total size: $(du -sh "$RANGES_DIR" | cut -f1)"
        echo ""
        echo "Total password hashes:"
        # Count total lines across all files (each line = one hash)
        find "$RANGES_DIR" -type f -name '[0-9A-F]*' -exec cat {} + | wc -l | tr -d ' '
    } > "$stats_file"
    
    cat "$stats_file"
}

# Main
main() {
    log "HIBP Pwned Passwords Downloader"
    log "================================"
    echo ""
    
    # Create directories
    mkdir -p "$RANGES_DIR"
    
    # Pre-flight checks
    check_curl_version
    check_disk_space
    
    # Download
    download_ranges
    
    # Verify
    if verify_download; then
        generate_stats
        log "Download complete! Data is ready in: $RANGES_DIR"
    else
        warn "Download completed with warnings. Check the logs."
        exit 1
    fi
}

# Run if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

