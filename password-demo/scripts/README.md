# HIBP Download Scripts

Scripts to download the [HaveIBeenPwned Pwned Passwords](https://haveibeenpwned.com/Passwords) database.

## Scripts

| Script | Files | Size | Time | Use Case |
|--------|-------|------|------|----------|
| `download-hibp-tiny.sh` | 256 | ~100MB | ~10s | Quick testing |
| `download-hibp-sample.sh` | 65,536 | ~2.5GB | ~2min | Development |
| `download-hibp.sh` | 1,048,576 | ~38GB | ~15min | Production |

## Usage

```bash
# Quick test (256 files, ~100MB)
./download-hibp-tiny.sh

# Development sample (65k files, ~2.5GB)
./download-hibp-sample.sh

# Full database (1M files, ~38GB)
./download-hibp.sh
```

## Data Format

Files are downloaded to `../data/ranges/` with filenames being the 5-character hex prefix (e.g., `00000`, `ABCDE`, `FFFFF`).

Each file contains lines in the format:
```
SUFFIX:COUNT
```

Where:
- **SUFFIX**: The remaining 35 characters of the SHA-1 hash (full hash = prefix + suffix)
- **COUNT**: Number of times this password appeared in breaches

Example (`ranges/00000` file):
```
0018A45C4D1DEF81644B54AB7F969B88D65:21
003D68EB55068C33ACE09247EE4C639306B:3
00A8DAE4228F821FB418F59826079BF368D:2
```

To check if a password is pwned:
1. SHA-1 hash the password (uppercase hex)
2. Take first 5 chars as prefix
3. Look up the file `ranges/{prefix}`
4. Search for the remaining 35 chars (suffix) in the file
5. If found, the count indicates how many times it appeared in breaches

## Requirements

- **curl** 7.66.0+ (for `--parallel` support)
- **Disk space**: 45GB+ for full download
- **Network**: Good connection recommended

## Attribution

Password data provided by [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt.

