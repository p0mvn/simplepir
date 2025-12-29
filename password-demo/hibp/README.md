# HIBP - HaveIBeenPwned Pwned Passwords Library

A Rust library for downloading and querying the [HaveIBeenPwned Pwned Passwords](https://haveibeenpwned.com/Passwords) database.

## Features

- **Async downloader** with parallel HTTP requests (150 concurrent by default)
- **In-memory downloader** for direct-to-memory loading (no disk needed)
- **Password checker** for looking up hashes in downloaded data
- **Flexible download sizes**: tiny (256 files), sample (65k files), or full (1M files)
- **In-memory or disk-based** lookups

## Usage

### Download Data to Disk

```rust
use hibp::Downloader;

#[tokio::main]
async fn main() -> Result<(), hibp::Error> {
    let downloader = Downloader::new("./data/ranges");
    
    // Quick test (256 files, ~20MB)
    downloader.download_tiny().await?;
    
    // Development (65k files, ~2.5GB)
    // downloader.download_sample().await?;
    
    // Production (1M files, ~38GB)
    // downloader.download_full().await?;
    
    Ok(())
}
```

### Download Data Directly to Memory

```rust
use hibp::{InMemoryDownloader, DownloadSize, PasswordChecker};

#[tokio::main]
async fn main() -> Result<(), hibp::Error> {
    // Download directly to memory (no disk needed)
    let downloader = InMemoryDownloader::new();
    let cache = downloader.download_to_memory(DownloadSize::Sample).await?;
    
    // Create checker from in-memory cache
    let checker = PasswordChecker::from_cache(cache);
    
    // Check passwords
    if let Some(count) = checker.check("password123")? {
        println!("Password found in {} breaches!", count);
    }
    
    Ok(())
}
```

### Check Passwords

```rust
use hibp::PasswordChecker;

fn main() -> Result<(), hibp::Error> {
    // Load from disk
    let checker = PasswordChecker::from_directory("./data/ranges")?;
    
    // Optionally load into memory for faster lookups
    let checker = checker.load_into_memory()?;
    
    // Check a password (hashed internally)
    if let Some(count) = checker.check("password123")? {
        println!("Password found in {} breaches!", count);
    }
    
    // Or check a pre-computed SHA-1 hash
    let hash = hibp::hash_password("password123");
    if let Some(count) = checker.check_hash(&hash)? {
        println!("Hash found {} times", count);
    }
    
    Ok(())
}
```

### CLI Tool

```bash
# Build with CLI feature
cargo build --features cli --release

# Download data to disk
./target/release/hibp-download tiny ./data/ranges    # ~20MB, 2 seconds
./target/release/hibp-download sample ./data/ranges  # ~2.5GB, 5 minutes
./target/release/hibp-download full ./data/ranges    # ~38GB, 15 minutes
```

## Download Sizes

| Size | Ranges | Data Size | Download Time | Memory Usage |
|------|--------|-----------|---------------|--------------|
| `tiny` | 256 | ~20MB | ~2 seconds | ~50MB |
| `sample` | 65,536 | ~2.5GB | ~5 minutes | ~2GB |
| `full` | 1,048,576 | ~38GB | ~15 minutes | ~20-40GB |

## Data Format

The HIBP API uses k-anonymity:
- Request prefix (5 hex chars) → get all matching suffixes
- Full SHA-1 hash = prefix + suffix
- Each suffix includes a breach count

Example range file (`00000`):
```
0005AD76BD555C1D6D771DE417A4B87E4B4:58
000A8DAE4228F821FB418F59826079BF368:4
000DD7F2A1C68A35673713783CA390C9E93:1469
```

## API Reference

### `Downloader`
Downloads HIBP data to disk files.

- `new(output_dir)` - Create downloader for a directory
- `download_tiny()` - Download 256 ranges
- `download_sample()` - Download 65,536 ranges
- `download_full()` - Download 1,048,576 ranges
- `with_concurrency(n)` - Set parallel request count

### `InMemoryDownloader`
Downloads HIBP data directly into memory.

- `new()` - Create in-memory downloader
- `download_to_memory(size)` - Download and return HashMap
- `with_concurrency(n)` - Set parallel request count

### `PasswordChecker`
Checks passwords against downloaded data.

- `from_directory(path)` - Load from disk files
- `from_cache(hashmap)` - Load from in-memory cache
- `load_into_memory()` - Load disk files into RAM
- `check(password)` - Check plaintext password
- `check_hash(hash)` - Check SHA-1 hash
- `stats()` - Get loaded data statistics

### `DownloadSize`
Enum for download size options.

- `Tiny` - 256 ranges
- `Sample` - 65,536 ranges
- `Full` - 1,048,576 ranges
- `from_str(s)` - Parse from string
- `description()` - Human-readable description
- `range_count()` - Number of ranges

## Attribution

Password data provided by [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt.
