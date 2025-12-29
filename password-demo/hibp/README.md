# HIBP - HaveIBeenPwned Pwned Passwords Library

A Rust library for downloading and querying the [HaveIBeenPwned Pwned Passwords](https://haveibeenpwned.com/Passwords) database.

## Features

- **Async downloader** with parallel HTTP requests (150 concurrent by default)
- **Password checker** for looking up hashes in downloaded data
- **Flexible download sizes**: tiny (256 files), sample (65k files), or full (1M files)
- **In-memory or disk-based** lookups

## Usage

### Download Data

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

### Check Passwords

```rust
use hibp::PasswordChecker;

fn main() -> Result<(), hibp::Error> {
    let checker = PasswordChecker::from_directory("./data/ranges")?;
    
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
cargo build --features cli

# Download data
./target/debug/hibp-download tiny ./data/ranges    # ~20MB, 10 seconds
./target/debug/hibp-download sample ./data/ranges  # ~2.5GB, 2 minutes
./target/debug/hibp-download full ./data/ranges    # ~38GB, 15 minutes
```

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

## Attribution

Password data provided by [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt.

