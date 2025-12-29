//! CLI tool to download HIBP Pwned Passwords database
//!
//! Usage:
//!   hibp-download tiny    # 256 files, ~20MB (quick test)
//!   hibp-download sample  # 65,536 files, ~2.5GB (development)
//!   hibp-download full    # 1,048,576 files, ~38GB (production)

use hibp::Downloader;
use std::env;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    let size = args.get(1).map(|s| s.as_str()).unwrap_or("tiny");
    let output_dir = args.get(2).map(|s| s.as_str()).unwrap_or("./data/ranges");

    println!("HIBP Pwned Passwords Downloader");
    println!("================================");
    println!();

    let downloader = Downloader::new(output_dir);
    let start = Instant::now();

    let count = match size {
        "tiny" => {
            println!("Downloading tiny sample (256 files, ~20MB)...");
            downloader.download_tiny().await?
        }
        "sample" => {
            println!("Downloading sample (65,536 files, ~2.5GB)...");
            downloader.download_sample().await?
        }
        "full" => {
            println!("Downloading full database (1,048,576 files, ~38GB)...");
            println!("This will take approximately 15 minutes...");
            downloader.download_full().await?
        }
        _ => {
            eprintln!("Usage: hibp-download [tiny|sample|full] [output_dir]");
            eprintln!();
            eprintln!("Sizes:");
            eprintln!("  tiny   - 256 files, ~20MB (quick test)");
            eprintln!("  sample - 65,536 files, ~2.5GB (development)");
            eprintln!("  full   - 1,048,576 files, ~38GB (production)");
            std::process::exit(1);
        }
    };

    let elapsed = start.elapsed();
    println!();
    println!("Download complete!");
    println!("  Files: {}", count);
    println!("  Time: {:.1}s", elapsed.as_secs_f64());
    println!("  Output: {}", output_dir);

    Ok(())
}
