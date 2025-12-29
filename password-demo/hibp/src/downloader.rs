//! HIBP Pwned Passwords downloader
//!
//! Downloads password hash ranges from the HaveIBeenPwned API.
//! Uses parallel HTTP requests for fast downloads.

use crate::Error;
use futures::{stream, StreamExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Progress callback for download operations
pub trait DownloadProgress: Send + Sync {
    fn on_file_complete(&self, prefix: &str, current: usize, total: usize);
    fn on_error(&self, prefix: &str, error: &Error);
}

/// Default progress reporter that logs to tracing
pub struct LogProgress;

impl DownloadProgress for LogProgress {
    fn on_file_complete(&self, _prefix: &str, current: usize, total: usize) {
        if current % 1000 == 0 || current == total {
            info!("Downloaded {}/{} files ({:.1}%)", current, total, (current as f64 / total as f64) * 100.0);
        }
    }

    fn on_error(&self, prefix: &str, error: &Error) {
        warn!("Failed to download {}: {}", prefix, error);
    }
}

/// HIBP Pwned Passwords downloader
pub struct Downloader {
    output_dir: PathBuf,
    concurrent_requests: usize,
    client: reqwest::Client,
}

impl Downloader {
    /// Create a new downloader with default settings
    pub fn new<P: AsRef<Path>>(output_dir: P) -> Self {
        Self {
            output_dir: output_dir.as_ref().to_path_buf(),
            concurrent_requests: 150,
            client: reqwest::Client::builder()
                .user_agent("pir-password-checker/0.1")
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Set the number of concurrent requests
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrent_requests = n;
        self
    }

    /// Generate all possible 5-character hex prefixes (00000 to FFFFF)
    fn all_prefixes() -> Vec<String> {
        let chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
        let mut prefixes = Vec::with_capacity(1_048_576); // 16^5

        for a in &chars {
            for b in &chars {
                for c in &chars {
                    for d in &chars {
                        for e in &chars {
                            prefixes.push(format!("{}{}{}{}{}", a, b, c, d, e));
                        }
                    }
                }
            }
        }
        prefixes
    }

    /// Generate prefixes for a tiny sample (000XX - 256 files)
    fn tiny_prefixes() -> Vec<String> {
        let chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
        let mut prefixes = Vec::with_capacity(256);

        for d in &chars {
            for e in &chars {
                prefixes.push(format!("000{}{}", d, e));
            }
        }
        prefixes
    }

    /// Generate prefixes for a sample (0XXXX - 65,536 files)
    fn sample_prefixes() -> Vec<String> {
        let chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
        let mut prefixes = Vec::with_capacity(65_536);

        for b in &chars {
            for c in &chars {
                for d in &chars {
                    for e in &chars {
                        prefixes.push(format!("0{}{}{}{}", b, c, d, e));
                    }
                }
            }
        }
        prefixes
    }

    /// Download a single range file
    async fn download_range(&self, prefix: &str) -> Result<(), Error> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let response = self.client.get(&url).send().await?;
        let body = response.text().await?;

        let file_path = self.output_dir.join(prefix);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(body.as_bytes()).await?;

        Ok(())
    }

    /// Download ranges with progress reporting
    async fn download_prefixes<P: DownloadProgress>(
        &self,
        prefixes: Vec<String>,
        progress: &P,
    ) -> Result<usize, Error> {
        fs::create_dir_all(&self.output_dir).await?;

        let total = prefixes.len();
        let completed = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(AtomicUsize::new(0));

        stream::iter(prefixes)
            .map(|prefix| {
                let completed = Arc::clone(&completed);
                let errors = Arc::clone(&errors);
                async move {
                    // Retry logic
                    let mut attempts = 0;
                    loop {
                        match self.download_range(&prefix).await {
                            Ok(()) => {
                                let current = completed.fetch_add(1, Ordering::SeqCst) + 1;
                                progress.on_file_complete(&prefix, current, total);
                                break;
                            }
                            Err(e) => {
                                attempts += 1;
                                if attempts >= 3 {
                                    progress.on_error(&prefix, &e);
                                    errors.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                tokio::time::sleep(tokio::time::Duration::from_millis(100 * attempts)).await;
                            }
                        }
                    }
                }
            })
            .buffer_unordered(self.concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        let error_count = errors.load(Ordering::SeqCst);
        if error_count > 0 {
            warn!("{} files failed to download", error_count);
        }

        Ok(completed.load(Ordering::SeqCst))
    }

    /// Download a tiny sample (256 files, ~20MB)
    /// Good for quick testing
    pub async fn download_tiny(&self) -> Result<usize, Error> {
        info!("Downloading tiny HIBP sample (256 files)...");
        self.download_prefixes(Self::tiny_prefixes(), &LogProgress).await
    }

    /// Download a sample (65,536 files, ~2.5GB)
    /// Good for development
    pub async fn download_sample(&self) -> Result<usize, Error> {
        info!("Downloading HIBP sample (65,536 files)...");
        self.download_prefixes(Self::sample_prefixes(), &LogProgress).await
    }

    /// Download the full database (1,048,576 files, ~38GB)
    /// Takes ~15 minutes with good connection
    pub async fn download_full(&self) -> Result<usize, Error> {
        info!("Downloading full HIBP database (1,048,576 files)...");
        self.download_prefixes(Self::all_prefixes(), &LogProgress).await
    }

    /// Download with custom progress reporting
    pub async fn download_with_progress<P: DownloadProgress>(
        &self,
        size: DownloadSize,
        progress: &P,
    ) -> Result<usize, Error> {
        let prefixes = match size {
            DownloadSize::Tiny => Self::tiny_prefixes(),
            DownloadSize::Sample => Self::sample_prefixes(),
            DownloadSize::Full => Self::all_prefixes(),
        };
        self.download_prefixes(prefixes, progress).await
    }
}

/// Download size options
#[derive(Debug, Clone, Copy)]
pub enum DownloadSize {
    /// 256 files, ~20MB
    Tiny,
    /// 65,536 files, ~2.5GB
    Sample,
    /// 1,048,576 files, ~38GB
    Full,
}

