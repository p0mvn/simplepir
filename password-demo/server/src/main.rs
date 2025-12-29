//! HIBP Password Checker HTTP Server
//!
//! A simple HTTP server that checks if password hashes exist in the HIBP database.
//!
//! ## Endpoints
//!
//! - `GET /health` - Health check
//! - `POST /check` - Check if a SHA-1 hash is pwned
//!
//! ## Usage
//!
//! ```bash
//! # Start server loading data from local files (default)
//! HIBP_DATA_DIR=./data/ranges cargo run --release
//!
//! # Start server and download data on startup (no local files needed)
//! HIBP_DOWNLOAD_ON_START=tiny cargo run --release   # 256 ranges, ~20MB
//! HIBP_DOWNLOAD_ON_START=sample cargo run --release # 65k ranges, ~2.5GB
//! HIBP_DOWNLOAD_ON_START=full cargo run --release   # 1M ranges, ~38GB
//!
//! # Check a password hash
//! curl -X POST http://localhost:3000/check \
//!   -H "Content-Type: application/json" \
//!   -d '{"hash": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}'
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use hibp::{DownloadSize, InMemoryDownloader, PasswordChecker};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info, warn};

/// Application state shared across all handlers
struct AppState {
    checker: PasswordChecker,
}

/// Request body for /check endpoint
#[derive(Debug, Deserialize)]
struct CheckRequest {
    /// SHA-1 hash of the password (40 hex characters, uppercase)
    hash: String,
}

/// Response body for /check endpoint
#[derive(Debug, Serialize)]
struct CheckResponse {
    /// Whether the password hash was found in the database
    pwned: bool,
    /// Number of times the password appeared in breaches (0 if not found)
    count: u32,
}

/// Response body for /health endpoint
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    ranges_loaded: usize,
    total_hashes: usize,
}

/// Health check endpoint
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let stats = state.checker.stats();
    Json(HealthResponse {
        status: "ok",
        ranges_loaded: stats.ranges_loaded,
        total_hashes: stats.total_hashes,
    })
}

/// Check if a password hash is pwned
async fn check(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    // Validate hash format
    if payload.hash.len() != 40 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid hash length: expected 40 characters, got {}",
                payload.hash.len()
            ),
        ));
    }

    // Check if all characters are valid hex
    if !payload.hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid hash: must contain only hexadecimal characters".to_string(),
        ));
    }

    // Look up the hash
    match state.checker.check_hash(&payload.hash) {
        Ok(Some(count)) => Ok(Json(CheckResponse { pwned: true, count })),
        Ok(None) => Ok(Json(CheckResponse {
            pwned: false,
            count: 0,
        })),
        Err(e) => {
            error!("Error checking hash: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[tokio::main]
async fn main() {
    // Load .env file if present
    match dotenvy::dotenv() {
        Ok(path) => eprintln!("Loaded .env from {:?}", path),
        Err(_) => {} // .env file is optional
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    // Get configuration from environment
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    // Check if we should download data on startup
    let download_on_start = std::env::var("HIBP_DOWNLOAD_ON_START").ok();

    info!("Starting HIBP server...");
    info!("Port: {}", port);

    let checker = if let Some(size_str) = download_on_start {
        // Download data directly to memory on startup
        let size = match DownloadSize::from_str(&size_str) {
            Some(s) => s,
            None => {
                error!(
                    "Invalid HIBP_DOWNLOAD_ON_START value: '{}'. Use 'tiny', 'sample', or 'full'",
                    size_str
                );
                std::process::exit(1);
            }
        };

        info!("==============================================");
        info!("HIBP_DOWNLOAD_ON_START={}", size_str);
        info!("Downloading {} dataset from HaveIBeenPwned API...", size.description());
        info!("This will download {} ranges directly into memory", size.range_count());
        info!("==============================================");

        let start = Instant::now();
        let downloader = InMemoryDownloader::new();

        match downloader.download_to_memory(size).await {
            Ok(cache) => {
                let elapsed = start.elapsed();
                let total_hashes: usize = cache.values().map(|m| m.len()).sum();

                info!("==============================================");
                info!("Download completed successfully!");
                info!("  Ranges: {}", cache.len());
                info!("  Total hashes: {}", total_hashes);
                info!("  Time: {:.1}s", elapsed.as_secs_f64());
                info!("==============================================");

                PasswordChecker::from_cache(cache)
            }
            Err(e) => {
                error!("Failed to download HIBP data: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Load from local files (default behavior)
        let data_dir = std::env::var("HIBP_DATA_DIR").unwrap_or_else(|_| "./data/ranges".to_string());
        let load_into_memory = std::env::var("HIBP_MEMORY_MODE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);

        info!("Data source: local files");
        info!("Data directory: {}", data_dir);
        info!("Memory mode: {}", load_into_memory);

        // Load HIBP data from files
        info!("Loading HIBP data from {}...", data_dir);
        let checker = match PasswordChecker::from_directory(&data_dir) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to load HIBP data: {}", e);
                warn!("Hint: Set HIBP_DOWNLOAD_ON_START=tiny to download data on startup");
                std::process::exit(1);
            }
        };

        // Optionally load into memory for faster lookups
        if load_into_memory {
            info!("Loading data into memory (this may take a while for full dataset)...");
            match checker.load_into_memory() {
                Ok(c) => {
                    let stats = c.stats();
                    info!(
                        "Loaded {} ranges with {} total hashes",
                        stats.ranges_loaded, stats.total_hashes
                    );
                    c
                }
                Err(e) => {
                    error!("Failed to load data into memory: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            info!("Running in disk mode (slower lookups, less memory)");
            checker
        }
    };

    let state = Arc::new(AppState { checker });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/check", post(check))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
