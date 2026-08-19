//! Latency/throughput benchmark for gratis's SOCKS5 proxies, run against a live daemon.
//!
//! Ad-hoc `curl` timing (what this replaces) turned out to be a bad way to measure this: a
//! single request's number is dominated by whichever unrelated thing happened to be slow that
//! moment (a rate-limited test target, this machine's own DNS resolver — `resolvectl
//! statistics` shows an ~18% timeout rate on it independent of gratis entirely, a cold tunnel
//! mixed in with warm ones). This tool controls for that the way any latency benchmark should:
//! many samples, cold isolated from warm, a fixed target IP (no per-run DNS variance), and
//! percentiles instead of one number.
//!
//! ```sh
//! cargo run --release --example bench -- --port 20032 --port 20009
//! cargo run --release --example bench -- --all --iterations 20
//! ```
use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Cloudflare's own speed-test endpoint: `bytes=N` streams back exactly `N` bytes of
/// non-cacheable data. Chosen over a random file mirror specifically because it won't rate
/// limit or go down mid-benchmark the way a one-off hosted zip did during manual testing.
const THROUGHPUT_URL: &str = "https://speed.cloudflare.com/__down";

/// Small, fixed-size, no-redirect endpoint for latency sampling — just enough of a real TLS
/// request to measure connect + handshake + first-byte, without a download skewing the number.
const LATENCY_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

/// Pinned IPs for the two targets above, resolved once via a public resolver at startup rather
/// than per-request — see the module doc comment on why per-run DNS variance is worth removing
/// from these numbers rather than measuring it by accident.
const LATENCY_HOST: &str = "1.1.1.1";
const THROUGHPUT_HOST: &str = "speed.cloudflare.com";

#[derive(Parser)]
#[command(about = "Benchmark gratis SOCKS5 proxies: cold/warm latency + throughput")]
struct Args {
    /// Proxy port(s) to benchmark, e.g. --port 20032 --port 20009. Repeatable.
    #[arg(long = "port")]
    ports: Vec<u16>,

    /// Benchmark every server the control API knows about instead of specific --port values.
    #[arg(long)]
    all: bool,

    /// gratis control API base URL, used to resolve --all and to label ports with server names.
    #[arg(long, default_value = "http://127.0.0.1:9000")]
    control_api: String,

    /// Warm-latency samples per target, taken after one discarded cold sample.
    #[arg(long, default_value_t = 10)]
    iterations: usize,

    /// Bytes to pull for the throughput measurement.
    #[arg(long, default_value_t = 10_000_000)]
    bytes: usize,

    /// Skip the throughput leg (it's the slow part on a loaded free-tier server).
    #[arg(long)]
    no_throughput: bool,
}

#[derive(Deserialize)]
struct ServerStatus {
    name: String,
    port: u16,
}

struct Report {
    label: String,
    cold: Duration,
    warm: Vec<Duration>,
    throughput_bps: Option<f64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let servers = fetch_servers(&args.control_api).await.unwrap_or_default();
    let targets = resolve_targets(&args, &servers)?;

    // Resolved once, up front: every client below uses `.resolve()` to pin these instead of
    // going through this machine's (measurably flaky) system resolver on every single sample.
    let latency_ip = resolve_one(LATENCY_HOST).await?;
    let throughput_ip = resolve_one(THROUGHPUT_HOST).await?;

    let mut reports = Vec::new();

    println!("--- direct (no proxy) baseline ---");
    reports.push(
        bench_target(
            "direct",
            None,
            latency_ip,
            throughput_ip,
            &args,
        )
        .await?,
    );

    for port in targets {
        let label = servers
            .iter()
            .find(|s| s.port == port)
            .map(|s| format!("{port} ({})", s.name))
            .unwrap_or_else(|| port.to_string());
        println!("--- {label} ---");
        reports.push(
            bench_target(&label, Some(port), latency_ip, throughput_ip, &args).await?,
        );
    }

    print_summary(&reports);
    Ok(())
}

fn resolve_targets(args: &Args, servers: &[ServerStatus]) -> Result<Vec<u16>> {
    if args.all {
        if servers.is_empty() {
            anyhow::bail!(
                "--all requested but the control API at {} returned no servers (is gratis running?)",
                args.control_api
            );
        }
        return Ok(servers.iter().map(|s| s.port).collect());
    }
    Ok(args.ports.clone())
}

async fn fetch_servers(control_api: &str) -> Result<Vec<ServerStatus>> {
    let url = format!("{control_api}/api/servers");
    let servers = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .json::<Vec<ServerStatus>>()
        .await
        .with_context(|| format!("parsing {url} response"))?;
    Ok(servers)
}

async fn resolve_one(host: &str) -> Result<IpAddr> {
    tokio::net::lookup_host((host, 443))
        .await
        .with_context(|| format!("resolving {host}"))?
        .next()
        .map(|addr| addr.ip())
        .with_context(|| format!("{host} resolved to no addresses"))
}

fn build_client(port: Option<u16>, latency_ip: IpAddr, throughput_ip: IpAddr) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));

    if let Some(port) = port {
        // socks5h: the domain name goes to gratis, which resolves it *through the tunnel*
        // itself (see `socks5.rs::resolve_target`) — this machine's own resolver never gets
        // involved for proxied requests, so it can't be a variance source in these numbers.
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
            .with_context(|| format!("building proxy for port {port}"))?;
        builder = builder.proxy(proxy);
    } else {
        // The direct baseline has no tunnel to resolve through, so it's pinned to the same IP
        // the proxied runs will independently resolve to — keeps the comparison apples-to-apples
        // instead of exposing this machine's own (measurably flaky, see module doc comment)
        // resolver as noise in the direct numbers.
        builder = builder
            .resolve(LATENCY_HOST, SocketAddr::new(latency_ip, 443))
            .resolve(THROUGHPUT_HOST, SocketAddr::new(throughput_ip, 443))
            .no_proxy();
    }

    builder.build().context("building reqwest client")
}

async fn bench_target(
    label: &str,
    port: Option<u16>,
    latency_ip: IpAddr,
    throughput_ip: IpAddr,
    args: &Args,
) -> Result<Report> {
    let client = build_client(port, latency_ip, throughput_ip)?;

    // First request against a freshly-built client pays whatever cold cost exists (tunnel
    // bring-up + readiness unlock for a proxy target, TCP+TLS handshake either way) — kept
    // separate from the warm samples instead of averaged in with them.
    let cold = time_request(&client).await?;
    println!("  cold:  {:>8.3}s", cold.as_secs_f64());

    let mut warm = Vec::with_capacity(args.iterations);
    for i in 0..args.iterations {
        let d = time_request(&client).await?;
        println!("  warm[{i}]: {:>8.3}s", d.as_secs_f64());
        warm.push(d);
    }

    let throughput_bps = if args.no_throughput {
        None
    } else {
        let (bytes, elapsed) = time_download(&client, args.bytes).await?;
        let bps = bytes as f64 / elapsed.as_secs_f64();
        println!(
            "  throughput: {} bytes in {:.3}s = {:.0} B/s ({:.2} Mbit/s)",
            bytes,
            elapsed.as_secs_f64(),
            bps,
            bps * 8.0 / 1_000_000.0
        );
        Some(bps)
    };

    Ok(Report {
        label: label.to_string(),
        cold,
        warm,
        throughput_bps,
    })
}

async fn time_request(client: &reqwest::Client) -> Result<Duration> {
    let started = Instant::now();
    let resp = client
        .get(LATENCY_URL)
        .send()
        .await
        .context("latency request")?;
    // Read the body to first byte is not enough on its own to be comparable to `curl`'s
    // time_total, so drain it fully — it's tiny (a few hundred bytes of trace output).
    resp.bytes().await.context("reading latency response")?;
    Ok(started.elapsed())
}

async fn time_download(client: &reqwest::Client, bytes: usize) -> Result<(usize, Duration)> {
    let url = format!("{THROUGHPUT_URL}?bytes={bytes}");
    let started = Instant::now();
    let resp = client.get(&url).send().await.context("throughput request")?;
    let body = resp.bytes().await.context("reading throughput response")?;
    Ok((body.len(), started.elapsed()))
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

fn print_summary(reports: &[Report]) {
    println!("\n=== summary ===");
    println!(
        "{:<28} {:>8} {:>8} {:>8} {:>8} {:>10}",
        "target", "cold", "p50", "p95", "max", "throughput"
    );
    for r in reports {
        let mut warm = r.warm.clone();
        warm.sort();
        let p50 = percentile(&warm, 0.50);
        let p95 = percentile(&warm, 0.95);
        let max = warm.last().copied().unwrap_or_default();
        let throughput = r
            .throughput_bps
            .map(|bps| format!("{:.0} KB/s", bps / 1000.0))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<28} {:>7.3}s {:>7.3}s {:>7.3}s {:>7.3}s {:>10}",
            r.label,
            r.cold.as_secs_f64(),
            p50.as_secs_f64(),
            p95.as_secs_f64(),
            max.as_secs_f64(),
            throughput
        );
    }
}
