//! Release benchmark & smoke runner for `S-Win-1` (`cargo run --release -- --bench`).
//! Keeps all three Win32 primitives reachable in the stripped release `.exe` so binary size
//! and tuned release latencies reflect production flags (`lto = "thin", strip = true`).

#[cfg(windows)]
#[tokio::main]
async fn main() {
    use s_win_1_platform::{clipboard, named_pipe, subprocess};
    use std::time::{Duration, Instant};

    let args: Vec<String> = std::env::args().collect();
    let bench = args.iter().any(|a| a == "--bench");

    let sids = named_pipe::query_current_process_sids().expect("query process SIDs");
    println!(
        "[S-Win-1][RELEASE] TokenUser={} TokenOwner={}",
        sids.token_user_sid, sids.token_owner_sid
    );

    if !bench {
        return;
    }

    // 1. Release Named Pipe NDJSON roundtrip (5 trials)
    let mut stream_p50 = Vec::new();
    let mut conn_p50 = Vec::new();
    for trial in 1..=5 {
        let res = named_pipe::benchmark_ndjson_roundtrip(named_pipe::PIPE_OWNER_ONLY_SDDL, 1000, 200)
            .await
            .expect("release pipe bench");
        println!(
            "[S-Win-1][RELEASE][PIPE][Trial {trial}/5] persistent_1000(min={:.1}us p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us) | connect+roundtrip_200(min={:.1}us p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us)",
            res.persistent_stream.min_us,
            res.persistent_stream.p50_us,
            res.persistent_stream.p95_us,
            res.persistent_stream.p99_us,
            res.persistent_stream.max_us,
            res.per_call_connect_roundtrip.min_us,
            res.per_call_connect_roundtrip.p50_us,
            res.per_call_connect_roundtrip.p95_us,
            res.per_call_connect_roundtrip.p99_us,
            res.per_call_connect_roundtrip.max_us,
        );
        stream_p50.push(res.persistent_stream.p50_us);
        conn_p50.push(res.per_call_connect_roundtrip.p50_us);
    }
    stream_p50.sort_by(|a, b| a.partial_cmp(b).unwrap());
    conn_p50.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "[S-Win-1][RELEASE][PIPE][Summary] persistent p50 median={:.1}us (range {:.1}..{:.1}us) | connect+roundtrip p50 median={:.1}us (range {:.1}..{:.1}us)",
        stream_p50[2], stream_p50[0], stream_p50[4], conn_p50[2], conn_p50[0], conn_p50[4]
    );

    // 2. Release Job Object child+grandchild kill + Python oneshot cold-start
    let (_cpid, _gcpid, kill_dur) =
        subprocess::verify_job_object_kills_grandchild_tree().expect("release job kill");
    let mut py_ms = Vec::new();
    for _ in 0..5 {
        let out = subprocess::run_hardened_oneshot(
            "python",
            &["-c", "import sys; sys.stdout.write(sys.stdin.read())"],
            "{\"msg\":\"你好 🚀\"}\n",
            &[],
            Duration::from_secs(10),
        )
        .expect("release python oneshot");
        assert_eq!(out.exit_code, 0);
        py_ms.push(out.elapsed.as_secs_f64() * 1_000.0);
    }
    py_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "[S-Win-1][RELEASE][PROC] job_kill_convergence={:.3}ms | python oneshot 5-run median={:.2}ms (range {:.2}..{:.2}ms)",
        kill_dur.as_secs_f64() * 1_000.0,
        py_ms[2],
        py_ms[0],
        py_ms[4]
    );

    // 3. Release 1920x1080 CF_DIBV5 -> PNG transcode (5 trials)
    let hd_rgba: Vec<u8> = (0..(1920 * 1080 * 4)).map(|i| ((i * 7) & 0xFF) as u8).collect();
    let hd_dib = clipboard::rgba_to_dibv5_bytes(1920, 1080, &hd_rgba);
    let mut dib_ms = Vec::new();
    let mut out_bytes = 0usize;
    for _ in 0..5 {
        let t0 = Instant::now();
        let (png, w, h) = clipboard::dibv5_to_png(&hd_dib).expect("release dibv5_to_png");
        dib_ms.push(t0.elapsed().as_secs_f64() * 1_000.0);
        out_bytes = png.len();
        assert_eq!((w, h), (1920, 1080));
    }
    dib_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "[S-Win-1][RELEASE][CLIP] 1920x1080 CF_DIBV5 ({} B) -> PNG ({} B) 5-run median={:.2}ms (range {:.2}..{:.2}ms)",
        hd_dib.len(),
        out_bytes,
        dib_ms[2],
        dib_ms[0],
        dib_ms[4]
    );
}

#[cfg(not(windows))]
fn main() {
    println!(
        "s-win-1-platform non-Windows stub (pipe_sddl='{}', env_allowlist_count={})",
        s_win_1_platform::named_pipe::PIPE_OWNER_ONLY_SDDL,
        s_win_1_platform::subprocess::WINDOWS_ENV_ALLOWLIST.len()
    );
}
