mod regions;
mod scanner;
mod source;
mod target;

use std::cmp::Ordering;
use std::time::Instant;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use scanner::{OffsetResult, ScanCfg, Worker};
use source::Source;
use target::{host_target, os_name, parse_archs, parse_os};

/// Shellcode detector: emulates a file or a process memory from every offset
/// and ranks offsets by how many instructions they manage to execute.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// file to scan (png, mp4, pdf, anything)
    #[arg(required_unless_present_any = ["pid", "dump"])]
    file: Option<String>,

    /// scan the memory of a live process (Linux, needs ptrace permission)
    #[arg(long, conflicts_with_all = ["file", "dump"])]
    pid: Option<i32>,

    /// scan the memory maps of a mwemu dump (mwemu-snapshot .mwemu or minidump)
    #[arg(long, conflicts_with = "file")]
    dump: Option<String>,

    /// only scan memory maps whose permissions contain these chars, e.g. "x"
    #[arg(long)]
    perms: Option<String>,

    /// target OS: host|windows|linux|macos
    #[arg(long, default_value = "host")]
    os: String,

    /// comma separated archs: x86,x64,arm64 (default: depends on the host)
    #[arg(long)]
    arch: Option<String>,

    /// max instructions to emulate per offset
    #[arg(long, default_value_t = 10_000)]
    max_insns: u64,

    /// bytes mapped as code from each offset
    #[arg(long, default_value_t = 0x10000)]
    window: usize,

    /// wall-clock timeout per offset (seconds)
    #[arg(long, default_value_t = 2.0)]
    timeout: f64,

    /// first offset/address to scan (hex or dec)
    #[arg(long, default_value = "0", value_parser = parse_num)]
    start: u64,

    /// last offset/address to scan, exclusive (hex or dec)
    #[arg(long, value_parser = parse_num)]
    end: Option<u64>,

    /// scan every N bytes
    #[arg(long, default_value_t = 1)]
    stride: usize,

    /// rows to print
    #[arg(long, default_value_t = 30)]
    top: usize,

    /// best results kept in memory (and printed by --json)
    #[arg(long, default_value_t = 10_000)]
    keep: usize,

    /// emulate only this offset/address (hex or dec) printing every instruction
    #[arg(long, value_parser = parse_num)]
    trace: Option<u64>,

    /// -v: one line per emulated offset, -vv: also every instruction (single thread)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// output the kept results as json
    #[arg(long)]
    json: bool,
}

fn main() {
    let args = Args::parse();

    // libmwemu may panic on weird bytes; we catch it per offset, keep stderr clean
    if args.trace.is_none() && std::env::var_os("SCDETECT_PANICS").is_none() {
        std::panic::set_hook(Box::new(|_| {}));
    }

    // libmwemu uses big stack frames
    // -vv runs on one thread so instruction traces don't interleave
    rayon::ThreadPoolBuilder::new()
        .stack_size(64 << 20)
        .num_threads(if args.verbose >= 2 { 1 } else { 0 })
        .build_global()
        .unwrap();

    let mut tgt = host_target();
    match parse_os(&args.os) {
        Ok(Some(os)) => tgt.os = os,
        Ok(None) => {}
        Err(e) => die(&e),
    }
    if let Some(a) = &args.arch {
        tgt.archs = parse_archs(a).unwrap_or_else(|e| die(&e));
    }

    let src = if let Some(pid) = args.pid {
        Source::pid(pid)
    } else if let Some(d) = &args.dump {
        Source::dump(d)
    } else {
        Source::file(args.file.as_deref().unwrap())
    }
    .unwrap_or_else(|e| die(&e));

    let cfg = ScanCfg {
        max_insns: args.max_insns,
        window: args.window,
        timeout_secs: args.timeout,
        trace: args.verbose >= 2,
    };
    let addr_fmt = |a: u64| {
        if src.is_memory {
            format!("{a:#14x}")
        } else {
            format!("{a:#10x}")
        }
    };

    if let Some(addr) = args.trace {
        let (seg, off) = src
            .locate(addr)
            .unwrap_or_else(|| die(&format!("{addr:#x} is not in any segment")));
        let cfg = ScanCfg { trace: true, ..cfg };
        for &arch in &tgt.archs {
            println!(
                "=== {} arch {} {}",
                addr_fmt(addr).trim(),
                target::arch_name(arch),
                src.label(seg, off)
            );
            let r = Worker::new(arch, tgt.os).emulate_at(&src.segs[seg].bytes, off, &cfg);
            println!("=== insns {} unique {} stop {}", r.insns, r.unique, r.stop);
        }
        return;
    }

    // offsets to scan per segment: --start/--end/--perms filters
    let stride = args.stride.max(1) as u64;
    let end = args.end.unwrap_or(u64::MAX);
    let plan: Vec<(usize, u64, u64)> = src
        .segs
        .iter()
        .enumerate()
        .filter(|(_, s)| match &args.perms {
            Some(p) => p.chars().all(|c| s.perms.contains(c)),
            None => true,
        })
        .filter_map(|(i, s)| {
            let lo = args.start.max(s.addr) - s.addr;
            let hi = end
                .min(s.addr + s.bytes.len() as u64)
                .saturating_sub(s.addr);
            (hi > lo).then(|| (i, lo, (hi - lo).div_ceil(stride)))
        })
        .collect();
    let njobs: u64 = plan.iter().map(|p| p.2).sum::<u64>() * tgt.archs.len() as u64;

    eprintln!(
        "scanning {} os={} archs={:?}, {} segments, {} emulations",
        src.desc,
        os_name(tgt.os),
        tgt.archs,
        plan.len(),
        njobs
    );

    let pb = ProgressBar::new(njobs);
    pb.set_style(ProgressStyle::with_template("{bar:40} {pos}/{len} {per_sec} eta {eta}").unwrap());
    let t0 = Instant::now();
    let keep = args.keep.max(args.top).max(1);

    let mut results: Vec<OffsetResult> = Vec::new();
    for &arch in &tgt.archs {
        for &(si, lo, count) in &plan {
            let seg = &src.segs[si];
            let part = (0..count)
                .into_par_iter()
                .map_init(
                    || Worker::new(arch, tgt.os),
                    |w, i| {
                        let off = (lo + i * stride) as usize;
                        let addr = seg.addr + off as u64;
                        if cfg.trace {
                            pb.suspend(|| {
                                println!("=== {addr:#x} arch {}", target::arch_name(arch))
                            });
                        }
                        let mut r = w.emulate_at(&seg.bytes, off, &cfg);
                        r.seg = si;
                        r.addr = addr;
                        if args.verbose >= 1 {
                            pb.suspend(|| {
                                println!(
                                    "{addr:#x} {} insns {} unique {} stop {}",
                                    r.arch, r.insns, r.unique, r.stop
                                )
                            });
                        }
                        pb.inc(1);
                        r
                    },
                )
                // keep only the best `keep` results per thread chunk
                .fold(Vec::new, |mut acc, r| {
                    acc.push(r);
                    if acc.len() >= 2 * keep {
                        best(&mut acc, keep);
                    }
                    acc
                })
                .reduce(Vec::new, |mut a, b| {
                    a.extend(b);
                    best(&mut a, keep);
                    a
                });
            results.extend(part);
            best(&mut results, keep);
        }
    }
    pb.finish_and_clear();
    eprintln!("done in {:.2}s", t0.elapsed().as_secs_f64());
    results.sort_by(rank);

    if args.json {
        let rows: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let mut v = serde_json::to_value(r).unwrap();
                v["region"] = src.label(r.seg, r.offset).into();
                v
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        return;
    }

    println!(
        "{:>5}  {:>w$}  {:>5}  {:>8}  {:>7}  {:<8}  {}",
        "rank",
        if src.is_memory { "address" } else { "offset" },
        "arch",
        "insns",
        "unique",
        "stop",
        "region",
        w = if src.is_memory { 14 } else { 10 }
    );
    for (i, r) in results.iter().take(args.top).enumerate() {
        println!(
            "{:>5}  {}  {:>5}  {:>8}  {:>7}  {:<8}  {}",
            i + 1,
            addr_fmt(r.addr),
            r.arch,
            r.insns,
            r.unique,
            r.stop,
            src.label(r.seg, r.offset)
        );
    }
}

/// Ranking: more distinct addresses first, then more instructions.
fn rank(a: &OffsetResult, b: &OffsetResult) -> Ordering {
    b.unique
        .cmp(&a.unique)
        .then(b.insns.cmp(&a.insns))
        .then(a.addr.cmp(&b.addr))
}

/// Keep the `n` best results (unordered).
fn best(v: &mut Vec<OffsetResult>, n: usize) {
    if v.len() > n {
        v.select_nth_unstable_by(n - 1, rank);
        v.truncate(n);
    }
}

fn parse_num(s: &str) -> Result<u64, String> {
    let r = match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    r.map_err(|e| e.to_string())
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
