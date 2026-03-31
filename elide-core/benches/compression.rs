/// Benchmark: zstd level-1 vs lz4_flex for 4KB block compression and decompression.
///
/// Three block types:
///   zeros     — all-zero block (best-case compressible)
///   text      — repeated ASCII text (realistic low-medium entropy)
///   random    — pseudo-random bytes (incompressible; both paths skip in production)
///
/// The "random" case is included to confirm the skip is warranted and to measure
/// the cost of the entropy check itself.
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const BLOCK_SIZE: usize = 4096;

fn make_zeros() -> Vec<u8> {
    vec![0u8; BLOCK_SIZE]
}

fn make_text() -> Vec<u8> {
    // Repeating ASCII text — similar entropy to typical ext4 metadata / small files.
    let template = b"The quick brown fox jumps over the lazy dog. \
                     Pack my box with five dozen liquor jugs. \
                     How vexingly quick daft zebras jump!\n";
    let mut buf = Vec::with_capacity(BLOCK_SIZE);
    while buf.len() < BLOCK_SIZE {
        let remaining = BLOCK_SIZE - buf.len();
        buf.extend_from_slice(&template[..remaining.min(template.len())]);
    }
    buf.truncate(BLOCK_SIZE);
    buf
}

fn make_random() -> Vec<u8> {
    // Simple LCG — deterministic, fast, high entropy.
    let mut buf = Vec::with_capacity(BLOCK_SIZE);
    let mut state: u64 = 0xdeadbeef_cafebabe;
    for _ in 0..BLOCK_SIZE {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        buf.push((state >> 33) as u8);
    }
    buf
}

// ---------------------------------------------------------------------------
// Compression benchmarks
// ---------------------------------------------------------------------------

fn bench_compress(c: &mut Criterion) {
    let cases: &[(&str, Vec<u8>)] = &[
        ("zeros", make_zeros()),
        ("text", make_text()),
        ("random", make_random()),
    ];

    let mut group = c.benchmark_group("compress_4k");

    for (name, data) in cases {
        group.throughput(Throughput::Bytes(BLOCK_SIZE as u64));

        group.bench_with_input(BenchmarkId::new("zstd_l1", name), data, |b, data| {
            b.iter(|| zstd::bulk::compress(data, 1).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("lz4_flex", name), data, |b, data| {
            b.iter(|| lz4_flex::compress_prepend_size(data));
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Decompression benchmarks
// ---------------------------------------------------------------------------

fn bench_decompress(c: &mut Criterion) {
    let cases: &[(&str, Vec<u8>)] = &[
        ("zeros", make_zeros()),
        ("text", make_text()),
        // random blocks are not compressed in production; skip decompression benchmark
    ];

    let mut group = c.benchmark_group("decompress_4k");

    for (name, data) in cases {
        let zstd_compressed = zstd::bulk::compress(data, 1).unwrap();
        let lz4_compressed = lz4_flex::compress_prepend_size(data);

        group.throughput(Throughput::Bytes(BLOCK_SIZE as u64));

        group.bench_with_input(
            BenchmarkId::new("zstd", name),
            &zstd_compressed,
            |b, compressed| {
                b.iter(|| zstd::decode_all(compressed.as_slice()).unwrap());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("lz4_flex", name),
            &lz4_compressed,
            |b, compressed| {
                b.iter(|| lz4_flex::decompress_size_prepended(compressed).unwrap());
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Compressed size comparison (single-shot, printed via eprintln — not timed)
// ---------------------------------------------------------------------------

fn bench_ratio(c: &mut Criterion) {
    let cases: &[(&str, Vec<u8>)] = &[
        ("zeros", make_zeros()),
        ("text", make_text()),
        ("random", make_random()),
    ];

    // Print sizes once so they appear in the terminal output alongside timings.
    for (name, data) in cases {
        let zstd_len = zstd::bulk::compress(data, 1).unwrap().len();
        let lz4_len = lz4_flex::compress_prepend_size(data).len();
        eprintln!(
            "[ratio] {name}: raw={BLOCK_SIZE}  zstd_l1={zstd_len} ({:.1}%)  lz4_flex={lz4_len} ({:.1}%)",
            100.0 * zstd_len as f64 / BLOCK_SIZE as f64,
            100.0 * lz4_len as f64 / BLOCK_SIZE as f64,
        );
    }

    // A trivial benchmark so criterion includes this group in its run.
    let mut group = c.benchmark_group("ratio_noop");
    group.bench_function("noop", |b| b.iter(|| {}));
    group.finish();
}

criterion_group!(benches, bench_compress, bench_decompress, bench_ratio);
criterion_main!(benches);
