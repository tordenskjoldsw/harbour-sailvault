//! Measures KDF and unlock costs on the machine it runs on, for example the
//! Jolla Phone. Prints timings only; uses fixture data, no real secrets.
//!
//! Build for the device with `tools/run-kdf-benchmark.sh`.

use std::time::{Duration, Instant};

use sailvault_core::kdbx::{Argon2Variant, CompositeKey, Database, KdfParameters, OuterHeader};

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/kdbx4-aes-argon2d.kdbx");
const LARGE: &[u8] = include_bytes!("../tests/fixtures/kdbx4-1000-entries.kdbx");
const RUNS: u32 = 3;

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn time_kdf(parameters: &KdfParameters, key: &CompositeKey) -> Duration {
    median(
        (0..RUNS)
            .map(|_| {
                let start = Instant::now();
                parameters
                    .transform(key)
                    .expect("benchmark parameters are valid");
                start.elapsed()
            })
            .collect(),
    )
}

fn argon2(
    variant: Argon2Variant,
    iterations: u64,
    memory_mib: u64,
    parallelism: u32,
) -> KdfParameters {
    KdfParameters::Argon2 {
        variant,
        iterations,
        memory_bytes: memory_mib << 20,
        parallelism,
        version: 0x13,
        salt: vec![0x5a; 32],
    }
}

fn main() {
    let key = CompositeKey::new(Some(b"benchmark"), None).expect("password is set");

    println!("kdf,parameters,median_ms");
    for (variant, label) in [
        (Argon2Variant::Argon2d, "argon2d"),
        (Argon2Variant::Argon2id, "argon2id"),
    ] {
        for (iterations, memory_mib, parallelism) in
            [(2, 64, 2), (10, 64, 2), (2, 256, 2), (2, 64, 8)]
        {
            let elapsed = time_kdf(&argon2(variant, iterations, memory_mib, parallelism), &key);
            println!(
                "{label},t={iterations} m={memory_mib}MiB p={parallelism},{}",
                elapsed.as_millis()
            );
        }
    }

    let rounds = 1_000_000;
    let aes = KdfParameters::AesKdf {
        rounds,
        seed: [0x5a; 32],
    };
    let elapsed = time_kdf(&aes, &key);
    println!("aes-kdf,rounds={rounds},{}", elapsed.as_millis());
    println!(
        "aes-kdf,rounds_per_second,{}",
        (rounds as f64 / elapsed.as_secs_f64()) as u64
    );

    let fixture_key = CompositeKey::new(Some(b"sailvault-fixture"), None).expect("password is set");
    let open = median(
        (0..RUNS)
            .map(|_| {
                let start = Instant::now();
                Database::open(FIXTURE, &fixture_key).expect("fixture opens");
                start.elapsed()
            })
            .collect(),
    );
    let fixture_kdf = time_kdf(
        &OuterHeader::parse(FIXTURE).expect("fixture header").0.kdf,
        &fixture_key,
    );
    println!("open,fixture total,{}", open.as_millis());
    println!(
        "open,fixture without KDF,{}",
        open.saturating_sub(fixture_kdf).as_millis()
    );

    let large_open = median(
        (0..RUNS)
            .map(|_| {
                let start = Instant::now();
                Database::open(LARGE, &fixture_key).expect("large fixture opens");
                start.elapsed()
            })
            .collect(),
    );
    let large_kdf = time_kdf(
        &OuterHeader::parse(LARGE).expect("large header").0.kdf,
        &fixture_key,
    );
    println!("large,open total (1000 entries),{}", large_open.as_millis());
    println!(
        "large,open without KDF,{}",
        large_open.saturating_sub(large_kdf).as_millis()
    );

    let database = Database::open(LARGE, &fixture_key).expect("large fixture opens");
    let list_root = median(
        (0..RUNS)
            .map(|_| {
                let start = Instant::now();
                let root = database.root_group().expect("root group");
                let rows =
                    root.groups().map(|g| g.name().len()).sum::<usize>() + root.entries().count();
                std::hint::black_box(rows);
                start.elapsed()
            })
            .collect(),
    );
    println!(
        "large,list root group,{}",
        list_root.as_micros() as f64 / 1000.0
    );
    for query in ["user0500", "example"] {
        let search = median(
            (0..RUNS)
                .map(|_| {
                    let start = Instant::now();
                    std::hint::black_box(database.search(query).expect("search").len());
                    start.elapsed()
                })
                .collect(),
        );
        println!(
            "large,search \"{query}\",{}",
            search.as_micros() as f64 / 1000.0
        );
    }
}
