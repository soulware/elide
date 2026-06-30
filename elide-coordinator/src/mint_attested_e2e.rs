//! End-to-end proof of the attested credential loop over elide's own
//! mint role inventory: a real mint daemon (the hermetic `mint-e2e`
//! harness from the mint repo, github.com/soulware/mint), a real coord B
//! discharge listener (`elide-attestation`), and this crate's own
//! enrollment + assume-role client as coord A. The mint config and role
//! templates are the elide-owned deployment artifact under `deploy/mint/`
//! (mint is a separate repo; only its binaries are consumed, via MINT_BIN /
//! MINT_E2E_BIN) — this test is the lockstep check that the coordinator
//! client works against exactly those shipped templates. The config is
//! patched only for paths and the colocated demo auth role.
//!
//! Ignored by default: it spawns the mint binaries and binds sockets.
//! Build mint from a sibling `../mint` checkout (clone it there if you
//! don't have one) and point the env vars at the two binaries:
//!
//! ```sh
//! (cd ../mint && cargo build --bin mint --features e2e-harness --bin mint-e2e)
//! MINT_BIN=../mint/target/debug/mint MINT_E2E_BIN=../mint/target/debug/mint-e2e \
//!   cargo test -p elide-coordinator --bin elide-coordinator -- --ignored attested_loop
//! ```
//!
//! CI runs this in the `attested-e2e` job.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use ulid::Ulid;

use elide_attestation::{DischargeState, discharge_router, put_object};
use elide_coordinator::config::MintConfig;
use elide_coordinator::identity::CoordinatorIdentity;
use elide_coordinator::volume_state;
use elide_core::config::VolumeConfig;
use elide_core::name_record::NameRecord;
use elide_core::signing::{
    ParentRef, ProvenanceLineage, VOLUME_KEY_FILE, VOLUME_PROVENANCE_FILE, decode_hex, encode_hex,
    write_provenance,
};
use elide_core::store_keys::{meta_provenance_key, meta_pub_key};
use object_store::ObjectStore;
use object_store::local::LocalFileSystem;

use crate::enroll;
use crate::mint_client::{AssumeTarget, MintEndpoint};

const STEP_TIMEOUT: Duration = Duration::from_secs(30);

fn bin_from_env(var: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(p) => PathBuf::from(p),
        None => panic!(
            "{var} not set; build mint from a sibling ../mint checkout first:\n  \
             (cd ../mint && cargo build --bin mint --features e2e-harness --bin mint-e2e)\n\
             then point MINT_BIN / MINT_E2E_BIN at ../mint/target/debug/"
        ),
    }
}

/// Kills the spawned daemon on scope exit; on a panicking unwind, dumps
/// its captured log first so a CI failure is diagnosable.
struct Daemon {
    child: std::process::Child,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking()
            && let Ok(log) = std::fs::read_to_string(&self.log)
        {
            eprintln!("--- mint-e2e harness log ---\n{log}");
        }
    }
}

/// Run one mint operator CLI command, its per-user session state pinned
/// under `home`. Returns stdout; `Err` carries the full output.
fn mint_cli(bin: &Path, home: &Path, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .unwrap_or_else(|e| panic!("spawning {} {args:?}: {e}", bin.display()));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "mint {args:?} exited {:?}\nstdout: {stdout}\nstderr: {stderr}",
            out.status.code()
        ))
    }
}

async fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {} — did the daemon start?",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Sign and publish a volume's identity the way the coordinator plane
/// does at creation: hex pubkey at `meta/<vol>.pub`, signed lineage at
/// `meta/<vol>.provenance`.
async fn seed_identity(
    store: &dyn ObjectStore,
    vol: Ulid,
    sk: &SigningKey,
    lineage: &ProvenanceLineage,
) {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    write_provenance(dir.path(), sk, VOLUME_PROVENANCE_FILE, lineage).expect("sign provenance");
    let prov = std::fs::read(dir.path().join(VOLUME_PROVENANCE_FILE)).expect("read provenance");
    put_object(store, &meta_provenance_key(vol), prov)
        .await
        .expect("put provenance");
    put_object(
        store,
        &meta_pub_key(vol),
        encode_hex(sk.verifying_key().as_bytes()).into_bytes(),
    )
    .await
    .expect("put pub");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns mint-workspace binaries; needs MINT_BIN + MINT_E2E_BIN (CI: attested-e2e job)"]
async fn attested_loop_over_shipped_templates() {
    let mint_bin = bin_from_env("MINT_BIN");
    let harness_bin = bin_from_env("MINT_E2E_BIN");

    let root = tempfile::TempDir::new().expect("test root");
    let root_p = root.path();
    let coord_dir = root_p.join("coord");
    let bucket_dir = root_p.join("bucket");
    let home = root_p.join("home");
    std::fs::create_dir_all(&coord_dir).expect("coord dir");
    std::fs::create_dir_all(&bucket_dir).expect("bucket dir");
    std::fs::create_dir_all(home.join(".config")).expect("home dir");

    // The shipped deployment artifact (deploy/mint/), patched for the test
    // root. mint is a separate repo; elide owns the config + role templates
    // it runs mint with (only the binaries come from there, via MINT_BIN /
    // MINT_E2E_BIN), so this test runs the real shipped config. mint seals
    // its [attestation].location into the caveat; coord A reads the route
    // from there, never from config — the location is the authority's
    // identity, never dialled, and the connection is the coord B UDS below.
    // [auth.demo] is inserted because the operator gates (login / seal /
    // invite / approve) need an issuer and production's is a separate
    // auth-service binary.
    let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/mint");
    let shipped = std::fs::read_to_string(deploy.join("mint-elide.toml")).expect("mint-elide");
    let mut cfg_doc: toml::Value = toml::from_str(&shipped).expect("parse mint-elide.toml");
    let mint_sock = root_p.join("mint.sock");
    let auth_sock = root_p.join("auth.sock");
    let coord_b_sock = root_p.join("coord-b.sock");
    // The shared-key demo secret: mint sources K_M-A from [auth.demo].k_m_a
    // and the coordinator self-issues its operator discharges under the same
    // value (the DemoIssuer below) — a fixed test key (any 32 bytes).
    let k_m_a: [u8; 32] = [0x5a; 32];

    // `roles_dir` is the rendered output `mint serve` / `mint seal` load; the
    // render step (below) writes it from the shipped role-templates/. The store
    // is local, so the rendered bucket name is cosmetic; any valid name works.
    let rendered_roles = root_p.join("roles");
    {
        let tbl = cfg_doc.as_table_mut().expect("config table");
        {
            let mut set = |k: &str, v: String| {
                tbl.insert(k.into(), toml::Value::String(v));
            };
            set("data_dir", root_p.join("mint_data").display().to_string());
            set("roles_dir", rendered_roles.display().to_string());
            set("socket", mint_sock.display().to_string());
            set(
                "catalog_file",
                deploy.join("catalog.toml").display().to_string(),
            );
        }
        // Colocate the demo auth role under the shipped [auth] table.
        // Presence of the [auth.demo] table is the switch; the socket binds it.
        let mut demo = toml::value::Table::new();
        demo.insert(
            "socket".into(),
            toml::Value::String(auth_sock.display().to_string()),
        );
        demo.insert(
            "k_m_a".into(),
            toml::Value::String(base64::engine::general_purpose::STANDARD.encode(k_m_a)),
        );
        tbl.get_mut("auth")
            .and_then(toml::Value::as_table_mut)
            .expect("[auth] table from shipped config")
            .insert("demo".into(), toml::Value::Table(demo));
    }
    let cfg_path = root_p.join("mint.toml");
    std::fs::write(
        &cfg_path,
        toml::to_string(&cfg_doc).expect("serialise config"),
    )
    .expect("write config");
    let cfg_str = cfg_path.to_str().expect("utf-8 path");

    // Render the shipped role templates the way a real deployment does:
    // `mint render` bakes the `{{build.bucket}}` token from role-templates/ into
    // roles_dir before mint seals them. Running the real command keeps the e2e
    // in lockstep with the documented deploy flow.
    let render_status = std::process::Command::new(&mint_bin)
        .arg("render")
        .arg("--in-dir")
        .arg(deploy.join("role-templates"))
        .arg("--build")
        .arg("bucket=elide-e2e")
        .arg("--out-dir")
        .arg(&rendered_roles)
        .status()
        .expect("spawn mint render");
    assert!(render_status.success(), "mint render failed");

    // The daemon: production serve loop over FakeMinter + local store.
    let log_path = root_p.join("mint-e2e.log");
    let log = std::fs::File::create(&log_path).expect("log file");
    let child = std::process::Command::new(&harness_bin)
        .arg("--config")
        .arg(&cfg_path)
        .stdout(log.try_clone().expect("clone log handle"))
        .stderr(log)
        .spawn()
        .expect("spawn mint-e2e");
    let _daemon = Daemon {
        child,
        log: log_path,
    };
    wait_for_socket(&mint_sock).await;
    wait_for_socket(&auth_sock).await;

    // Operator plane: login, seal the shipped templates, mint the invite.
    mint_cli(
        &mint_bin,
        &home,
        &["login", "--config", cfg_str, "--subject", "e2e-operator"],
    )
    .expect("mint login");
    mint_cli(&mint_bin, &home, &["seal", "--config", cfg_str]).expect("mint seal");
    let invite = mint_cli(&mint_bin, &home, &["invite", "--config", cfg_str])
        .expect("mint invite")
        .trim()
        .to_string();

    // coord B serves over the daemon's demo-generated K_M-B (the
    // documented demo key-sharing shape) and the bucket the test seeds,
    // on a UDS — the co-located off-network shape. The sealed location
    // is never dialled; the transport below supplies the connection.
    let k_m_b_hex = std::fs::read_to_string(root_p.join("mint_data/attestation-shared.key"))
        .expect("attestation-shared.key — the harness generates it when a role attests");
    let k_m_b: [u8; 32] = decode_hex(k_m_b_hex.trim())
        .expect("hex K_M-B")
        .try_into()
        .expect("32-byte K_M-B");
    let store: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(&bucket_dir).expect("bucket store"));
    let coord_b = DischargeState::new(k_m_b, store.clone());
    {
        let sock = coord_b_sock.clone();
        tokio::spawn(async move {
            elide_attestation::serve::serve_uds(sock, discharge_router(coord_b))
                .await
                .expect("coord B serve");
        });
    }
    wait_for_socket(&coord_b_sock).await;

    // Enrollment: the real invite → approve → exchange flow. `run`
    // blocks on operator approval, so it runs as a task while the test
    // plays the operator.
    let identity = Arc::new(CoordinatorIdentity::load_or_generate(&coord_dir).expect("identity"));
    let sub = identity.coordinator_id_str().to_string();
    let mint_cfg = MintConfig {
        url: format!("unix:{}", mint_sock.display()),
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(30),
        attestation_transport: Some(format!("unix:{}", coord_b_sock.display())),
    };
    // The coordinator self-issues its operator discharges from the shared
    // K_M-A (same value mint sources from [auth.demo].k_m_a), stamping the
    // logged-in operator as `sub` — no ~/.config session read.
    let issuer = enroll::SelfMint {
        k_m_a,
        subject: "e2e-operator".to_owned(),
    };
    let enroll_task = {
        let cfg = mint_cfg.clone();
        let identity = identity.clone();
        let coord_dir = coord_dir.clone();
        tokio::spawn(async move {
            enroll::run(
                &cfg,
                &identity,
                &coord_dir,
                &invite,
                enroll::EnrollOptions {
                    wait: Duration::from_secs(60),
                    force: false,
                    profile: enroll::EnrollProfile::Coordinator,
                },
                &issuer,
            )
            .await
        })
    };
    // Approval races the spawned enroll's pending record; retry until it
    // lands.
    let deadline = Instant::now() + STEP_TIMEOUT;
    loop {
        match mint_cli(
            &mint_bin,
            &home,
            &["enroll", "approve", "--config", cfg_str, &sub, "--yes"],
        ) {
            Ok(_) => break,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "approving enrollment for {sub}: {e}"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    enroll_task
        .await
        .expect("enroll task")
        .expect("enrollment completes — coord credentials + volume intermediates");

    // A named, locally-keyed volume to anchor on, forked from a parent:
    // key + name in the coordinator's fork dir (what coord A's discharge
    // request reads), pub + signed lineage + names record in the bucket
    // (what coord B's predicate reads).
    let owned = Ulid::new();
    let parent = Ulid::new();
    let owned_sk = SigningKey::generate(&mut OsRng);
    let parent_sk = SigningKey::generate(&mut OsRng);
    let fork = volume_state::fork_dir(&coord_dir, owned);
    std::fs::create_dir_all(&fork).expect("fork dir");
    std::fs::write(fork.join(VOLUME_KEY_FILE), owned_sk.to_bytes()).expect("volume.key");
    VolumeConfig {
        name: Some("e2e-vol".into()),
        ..Default::default()
    }
    .write(&fork)
    .expect("volume.toml");

    seed_identity(
        store.as_ref(),
        owned,
        &owned_sk,
        &ProvenanceLineage {
            parent: Some(ParentRef {
                volume_ulid: parent.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: parent_sk.verifying_key().to_bytes(),
            }),
            extent_index: Vec::new(),
            oci_source: None,
        },
    )
    .await;
    seed_identity(
        store.as_ref(),
        parent,
        &parent_sk,
        &ProvenanceLineage {
            parent: None,
            extent_index: Vec::new(),
            oci_source: None,
        },
    )
    .await;
    let record = NameRecord::live_minimal(owned, 4 * 1024 * 1024 * 1024);
    put_object(
        store.as_ref(),
        "names/e2e-vol",
        record.to_toml().expect("record toml").into_bytes(),
    )
    .await
    .expect("put names record");

    // The loop itself. Coord roles were minted directly at enrollment;
    // volume roles are attested and per-volume, so the first `assume-role`
    // for a volume *finalizes* its credential from the durable enrollment
    // intermediate — coord B vouches the volume, mint bakes it in — stores it,
    // and renders. Every later `assume-role` reads that stored credential and is
    // a pure render. No operator session or ticket is in this path.
    let endpoint = MintEndpoint::new(&mint_cfg, coord_dir.clone(), identity.clone());

    // A coord role was minted directly at enrollment; assume-role is a
    // pure render with no attestation.
    endpoint
        .assume_role("coord-ro", 3600, AssumeTarget::Coord)
        .await
        .expect("coord-ro assumes without a discharge");

    // volume-rw: first assume finalizes (possession of owned's volume.key +
    // binding liveness, vouched by coord B, baked by mint as the
    // by_id/<owned> scope) then renders.
    let rw = endpoint
        .assume_role("volume-rw", 3600, AssumeTarget::VolumeRw(owned))
        .await
        .expect("volume-rw finalize-on-miss + render");
    assert!(!rw.access_key_id.is_empty(), "vended keypair");

    // volume-ro: the fork's parent is in owned's read set; the leaf
    // reading its own prefix is the degenerate target == owned case. One
    // durable intermediate finalizes for both volumes.
    for target in [parent, owned] {
        endpoint
            .assume_role("volume-ro", 3600, AssumeTarget::VolumeRo { owned, target })
            .await
            .expect("volume-ro finalize-on-miss + render");
    }

    // A volume outside owned's read set: coord B refuses the discharge at
    // finalize, so no credential is ever minted and the first assume fails.
    let stranger = Ulid::new();
    let err = endpoint
        .assume_role(
            "volume-ro",
            3600,
            AssumeTarget::VolumeRo {
                owned,
                target: stranger,
            },
        )
        .await
        .map(|_| ())
        .expect_err("a volume outside the read set must not be vouched");
    assert!(
        err.to_string().contains("coord B discharge"),
        "refusal happens at coord B, got: {err}"
    );

    // Fail-closed: attestation is mandatory and anchored. There is no config
    // knob to skip the discharge — finalize always discharges the
    // intermediate's TPC — and the discharge must anchor on a locally-keyed
    // volume, so a target with no on-disk volume key produces no possession
    // proof, fails before any credential is minted, and leaves nothing
    // stored. Use a not-yet-finalized volume so the call hits finalize-on-miss
    // rather than rendering an already-stored credential.
    let blind_vol = Ulid::new();
    let err = endpoint
        .assume_role("volume-rw", 3600, AssumeTarget::VolumeRw(blind_vol))
        .await
        .map(|_| ())
        .expect_err("a volume with no local key cannot finalize");
    assert!(
        err.to_string().contains("no local volume name"),
        "finalize fails closed without a local anchor, got: {err}"
    );
    assert!(
        !coord_dir
            .join("credentials")
            .join("volume-rw")
            .join(blind_vol.to_string())
            .exists(),
        "no credential is minted when the anchor cannot prove possession",
    );
}
