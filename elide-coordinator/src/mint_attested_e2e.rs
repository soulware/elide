//! End-to-end proof of the attested credential loop over the **shipped**
//! elide role inventory: a real mint daemon (the hermetic `mint-e2e`
//! harness from the mint workspace), a real coord B discharge listener
//! (`elide-attestation`), and this crate's own enrollment + assume-role
//! client as coord A. The mint config is `mint/examples/mint-elide.toml`
//! itself, patched only for paths, the attestation location, and the
//! colocated demo auth role; the sealed templates are the shipped
//! `mint/examples/elide_roles/*.json`.
//!
//! Ignored by default: it spawns the mint workspace's binaries and binds
//! sockets. Build them first, then point the env vars at them:
//!
//! ```sh
//! (cd mint && cargo build --bin mint --features e2e-harness --bin mint-e2e)
//! MINT_BIN=mint/target/debug/mint MINT_E2E_BIN=mint/target/debug/mint-e2e \
//!   cargo test -p elide-coordinator --bin elide-coordinator -- --ignored attested_loop
//! ```
//!
//! CI runs this in the `attested-e2e` job.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
            "{var} not set; build the mint workspace bins first:\n  \
             (cd mint && cargo build --bin mint --features e2e-harness --bin mint-e2e)\n\
             and point MINT_BIN / MINT_E2E_BIN at mint/target/debug/"
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

    // The mint config is the shipped elide inventory, patched for the
    // test root. The attestation location stays the shipped value — it
    // is the authority's identity, never dialled; the connection is the
    // coord B UDS below. [auth.demo] is inserted because the operator
    // gates (login / seal / invite / approve) need an issuer and
    // production's is a separate auth-service binary.
    let repo_mint = Path::new(env!("CARGO_MANIFEST_DIR")).join("../mint");
    let shipped =
        std::fs::read_to_string(repo_mint.join("examples/mint-elide.toml")).expect("mint-elide");
    let mut cfg_doc: toml::Value = toml::from_str(&shipped).expect("parse mint-elide.toml");
    let location = cfg_doc["attestation"]["location"]
        .as_str()
        .expect("shipped [attestation].location")
        .to_owned();
    let mint_sock = root_p.join("mint.sock");
    let auth_sock = root_p.join("auth.sock");
    let coord_b_sock = root_p.join("coord-b.sock");
    {
        let tbl = cfg_doc.as_table_mut().expect("config table");
        let mut set = |k: &str, v: String| {
            tbl.insert(k.into(), toml::Value::String(v));
        };
        set("data_dir", root_p.join("mint_data").display().to_string());
        set(
            "roles_dir",
            repo_mint.join("examples/elide_roles").display().to_string(),
        );
        set("socket", mint_sock.display().to_string());
        drop(set);
        // Colocate the demo auth role under the shipped [auth] table.
        let mut demo = toml::value::Table::new();
        demo.insert("enabled".into(), toml::Value::Boolean(true));
        demo.insert(
            "socket".into(),
            toml::Value::String(auth_sock.display().to_string()),
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
        attestation_location: Some(location.clone()),
        attestation_transport: Some(format!("unix:{}", coord_b_sock.display())),
    };
    // The operator session `mint login` wrote, read from the same store
    // the production command loads it from.
    let session_dir = home.join(".config/mint");
    let session = enroll::OperatorSession {
        session: std::fs::read_to_string(session_dir.join("session"))
            .expect("session written by mint login")
            .trim()
            .to_owned(),
        transport: std::fs::read_to_string(session_dir.join("auth-transport"))
            .expect("auth transport written by mint login")
            .trim()
            .to_owned(),
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
                Duration::from_secs(60),
                false,
                &session,
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
        .expect("enrollment completes");

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

    // The loop itself: every role assumed through the sealed surface.
    let endpoint = MintEndpoint::new(&mint_cfg, coord_dir.clone(), identity.clone());

    // A coord role carries no attestation TPC; no discharge is fetched.
    endpoint
        .assume_role("coord-ro", 3600, AssumeTarget::Coord)
        .await
        .expect("coord-ro assumes without a discharge");

    // volume-rw: possession of owned's volume.key + binding liveness,
    // vouched by coord B, rendered by mint as the by_id/<owned> scope.
    let rw = endpoint
        .assume_role("volume-rw", 3600, AssumeTarget::VolumeRw(owned))
        .await
        .expect("volume-rw round trip");
    assert!(!rw.access_key_id.is_empty(), "vended keypair");

    // volume-ro: the fork's parent is in owned's read set; the leaf
    // reading its own prefix is the degenerate target == owned case.
    endpoint
        .assume_role(
            "volume-ro",
            3600,
            AssumeTarget::VolumeRo {
                owned,
                target: parent,
            },
        )
        .await
        .expect("volume-ro round trip");
    endpoint
        .assume_role(
            "volume-ro",
            3600,
            AssumeTarget::VolumeRo {
                owned,
                target: owned,
            },
        )
        .await
        .expect("volume-ro leaf-self round trip");

    // A volume outside owned's read set: coord B refuses the discharge,
    // so the assume never reaches mint.
    let stranger = Ulid::new();
    let err = match endpoint
        .assume_role(
            "volume-ro",
            3600,
            AssumeTarget::VolumeRo {
                owned,
                target: stranger,
            },
        )
        .await
    {
        Ok(_) => panic!("a volume outside the read set must not be vouched"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("coord B discharge"),
        "refusal happens at coord B, got: {err}"
    );

    // Fail-closed: the sealed template demands `attested.volume`, so a
    // client not configured for attestation presents an undischarged TPC
    // and mint refuses the volume role outright.
    let blind_cfg = MintConfig {
        attestation_location: None,
        attestation_transport: None,
        ..mint_cfg.clone()
    };
    let blind = MintEndpoint::new(&blind_cfg, coord_dir.clone(), identity.clone());
    let err = match blind
        .assume_role("volume-rw", 3600, AssumeTarget::VolumeRw(owned))
        .await
    {
        Ok(_) => panic!("an undischarged attestation TPC must not vend"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("401"),
        "mint refuses the undischarged primary, got: {err}"
    );
}
