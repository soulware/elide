# Hand-off: `[attestation.demo].k_m_b` literal (mint repo)

**Status: cross-repo interface spec for the `soulware/mint` session.**
Retained as the reference record of the mint ↔ coordinator `K_M-B` sharing
contract. References are to `soulware/mint@main`.

## Goal

Let mint source `K_M-B` from a config literal shared with the coordinator,
instead of generating it at first boot. This is the `K_M-B` analog of the
`[auth.demo].k_m_a` path that already exists — **implement it by mirroring
`K_M-A` exactly.**

## Why

The Elide coordinator runs as the attestation authority (coord B) and now
carries `[attestation] k_m_b` as a base64 literal (elide PR #611). mint
seals attestation CIDs under `K_M-B`; coord B opens them. For the seal and
the open to agree, both sides must hold the *same* key. Today mint
*generates* `K_M-B` on first start (`Store::init_k_m_b`, no `configured`
arm), so a coordinator deployed with a literal opens CIDs under a key mint
never used → the discharge CID fails to open. Sharing the literal closes
that gap — exactly as `[auth.demo].k_m_a` does for the operator discharges.

This is the last step before `volume start vol1` finalizes on the Fly demo.

## Scope: config sourcing only — no protocol change

The CID seal/open construction, the discharge MAC, the `mint-macaroon-v6`
domain, and `testdata/mint-discharge-vectors.json` are all **unchanged**.
Only where the 32 bytes of `K_M-B` come from changes. No DOMAIN bump, no
vector regeneration.

## Changes (each mirrors the `k_m_a` site)

### `src/config.rs`

1. **`RawDemoAttestation`** — add the field next to `socket`, mirroring
   `RawDemoAuth.k_m_a`:

   ```rust
   /// `K_M-B`, the attestation TPC-CID wrapping key, as standard base64 of
   /// 32 bytes. Supplied only in the distributed demo, where mint and the
   /// attestation coordinator run on separate hosts and both source the
   /// *same* value from config so the coordinator opens attestation CIDs
   /// without holding a key mint generated. Omit for the single-process
   /// fixture, where mint generates `K_M-B` on first start.
   #[serde(default)]
   pub k_m_b: Option<String>,
   ```

   Update the existing `socket` doc that says "`K_M-B` is generated on first
   start" to "generated on first start when `k_m_b` is omitted."

2. **`ConfigError`** — add `BadDemoKMB { reason: String }` mirroring
   `BadDemoKMA`. Suggested: factor the shared decode so the two variants
   stay the only difference:

   ```rust
   fn decode_demo_key(value: &str) -> Result<[u8; 32], String> { /* current
       decode_demo_k_m_a body, returning the reason string */ }

   fn decode_demo_k_m_a(v: &str) -> Result<[u8; 32], ConfigError> {
       decode_demo_key(v).map_err(|reason| ConfigError::BadDemoKMA { reason })
   }
   fn decode_demo_k_m_b(v: &str) -> Result<[u8; 32], ConfigError> {
       decode_demo_key(v).map_err(|reason| ConfigError::BadDemoKMB { reason })
   }
   ```
   (Duplicating the decode body instead is fine — mint's call.)

3. **`DemoAttestation`** (resolved struct) — add `k_m_b: Option<[u8; 32]>`
   mirroring `DemoAuth.k_m_a`.

4. **Build block** — `demo_attestation` is currently a `.map(|d| …)` closure
   that can't use `?`. Convert it to a `match` like `demo_auth` so the
   decode propagates:

   ```rust
   let demo_attestation = match demo_attestation_raw {
       Some(d) => {
           let k_m_b = d.k_m_b.as_deref().map(decode_demo_k_m_b).transpose()?;
           Some(DemoAttestation {
               socket: d.socket.map(PathBuf::from)
                   .unwrap_or_else(|| data_dir.join("attest.sock")),
               k_m_b,
           })
       }
       None => None,
   };
   ```

   The existing `demo_attestation.is_some() && demo_auth.is_none()` →
   `DemoAttestationWithoutDemoAuth` check stays as-is. No mutual-exclusion
   check is needed (mint has no `discharge_key_file` — that is
   coordinator-side only).

### `src/state.rs`

5. **`Store::init_k_m_b`** — give it the same `configured: Option<[u8; 32]>`
   parameter and the same 3-tier precedence as `init_k_m_a` (config →
   on-disk `attestation-shared.key` → generate-if-demo). The body becomes a
   copy of `init_k_m_a`'s, **without** the `org_id` assignment (init_k_m_b
   already omits it):

   ```rust
   pub fn init_k_m_b(
       &mut self,
       dir: &Path,
       demo_enabled: bool,
       configured: Option<[u8; 32]>,
   ) -> io::Result<()> {
       let path = dir.join(K_M_B_FILE);
       let bytes = match configured {
           Some(k) => { /* mirror onto disk when it differs; return k */ }
           None => { /* current load-or-generate-if-demo body */ }
       };
       self.k_m_b = Some(Arc::new(bytes));
       Ok(())
   }
   ```

### `src/main.rs`

6. At the `init_k_m_b` call (currently
   `store.init_k_m_b(&cfg.data_dir, demo_enabled)?;`), thread the literal,
   mirroring the `init_k_m_a` call two lines up:

   ```rust
   let configured = cfg.demo_attestation.as_ref().and_then(|d| d.k_m_b);
   store.init_k_m_b(&cfg.data_dir, demo_enabled, configured)?;
   ```

### Tests (`src/config.rs`)

7. Mirror the three `demo_auth_k_m_a_*` tests for `k_m_b`
   (`decodes_from_standard_base64`, `absent_leaves_it_none`,
   `rejects_malformed_or_wrong_length`). The toml must include **both**
   `[auth.demo]` and `[attestation.demo]` (the latter requires the former).

## Elide-side follow-up (lands with the `MINT_REF` bump)

Once mint ships the above:

- `deploy/mint/mint-fly.toml` — add `k_m_b = "<value>"` under
  `[attestation.demo]`, byte-identical to `deploy/coord/coord.toml`'s
  `[attestation] k_m_b` (currently `8K0oyDybI3jBHjtUYxtrfLKHeniWHK8JmxxpCS/e3IU=`).
- Bump the deploy `MINT_REF` to the commit carrying this change.
- The co-located `[attestation.demo].socket` stands up mint's *own*
  discharge authority — unused in the Elide deploy (the coordinator is coord
  B). Leaving it set is harmless; what Elide consumes from
  `[attestation.demo]` is the `k_m_b` literal.

After both sides carry the same literal, the committed configs converge and
the proven-via-in-container-shim caveat in
`project_demo_auth_shared_kma` is retired for `K_M-B`.
