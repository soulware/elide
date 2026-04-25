// Proptest coverage for the pending-delete target parser.
//
// The reaper deletes anything `parse_target` returns Ok for. The
// invariant exercised here is the safety contract: no input string
// can produce an Ok target that escapes the supplied volume scope, no
// input can panic the parser, and every Ok result round-trips through
// `to_key`.

use elide_coordinator::pending_delete::{parse_marker_key, parse_target};
use proptest::prelude::*;
use ulid::Ulid;

fn arb_volume() -> impl Strategy<Value = Ulid> {
    any::<u128>().prop_map(Ulid::from)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        ..ProptestConfig::default()
    })]

    /// Arbitrary byte strings must never panic the parser. Either the
    /// input is rejected, or it's a valid target whose `to_key()`
    /// round-trips bit-for-bit.
    #[test]
    fn parse_target_total_function(s in ".{0,256}", v in arb_volume()) {
        match parse_target(&s, v) {
            Ok(target) => {
                prop_assert_eq!(
                    target.to_key().as_ref().to_owned(),
                    s,
                    "round-trip mismatch"
                );
            }
            Err(_) => {}
        }
    }

    /// Volume scope: any Ok result has its volume component equal to the
    /// supplied `expected_vol`. A successful parse cannot reach into a
    /// foreign volume's prefix, even with adversarial inputs.
    #[test]
    fn parse_target_volume_scope(s in ".{0,256}", v in arb_volume()) {
        if let Ok(target) = parse_target(&s, v) {
            // The rendered key must start with `by_id/<v>/`.
            let prefix = format!("by_id/{v}/");
            prop_assert!(
                target.to_key().as_ref().starts_with(&prefix),
                "target {:?} not under expected volume {}",
                target,
                v
            );
        }
    }

    /// Marker-key parser is total too. An Ok result must round-trip when
    /// the components are reconstructed.
    #[test]
    fn parse_marker_key_total_function(s in ".{0,256}") {
        if let Ok((vol, marker)) = parse_marker_key(&s) {
            let reconstructed = format!("by_id/{vol}/pending-delete/{marker}.toml");
            prop_assert_eq!(reconstructed, s);
        }
    }
}
