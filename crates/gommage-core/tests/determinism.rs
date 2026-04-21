//! Determinism regression suite.
//!
//! Loads the shipped stdlib policies + capability mappers and replays a fixed
//! set of fixtures. Asserts that:
//!
//!   1. Each fixture produces the expected decision.
//!   2. Running the fixtures in declared order and in a pseudo-randomised
//!      order (seed 0xC0FFEE) yields byte-identical results per fixture.
//!
//! This is the promise Gommage makes to the user. If this test flakes, the
//! contract is broken. Do not fix the flake by adjusting the test; fix the
//! cause.

use gommage_core::{CapabilityMapper, Decision, EvalResult, ToolCall, evaluate, policy::Policy};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    call: ToolCall,
    expected: Expected,
    #[serde(default)]
    expedition_root: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Expected {
    Allow,
    Gommage {
        #[serde(default)]
        hard_stop: Option<bool>,
    },
    AskPicto {
        required_scope: String,
    },
}

fn repo_root() -> PathBuf {
    // tests/determinism.rs → manifest_dir = crates/gommage-core.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolving repo root")
}

fn load_fixtures() -> Vec<(PathBuf, Fixture)> {
    let fixtures_dir = repo_root().join("tests/determinism/fixtures");
    let mut files: Vec<PathBuf> = fs::read_dir(&fixtures_dir)
        .expect("reading fixtures dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    files.sort();

    files
        .into_iter()
        .map(|p| {
            let raw = fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {p:?}: {e}"));
            let fx: Fixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {p:?}: {e}"));
            (p, fx)
        })
        .collect()
}

fn mapper() -> CapabilityMapper {
    let dir = repo_root().join("capabilities");
    CapabilityMapper::load_from_dir(&dir).expect("loading capabilities")
}

fn policy_for(fixture: &Fixture) -> Policy {
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert(
        "EXPEDITION_ROOT".into(),
        fixture
            .expedition_root
            .clone()
            .unwrap_or_else(|| "/__no_expedition__".into()),
    );
    env.insert("HOME".into(), "/__no_home__".into());
    let dir = repo_root().join("policies");
    Policy::load_from_dir(&dir, &env).expect("loading policies")
}

fn run_fixture(fixture: &Fixture, mapper: &CapabilityMapper) -> EvalResult {
    let pol = policy_for(fixture);
    let caps = mapper.map(&fixture.call);
    evaluate(&caps, &pol)
}

fn assert_matches_expected(path: &Path, fx: &Fixture, eval: &EvalResult) {
    match (&fx.expected, &eval.decision) {
        (Expected::Allow, Decision::Allow) => {}
        (
            Expected::Gommage {
                hard_stop: expected_hs,
            },
            Decision::Gommage { hard_stop, .. },
        ) => {
            if let Some(e) = expected_hs {
                assert_eq!(
                    *e,
                    *hard_stop,
                    "fixture {:?} at {}: hard_stop mismatch (expected {e}, got {hard_stop})",
                    fx.name,
                    path.display()
                );
            }
        }
        (
            Expected::AskPicto {
                required_scope: expected_scope,
            },
            Decision::AskPicto { required_scope, .. },
        ) => {
            assert_eq!(
                expected_scope,
                required_scope,
                "fixture {:?} at {}: scope mismatch",
                fx.name,
                path.display()
            );
        }
        (exp, got) => panic!(
            "fixture {:?} at {}:\n  expected: {exp:?}\n  got:      {got:?}\n  caps:     {:?}",
            fx.name,
            path.display(),
            eval.capabilities
        ),
    }
}

#[test]
fn fixtures_match_expected_decisions() {
    let fixtures = load_fixtures();
    let m = mapper();
    assert!(!fixtures.is_empty(), "no fixtures found");
    for (path, fx) in &fixtures {
        let eval = run_fixture(fx, &m);
        assert_matches_expected(path, fx, &eval);
    }
}

/// The determinism property: evaluating in declared order and in shuffled
/// order must produce the same decision per fixture, byte-for-byte (we compare
/// by the serialized JSON of the decision + the sorted capability list).
#[test]
fn results_are_order_independent() {
    let fixtures = load_fixtures();
    let m = mapper();

    fn canonical(eval: &EvalResult) -> String {
        let mut caps: Vec<String> = eval
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        caps.sort();
        let decision = serde_json::to_string(&eval.decision).unwrap();
        format!("{decision}|{caps:?}")
    }

    let forward: Vec<(String, String)> = fixtures
        .iter()
        .map(|(_, fx)| (fx.name.clone(), canonical(&run_fixture(fx, &m))))
        .collect();

    // Deterministic "shuffle" by sorting on a hash seed — same inputs → same order.
    let mut shuffled = fixtures.clone();
    shuffled.sort_by_key(|(_, fx)| {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        fx.name.hash(&mut h);
        0xC0FFEE_u64 ^ h.finish()
    });
    let shuffled_results: HashMap<String, String> = shuffled
        .iter()
        .map(|(_, fx)| (fx.name.clone(), canonical(&run_fixture(fx, &m))))
        .collect();

    for (name, result) in &forward {
        let s = shuffled_results
            .get(name)
            .expect("fixture present in shuffled run");
        assert_eq!(
            result, s,
            "determinism break on fixture {name:?}:\n  forward:  {result}\n  shuffled: {s}"
        );
    }

    // Also: run the whole forward sweep twice and compare — catches any hidden
    // mutable state in the evaluator.
    let forward_again: Vec<(String, String)> = fixtures
        .iter()
        .map(|(_, fx)| (fx.name.clone(), canonical(&run_fixture(fx, &m))))
        .collect();
    assert_eq!(
        forward, forward_again,
        "two consecutive forward sweeps differ"
    );
}

// `Fixture` needs `Clone` for the shuffle test. Implement manually because
// ToolCall already derives Clone and serde_json::Value is Clone.
impl Clone for Fixture {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            call: self.call.clone(),
            expected: self.expected.clone(),
            expedition_root: self.expedition_root.clone(),
        }
    }
}
