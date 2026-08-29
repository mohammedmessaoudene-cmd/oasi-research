use osia_core_r1::ledger::{LEDGER_SCHEMA, Ledger, verify_path};
use osia_core_r1::model::{BodyState, Decision, SafetyLease};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryLedger {
    path: PathBuf,
}

impl TemporaryLedger {
    fn new(label: &str) -> Self {
        let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "osia-core-r1-r1-{label}-{}-{counter}.jsonl",
            std::process::id()
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryLedger {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn fixture() -> (BodyState, SafetyLease) {
    (
        BodyState {
            body_uid: 1,
            epoch: 2,
            generation: 3,
            certificate: 4,
            quarantined: false,
        },
        SafetyLease {
            body_uid: 1,
            epoch: 2,
            generation: 3,
            certificate: 4,
            valid_until_ns: 100,
            principal_id: 5,
            resource_id: 6,
            action_id: 7,
        },
    )
}

fn write_baseline(path: &Path) {
    let (body, lease) = fixture();
    let mut ledger = Ledger::create(path).expect("create ledger");
    ledger
        .record(
            "TEST_EVENT",
            "ledger round trip",
            Decision::Allow,
            &body,
            Some(&lease),
        )
        .expect("record lease-present event");
    ledger
        .record(
            "QUARANTINE",
            "lease deliberately absent",
            Decision::BlockQuarantine,
            &BodyState {
                quarantined: true,
                ..body
            },
            None,
        )
        .expect("record lease-absent event");
    ledger
        .seal(
            &BodyState {
                quarantined: true,
                ..body
            },
            None,
        )
        .expect("seal ledger");
    assert!(ledger.is_sealed());
    assert_eq!(ledger.entries(), 3);
    assert_eq!(ledger.event_entries(), 2);
}

#[test]
fn autonomous_ledger_round_trip_and_golden_hash() {
    let temporary = TemporaryLedger::new("round-trip");
    write_baseline(temporary.path());
    let report = verify_path(temporary.path()).expect("verify ledger");
    assert!(report.passed(), "{:?}", report.errors);
    assert_eq!(report.entries, 3);
    assert_eq!(report.event_entries, 2);

    let contents = fs::read_to_string(temporary.path()).expect("read ledger");
    assert!(contents.ends_with('\n'));
    assert!(contents.contains(&format!("\"schema\":\"{LEDGER_SCHEMA}\"")));
    assert!(contents.contains("\"lease_principal_id\":5"));
    assert!(contents.contains("\"lease_resource_id\":6"));
    assert!(contents.contains("\"lease_action_id\":7"));
    assert!(contents.contains("\"kind\":\"seal\""));
    assert!(
        contents
            .lines()
            .next()
            .expect("first ledger line")
            .contains("\"hash\":\"e3ec7b815e295c4c\"")
    );
}

#[test]
fn missing_or_modified_authority_fields_are_rejected() {
    let temporary = TemporaryLedger::new("authority-mutation");
    write_baseline(temporary.path());
    let original = fs::read_to_string(temporary.path()).expect("read baseline");

    let mutations = [
        original.replace(",\"lease_action_id\":7", ""),
        original.replace("\"lease_principal_id\":5", "\"lease_principal_id\":6"),
        original.replace("\"certificate\":4", "\"certificate\":9"),
        original.replace("\"lease_present\":true", "\"lease_present\":false"),
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        fs::write(temporary.path(), mutation).expect("write mutation");
        let report = verify_path(temporary.path()).expect("verify mutation");
        assert!(
            !report.passed(),
            "mutation {index} unexpectedly passed verification"
        );
    }
}

#[test]
fn sequence_reorder_duplicate_and_truncation_are_rejected() {
    let temporary = TemporaryLedger::new("structural-mutation");
    write_baseline(temporary.path());
    let original = fs::read_to_string(temporary.path()).expect("read baseline");
    let lines = original.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);

    let reordered = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
    let duplicated = format!("{}\n{}\n{}\n{}\n", lines[0], lines[0], lines[1], lines[2]);
    let without_seal = format!("{}\n{}\n", lines[0], lines[1]);
    let truncated = original[..original.len() - 11].to_owned();
    for (index, mutation) in [reordered, duplicated, without_seal, truncated]
        .iter()
        .enumerate()
    {
        fs::write(temporary.path(), mutation).expect("write structural mutation");
        let report = verify_path(temporary.path()).expect("verify structural mutation");
        assert!(
            !report.passed(),
            "structural mutation {index} unexpectedly passed"
        );
    }
}

#[test]
fn duplicate_and_extra_json_keys_are_rejected() {
    let temporary = TemporaryLedger::new("json-key-mutation");
    write_baseline(temporary.path());
    let original = fs::read_to_string(temporary.path()).expect("read baseline");

    let duplicate = original.replacen("{\"schema\":", "{\"schema\":\"duplicate\",\"schema\":", 1);
    fs::write(temporary.path(), duplicate).expect("write duplicate-key mutation");
    assert!(
        !verify_path(temporary.path())
            .expect("verify duplicate")
            .passed()
    );

    let extra = original.replacen("{\"schema\":", "{\"unexpected\":1,\"schema\":", 1);
    fs::write(temporary.path(), extra).expect("write extra-key mutation");
    assert!(
        !verify_path(temporary.path())
            .expect("verify extra")
            .passed()
    );
}

#[test]
fn sealed_ledger_refuses_additional_records_and_second_seal() {
    let temporary = TemporaryLedger::new("sealed-state");
    let (body, lease) = fixture();
    let mut ledger = Ledger::create(temporary.path()).expect("create ledger");
    ledger
        .record("EVENT", "detail", Decision::Allow, &body, Some(&lease))
        .expect("record event");
    ledger.seal(&body, Some(&lease)).expect("seal ledger");
    assert!(
        ledger
            .record("LATE", "forbidden", Decision::Allow, &body, Some(&lease))
            .is_err()
    );
    assert!(ledger.seal(&body, Some(&lease)).is_err());
}
