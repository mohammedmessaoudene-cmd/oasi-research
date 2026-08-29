use osia_core_r1::ledger::{Ledger, recover_valid_prefix, verify_reader};
use osia_core_r1::model::{BodyState, CommitRequest, Decision, SafetyLease, validate_commit};
use osia_core_r1::protocol::{
    AuthoritySnapshot, BoundExpectedAck, ExpectedAck, bound_work_ack, bound_work_request, hello,
    parse_bound_request, parse_request, validate_bound_ack, validate_hello, work_ack, work_digest,
    work_request,
};
use osia_core_r1::runtime::ChildProcess;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MILLION: u64 = 1_000_000;

fn output_dir() -> PathBuf {
    let path = std::env::var_os("OASI_R1_R5_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("oasi-r1-r5-test-output-{}", std::process::id()))
        });
    fs::create_dir_all(&path).expect("create R1-R5 output directory");
    path
}

fn unique_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("oasi-r1-r5-{label}-{}-{nonce}", std::process::id()))
}

fn fixture() -> (BodyState, SafetyLease, CommitRequest) {
    let body = BodyState {
        body_uid: 11,
        epoch: 22,
        generation: 33,
        certificate: 44,
        quarantined: false,
    };
    let lease = SafetyLease {
        body_uid: 11,
        epoch: 22,
        generation: 33,
        certificate: 44,
        valid_until_ns: 1_000,
        principal_id: 55,
        resource_id: 66,
        action_id: 77,
    };
    let request = CommitRequest {
        now_ns: 999,
        principal_id: 55,
        resource_id: 66,
        action_id: 77,
    };
    (body, lease, request)
}

fn expected_case(index: u64) -> (BodyState, Option<SafetyLease>, CommitRequest, Decision) {
    let (mut body, mut lease, mut request) = fixture();
    let mut present = true;
    let expected = match index % 11 {
        0 => Decision::Allow,
        1 => {
            present = false;
            Decision::BlockNoLease
        }
        2 => {
            body.quarantined = true;
            Decision::BlockQuarantine
        }
        3 => {
            lease.body_uid ^= 1;
            Decision::BlockBodyUid
        }
        4 => {
            lease.epoch += 1;
            Decision::BlockEpoch
        }
        5 => {
            lease.generation += 1;
            Decision::BlockGeneration
        }
        6 => {
            lease.certificate ^= 1;
            Decision::BlockCertificate
        }
        7 => {
            request.now_ns = lease.valid_until_ns;
            Decision::BlockExpired
        }
        8 => {
            request.principal_id += 1;
            Decision::BlockPrincipal
        }
        9 => {
            request.resource_id += 1;
            Decision::BlockResource
        }
        _ => {
            request.action_id += 1;
            Decision::BlockAction
        }
    };
    (body, present.then_some(lease), request, expected)
}

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd must be available")
        .count()
}

fn status_value(name: &str) -> u64 {
    let text = fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| {
                value
                    .split_whitespace()
                    .next()
                    .expect("status value")
                    .parse::<u64>()
                    .expect("numeric status value")
            })
        })
        .expect("status field")
}

#[test]
fn million_scale_and_resource_assurance() {
    let out = output_dir();
    let fd_before = fd_count();
    let rss_before_kib = status_value("VmRSS");
    let threads_before = status_value("Threads");

    let mut decision_counts = [0_u64; 11];
    for index in 0..MILLION {
        let (body, lease, request, expected) = expected_case(index);
        let observed = validate_commit(&body, lease.as_ref(), &request);
        assert_eq!(observed, expected, "state-machine mismatch at {index}");
        decision_counts[observed as usize] += 1;
    }
    assert!(decision_counts.iter().all(|count| *count > 0));

    let mut protocol_valid = 0_u64;
    let mut protocol_rejected = 0_u64;
    let mut lcg = 0x051a_c0de_u64;
    for index in 0..MILLION {
        if index % 1_000 == 0 {
            let line = work_request(index + 1, lcg, 17);
            parse_request(line.trim_end()).expect("valid protocol frame rejected");
            protocol_valid += 1;
        } else {
            lcg = lcg
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = usize::try_from((lcg >> 58) + 1).expect("bounded length");
            let mut line = String::with_capacity(length);
            for offset in 0..length {
                let shifted = lcg.rotate_left(u32::try_from(offset % 64).expect("rotation"));
                let byte = 33 + u8::try_from(shifted % 90).expect("ASCII range");
                line.push(char::from(byte));
            }
            assert!(
                parse_request(&line).is_err(),
                "random frame unexpectedly accepted"
            );
            protocol_rejected += 1;
        }
    }
    assert_eq!(protocol_valid + protocol_rejected, MILLION);

    let ledger_path = unique_path("ledger");
    let (body, lease, _) = fixture();
    let mut ledger = Ledger::create(&ledger_path).expect("create baseline ledger");
    ledger
        .record(
            "BEGIN",
            "extreme baseline",
            Decision::Allow,
            &body,
            Some(&lease),
        )
        .expect("record baseline");
    ledger.seal(&body, Some(&lease)).expect("seal baseline");
    drop(ledger);
    let baseline = fs::read(&ledger_path).expect("read baseline");
    assert!(
        verify_reader(Cursor::new(&baseline))
            .expect("verify baseline")
            .passed()
    );
    let interrupted_path = unique_path("interrupted-ledger");
    let mut interrupted = baseline.clone();
    interrupted.extend_from_slice(b"{\"torn\":");
    fs::write(&interrupted_path, interrupted).expect("write interrupted ledger fixture");
    assert!(
        recover_valid_prefix(&interrupted_path)
            .expect("recover verified ledger prefix")
            .passed()
    );
    assert_eq!(
        fs::read(&interrupted_path).expect("read recovered ledger"),
        baseline
    );
    fs::remove_file(&interrupted_path).expect("remove recovered ledger fixture");
    let mutable_positions: Vec<usize> = baseline
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte != b'\n').then_some(index))
        .collect();
    assert!(!mutable_positions.is_empty());
    for index in 0..MILLION {
        let mut mutated = baseline.clone();
        let position =
            mutable_positions[usize::try_from(index).expect("index") % mutable_positions.len()];
        mutated[position] ^= 1;
        let report = verify_reader(Cursor::new(mutated)).expect("ledger fuzz verifier IO");
        assert!(!report.passed(), "mutated ledger accepted at {index}");
    }
    fs::remove_file(&ledger_path).expect("remove temporary ledger");

    let mut concurrency_operations = 0_u64;
    for producers in [1_usize, 2, 4, 8, 16, 32] {
        for schedule in 0..100_u64 {
            let barrier = Arc::new(Barrier::new(producers));
            let counter = Arc::new(AtomicU64::new(0));
            let mut workers = Vec::with_capacity(producers);
            for producer in 0..producers {
                let barrier = Arc::clone(&barrier);
                let counter = Arc::clone(&counter);
                workers.push(thread::spawn(move || {
                    barrier.wait();
                    for iteration in 0..64_u64 {
                        let index = schedule
                            .wrapping_mul(65_537)
                            .wrapping_add(u64::try_from(producer).expect("producer"))
                            .wrapping_add(iteration);
                        let (body, lease, request, expected) = expected_case(index);
                        assert_eq!(validate_commit(&body, lease.as_ref(), &request), expected);
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            for worker in workers {
                worker.join().expect("concurrency worker panicked");
            }
            let expected = u64::try_from(producers).expect("producers") * 64;
            assert_eq!(counter.load(Ordering::Relaxed), expected);
            concurrency_operations += expected;
        }
    }

    let (sender, receiver) = mpsc::channel::<u64>();
    let event_counter = Arc::new(AtomicU64::new(0));
    let mut event_workers = Vec::new();
    for _producer in 0..32_u64 {
        let sender = sender.clone();
        event_workers.push(thread::spawn(move || {
            let base = MILLION / 32;
            for _ in 0..base {
                sender.send(1).expect("event receiver alive");
            }
        }));
    }
    drop(sender);
    for value in receiver {
        event_counter.fetch_add(value, Ordering::Relaxed);
    }
    for worker in event_workers {
        worker.join().expect("event producer panicked");
    }
    assert_eq!(event_counter.load(Ordering::Relaxed), MILLION);

    let mut child_lifecycles = 0_u64;
    for _ in 0..10_000 {
        let status = Command::new("/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn disposable child");
        assert!(status.success());
        child_lifecycles += 1;
    }

    let storage_dir = unique_path("storage-failure");
    fs::create_dir(&storage_dir).expect("create storage failure fixture");
    assert!(
        Ledger::create(&storage_dir).is_err(),
        "directory accepted as ledger file"
    );
    fs::remove_dir(&storage_dir).expect("remove storage failure fixture");

    let fd_after = fd_count();
    let rss_after_kib = status_value("VmRSS");
    let threads_after = status_value("Threads");
    assert!(
        fd_after <= fd_before + 2,
        "file descriptor growth exceeded bound"
    );
    assert!(
        threads_after <= threads_before + 1,
        "thread growth exceeded bound"
    );
    assert!(
        rss_after_kib <= rss_before_kib + 65_536,
        "resident memory growth exceeded 64 MiB bound"
    );

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"oasi-core-r1-r5-extreme-assurance-1\",\n",
            "  \"state_machine_transitions\": {MILLION},\n",
            "  \"decision_counts\": {decision_counts:?},\n",
            "  \"protocol_frames\": {MILLION},\n",
            "  \"protocol_valid\": {protocol_valid},\n",
            "  \"protocol_rejected\": {protocol_rejected},\n",
            "  \"ledger_mutations\": {MILLION},\n",
            "  \"ledger_mutations_rejected\": {MILLION},\n",
            "  \"interrupted_ledger_valid_prefix_recovered\": true,\n",
            "  \"concurrency_levels\": [1, 2, 4, 8, 16, 32],\n",
            "  \"schedules_per_level\": 100,\n",
            "  \"concurrency_operations\": {concurrency_operations},\n",
            "  \"event_wakeups\": {MILLION},\n",
            "  \"child_lifecycles\": {child_lifecycles},\n",
            "  \"fd_before\": {fd_before},\n",
            "  \"fd_after\": {fd_after},\n",
            "  \"rss_before_kib\": {rss_before_kib},\n",
            "  \"rss_after_kib\": {rss_after_kib},\n",
            "  \"threads_before\": {threads_before},\n",
            "  \"threads_after\": {threads_after},\n",
            "  \"storage_failure_fail_closed\": true,\n",
            "  \"deadlocks\": 0,\n",
            "  \"livelocks\": 0,\n",
            "  \"orphan_processes\": 0,\n",
            "  \"pass\": true\n",
            "}}\n"
        ),
        MILLION = MILLION,
        decision_counts = decision_counts,
        protocol_valid = protocol_valid,
        protocol_rejected = protocol_rejected,
        concurrency_operations = concurrency_operations,
        child_lifecycles = child_lifecycles,
        fd_before = fd_before,
        fd_after = fd_after,
        rss_before_kib = rss_before_kib,
        rss_after_kib = rss_after_kib,
        threads_before = threads_before,
        threads_after = threads_after,
    );
    fs::write(out.join("R1_R5_EXTREME_ASSURANCE.json"), report)
        .expect("write extreme assurance report");
}

fn python_child(source: &str) -> ChildProcess {
    ChildProcess::spawn_program(Path::new("/usr/bin/python3"), &["-c", source])
        .expect("spawn Python child")
}

fn signal_child(child: &ChildProcess, signal: &str) {
    let status = Command::new("/bin/kill")
        .arg(signal)
        .arg(child.process_id().to_string())
        .status()
        .expect("execute kill");
    assert!(status.success(), "kill command failed");
}

#[test]
fn protocol_crash_signal_and_frame_assurance() {
    let out = output_dir();
    let request = work_request(1, 2, 3);
    let expected = ExpectedAck::Work {
        id: 1,
        nonce: 2,
        actions: 3,
        digest: work_digest(1, 3),
    };

    let mut exit_before_ack = python_child("import sys; sys.exit(7)");
    assert!(exit_before_ack.transact(&request, expected).is_err());
    assert!(exit_before_ack.is_reaped());

    let ack = work_ack(1, 2, 3, work_digest(1, 3));
    let partial_source = format!(
        "import sys\nsys.stdin.readline()\nfor c in {ack:?}:\n sys.stdout.write(c); sys.stdout.flush()\n"
    );
    let mut partial = python_child(&partial_source);
    partial
        .transact(&request, expected)
        .expect("partial ACK transport failed");
    drop(partial);

    let duplicate_source = format!(
        "import sys\nsys.stdin.readline()\nsys.stdout.write({double_ack:?}); sys.stdout.flush()\nsys.stdin.readline()\n",
        double_ack = format!("{ack}{ack}")
    );
    let mut duplicate = python_child(&duplicate_source);
    duplicate
        .transact(&request, expected)
        .expect("first ACK rejected");
    let next_request = work_request(2, 3, 3);
    let next_expected = ExpectedAck::Work {
        id: 2,
        nonce: 3,
        actions: 4,
        digest: work_digest(2, 3),
    };
    assert!(duplicate.transact(&next_request, next_expected).is_err());
    assert!(duplicate.is_reaped());

    let mut oversized = python_child(
        "import sys,time; sys.stdin.readline(); print('X'*2048,flush=True); time.sleep(5)",
    );
    assert!(oversized.transact(&request, expected).is_err());
    assert!(oversized.is_reaped());

    let authority_extra = format!(
        "import sys,time; sys.stdin.readline(); print({line:?}+' 11 22 33 44',flush=True); time.sleep(5)",
        line = ack.trim_end()
    );
    let mut extra = python_child(&authority_extra);
    assert!(extra.transact(&request, expected).is_err());
    assert!(extra.is_reaped());

    let mut term = python_child("import time; time.sleep(30)");
    signal_child(&term, "-TERM");
    assert!(term.transact(&request, expected).is_err());
    assert!(term.is_reaped());

    let mut killed = python_child("import time; time.sleep(30)");
    signal_child(&killed, "-KILL");
    assert!(killed.transact(&request, expected).is_err());
    assert!(killed.is_reaped());

    let mut stopped = python_child("import time; time.sleep(30)");
    signal_child(&stopped, "-STOP");
    assert!(stopped.transact(&request, expected).is_err());
    assert!(stopped.is_reaped());

    let exit_after_source = format!(
        "import sys\nsys.stdin.readline()\nsys.stdout.write({ack:?}); sys.stdout.flush()\n"
    );
    let mut exit_after = python_child(&exit_after_source);
    exit_after
        .transact(&request, expected)
        .expect("ACK before exit rejected");
    thread::sleep(Duration::from_millis(50));
    assert!(exit_after.transact(&request, expected).is_err());
    assert!(exit_after.is_reaped());

    assert!(
        ChildProcess::spawn_program(Path::new("/definitely/not/present"), &[]).is_err(),
        "missing executable unexpectedly spawned"
    );

    let authority = AuthoritySnapshot {
        body_uid: 11,
        epoch: 22,
        generation: 33,
        certificate: 44,
        principal_id: 55,
        resource_id: 66,
        action_id: 77,
    };
    let bound_request = bound_work_request(9, 10, 11, authority);
    parse_bound_request(bound_request.trim_end()).expect("bound request rejected");
    let bound_expected = BoundExpectedAck::Work {
        id: 9,
        nonce: 10,
        actions: 12,
        digest: work_digest(9, 11),
        authority,
    };
    let valid_bound_ack = bound_work_ack(9, 10, 12, work_digest(9, 11), authority);
    validate_bound_ack(valid_bound_ack.trim_end(), bound_expected)
        .expect("valid authority-bound ACK rejected");
    let authority_mutations = [
        AuthoritySnapshot {
            body_uid: authority.body_uid + 1,
            ..authority
        },
        AuthoritySnapshot {
            epoch: authority.epoch + 1,
            ..authority
        },
        AuthoritySnapshot {
            generation: authority.generation + 1,
            ..authority
        },
        AuthoritySnapshot {
            certificate: authority.certificate + 1,
            ..authority
        },
        AuthoritySnapshot {
            principal_id: authority.principal_id + 1,
            ..authority
        },
        AuthoritySnapshot {
            resource_id: authority.resource_id + 1,
            ..authority
        },
        AuthoritySnapshot {
            action_id: authority.action_id + 1,
            ..authority
        },
    ];
    for mutated_authority in authority_mutations {
        let wrong = bound_work_ack(9, 10, 12, work_digest(9, 11), mutated_authority);
        assert!(
            validate_bound_ack(wrong.trim_end(), bound_expected).is_err(),
            "correctly checksummed wrong authority ACK accepted"
        );
    }
    let valid_hello = hello(1234);
    validate_hello(valid_hello.trim_end(), 1234).expect("valid HELLO rejected");
    assert!(validate_hello(valid_hello.trim_end(), 1235).is_err());

    fs::write(
        out.join("R1_R5_PROTOCOL_CRASH_ASSURANCE.json"),
        concat!(
            "{\n",
            "  \"schema\": \"oasi-core-r1-r5-protocol-crash-assurance-1\",\n",
            "  \"exit_before_ack\": true,\n",
            "  \"exit_after_ack\": true,\n",
            "  \"sigterm\": true,\n",
            "  \"sigkill\": true,\n",
            "  \"sigstop_timeout_cleanup\": true,\n",
            "  \"partial_ack\": true,\n",
            "  \"duplicate_ack_rejected\": true,\n",
            "  \"oversize_frame_rejected\": true,\n",
            "  \"authority_extra_fields_rejected\": true,\n",
            "  \"authority_bound_ack_fields_checked\": 7,\n",
            "  \"hello_identity_checked\": true,\n",
            "  \"fork_exec_failure_fail_closed\": true,\n",
            "  \"children_reaped\": true,\n",
            "  \"pass\": true\n",
            "}\n"
        ),
    )
    .expect("write protocol crash report");
}
