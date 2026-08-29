use osia_core_r1::protocol::{ExpectedAck, probe_request};
use osia_core_r1::runtime::ChildProcess;
use std::io;
use std::path::Path;

fn python_child(source: &str) -> io::Result<ChildProcess> {
    ChildProcess::spawn_program(Path::new("python3"), &["-c", source])
}

#[test]
fn malformed_ack_is_rejected_and_child_is_reaped() {
    let mut child = python_child(
        "import sys\nsys.stdin.readline()\nprint('MALFORMED ACK extra', flush=True)\n",
    )
    .expect("spawn fault child");
    let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
    assert!(result.is_err());
    assert!(child.is_reaped());
}

#[test]
fn wrong_identifier_nonce_and_checksum_are_rejected() {
    for line in [
        "OSIA-R1R1/1 ACK PROBE 8 9 0000000000000000",
        "OSIA-R1R1/1 ACK PROBE 7 10 0000000000000000",
        "OSIA-R1R1/1 ACK PROBE 7 9 0000000000000000",
        "OSIA-R1R1/1 ACK PROBE 7 9 0000000000000000 EXTRA",
    ] {
        let source = format!("import sys\nsys.stdin.readline()\nprint({line:?}, flush=True)\n");
        let mut child = python_child(&source).expect("spawn fault child");
        let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
        assert!(result.is_err(), "fault line unexpectedly accepted: {line}");
        assert!(child.is_reaped(), "fault child was not reaped: {line}");
    }
}

#[test]
fn premature_eof_is_rejected_and_child_is_reaped() {
    let mut child = python_child("import sys\nsys.stdin.readline()\n").expect("spawn fault child");
    let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
    assert!(result.is_err());
    assert!(child.is_reaped());
}

#[test]
fn ack_timeout_kills_and_reaps_child() {
    let mut child = python_child("import sys,time\nsys.stdin.readline()\ntime.sleep(60)\n")
        .expect("spawn fault child");
    let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
    assert!(result.is_err());
    assert!(child.is_reaped());
}
