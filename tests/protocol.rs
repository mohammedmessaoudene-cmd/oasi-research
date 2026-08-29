use osia_core_r1::protocol::{
    ChildRequest, ExpectedAck, PROTOCOL_VERSION, parse_request, probe_ack, probe_request,
    rollback_ack, rollback_request, stop_ack, stop_request, validate_ack, work_ack, work_digest,
    work_request,
};

#[test]
fn valid_requests_round_trip_through_strict_parser() {
    let cases = [
        (
            work_request(7, 11, 5_000),
            ChildRequest::Work {
                id: 7,
                nonce: 11,
                units: 5_000,
            },
        ),
        (
            rollback_request(8, 12),
            ChildRequest::Rollback { id: 8, nonce: 12 },
        ),
        (
            probe_request(9, 13),
            ChildRequest::Probe { id: 9, nonce: 13 },
        ),
        (
            stop_request(10, 14),
            ChildRequest::Stop { id: 10, nonce: 14 },
        ),
    ];
    for (line, expected) in cases {
        assert_eq!(parse_request(line.trim_end_matches('\n')), Ok(expected),);
    }
}

#[test]
fn every_ack_type_is_validated_exactly() {
    let digest = work_digest(7, 5_000);
    let cases = [
        (
            work_ack(7, 11, 3, digest),
            ExpectedAck::Work {
                id: 7,
                nonce: 11,
                actions: 3,
                digest,
            },
        ),
        (
            rollback_ack(8, 12),
            ExpectedAck::Rollback { id: 8, nonce: 12 },
        ),
        (probe_ack(9, 13), ExpectedAck::Probe { id: 9, nonce: 13 }),
        (stop_ack(10, 14), ExpectedAck::Stop { id: 10, nonce: 14 }),
    ];
    for (line, expected) in cases {
        assert!(validate_ack(line.trim_end_matches('\n'), expected).is_ok());
    }
}

#[test]
fn malformed_or_replayed_acks_are_rejected() {
    let digest = work_digest(7, 5_000);
    let expected = ExpectedAck::Work {
        id: 7,
        nonce: 11,
        actions: 3,
        digest,
    };
    let valid = work_ack(7, 11, 3, digest);
    let valid = valid.trim_end_matches('\n');
    let digest_hex = format!("{digest:016x}");
    let mutants = [
        valid.replacen(PROTOCOL_VERSION, "OSIA-R1R1/0", 1),
        valid.replacen(" ACK WORK ", " ACK PROBE ", 1),
        valid.replacen(" WORK 7 ", " WORK 8 ", 1),
        valid.replacen(" 11 3 ", " 12 3 ", 1),
        valid.replacen(" 3 ", " 4 ", 1),
        valid.replacen(digest_hex.as_str(), "0000000000000000", 1),
        valid[..valid.rfind(' ').expect("checksum separator")].to_owned(),
        format!("{valid} extra"),
        format!(" {valid}"),
        valid.replace(' ', "  "),
    ];
    for mutant in mutants {
        assert!(
            validate_ack(&mutant, expected).is_err(),
            "mutant unexpectedly accepted: {mutant}"
        );
    }

    let mut bad_checksum = valid.as_bytes().to_vec();
    let last = bad_checksum.last_mut().expect("non-empty ACK");
    *last = if *last == b'0' { b'1' } else { b'0' };
    let bad_checksum = String::from_utf8(bad_checksum).expect("ASCII ACK");
    assert!(validate_ack(&bad_checksum, expected).is_err());
}

#[test]
fn malformed_requests_are_rejected_before_work() {
    let valid = work_request(7, 11, 5_000);
    let valid = valid.trim_end_matches('\n');
    let mutants = [
        valid.replacen(PROTOCOL_VERSION, "OSIA-R1R1/0", 1),
        valid.replacen(" REQUEST WORK ", " ACK WORK ", 1),
        valid.replacen(" WORK 7 ", " WORK 07 ", 1),
        valid.replacen(" 11 5000 ", " +11 5000 ", 1),
        valid.replacen(" 5000 ", " 0 ", 1),
        valid.replacen(" 5000 ", " 1000001 ", 1),
        format!("{valid} extra"),
        valid.replace(' ', "\t"),
    ];
    for mutant in mutants {
        assert!(
            parse_request(&mutant).is_err(),
            "mutant unexpectedly accepted: {mutant}"
        );
    }
}

#[test]
fn workload_result_is_observable_and_input_bound() {
    let baseline = work_digest(7, 5_000);
    assert_ne!(baseline, 0);
    assert_ne!(baseline, work_digest(8, 5_000));
    assert_ne!(baseline, work_digest(7, 5_001));
    let ack = work_ack(7, 11, 1, baseline);
    assert!(ack.contains(&format!("{baseline:016x}")));
    assert!(
        validate_ack(
            ack.trim_end_matches('\n'),
            ExpectedAck::Work {
                id: 7,
                nonce: 11,
                actions: 1,
                digest: baseline,
            },
        )
        .is_ok()
    );
}
