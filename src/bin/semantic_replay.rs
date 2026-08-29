use osia_core_r1::model::{BodyState, CommitRequest, SafetyLease, validate_commit};
use std::io::{self, BufRead};

fn parse_u64(value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.trim().split(',').collect();
        if fields.len() != 18 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected 18 CSV fields",
            ));
        }
        let body = BodyState {
            body_uid: parse_u64(fields[0])?,
            epoch: parse_u64(fields[1])?,
            generation: parse_u64(fields[2])?,
            certificate: parse_u64(fields[3])?,
            quarantined: parse_u64(fields[4])? != 0,
        };
        let present = parse_u64(fields[5])? != 0;
        let lease = SafetyLease {
            body_uid: parse_u64(fields[6])?,
            epoch: parse_u64(fields[7])?,
            generation: parse_u64(fields[8])?,
            certificate: parse_u64(fields[9])?,
            valid_until_ns: parse_u64(fields[10])?,
            principal_id: parse_u64(fields[11])?,
            resource_id: parse_u64(fields[12])?,
            action_id: parse_u64(fields[13])?,
        };
        let request = CommitRequest {
            now_ns: parse_u64(fields[14])?,
            principal_id: parse_u64(fields[15])?,
            resource_id: parse_u64(fields[16])?,
            action_id: parse_u64(fields[17])?,
        };
        let decision = validate_commit(&body, present.then_some(&lease), &request);
        println!("{}", decision as u8);
    }
    Ok(())
}
