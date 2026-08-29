//! Strict child-process protocol for the R1-R1 reference runtime.
//!
//! The FNV-1a checksum used here detects accidental corruption in a
//! deterministic transcript. It is not a MAC, signature, identity proof, or
//! cryptographic/hardware attestation.

use crate::model::MAX_WORK_UNITS;
use std::fmt;

pub const PROTOCOL_VERSION: &str = "OSIA-R1R1/1";

const FNV_OFFSET: u64 = 1_469_598_103_934_665_603;
const FNV_PRIME: u64 = 1_099_511_628_211;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildRequest {
    Work { id: u64, nonce: u64, units: u64 },
    Rollback { id: u64, nonce: u64 },
    Probe { id: u64, nonce: u64 },
    Stop { id: u64, nonce: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedAck {
    Work {
        id: u64,
        nonce: u64,
        actions: u64,
        digest: u64,
    },
    Rollback {
        id: u64,
        nonce: u64,
    },
    Probe {
        id: u64,
        nonce: u64,
    },
    Stop {
        id: u64,
        nonce: u64,
    },
}

/// Authority identity captured by the parent and echoed by the disposable
/// child. It is a strict protocol binding, not a cryptographic attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub body_uid: u64,
    pub epoch: u64,
    pub generation: u64,
    pub certificate: u64,
    pub principal_id: u64,
    pub resource_id: u64,
    pub action_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundChildRequest {
    Work {
        id: u64,
        nonce: u64,
        units: u64,
        authority: AuthoritySnapshot,
    },
    Rollback {
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    },
    Probe {
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    },
    Stop {
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundExpectedAck {
    Work {
        id: u64,
        nonce: u64,
        actions: u64,
        digest: u64,
        authority: AuthoritySnapshot,
    },
    Rollback {
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    },
    Probe {
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    },
    Stop {
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    detail: String,
}

impl ProtocolError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ProtocolError {}

fn fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fnv_segment(mut hash: u64, bytes: &[u8]) -> u64 {
    hash = fnv_bytes(hash, &(bytes.len() as u64).to_le_bytes());
    fnv_bytes(hash, bytes)
}

fn protocol_checksum(direction: &str, operation: &str, fields: &[u64]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash = fnv_segment(hash, PROTOCOL_VERSION.as_bytes());
    hash = fnv_segment(hash, direction.as_bytes());
    hash = fnv_segment(hash, operation.as_bytes());
    hash = fnv_bytes(hash, &(fields.len() as u64).to_le_bytes());
    for field in fields {
        hash = fnv_bytes(hash, &field.to_le_bytes());
    }
    hash
}

fn parse_canonical_u64(token: &str, field: &str) -> Result<u64, ProtocolError> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProtocolError::new(format!(
            "{field} is not unsigned decimal"
        )));
    }
    let value = token
        .parse::<u64>()
        .map_err(|_| ProtocolError::new(format!("{field} overflows u64")))?;
    if value.to_string() != token {
        return Err(ProtocolError::new(format!(
            "{field} is not canonical decimal"
        )));
    }
    Ok(value)
}

fn exact_tokens(line: &str, expected_count: usize) -> Result<Vec<&str>, ProtocolError> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() != expected_count {
        return Err(ProtocolError::new(format!(
            "expected {expected_count} tokens, observed {}",
            tokens.len()
        )));
    }
    if tokens.join(" ") != line {
        return Err(ProtocolError::new("non-canonical protocol whitespace"));
    }
    Ok(tokens)
}

pub fn work_request(id: u64, nonce: u64, units: u64) -> String {
    let checksum = protocol_checksum("REQUEST", "WORK", &[id, nonce, units]);
    format!("{PROTOCOL_VERSION} REQUEST WORK {id} {nonce} {units} {checksum:016x}\n")
}

pub fn rollback_request(id: u64, nonce: u64) -> String {
    let checksum = protocol_checksum("REQUEST", "ROLLBACK", &[id, nonce]);
    format!("{PROTOCOL_VERSION} REQUEST ROLLBACK {id} {nonce} {checksum:016x}\n")
}

pub fn probe_request(id: u64, nonce: u64) -> String {
    let checksum = protocol_checksum("REQUEST", "PROBE", &[id, nonce]);
    format!("{PROTOCOL_VERSION} REQUEST PROBE {id} {nonce} {checksum:016x}\n")
}

pub fn stop_request(id: u64, nonce: u64) -> String {
    let checksum = protocol_checksum("REQUEST", "STOP", &[id, nonce]);
    format!("{PROTOCOL_VERSION} REQUEST STOP {id} {nonce} {checksum:016x}\n")
}

pub fn work_ack(id: u64, nonce: u64, actions: u64, digest: u64) -> String {
    let checksum = protocol_checksum("ACK", "WORK", &[id, nonce, actions, digest]);
    format!("{PROTOCOL_VERSION} ACK WORK {id} {nonce} {actions} {digest:016x} {checksum:016x}\n")
}

pub fn rollback_ack(id: u64, nonce: u64) -> String {
    let checksum = protocol_checksum("ACK", "ROLLBACK", &[id, nonce]);
    format!("{PROTOCOL_VERSION} ACK ROLLBACK {id} {nonce} {checksum:016x}\n")
}

pub fn probe_ack(id: u64, nonce: u64) -> String {
    let checksum = protocol_checksum("ACK", "PROBE", &[id, nonce]);
    format!("{PROTOCOL_VERSION} ACK PROBE {id} {nonce} {checksum:016x}\n")
}

pub fn stop_ack(id: u64, nonce: u64) -> String {
    let checksum = protocol_checksum("ACK", "STOP", &[id, nonce]);
    format!("{PROTOCOL_VERSION} ACK STOP {id} {nonce} {checksum:016x}\n")
}

pub fn parse_request(line: &str) -> Result<ChildRequest, ProtocolError> {
    let prefix: Vec<&str> = line.split_whitespace().take(3).collect();
    if prefix.len() != 3 || prefix[0] != PROTOCOL_VERSION || prefix[1] != "REQUEST" {
        return Err(ProtocolError::new("wrong protocol version or request type"));
    }
    match prefix[2] {
        "WORK" => {
            let tokens = exact_tokens(line, 7)?;
            let id = parse_canonical_u64(tokens[3], "work id")?;
            let nonce = parse_canonical_u64(tokens[4], "work nonce")?;
            let units = parse_canonical_u64(tokens[5], "work units")?;
            if units == 0 || units > MAX_WORK_UNITS {
                return Err(ProtocolError::new("work units outside protocol bounds"));
            }
            if work_request(id, nonce, units).trim_end_matches('\n') != line {
                return Err(ProtocolError::new("WORK request checksum mismatch"));
            }
            Ok(ChildRequest::Work { id, nonce, units })
        }
        "ROLLBACK" => {
            let tokens = exact_tokens(line, 6)?;
            let id = parse_canonical_u64(tokens[3], "rollback id")?;
            let nonce = parse_canonical_u64(tokens[4], "rollback nonce")?;
            if rollback_request(id, nonce).trim_end_matches('\n') != line {
                return Err(ProtocolError::new("ROLLBACK request checksum mismatch"));
            }
            Ok(ChildRequest::Rollback { id, nonce })
        }
        "PROBE" => {
            let tokens = exact_tokens(line, 6)?;
            let id = parse_canonical_u64(tokens[3], "probe id")?;
            let nonce = parse_canonical_u64(tokens[4], "probe nonce")?;
            if probe_request(id, nonce).trim_end_matches('\n') != line {
                return Err(ProtocolError::new("PROBE request checksum mismatch"));
            }
            Ok(ChildRequest::Probe { id, nonce })
        }
        "STOP" => {
            let tokens = exact_tokens(line, 6)?;
            let id = parse_canonical_u64(tokens[3], "stop id")?;
            let nonce = parse_canonical_u64(tokens[4], "stop nonce")?;
            if stop_request(id, nonce).trim_end_matches('\n') != line {
                return Err(ProtocolError::new("STOP request checksum mismatch"));
            }
            Ok(ChildRequest::Stop { id, nonce })
        }
        _ => Err(ProtocolError::new("unknown request operation")),
    }
}

pub fn validate_ack(line: &str, expected: ExpectedAck) -> Result<(), ProtocolError> {
    let canonical = match expected {
        ExpectedAck::Work {
            id,
            nonce,
            actions,
            digest,
        } => work_ack(id, nonce, actions, digest),
        ExpectedAck::Rollback { id, nonce } => rollback_ack(id, nonce),
        ExpectedAck::Probe { id, nonce } => probe_ack(id, nonce),
        ExpectedAck::Stop { id, nonce } => stop_ack(id, nonce),
    };
    let expected_line = canonical.trim_end_matches('\n');
    if line != expected_line {
        return Err(ProtocolError::new(format!(
            "ACK mismatch: expected `{expected_line}`, observed `{line}`"
        )));
    }
    Ok(())
}

fn authority_fields(authority: AuthoritySnapshot) -> [u64; 7] {
    [
        authority.body_uid,
        authority.epoch,
        authority.generation,
        authority.certificate,
        authority.principal_id,
        authority.resource_id,
        authority.action_id,
    ]
}

fn authority_from_tokens(
    tokens: &[&str],
    start: usize,
) -> Result<AuthoritySnapshot, ProtocolError> {
    Ok(AuthoritySnapshot {
        body_uid: parse_canonical_u64(tokens[start], "authority body_uid")?,
        epoch: parse_canonical_u64(tokens[start + 1], "authority epoch")?,
        generation: parse_canonical_u64(tokens[start + 2], "authority generation")?,
        certificate: parse_canonical_u64(tokens[start + 3], "authority certificate")?,
        principal_id: parse_canonical_u64(tokens[start + 4], "authority principal")?,
        resource_id: parse_canonical_u64(tokens[start + 5], "authority resource")?,
        action_id: parse_canonical_u64(tokens[start + 6], "authority action")?,
    })
}

pub fn hello(instance_id: u64) -> String {
    let checksum = protocol_checksum("HELLO", "INSTANCE", &[instance_id]);
    format!("{PROTOCOL_VERSION} HELLO {instance_id} {checksum:016x}\n")
}

pub fn validate_hello(line: &str, instance_id: u64) -> Result<(), ProtocolError> {
    let expected = hello(instance_id);
    if line != expected.trim_end_matches('\n') {
        return Err(ProtocolError::new(format!(
            "HELLO mismatch: expected `{}`, observed `{line}`",
            expected.trim_end_matches('\n')
        )));
    }
    Ok(())
}

pub fn bound_work_request(id: u64, nonce: u64, units: u64, authority: AuthoritySnapshot) -> String {
    let a = authority_fields(authority);
    let fields = [id, nonce, units, a[0], a[1], a[2], a[3], a[4], a[5], a[6]];
    let checksum = protocol_checksum("BOUND_REQUEST", "WORK", &fields);
    format!(
        "{PROTOCOL_VERSION} BOUND_REQUEST WORK {id} {nonce} {units} {} {} {} {} {} {} {} {checksum:016x}\n",
        a[0], a[1], a[2], a[3], a[4], a[5], a[6]
    )
}

fn bound_simple_request(
    operation: &str,
    id: u64,
    nonce: u64,
    authority: AuthoritySnapshot,
) -> String {
    let a = authority_fields(authority);
    let fields = [id, nonce, a[0], a[1], a[2], a[3], a[4], a[5], a[6]];
    let checksum = protocol_checksum("BOUND_REQUEST", operation, &fields);
    format!(
        "{PROTOCOL_VERSION} BOUND_REQUEST {operation} {id} {nonce} {} {} {} {} {} {} {} {checksum:016x}\n",
        a[0], a[1], a[2], a[3], a[4], a[5], a[6]
    )
}

pub fn bound_rollback_request(id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    bound_simple_request("ROLLBACK", id, nonce, authority)
}

pub fn bound_probe_request(id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    bound_simple_request("PROBE", id, nonce, authority)
}

pub fn bound_stop_request(id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    bound_simple_request("STOP", id, nonce, authority)
}

pub fn bound_work_ack(
    id: u64,
    nonce: u64,
    actions: u64,
    digest: u64,
    authority: AuthoritySnapshot,
) -> String {
    let a = authority_fields(authority);
    let fields = [
        id, nonce, actions, digest, a[0], a[1], a[2], a[3], a[4], a[5], a[6],
    ];
    let checksum = protocol_checksum("BOUND_ACK", "WORK", &fields);
    format!(
        "{PROTOCOL_VERSION} BOUND_ACK WORK {id} {nonce} {actions} {digest:016x} {} {} {} {} {} {} {} {checksum:016x}\n",
        a[0], a[1], a[2], a[3], a[4], a[5], a[6]
    )
}

fn bound_simple_ack(operation: &str, id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    let a = authority_fields(authority);
    let fields = [id, nonce, a[0], a[1], a[2], a[3], a[4], a[5], a[6]];
    let checksum = protocol_checksum("BOUND_ACK", operation, &fields);
    format!(
        "{PROTOCOL_VERSION} BOUND_ACK {operation} {id} {nonce} {} {} {} {} {} {} {} {checksum:016x}\n",
        a[0], a[1], a[2], a[3], a[4], a[5], a[6]
    )
}

pub fn bound_rollback_ack(id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    bound_simple_ack("ROLLBACK", id, nonce, authority)
}

pub fn bound_probe_ack(id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    bound_simple_ack("PROBE", id, nonce, authority)
}

pub fn bound_stop_ack(id: u64, nonce: u64, authority: AuthoritySnapshot) -> String {
    bound_simple_ack("STOP", id, nonce, authority)
}

pub fn parse_bound_request(line: &str) -> Result<BoundChildRequest, ProtocolError> {
    let prefix: Vec<&str> = line.split_whitespace().take(3).collect();
    if prefix.len() != 3 || prefix[0] != PROTOCOL_VERSION || prefix[1] != "BOUND_REQUEST" {
        return Err(ProtocolError::new(
            "wrong protocol version or bound request type",
        ));
    }
    match prefix[2] {
        "WORK" => {
            let tokens = exact_tokens(line, 14)?;
            let id = parse_canonical_u64(tokens[3], "work id")?;
            let nonce = parse_canonical_u64(tokens[4], "work nonce")?;
            let units = parse_canonical_u64(tokens[5], "work units")?;
            if units == 0 || units > MAX_WORK_UNITS {
                return Err(ProtocolError::new("work units outside protocol bounds"));
            }
            let authority = authority_from_tokens(&tokens, 6)?;
            if bound_work_request(id, nonce, units, authority).trim_end_matches('\n') != line {
                return Err(ProtocolError::new("bound WORK request checksum mismatch"));
            }
            Ok(BoundChildRequest::Work {
                id,
                nonce,
                units,
                authority,
            })
        }
        "ROLLBACK" | "PROBE" | "STOP" => {
            let tokens = exact_tokens(line, 13)?;
            let id = parse_canonical_u64(tokens[3], "request id")?;
            let nonce = parse_canonical_u64(tokens[4], "request nonce")?;
            let authority = authority_from_tokens(&tokens, 5)?;
            let canonical = bound_simple_request(prefix[2], id, nonce, authority);
            if canonical.trim_end_matches('\n') != line {
                return Err(ProtocolError::new("bound request checksum mismatch"));
            }
            Ok(match prefix[2] {
                "ROLLBACK" => BoundChildRequest::Rollback {
                    id,
                    nonce,
                    authority,
                },
                "PROBE" => BoundChildRequest::Probe {
                    id,
                    nonce,
                    authority,
                },
                _ => BoundChildRequest::Stop {
                    id,
                    nonce,
                    authority,
                },
            })
        }
        _ => Err(ProtocolError::new("unknown bound request operation")),
    }
}

pub fn validate_bound_ack(line: &str, expected: BoundExpectedAck) -> Result<(), ProtocolError> {
    let canonical = match expected {
        BoundExpectedAck::Work {
            id,
            nonce,
            actions,
            digest,
            authority,
        } => bound_work_ack(id, nonce, actions, digest, authority),
        BoundExpectedAck::Rollback {
            id,
            nonce,
            authority,
        } => bound_rollback_ack(id, nonce, authority),
        BoundExpectedAck::Probe {
            id,
            nonce,
            authority,
        } => bound_probe_ack(id, nonce, authority),
        BoundExpectedAck::Stop {
            id,
            nonce,
            authority,
        } => bound_stop_ack(id, nonce, authority),
    };
    let expected_line = canonical.trim_end_matches('\n');
    if line != expected_line {
        return Err(ProtocolError::new(format!(
            "bound ACK mismatch: expected `{expected_line}`, observed `{line}`"
        )));
    }
    Ok(())
}

pub fn work_digest(id: u64, units: u64) -> u64 {
    let mut accumulator = id ^ units.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15_u64;
    for index in 0..units {
        accumulator = accumulator.rotate_left(7) ^ index.wrapping_mul(0xd6e8_feb8_6659_fd93_u64);
        accumulator = accumulator.wrapping_add(0xa076_1d64_78bd_642f_u64);
    }
    accumulator
}
