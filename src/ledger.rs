use crate::model::{BodyState, Decision, SafetyLease};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

pub const LEDGER_SCHEMA: &str = "osia-core-r1-r1-ledger-2";
pub const SECURITY_SCOPE: &str = "deterministic FNV-1a-style chain with a historical project offset; not a cryptographic signature";

const FNV_OFFSET: u64 = 1_469_598_103_934_665_603;
const FNV_PRIME: u64 = 1_099_511_628_211;
const MAX_EVENT_BYTES: usize = 128;
const MAX_DETAIL_BYTES: usize = 16_384;
const MAX_LINE_BYTES: usize = 131_072;
const HASH_HEX_LEN: usize = 16;

const EXPECTED_FIELDS: [&str; 24] = [
    "schema",
    "kind",
    "seq",
    "event",
    "detail",
    "decision",
    "body_uid",
    "epoch",
    "generation",
    "certificate",
    "quarantined",
    "lease_present",
    "lease_body_uid",
    "lease_epoch",
    "lease_generation",
    "lease_certificate",
    "lease_valid_until_ns",
    "lease_principal_id",
    "lease_resource_id",
    "lease_action_id",
    "sealed_event_count",
    "sealed_event_hash",
    "prev_hash",
    "hash",
];

fn fnv1a(data: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str, maximum: usize) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() > maximum {
        return Err(format!(
            "string has {} UTF-8 bytes, maximum is {maximum}",
            bytes.len()
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "string length exceeds u32")?;
    push_u32(out, length);
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            push_u64(out, value);
        }
        None => out.push(0),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind {
    Event,
    Seal,
}

impl EntryKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Seal => "seal",
        }
    }

    const fn canonical_byte(self) -> u8 {
        match self {
            Self::Event => 0,
            Self::Seal => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LedgerEntry {
    kind: EntryKind,
    seq: u64,
    event: String,
    detail: String,
    decision: u8,
    body_uid: u64,
    epoch: u64,
    generation: u64,
    certificate: u64,
    quarantined: bool,
    lease_present: bool,
    lease_body_uid: Option<u64>,
    lease_epoch: Option<u64>,
    lease_generation: Option<u64>,
    lease_certificate: Option<u64>,
    lease_valid_until_ns: Option<u64>,
    lease_principal_id: Option<u64>,
    lease_resource_id: Option<u64>,
    lease_action_id: Option<u64>,
    sealed_event_count: Option<u64>,
    sealed_event_hash: Option<u64>,
    prev_hash: u64,
    hash: u64,
}

struct LedgerSnapshot<'a> {
    kind: EntryKind,
    seq: u64,
    event: &'a str,
    detail: &'a str,
    decision: Decision,
    body: &'a BodyState,
    lease: Option<&'a SafetyLease>,
    sealed_event_count: Option<u64>,
    sealed_event_hash: Option<u64>,
    prev_hash: u64,
}

impl LedgerEntry {
    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(256 + self.event.len() + self.detail.len());
        push_string(&mut out, LEDGER_SCHEMA, u32::MAX as usize)?;
        out.push(self.kind.canonical_byte());
        push_u64(&mut out, self.seq);
        push_string(&mut out, &self.event, MAX_EVENT_BYTES)?;
        push_string(&mut out, &self.detail, MAX_DETAIL_BYTES)?;
        out.push(self.decision);
        push_u64(&mut out, self.body_uid);
        push_u64(&mut out, self.epoch);
        push_u64(&mut out, self.generation);
        push_u64(&mut out, self.certificate);
        out.push(u8::from(self.quarantined));
        out.push(u8::from(self.lease_present));
        if self.lease_present {
            push_u64(
                &mut out,
                self.lease_body_uid
                    .ok_or("present lease lacks lease_body_uid")?,
            );
            push_u64(
                &mut out,
                self.lease_epoch.ok_or("present lease lacks lease_epoch")?,
            );
            push_u64(
                &mut out,
                self.lease_generation
                    .ok_or("present lease lacks lease_generation")?,
            );
            push_u64(
                &mut out,
                self.lease_certificate
                    .ok_or("present lease lacks lease_certificate")?,
            );
            push_u64(
                &mut out,
                self.lease_valid_until_ns
                    .ok_or("present lease lacks lease_valid_until_ns")?,
            );
            push_u64(
                &mut out,
                self.lease_principal_id
                    .ok_or("present lease lacks lease_principal_id")?,
            );
            push_u64(
                &mut out,
                self.lease_resource_id
                    .ok_or("present lease lacks lease_resource_id")?,
            );
            push_u64(
                &mut out,
                self.lease_action_id
                    .ok_or("present lease lacks lease_action_id")?,
            );
        }
        push_optional_u64(&mut out, self.sealed_event_count);
        push_optional_u64(&mut out, self.sealed_event_hash);
        push_u64(&mut out, self.prev_hash);
        Ok(out)
    }

    fn expected_hash(&self) -> Result<u64, String> {
        Ok(fnv1a(&self.canonical_bytes()?, FNV_OFFSET ^ self.prev_hash))
    }

    fn from_snapshot(snapshot: LedgerSnapshot<'_>) -> Result<Self, String> {
        if snapshot.event.len() > MAX_EVENT_BYTES {
            return Err(format!("event exceeds {MAX_EVENT_BYTES} UTF-8 bytes"));
        }
        if snapshot.detail.len() > MAX_DETAIL_BYTES {
            return Err(format!("detail exceeds {MAX_DETAIL_BYTES} UTF-8 bytes"));
        }
        let mut entry = Self {
            kind: snapshot.kind,
            seq: snapshot.seq,
            event: snapshot.event.to_owned(),
            detail: snapshot.detail.to_owned(),
            decision: snapshot.decision as u8,
            body_uid: snapshot.body.body_uid,
            epoch: snapshot.body.epoch,
            generation: snapshot.body.generation,
            certificate: snapshot.body.certificate,
            quarantined: snapshot.body.quarantined,
            lease_present: snapshot.lease.is_some(),
            lease_body_uid: snapshot.lease.map(|value| value.body_uid),
            lease_epoch: snapshot.lease.map(|value| value.epoch),
            lease_generation: snapshot.lease.map(|value| value.generation),
            lease_certificate: snapshot.lease.map(|value| value.certificate),
            lease_valid_until_ns: snapshot.lease.map(|value| value.valid_until_ns),
            lease_principal_id: snapshot.lease.map(|value| value.principal_id),
            lease_resource_id: snapshot.lease.map(|value| value.resource_id),
            lease_action_id: snapshot.lease.map(|value| value.action_id),
            sealed_event_count: snapshot.sealed_event_count,
            sealed_event_hash: snapshot.sealed_event_hash,
            prev_hash: snapshot.prev_hash,
            hash: 0,
        };
        entry.hash = entry.expected_hash()?;
        Ok(entry)
    }

    fn write_json(&self, writer: &mut impl Write) -> io::Result<()> {
        write!(
            writer,
            "{{\"schema\":\"{LEDGER_SCHEMA}\",\"kind\":\"{}\",\"seq\":{},\"event\":\"{}\",\"detail\":\"{}\",\"decision\":{},\"body_uid\":{},\"epoch\":{},\"generation\":{},\"certificate\":{},\"quarantined\":{},\"lease_present\":{}",
            self.kind.as_str(),
            self.seq,
            escape_json(&self.event),
            escape_json(&self.detail),
            self.decision,
            self.body_uid,
            self.epoch,
            self.generation,
            self.certificate,
            self.quarantined,
            self.lease_present,
        )?;
        write_optional_json(writer, "lease_body_uid", self.lease_body_uid)?;
        write_optional_json(writer, "lease_epoch", self.lease_epoch)?;
        write_optional_json(writer, "lease_generation", self.lease_generation)?;
        write_optional_json(writer, "lease_certificate", self.lease_certificate)?;
        write_optional_json(writer, "lease_valid_until_ns", self.lease_valid_until_ns)?;
        write_optional_json(writer, "lease_principal_id", self.lease_principal_id)?;
        write_optional_json(writer, "lease_resource_id", self.lease_resource_id)?;
        write_optional_json(writer, "lease_action_id", self.lease_action_id)?;
        write_optional_json(writer, "sealed_event_count", self.sealed_event_count)?;
        match self.sealed_event_hash {
            Some(value) => write!(writer, ",\"sealed_event_hash\":\"{value:016x}\"")?,
            None => writer.write_all(b",\"sealed_event_hash\":null")?,
        }
        writeln!(
            writer,
            ",\"prev_hash\":\"{:016x}\",\"hash\":\"{:016x}\"}}",
            self.prev_hash, self.hash
        )
    }
}

fn write_optional_json(writer: &mut impl Write, name: &str, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(writer, ",\"{name}\":{value}"),
        None => write!(writer, ",\"{name}\":null"),
    }
}

pub struct Ledger {
    writer: BufWriter<File>,
    seq: u64,
    hash: u64,
    event_entries: u64,
    sealed: bool,
}

impl Ledger {
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            writer: BufWriter::new(File::create(path)?),
            seq: 0,
            hash: 0,
            event_entries: 0,
            sealed: false,
        })
    }

    pub fn record(
        &mut self,
        event: &str,
        detail: &str,
        decision: Decision,
        body: &BodyState,
        lease: Option<&SafetyLease>,
    ) -> io::Result<()> {
        if self.sealed {
            return Err(io::Error::other("ledger is already sealed"));
        }
        let next_seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("ledger sequence overflow"))?;
        let next_event_entries = self
            .event_entries
            .checked_add(1)
            .ok_or_else(|| io::Error::other("ledger event count overflow"))?;
        let entry = LedgerEntry::from_snapshot(LedgerSnapshot {
            kind: EntryKind::Event,
            seq: next_seq,
            event,
            detail,
            decision,
            body,
            lease,
            sealed_event_count: None,
            sealed_event_hash: None,
            prev_hash: self.hash,
        })
        .map_err(io::Error::other)?;
        entry.write_json(&mut self.writer)?;
        self.writer.flush()?;
        self.seq = next_seq;
        self.event_entries = next_event_entries;
        self.hash = entry.hash;
        Ok(())
    }

    pub fn seal(&mut self, body: &BodyState, lease: Option<&SafetyLease>) -> io::Result<()> {
        if self.sealed {
            return Err(io::Error::other("ledger is already sealed"));
        }
        if self.event_entries == 0 {
            return Err(io::Error::other("cannot seal an empty ledger"));
        }
        let next_seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("ledger sequence overflow"))?;
        let entry = LedgerEntry::from_snapshot(LedgerSnapshot {
            kind: EntryKind::Seal,
            seq: next_seq,
            event: "LEDGER_SEAL",
            detail: "terminal seal",
            decision: Decision::Allow,
            body,
            lease,
            sealed_event_count: Some(self.event_entries),
            sealed_event_hash: Some(self.hash),
            prev_hash: self.hash,
        })
        .map_err(io::Error::other)?;
        entry.write_json(&mut self.writer)?;
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        self.seq = next_seq;
        self.hash = entry.hash;
        self.sealed = true;
        Ok(())
    }

    pub const fn entries(&self) -> u64 {
        self.seq
    }

    pub const fn event_entries(&self) -> u64 {
        self.event_entries
    }

    pub const fn final_hash(&self) -> u64 {
        self.hash
    }

    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }
}

#[derive(Debug)]
pub struct VerificationReport {
    pub entries: u64,
    pub event_entries: u64,
    pub final_hash: u64,
    pub errors: Vec<String>,
}

impl VerificationReport {
    pub fn passed(&self) -> bool {
        self.errors.is_empty() && self.entries > 0
    }

    pub fn to_json(&self) -> String {
        let errors = self
            .errors
            .iter()
            .map(|error| format!("\"{}\"", escape_json(error)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\n  \"schema\": \"osia-core-r1-r1-ledger-verification-2\",\n  \"ledger_schema\": \"{LEDGER_SCHEMA}\",\n  \"entries\": {},\n  \"event_entries\": {},\n  \"final_hash\": \"{:016x}\",\n  \"errors\": [{}],\n  \"pass\": {},\n  \"security_scope\": \"{}\"\n}}\n",
            self.entries,
            self.event_entries,
            self.final_hash,
            errors,
            self.passed(),
            escape_json(SECURITY_SCOPE),
        )
    }
}

pub fn verify_path(path: impl AsRef<Path>) -> io::Result<VerificationReport> {
    let file = File::open(path)?;
    verify_reader(BufReader::new(file))
}

/// Recovers only a fully verified, terminally sealed prefix when an
/// interrupted append left a torn final fragment. No invalid complete record
/// is discarded and no unsealed ledger is promoted.
pub fn recover_valid_prefix(path: impl AsRef<Path>) -> io::Result<VerificationReport> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    let prefix_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no complete ledger line"))?;
    let prefix = &bytes[..prefix_len];
    let report = verify_reader(BufReader::new(prefix))?;
    if !report.passed() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no verified sealed prefix: {}", report.errors.join("; ")),
        ));
    }
    if prefix_len != bytes.len() {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(u64::try_from(prefix_len).expect("prefix length fits u64"))?;
        file.sync_all()?;
    }
    Ok(report)
}

pub fn verify_reader(mut reader: impl BufRead) -> io::Result<VerificationReport> {
    let mut errors = Vec::new();
    let mut entries = 0_u64;
    let mut event_entries = 0_u64;
    let mut previous_hash = 0_u64;
    let mut seal_seen = false;
    let mut line_number = 0_u64;

    loop {
        let mut bytes = Vec::new();
        let count = reader.read_until(b'\n', &mut bytes)?;
        if count == 0 {
            break;
        }
        line_number = line_number.saturating_add(1);
        if bytes.len() > MAX_LINE_BYTES {
            errors.push(format!(
                "line {line_number}: exceeds {MAX_LINE_BYTES} bytes"
            ));
            break;
        }
        let terminated = bytes.last() == Some(&b'\n');
        if terminated {
            bytes.pop();
        } else {
            errors.push(format!("line {line_number}: missing terminal LF"));
        }
        if bytes.is_empty() || bytes.iter().all(u8::is_ascii_whitespace) {
            errors.push(format!("line {line_number}: blank lines are forbidden"));
            continue;
        }
        let line = match std::str::from_utf8(&bytes) {
            Ok(line) => line,
            Err(error) => {
                errors.push(format!("line {line_number}: invalid UTF-8: {error}"));
                break;
            }
        };
        let entry = match parse_entry(line) {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("line {line_number}: {error}"));
                break;
            }
        };
        let mut canonical_line = Vec::new();
        entry.write_json(&mut canonical_line)?;
        if canonical_line.last() == Some(&b'\n') {
            canonical_line.pop();
        }
        if canonical_line != bytes {
            errors.push(format!("line {line_number}: non-canonical JSON encoding"));
        }
        entries = entries.saturating_add(1);

        if entry.seq != entries {
            errors.push(format!(
                "line {line_number}: seq {} != expected {entries}",
                entry.seq
            ));
        }
        if entry.prev_hash != previous_hash {
            errors.push(format!(
                "line {line_number}: prev_hash {:016x} != previous hash {previous_hash:016x}",
                entry.prev_hash
            ));
        }
        match entry.expected_hash() {
            Ok(expected) if entry.hash != expected => errors.push(format!(
                "line {line_number}: hash {:016x} != expected {expected:016x}",
                entry.hash
            )),
            Err(error) => errors.push(format!("line {line_number}: canonicalization: {error}")),
            _ => {}
        }

        match entry.kind {
            EntryKind::Event => {
                event_entries = event_entries.saturating_add(1);
                if seal_seen {
                    errors.push(format!("line {line_number}: event appears after seal"));
                }
            }
            EntryKind::Seal => {
                if seal_seen {
                    errors.push(format!("line {line_number}: duplicate seal"));
                }
                seal_seen = true;
                if entry.event != "LEDGER_SEAL" || entry.detail != "terminal seal" {
                    errors.push(format!("line {line_number}: invalid seal marker"));
                }
                if entry.decision != Decision::Allow as u8 {
                    errors.push(format!("line {line_number}: seal decision is not ALLOW"));
                }
                if entry.sealed_event_count != Some(event_entries) {
                    errors.push(format!(
                        "line {line_number}: sealed_event_count is not {event_entries}"
                    ));
                }
                if entry.sealed_event_hash != Some(entry.prev_hash) {
                    errors.push(format!(
                        "line {line_number}: sealed_event_hash does not equal prev_hash"
                    ));
                }
            }
        }
        previous_hash = entry.hash;
    }

    if entries == 0 {
        errors.push("ledger is empty".to_owned());
    }
    if !seal_seen {
        errors.push("terminal seal is missing".to_owned());
    }

    Ok(VerificationReport {
        entries,
        event_entries,
        final_hash: previous_hash,
        errors,
    })
}

#[cfg(test)]
mod assurance_tests {
    use super::Ledger;
    use crate::model::{BodyState, Decision};
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("oasi-r1-r5-{label}-{}-{nonce}", std::process::id()))
    }

    fn output_path(name: &str) -> PathBuf {
        let directory = std::env::var_os("OASI_R1_R5_OUTPUT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::create_dir_all(&directory).expect("create assurance output directory");
        directory.join(name)
    }

    fn json_string(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len() + 2);
        escaped.push('"');
        for character in value.chars() {
            match character {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                character if character.is_control() => {
                    escaped.push_str(&format!("\\u{:04x}", character as u32));
                }
                character => escaped.push(character),
            }
        }
        escaped.push('"');
        escaped
    }

    fn body() -> BodyState {
        BodyState {
            body_uid: 11,
            epoch: 22,
            generation: 33,
            certificate: 44,
            quarantined: false,
        }
    }

    #[test]
    fn ledger_sequence_overflow_is_fail_closed_and_reports_exact_result() {
        let record_path = unique_path("record-sequence-overflow");
        let mut record_ledger = Ledger::create(&record_path).expect("create record ledger");
        record_ledger.seq = u64::MAX;
        let record_before = (
            record_ledger.seq,
            record_ledger.event_entries,
            record_ledger.hash,
            record_ledger.sealed,
            fs::metadata(&record_path).expect("record metadata").len(),
        );
        let record_error = record_ledger
            .record(
                "OVERFLOW",
                "must not be written",
                Decision::Allow,
                &body(),
                None,
            )
            .expect_err("record sequence overflow was accepted");
        let record_after = (
            record_ledger.seq,
            record_ledger.event_entries,
            record_ledger.hash,
            record_ledger.sealed,
            fs::metadata(&record_path).expect("record metadata").len(),
        );
        let record_pass = record_error.kind() == io::ErrorKind::Other
            && record_error.to_string() == "ledger sequence overflow"
            && record_before == record_after;
        drop(record_ledger);

        let seal_path = unique_path("seal-sequence-overflow");
        let mut seal_ledger = Ledger::create(&seal_path).expect("create seal ledger");
        seal_ledger.seq = u64::MAX;
        seal_ledger.event_entries = 1;
        let seal_before = (
            seal_ledger.seq,
            seal_ledger.event_entries,
            seal_ledger.hash,
            seal_ledger.sealed,
            fs::metadata(&seal_path).expect("seal metadata").len(),
        );
        let seal_error = seal_ledger
            .seal(&body(), None)
            .expect_err("seal sequence overflow was accepted");
        let seal_after = (
            seal_ledger.seq,
            seal_ledger.event_entries,
            seal_ledger.hash,
            seal_ledger.sealed,
            fs::metadata(&seal_path).expect("seal metadata").len(),
        );
        let seal_pass = seal_error.kind() == io::ErrorKind::Other
            && seal_error.to_string() == "ledger sequence overflow"
            && seal_before == seal_after;
        drop(seal_ledger);

        let overall_pass = record_pass && seal_pass;
        let executed = !record_error.to_string().is_empty() && !seal_error.to_string().is_empty();
        let observed_equals_expected = record_pass && seal_pass;
        let return_code = if overall_pass { 0 } else { 1 };
        let campaign_kind = std::env::var("OASI_R1_R5_CAMPAIGN_KIND")
            .unwrap_or_else(|_| "targeted_test".to_owned());
        let report = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"oasi-core-r1-r5-ledger-sequence-overflow-assurance-1\",\n",
                "  \"campaign_kind\": {},\n",
                "  \"cases\": {{\n",
                "    \"ledger_sequence_overflow_fail_closed\": {{\n",
                "      \"case_id\": \"ledger_sequence_overflow_fail_closed\",\n",
                "      \"gate_id\": \"G185\",\n",
                "      \"executed\": {},\n",
                "      \"return_code\": {},\n",
                "      \"timed_out\": false,\n",
                "      \"expected\": \"record and seal reject u64::MAX without state change or write\",\n",
                "      \"observed\": \"record and seal returned ledger sequence overflow\",\n",
                "      \"observed_equals_expected\": {},\n",
                "      \"initial_sequence\": {},\n",
                "      \"operations\": {{\n",
                "        \"record\": {{\"error_kind\":{},\"error_message\":{},",
                "\"sequence_after\":{},\"event_entries_after\":{},\"file_bytes_after\":{},",
                "\"state_unchanged\":{},\"pass\":{}}},\n",
                "        \"seal\": {{\"error_kind\":{},\"error_message\":{},",
                "\"sequence_after\":{},\"event_entries_after\":{},\"file_bytes_after\":{},",
                "\"state_unchanged\":{},\"pass\":{}}}\n",
                "      }},\n",
                "      \"unauthorized_effects\": 0,\n",
                "      \"pass\": {}\n",
                "    }}\n",
                "  }},\n",
                "  \"pass\": {}\n",
                "}}\n"
            ),
            json_string(&campaign_kind),
            executed,
            return_code,
            observed_equals_expected,
            u64::MAX,
            json_string(&format!("{:?}", record_error.kind())),
            json_string(&record_error.to_string()),
            record_after.0,
            record_after.1,
            record_after.4,
            record_before == record_after,
            record_pass,
            json_string(&format!("{:?}", seal_error.kind())),
            json_string(&seal_error.to_string()),
            seal_after.0,
            seal_after.1,
            seal_after.4,
            seal_before == seal_after,
            seal_pass,
            overall_pass,
            overall_pass,
        );
        fs::write(
            output_path("LEDGER_SEQUENCE_OVERFLOW_ASSURANCE.json"),
            report,
        )
        .expect("write ledger sequence overflow assurance report");
        fs::remove_file(record_path).expect("remove record overflow fixture");
        fs::remove_file(seal_path).expect("remove seal overflow fixture");
        assert!(record_pass, "record overflow did not fail closed");
        assert!(seal_pass, "seal overflow did not fail closed");
    }
}

#[derive(Clone, Debug)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
}

struct FlatJsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> FlatJsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            position: 0,
        }
    }

    fn parse_object(mut self) -> Result<HashMap<String, JsonValue>, String> {
        self.skip_whitespace();
        self.expect_byte(b'{')?;
        let mut values = HashMap::new();
        let mut keys = HashSet::new();
        self.skip_whitespace();
        if self.consume_byte(b'}') {
            return Err("object is empty".to_owned());
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                return Err(format!("duplicate JSON key {key:?}"));
            }
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            let value = self.parse_value()?;
            values.insert(key, value);
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                break;
            }
            self.expect_byte(b',')?;
        }
        self.skip_whitespace();
        if self.position != self.bytes.len() {
            return Err("trailing data after JSON object".to_owned());
        }
        Ok(values)
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        match self.peek_byte() {
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') if self.consume_literal(b"true") => Ok(JsonValue::Bool(true)),
            Some(b'f') if self.consume_literal(b"false") => Ok(JsonValue::Bool(false)),
            Some(b'n') if self.consume_literal(b"null") => Ok(JsonValue::Null),
            Some(b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            _ => Err(format!("unsupported JSON value at byte {}", self.position)),
        }
    }

    fn parse_number(&mut self) -> Result<u64, String> {
        let start = self.position;
        if self.peek_byte() == Some(b'0') {
            self.position += 1;
            if matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err("number has a leading zero".to_owned());
            }
        } else {
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| "number is not UTF-8")?;
        text.parse::<u64>()
            .map_err(|_| format!("number {text:?} is not u64"))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        let mut chunk_start = self.position;
        loop {
            let byte = self
                .peek_byte()
                .ok_or_else(|| "unterminated JSON string".to_owned())?;
            match byte {
                b'"' => {
                    self.push_utf8_chunk(&mut out, chunk_start, self.position)?;
                    self.position += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.push_utf8_chunk(&mut out, chunk_start, self.position)?;
                    self.position += 1;
                    let escaped = self
                        .next_byte()
                        .ok_or_else(|| "unterminated JSON escape".to_owned())?;
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => self.parse_unicode_escape(&mut out)?,
                        _ => return Err("invalid JSON escape".to_owned()),
                    }
                    chunk_start = self.position;
                }
                0x00..=0x1f => return Err("unescaped control character in string".to_owned()),
                _ => self.position += 1,
            }
        }
    }

    fn parse_unicode_escape(&mut self, out: &mut String) -> Result<(), String> {
        let first = self.parse_hex_u16()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if self.next_byte() != Some(b'\\') || self.next_byte() != Some(b'u') {
                return Err("high surrogate is not followed by low surrogate".to_owned());
            }
            let second = self.parse_hex_u16()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err("invalid low surrogate".to_owned());
            }
            0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err("unpaired low surrogate".to_owned());
        } else {
            u32::from(first)
        };
        out.push(char::from_u32(scalar).ok_or("invalid Unicode scalar")?);
        Ok(())
    }

    fn parse_hex_u16(&mut self) -> Result<u16, String> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self
                .next_byte()
                .and_then(|byte| (byte as char).to_digit(16))
                .ok_or_else(|| "invalid Unicode escape".to_owned())?;
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }

    fn push_utf8_chunk(&self, out: &mut String, start: usize, end: usize) -> Result<(), String> {
        let chunk =
            std::str::from_utf8(&self.bytes[start..end]).map_err(|_| "invalid UTF-8 in string")?;
        out.push_str(chunk);
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    fn consume_literal(&mut self, literal: &[u8]) -> bool {
        if self.bytes.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            true
        } else {
            false
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        match self.next_byte() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(format!(
                "expected byte {:?}, got {:?} at byte {}",
                expected as char,
                actual as char,
                self.position.saturating_sub(1)
            )),
            None => Err(format!("expected byte {:?}, got EOF", expected as char)),
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.peek_byte() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let value = self.peek_byte()?;
        self.position += 1;
        Some(value)
    }
}

fn parse_entry(line: &str) -> Result<LedgerEntry, String> {
    let values = FlatJsonParser::new(line).parse_object()?;
    let actual_keys = values.keys().map(String::as_str).collect::<HashSet<_>>();
    let expected_keys = EXPECTED_FIELDS.into_iter().collect::<HashSet<_>>();
    if actual_keys != expected_keys {
        let mut missing = expected_keys
            .difference(&actual_keys)
            .copied()
            .collect::<Vec<_>>();
        let mut extra = actual_keys
            .difference(&expected_keys)
            .copied()
            .collect::<Vec<_>>();
        missing.sort_unstable();
        extra.sort_unstable();
        return Err(format!(
            "field set mismatch; missing={missing:?}, extra={extra:?}"
        ));
    }

    if require_string(&values, "schema")? != LEDGER_SCHEMA {
        return Err("wrong ledger schema".to_owned());
    }
    let kind = match require_string(&values, "kind")? {
        "event" => EntryKind::Event,
        "seal" => EntryKind::Seal,
        other => return Err(format!("invalid kind {other:?}")),
    };
    let decision_u64 = require_u64(&values, "decision")?;
    let decision = u8::try_from(decision_u64).map_err(|_| "decision is not u8")?;
    if decision > Decision::BlockNoLease as u8 {
        return Err(format!("decision {decision} is outside 0..=10"));
    }
    let lease_present = require_bool(&values, "lease_present")?;
    let lease_body_uid = require_optional_u64(&values, "lease_body_uid")?;
    let lease_epoch = require_optional_u64(&values, "lease_epoch")?;
    let lease_generation = require_optional_u64(&values, "lease_generation")?;
    let lease_certificate = require_optional_u64(&values, "lease_certificate")?;
    let lease_valid_until_ns = require_optional_u64(&values, "lease_valid_until_ns")?;
    let lease_principal_id = require_optional_u64(&values, "lease_principal_id")?;
    let lease_resource_id = require_optional_u64(&values, "lease_resource_id")?;
    let lease_action_id = require_optional_u64(&values, "lease_action_id")?;
    let lease_values = [
        lease_body_uid,
        lease_epoch,
        lease_generation,
        lease_certificate,
        lease_valid_until_ns,
        lease_principal_id,
        lease_resource_id,
        lease_action_id,
    ];
    if lease_present && lease_values.iter().any(Option::is_none) {
        return Err("lease_present=true requires all eight lease fields".to_owned());
    }
    if !lease_present && lease_values.iter().any(Option::is_some) {
        return Err("lease_present=false requires all eight lease fields to be null".to_owned());
    }
    let sealed_event_count = require_optional_u64(&values, "sealed_event_count")?;
    let sealed_event_hash = require_optional_hash(&values, "sealed_event_hash")?;
    match kind {
        EntryKind::Event if sealed_event_count.is_some() || sealed_event_hash.is_some() => {
            return Err("event entries require null seal fields".to_owned());
        }
        EntryKind::Seal if sealed_event_count.is_none() || sealed_event_hash.is_none() => {
            return Err("seal entries require non-null seal fields".to_owned());
        }
        _ => {}
    }

    Ok(LedgerEntry {
        kind,
        seq: require_u64(&values, "seq")?,
        event: require_string(&values, "event")?.to_owned(),
        detail: require_string(&values, "detail")?.to_owned(),
        decision,
        body_uid: require_u64(&values, "body_uid")?,
        epoch: require_u64(&values, "epoch")?,
        generation: require_u64(&values, "generation")?,
        certificate: require_u64(&values, "certificate")?,
        quarantined: require_bool(&values, "quarantined")?,
        lease_present,
        lease_body_uid,
        lease_epoch,
        lease_generation,
        lease_certificate,
        lease_valid_until_ns,
        lease_principal_id,
        lease_resource_id,
        lease_action_id,
        sealed_event_count,
        sealed_event_hash,
        prev_hash: require_hash(&values, "prev_hash")?,
        hash: require_hash(&values, "hash")?,
    })
}

fn get_value<'a>(
    values: &'a HashMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, String> {
    values
        .get(name)
        .ok_or_else(|| format!("missing field {name:?}"))
}

fn require_string<'a>(
    values: &'a HashMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, String> {
    match get_value(values, name)? {
        JsonValue::String(value) => Ok(value),
        _ => Err(format!("field {name:?} is not a string")),
    }
}

fn require_u64(values: &HashMap<String, JsonValue>, name: &str) -> Result<u64, String> {
    match get_value(values, name)? {
        JsonValue::Number(value) => Ok(*value),
        _ => Err(format!("field {name:?} is not u64")),
    }
}

fn require_bool(values: &HashMap<String, JsonValue>, name: &str) -> Result<bool, String> {
    match get_value(values, name)? {
        JsonValue::Bool(value) => Ok(*value),
        _ => Err(format!("field {name:?} is not bool")),
    }
}

fn require_optional_u64(
    values: &HashMap<String, JsonValue>,
    name: &str,
) -> Result<Option<u64>, String> {
    match get_value(values, name)? {
        JsonValue::Null => Ok(None),
        JsonValue::Number(value) => Ok(Some(*value)),
        _ => Err(format!("field {name:?} is neither null nor u64")),
    }
}

fn parse_hash_text(value: &str, name: &str) -> Result<u64, String> {
    if value.len() != HASH_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "field {name:?} is not exactly 16 lowercase hexadecimal digits"
        ));
    }
    u64::from_str_radix(value, 16).map_err(|_| format!("field {name:?} is not a u64 hash"))
}

fn require_hash(values: &HashMap<String, JsonValue>, name: &str) -> Result<u64, String> {
    parse_hash_text(require_string(values, name)?, name)
}

fn require_optional_hash(
    values: &HashMap<String, JsonValue>,
    name: &str,
) -> Result<Option<u64>, String> {
    match get_value(values, name)? {
        JsonValue::Null => Ok(None),
        JsonValue::String(value) => parse_hash_text(value, name).map(Some),
        _ => Err(format!("field {name:?} is neither null nor a hash string")),
    }
}
