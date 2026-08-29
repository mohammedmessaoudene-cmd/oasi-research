use crate::ledger::Ledger;
use crate::model::{
    AuthorityTransaction, BodyState, CommitRequest, Decision, Goal, MAX_LEASE_NS, MIN_LEASE_NS,
    PolicyIr, ReflexInstruction, ReflexProgram, SafetyLease, compile_policy,
};
use crate::protocol::{
    AuthoritySnapshot, BoundChildRequest, BoundExpectedAck, ChildRequest, ExpectedAck,
    PROTOCOL_VERSION, bound_probe_ack, bound_probe_request, bound_rollback_ack,
    bound_rollback_request, bound_stop_ack, bound_stop_request, bound_work_ack, bound_work_request,
    hello, parse_bound_request, parse_request, probe_ack, rollback_ack, stop_ack, stop_request,
    validate_ack, validate_bound_ack, validate_hello, work_ack, work_digest,
};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PRINCIPAL_ID: u64 = 7;
const RESOURCE_ID: u64 = 11;
const ACTION_ID: u64 = 13;
const DEFAULT_LEASE_NS: u64 = 50_000_000;
const CHILD_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PROTOCOL_LINE: usize = 1_024;

fn monotonic_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let elapsed = START.get_or_init(Instant::now).elapsed().as_nanos();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseDeadlineError {
    DurationOutOfRange,
    Overflow,
}

impl fmt::Display for LeaseDeadlineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurationOutOfRange => formatter.write_str("lease duration outside bounds"),
            Self::Overflow => formatter.write_str("monotonic lease deadline overflow"),
        }
    }
}

impl std::error::Error for LeaseDeadlineError {}

pub fn checked_lease_deadline(now_ns: u64, duration_ns: u64) -> Result<u64, LeaseDeadlineError> {
    if !(MIN_LEASE_NS..=MAX_LEASE_NS).contains(&duration_ns) {
        return Err(LeaseDeadlineError::DurationOutOfRange);
    }
    now_ns
        .checked_add(duration_ns)
        .ok_or(LeaseDeadlineError::Overflow)
}

pub fn checked_counter_increment(value: u64, counter_name: &str) -> io::Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| io::Error::other(format!("{counter_name} overflow")))
}

#[derive(Clone, Copy, Debug)]
enum Event {
    Begin,
    Commit,
    Reset,
    FunctionalFreshnessProbe,
    Stop,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Metrics {
    pub allowed_commits: u64,
    pub blocked_commits: u64,
    pub stale_or_expired_blocked: u64,
    pub child_actions: u64,
    pub verified_work_acks: u64,
    pub quarantines: u64,
    pub rollbacks: u64,
    pub rollback_acks: u64,
    pub functional_probe_requests: u64,
    pub functional_probe_recoveries: u64,
    pub damage: u64,
}

enum ReaderMessage {
    Line(String),
    Eof,
    Error(io::ErrorKind, String),
}

pub struct ChildProcess {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<ReaderMessage>,
    reader: Option<JoinHandle<()>>,
    reaped: bool,
}

impl ChildProcess {
    pub fn spawn(executable: &Path) -> io::Result<Self> {
        Self::spawn_program(executable, &["--child"])
    }

    pub fn spawn_verified(executable: &Path) -> io::Result<Self> {
        Self::spawn_verified_program(executable, &["--child"])
    }

    pub fn spawn_verified_program(executable: &Path, arguments: &[&str]) -> io::Result<Self> {
        let mut process = Self::spawn_program(executable, arguments)?;
        process.expect_hello()?;
        Ok(process)
    }

    pub fn spawn_program(executable: &Path, arguments: &[&str]) -> io::Result<Self> {
        let mut child = Command::new(executable)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing child stdin"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing child stdout"))?;
        let (sender, responses) = mpsc::channel();
        let reader = thread::spawn(move || child_reader(output, sender));
        Ok(Self {
            child,
            input: Some(input),
            responses,
            reader: Some(reader),
            reaped: false,
        })
    }

    pub const fn is_reaped(&self) -> bool {
        self.reaped
    }

    /// Exposes the disposable child's process identifier for the R1-R5
    /// signal/crash assurance harness. This grants no new authority over any
    /// process other than the child already owned by this handle.
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    fn expect_hello(&mut self) -> io::Result<()> {
        match self.responses.recv_timeout(CHILD_RESPONSE_TIMEOUT) {
            Ok(ReaderMessage::Line(line)) => {
                if let Err(error) = validate_hello(&line, u64::from(self.process_id())) {
                    return Err(self.cleanup_error(
                        io::ErrorKind::InvalidData,
                        format!("child HELLO rejected: {error}"),
                    ));
                }
                Ok(())
            }
            Ok(ReaderMessage::Eof) => Err(self.cleanup_error(
                io::ErrorKind::UnexpectedEof,
                "child closed stdout before HELLO".to_owned(),
            )),
            Ok(ReaderMessage::Error(kind, message)) => {
                Err(self.cleanup_error(kind, format!("child HELLO failed: {message}")))
            }
            Err(RecvTimeoutError::Timeout) => {
                Err(self.cleanup_error(io::ErrorKind::TimedOut, "child HELLO timeout".to_owned()))
            }
            Err(RecvTimeoutError::Disconnected) => Err(self.cleanup_error(
                io::ErrorKind::BrokenPipe,
                "child stdout reader disconnected before HELLO".to_owned(),
            )),
        }
    }

    fn cleanup_error(&mut self, kind: io::ErrorKind, message: String) -> io::Error {
        match self.terminate_and_reap() {
            Ok(()) => io::Error::new(kind, message),
            Err(cleanup) => io::Error::new(
                kind,
                format!("{message}; child cleanup also failed: {cleanup}"),
            ),
        }
    }

    fn terminate_and_reap(&mut self) -> io::Result<()> {
        self.input.take();
        if !self.reaped {
            if self.child.try_wait()?.is_none() {
                match self.child.kill() {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
                    Err(error) => return Err(error),
                }
                self.child.wait()?;
            }
            self.reaped = true;
        }
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| io::Error::other("child stdout reader panicked"))?;
        }
        Ok(())
    }

    pub fn transact(&mut self, command: &str, expected: ExpectedAck) -> io::Result<()> {
        let write_result = match self.input.as_mut() {
            Some(input) => input
                .write_all(command.as_bytes())
                .and_then(|()| input.flush()),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "child stdin is closed",
            )),
        };
        if let Err(error) = write_result {
            return Err(self.cleanup_error(error.kind(), format!("child write failed: {error}")));
        }

        match self.responses.recv_timeout(CHILD_RESPONSE_TIMEOUT) {
            Ok(ReaderMessage::Line(line)) => {
                if let Err(error) = validate_ack(&line, expected) {
                    return Err(self.cleanup_error(
                        io::ErrorKind::InvalidData,
                        format!("child ACK rejected: {error}"),
                    ));
                }
                Ok(())
            }
            Ok(ReaderMessage::Eof) => Err(self.cleanup_error(
                io::ErrorKind::UnexpectedEof,
                "child closed stdout before ACK".to_owned(),
            )),
            Ok(ReaderMessage::Error(kind, message)) => {
                Err(self.cleanup_error(kind, format!("child stdout failed: {message}")))
            }
            Err(RecvTimeoutError::Timeout) => {
                Err(self.cleanup_error(io::ErrorKind::TimedOut, "child ACK timeout".to_owned()))
            }
            Err(RecvTimeoutError::Disconnected) => Err(self.cleanup_error(
                io::ErrorKind::BrokenPipe,
                "child stdout reader disconnected".to_owned(),
            )),
        }
    }

    pub fn transact_bound(&mut self, command: &str, expected: BoundExpectedAck) -> io::Result<()> {
        let write_result = match self.input.as_mut() {
            Some(input) => input
                .write_all(command.as_bytes())
                .and_then(|()| input.flush()),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "child stdin is closed",
            )),
        };
        if let Err(error) = write_result {
            return Err(self.cleanup_error(error.kind(), format!("child write failed: {error}")));
        }
        match self.responses.recv_timeout(CHILD_RESPONSE_TIMEOUT) {
            Ok(ReaderMessage::Line(line)) => {
                if let Err(error) = validate_bound_ack(&line, expected) {
                    return Err(self.cleanup_error(
                        io::ErrorKind::InvalidData,
                        format!("child bound ACK rejected: {error}"),
                    ));
                }
                Ok(())
            }
            Ok(ReaderMessage::Eof) => Err(self.cleanup_error(
                io::ErrorKind::UnexpectedEof,
                "child closed stdout before bound ACK".to_owned(),
            )),
            Ok(ReaderMessage::Error(kind, message)) => {
                Err(self.cleanup_error(kind, format!("child stdout failed: {message}")))
            }
            Err(RecvTimeoutError::Timeout) => Err(self.cleanup_error(
                io::ErrorKind::TimedOut,
                "child bound ACK timeout".to_owned(),
            )),
            Err(RecvTimeoutError::Disconnected) => Err(self.cleanup_error(
                io::ErrorKind::BrokenPipe,
                "child stdout reader disconnected".to_owned(),
            )),
        }
    }

    fn wait_for_clean_exit(&mut self) -> io::Result<()> {
        self.input.take();
        let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "child exited with status {status}"
                    )));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(self.cleanup_error(
                    io::ErrorKind::TimedOut,
                    "child did not exit after STOP ACK".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(2));
        }
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| io::Error::other("child stdout reader panicked"))?;
        }
        let mut observed_eof = false;
        while let Ok(message) = self.responses.try_recv() {
            match message {
                ReaderMessage::Eof if !observed_eof => observed_eof = true,
                ReaderMessage::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate child EOF notification",
                    ));
                }
                ReaderMessage::Line(line) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected child output after STOP ACK: {line}"),
                    ));
                }
                ReaderMessage::Error(kind, message) => {
                    return Err(io::Error::new(kind, message));
                }
            }
        }
        if !observed_eof {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "child reader ended without EOF notification",
            ));
        }
        Ok(())
    }

    pub fn stop(mut self, id: u64, nonce: u64) -> io::Result<()> {
        self.transact(&stop_request(id, nonce), ExpectedAck::Stop { id, nonce })?;
        self.wait_for_clean_exit()
    }

    pub fn stop_bound(
        mut self,
        id: u64,
        nonce: u64,
        authority: AuthoritySnapshot,
    ) -> io::Result<()> {
        self.transact_bound(
            &bound_stop_request(id, nonce, authority),
            BoundExpectedAck::Stop {
                id,
                nonce,
                authority,
            },
        )?;
        self.wait_for_clean_exit()
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

fn child_reader(output: ChildStdout, sender: mpsc::Sender<ReaderMessage>) {
    let mut output = BufReader::new(output);
    loop {
        match read_protocol_frame(&mut output) {
            Ok(None) => {
                let _ = sender.send(ReaderMessage::Eof);
                break;
            }
            Ok(Some(line)) => {
                if sender.send(ReaderMessage::Line(line)).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(ReaderMessage::Error(error.kind(), error.to_string()));
                break;
            }
        }
    }
}

pub fn read_protocol_frame(input: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut bytes = Vec::with_capacity(MAX_PROTOCOL_LINE + 1);
    let count = input
        .take(u64::try_from(MAX_PROTOCOL_LINE + 2).expect("protocol bound"))
        .read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_PROTOCOL_LINE + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol line exceeds bound",
        ));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "protocol line truncated before newline",
        ));
    }
    bytes.pop();
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub struct Runtime {
    body: BodyState,
    active_lease: Option<SafetyLease>,
    authority_transaction: AuthorityTransaction,
    reflex: ReflexProgram,
    ledger: Ledger,
    child: Option<ChildProcess>,
    metrics: Metrics,
    action_counter: u64,
    transaction_nonce: u64,
    rollback_confirmed: bool,
}

impl Runtime {
    pub fn new(executable: &Path, ledger_path: &Path) -> io::Result<Self> {
        let policy = PolicyIr {
            policy_id: 1,
            principal_id: PRINCIPAL_ID,
            resource_id: RESOURCE_ID,
            action_id: ACTION_ID,
            goal: Goal::ExecuteChildWork { units: 5_000 },
            max_units: 100_000,
            lease_ns: DEFAULT_LEASE_NS,
            rollback_required: true,
        };
        let reflex = compile_policy(&policy)
            .map_err(|error| io::Error::other(format!("policy compilation failed: {error:?}")))?;
        let mut runtime = Self {
            body: BodyState {
                body_uid: 0x0A51A,
                epoch: 1,
                generation: 1,
                certificate: 100,
                quarantined: false,
            },
            active_lease: None,
            authority_transaction: AuthorityTransaction::new(),
            reflex,
            ledger: Ledger::create(ledger_path)?,
            child: Some(ChildProcess::spawn_verified(executable)?),
            metrics: Metrics::default(),
            action_counter: 0,
            transaction_nonce: 0,
            rollback_confirmed: false,
        };
        runtime.install_lease()?;
        Ok(runtime)
    }

    fn next_transaction_nonce(&mut self) -> io::Result<u64> {
        let nonce = checked_counter_increment(self.transaction_nonce, "transaction nonce")?;
        self.transaction_nonce = nonce;
        Ok(nonce)
    }

    fn authority_snapshot(&self) -> AuthoritySnapshot {
        AuthoritySnapshot {
            body_uid: self.body.body_uid,
            epoch: self.body.epoch,
            generation: self.body.generation,
            certificate: self.body.certificate,
            principal_id: self.reflex.principal_id,
            resource_id: self.reflex.resource_id,
            action_id: self.reflex.action_id,
        }
    }

    fn install_lease(&mut self) -> io::Result<()> {
        let valid_until_ns = checked_lease_deadline(monotonic_ns(), self.reflex.lease_ns)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.active_lease = Some(SafetyLease {
            body_uid: self.body.body_uid,
            epoch: self.body.epoch,
            generation: self.body.generation,
            certificate: self.body.certificate,
            valid_until_ns,
            principal_id: self.reflex.principal_id,
            resource_id: self.reflex.resource_id,
            action_id: self.reflex.action_id,
        });
        self.ledger.record(
            "LEASE_INSTALLED",
            "PolicyIr lease duration applied with checked monotonic addition",
            Decision::Allow,
            &self.body,
            self.active_lease.as_ref(),
        )
    }

    fn record_protocol_rejection(&mut self, reason: &str) -> io::Result<()> {
        if !self.body.quarantined {
            self.metrics.quarantines = self.metrics.quarantines.saturating_add(1);
        }
        self.body.quarantined = true;
        self.active_lease = None;
        self.authority_transaction.abort();
        self.rollback_confirmed = false;
        self.metrics.damage = 1;
        self.ledger.record(
            "PROTOCOL_ACK_REJECTED",
            reason,
            Decision::BlockQuarantine,
            &self.body,
            None,
        )
    }

    fn quarantine(&mut self, reason: &str) -> io::Result<()> {
        if !self.body.quarantined {
            self.metrics.quarantines = self.metrics.quarantines.saturating_add(1);
        }
        self.body.quarantined = true;
        self.active_lease = None;
        self.authority_transaction.abort();
        self.rollback_confirmed = false;
        self.metrics.rollbacks = self
            .metrics
            .rollbacks
            .checked_add(1)
            .ok_or_else(|| io::Error::other("rollback identifier overflow"))?;
        self.ledger.record(
            "QUARANTINE",
            reason,
            Decision::BlockQuarantine,
            &self.body,
            None,
        )?;

        let id = self.metrics.rollbacks;
        let nonce = self.next_transaction_nonce()?;
        let authority = self.authority_snapshot();
        let ack_result = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("child unavailable during rollback"))?
            .transact_bound(
                &bound_rollback_request(id, nonce, authority),
                BoundExpectedAck::Rollback {
                    id,
                    nonce,
                    authority,
                },
            );
        match ack_result {
            Ok(()) => {
                self.rollback_confirmed = true;
                self.metrics.rollback_acks = self.metrics.rollback_acks.saturating_add(1);
                self.ledger.record(
                    "ROLLBACK_ACK_ACCEPTED",
                    "strict version/id/nonce/checksum validation passed",
                    Decision::BlockQuarantine,
                    &self.body,
                    None,
                )
            }
            Err(error) => {
                self.metrics.damage = 1;
                self.ledger.record(
                    "ROLLBACK_ACK_REJECTED",
                    &error.to_string(),
                    Decision::BlockQuarantine,
                    &self.body,
                    None,
                )?;
                Err(error)
            }
        }
    }

    fn begin(&mut self) -> io::Result<()> {
        self.authority_transaction
            .begin(self.active_lease)
            .map_err(|error| io::Error::other(format!("BEGIN rejected: {error:?}")))?;
        self.ledger.record(
            "BEGIN_ACTION",
            "permit snapshot captured",
            Decision::Allow,
            &self.body,
            self.active_lease.as_ref(),
        )
    }

    fn commit(&mut self) -> io::Result<()> {
        let request = CommitRequest {
            now_ns: monotonic_ns(),
            principal_id: PRINCIPAL_ID,
            resource_id: RESOURCE_ID,
            action_id: ACTION_ID,
        };
        let decision =
            self.authority_transaction
                .commit(&self.body, self.active_lease.as_ref(), &request);
        if decision == Decision::Allow {
            let id = checked_counter_increment(self.action_counter, "action identifier")?;
            let actions = self
                .metrics
                .child_actions
                .checked_add(1)
                .ok_or_else(|| io::Error::other("child action counter overflow"))?;
            let units = match self.reflex.instructions.first() {
                Some(ReflexInstruction::Work { units }) => *units,
                _ => {
                    return Err(io::Error::other(
                        "runtime commit has no bounded WORK instruction",
                    ));
                }
            };
            let nonce = self.next_transaction_nonce()?;
            let digest = work_digest(id, units);
            let authority = self.authority_snapshot();
            let ack_result = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("child unavailable during commit"))?
                .transact_bound(
                    &bound_work_request(id, nonce, units, authority),
                    BoundExpectedAck::Work {
                        id,
                        nonce,
                        actions,
                        digest,
                        authority,
                    },
                );
            if let Err(error) = ack_result {
                self.record_protocol_rejection(&error.to_string())?;
                return Err(error);
            }
            self.metrics.allowed_commits = self
                .metrics
                .allowed_commits
                .checked_add(1)
                .ok_or_else(|| io::Error::other("allowed commit counter overflow"))?;
            self.action_counter = id;
            self.metrics.child_actions = actions;
            self.metrics.verified_work_acks = self.metrics.verified_work_acks.saturating_add(1);
            self.ledger.record(
                "CHILD_ACK_ACCEPTED",
                &format!("WORK id={id} nonce={nonce} actions={actions} digest={digest:016x}"),
                Decision::Allow,
                &self.body,
                self.active_lease.as_ref(),
            )?;
            self.ledger.record(
                "COMMIT",
                "child action dispatched and strict ACK validated",
                decision,
                &self.body,
                self.active_lease.as_ref(),
            )?;
        } else {
            self.metrics.blocked_commits = self.metrics.blocked_commits.saturating_add(1);
            self.metrics.stale_or_expired_blocked =
                self.metrics.stale_or_expired_blocked.saturating_add(1);
            self.ledger.record(
                "COMMIT_BLOCKED",
                decision.as_str(),
                decision,
                &self.body,
                self.active_lease.as_ref(),
            )?;
        }
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        self.body.epoch = self
            .body
            .epoch
            .checked_add(1)
            .ok_or_else(|| io::Error::other("body epoch overflow"))?;
        self.body.generation = self
            .body
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("body generation overflow"))?;
        self.quarantine("epoch reset invalidated authority")
    }

    fn functional_freshness_probe(&mut self) -> io::Result<()> {
        self.metrics.functional_probe_requests =
            self.metrics.functional_probe_requests.saturating_add(1);
        if !self.body.quarantined || !self.rollback_confirmed {
            return self.ledger.record(
                "FUNCTIONAL_FRESHNESS_PROBE_REJECTED",
                "rollback ACK not confirmed; no reauthorization",
                Decision::BlockQuarantine,
                &self.body,
                None,
            );
        }

        let certificate = self
            .body
            .certificate
            .checked_add(1)
            .ok_or_else(|| io::Error::other("probe certificate overflow"))?;
        let generation = self
            .body
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("probe generation overflow"))?;
        let id = certificate;
        let nonce = self.next_transaction_nonce()?;
        let authority = self.authority_snapshot();
        self.ledger.record(
            "FUNCTIONAL_FRESHNESS_PROBE_REQUEST",
            "local child-process freshness/liveness challenge; not cryptographic or hardware attestation",
            Decision::BlockQuarantine,
            &self.body,
            None,
        )?;
        let ack_result = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("child unavailable during functional probe"))?
            .transact_bound(
                &bound_probe_request(id, nonce, authority),
                BoundExpectedAck::Probe {
                    id,
                    nonce,
                    authority,
                },
            );
        if let Err(error) = ack_result {
            self.record_protocol_rejection(&error.to_string())?;
            return Err(error);
        }

        let valid_until_ns = checked_lease_deadline(monotonic_ns(), self.reflex.lease_ns)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.body.certificate = certificate;
        self.body.generation = generation;
        self.body.quarantined = false;
        self.active_lease = Some(SafetyLease {
            body_uid: self.body.body_uid,
            epoch: self.body.epoch,
            generation: self.body.generation,
            certificate: self.body.certificate,
            valid_until_ns,
            principal_id: self.reflex.principal_id,
            resource_id: self.reflex.resource_id,
            action_id: self.reflex.action_id,
        });
        self.rollback_confirmed = false;
        self.metrics.functional_probe_recoveries =
            self.metrics.functional_probe_recoveries.saturating_add(1);
        self.ledger.record(
            "LEASE_INSTALLED",
            "PolicyIr lease duration applied after functional challenge",
            Decision::Allow,
            &self.body,
            self.active_lease.as_ref(),
        )?;
        self.ledger.record(
            "FUNCTIONAL_FRESHNESS_PROBE_ACCEPTED",
            "functional child-process liveness/freshness only; no identity or hardware attestation",
            Decision::Allow,
            &self.body,
            self.active_lease.as_ref(),
        )
    }

    fn lease_timeout(&self) -> Duration {
        match self.active_lease {
            Some(lease) => {
                Duration::from_nanos(lease.valid_until_ns.saturating_sub(monotonic_ns()))
            }
            None => Duration::from_secs(1),
        }
    }

    pub fn run(mut self) -> io::Result<Metrics> {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let schedule = [
                (5, Event::Begin),
                (5, Event::Commit),
                (5, Event::Begin),
                (2, Event::Reset),
                (2, Event::Commit),
                (5, Event::FunctionalFreshnessProbe),
                (8, Event::Begin),
                (5, Event::Commit),
                (5, Event::Begin),
                (70, Event::Commit),
                (5, Event::FunctionalFreshnessProbe),
                (8, Event::Begin),
                (5, Event::Commit),
                (5, Event::Stop),
            ];
            for (delay_ms, event) in schedule {
                thread::sleep(Duration::from_millis(delay_ms));
                if sender.send(event).is_err() {
                    break;
                }
            }
        });

        let mut running = true;
        while running {
            match receiver.recv_timeout(self.lease_timeout()) {
                Ok(Event::Begin) => self.begin()?,
                Ok(Event::Commit) => self.commit()?,
                Ok(Event::Reset) => self.reset()?,
                Ok(Event::FunctionalFreshnessProbe) => self.functional_freshness_probe()?,
                Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => running = false,
                Err(RecvTimeoutError::Timeout) => {
                    self.quarantine("safety lease expired during silence")?
                }
            }
        }

        let stop_id = self.action_counter;
        let stop_nonce = self.next_transaction_nonce()?;
        let stop_authority = self.authority_snapshot();
        let stop_result = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("child unavailable during STOP"))?
            .stop_bound(stop_id, stop_nonce, stop_authority);
        if let Err(error) = stop_result {
            self.record_protocol_rejection(&error.to_string())?;
            return Err(error);
        }
        self.metrics.damage = u64::from(
            self.metrics.child_actions != self.metrics.allowed_commits
                || self.metrics.verified_work_acks != self.metrics.allowed_commits
                || self.metrics.rollback_acks != self.metrics.rollbacks,
        );
        self.ledger.record(
            "FINAL",
            "runtime complete with strict versioned child protocol",
            if self.metrics.damage == 0 {
                Decision::Allow
            } else {
                Decision::BlockAction
            },
            &self.body,
            self.active_lease.as_ref(),
        )?;
        self.ledger.seal(&self.body, self.active_lease.as_ref())?;
        Ok(self.metrics)
    }
}

pub fn child_loop() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_all(hello(u64::from(std::process::id())).as_bytes())?;
    output.flush()?;
    let mut actions = 0_u64;
    loop {
        let Some(line) = read_protocol_frame(&mut input)? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "child stdin closed before strict STOP request",
            ));
        };
        if line.starts_with(&format!("{PROTOCOL_VERSION} BOUND_REQUEST ")) {
            let request = parse_bound_request(&line)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let response = match request {
                BoundChildRequest::Work {
                    id,
                    nonce,
                    units,
                    authority,
                } => {
                    actions = actions
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("child action counter overflow"))?;
                    bound_work_ack(id, nonce, actions, work_digest(id, units), authority)
                }
                BoundChildRequest::Rollback {
                    id,
                    nonce,
                    authority,
                } => bound_rollback_ack(id, nonce, authority),
                BoundChildRequest::Probe {
                    id,
                    nonce,
                    authority,
                } => bound_probe_ack(id, nonce, authority),
                BoundChildRequest::Stop {
                    id,
                    nonce,
                    authority,
                } => {
                    output.write_all(bound_stop_ack(id, nonce, authority).as_bytes())?;
                    output.flush()?;
                    return Ok(());
                }
            };
            output.write_all(response.as_bytes())?;
            output.flush()?;
            continue;
        }
        let request = parse_request(&line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let response = match request {
            ChildRequest::Work { id, nonce, units } => {
                actions = actions
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("child action counter overflow"))?;
                work_ack(id, nonce, actions, work_digest(id, units))
            }
            ChildRequest::Rollback { id, nonce } => rollback_ack(id, nonce),
            ChildRequest::Probe { id, nonce } => probe_ack(id, nonce),
            ChildRequest::Stop { id, nonce } => {
                output.write_all(stop_ack(id, nonce).as_bytes())?;
                output.flush()?;
                return Ok(());
            }
        };
        output.write_all(response.as_bytes())?;
        output.flush()?;
    }
}

#[cfg(test)]
mod assurance_tests {
    use super::read_protocol_frame;
    use std::fs;
    use std::io::{self, BufRead, Cursor, Read};
    use std::path::PathBuf;

    struct InterruptOnce {
        inner: Cursor<Vec<u8>>,
        interruptions_injected: u64,
        fill_buf_calls: u64,
    }

    impl InterruptOnce {
        fn new(bytes: &[u8]) -> Self {
            Self {
                inner: Cursor::new(bytes.to_vec()),
                interruptions_injected: 0,
                fill_buf_calls: 0,
            }
        }
    }

    impl Read for InterruptOnce {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl BufRead for InterruptOnce {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.fill_buf_calls += 1;
            if self.interruptions_injected == 0 {
                self.interruptions_injected += 1;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "injected EINTR"));
            }
            self.inner.fill_buf()
        }

        fn consume(&mut self, amount: usize) {
            self.inner.consume(amount);
        }
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

    #[test]
    fn interrupted_protocol_read_retries_and_reports_exact_result() {
        let mut reader = InterruptOnce::new(b"FRAME-AFTER-EINTR\n");
        let observed = read_protocol_frame(&mut reader);
        let (observed_line, error_kind, error_message) = match observed {
            Ok(line) => (line, None, None),
            Err(error) => (
                None,
                Some(format!("{:?}", error.kind())),
                Some(error.to_string()),
            ),
        };
        let passed = observed_line.as_deref() == Some("FRAME-AFTER-EINTR")
            && reader.interruptions_injected == 1
            && reader.fill_buf_calls >= 2
            && error_kind.is_none();
        let observed_json = observed_line
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_owned());
        let kind_json = error_kind
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_owned());
        let message_json = error_message
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_owned());
        let report = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"oasi-core-r1-r5-eintr-assurance-1\",\n",
                "  \"scenario\": \"protocol_reader_interrupted_once\",\n",
                "  \"injection\": \"BufRead::fill_buf returned ErrorKind::Interrupted exactly once\",\n",
                "  \"interruptions_injected\": {},\n",
                "  \"fill_buf_calls\": {},\n",
                "  \"expected_line\": \"FRAME-AFTER-EINTR\",\n",
                "  \"observed_line\": {},\n",
                "  \"error_kind\": {},\n",
                "  \"error_message\": {},\n",
                "  \"pass\": {}\n",
                "}}\n"
            ),
            reader.interruptions_injected,
            reader.fill_buf_calls,
            observed_json,
            kind_json,
            message_json,
            passed,
        );
        fs::write(
            output_path("R1_R5_EINTR_PROTOCOL_READER_ASSURANCE.json"),
            report,
        )
        .expect("write EINTR assurance report");
        assert!(
            passed,
            "protocol reader did not recover from injected EINTR"
        );
    }
}
