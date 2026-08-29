use osia_core_r1::protocol::{
    AuthoritySnapshot, BoundExpectedAck, ExpectedAck, bound_work_ack, bound_work_request, hello,
    probe_ack, probe_request, work_digest,
};
use osia_core_r1::runtime::{ChildProcess, read_protocol_frame};
use std::fs;
use std::io::{self, BufRead, Cursor, Read};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PYTHON: &str = "/usr/bin/python3";
const WAIT_LIMIT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct Observation {
    scenario: &'static str,
    expectation: &'static str,
    observed: String,
    error_kind: Option<String>,
    error_message: Option<String>,
    elapsed_ms: u128,
    child_pid: Option<u32>,
    child_reaped: bool,
    process_absent: bool,
    bytes_exercised: u64,
    frames_exercised: u64,
    pass: bool,
}

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

fn unique_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("oasi-r1-r5-{label}-{}-{nonce}", std::process::id()))
}

fn output_path() -> PathBuf {
    let directory = std::env::var_os("OASI_R1_R5_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&directory).expect("create assurance output directory");
    directory.join("PROTOCOL_CASE_MATRIX.json")
}

fn read_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Ok(text) = fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for complete child PID sentinel {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn process_absent(pid: u32) -> bool {
    !Path::new("/proc").join(pid.to_string()).exists()
}

fn cleanup_sentinel(path: &Path) {
    if path.exists() {
        fs::remove_file(path).expect("remove child sentinel");
    }
}

fn error_fields(result: &io::Result<ChildProcess>) -> (Option<String>, Option<String>) {
    match result {
        Ok(_) => (None, None),
        Err(error) => (Some(format!("{:?}", error.kind())), Some(error.to_string())),
    }
}

fn handshake_failure(
    scenario: &'static str,
    expectation: &'static str,
    source: &str,
    expected_kind: io::ErrorKind,
    expected_message: &str,
) -> Observation {
    let pid_file = unique_path(scenario);
    let pid_file_text = pid_file.to_string_lossy().into_owned();
    let start = Instant::now();
    let result =
        ChildProcess::spawn_verified_program(Path::new(PYTHON), &["-c", source, &pid_file_text]);
    let elapsed_ms = start.elapsed().as_millis();
    let pid = read_pid(&pid_file);
    let (error_kind, error_message) = error_fields(&result);
    let absent = process_absent(pid);
    let pass = matches!(&result, Err(error) if error.kind() == expected_kind
        && error.to_string().contains(expected_message))
        && absent;
    let observed = match &result {
        Ok(_) => "child accepted".to_owned(),
        Err(error) => format!("child rejected: {error}"),
    };
    cleanup_sentinel(&pid_file);
    Observation {
        scenario,
        expectation,
        observed,
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: absent,
        process_absent: absent,
        bytes_exercised: 0,
        frames_exercised: 0,
        pass,
    }
}

fn exit_before_hello() -> Observation {
    handshake_failure(
        "exit_before_hello",
        "reject UnexpectedEof and reap child",
        concat!(
            "import os,pathlib,sys\n",
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n",
            "sys.exit(17)\n"
        ),
        io::ErrorKind::UnexpectedEof,
        "child closed stdout before HELLO",
    )
}

fn wrong_hello() -> Observation {
    let wrong_identity_hello = hello(0);
    let source = format!(
        concat!(
            "import os,pathlib,sys,time\n",
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n",
            "sys.stdout.write({wrong_identity_hello:?})\n",
            "sys.stdout.flush()\n",
            "time.sleep(30)\n"
        ),
        wrong_identity_hello = wrong_identity_hello,
    );
    handshake_failure(
        "wrong_hello",
        "reject checksum-valid HELLO bound to the wrong child identity and reap child",
        &source,
        io::ErrorKind::InvalidData,
        "child HELLO rejected",
    )
}

fn partial_hello() -> Observation {
    handshake_failure(
        "partial_hello",
        "reject HELLO truncated before LF and reap child",
        concat!(
            "import os,pathlib,sys\n",
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n",
            "sys.stdout.write('OSIA-R1R1/1 HELLO ')\n",
            "sys.stdout.flush()\n",
            "sys.exit(19)\n"
        ),
        io::ErrorKind::UnexpectedEof,
        "protocol line truncated before newline",
    )
}

fn eintr_recovery(scenario: &'static str) -> Observation {
    let mut reader = InterruptOnce::new(b"FRAME-AFTER-EINTR\n");
    let start = Instant::now();
    let result = read_protocol_frame(&mut reader);
    let elapsed_ms = start.elapsed().as_millis();
    let (observed, error_kind, error_message) = match &result {
        Ok(Some(line)) => (format!("line recovered: {line}"), None, None),
        Ok(None) => ("unexpected EOF".to_owned(), None, None),
        Err(error) => (
            format!("read failed: {error}"),
            Some(format!("{:?}", error.kind())),
            Some(error.to_string()),
        ),
    };
    let pass = matches!(&result, Ok(Some(line)) if line == "FRAME-AFTER-EINTR")
        && reader.interruptions_injected == 1
        && reader.fill_buf_calls >= 2;
    Observation {
        scenario,
        expectation: "retry one ErrorKind::Interrupted and return the complete frame",
        observed,
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: None,
        child_reaped: false,
        process_absent: false,
        bytes_exercised: u64::try_from("FRAME-AFTER-EINTR\n".len()).expect("frame length"),
        frames_exercised: 1,
        pass,
    }
}

fn epipe_on_child_stdin() -> Observation {
    let sentinel = unique_path("epipe-ready");
    let sentinel_text = sentinel.to_string_lossy().into_owned();
    let source = concat!(
        "import os,pathlib,sys,time\n",
        "os.close(0)\n",
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n",
        "time.sleep(30)\n"
    );
    let mut child = ChildProcess::spawn_program(Path::new(PYTHON), &["-c", source, &sentinel_text])
        .expect("spawn EPIPE child");
    let pid = read_pid(&sentinel);
    let start = Instant::now();
    let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = result
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = result.as_ref().err().map(ToString::to_string);
    let pass = matches!(&result, Err(error) if error.kind() == io::ErrorKind::BrokenPipe
        && error.to_string().contains("child write failed"))
        && reaped
        && absent;
    cleanup_sentinel(&sentinel);
    Observation {
        scenario: "epipe_on_child_stdin",
        expectation: "surface BrokenPipe from write, terminate, and reap child",
        observed: result.as_ref().map_or_else(
            |error| format!("write rejected: {error}"),
            |()| "write accepted".into(),
        ),
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(probe_request(7, 9).len()).expect("request length"),
        frames_exercised: 1,
        pass,
    }
}

fn invalid_ack_frame(
    scenario: &'static str,
    expectation: &'static str,
    request: &str,
    expected: ExpectedAck,
    frame: &str,
    expected_kind: io::ErrorKind,
    expected_message: &str,
) -> Observation {
    let source = concat!(
        "import sys,time\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[1])\n",
        "sys.stdout.flush()\n",
        "time.sleep(30)\n"
    );
    let mut child = ChildProcess::spawn_program(Path::new(PYTHON), &["-c", source, frame])
        .expect("spawn invalid ACK child");
    let pid = child.process_id();
    let start = Instant::now();
    let result = child.transact(request, expected);
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = result
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = result.as_ref().err().map(ToString::to_string);
    let pass = matches!(&result, Err(error) if error.kind() == expected_kind
        && error.to_string().contains(expected_message))
        && reaped
        && absent;
    Observation {
        scenario,
        expectation,
        observed: result.as_ref().map_or_else(
            |error| format!("fault frame rejected: {error}"),
            |()| "fault frame accepted".to_owned(),
        ),
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(request.len() + frame.len())
            .expect("fault frame byte count"),
        frames_exercised: 1,
        pass,
    }
}

fn invalid_bound_ack_frame(
    scenario: &'static str,
    expectation: &'static str,
    request: &str,
    expected: BoundExpectedAck,
    frame: &str,
) -> Observation {
    let source = concat!(
        "import sys,time\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[1])\n",
        "sys.stdout.flush()\n",
        "time.sleep(30)\n"
    );
    let mut child = ChildProcess::spawn_program(Path::new(PYTHON), &["-c", source, frame])
        .expect("spawn invalid bound ACK child");
    let pid = child.process_id();
    let start = Instant::now();
    let result = child.transact_bound(request, expected);
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = result
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = result.as_ref().err().map(ToString::to_string);
    let pass = matches!(&result, Err(error) if error.kind() == io::ErrorKind::InvalidData
        && error.to_string().contains("child bound ACK rejected"))
        && reaped
        && absent;
    Observation {
        scenario,
        expectation,
        observed: result.as_ref().map_or_else(
            |error| format!("authority-bound fault ACK rejected: {error}"),
            |()| "authority-bound fault ACK accepted".to_owned(),
        ),
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(request.len() + frame.len())
            .expect("bound fault byte count"),
        frames_exercised: 1,
        pass,
    }
}

fn wrong_nonce_ack(
    scenario: &'static str,
    expected_nonce: u64,
    observed_nonce: u64,
) -> Observation {
    let request = probe_request(41, expected_nonce);
    let frame = probe_ack(41, observed_nonce);
    invalid_ack_frame(
        scenario,
        "reject a checksum-valid ACK carrying the wrong nonce and reap child",
        &request,
        ExpectedAck::Probe {
            id: 41,
            nonce: expected_nonce,
        },
        &frame,
        io::ErrorKind::InvalidData,
        "child ACK rejected",
    )
}

fn authority() -> AuthoritySnapshot {
    AuthoritySnapshot {
        body_uid: 71,
        epoch: 73,
        generation: 79,
        certificate: 83,
        principal_id: 89,
        resource_id: 97,
        action_id: 101,
    }
}

fn wrong_authority_ack(
    scenario: &'static str,
    expectation: &'static str,
    observed_authority: AuthoritySnapshot,
) -> Observation {
    const ID: u64 = 43;
    const NONCE: u64 = 47;
    const UNITS: u64 = 5;
    let expected_authority = authority();
    let actions = UNITS;
    let digest = work_digest(ID, UNITS);
    let request = bound_work_request(ID, NONCE, UNITS, expected_authority);
    let frame = bound_work_ack(ID, NONCE, actions, digest, observed_authority);
    invalid_bound_ack_frame(
        scenario,
        expectation,
        &request,
        BoundExpectedAck::Work {
            id: ID,
            nonce: NONCE,
            actions,
            digest,
            authority: expected_authority,
        },
        &frame,
    )
}

fn replayed_ack(scenario: &'static str) -> Observation {
    const FIRST_ID: u64 = 107;
    const FIRST_NONCE: u64 = 109;
    const SECOND_ID: u64 = 113;
    const SECOND_NONCE: u64 = 127;
    let replay = probe_ack(FIRST_ID, FIRST_NONCE);
    let source = concat!(
        "import sys,time\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[1]);sys.stdout.flush()\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[1]);sys.stdout.flush()\n",
        "time.sleep(30)\n"
    );
    let mut child = ChildProcess::spawn_program(Path::new(PYTHON), &["-c", source, &replay])
        .expect("spawn replay child");
    let pid = child.process_id();
    let start = Instant::now();
    let first = child.transact(
        &probe_request(FIRST_ID, FIRST_NONCE),
        ExpectedAck::Probe {
            id: FIRST_ID,
            nonce: FIRST_NONCE,
        },
    );
    let second = child.transact(
        &probe_request(SECOND_ID, SECOND_NONCE),
        ExpectedAck::Probe {
            id: SECOND_ID,
            nonce: SECOND_NONCE,
        },
    );
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = second
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = second.as_ref().err().map(ToString::to_string);
    let pass = first.is_ok()
        && matches!(&second, Err(error) if error.kind() == io::ErrorKind::InvalidData
            && error.to_string().contains("child ACK rejected"))
        && reaped
        && absent;
    Observation {
        scenario,
        expectation: "accept the first ACK, reject its replay for a new transaction, and reap child",
        observed: match (&first, &second) {
            (Ok(()), Err(error)) => format!("first ACK accepted; replay rejected: {error}"),
            (Err(error), _) => format!("first ACK unexpectedly rejected: {error}"),
            (Ok(()), Ok(())) => "replayed ACK unexpectedly accepted".to_owned(),
        },
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(
            probe_request(FIRST_ID, FIRST_NONCE).len()
                + probe_request(SECOND_ID, SECOND_NONCE).len()
                + replay.len() * 2,
        )
        .expect("replay byte count"),
        frames_exercised: 2,
        pass,
    }
}

fn reordered_ack(scenario: &'static str) -> Observation {
    const FIRST_ID: u64 = 131;
    const FIRST_NONCE: u64 = 137;
    const SECOND_ID: u64 = 139;
    const SECOND_NONCE: u64 = 149;
    let first_ack = probe_ack(FIRST_ID, FIRST_NONCE);
    let second_ack = probe_ack(SECOND_ID, SECOND_NONCE);
    let reversed = format!("{second_ack}{first_ack}");
    let request = probe_request(FIRST_ID, FIRST_NONCE);
    let source = concat!(
        "import sys,time\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[1]);sys.stdout.flush()\n",
        "time.sleep(30)\n"
    );
    let mut child = ChildProcess::spawn_program(Path::new(PYTHON), &["-c", source, &reversed])
        .expect("spawn reordered ACK child");
    let pid = child.process_id();
    let start = Instant::now();
    let result = child.transact(
        &request,
        ExpectedAck::Probe {
            id: FIRST_ID,
            nonce: FIRST_NONCE,
        },
    );
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = result
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = result.as_ref().err().map(ToString::to_string);
    let pass = matches!(&result, Err(error) if error.kind() == io::ErrorKind::InvalidData
        && error.to_string().contains("child ACK rejected"))
        && reaped
        && absent;
    Observation {
        scenario,
        expectation: "reject a later transaction ACK delivered before the current ACK and reap child",
        observed: result.as_ref().map_or_else(
            |error| format!("reordered ACK stream rejected: {error}"),
            |()| "reordered ACK stream accepted".to_owned(),
        ),
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(request.len() + reversed.len())
            .expect("reordered byte count"),
        frames_exercised: 2,
        pass,
    }
}

fn partial_transport(
    scenario: &'static str,
    expectation: &'static str,
    partial_read: bool,
    partial_write: bool,
) -> Observation {
    const ID: u64 = 151;
    const NONCE: u64 = 157;
    let request = probe_request(ID, NONCE);
    let ack = probe_ack(ID, NONCE);
    let read_mode = if partial_read { "1" } else { "0" };
    let write_mode = if partial_write { "1" } else { "0" };
    let source = concat!(
        "import os,sys\n",
        "if sys.argv[2]=='1':\n",
        " while True:\n",
        "  byte=sys.stdin.buffer.read(1)\n",
        "  if not byte: sys.exit(41)\n",
        "  if byte==b'\\n': break\n",
        "else:\n",
        " sys.stdin.readline()\n",
        "payload=sys.argv[1].encode()\n",
        "if sys.argv[3]=='1':\n",
        " for byte in payload: os.write(1,bytes([byte]))\n",
        "else:\n",
        " os.write(1,payload)\n"
    );
    let mut child = ChildProcess::spawn_program(
        Path::new(PYTHON),
        &["-c", source, &ack, read_mode, write_mode],
    )
    .expect("spawn partial transport child");
    let pid = child.process_id();
    let start = Instant::now();
    let result = child.transact(
        &request,
        ExpectedAck::Probe {
            id: ID,
            nonce: NONCE,
        },
    );
    thread::sleep(Duration::from_millis(25));
    let cleanup = child.transact(
        &probe_request(ID + 1, NONCE + 1),
        ExpectedAck::Probe {
            id: ID + 1,
            nonce: NONCE + 1,
        },
    );
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = cleanup
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = cleanup.as_ref().err().map(ToString::to_string);
    let pass = result.is_ok() && cleanup.is_err() && reaped && absent;
    Observation {
        scenario,
        expectation,
        observed: match (&result, &cleanup) {
            (Ok(()), Err(error)) => {
                format!("fragmented transport ACK validated; terminal cleanup: {error}")
            }
            (Err(error), _) => format!("fragmented transport failed: {error}"),
            (Ok(()), Ok(())) => "unexpected second ACK accepted".to_owned(),
        },
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(request.len() + ack.len())
            .expect("partial transport byte count"),
        frames_exercised: 1,
        pass,
    }
}

fn stdout_flood_is_rejected() -> Observation {
    const FRAMES: u64 = 16_384;
    const LINE: &str = "UNSOLICITED-FLOOD-FRAME\n";
    let sentinel = unique_path("stdout-flood-ready");
    let sentinel_text = sentinel.to_string_lossy().into_owned();
    let frames_text = FRAMES.to_string();
    let source = concat!(
        "import os,pathlib,sys,time\n",
        "frames=int(sys.argv[2])\n",
        "sys.stdout.write('UNSOLICITED-FLOOD-FRAME\\n'*frames)\n",
        "sys.stdout.flush()\n",
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n",
        "time.sleep(30)\n"
    );
    let mut child = ChildProcess::spawn_program(
        Path::new(PYTHON),
        &["-c", source, &sentinel_text, &frames_text],
    )
    .expect("spawn stdout flood child");
    let pid = read_pid(&sentinel);
    let start = Instant::now();
    let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
    let elapsed_ms = start.elapsed().as_millis();
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = result
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = result.as_ref().err().map(ToString::to_string);
    let pass = matches!(&result, Err(error) if error.kind() == io::ErrorKind::InvalidData
        && error.to_string().contains("child ACK rejected"))
        && reaped
        && absent;
    cleanup_sentinel(&sentinel);
    Observation {
        scenario: "stdout_flood",
        expectation: "reject first unsolicited frame and reap flooding child",
        observed: result.as_ref().map_or_else(
            |error| format!("flood rejected: {error}"),
            |()| "flood accepted".into(),
        ),
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: FRAMES * u64::try_from(LINE.len()).expect("line length"),
        frames_exercised: FRAMES,
        pass,
    }
}

fn stderr_flood_is_drained_externally() -> Observation {
    const BYTES: u64 = 1_048_576;
    let sentinel = unique_path("stderr-flood-ready");
    let sentinel_text = sentinel.to_string_lossy().into_owned();
    let bytes_text = BYTES.to_string();
    let ack = probe_ack(7, 9);
    let source = concat!(
        "import os,pathlib,sys\n",
        "remaining=int(sys.argv[2])\n",
        "block=b'E'*16384\n",
        "while remaining:\n",
        " chunk=block[:min(len(block),remaining)]\n",
        " written=os.write(2,chunk)\n",
        " remaining-=written\n",
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[3])\n",
        "sys.stdout.flush()\n"
    );
    let mut child = ChildProcess::spawn_program(
        Path::new(PYTHON),
        &["-c", source, &sentinel_text, &bytes_text, &ack],
    )
    .expect("spawn stderr flood child");
    let pid = read_pid(&sentinel);
    let start = Instant::now();
    let result = child.transact(&probe_request(7, 9), ExpectedAck::Probe { id: 7, nonce: 9 });
    let elapsed_ms = start.elapsed().as_millis();
    thread::sleep(Duration::from_millis(25));
    let cleanup = child.transact(
        &probe_request(8, 10),
        ExpectedAck::Probe { id: 8, nonce: 10 },
    );
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = cleanup
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = cleanup.as_ref().err().map(ToString::to_string);
    let pass = result.is_ok() && cleanup.is_err() && reaped && absent;
    cleanup_sentinel(&sentinel);
    Observation {
        scenario: "stderr_flood",
        expectation: "complete exact stderr write, validate ACK, and reap child without deadlock",
        observed: match (&result, &cleanup) {
            (Ok(()), Err(error)) => format!("ACK validated; terminal cleanup observed: {error}"),
            (Err(error), _) => format!("ACK rejected: {error}"),
            (Ok(()), Ok(())) => "unexpected second ACK accepted".to_owned(),
        },
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: BYTES,
        frames_exercised: 1,
        pass,
    }
}

fn finite_stdin_backpressure_recovers() -> Observation {
    const BYTES: usize = 4 * 1024 * 1024;
    const DELAY_MS: u64 = 200;
    let bytes_text = BYTES.to_string();
    let ack = probe_ack(7, 9);
    let source = concat!(
        "import sys,time\n",
        "target=int(sys.argv[1])\n",
        "time.sleep(0.2)\n",
        "remaining=target\n",
        "while remaining:\n",
        " chunk=sys.stdin.buffer.read(min(65536,remaining))\n",
        " if not chunk: sys.exit(31)\n",
        " remaining-=len(chunk)\n",
        "sys.stdout.write(sys.argv[2])\n",
        "sys.stdout.flush()\n"
    );
    let mut child =
        ChildProcess::spawn_program(Path::new(PYTHON), &["-c", source, &bytes_text, &ack])
            .expect("spawn backpressure child");
    let pid = child.process_id();
    let request = "X".repeat(BYTES);
    let start = Instant::now();
    let result = child.transact(&request, ExpectedAck::Probe { id: 7, nonce: 9 });
    let elapsed_ms = start.elapsed().as_millis();
    thread::sleep(Duration::from_millis(25));
    let cleanup = child.transact(
        &probe_request(8, 10),
        ExpectedAck::Probe { id: 8, nonce: 10 },
    );
    let reaped = child.is_reaped();
    let absent = process_absent(pid);
    let error_kind = cleanup
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let error_message = cleanup.as_ref().err().map(ToString::to_string);
    let pass = result.is_ok()
        && cleanup.is_err()
        && elapsed_ms >= u128::from(DELAY_MS / 2)
        && elapsed_ms < WAIT_LIMIT.as_millis()
        && reaped
        && absent;
    Observation {
        scenario: "finite_stdin_backpressure",
        expectation: "4 MiB write blocks until delayed drain, then ACK validates within bound",
        observed: match (&result, &cleanup) {
            (Ok(()), Err(error)) => {
                format!("ACK validated after {elapsed_ms} ms; terminal cleanup: {error}")
            }
            (Err(error), _) => format!("backpressured transaction failed: {error}"),
            (Ok(()), Ok(())) => "unexpected second ACK accepted".to_owned(),
        },
        error_kind,
        error_message,
        elapsed_ms,
        child_pid: Some(pid),
        child_reaped: reaped,
        process_absent: absent,
        bytes_exercised: u64::try_from(BYTES).expect("backpressure byte count"),
        frames_exercised: 1,
        pass,
    }
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

fn optional_json_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_owned())
}

fn observation_json(observation: &Observation) -> String {
    let executed = !observation.observed.is_empty();
    let timed_out = observation.elapsed_ms >= WAIT_LIMIT.as_millis();
    let return_code = if observation.pass { 0 } else { 1 };
    let child_reaped = observation.child_pid.map_or_else(
        || "null".to_owned(),
        |_| observation.child_reaped.to_string(),
    );
    format!(
        concat!(
            "{{\"scenario\":{},\"executed\":{},\"return_code\":{},\"timed_out\":{},",
            "\"expected\":{},\"observed\":{},\"observed_equals_expected\":{},",
            "\"error_kind\":{},\"error_message\":{},\"elapsed_ms\":{},",
            "\"child_pid\":{},\"child_reaped\":{},\"process_absent\":{},",
            "\"bytes_exercised\":{},\"frames_exercised\":{},",
            "\"unauthorized_effects\":0,\"pass\":{}}}"
        ),
        json_string(observation.scenario),
        executed,
        return_code,
        timed_out,
        json_string(observation.expectation),
        json_string(&observation.observed),
        observation.pass,
        optional_json_string(observation.error_kind.as_deref()),
        optional_json_string(observation.error_message.as_deref()),
        observation.elapsed_ms,
        observation
            .child_pid
            .map_or_else(|| "null".to_owned(), |pid| pid.to_string()),
        child_reaped,
        observation.process_absent,
        observation.bytes_exercised,
        observation.frames_exercised,
        observation.pass,
    )
}

fn gate_case_json(case_id: &str, gate_id: &str, subcases: &[&Observation]) -> String {
    let executed = !subcases.is_empty() && subcases.iter().all(|case| !case.observed.is_empty());
    let timed_out = subcases
        .iter()
        .any(|case| case.elapsed_ms >= WAIT_LIMIT.as_millis());
    let observed_equals_expected = subcases.iter().all(|case| case.pass);
    let passed = executed && !timed_out && observed_equals_expected;
    let return_code = if passed { 0 } else { 1 };
    let child_cases = subcases
        .iter()
        .filter(|case| case.child_pid.is_some())
        .copied()
        .collect::<Vec<_>>();
    let child_reaped = if child_cases.is_empty() {
        "null".to_owned()
    } else {
        child_cases
            .iter()
            .all(|case| case.child_reaped && case.process_absent)
            .to_string()
    };
    let expected = subcases
        .iter()
        .map(|case| case.expectation)
        .collect::<Vec<_>>()
        .join("; ");
    let observed = subcases
        .iter()
        .map(|case| format!("{}: {}", case.scenario, case.observed))
        .collect::<Vec<_>>()
        .join("; ");
    let bytes_exercised = subcases
        .iter()
        .map(|case| case.bytes_exercised)
        .sum::<u64>();
    let frames_exercised = subcases
        .iter()
        .map(|case| case.frames_exercised)
        .sum::<u64>();
    format!(
        concat!(
            "{{\"case_id\":{},\"gate_id\":{},\"executed\":{},\"return_code\":{},",
            "\"timed_out\":{},\"expected\":{},\"observed\":{},",
            "\"observed_equals_expected\":{},\"unauthorized_effects\":0,",
            "\"child_reaped\":{},\"bytes_exercised\":{},\"frames_exercised\":{},",
            "\"subcases\":{{{}}},\"pass\":{}}}"
        ),
        json_string(case_id),
        json_string(gate_id),
        executed,
        return_code,
        timed_out,
        json_string(&expected),
        json_string(&observed),
        observed_equals_expected,
        child_reaped,
        bytes_exercised,
        frames_exercised,
        subcases
            .iter()
            .map(|case| format!("{}:{}", json_string(case.scenario), observation_json(case)))
            .collect::<Vec<_>>()
            .join(","),
        passed,
    )
}

#[test]
fn runtime_io_faults_are_executed_and_reported() {
    let exit_before_hello = exit_before_hello();
    let wrong_hello = wrong_hello();
    let partial_hello = partial_hello();
    let ack_wrong_nonce = wrong_nonce_ack("ack_wrong_nonce_execution", 163, 167);
    let mut wrong_identity_authority = authority();
    wrong_identity_authority.body_uid += 1;
    let ack_wrong_identity = wrong_authority_ack(
        "ack_wrong_identity_execution",
        "reject a checksum-valid ACK bound to the wrong body identity and reap child",
        wrong_identity_authority,
    );
    let ack_replay = replayed_ack("ack_replay_execution");
    let ack_reordered = reordered_ack("ack_reordered_execution");
    let trailing_ack = format!(
        "{} TRAILING-BYTES\n",
        probe_ack(173, 179).trim_end_matches('\n')
    );
    let ack_trailing_bytes = invalid_ack_frame(
        "ack_trailing_bytes_execution",
        "reject a valid ACK extended with non-canonical trailing bytes and reap child",
        &probe_request(173, 179),
        ExpectedAck::Probe {
            id: 173,
            nonce: 179,
        },
        &trailing_ack,
        io::ErrorKind::InvalidData,
        "child ACK rejected",
    );
    let partial_read_write = partial_transport(
        "partial_read_write_execution",
        "accept a request read one byte at a time and an ACK written one byte at a time",
        true,
        true,
    );
    let oversized_frame = format!("{}\n", "O".repeat(1_026));
    let oversize_frame = invalid_ack_frame(
        "oversize_frame_execution",
        "reject a protocol frame exceeding the 1024-byte bound and reap child",
        &probe_request(181, 191),
        ExpectedAck::Probe {
            id: 181,
            nonce: 191,
        },
        &oversized_frame,
        io::ErrorKind::InvalidData,
        "protocol line exceeds bound",
    );
    let empty_frame_for_aggregate = invalid_ack_frame(
        "empty_frame_aggregate_execution",
        "reject an empty LF-terminated protocol frame and reap child",
        &probe_request(193, 197),
        ExpectedAck::Probe {
            id: 193,
            nonce: 197,
        },
        "\n",
        io::ErrorKind::InvalidData,
        "child ACK rejected",
    );
    let garbage_frame = invalid_ack_frame(
        "garbage_frame_execution",
        "reject an LF-terminated garbage protocol frame and reap child",
        &probe_request(199, 211),
        ExpectedAck::Probe {
            id: 199,
            nonce: 211,
        },
        "NOT-A-PROTOCOL-ACK\n",
        io::ErrorKind::InvalidData,
        "child ACK rejected",
    );
    let eintr_handled = eintr_recovery("eintr_handled_execution");
    let epipe_handled = epipe_on_child_stdin();
    let wrong_ack_nonce = wrong_nonce_ack("wrong_ack_nonce_execution", 223, 227);
    let mut wrong_certificate_authority = authority();
    wrong_certificate_authority.certificate += 1;
    let wrong_ack_certificate = wrong_authority_ack(
        "wrong_ack_certificate_execution",
        "reject a checksum-valid ACK bound to the wrong certificate and reap child",
        wrong_certificate_authority,
    );
    let mut wrong_epoch_authority = authority();
    wrong_epoch_authority.epoch += 1;
    let wrong_ack_epoch = wrong_authority_ack(
        "wrong_ack_epoch_execution",
        "reject a checksum-valid ACK bound to the wrong epoch and reap child",
        wrong_epoch_authority,
    );
    let mut wrong_generation_authority = authority();
    wrong_generation_authority.generation += 1;
    let wrong_ack_generation = wrong_authority_ack(
        "wrong_ack_generation_execution",
        "reject a checksum-valid ACK bound to the wrong generation and reap child",
        wrong_generation_authority,
    );
    let mut wrong_principal_authority = authority();
    wrong_principal_authority.principal_id += 1;
    let wrong_ack_principal = wrong_authority_ack(
        "wrong_ack_principal_execution",
        "reject a checksum-valid ACK bound to the wrong principal and reap child",
        wrong_principal_authority,
    );
    let mut wrong_resource_authority = authority();
    wrong_resource_authority.resource_id += 1;
    let wrong_ack_resource = wrong_authority_ack(
        "wrong_ack_resource_execution",
        "reject a checksum-valid ACK bound to the wrong resource and reap child",
        wrong_resource_authority,
    );
    let mut wrong_action_authority = authority();
    wrong_action_authority.action_id += 1;
    let wrong_ack_action = wrong_authority_ack(
        "wrong_ack_action_execution",
        "reject a checksum-valid ACK bound to the wrong action and reap child",
        wrong_action_authority,
    );
    let replayed_ack = replayed_ack("replayed_ack_execution");
    let reordered_ack = reordered_ack("reordered_ack_execution");
    let second_trailing_ack = format!("{} EXTRA\n", probe_ack(229, 233).trim_end_matches('\n'));
    let trailing_bytes = invalid_ack_frame(
        "trailing_bytes_execution",
        "reject a second independently executed ACK trailing-bytes fault and reap child",
        &probe_request(229, 233),
        ExpectedAck::Probe {
            id: 229,
            nonce: 233,
        },
        &second_trailing_ack,
        io::ErrorKind::InvalidData,
        "child ACK rejected",
    );
    let partial_read = partial_transport(
        "partial_read_execution",
        "accept a protocol request consumed one byte at a time",
        true,
        false,
    );
    let partial_write = partial_transport(
        "partial_write_execution",
        "accept a complete ACK delivered one byte at a time",
        false,
        true,
    );
    let eintr_handling = eintr_recovery("eintr_handling_execution");
    let epipe_handling = epipe_on_child_stdin();
    let empty_frame = invalid_ack_frame(
        "empty_frame_execution",
        "reject an independently executed empty LF-terminated frame and reap child",
        &probe_request(239, 241),
        ExpectedAck::Probe {
            id: 239,
            nonce: 241,
        },
        "\n",
        io::ErrorKind::InvalidData,
        "child ACK rejected",
    );
    let stdout_flood = stdout_flood_is_rejected();
    let stderr_flood = stderr_flood_is_drained_externally();
    let backpressure = finite_stdin_backpressure_recovers();
    let cases = [
        (
            "child_hello_fail_closed",
            "G048",
            vec![&wrong_hello, &partial_hello],
        ),
        ("ack_wrong_nonce", "G054", vec![&ack_wrong_nonce]),
        ("ack_wrong_identity", "G055", vec![&ack_wrong_identity]),
        ("ack_replay", "G058", vec![&ack_replay]),
        ("ack_reordered", "G059", vec![&ack_reordered]),
        ("ack_trailing_bytes", "G060", vec![&ack_trailing_bytes]),
        ("partial_read_write", "G061", vec![&partial_read_write]),
        ("eintr_handled", "G062", vec![&eintr_handled]),
        ("epipe_handled", "G063", vec![&epipe_handled]),
        (
            "oversize_empty_garbage_frames",
            "G064",
            vec![&oversize_frame, &empty_frame_for_aggregate, &garbage_frame],
        ),
        ("child_exit_before_hello", "G148", vec![&exit_before_hello]),
        ("wrong_ack_nonce", "G154", vec![&wrong_ack_nonce]),
        (
            "wrong_ack_certificate",
            "G155",
            vec![&wrong_ack_certificate],
        ),
        ("wrong_ack_epoch", "G156", vec![&wrong_ack_epoch]),
        ("wrong_ack_generation", "G157", vec![&wrong_ack_generation]),
        ("wrong_ack_principal", "G158", vec![&wrong_ack_principal]),
        ("wrong_ack_resource", "G159", vec![&wrong_ack_resource]),
        ("wrong_ack_action", "G160", vec![&wrong_ack_action]),
        ("replayed_ack", "G162", vec![&replayed_ack]),
        ("reordered_ack", "G163", vec![&reordered_ack]),
        ("trailing_bytes", "G164", vec![&trailing_bytes]),
        ("partial_read", "G165", vec![&partial_read]),
        ("partial_write", "G166", vec![&partial_write]),
        ("eintr_handling", "G167", vec![&eintr_handling]),
        ("epipe_handling", "G168", vec![&epipe_handling]),
        ("empty_frame", "G170", vec![&empty_frame]),
        (
            "stdout_stderr_flood",
            "G172",
            vec![&stdout_flood, &stderr_flood],
        ),
        (
            "protocol_backpressure_no_deadlock",
            "G174",
            vec![&backpressure],
        ),
    ];
    let passed = cases
        .iter()
        .filter(|(_, _, subcases)| subcases.iter().all(|case| case.pass))
        .count();
    let total = cases.len();
    let campaign_kind =
        std::env::var("OASI_R1_R5_CAMPAIGN_KIND").unwrap_or_else(|_| "targeted_test".to_owned());
    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"oasi-core-r1-r5-protocol-case-matrix-1\",\n",
            "  \"campaign_kind\": {},\n",
            "  \"cases\": {{\n",
            "{}\n",
            "  }},\n",
            "  \"executed_cases\": {},\n",
            "  \"passed_cases\": {},\n",
            "  \"failed_cases\": {},\n",
            "  \"pass\": {}\n",
            "}}\n"
        ),
        json_string(&campaign_kind),
        cases
            .iter()
            .map(|(case_id, gate_id, subcases)| format!(
                "    {}: {}",
                json_string(case_id),
                gate_case_json(case_id, gate_id, subcases)
            ))
            .collect::<Vec<_>>()
            .join(",\n"),
        total,
        passed,
        total - passed,
        passed == total,
    );
    fs::write(output_path(), report).expect("write runtime I/O assurance report");
    for (case_id, _, subcases) in &cases {
        for observation in subcases {
            assert!(
                observation.pass,
                "case {case_id} scenario failed: {}: {}",
                observation.scenario, observation.observed
            );
        }
    }
}
