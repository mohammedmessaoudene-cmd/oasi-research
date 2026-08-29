use osia_core_r1::ledger::verify_path;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: osia-core-r1-ledger-verify LEDGER --output REPORT.json",
    )
}

fn main() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let ledger_path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err(usage());
    }
    let output_path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if arguments.next().is_some() {
        return Err(usage());
    }

    let report = verify_path(&ledger_path)?;
    let rendered = report.to_json();
    fs::write(&output_path, &rendered)?;
    print!("{rendered}");
    if report.passed() {
        Ok(())
    } else {
        Err(io::Error::other("ledger verification failed"))
    }
}
