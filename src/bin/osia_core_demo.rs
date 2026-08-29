use osia_core_r1::runtime::{Runtime, child_loop};
use std::env;
use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    if env::args().any(|arg| arg == "--child") {
        return child_loop();
    }
    let executable = env::current_exe()?;
    let ledger_path = env::args()
        .skip_while(|arg| arg != "--ledger")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("osia_core_r1_ledger.jsonl"));
    let metrics = Runtime::new(&executable, &ledger_path)?.run()?;
    println!("{metrics:#?}");
    if metrics.damage == 0 && metrics.blocked_commits >= 2 {
        Ok(())
    } else {
        Err(io::Error::other("runtime gate failed"))
    }
}
