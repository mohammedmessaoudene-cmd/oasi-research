//! Bounded local adapter to the unchanged published AERA decision model.
//! This is not the Linux PID1 guardian, a cryptographic issuer, or an OS sandbox.
#![forbid(unsafe_code)]
#[allow(dead_code)]
mod model;
use std::io::{self, BufRead, Read, Write};
use model::{BodyState, SafetyLease, CommitRequest, PolicyIr, Goal};

fn evaluate(line: &str) -> Result<String, &'static str> {
    let mut fields=line.split_whitespace();
    let op=fields.next().ok_or("EMPTY")?;
    let args:Vec<u64>=fields.map(|v|v.parse::<u64>().map_err(|_|"INTEGER")).collect::<Result<_,_>>()?;
    match op {
        "G" if args.len()==17 && args[4]<=1 => {
            let a=&args;
            let body=BodyState{body_uid:a[0],epoch:a[1],generation:a[2],certificate:a[3],quarantined:a[4]==1};
            let lease=SafetyLease{body_uid:a[5],epoch:a[6],generation:a[7],certificate:a[8],valid_until_ns:a[9],principal_id:a[10],resource_id:a[11],action_id:a[12]};
            let req=CommitRequest{now_ns:a[13],principal_id:a[14],resource_id:a[15],action_id:a[16]};
            Ok(model::validate_commit(&body,Some(&lease),&req).as_str().to_string())
        },
        "C" if args.len()==6 => {
            let a=&args;
            let policy=PolicyIr{policy_id:a[1],principal_id:a[2],resource_id:a[3],action_id:a[4],goal:Goal::ExecuteChildWork{units:a[0]},max_units:524288,lease_ns:a[5],rollback_required:true};
            match model::compile_policy(&policy) {
                Ok(program) => match program.instructions.first() {
                    Some(model::ReflexInstruction::Work{units}) => Ok(format!("COMPILED {units}")),
                    _ => Err("INSTRUCTION"),
                },
                Err(_) => Err("POLICY"),
            }
        },
        _=>Err("SCHEMA"),
    }
}

fn main()->io::Result<()> {
    let input=io::stdin();let mut reader=input.lock();let mut output=io::stdout().lock();
    loop {
        let mut raw=Vec::new();let count=reader.by_ref().take(1025).read_until(b'\n',&mut raw)?;
        if count==0 {break}
        if count>1024 || !raw.ends_with(b"\n") {writeln!(output,"ERROR BOUNDS")?;output.flush()?;break}
        let result=std::str::from_utf8(&raw).map_err(|_|"UTF8").and_then(evaluate);
        match result {Ok(value)=>writeln!(output,"{value}")?,Err(reason)=>writeln!(output,"ERROR {reason}")?}
        output.flush()?;
    }
    Ok(())
}
