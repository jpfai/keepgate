use std::io::{self, Read};
use std::process;

use keepgate::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let command = &args[1];
    
    match command.as_str() {
        "classify" => cmd_classify(),
        "check" => cmd_check(),
        "detect" => cmd_detect(),
        "redact" => cmd_redact(),
        "version" => println!("keepgate v0.1.0"),
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: keepgate <command> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  classify   Read stdin, output JSON with sensitivity classification");
    eprintln!("  check      Read stdin, check if output is safe (exit 1 if blocked)");
    eprintln!("  detect     Read stdin, detect secrets (exit 1 if found)");
    eprintln!("  redact     Read stdin, output with secrets redacted");
    eprintln!("  version    Print version");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  echo 'hello world' | keepgate classify");
    eprintln!("  echo 'sk-abc123' | keepgate detect");
    eprintln!("  echo 'key sk-abc123' | keepgate redact");
}

fn read_stdin() -> Vec<u8> {
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer).expect("Failed to read stdin");
    buffer
}

fn cmd_classify() {
    let data = read_stdin();
    let classifier = BasicClassifier::new();
    let ctx = DataContext::new(DataSource::User);
    let tag = classifier.classify(&data, &ctx);
    
    let result = serde_json::json!({
        "sensitivity": tag.sensitivity.to_string(),
        "source": format!("{:?}", tag.source),
        "id": tag.id.to_string(),
        "created_at": tag.created_at,
    });
    
    println!("{}", result);
}

fn cmd_check() {
    let data = read_stdin();
    let classifier = BasicClassifier::new();
    let ctx = DataContext::new(DataSource::User);
    let tag = classifier.classify(&data, &ctx);
    
    let gate = BasicOutputGate::with_approval_provider(DefaultApprovalProvider::deny_all());
    let destination = Destination::Message { channel: "cli".to_string() };
    let output = DataOutput::new(data.clone(), destination, tag.clone());
    
    match gate.check(&output, &tag) {
        Ok(()) => {
            println!(r#"{{"status":"ok","sensitivity":"{}"}}"#, tag.sensitivity);
        }
        Err(e) => {
            eprintln!("BLOCKED: {}", e);
            println!(r#"{{"status":"blocked","error":"{}","sensitivity":"{}"}}"#, e, tag.sensitivity);
            process::exit(1);
        }
    }
}

fn cmd_detect() {
    let data = read_stdin();
    let secrets = detect_secrets(&data);
    
    if secrets.is_empty() {
        println!(r#"{{"secrets_found":0}}"#);
    } else {
        let items: Vec<serde_json::Value> = secrets.iter().map(|s| {
            serde_json::json!({
                "pattern_type": format!("{:?}", s.pattern_type),
                "location": s.location,
                "confidence": s.confidence,
            })
        }).collect();
        
        let result = serde_json::json!({
            "secrets_found": secrets.len(),
            "items": items,
        });
        println!("{}", result);
        process::exit(1);
    }
}

fn cmd_redact() {
    let data = read_stdin();
    let classifier = BasicClassifier::new();
    let ctx = DataContext::new(DataSource::User);
    let tag = classifier.classify(&data, &ctx);
    
    let gate = BasicOutputGate::new();
    let destination = Destination::Log;
    let mut output = DataOutput::new(data.clone(), destination, tag.clone());
    
    let report = gate.redact(&mut output, &tag);
    
    if report.fields_redacted > 0 {
        eprintln!("Redacted {} secrets", report.fields_redacted);
        let result = serde_json::json!({
            "status": "redacted",
            "fields_redacted": report.fields_redacted,
            "patterns_found": report.patterns_found,
            "output": String::from_utf8_lossy(&output.data),
        });
        println!("{}", result);
    } else {
        let result = serde_json::json!({
            "status": "clean",
            "output": String::from_utf8_lossy(&output.data),
        });
        println!("{}", result);
    }
}
