//! Precision-measurement harness for the install-gate profiler.
//!
//! Resolves each package spec passed on the command line through the real
//! `add_package_graph` registry API (the same path `omc inspect`/`omc add`
//! take) into a unique throwaway project dir, records blocked packages instead
//! of aborting, and prints ONE JSON object per resolved package (the requested
//! root only, not its transitive deps) to stdout — one JSON object per line.
//!
//! Each line carries the full per-finding detail the human renderers collapse:
//! `{ecosystem, name, version, verdict, files_scanned, capabilities:[{kind,
//! target, source, evidence}], verifier_findings:[..]}`. This is read-only:
//! `omc inspect` semantics, no install scripts, nothing written to the user's
//! project. Errors are emitted as `{spec, error}` lines so a single failed
//! resolution never aborts the whole corpus run.
//!
//! Usage: omc-corpus-capture pypi:numpy pypi:pandas npm:esbuild ...
//! (Set OMC_HOME to an isolated empty dir before running for a clean cache.)

use std::path::PathBuf;

use omc_registry::{add_package_graph, LinkOptions, PackageSpec};
use serde_json::json;

fn main() {
    let specs: Vec<String> = std::env::args().skip(1).collect();
    if specs.is_empty() {
        eprintln!("usage: corpus_capture <spec> [<spec> ...]");
        std::process::exit(2);
    }

    // One scratch project dir reused across specs: add_package_graph treats it
    // purely as LinkOptions::project_dir, and each spec resolves independently.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let scratch: PathBuf =
        std::env::temp_dir().join(format!("omc-corpus-{}-{nonce}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch);

    for raw in &specs {
        let spec = match PackageSpec::parse(raw) {
            Ok(s) => s,
            Err(e) => {
                println!("{}", json!({"spec": raw, "error": format!("parse: {e}")}));
                continue;
            }
        };

        let mut options = LinkOptions::new(&scratch);
        // Record (don't throw on) blocked packages — mirror `omc inspect`.
        options.record_blocked = true;

        match add_package_graph(&spec, &options) {
            Ok(reports) => {
                // The first report is the requested root; deps follow. Capture
                // only the root so the corpus is keyed to the requested package
                // (deps of one package may themselves be in the corpus).
                if let Some(report) = reports.first() {
                    let locked = &report.locked;
                    let art = &report.artifact;
                    let caps: Vec<_> = art
                        .capabilities
                        .iter()
                        .map(|f| {
                            json!({
                                "kind": format!("{}", f.kind),
                                "target": f.target,
                                "source": f.source,
                                "evidence": f.evidence,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        json!({
                            "spec": raw,
                            "ecosystem": format!("{}", locked.ecosystem),
                            "name": locked.name,
                            "version": locked.version,
                            "verdict": format!("{:?}", locked.verdict),
                            "behavior": format!("{:?}", locked.behavior),
                            "files_scanned": art.files_scanned,
                            "capabilities": caps,
                            "verifier_findings": art.verifier_findings,
                        })
                    );
                } else {
                    println!("{}", json!({"spec": raw, "error": "no reports"}));
                }
            }
            Err(e) => {
                println!("{}", json!({"spec": raw, "error": format!("{e}")}));
            }
        }
    }

    let _ = std::fs::remove_dir_all(&scratch);
}
