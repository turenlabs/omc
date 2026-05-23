use omc_cap::{Capability, Policy};
use omc_verify::{malicious_date_helper_module, verify_module};

fn main() {
    let module = malicious_date_helper_module();
    let policy = Policy::pure()
        .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
        .allow_capability(Capability::HttpHost(
            "cdn-update-service.example".to_owned(),
        ));

    println!("Package: {}@{}", module.package, module.version);
    println!("Claimed type: {:?}", module.declared_behavior);
    println!();

    match verify_module(&module, &policy) {
        Ok(report) => {
            println!("Compile result: ACCEPTED");
            println!("Observed capabilities:");
            for capability in report.observed_capabilities {
                println!("  + {capability}");
            }
        }
        Err(error) => {
            println!("Compile result: FAILED");
            println!();
            println!("Verifier findings:");
            for finding in error.findings {
                println!(
                    "  - {}[{}]: {}",
                    finding.function, finding.instruction, finding.message
                );
            }
        }
    }
}
