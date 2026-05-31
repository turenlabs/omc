use crate::*;

use omc_registry::{LinkOptions, OmcRegistryError};

#[derive(Clone, Copy)]
pub(crate) struct CliPolicyArgs<'a> {
    pub(crate) allow: &'a [String],
    pub(crate) allow_flow: &'a [String],
    pub(crate) allow_all_host: bool,
}

impl<'a> CliPolicyArgs<'a> {
    pub(crate) fn new(allow: &'a [String], allow_flow: &'a [String], allow_all_host: bool) -> Self {
        Self {
            allow,
            allow_flow,
            allow_all_host,
        }
    }
}

pub(crate) fn apply_cli_policy_options(
    options: &mut LinkOptions,
    allow: &[String],
    allow_flow: &[String],
    allow_all_host: bool,
) -> Result<(), OmcRegistryError> {
    options.allowed_capabilities = parse_grants(allow, allow_all_host)?;
    options.allowed_flows = parse_flow_grants(allow_flow)?;
    Ok(())
}
