// SPDX-License-Identifier: CC-BY-NC-SA-4.0

use anyhow::{Context, Result};
use kagi_object_store::placement::PlacementPlan;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Identifies one deployment policy in a kagi-config output file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerOutputRef {
    pub path: PathBuf,
    pub policy: String,
}

#[derive(Deserialize)]
struct PlannerOutput {
    policies: BTreeMap<String, PolicyOutput>,
    join_admission: JoinAdmission,
}

#[derive(Deserialize)]
struct PolicyOutput {
    deployment: Option<PlacementPlan>,
}

#[derive(Deserialize)]
struct JoinAdmission {
    key_hash_hex: String,
}

impl PlannerOutputRef {
    /// Resolve relative output paths against the file containing the reference.
    pub fn load(&self, config_path: &Path) -> Result<(PlacementPlan, String)> {
        let path = config_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(&self.path);
        let input = fs::read_to_string(&path)
            .with_context(|| format!("read kagi-config output {}", path.display()))?;
        let mut output: PlannerOutput = serde_saphyr::from_str(&input)
            .with_context(|| format!("parse kagi-config output {}", path.display()))?;
        let plan = output
            .policies
            .remove(&self.policy)
            .with_context(|| format!("kagi-config output has no policy {:?}", self.policy))?
            .deployment
            .context("selected policy has no deployment plan")?;
        Ok((plan, output.join_admission.key_hash_hex))
    }
}
