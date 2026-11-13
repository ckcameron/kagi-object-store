// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Shared 60-bit addressing, shard placement, and mixed-outage verification.

use crate::erasure::{lrc_basis, ErasureLayout, ErasureScheme};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const KEYSPACE_BITS: u8 = 60;
const KEYSPACE_SIZE: u64 = 1 << KEYSPACE_BITS;
pub const TWO_SITE_ACKNOWLEDGMENT: &str =
    "I ACCEPT THAT LOSING A SITE CAN MAKE OBJECTS UNAVAILABLE";
const VERIFICATION_STEPS: usize = 2_000_000;

pub fn mask_position(position: u64) -> u64 {
    position & (KEYSPACE_SIZE - 1)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DomainDisk {
    pub id: String,
    pub host: String,
    pub rack: Option<String>,
    pub site: Option<String>,
    #[serde(default)]
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct FailureBudget {
    pub sites: usize,
    pub racks: usize,
    pub hosts: usize,
    pub disks: usize,
    pub networks: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtectionLayout {
    Replication { copies: usize },
    ReedSolomon { k: usize, m: usize },
    Lrc { k: usize, m: usize },
    Msr { k: usize, m: usize, d: usize },
    Clay { k: usize, m: usize, d: usize },
}

impl ProtectionLayout {
    pub fn erasure_layout(self) -> Option<ErasureLayout> {
        let (scheme, data_shards, parity_shards, repair_helpers) = match self {
            Self::Replication { .. } => return None,
            Self::ReedSolomon { k, m } => (ErasureScheme::ReedSolomon, k, m, None),
            Self::Lrc { k, m } => (ErasureScheme::Lrc, k, m, None),
            Self::Msr { k, m, d } => (ErasureScheme::Msr, k, m, Some(d)),
            Self::Clay { k, m, d } => (ErasureScheme::Clay, k, m, Some(d)),
        };
        Some(ErasureLayout {
            scheme,
            data_shards,
            parity_shards,
            repair_helpers,
        })
    }

    pub fn fragments(self) -> usize {
        match self {
            Self::Replication { copies } => copies,
            Self::ReedSolomon { k, m }
            | Self::Lrc { k, m }
            | Self::Msr { k, m, .. }
            | Self::Clay { k, m, .. } => k.saturating_add(m),
        }
    }

    pub fn data_fragments(self) -> usize {
        self.erasure_layout().map_or(1, |layout| layout.data_shards)
    }

    pub fn validate(self) -> Result<()> {
        if let Some(layout) = self.erasure_layout() {
            ensure!(
                layout
                    .data_shards
                    .checked_add(layout.parity_shards)
                    .is_some(),
                "erasure shard count overflows"
            );
            layout.validate()?;
        } else {
            ensure!(self.fragments() > 0, "replication needs at least one copy");
        }
        match self {
            Self::Msr { k, m, .. } => {
                // The codec needs n distinct alpha-th powers in GF(256).
                let mut a = k - 1;
                let mut b = 255;
                while b != 0 {
                    (a, b) = (b, a % b);
                }
                ensure!(
                    k + m <= 255 / a,
                    "MSR has insufficient distinct GF(256) evaluation points"
                );
            }
            Self::Clay { .. } => {
                self.shard_alignment()?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn readable(self, alive: &[bool]) -> bool {
        if alive.len() != self.fragments() {
            return false;
        }
        if let Self::Lrc { .. } = self {
            let layout = self.erasure_layout().unwrap();
            let surviving: Vec<_> = alive
                .iter()
                .enumerate()
                .filter_map(|(index, &present)| present.then_some(index))
                .collect();
            return lrc_basis(&layout, &surviving).is_ok();
        }
        alive.iter().filter(|&&present| present).count() >= self.data_fragments()
    }

    pub fn nominal_overhead(self, copies: usize) -> f64 {
        self.fragments() as f64 * copies as f64 / self.data_fragments() as f64
    }

    fn shard_alignment(self) -> Result<u64> {
        match self {
            Self::Msr { k, .. } => Ok((k - 1) as u64),
            Self::Clay { k, m, d } => {
                let q = d - k + 1;
                let exponent = (k + m).div_ceil(q) as u32;
                let alpha = (q as u32)
                    .checked_pow(exponent)
                    .context("CLAY sub-chunk count exceeds the persisted format")?;
                Ok(u64::from(alpha) * 2)
            }
            _ => Ok(1),
        }
    }

    /// Total fragment payload bytes including codec padding and each physical copy.
    pub fn payload_bytes(self, object_size: u64, copies: usize) -> Result<u64> {
        self.validate()?;
        let shard_size = if matches!(self, Self::Replication { .. }) {
            object_size
        } else {
            let alignment = self.shard_alignment()?;
            let stripe = self.data_fragments() as u64 * alignment;
            object_size
                .div_ceil(stripe)
                .max(1)
                .checked_mul(alignment)
                .context("padded shard size exceeds u64")?
        };
        shard_size
            .checked_mul(self.fragments() as u64)
            .and_then(|bytes| bytes.checked_mul(copies as u64))
            .context("total stored payload exceeds u64")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlacementPlan {
    /// Public input used to choose a deterministic layout.
    #[serde(rename = "salt")]
    pub placement_seed: u64,
    pub disks: Vec<DomainDisk>,
    pub protection: ProtectionLayout,
    pub chunk_replicas: usize,
    pub max_fragments_per_host: usize,
    pub max_fragments_per_disk: usize,
    pub tolerate: FailureBudget,
    #[serde(default)]
    pub acknowledged_unsafe_two_site: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostRange {
    pub host: String,
    pub start_key: u64,
    pub end_key: u64,
}

pub struct DiskPermutations {
    ranges: Vec<HostRange>,
    groups: Vec<Vec<usize>>,
    slots: Vec<(usize, usize)>,
}

impl DiskPermutations {
    pub fn owner_index(&self, position: u64) -> Option<usize> {
        range_index(KEYSPACE_SIZE, self.ranges.len(), position)
    }

    pub fn disk_index(&self, position: u64, index: usize) -> usize {
        let owner = self
            .owner_index(position)
            .expect("valid 60-bit object position");
        self.disk_index_for_owner(position, owner, index)
    }

    pub fn disk_index_for_owner(&self, position: u64, owner: usize, index: usize) -> usize {
        let (group, ordinal) = self.slots[index];
        let disks = &self.groups[group];
        let rotation = (position - self.ranges[owner].start_key) % disks.len() as u64;
        disks[(ordinal + rotation as usize) % disks.len()]
    }
}

fn hosts(disks: &[DomainDisk]) -> Vec<&str> {
    disks
        .iter()
        .map(|disk| disk.host.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn split_range(width: u64, count: usize, index: usize) -> (u64, u64) {
    let (count, index) = (count as u64, index as u64);
    let (base, remainder) = (width / count, width % count);
    let start = index * base + index.min(remainder);
    (start, base + u64::from(index < remainder))
}

fn range_index(width: u64, count: usize, offset: u64) -> Option<usize> {
    if count == 0 || count as u64 > width || offset >= width {
        return None;
    }
    let (base, remainder) = (width / count as u64, width % count as u64);
    let large = (base + 1) * remainder;
    let index = if offset < large {
        offset / (base + 1)
    } else {
        remainder + (offset - large) / base
    };
    Some(index as usize)
}

fn hash(parts: &[&[u8]]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kagi-placement-v1");
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().unwrap())
}

fn site(disk: &DomainDisk) -> &str {
    disk.site.as_deref().unwrap_or("")
}

fn rack(disk: &DomainDisk) -> (&str, &str) {
    (site(disk), disk.rack.as_deref().unwrap_or(""))
}

#[derive(Default)]
struct Occupancy<'a> {
    sites: BTreeMap<&'a str, usize>,
    racks: BTreeMap<(&'a str, &'a str), usize>,
    hosts: BTreeMap<&'a str, usize>,
    disks: BTreeMap<usize, usize>,
}

impl Occupancy<'_> {
    fn counts(&self, index: usize, disk: &DomainDisk) -> [usize; 4] {
        [
            *self.sites.get(site(disk)).unwrap_or(&0),
            *self.racks.get(&rack(disk)).unwrap_or(&0),
            *self.hosts.get(disk.host.as_str()).unwrap_or(&0),
            *self.disks.get(&index).unwrap_or(&0),
        ]
    }
}

impl<'a> Occupancy<'a> {
    fn add(&mut self, index: usize, disk: &'a DomainDisk) {
        *self.sites.entry(site(disk)).or_default() += 1;
        *self.racks.entry(rack(disk)).or_default() += 1;
        *self.hosts.entry(&disk.host).or_default() += 1;
        *self.disks.entry(index).or_default() += 1;
    }
}

fn locations_for_host(
    disks: &[DomainDisk],
    owner: &str,
    placement_seed: u64,
    fragments: usize,
    copies: usize,
    host_limit: usize,
    disk_limit: usize,
) -> Result<Vec<Vec<usize>>> {
    ensure!(
        fragments > 0 && copies > 0,
        "placement needs at least one fragment and copy"
    );
    ensure!(
        copies <= disks.len(),
        "a fragment cannot store multiple copies on the same disk"
    );
    ensure!(
        u32::try_from(fragments).is_ok(),
        "fragment count exceeds the persisted format"
    );
    let physical = fragments
        .checked_mul(copies)
        .context("placement count overflows")?;
    ensure!(
        physical <= disks.len().saturating_mul(disk_limit),
        "insufficient disks for fragment placement"
    );
    let mut result: Vec<Vec<usize>> = (0..fragments).map(|_| Vec::with_capacity(copies)).collect();
    let mut stripe = Occupancy::default();
    let mut by_fragment: Vec<_> = (0..fragments).map(|_| Occupancy::default()).collect();
    for copy in 0..copies {
        for (shard, targets) in result.iter_mut().enumerate() {
            let per_shard = &mut by_fragment[shard];
            let selected = disks.iter().enumerate()
                .filter_map(|(index, disk)| {
                    let global = stripe.counts(index, disk);
                    let local = per_shard.counts(index, disk);
                    if global[2] >= host_limit || global[3] >= disk_limit || local[3] != 0 {
                        return None;
                    }
                    let anchor = shard == 0 && copy == 0 && disk.host != owner;
                    let score = hash(&[
                        owner.as_bytes(), &placement_seed.to_le_bytes(), &(shard as u64).to_le_bytes(),
                        &(copy as u64).to_le_bytes(), disk.id.as_bytes(),
                    ]);
                    Some(((anchor, local, global, std::cmp::Reverse(score), &disk.id), index))
                })
                .min_by(|(a, _), (b, _)| a.cmp(b))
                .map(|(_, index)| index)
                .with_context(|| format!("cannot place shard {shard} copy {copy} for owner {owner} under locality limits"))?;
            stripe.add(selected, &disks[selected]);
            per_shard.add(selected, &disks[selected]);
            targets.push(selected);
        }
    }
    Ok(result)
}

impl PlacementPlan {
    pub fn host_ranges(&self) -> Vec<HostRange> {
        let hosts = hosts(&self.disks);
        hosts
            .iter()
            .enumerate()
            .map(|(index, host)| {
                let (start_key, width) = split_range(KEYSPACE_SIZE, hosts.len(), index);
                HostRange {
                    host: (*host).into(),
                    start_key,
                    end_key: start_key + width - 1,
                }
            })
            .collect()
    }

    pub fn owner_index(&self, position: u64) -> Option<usize> {
        range_index(KEYSPACE_SIZE, hosts(&self.disks).len(), position)
    }

    pub fn locations(&self, position: u64) -> Result<Vec<Vec<usize>>> {
        let permutations = self.permutations();
        let owner = permutations
            .owner_index(position)
            .context("object position is outside the 60-bit placement plan")?;
        let mut result = locations_for_host(
            &self.disks,
            &permutations.ranges[owner].host,
            self.placement_seed,
            self.protection.fragments(),
            self.chunk_replicas,
            self.max_fragments_per_host,
            self.max_fragments_per_disk,
        )?;
        for index in result.iter_mut().flatten() {
            *index = permutations.disk_index_for_owner(position, owner, *index);
        }
        Ok(result)
    }

    /// Rotate disks with the same host and network paths. This spreads objects
    /// over those disks without changing the verified outage envelope.
    pub fn permutations(&self) -> DiskPermutations {
        let mut grouped = BTreeMap::new();
        for (index, disk) in self.disks.iter().enumerate() {
            let networks: BTreeSet<_> = disk.networks.iter().map(String::as_str).collect();
            grouped
                .entry((&disk.host, networks))
                .or_insert_with(Vec::new)
                .push(index);
        }
        let groups: Vec<_> = grouped
            .into_values()
            .map(|mut disks| {
                disks.sort_unstable_by(|&a, &b| self.disks[a].id.cmp(&self.disks[b].id));
                disks
            })
            .collect();
        let mut slots = vec![(0, 0); self.disks.len()];
        for (group, disks) in groups.iter().enumerate() {
            for (offset, &disk) in disks.iter().enumerate() {
                slots[disk] = (group, offset);
            }
        }
        DiskPermutations {
            ranges: self.host_ranges(),
            groups,
            slots,
        }
    }

    fn host_disks(&self, host: &str) -> Vec<(usize, &DomainDisk)> {
        let mut disks: Vec<_> = self
            .disks
            .iter()
            .enumerate()
            .filter(|(_, disk)| disk.host == host)
            .collect();
        disks.sort_unstable_by(|(_, a), (_, b)| a.id.cmp(&b.id));
        disks
    }

    pub fn chunk_position(
        &self,
        object_position: u64,
        shard: usize,
        replica: usize,
        disk_index: usize,
    ) -> Result<u64> {
        ensure!(
            object_position < KEYSPACE_SIZE,
            "object position exceeds the 60-bit keyspace"
        );
        let disk = self
            .disks
            .get(disk_index)
            .context("chunk destination disk is outside the plan")?;
        let ranges = self.host_ranges();
        let range = ranges
            .iter()
            .find(|range| range.host == disk.host)
            .context("disk has no host range")?;
        let disks = self.host_disks(&disk.host);
        let ordinal = disks
            .iter()
            .position(|(index, _)| *index == disk_index)
            .context("disk has no range on host")?;
        let (start, width) = split_range(range.end_key - range.start_key + 1, disks.len(), ordinal);
        ensure!(width > 0, "disk has an empty key range");
        let offset = hash(&[
            &object_position.to_le_bytes(),
            &(shard as u64).to_le_bytes(),
            &(replica as u64).to_le_bytes(),
            &self.placement_seed.to_le_bytes(),
            disk.id.as_bytes(),
        ]) % width;
        Ok(range.start_key + start + offset)
    }

    pub fn disk_at(&self, position: u64) -> Option<&DomainDisk> {
        let ranges = self.host_ranges();
        let range = ranges.get(range_index(KEYSPACE_SIZE, ranges.len(), position)?)?;
        let disks = self.host_disks(&range.host);
        let index = range_index(
            range.end_key - range.start_key + 1,
            disks.len(),
            position - range.start_key,
        )?;
        Some(disks[index].1)
    }

    pub fn unsafe_two_site(&self) -> bool {
        self.tolerate.sites == 0
            && self
                .disks
                .iter()
                .filter_map(|disk| disk.site.as_ref())
                .collect::<BTreeSet<_>>()
                .len()
                == 2
    }

    fn validate_structure(&self) -> Result<()> {
        self.protection.validate()?;
        ensure!(self.chunk_replicas > 0, "chunk_replicas must be positive");
        ensure!(
            self.max_fragments_per_host > 0 && self.max_fragments_per_disk > 0,
            "fragment locality limits must be positive"
        );
        let mut ids = BTreeSet::new();
        let mut host_domains = BTreeMap::new();
        for disk in &self.disks {
            ensure!(
                !disk.id.is_empty() && ids.insert(&disk.id),
                "empty or duplicate disk ID {}",
                disk.id
            );
            ensure!(
                !disk.host.is_empty() && !site(disk).is_empty() && !rack(disk).1.is_empty(),
                "disk {} needs site, rack, and host labels",
                disk.id
            );
            if let Some(previous) = host_domains.insert(&disk.host, rack(disk)) {
                ensure!(
                    previous == rack(disk),
                    "host {} appears in multiple racks or sites",
                    disk.host
                );
            }
        }
        let sites = self.disks.iter().map(site).collect::<BTreeSet<_>>().len();
        let racks = self.disks.iter().map(rack).collect::<BTreeSet<_>>().len();
        let networks = self
            .disks
            .iter()
            .flat_map(|disk| disk.networks.iter())
            .collect::<BTreeSet<_>>()
            .len();
        for (name, count, requested, min) in [
            (
                "site",
                sites,
                self.tolerate.sites,
                usize::from(sites >= 2 && !self.unsafe_two_site()),
            ),
            ("rack", racks, self.tolerate.racks, 1),
            ("host", host_domains.len(), self.tolerate.hosts, 1),
            ("disk", self.disks.len(), self.tolerate.disks, 1),
            (
                "network",
                networks,
                self.tolerate.networks,
                usize::from(networks >= 2),
            ),
        ] {
            let max = count - count.div_ceil(4);
            ensure!(requested >= min && requested <= max,
                "requested {name} tolerance {requested} is outside {min}..={max} for {count} domains");
        }
        ensure!(
            self.acknowledged_unsafe_two_site == self.unsafe_two_site(),
            "zero site tolerance across two sites requires the setup acknowledgment"
        );
        Ok(())
    }

    /// Prove recovery for every object placement and concurrent outage within the
    /// budget. Disk rotations preserve host, rack, site, network, and colocation. A verification work limit returns an error, never a passing result.
    pub fn validate_tolerance(&self) -> Result<()> {
        self.validate_structure()?;
        for host in hosts(&self.disks) {
            let positions = locations_for_host(
                &self.disks,
                host,
                self.placement_seed,
                self.protection.fragments(),
                self.chunk_replicas,
                self.max_fragments_per_host,
                self.max_fragments_per_disk,
            )?;
            self.verify_layout(&positions)
                .with_context(|| format!("objects in host {host}'s key range"))?;
        }
        Ok(())
    }
}

/// Check whether the mapped Raft voters can retain a majority within the
/// physical and network budget. Metadata disks must be accounted for separately
/// by the caller because the data disk budget describes shard destinations.
pub fn validate_metadata_tolerance(
    voters: &[DomainDisk],
    quorum: usize,
    tolerate: &FailureBudget,
) -> Result<()> {
    ensure!(
        quorum > 0 && quorum <= voters.len(),
        "metadata quorum cannot be reached with the mapped voters"
    );
    let plan = PlacementPlan {
        placement_seed: 0,
        disks: voters.to_vec(),
        protection: ProtectionLayout::ReedSolomon {
            k: quorum,
            m: voters.len() - quorum,
        },
        chunk_replicas: 1,
        max_fragments_per_host: 1,
        max_fragments_per_disk: 1,
        tolerate: FailureBudget {
            disks: 0,
            ..tolerate.clone()
        },
        acknowledged_unsafe_two_site: false,
    };
    let locations: Vec<_> = (0..voters.len()).map(|index| vec![index]).collect();
    plan.verify_layout(&locations)
        .context("metadata quorum is unavailable within the configured mixed failure budget")
}

type Counts = [usize; 4];

struct FailureDomain {
    level: usize,
    label: String,
    disks: Vec<usize>,
    after: usize,
}

fn failure_tree(
    disks: &[DomainDisk],
    used: &[usize],
    level: usize,
    domains: &mut Vec<FailureDomain>,
) {
    if level == 4 {
        return;
    }
    let mut groups = BTreeMap::<&str, Vec<usize>>::new();
    for &index in used {
        let disk = &disks[index];
        let name = match level {
            0 => site(disk),
            1 => rack(disk).1,
            2 => disk.host.as_str(),
            _ => disk.id.as_str(),
        };
        groups.entry(name).or_default().push(index);
    }
    for (name, indices) in groups {
        let index = domains.len();
        let kind = ["site", "rack", "host", "disk"][level];
        let label = if level == 1 {
            format!("{kind} {}/{}", site(&disks[indices[0]]), name)
        } else {
            format!("{kind} {name}")
        };
        failure_tree_node(disks, level, domains, index, label, indices);
    }
}

fn failure_tree_node(
    disks: &[DomainDisk],
    level: usize,
    domains: &mut Vec<FailureDomain>,
    index: usize,
    label: String,
    indices: Vec<usize>,
) {
    domains.push(FailureDomain {
        level,
        label,
        disks: Vec::new(),
        after: 0,
    });
    failure_tree(disks, &indices, level + 1, domains);
    domains[index].after = domains.len();
    domains[index].disks = indices;
}

struct Verification<'a> {
    plan: &'a PlacementPlan,
    locations: &'a [Vec<usize>],
    used: Vec<usize>,
    domains: Vec<FailureDomain>,
    networks: Vec<&'a str>,
    steps: usize,
}

impl PlacementPlan {
    fn verify_layout(&self, locations: &[Vec<usize>]) -> Result<()> {
        let used: Vec<_> = locations
            .iter()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut domains = Vec::new();
        failure_tree(&self.disks, &used, 0, &mut domains);
        let networks = used
            .iter()
            .flat_map(|&index| self.disks[index].networks.iter().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut check = Verification {
            plan: self,
            locations,
            used,
            domains,
            networks,
            steps: 0,
        };
        check.verify_networks(0, self.tolerate.networks, &mut BTreeSet::new())
    }
}

impl Verification<'_> {
    fn step(&mut self) -> Result<()> {
        self.steps += 1;
        ensure!(
            self.steps <= VERIFICATION_STEPS,
            "mixed-outage verification reached its work limit before it could prove this placement"
        );
        Ok(())
    }

    fn verify_networks<'a>(
        &mut self,
        start: usize,
        remaining: usize,
        down: &mut BTreeSet<&'a str>,
    ) -> Result<()>
    where
        Self: 'a,
    {
        self.step()?;
        let budgets = [
            self.plan.tolerate.sites,
            self.plan.tolerate.racks,
            self.plan.tolerate.hosts,
            self.plan.tolerate.disks,
        ];
        let mut failed = vec![false; self.plan.disks.len()];
        for &index in &self.used {
            let paths = &self.plan.disks[index].networks;
            failed[index] =
                !paths.is_empty() && paths.iter().all(|path| down.contains(path.as_str()));
        }
        if self.plan.chunk_replicas == 1
            && !matches!(self.plan.protection, ProtectionLayout::Lrc { .. })
        {
            self.verify_single_copy(budgets, &failed, down)?;
        } else {
            self.verify_combinations(0, budgets, &mut failed, &mut Vec::new(), down)?;
        }
        if remaining > 0 {
            for index in start..self.networks.len() {
                let network = self.networks[index];
                down.insert(network);
                self.verify_networks(index + 1, remaining - 1, down)?;
                down.remove(network);
            }
        }
        Ok(())
    }

    fn verify_combinations(
        &mut self,
        start: usize,
        budgets: Counts,
        failed: &mut [bool],
        outages: &mut Vec<String>,
        networks: &BTreeSet<&str>,
    ) -> Result<()> {
        self.step()?;
        let alive: Vec<_> = self
            .locations
            .iter()
            .map(|copies| copies.iter().any(|&index| !failed[index]))
            .collect();
        ensure!(
            self.plan.protection.readable(&alive),
            "object unreadable under mixed outages [{}], network outages {:?}",
            outages.join(", "),
            networks
        );
        for index in start..self.domains.len() {
            let domain = &self.domains[index];
            if budgets[domain.level] == 0 || domain.disks.iter().all(|&disk| failed[disk]) {
                continue;
            }
            let changed: Vec<_> = domain
                .disks
                .iter()
                .copied()
                .filter(|&disk| !failed[disk])
                .collect();
            for &disk in &changed {
                failed[disk] = true;
            }
            let mut left = budgets;
            left[domain.level] -= 1;
            let after = domain.after;
            outages.push(domain.label.clone());
            self.verify_combinations(after, left, failed, outages, networks)?;
            outages.pop();
            for disk in changed {
                failed[disk] = false;
            }
        }
        Ok(())
    }

    fn verify_single_copy(
        &mut self,
        budgets: Counts,
        failed: &[bool],
        networks: &BTreeSet<&str>,
    ) -> Result<()> {
        let mut weights = vec![0; failed.len()];
        for copies in self.locations {
            weights[copies[0]] += 1;
        }
        let already_lost: usize = self
            .used
            .iter()
            .filter(|&&disk| failed[disk])
            .map(|&disk| weights[disk])
            .sum();
        let losses = self.worst_in_forest(0, self.domains.len(), budgets, failed, &weights)?;
        let (lost, outages) = losses
            .into_values()
            .max_by_key(|(lost, _)| *lost)
            .unwrap_or_default();
        let total_lost = already_lost + lost;
        ensure!(self.locations.len() - total_lost >= self.plan.protection.data_fragments(),
            "insufficient survivors after losing {total_lost} of {} members under mixed outages [{}], network outages {:?}",
            self.locations.len(), outages.join(", "), networks);
        Ok(())
    }

    /// For single-copy MDS stripes and full-object replication, outages in disjoint
    /// subtrees have additive losses. Keep only the worst result for each budget.
    fn worst_in_forest(
        &mut self,
        mut index: usize,
        end: usize,
        budgets: Counts,
        failed: &[bool],
        weights: &[usize],
    ) -> Result<LossByCounts> {
        let mut combined = BTreeMap::from([([0; 4], (0, Vec::new()))]);
        while index < end {
            let level = self.domains[index].level;
            let after = self.domains[index].after;
            let mut subtree = self.worst_in_forest(index + 1, after, budgets, failed, weights)?;
            let domain = &self.domains[index];
            if budgets[level] > 0 {
                let mut spent = [0; 4];
                spent[level] = 1;
                let lost = domain
                    .disks
                    .iter()
                    .filter(|&&disk| !failed[disk])
                    .map(|&disk| weights[disk])
                    .sum();
                if lost > 0 {
                    subtree.insert(spent, (lost, vec![domain.label.clone()]));
                }
            }
            let mut next = BTreeMap::<Counts, (usize, Vec<String>)>::new();
            for (a, (left, left_names)) in &combined {
                for (b, (right, right_names)) in &subtree {
                    self.step()?;
                    let spent = std::array::from_fn(|i| a[i] + b[i]);
                    if (0..4).all(|i| spent[i] <= budgets[i]) {
                        let entry = next.entry(spent).or_default();
                        if left + right > entry.0 {
                            *entry = (
                                left + right,
                                left_names.iter().chain(right_names).cloned().collect(),
                            );
                        }
                    }
                }
            }
            combined = next;
            index = after;
        }
        Ok(combined)
    }
}

type LossByCounts = BTreeMap<Counts, (usize, Vec<String>)>;

#[cfg(test)]
mod tests {
    use super::*;

    fn one_disk_per_host(count: usize, protection: ProtectionLayout) -> PlacementPlan {
        PlacementPlan {
            placement_seed: 7,
            disks: (0..count)
                .map(|index| DomainDisk {
                    id: format!("disk-{index}"),
                    host: format!("host-{index}"),
                    rack: Some("rack".into()),
                    site: Some(format!("site-{index}")),
                    networks: Vec::new(),
                })
                .collect(),
            protection,
            chunk_replicas: 1,
            max_fragments_per_host: 1,
            max_fragments_per_disk: 1,
            tolerate: FailureBudget {
                sites: 1,
                racks: 1,
                hosts: 1,
                disks: 1,
                networks: 0,
            },
            acknowledged_unsafe_two_site: false,
        }
    }

    #[test]
    fn equal_ranges_cover_the_keyspace_and_chunk_addresses_resolve() {
        let plan = one_disk_per_host(7, ProtectionLayout::ReedSolomon { k: 2, m: 5 });
        let ranges = plan.host_ranges();
        assert_eq!(ranges[0].start_key, 0);
        assert_eq!(ranges.last().unwrap().end_key, (1 << 60) - 1);
        for neighbors in ranges.windows(2) {
            assert_eq!(neighbors[0].end_key + 1, neighbors[1].start_key);
        }
        let widths: Vec<_> = ranges.iter().map(|r| r.end_key - r.start_key + 1).collect();
        assert!(widths.iter().max().unwrap() - widths.iter().min().unwrap() <= 1);
        for (index, range) in ranges.iter().enumerate() {
            let positions = plan.locations(range.start_key).unwrap();
            assert_eq!(plan.owner_index(range.end_key), Some(index));
            assert_eq!(positions, plan.locations(range.end_key).unwrap());
            assert_eq!(plan.disks[positions[0][0]].host, range.host);
            for (shard, disks) in positions.iter().enumerate() {
                let pos = plan
                    .chunk_position(range.end_key, shard, 0, disks[0])
                    .unwrap();
                assert_eq!(plan.disk_at(pos), Some(&plan.disks[disks[0]]));
            }
        }
        assert_eq!(mask_position(u64::MAX), (1 << 60) - 1);
        assert!(plan.disk_at(1 << 60).is_none());
    }

    #[test]
    fn rotation_uses_all_equivalent_disks_without_changing_failure_domains() {
        let mut plan = one_disk_per_host(7, ProtectionLayout::ReedSolomon { k: 2, m: 5 });
        let mut disk = plan.disks[0].clone();
        disk.id = "disk-0-second".into();
        plan.disks.push(disk.clone());
        disk.id = "disk-0-other-network".into();
        disk.networks.push("separate".into());
        plan.disks.push(disk);
        assert!(plan.validate_tolerance().is_ok());
        // Find a placement seed that selects the two-disk network group as the anchor.
        plan.placement_seed = (0..100)
            .find(|&placement_seed| {
                locations_for_host(&plan.disks, "host-0", placement_seed, 7, 1, 1, 1)
                    .is_ok_and(|layout| layout[0][0] != 8)
            })
            .unwrap();

        let permutations = plan.permutations();
        let owner = &plan.host_ranges()[0];
        let first = plan.locations(owner.start_key).unwrap();
        let second = plan.locations(owner.start_key + 1).unwrap();
        assert_eq!(
            BTreeSet::from([first[0][0], second[0][0]]),
            BTreeSet::from([0, 7])
        );
        assert_eq!(permutations.disk_index(owner.start_key + 1, 8), 8);
        for (base, rotated) in first.iter().flatten().zip(second.iter().flatten()) {
            assert_eq!(
                *rotated,
                permutations.disk_index(owner.start_key + 1, *base)
            );
            assert_eq!(plan.disks[*base].host, plan.disks[*rotated].host);
            assert_eq!(plan.disks[*base].networks, plan.disks[*rotated].networks);
        }
    }

    #[test]
    fn mixed_outage_rejects_a_stripe_that_survives_each_domain_individually() {
        let mut plan = one_disk_per_host(8, ProtectionLayout::ReedSolomon { k: 2, m: 6 });
        plan.tolerate.sites = 6;
        let error = format!("{:#}", plan.validate_tolerance().unwrap_err());
        assert!(
            error.contains("losing 8 of 8 members under mixed outages"),
            "{error}"
        );
        plan.tolerate.sites = 3;
        assert!(plan.validate_tolerance().is_ok());
        plan.tolerate.sites = 7;
        let error = plan.validate_tolerance().unwrap_err().to_string();
        assert!(error.contains("outside 1..=6"), "{error}");
    }

    #[test]
    fn verifier_requires_acknowledgment_only_for_two_site_exception() {
        let mut plan = one_disk_per_host(6, ProtectionLayout::Replication { copies: 6 });
        for (index, disk) in plan.disks.iter_mut().enumerate() {
            disk.site = Some(format!("site-{}", index % 2));
            disk.rack = Some(format!("rack-{index}"));
        }
        plan.tolerate.sites = 0;
        assert!(plan
            .validate_tolerance()
            .unwrap_err()
            .to_string()
            .contains("acknowledgment"));
        plan.acknowledged_unsafe_two_site = true;
        assert!(plan.validate_tolerance().is_ok());
    }

    #[test]
    fn replicas_and_network_outages_use_physical_destinations() {
        let mut plan = one_disk_per_host(8, ProtectionLayout::ReedSolomon { k: 1, m: 3 });
        plan.chunk_replicas = 2;
        for disk in &mut plan.disks {
            disk.networks = vec!["common".into(), format!("path-{}", disk.host)];
        }
        plan.tolerate.networks = 1;
        assert!(plan.validate_tolerance().is_ok());
        for disk in &mut plan.disks {
            disk.networks = vec!["common".into(), "backup".into()];
        }
        // A host can still use either of its two paths.
        assert!(plan.validate_tolerance().is_ok());
        plan.disks[0].networks = vec!["common".into(), "third".into()];
        plan.tolerate.networks = 2;
        assert!(plan.validate_tolerance().is_err());
    }

    #[test]
    fn lrc_recovery_matches_the_codec_and_overhead_counts_copy_padding() {
        let lrc = ProtectionLayout::Lrc { k: 4, m: 3 };
        assert!(!lrc.readable(&[false, true, true, true, false, true, false]));
        assert!(lrc.readable(&[true, true, true, true, false, false, false]));
        assert_eq!(lrc.payload_bytes(5, 2).unwrap(), 28);
        assert_eq!(
            ProtectionLayout::ReedSolomon { k: 4, m: 2 }.nominal_overhead(1),
            1.5
        );
    }
}
