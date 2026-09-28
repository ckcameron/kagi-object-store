//! Crash-safe, content-addressed simulation batch checkpoints.
//!
//! Every random stream is indexed by its original trial number. Completed batch
//! reductions are immutable and checksummed; restarting recomputes only unsaved
//! batches. Ordered reduction makes results independent of Rayon scheduling.
use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

const FORMAT: u32 = 1;
static ACTIVE: OnceLock<Arc<Store>> = OnceLock::new();
#[derive(Serialize, Deserialize)]
struct Envelope {
    format: u32,
    hash: String,
    payload: String,
}
struct Pending {
    last_save: Instant,
    records: BTreeMap<String, Vec<u8>>,
}
/// The held file lock prevents two processes from changing the same checkpoint.
pub struct Store {
    root: PathBuf,
    _lock: File,
    pub interval: Duration,
    pub batch: u64,
    pending: Mutex<Pending>,
}

/// Same-directory rename plus file/directory sync prevents a torn committed record.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".kagi-save-{}", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = serde_yaml::to_string(value)?;
    Ok(serde_json::to_vec(&Envelope {
        format: FORMAT,
        hash: blake3::hash(payload.as_bytes()).to_hex().to_string(),
        payload,
    })?)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let record: Envelope = serde_json::from_slice(bytes).context("invalid checkpoint record")?;
    if record.format != FORMAT
        || record.hash != blake3::hash(record.payload.as_bytes()).to_hex().as_str()
    {
        bail!("checkpoint format or checksum mismatch");
    }
    Ok(serde_yaml::from_str(&record.payload)?)
}
impl Store {
    pub fn open(root: PathBuf, resume: bool, interval: Duration, batch: u64) -> Result<Self> {
        if batch == 0 || interval.is_zero() {
            bail!("checkpoint interval and batch size must be positive");
        }
        if resume && !root.join("run.json").is_file() {
            bail!("resume checkpoint has no run manifest");
        }
        fs::create_dir_all(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("lock"))?;
        lock.try_lock()
            .context("checkpoint is in use by another process")?;
        if !resume && root.join("run.json").exists() {
            bail!("checkpoint already exists; use --resume or a new directory");
        }
        fs::create_dir_all(root.join("batches"))?;
        Ok(Self {
            root,
            _lock: lock,
            interval,
            batch,
            pending: Mutex::new(Pending {
                last_save: Instant::now(),
                records: BTreeMap::new(),
            }),
        })
    }
    pub fn save_manifest<T: Serialize>(&self, run: &T) -> Result<()> {
        atomic_write(&self.root.join("run.json"), &encode(run)?)
    }
    pub fn manifest<T: DeserializeOwned>(&self) -> Result<T> {
        decode(&fs::read(self.root.join("run.json"))?)
    }
    fn get<T: DeserializeOwned>(&self, id: &str) -> Result<Option<T>> {
        if let Some(bytes) = self.pending.lock().unwrap().records.get(id) {
            return decode(bytes).map(Some);
        }
        match fs::read(self.root.join("batches").join(id)) {
            Ok(bytes) => decode(&bytes).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn put<T: Serialize>(&self, id: String, value: &T) -> Result<()> {
        let bytes = encode(value)?;
        let mut pending = self.pending.lock().unwrap();
        pending.records.insert(id, bytes);
        // Bound pending records as well as wall-clock save intervals.
        if pending.last_save.elapsed() >= self.interval || pending.records.len() >= 128 {
            self.flush_locked(&mut pending)?;
        }
        Ok(())
    }
    fn flush_locked(&self, pending: &mut Pending) -> Result<()> {
        for (id, bytes) in &pending.records {
            atomic_write(&self.root.join("batches").join(id), bytes)?;
        }
        pending.records.clear();
        pending.last_save = Instant::now();
        Ok(())
    }
    pub fn flush(&self) -> Result<()> {
        self.flush_locked(&mut self.pending.lock().unwrap())
    }
}
pub fn install(store: Arc<Store>) -> Result<()> {
    ACTIVE
        .set(store)
        .map_err(|_| anyhow::anyhow!("checkpoint already initialized"))
}
pub fn flush() -> Result<()> {
    if let Some(store) = ACTIVE.get() {
        store.flush()?;
    }
    Ok(())
}

/// A fixed batch partition is used with and without saving, so a resumed sum has
/// exactly the same floating-point addition order as an uninterrupted run.
pub fn reduce<K, T, F, I, R>(key: &K, trials: u64, trial: F, identity: I, merge: R) -> T
where
    K: Serialize,
    T: Serialize + DeserializeOwned + Send,
    F: Fn(u64) -> T + Sync,
    I: Fn() -> T + Sync,
    R: Fn(T, T) -> T + Sync,
{
    batches(
        key,
        trials,
        |start, end| (start..end).map(&trial).fold(identity(), &merge),
        &identity,
        &merge,
    )
}
pub fn batches<K, T, F, I, R>(key: &K, trials: u64, batch: F, identity: I, merge: R) -> T
where
    K: Serialize,
    T: Serialize + DeserializeOwned + Send,
    F: Fn(u64, u64) -> T + Sync,
    I: Fn() -> T + Sync,
    R: Fn(T, T) -> T + Sync,
{
    let store = ACTIVE.get();
    let width = store.map_or(1024, |s| s.batch);
    let job = blake3::hash(
        serde_yaml::to_string(&(env!("CARGO_PKG_VERSION"), width, key))
            .expect("serialize checkpoint identity")
            .as_bytes(),
    )
    .to_hex()
    .to_string();
    let count = trials.div_ceil(width);
    let window = rayon::current_num_threads()
        .saturating_mul(4)
        .clamp(1, 1024);
    let mut result = identity();
    // Bound completed reduction storage without changing global batch order.
    for first in (0..count).step_by(window) {
        let values: Vec<T> = (first..count.min(first.saturating_add(window as u64)))
            .into_par_iter()
            .map(|index| {
                let id = format!("{job}-{index:016x}.json");
                if let Some(store) = store {
                    if let Some(value) = store
                        .get(&id)
                        .expect("checkpoint read failed; refusing an unsafe resume")
                    {
                        return value;
                    }
                }
                let start = index * width;
                let value = batch(start, trials.min(start.saturating_add(width)));
                if let Some(store) = store {
                    store
                        .put(id, &value)
                        .expect("checkpoint save failed; stopping simulation");
                }
                value
            })
            .collect();
        result = values.into_iter().fold(result, &merge);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_lock_and_corruption_detection() {
        let root = std::env::temp_dir().join(format!("kagi-save-test-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone(), false, Duration::from_secs(60), 4).unwrap();
        store.save_manifest(&vec![1u64, 2, 3]).unwrap();
        assert!(Store::open(root.clone(), true, Duration::from_secs(60), 4).is_err());
        store.put("sample.json".into(), &(7u64, 1e-20f64)).unwrap();
        store.flush().unwrap();
        drop(store);
        let store = Store::open(root.clone(), true, Duration::from_secs(60), 4).unwrap();
        assert_eq!(store.manifest::<Vec<u64>>().unwrap(), vec![1, 2, 3]);
        assert_eq!(
            store.get::<(u64, f64)>("sample.json").unwrap(),
            Some((7, 1e-20))
        );
        fs::write(root.join("batches/sample.json"), "broken").unwrap();
        assert!(store.get::<(u64, f64)>("sample.json").is_err());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn ordered_reduction_matches_across_thread_counts() {
        let run = || reduce(&"test", 4097, |i| (i as f64).sin(), || 0.0, |a, b| a + b);
        let one = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(run);
        let four = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
            .install(run);
        assert_eq!(one.to_bits(), four.to_bits());
    }
}
