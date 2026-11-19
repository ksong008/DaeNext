use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{self, Instant};

use crate::SpawnedLogicalStream;

const SEGMENT_BYTES: usize = 32 * 1024;
const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
const UPLOAD_WINDOW: u64 = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn open(folder: &str) -> Result<SpawnedLogicalStream, String> {
    let root = PathBuf::from(folder);
    check_storage_dir(&root).await.map_err(xdrive_error)?;
    let mut random = [0; 16];
    boring::rand::rand_bytes(&mut random)
        .map_err(|error| format!("create XDrive session ID: {error}"))?;
    let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let announce_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("get XDrive announcement time: {error}"))?
        .as_nanos();
    let streams = root.join("streams");
    let sessions = root.join("sessions");
    ensure_storage_dir(&streams).await.map_err(xdrive_error)?;
    ensure_storage_dir(&sessions).await.map_err(xdrive_error)?;
    let folder = streams.join(&id);
    let up = folder.join("c2s");
    let down = folder.join("s2c");
    let announce = sessions.join(format!("{announce_time}-{id}"));
    tokio::fs::create_dir(&folder).await.map_err(xdrive_error)?;
    let objects = SessionObjects {
        folder,
        announce: announce.clone(),
    };
    tokio::fs::create_dir(&up).await.map_err(xdrive_error)?;
    tokio::fs::create_dir(&down).await.map_err(xdrive_error)?;
    put(&announce, &[]).await.map_err(xdrive_error)?;
    Ok(SpawnedLogicalStream::spawn(async move |stream| {
        let _objects = objects;
        let (reader, writer) = tokio::io::split(stream);
        tokio::try_join!(upload(up, reader), download(down, writer))
            .map(|_| ())
            .map_err(xdrive_error)
    }))
}

async fn ensure_storage_dir(path: &Path) -> io::Result<()> {
    match tokio::fs::create_dir(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check_storage_dir(path).await
}

async fn check_storage_dir(path: &Path) -> io::Result<()> {
    let info = tokio::fs::symlink_metadata(path).await?;
    if info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XDrive storage needs a directory owned by the daemon with no group or other write access",
        ))
    }
}

struct SessionObjects {
    folder: PathBuf,
    announce: PathBuf,
}

impl Drop for SessionObjects {
    fn drop(&mut self) {
        let folder = self.folder.clone();
        let announce = self.announce.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(move || {
                let _ = std::fs::remove_file(announce);
                let _ = std::fs::remove_dir_all(folder);
            });
        }
    }
}

fn xdrive_error(error: io::Error) -> String {
    format!("XDrive local storage: {error}")
}

fn object(folder: &Path, seq: u64, suffix: &str) -> PathBuf {
    folder.join(format!("{seq:09}.{suffix}"))
}

async fn put(path: &Path, data: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("partial");
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .await?;
    let result = async {
        file.write_all(data).await?;
        file.flush().await?;
        drop(file);
        tokio::fs::rename(&temp, path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
    }
    result
}

async fn upload(
    folder: PathBuf,
    mut reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
) -> io::Result<()> {
    let mut seq = 0_u64;
    let mut segment = vec![0; SEGMENT_BYTES];
    loop {
        let len = reader.read(&mut segment).await?;
        if len == 0 {
            return put(&object(&folder, seq, "end"), &[]).await;
        }
        if let Some(oldest) = seq.checked_sub(UPLOAD_WINDOW) {
            let path = object(&folder, oldest, "seg");
            time::timeout(IDLE_TIMEOUT, async {
                while tokio::fs::try_exists(&path).await? {
                    time::sleep(POLL_INTERVAL).await;
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| io::Error::other("XDrive upload window did not drain"))??;
        }
        if let Err(error) = put(&object(&folder, seq, "seg"), &segment[..len]).await {
            let _ = put(&object(&folder, seq, "err"), &[]).await;
            return Err(error);
        }
        seq = seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("XDrive upload sequence exhausted"))?;
    }
}

async fn download(
    folder: PathBuf,
    mut writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> io::Result<()> {
    let mut seq = 0_u64;
    let mut last_data = Instant::now();
    loop {
        let path = object(&folder, seq, "seg");
        if let Some(data) = read_segment(path.clone()).await? {
            writer.write_all(&data).await?;
            tokio::fs::remove_file(path).await?;
            last_data = Instant::now();
            seq = seq
                .checked_add(1)
                .ok_or_else(|| io::Error::other("XDrive download sequence exhausted"))?;
        } else if tokio::fs::try_exists(object(&folder, seq, "err")).await? {
            return Err(io::Error::other("XDrive peer reported a segment error"));
        } else {
            let end = object(&folder, seq, "end");
            if tokio::fs::try_exists(&end).await? {
                tokio::fs::remove_file(end).await?;
                return writer.shutdown().await;
            }
            if last_data.elapsed() >= IDLE_TIMEOUT {
                return Err(io::Error::other(
                    "XDrive download timed out waiting for a segment",
                ));
            }
            time::sleep(POLL_INTERVAL).await;
        }
    }
}

async fn read_segment(path: PathBuf) -> io::Result<Option<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_SEGMENT_BYTES {
            return Err(io::Error::other("invalid XDrive segment file"));
        }
        let mut data = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_SEGMENT_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_SEGMENT_BYTES {
            return Err(io::Error::other("XDrive segment exceeds the size limit"));
        }
        Ok(Some(data))
    })
    .await
    .map_err(io::Error::other)?
}
