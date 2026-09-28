// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi NBD frontend for sparse virtual volumes.
//!
//! The frontend implements the fixed-newstyle NBD handshake and translates block requests
//! into Kagi volume API operations. It carries a stable initiator identifier on every request
//! so persistent-reservation enforcement remains effective when the volume is attached to a
//! hypervisor or guest.

// NBD frontend exposing Kagi object-backed sparse volumes as block devices.
//! NBD frontend for a Kagi virtual volume. QEMU/KVM can attach this directly.
use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
const NBD_MAGIC: u64 = 0x4e42444d41474943;
const IHAVEOPT: u64 = 0x49484156454f5054;
const REQ_MAGIC: u32 = 0x25609513;
const REP_MAGIC: u32 = 0x67446698;
#[derive(Parser, Clone)]
struct Opt {
    #[arg(long, default_value = "127.0.0.1:10809")]
    listen: String,
    #[arg(long)]
    api: String,
    #[arg(long)]
    volume: String,
    #[arg(long, default_value = "nbd:anonymous")]
    initiator: String,
}
#[derive(Deserialize)]
struct Volume {
    size_bytes: u64,
    #[serde(rename = "logical_block_bytes")]
    _logical_block_bytes: u32,
}
/// Implements the volume step and keeps its validation and state transitions visible at the call site.
async fn volume(c: &reqwest::Client, o: &Opt) -> Result<Volume> {
    Ok(c.get(format!(
        "{}/v1/volumes/{}",
        o.api.trim_end_matches('/'),
        o.volume
    ))
    .header("x-kagi-initiator", &o.initiator)
    .send()
    .await?
    .error_for_status()?
    .json()
    .await?)
}
/// Implements the read be u32 step and keeps its validation and state transitions visible at the call site.
async fn read_be_u32(s: &mut TcpStream) -> Result<u32> {
    Ok(s.read_u32().await?)
}
/// Implements the read be u64 step and keeps its validation and state transitions visible at the call site.
async fn read_be_u64(s: &mut TcpStream) -> Result<u64> {
    Ok(s.read_u64().await?)
}
/// Implements the handshake step and keeps its validation and state transitions visible at the call site.
async fn handshake(s: &mut TcpStream, size: u64) -> Result<()> {
    s.write_u64(NBD_MAGIC).await?;
    s.write_u64(IHAVEOPT).await?;
    s.write_u16(3).await?;
    s.flush().await?;
    let client_flags = s.read_u32().await?;
    loop {
        if read_be_u64(s).await? != IHAVEOPT {
            bail!("invalid NBD option magic")
        }
        let opt = read_be_u32(s).await?;
        let len = read_be_u32(s).await? as usize;
        let mut payload = vec![0; len];
        s.read_exact(&mut payload).await?;
        if opt == 1 {
            s.write_u64(size).await?;
            s.write_u16(1 | 4 | 32).await?;
            if client_flags & 2 == 0 {
                s.write_all(&[0u8; 124]).await?;
            }
            s.flush().await?;
            return Ok(());
        } else {
            // NBD_REP_ERR_UNSUP
            s.write_u64(0x0003e889045565a9).await?;
            s.write_u32(opt).await?;
            s.write_u32(0x80000001).await?;
            s.write_u32(0).await?;
            s.flush().await?;
        }
    }
}
/// Implements the reply step and keeps its validation and state transitions visible at the call site.
async fn reply(s: &mut TcpStream, errno: u32, handle: u64, data: Option<&[u8]>) -> Result<()> {
    s.write_u32(REP_MAGIC).await?;
    s.write_u32(errno).await?;
    s.write_u64(handle).await?;
    if let Some(d) = data {
        s.write_all(d).await?
    }
    s.flush().await?;
    Ok(())
}
/// Implements the serve step and keeps its validation and state transitions visible at the call site.
async fn serve(mut s: TcpStream, o: Opt) -> Result<()> {
    let c = reqwest::Client::new();
    let v = volume(&c, &o).await?;
    handshake(&mut s, v.size_bytes).await?;
    loop {
        let magic = match s.read_u32().await {
            Ok(x) => x,
            Err(_) => return Ok(()),
        };
        if magic != REQ_MAGIC {
            bail!("invalid NBD request magic")
        }
        let _flags = s.read_u16().await?;
        let typ = s.read_u16().await?;
        let handle = s.read_u64().await?;
        let off = s.read_u64().await?;
        let len = s.read_u32().await? as usize;
        if off.saturating_add(len as u64) > v.size_bytes {
            reply(&mut s, 22, handle, None).await?;
            continue;
        }
        match typ {
            0 => {
                let r = c
                    .get(format!(
                        "{}/v1/volumes/{}/data/{}/{}",
                        o.api.trim_end_matches('/'),
                        o.volume,
                        off,
                        len
                    ))
                    .header("x-kagi-initiator", &o.initiator)
                    .send()
                    .await;
                match r {
                    Ok(x) if x.status().is_success() => {
                        let b = x.bytes().await?;
                        reply(&mut s, 0, handle, Some(&b)).await?
                    }
                    _ => reply(&mut s, 5, handle, None).await?,
                }
            }
            1 => {
                let mut b = vec![0; len];
                s.read_exact(&mut b).await?;
                let r = c
                    .put(format!(
                        "{}/v1/volumes/{}/data/{}",
                        o.api.trim_end_matches('/'),
                        o.volume,
                        off
                    ))
                    .body(b)
                    .header("x-kagi-initiator", &o.initiator)
                    .send()
                    .await;
                reply(
                    &mut s,
                    if r.map(|x| x.status().is_success()).unwrap_or(false) {
                        0
                    } else {
                        5
                    },
                    handle,
                    None,
                )
                .await?
            }
            2 => return Ok(()),
            3 => reply(&mut s, 0, handle, None).await?,
            4 => {
                let r = c
                    .put(format!(
                        "{}/v1/volumes/{}/unmap/{}/{}",
                        o.api.trim_end_matches('/'),
                        o.volume,
                        off,
                        len
                    ))
                    .header("x-kagi-initiator", &o.initiator)
                    .send()
                    .await;
                reply(
                    &mut s,
                    if r.map(|x| x.status().is_success()).unwrap_or(false) {
                        0
                    } else {
                        5
                    },
                    handle,
                    None,
                )
                .await?
            }
            _ => reply(&mut s, 95, handle, None).await?,
        }
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let o = Opt::parse();
    let l = TcpListener::bind(&o.listen)
        .await
        .with_context(|| format!("bind {}", o.listen))?;
    println!("NBD volume {} listening on {}", o.volume, o.listen);
    loop {
        let (s, _) = l.accept().await?;
        let x = o.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(s, x).await {
                eprintln!("NBD session: {e:#}")
            }
        });
    }
}
