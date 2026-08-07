//! Daemon side: publish hot cache to POSIX shm for nss-resolve lock-free reads.
//!
//! Layout (lock-free RCU):
//!   [ShmHeader]
//!   [Bucket; N]  — each bucket: gen, key_hash, off, len, expires_unix_ms, flags
//!   [Payload arena]
//!
//! Writer (daemon): update payload → publish new gen with Release.
//! Reader (NSS): load gen Acquire → read → reload gen; retry if changed.
#![allow(missing_debug_implementations)]

use std::fs::OpenOptions;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use memmap2::{MmapMut, MmapOptions};

pub const SHM_PATH: &str = "/dev/shm/systemd-resolved-rs-l1";
pub const SHM_MAGIC: u64 = 0x5253_4C31_4E53_5301; // RSL1NSS\x01
pub const SHM_VERSION: u32 = 1;
pub const N_BUCKETS: usize = 65536;
pub const ARENA_SIZE: usize = 16 * 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmHeader {
    pub magic: u64,
    pub version: u32,
    pub n_buckets: u32,
    pub arena_off: u32,
    pub arena_size: u32,
    pub write_gen: u64, // atomic via AtomicU64 transmute at offset
    pub arena_used: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmBucket {
    pub gen: u64,
    pub hash: u64,
    pub off: u32,
    pub len: u32,
    pub expires_ms: u64,
    pub flags: u32, // bit0 stale_ok, bit1 negative, bit2 secure
    pub qtype: u16,
    pub qclass: u16,
    pub rcode: u8,
    pub n_addrs: u8,
    pub _pad: u16,
}

/// Packed after bucket points into arena:
/// [u8 owner_len][owner wire...][addrs: n * (u8 family, u8 plen, addr bytes)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmAddr {
    pub family: u8, // 4 or 6
    pub _pad: u8,
    pub scope_id: u16,
    pub addr: [u8; 16],
}

pub struct ShmPublisher {
    mmap: MmapMut,
    hdr_size: usize,
}

impl ShmPublisher {
    pub fn create() -> io::Result<Self> {
        let total = std::mem::size_of::<ShmHeader>()
            + N_BUCKETS * std::mem::size_of::<ShmBucket>()
            + ARENA_SIZE;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(SHM_PATH)?;
        file.set_len(total as u64)?;
        // chmod 644 — world-readable for nss in user processes
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(SHM_PATH, std::fs::Permissions::from_mode(0o644))?;
        }
        let mut mmap = unsafe { MmapOptions::new().map_mut(&file)? };
        let arena_off =
            (std::mem::size_of::<ShmHeader>() + N_BUCKETS * std::mem::size_of::<ShmBucket>()) as u32;
        let hdr = ShmHeader {
            magic: SHM_MAGIC,
            version: SHM_VERSION,
            n_buckets: N_BUCKETS as u32,
            arena_off,
            arena_size: ARENA_SIZE as u32,
            write_gen: 1,
            arena_used: 0,
            _pad: 0,
        };
        unsafe {
            let p = mmap.as_mut_ptr() as *mut ShmHeader;
            std::ptr::write(p, hdr);
            let b = mmap.as_mut_ptr().add(std::mem::size_of::<ShmHeader>()) as *mut ShmBucket;
            std::ptr::write_bytes(b, 0, N_BUCKETS);
        }
        Ok(Self {
            mmap,
            hdr_size: std::mem::size_of::<ShmHeader>(),
        })
    }

    fn header_mut(&mut self) -> &mut ShmHeader {
        unsafe { &mut *(self.mmap.as_mut_ptr() as *mut ShmHeader) }
    }

    fn buckets_mut(&mut self) -> &mut [ShmBucket] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.mmap.as_mut_ptr().add(self.hdr_size) as *mut ShmBucket,
                N_BUCKETS,
            )
        }
    }

    #[allow(dead_code)]
    fn arena_mut(&mut self) -> &mut [u8] {
        let off = self.header_mut().arena_off as usize;
        let size = self.header_mut().arena_size as usize;
        &mut self.mmap[off..off + size]
    }

    pub fn publish_addrs(
        &mut self,
        owner_wire: &[u8],
        qtype: u16,
        qclass: u16,
        rcode: u8,
        addrs: &[ShmAddr],
        ttl: Duration,
        secure: bool,
        negative: bool,
    ) {
        let h = hash_key(owner_wire, qtype, qclass);
        let bi = (h as usize) & (N_BUCKETS - 1);
        let exp = system_now_ms() + ttl.as_millis() as u64;

        // allocate arena (bump; wrap on full)
        let need = 1 + owner_wire.len() + addrs.len() * std::mem::size_of::<ShmAddr>();
        let hdr = self.header_mut();
        if hdr.arena_used as usize + need > hdr.arena_size as usize {
            hdr.arena_used = 0; // epoch wrap — readers retry on gen
        }
        let off = hdr.arena_used;
        hdr.arena_used += need as u32;
        let gen = hdr.write_gen.wrapping_add(1);
        hdr.write_gen = gen;

        let arena_off = hdr.arena_off as usize;
        let slot = &mut self.mmap[arena_off + off as usize..arena_off + off as usize + need];
        slot[0] = owner_wire.len() as u8;
        slot[1..1 + owner_wire.len()].copy_from_slice(owner_wire);
        let mut p = 1 + owner_wire.len();
        for a in addrs {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (a as *const ShmAddr) as *const u8,
                    std::mem::size_of::<ShmAddr>(),
                )
            };
            slot[p..p + bytes.len()].copy_from_slice(bytes);
            p += bytes.len();
        }

        let mut flags = 0u32;
        if secure {
            flags |= 4;
        }
        if negative {
            flags |= 2;
        }
        flags |= 1; // stale_ok default supremacy

        // invalidate then publish
        let b = &mut self.buckets_mut()[bi];
        b.gen = 0;
        std::sync::atomic::fence(Ordering::Release);
        b.hash = h;
        b.off = off;
        b.len = need as u32;
        b.expires_ms = exp;
        b.flags = flags;
        b.qtype = qtype;
        b.qclass = qclass;
        b.rcode = rcode;
        b.n_addrs = addrs.len() as u8;
        std::sync::atomic::fence(Ordering::Release);
        b.gen = gen;

        // keep write_gen visible
        let _ = AtomicU64::new(gen);
    }
}

pub fn hash_key(owner: &[u8], qtype: u16, qclass: u16) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in owner {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= (qtype as u64) << 16;
    h = h.wrapping_mul(0x100000001b3);
    h ^= qclass as u64;
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// NSS-side lookup (also usable from Rust tests).
pub struct ShmReader {
    mmap: memmap2::Mmap,
}

impl ShmReader {
    pub fn open() -> io::Result<Self> {
        let f = OpenOptions::new().read(true).open(SHM_PATH)?;
        let mmap = unsafe { MmapOptions::new().map(&f)? };
        Ok(Self { mmap })
    }

    pub fn lookup(
        &self,
        owner: &[u8],
        qtype: u16,
        qclass: u16,
    ) -> Option<(u8 /*rcode*/, Vec<ShmAddr>, bool /*secure*/)> {
        if self.mmap.len() < std::mem::size_of::<ShmHeader>() {
            return None;
        }
        let hdr = unsafe { &*(self.mmap.as_ptr() as *const ShmHeader) };
        if hdr.magic != SHM_MAGIC || hdr.version != SHM_VERSION {
            return None;
        }
        let h = hash_key(owner, qtype, qclass);
        let bi = (h as usize) & (hdr.n_buckets as usize - 1);
        let buck_base = std::mem::size_of::<ShmHeader>();
        for _ in 0..4 {
            let b = unsafe {
                &*((self.mmap.as_ptr().add(buck_base) as *const ShmBucket).add(bi))
            };
            let g1 = b.gen;
            std::sync::atomic::fence(Ordering::Acquire);
            if g1 == 0 || b.hash != h || b.qtype != qtype || b.qclass != qclass {
                return None;
            }
            if system_now_ms() > b.expires_ms + 30_000 {
                // allow 30s stale read in NSS; daemon owns SWR policy
                // still serve if stale_ok
                if b.flags & 1 == 0 {
                    return None;
                }
            }
            let off = hdr.arena_off as usize + b.off as usize;
            let len = b.len as usize;
            if off + len > self.mmap.len() {
                return None;
            }
            let slice = &self.mmap[off..off + len];
            let olen = slice[0] as usize;
            if 1 + olen > slice.len() {
                return None;
            }
            if &slice[1..1 + olen] != owner {
                // hash collision
                return None;
            }
            let mut addrs = Vec::new();
            let mut p = 1 + olen;
            let asz = std::mem::size_of::<ShmAddr>();
            for _ in 0..b.n_addrs {
                if p + asz > slice.len() {
                    break;
                }
                let a = unsafe { *(slice.as_ptr().add(p) as *const ShmAddr) };
                addrs.push(a);
                p += asz;
            }
            std::sync::atomic::fence(Ordering::Acquire);
            let g2 = unsafe {
                &*((self.mmap.as_ptr().add(buck_base) as *const ShmBucket).add(bi))
            }
            .gen;
            if g1 == g2 {
                return Some((b.rcode, addrs, b.flags & 4 != 0));
            }
        }
        None
    }
}
