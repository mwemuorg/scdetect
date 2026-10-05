use std::fs::File;
use std::ops::Deref;

use crate::regions::Regions;

/// Bytes of a segment: a mapped file or a copy of process memory.
pub enum Bytes {
    Map(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Map(m) => m,
            Bytes::Owned(v) => v,
        }
    }
}

/// A contiguous chunk to scan: the whole file, or one memory map.
pub struct Segment {
    /// file offset (0 for files) or virtual address of the first byte
    pub addr: u64,
    pub bytes: Bytes,
    /// "rwx"-style permissions, empty for files
    pub perms: String,
    pub name: String,
}

pub struct Source {
    pub segs: Vec<Segment>,
    /// sections of PE/ELF/Mach-O files, None for memory
    pub regions: Option<Regions>,
    /// true when addresses are virtual addresses (process memory / dumps)
    pub is_memory: bool,
    pub desc: String,
}

impl Source {
    pub fn file(path: &str) -> Result<Source, String> {
        let f = File::open(path).map_err(|e| format!("{path}: {e}"))?;
        let map = unsafe { memmap2::Mmap::map(&f) }.map_err(|e| format!("{path}: {e}"))?;
        let regions = Regions::parse(&map);
        let desc = format!("{path} ({} bytes, {})", map.len(), regions.format);
        Ok(Source {
            segs: vec![Segment {
                addr: 0,
                bytes: Bytes::Map(map),
                perms: String::new(),
                name: String::new(),
            }],
            regions: Some(regions),
            is_memory: false,
            desc,
        })
    }

    /// A mwemu dump: `.mwemu` from mwemu-snapshot or a minidump.
    pub fn dump(path: &str) -> Result<Source, String> {
        let p = path.to_string();
        let emu =
            std::panic::catch_unwind(move || libmwemu::serialization::Serialization::load(&p))
                .map_err(|_| format!("{path}: cannot load the dump"))?;
        let mut segs = Vec::new();
        for (_, m) in emu.maps.mem_slab.iter() {
            if !m.can_read() || m.size() == 0 {
                continue;
            }
            segs.push(Segment {
                addr: m.get_base(),
                bytes: Bytes::Owned(m.get_bytes().to_vec()),
                perms: perms_str(m.can_read(), m.can_write(), m.can_execute()),
                name: m.get_name().to_string(),
            });
        }
        Ok(Source::memory(segs, format!("dump {path}")))
    }

    /// Live Linux process: stop it with ptrace, copy every readable map, resume.
    #[cfg(target_os = "linux")]
    pub fn pid(pid: i32) -> Result<Source, String> {
        let segs = linux::read_process(pid)?;
        Ok(Source::memory(segs, format!("pid {pid}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn pid(_pid: i32) -> Result<Source, String> {
        Err("--pid is only supported on Linux, use --dump with a mwemu-snapshot file".into())
    }

    fn memory(mut segs: Vec<Segment>, desc: String) -> Source {
        segs.sort_by_key(|s| s.addr);
        let total: usize = segs.iter().map(|s| s.bytes.len()).sum();
        let desc = format!("{desc} ({} maps, {total} bytes)", segs.len());
        Source {
            segs,
            regions: None,
            is_memory: true,
            desc,
        }
    }

    /// Segment index and offset inside it for an address.
    pub fn locate(&self, addr: u64) -> Option<(usize, usize)> {
        self.segs.iter().enumerate().find_map(|(i, s)| {
            let off = addr.checked_sub(s.addr)? as usize;
            (off < s.bytes.len()).then_some((i, off))
        })
    }

    /// Report label: file section, or "perms name" of the memory map.
    pub fn label(&self, seg: usize, off: usize) -> String {
        match &self.regions {
            Some(r) => r.name(off).to_string(),
            None => {
                let s = &self.segs[seg];
                format!("{} {}", s.perms, s.name)
            }
        }
    }
}

fn perms_str(r: bool, w: bool, x: bool) -> String {
    let mut s = String::new();
    s.push(if r { 'r' } else { '-' });
    s.push(if w { 'w' } else { '-' });
    s.push(if x { 'x' } else { '-' });
    s
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::IoSliceMut;

    use nix::sys::ptrace;
    use nix::sys::uio::{RemoteIoVec, process_vm_readv};
    use nix::sys::wait::waitpid;
    use nix::unistd::Pid;

    use super::{Bytes, Segment};

    /// Kernel special mappings process_vm_readv can't read (see mwemu-snapshot).
    const SPECIAL: [&str; 4] = ["[vvar]", "[vvar_vclock]", "[vdso]", "[vsyscall]"];

    pub fn read_process(pid: i32) -> Result<Vec<Segment>, String> {
        let target = Pid::from_raw(pid);
        // stop the process so the copy is consistent
        ptrace::attach(target).map_err(|e| {
            format!(
                "ptrace attach to {pid} failed: {e} (needs root/CAP_SYS_PTRACE, \
                 see /proc/sys/kernel/yama/ptrace_scope)"
            )
        })?;
        let r = waitpid(target, None)
            .map_err(|e| format!("waitpid {pid}: {e}"))
            .and_then(|_| read_maps(pid));
        let _ = ptrace::detach(target, None);
        r
    }

    fn read_maps(pid: i32) -> Result<Vec<Segment>, String> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| format!("/proc/{pid}/maps: {e}"))?;
        let mut segs = Vec::new();
        for line in maps.lines() {
            // start-end perms offset dev inode path
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            let name = parts.nth(3).unwrap_or("[anon]").to_string();
            let Some((s, e)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16))
            else {
                continue;
            };
            if !perms.starts_with('r') || SPECIAL.contains(&name.as_str()) || end <= start {
                continue;
            }
            match read_remote(pid, start, (end - start) as usize) {
                Some(bytes) => segs.push(Segment {
                    addr: start,
                    bytes: Bytes::Owned(bytes),
                    perms: perms.to_string(),
                    name,
                }),
                None => eprintln!("warning: cannot read {range} {perms} {name}"),
            }
        }
        Ok(segs)
    }

    fn read_remote(pid: i32, start: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut local = [IoSliceMut::new(&mut buf)];
        let remote = [RemoteIoVec {
            base: start as usize,
            len,
        }];
        match process_vm_readv(Pid::from_raw(pid), &mut local, &remote) {
            Ok(0) | Err(_) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(buf)
            }
        }
    }
}
