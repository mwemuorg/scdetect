use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;

use ahash::AHasher;
use libmwemu::arch::{Arch, OperatingSystem};
use libmwemu::emu::Emu;
use libmwemu::emu::decoded_instruction::DecodedInstruction;
use libmwemu::flags::Flags;
use libmwemu::maps::mem64::Permission;
use libmwemu::regs_aarch64::RegsAarch64;
use libmwemu::regs64::Regs64;
use serde::Serialize;

use crate::target::arch_name;

#[derive(Debug, Clone)]
pub struct ScanCfg {
    pub max_insns: u64,
    pub window: usize,
    pub timeout_secs: f64,
    /// print every executed instruction (used by --trace)
    pub trace: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OffsetResult {
    /// segment index (the file is segment 0)
    #[serde(skip)]
    pub seg: usize,
    /// file offset or virtual address
    pub addr: u64,
    /// offset inside the segment
    #[serde(skip)]
    pub offset: usize,
    pub arch: &'static str,
    /// instructions emulated before stopping
    pub insns: u64,
    /// distinct addresses executed, loops don't inflate it
    pub unique: u32,
    pub stop: &'static str,
}

/// One emulator per thread, reused for every offset.
///
/// Creating an `Emu` and calling `run()` allocate big instruction caches
/// (~ms each), so we build it once and drive it with `step()`, which decodes
/// straight from memory.
pub struct Worker {
    emu: Box<Emu>,
    arch: Arch,
    cpu0: Cpu,
    nmaps: usize,
    pcs: HashSet<u64>,
    /// (pc, cpu state) hashes seen, to spot repeated states
    states: HashSet<u64>,
    stack_zeros: Vec<u8>,
    /// stack map (base, end)
    stack: (u64, u64),
}

/// How far below the stack map sp may go (mwemu grows the x64 stack on demand).
const STACK_GROW_MAX: u64 = 0x100000;

/// Initial CPU state, restored before every offset.
#[derive(Clone, Copy)]
enum Cpu {
    X86(Regs64, Flags),
    A64(RegsAarch64),
}

impl Worker {
    pub fn new(arch: Arch, os: OperatingSystem) -> Worker {
        let mut emu = Box::new(match arch {
            Arch::X86 => libmwemu::emu32(),
            Arch::X86_64 => libmwemu::emu64(),
            Arch::Aarch64 => libmwemu::emu_aarch64(),
        });
        emu.cfg.verbose = 0;
        emu.cfg.nocolors = true;
        emu.cfg.console_enabled = false;
        emu.os = os;
        // creates the code + stack maps and the initial register state
        emu.load_code_bytes(&[0x90]);
        zero_regs(&mut emu, arch);
        small_stack(&mut emu, arch);
        let cpu0 = match arch {
            Arch::Aarch64 => Cpu::A64(*emu.regs_aarch64()),
            _ => Cpu::X86(*emu.regs(), emu.flags_snapshot()),
        };
        let nmaps = emu.maps.mem_slab.len();
        let st = emu.maps.get_map_by_name("stack").expect("no stack map");
        let stack = (st.get_base(), st.get_bottom());
        Worker {
            emu,
            arch,
            cpu0,
            nmaps,
            pcs: HashSet::new(),
            states: HashSet::new(),
            stack_zeros: Vec::new(),
            stack,
        }
    }

    fn sp(&self) -> u64 {
        match self.arch {
            Arch::Aarch64 => self.emu.regs_aarch64().sp,
            _ => self.emu.regs().rsp,
        }
    }

    /// Put the emulator back to the initial state with `code` mapped.
    fn reset(&mut self, code: &[u8]) {
        let os = self.emu.os;
        // syscalls like mmap may have created maps: start from scratch then
        if self.emu.maps.mem_slab.len() != self.nmaps {
            *self = Worker::new(self.arch, os);
        }
        // like load_code_bytes() but without init_cpu(), registers are restored below
        let base = self.emu.cfg.code_base_addr;
        self.emu.maps.free("code");
        self.emu
            .maps
            .create_map(
                "code",
                base,
                code.len() as u64,
                Permission::READ_WRITE_EXECUTE,
            )
            .expect("cannot create code map")
            .write_bytes(base, code);
        if let Some(stack) = self.emu.maps.get_map_by_name_mut("stack") {
            self.stack_zeros.resize(stack.size(), 0);
            stack.write_bytes(stack.get_base(), &self.stack_zeros);
        }
        match self.cpu0 {
            Cpu::X86(regs, flags) => {
                *self.emu.regs_mut() = regs;
                *self.emu.flags_overwrite_mut() = flags;
            }
            Cpu::A64(regs) => *self.emu.regs_aarch64_mut() = regs,
        }
        self.emu.set_pc(self.emu.cfg.code_base_addr);
        self.emu.process_terminated = false;
        self.emu.pos = 0;
        self.pcs.clear();
        self.states.clear();
    }

    /// Emulate `data[off..]` as raw code and measure how far it gets.
    pub fn emulate_at(&mut self, data: &[u8], off: usize, cfg: &ScanCfg) -> OffsetResult {
        let end = off.saturating_add(cfg.window).min(data.len());
        self.reset(&data[off..end]);

        let code_base = self.emu.cfg.code_base_addr;
        let code_end = code_base + (end - off) as u64;
        let t0 = Instant::now();
        let mut insns: u64 = 0;
        let mut stop = "limit";
        // infinite loop proof: same pc + registers + flags + memory twice
        let mut pending: Option<(u64, u64, u64)> = None; // (state hash, memory hash, insns)
        let mut next_mem_check: u64 = 0;

        while insns < cfg.max_insns {
            let pc = self.emu.pc();
            // only the file bytes count: jumping to the stack or elsewhere ends the run
            if pc < code_base || pc >= code_end {
                if cfg.trace {
                    println!("pc {pc:#x} left the code map");
                }
                stop = "pc_out";
                break;
            }
            // a wild stack pointer (xchg esp,eax with eax=0...) is not shellcode, and
            // mwemu's x64 stack growing would happily map pages around it
            let sp = self.sp();
            let in_stack = sp > self.stack.0.saturating_sub(STACK_GROW_MAX) && sp <= self.stack.1;
            if !in_stack && (sp < code_base || sp > code_end) {
                if cfg.trace {
                    println!("sp {sp:#x} is outside the stack and the code");
                }
                stop = "sp_out";
                break;
            }
            let emu = &mut self.emu;
            match panic::catch_unwind(AssertUnwindSafe(|| emu.step())) {
                Err(_) => {
                    stop = "panic";
                    break;
                }
                Ok(false) => {
                    stop = if self.emu.process_terminated {
                        "exit"
                    } else {
                        "fault"
                    };
                    break;
                }
                Ok(true) => {}
            }
            insns += 1;
            self.pcs.insert(pc);

            if cfg.trace {
                print_ins(&self.emu, insns, pc);
            }

            let st = cpu_hash(&self.emu, self.arch);
            let repeated = !self.states.insert(st);
            match pending {
                // the pending state came back: a full lap of the loop happened,
                // only memory can make the next lap differ
                Some((s0, m0, _)) if s0 == st => {
                    if mem_hash(&self.emu) == m0 {
                        if cfg.trace {
                            println!(
                                "state repeated at {pc:#x} with no memory change: infinite loop"
                            );
                        }
                        stop = "inf_loop";
                        break;
                    }
                    // the loop writes memory, it may end: retry later
                    pending = None;
                    next_mem_check = insns + insns / 2;
                }
                // never came back to that state
                Some((_, _, at)) if insns - at > 0x1000 => pending = None,
                Some(_) => {}
                None if repeated && insns >= next_mem_check => {
                    pending = Some((st, mem_hash(&self.emu), insns));
                }
                None => {}
            }
            if insns & 0x3ff == 0 && t0.elapsed().as_secs_f64() > cfg.timeout_secs {
                stop = "timeout";
                break;
            }
        }

        OffsetResult {
            seg: 0,
            addr: off as u64,
            offset: off,
            arch: arch_name(self.arch),
            insns,
            unique: self.pcs.len() as u32,
            stop,
        }
    }
}

/// Hash of pc + general registers + flags (+ SIMD regs).
fn cpu_hash(emu: &Emu, arch: Arch) -> u64 {
    let mut h = AHasher::default();
    match arch {
        Arch::Aarch64 => {
            let r = emu.regs_aarch64();
            r.x.hash(&mut h);
            r.v.hash(&mut h);
            (r.sp, r.pc).hash(&mut h);
            (r.nzcv.n, r.nzcv.z, r.nzcv.c, r.nzcv.v).hash(&mut h);
        }
        _ => {
            let r = emu.regs();
            (r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp).hash(&mut h);
            (r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15).hash(&mut h);
            (
                r.xmm0, r.xmm1, r.xmm2, r.xmm3, r.xmm4, r.xmm5, r.xmm6, r.xmm7,
            )
                .hash(&mut h);
            r.rip.hash(&mut h);
            emu.flags_snapshot().dump().hash(&mut h);
        }
    }
    h.finish()
}

/// Hash of every mapped byte; in raw shellcode mode that's just code + stack.
fn mem_hash(emu: &Emu) -> u64 {
    let mut h = AHasher::default();
    for (_, m) in emu.maps.mem_slab.iter() {
        m.get_base().hash(&mut h);
        h.write(m.read_bytes(m.get_base(), m.size()));
    }
    h.finish()
}

fn print_ins(emu: &Emu, n: u64, pc: u64) {
    let map = emu
        .maps
        .get_mem_by_addr(pc)
        .map(|m| m.get_name())
        .unwrap_or("?");
    let txt = match emu.last_decoded {
        Some(DecodedInstruction::X86(i)) => i.to_string(),
        Some(DecodedInstruction::AArch64(i)) => i.to_string(),
        None => "?".into(),
    };
    println!("{n:>6} {pc:#x} [{map}] {txt}");
}

/// Replace the default stack (1MB on x64) by a 64KB one around the same sp,
/// it's zeroed and hashed for every offset.
fn small_stack(emu: &mut Emu, arch: Arch) {
    const HALF: u64 = 0x8000;
    let sp = match arch {
        Arch::Aarch64 => emu.regs_aarch64().sp,
        _ => emu.regs().rsp,
    };
    let base = (sp & !0xfff) - HALF;
    emu.maps.free("stack");
    emu.maps
        .create_map("stack", base, 2 * HALF, Permission::READ_WRITE)
        .expect("cannot create stack map");
}

/// All general purpose registers to 0 except the stack pointer, so random
/// memory operands fault instead of hitting the stack map.
fn zero_regs(emu: &mut Emu, arch: Arch) {
    match arch {
        Arch::Aarch64 => emu.regs_aarch64_mut().x = [0; 31],
        _ => {
            let (sp, ip) = (emu.regs().rsp, emu.regs().rip);
            emu.regs_mut().clear::<64>();
            emu.regs_mut().rsp = sp;
            emu.regs_mut().rip = ip;
        }
    }
}
