# scdetect

Shellcode detector based on emulation, built on [libmwemu](https://github.com/mwemuorg/mwemu).

Instead of searching for byte patterns or signatures, scdetect **emulates the input
from every possible offset** (offset 0, 1, 2, ...) and measures how far execution gets
before it breaks. Random data, compressed media and most file formats fall apart after a
handful of instructions; real code keeps running. The result is a ranking of offsets,
from the one that emulated the most instructions to the one that emulated the least.

It works on anything: PNG, MP4, PDF, executables, raw blobs, or the memory of a live
Linux process.

## How it works

For every offset of the input and for every selected architecture:

1. The bytes from that offset on (up to `--window` bytes) are mapped as code in a fresh
   emulator state: general purpose registers set to 0, a small zeroed stack, no OS
   environment.
2. The code is emulated instruction by instruction until something stops it.
3. scdetect records how many instructions were executed and how many **distinct
   addresses** were executed (loops don't inflate this number).

Zeroed registers make random memory operands fault right away instead of landing on
valid memory, so noise dies fast. Shellcode is written to run with no context (it finds
its own address, builds data on the stack, makes syscalls...), so it stands out.

### Stop reasons

| stop       | meaning |
|------------|---------|
| `fault`    | invalid opcode, unmapped memory access or other emulation error |
| `pc_out`   | execution jumped outside the scanned bytes |
| `sp_out`   | the stack pointer left the stack and the code (e.g. `xchg esp,eax` with `eax=0`) |
| `inf_loop` | proven infinite loop (see below) |
| `limit`    | reached `--max-insns` |
| `timeout`  | reached `--timeout` |
| `exit`     | the emulator terminated the process (currently also reported for some faults) |
| `panic`    | the emulator panicked on these bytes (caught, the scan goes on) |

### Infinite loop detection

Loops are not cut by an iteration count but by their logic. In this setup the whole
machine state is the CPU registers + flags + the mapped memory (code and stack). When the
same program counter is reached with the same registers and flags, scdetect hashes the
memory and checks again one lap later: if registers, flags and memory are all identical,
the (deterministic) emulator would repeat the same lap forever, so the loop is
**provably infinite** and the run stops with `inf_loop` (`jmp $`, `b .`, loops with a
counter that never changes...).

Loops that make progress, like a XOR decoder writing to its own code, change the state on
every lap and keep running. Only loops that write memory forever without ending are left
to `--max-insns`.

### Performance

Creating a libmwemu `Emu` and calling `run()` is expensive (big instruction caches), so
every worker thread builds one emulator and reuses it for all its offsets, resetting
registers, flags, stack and the code map, and driving it with `step()`. Scans run in
parallel with rayon. Typical speed is hundreds of thousands of emulations per second,
for example a 6 MB MP4 with two architectures (12M emulations) takes ~45 s on an
8-core machine.

Only the best `--keep` results are held in memory, so big inputs and process memory
don't need one result per offset.

## Build

scdetect uses [libmwemu from crates.io](https://crates.io/crates/libmwemu).

```sh
cargo build --release
```

## Usage

```sh
# scan a file
scdetect suspicious.pdf

# choose target OS and architectures
scdetect image.png --os windows --arch x86,x64

# show the 50 best offsets, or everything kept as JSON
scdetect blob.bin --top 50
scdetect blob.bin --json > results.json

# scan a range, or every 4 bytes
scdetect video.mp4 --start 0x10000 --end 0x20000
scdetect video.mp4 --stride 4

# emulate a single offset printing every instruction
scdetect sample.exe --arch x64 --trace 0x1138f

# verbose scan: -v one line per offset, -vv every instruction (single thread)
scdetect blob.bin --start 0x3000 --end 0x3010 -vv
```

### Scanning process memory

```sh
# live Linux process (needs root/CAP_SYS_PTRACE, see /proc/sys/kernel/yama/ptrace_scope)
sudo scdetect --pid 1234 --os linux

# only executable maps
sudo scdetect --pid 1234 --perms x

# a dump made with mwemu-snapshot (or a minidump), on any machine
scdetect --dump process.mwemu --os linux

# trace an address of the process
scdetect --dump process.mwemu --trace 0x7f3a1c0021f0
```

The `.mwemu` format is libmwemu's serialized `Emu` state, which has no versioning: a dump
only loads if it was written by the same libmwemu version scdetect is built with, so build
`mwemu-snapshot` against the same libmwemu release.

`--pid` stops the process with ptrace, copies every readable map with
`process_vm_readv` (like `mwemu-snapshot`), and resumes it. Kernel special maps
(`[vvar]`, `[vdso]`, `[vsyscall]`) are skipped. Every offset of every map is scanned;
`--perms` only narrows the scan when asked. Addresses are reported as virtual addresses,
and the region column shows the map permissions and name, so injected code typically
shows up as `rwx [anon]`.

### Target OS and architectures

By default the target is the system scdetect runs on: the host OS and its architectures
(on Apple Silicon: macOS, `arm64` + `x64` for Rosetta; on Windows x64: `x64` + `x86` for
WoW64; on Linux x64: `x64` + `x86`). Use `--os` and `--arch` to target something else.

## Output

```
 rank      offset   arch     insns   unique  stop      region
    1       0x800    x86       135       41  inf_loop
    2      0x3000    x86        42       34  fault
```

- `offset` / `address`: file offset, or virtual address when scanning memory.
- `insns`: instructions emulated.
- `unique`: distinct addresses executed, the main ranking key.
- `region`: for PE / ELF / Mach-O files, the section containing the offset (`.text`,
  `.rsrc`, `overlay`...); for memory, the map permissions and name. It's only a label,
  every offset is scanned regardless of the region.

## Options

| option | default | description |
|--------|---------|-------------|
| `<file>` | | file to scan |
| `--pid <pid>` | | scan a live Linux process |
| `--dump <file>` | | scan the maps of a mwemu dump (`.mwemu` or minidump) |
| `--perms <chars>` | all | only scan maps whose permissions contain these chars, e.g. `x` |
| `--os <os>` | `host` | `host`, `windows`, `linux`, `macos` |
| `--arch <list>` | host | comma separated: `x86`, `x64`, `arm64` |
| `--max-insns <n>` | 10000 | max instructions per offset |
| `--window <n>` | 0x10000 | bytes mapped as code from each offset |
| `--timeout <s>` | 2.0 | wall-clock timeout per offset |
| `--start <n>` / `--end <n>` | whole input | offset/address range (hex or dec) |
| `--stride <n>` | 1 | scan every N bytes |
| `--top <n>` | 30 | rows printed |
| `--keep <n>` | 10000 | best results kept (and printed by `--json`) |
| `--trace <n>` | | emulate only this offset/address, printing every instruction |
| `-v`, `-vv` | | per-offset results, and every instruction |
| `--json` | | JSON output |

Set `SCDETECT_PANICS=1` to see libmwemu panics that are normally caught silently.

## Limitations

- **Compiled code also emulates well.** In executables the code sections are full of
  valid code, and entering a function in the middle can run for a hundred instructions.
  Ranking by instruction count alone doesn't separate it from shellcode yet.
- **Runs of harmless single-byte instructions** (data tables of `0x5D` = `pop rbp`, NOP
  sleds, padding) produce long runs with many distinct addresses.
- **No OS environment in the scan.** Windows shellcode stops when it reads the PEB
  (`gs:[0x60]` / `fs:[0x30]`), Linux shellcode keeps going after `execve`.
- **Small shellcode** is close to the noise floor: random data reaches ~20-25
  instructions by chance, a short shellcode may emulate only ~40.
- `--pid` is Linux only. On other systems use `--dump` with a dump taken on Linux.

## Roadmap

- Shellcode trait metrics: distinct instruction encodings, GetPC (`call $+5; pop`,
  `fnstenv`), PEB walking, export name hashing, OS-valid syscalls, self-modifying writes,
  stack strings; and compiled code traits (reads of locals from a stack frame never set up,
  uninitialized callee-saved registers).
- Clustering of neighbouring offsets that converge into the same trace.
- Second pass for the top candidates with a full OS environment (`init_win32`,
  `init_linux64`...) to see API calls and syscalls.
- Prefilter with a fast decoder to skip hopeless offsets.
- Container extractors: PDF streams, ZIP/Office entries, base64/hex blobs.
- ROP chain detection: statistical detection of address lists sharing a module base,
  matching the low 12 bits of addresses against known libc offsets (ASLR keeps them),
  and emulating the chain when the target module is available.
