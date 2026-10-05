use goblin::Object;

/// File layout of executables (PE / ELF / Mach-O), used only to label
/// offsets in the report: every offset is scanned anyway.
pub struct Regions {
    /// (start, end, name) sorted by start, file offsets
    list: Vec<(usize, usize, String)>,
    /// end of the last region, bytes after it are overlay
    last_end: usize,
    pub format: &'static str,
}

impl Regions {
    pub fn parse(data: &[u8]) -> Regions {
        let mut list = Vec::new();
        let format = match Object::parse(data) {
            Ok(Object::PE(pe)) => {
                if let Some(opt) = pe.header.optional_header {
                    let hdr = opt.windows_fields.size_of_headers as usize;
                    list.push((0, hdr, "header".to_string()));
                }
                for s in &pe.sections {
                    let start = s.pointer_to_raw_data as usize;
                    let end = start + s.size_of_raw_data as usize;
                    list.push((start, end, s.name().unwrap_or("?").to_string()));
                }
                "pe"
            }
            Ok(Object::Elf(elf)) => {
                for s in &elf.section_headers {
                    if s.sh_type == goblin::elf::section_header::SHT_NOBITS || s.sh_size == 0 {
                        continue;
                    }
                    let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("?");
                    let start = s.sh_offset as usize;
                    list.push((start, start + s.sh_size as usize, name.to_string()));
                }
                "elf"
            }
            Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => {
                for seg in &m.segments {
                    if let Ok(sections) = seg.sections() {
                        for (s, _) in sections {
                            let start = s.offset as usize;
                            let name = format!(
                                "{},{}",
                                s.segname().unwrap_or("?"),
                                s.name().unwrap_or("?")
                            );
                            list.push((start, start + s.size as usize, name));
                        }
                    }
                }
                "macho"
            }
            _ => "raw",
        };
        list.retain(|r| r.1 > r.0);
        list.sort_by_key(|r| r.0);
        let last_end = list.iter().map(|r| r.1).max().unwrap_or(0);
        Regions {
            list,
            last_end,
            format,
        }
    }

    /// Name of the region containing `off` ("" for raw files).
    pub fn name(&self, off: usize) -> &str {
        if self.format == "raw" {
            return "";
        }
        // innermost match wins: the last region starting at or before off
        for r in self.list.iter().rev() {
            if r.0 <= off && off < r.1 {
                return &r.2;
            }
        }
        if off >= self.last_end {
            "overlay"
        } else {
            "gap"
        }
    }
}
