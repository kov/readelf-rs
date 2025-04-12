use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use std::fmt;
use std::fs::File;
use std::path::Path;

use crate::emachine::EMachine;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ElfIdent {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    pub padding: [u8; 7],
}

#[repr(transparent)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct ElfType(pub u16);

impl fmt::Display for ElfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "NONE (None)"),
            1 => write!(f, "REL (Relocatable file)"),
            2 => write!(f, "EXEC (Executable file)"),
            3 => write!(f, "DYN (FIXME)"),
            4 => write!(f, "CORE (Core file)"),
            0xfe00..=0xfeff => write!(f, "OS Specific: ({:#x})", self.0),
            0xff00..=0xffff => write!(f, "Processor Specific: ({:#x})", self.0),
            _ => write!(f, "<unknown>: {:#x}", self.0),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Elf64Header {
    pub e_ident: ElfIdent,
    pub e_type: ElfType,
    pub e_machine: EMachine,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Elf32Header {
    pub e_ident: ElfIdent,
    pub e_type: ElfType,
    pub e_machine: EMachine,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

pub struct ElfFile<'a> {
    _mmap: Mmap,
    ident: &'a ElfIdent,
    header: ElfHeader<'a>,
}

pub enum ElfHeader<'a> {
    Elf32(&'a Elf32Header),
    Elf64(&'a Elf64Header),
}

impl<'a> ElfFile<'a> {
    pub fn new(path: &str) -> Result<Self> {
        let path = Path::new(path);

        let file = File::open(path).context("Failed to open ELF file")?;
        let mmap = unsafe { Mmap::map(&file).context("Failed to memory map ELF file")? };

        if mmap.len() < 4 || &mmap[0..4] != b"\x7fELF" {
            bail!("Not a valid ELF file");
        }

        let ident: &ElfIdent = unsafe { &*(mmap.as_ptr() as *const ElfIdent) };

        if (ident.data == 1) != cfg!(target_endian = "little") {
            bail!("ELF file endianess does not match the platform's endianess");
        }

        let header = match ident.class {
            1 => {
                let elf_header: &Elf32Header = unsafe { &*(mmap.as_ptr() as *const Elf32Header) };
                ElfHeader::Elf32(elf_header)
            }
            2 => {
                let elf_header: &Elf64Header = unsafe { &*(mmap.as_ptr() as *const Elf64Header) };
                ElfHeader::Elf64(elf_header)
            }
            _ => {
                bail!("Invalid ELF class (not 32-bit or 64-bit)");
            }
        };

        Ok(Self {
            _mmap: mmap,
            ident,
            header,
        })
    }
}

macro_rules! display_header {
    ($f:expr, $header:expr) => {{
        writeln!(
            $f,
            "  Type:                              {}",
            $header.e_type
        )?;
        writeln!(
            $f,
            "  Machine:                           {}",
            $header.e_machine
        )?;
        writeln!(
            $f,
            "  Version:                           {}",
            $header.e_version
        )?;
        writeln!(
            $f,
            "  Entry point address:               0x{:x}",
            $header.e_entry
        )?;
        writeln!(
            $f,
            "  Start of program headers:          {} (bytes into file)",
            $header.e_phoff
        )?;
        writeln!(
            $f,
            "  Start of section headers:          {} (bytes into file)",
            $header.e_shoff
        )?;
        writeln!(
            $f,
            "  Flags:                             0x{:x}",
            $header.e_flags
        )?;
        writeln!(
            $f,
            "  Size of this header:               {} (bytes)",
            $header.e_ehsize
        )?;
        writeln!(
            $f,
            "  Size of program headers:           {} (bytes)",
            $header.e_phentsize
        )?;
        writeln!(
            $f,
            "  Number of program headers:         {}",
            $header.e_phnum
        )?;
        writeln!(
            $f,
            "  Size of section headers:           {} (bytes)",
            $header.e_shentsize
        )?;
        writeln!(
            $f,
            "  Number of section headers:         {}",
            $header.e_shnum
        )?;
        writeln!(
            $f,
            "  Section header string table index: {}",
            $header.e_shstrndx
        )?;
        Ok(())
    }};
}

impl<'a> fmt::Display for ElfFile<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ELF Header:")?;
        writeln!(
            f,
            "  Magic:   {}",
            self.ident
                .magic
                .iter()
                .chain(self.ident.padding.iter())
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        )?;
        writeln!(
            f,
            "  Class:                             {}",
            match self.ident.class {
                1 => "ELF32",
                2 => "ELF64",
                _ => "Unknown",
            }
        )?;
        writeln!(
            f,
            "  Data:                              {}",
            match self.ident.data {
                1 => "2's complement, little endian",
                2 => "2's complement, big endian",
                _ => "Unknown",
            }
        )?;
        writeln!(
            f,
            "  Version:                           {} (current)",
            self.ident.version
        )?;
        writeln!(f, "  OS/ABI:                            UNIX - System V")?; // Simplified for now
        writeln!(
            f,
            "  ABI Version:                       {}",
            self.ident.abi_version
        )?;

        match &self.header {
            ElfHeader::Elf32(header) => display_header!(f, header),
            ElfHeader::Elf64(header) => display_header!(f, header),
        }
    }
}
