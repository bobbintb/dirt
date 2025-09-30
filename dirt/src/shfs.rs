use crate::error::ShfsError;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, Register};
use log::{debug, trace};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const SHFS_BINARY_PATH: &str = "/usr/libexec/unraid/shfs";

/// A struct to hold information about the shfs binary analysis.
struct ShfsAnalysis<'a> {
    elf: ElfBytes<'a, AnyEndian>,
    text_section: elf::section::SectionHeader,
    loadable_segments: Vec<elf::segment::ProgramHeader>,
}

impl<'a> ShfsAnalysis<'a> {
    /// Creates a new analysis instance for the shfs binary.
    fn new(file_bytes: &'a [u8]) -> Result<Self, ShfsError> {
        let elf = ElfBytes::<AnyEndian>::minimal_parse(file_bytes)
            .map_err(ShfsError::ElfParseError)?;

        let text_section = elf
            .section_header_by_name(".text")?
            .ok_or(ShfsError::ExecSegmentNotFound)?;

        let loadable_segments = elf
            .segments()
            .ok_or(ShfsError::ExecSegmentNotFound)?
            .iter()
            .filter(|phdr| phdr.p_type == elf::abi::PT_LOAD)
            .collect();

        Ok(Self {
            elf,
            text_section,
            loadable_segments,
        })
    }

    /// Converts a virtual address to a file offset.
    fn vaddr_to_offset(&self, vaddr: u64) -> Result<u64, ShfsError> {
        for phdr in &self.loadable_segments {
            if vaddr >= phdr.p_vaddr && vaddr < phdr.p_vaddr + phdr.p_memsz {
                return Ok(phdr.p_offset + (vaddr - phdr.p_vaddr));
            }
        }
        Err(ShfsError::AddressNotLoadable { addr: vaddr })
    }

    /// Finds the virtual address of a function's string identifier.
    fn find_string_vaddr(&self, func_name: &str) -> Result<u64, ShfsError> {
        let rodata = self.elf.section_header_by_name(".rodata")?.ok_or(
            ShfsError::StringNotFound {
                name: func_name.to_string(),
            },
        )?;

        let (data, _) = self.elf.section_data(&rodata)?;
        let cstr_name = std::ffi::CString::new(func_name).unwrap();

        let string_relative_offset = data
            .windows(cstr_name.as_bytes_with_nul().len())
            .position(|window| window == cstr_name.as_bytes_with_nul())
            .map(|pos| pos as u64)
            .ok_or_else(|| ShfsError::StringNotFound {
                name: func_name.to_string(),
            })?;

        Ok(rodata.sh_addr + string_relative_offset)
    }

    /// Finds the first reference to a virtual address in the .text section.
    fn find_string_ref_vaddr(&self, string_vaddr: u64) -> Result<u64, ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        let mut decoder = Decoder::new(64, text_data, DecoderOptions::AMD);
        decoder.set_ip(self.text_section.sh_addr);

        for instruction in decoder {
            if instruction.is_invalid() {
                continue;
            }

            // Case 1: IP-relative memory operand. This is the most common case in x64.
            if instruction.is_ip_rel_memory_operand() {
                if instruction.ip_rel_memory_address() == string_vaddr {
                    debug!("Found IP-relative reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                    return Ok(instruction.ip());
                }
            }

            // Case 2: Absolute memory operand or immediate operand.
            for i in 0..instruction.op_count() {
                let op_kind = instruction.op_kind(i);

                // Check for an absolute memory address (no base/index registers).
                if op_kind == iced_x86::OpKind::Memory &&
                   instruction.memory_base() == iced_x86::Register::None &&
                   instruction.memory_index() == iced_x86::Register::None {
                    if instruction.memory_displacement64() == string_vaddr {
                        debug!("Found absolute memory reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                        return Ok(instruction.ip());
                    }
                }

                // Check for an immediate value matching the address.
                match op_kind {
                    iced_x86::OpKind::Immediate64 if instruction.immediate64() == string_vaddr => {
                        debug!("Found immediate reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                        return Ok(instruction.ip());
                    }
                    iced_x86::OpKind::Immediate32 if instruction.immediate32() as u64 == string_vaddr => {
                        debug!("Found immediate reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                        return Ok(instruction.ip());
                    }
                    _ => {}
                }
            }
        }

        Err(ShfsError::StringRefNotFound { name: format!("{:#x}", string_vaddr) })
    }

    /// Searches backwards from a reference address to find the function prologue.
    fn find_function_prologue_vaddr(&self, ref_vaddr: u64) -> Result<u64, ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        // We only need to decode instructions up to the reference address.
        let ref_offset_in_text = (ref_vaddr - self.text_section.sh_addr) as usize;
        let data_to_decode = &text_data
            .get(..ref_offset_in_text)
            .ok_or_else(|| ShfsError::PrologueNotFound { name: format!("{:#x}", ref_vaddr) })?;

        let mut decoder = Decoder::new(64, data_to_decode, DecoderOptions::AMD);
        decoder.set_ip(self.text_section.sh_addr);

        let instructions: Vec<Instruction> = decoder.iter().collect();

        if let Some(prologue_window) = instructions.windows(2).rev().find(|window| {
            let push_ins = &window[0];
            let mov_ins = &window[1];

            // Check for `push rbp`
            let is_push_rbp = push_ins.mnemonic() == Mnemonic::Push
                && push_ins.op_count() == 1
                && push_ins.op0_register() == Register::RBP;

            // Check for `mov rbp, rsp`
            let is_mov_rbp_rsp = mov_ins.mnemonic() == Mnemonic::Mov
                && mov_ins.op_count() == 2
                && mov_ins.op0_register() == Register::RBP
                && mov_ins.op1_register() == Register::RSP;

            is_push_rbp && is_mov_rbp_rsp
        }) {
            let prologue_start_ins = &prologue_window[0];
            debug!(
                "Found function prologue for ref {:#x} at {:#x}",
                ref_vaddr,
                prologue_start_ins.ip()
            );
            Ok(prologue_start_ins.ip())
        } else {
            Err(ShfsError::PrologueNotFound {
                name: format!("{:#x}", ref_vaddr),
            })
        }
    }
}

/// Finds the file offsets for a list of function names in the shfs binary.
pub fn get_function_offsets(
    functions: &[&str],
) -> Result<HashMap<String, u64>, ShfsError> {
    debug!("Starting analysis of binary: {}", SHFS_BINARY_PATH);
    let binary_path = Path::new(SHFS_BINARY_PATH);
    if !binary_path.exists() {
        return Err(ShfsError::BinaryNotFound {
            path: SHFS_BINARY_PATH.to_string(),
        });
    }

    let file_bytes = fs::read(binary_path).map_err(|e| ShfsError::ReadError {
        path: SHFS_BINARY_PATH.to_string(),
        source: e,
    })?;

    let analysis = ShfsAnalysis::new(&file_bytes)?;
    let mut offsets = HashMap::new();

    for &func_name in functions {
        debug!("Searching for function: {}", func_name);

        let string_vaddr = analysis.find_string_vaddr(func_name)?;
        debug!("String virtual address: {:#x}", string_vaddr);

        let ref_vaddr = analysis.find_string_ref_vaddr(string_vaddr)?;
        trace!("Found reference to string at vaddr: {:#x}", ref_vaddr);

        let func_vaddr = analysis.find_function_prologue_vaddr(ref_vaddr)?;
        debug!("Function start virtual address: {:#x}", func_vaddr);

        let func_offset = analysis.vaddr_to_offset(func_vaddr)?;
        debug!("Function file offset: {:#x}", func_offset);

        offsets.insert(func_name.to_string(), func_offset);
    }

    Ok(offsets)
}
