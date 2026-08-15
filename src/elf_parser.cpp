
/**
 * @file    elf_parser.cpp
 * @brief   Implements ELF parsing using RuntimeXRay's MappedFile.
 *
 * @author  Peter Magram
 * @date    2026-08-12
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

// Copyright 2026 Peter Magram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "elf_parser.hpp"
#include "mapped_file.hpp"
#include <iostream>
#include <cstddef>
#include <cstring>
#include <array>
#include <cstdint>
#include <endian.h>

namespace runtimexray
{

    // Size of the ELF identification array (e_ident)
    constexpr std::size_t ELF_IDENT_SIZE = 16;

    // Printable desciptions for enum-s
    constexpr std::string_view ELF32_CLASS_STR = "Elf32";
    constexpr std::string_view ELF64_CLASS_STR = "Elf64";
    constexpr std::string_view NONE_CLASS_STR = "None";

    constexpr std::string_view L_ENDIAN_DATA_STR = "LittleEndian";
    constexpr std::string_view B_ENDIAN_DATA_STR = "BigEndian";
    constexpr std::string_view NONE_DATA_STR = "None";

    constexpr std::string_view ELF_TYPE_REL_STR = "REL (Relocatable)";
    constexpr std::string_view ELF_TYPE_EXEC_STR = "EXEC (Executable)";
    constexpr std::string_view ELF_TYPE_DYN_STR = "DYN (Shared object/PIE)";
    constexpr std::string_view ELF_TYPE_CORE_STR = "CORE (Core file)";
    constexpr std::string_view ELF_TYPE_UNK_STR = "Unknown";

    constexpr std::string_view ELF_MACHINE_X86_64_STR = "x86_64";
    constexpr std::string_view ELF_MACHINE_ARM64_STR = "ARM64";
    constexpr std::string_view ELF_MACHINE_UNK_STR = "Unknown";

    // ELF identification indexes (from e_ident[])
    enum ElfIdentIndex : std::size_t
    {
        EI_MAG0 = 0,
        EI_MAG1 = 1,
        EI_MAG2 = 2,
        EI_MAG3 = 3,
        EI_CLASS = 4,  // 1 = 32-bit, 2 = 64-bit
        EI_DATA = 5,   // 1 = little-endian, 2 = big-endian
        EI_VERSION = 6 // must be 1
    };

    // ELF class values
    enum class ElfClass : unsigned char
    {
        None = 0,
        Elf32 = 1,
        Elf64 = 2
    };

    // ELF data encoding values
    enum class ElfData : unsigned char
    {
        None = 0,
        LittleEndian = 1,
        BigEndian = 2
    };

    // ELF file type values (partial)
    enum class ElfType : uint16_t
    {
        None = 0,
        Rel = 1,  // relocatable
        Exec = 2, // executable
        Dyn = 3,  // shared object / PIE
        Core = 4  // core file
    };

    // Machine architectures (partial)
    enum class ElfMachine : uint16_t
    {
        None = 0,
        x86_64 = 62,
        ARM64 = 183
    };

    // Helper conversion functions that validate
    ElfClass to_elf_class(unsigned char byte)
    {
        switch (byte)
        {
        case 1:
            return ElfClass::Elf32;
        case 2:
            return ElfClass::Elf64;
        default:
            return ElfClass::None;
        }
    };

    ElfData to_elf_data(unsigned char byte)
    {
        switch (byte)
        {
        case 1:
            return ElfData::LittleEndian;
        case 2:
            return ElfData::BigEndian;
        default:
            return ElfData::None;
        }
    }

    const std::string_view &elf_class_to_string(const ElfClass &elf_class)
    {
        switch (elf_class)
        {
        case ElfClass::Elf32:
            return ELF32_CLASS_STR;
        case ElfClass::Elf64:
            return ELF64_CLASS_STR;
        default:
            return NONE_CLASS_STR;
        }
    }

    const std::string_view &elf_data_to_string(const ElfData &elf_data)
    {
        switch (elf_data)
        {
        case ElfData::LittleEndian:
            return L_ENDIAN_DATA_STR;
        case ElfData::BigEndian:
            return B_ENDIAN_DATA_STR;
        default:
            return NONE_DATA_STR;
        }
    }

    const std::string_view &elf_type_to_string(const ElfType &elf_type)
    {
        switch (elf_type)
        {
        case ElfType::Rel:
            return ELF_TYPE_REL_STR;
        case ElfType::Exec:
            return ELF_TYPE_EXEC_STR;
        case ElfType::Dyn:
            return ELF_TYPE_DYN_STR;
        case ElfType::Core:
            return ELF_TYPE_CORE_STR;
        default:
            return ELF_TYPE_UNK_STR;
        }
    }

    const std::string_view &elf_machine_to_string(const ElfMachine &elf_machine)
    {
        switch (elf_machine)
        {
        case ElfMachine::x86_64:
            return ELF_MACHINE_X86_64_STR;
        case ElfMachine::ARM64:
            return ELF_MACHINE_ARM64_STR;
        default:
            return ELF_MACHINE_UNK_STR;
        }
    }

    // Additional constants for program header types
    constexpr uint32_t PT_LOAD = 1;
    constexpr uint32_t PT_DYNAMIC = 2;
    constexpr uint32_t PT_GNU_STACK = 0x6474e551;
    constexpr uint32_t PT_GNU_RELRO = 0x6474e552;

    // Flags for segment permissions
    constexpr uint32_t PF_X = 1;
    constexpr uint32_t PF_W = 2;
    constexpr uint32_t PF_R = 4;

    // Program header offsets for 64-bit and 32-bit ELF
    // (these are the same in both, but sizes differ)
    // 64-bit program header:
    //   p_type   (4 bytes) offset 0
    //   p_flags  (4 bytes) offset 4
    //   p_offset (8 bytes) offset 8
    //   p_vaddr  (8 bytes) offset 16
    //   p_paddr  (8 bytes) offset 24
    //   p_filesz (8 bytes) offset 32
    //   p_memsz  (8 bytes) offset 40
    //   p_align  (8 bytes) offset 48
    // 32-bit program header:
    //   p_type   (4 bytes) offset 0
    //   p_offset (4 bytes) offset 4
    //   p_vaddr  (4 bytes) offset 8
    //   p_paddr  (4 bytes) offset 12
    //   p_filesz (4 bytes) offset 16
    //   p_memsz  (4 bytes) offset 20
    //   p_flags  (4 bytes) offset 24
    //   p_align  (4 bytes) offset 28

    // Section header types
    constexpr uint32_t SHT_SYMTAB = 2;
    constexpr uint32_t SHT_DYNSYM = 11;
    // Section header offsets for 64-bit and 32-bit
    // 64-bit section header:
    //   sh_name   (4 bytes) offset 0
    //   sh_type   (4 bytes) offset 4
    //   sh_flags  (8 bytes) offset 8
    //   sh_addr   (8 bytes) offset 16
    //   sh_offset (8 bytes) offset 24
    //   sh_size   (8 bytes) offset 32
    //   sh_link   (4 bytes) offset 40
    //   sh_info   (4 bytes) offset 44
    //   sh_addralign (8 bytes) offset 48
    //   sh_entsize (8 bytes) offset 56
    // 32-bit section header:
    //   sh_name   (4 bytes) offset 0
    //   sh_type   (4 bytes) offset 4
    //   sh_flags  (4 bytes) offset 8
    //   sh_addr   (4 bytes) offset 12
    //   sh_offset (4 bytes) offset 16
    //   sh_size   (4 bytes) offset 20
    //   sh_link   (4 bytes) offset 24
    //   sh_info   (4 bytes) offset 28
    //   sh_addralign (4 bytes) offset 32
    //   sh_entsize (4 bytes) offset 36

    // Endian-aware readers from byte buffer.
    // We always read from the start of the buffer at given offset.
    uint16_t read_u16(const std::byte *data, std::size_t offset, ElfData endian)
    {
        uint16_t val;
        std::memcpy(&val, data + offset, sizeof(val));
        if (endian == ElfData::LittleEndian)
        {
            return le16toh(val);
        }
        else if (endian == ElfData::BigEndian)
        {
            return be16toh(val);
        }
        return val;
    }

    uint32_t read_u32(const std::byte *data, std::size_t offset, ElfData endian)
    {
        uint32_t val;
        std::memcpy(&val, data + offset, sizeof(val));
        if (endian == ElfData::LittleEndian)
        {
            return le32toh(val);
        }
        else if (endian == ElfData::BigEndian)
        {
            return be32toh(val);
        }
        return val;
    }

    uint64_t read_u64(const std::byte *data, std::size_t offset, ElfData endian)
    {
        uint64_t val;
        std::memcpy(&val, data + offset, sizeof(val));
        if (endian == ElfData::LittleEndian)
        {
            return le64toh(val);
        }
        else if (endian == ElfData::BigEndian)
        {
            return be64toh(val);
        }
        return val;
    }

    /**
     * @brief Quick check: is this an ELF file?
     * @param data Pointer to the beginning of the mapped file.
     * @param size Size of the file in bytes.
     * @return true if the file starts with the ELF magic bytes.
     */
    bool is_elf(const std::byte *data, std::size_t size)
    {
        constexpr std::array<std::byte, 4> magic = {
            std::byte{0x7F}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'}};
        if (size < magic.size())
        {
            return false;
        }
        return std::memcmp(data, magic.data(), magic.size()) == 0;
    }

    struct ElfSecurityInfo {
        bool nx_enabled = false;
        bool pie_enabled = false;
        bool relro_full = false;
        bool relro_partial = false;
        bool canary_enabled = false;
    };

    bool has_stack_canary(const std::byte* data, ElfClass elf_class, ElfData elf_data)
    {
        uint64_t e_shoff = 0;
        uint16_t e_shentsize = 0;
        uint16_t e_shnum = 0;

        if (elf_class == ElfClass::Elf64) {
            e_shoff = read_u64(data, 40, elf_data);
            e_shentsize = read_u16(data, 58, elf_data);
            e_shnum = read_u16(data, 60, elf_data);
        } else {
            e_shoff = read_u32(data, 32, elf_data);
            e_shentsize = read_u16(data, 46, elf_data);
            e_shnum = read_u16(data, 48, elf_data);
        }

        if (e_shnum == 0 || e_shentsize == 0) {
            return false;
        }

        for (uint16_t i = 0; i < e_shnum; ++i) {
            std::size_t sh_offset = static_cast<std::size_t>(e_shoff + i * e_shentsize);
            uint32_t sh_type = read_u32(data, sh_offset + 4, elf_data);
            if (sh_type != SHT_DYNSYM && sh_type != SHT_SYMTAB) {
                continue;
            }

            // Read sh_link (associated string table section index)
            uint32_t sh_link = 0;
            uint64_t sh_size = 0;
            uint64_t sh_offset_sym = 0;
            if (elf_class == ElfClass::Elf64) {
                sh_link = read_u32(data, sh_offset + 40, elf_data);
                sh_size = read_u64(data, sh_offset + 32, elf_data);
                sh_offset_sym = read_u64(data, sh_offset + 24, elf_data);
            } else {
                sh_link = read_u32(data, sh_offset + 24, elf_data);
                sh_size = read_u32(data, sh_offset + 20, elf_data);
                sh_offset_sym = read_u32(data, sh_offset + 16, elf_data);
            }

            // Now read the string table section
            std::size_t str_sh_offset = static_cast<std::size_t>(e_shoff + sh_link * e_shentsize);
            uint64_t str_offset = 0;
            uint64_t str_size = 0;
            if (elf_class == ElfClass::Elf64) {
                str_offset = read_u64(data, str_sh_offset + 24, elf_data);
                str_size = read_u64(data, str_sh_offset + 32, elf_data);
            } else {
                str_offset = read_u32(data, str_sh_offset + 16, elf_data);
                str_size = read_u32(data, str_sh_offset + 20, elf_data);
            }

            // Iterate over symbols
            const std::size_t sym_size = (elf_class == ElfClass::Elf64) ? 24 : 16;
            const uint64_t num_syms = sh_size / sym_size;
            for (uint64_t j = 0; j < num_syms; ++j) {
                std::size_t sym_offset = static_cast<std::size_t>(sh_offset_sym + j * sym_size);
                uint32_t st_name = read_u32(data, sym_offset, elf_data);
                if (st_name == 0) {
                    continue;
                }
                // st_name is an offset into the string table; check that it does not exceed its size
                if (st_name >= str_size) {
                    continue;
                }

                const char *str = reinterpret_cast<const char*>(data + str_offset + st_name);
                if (std::strcmp(str, "__stack_chk_fail") == 0) {
                    return true;
                }                
            }
        }

        return false;
    }

    ElfSecurityInfo check_security_features(const std::byte* data, ElfClass elf_class, ElfData elf_data, uint16_t e_type)
    {
        ElfSecurityInfo info;

        // PIE check: if ELF type is ET_DYN (3), PIE is enabled (or it's a shared library)
        info.pie_enabled = (e_type == 3);

        // Read program header table offsets
        // First, get phoff, phentsize, phnum
        uint64_t e_phoff = 0;
        uint16_t e_phentsize = 0;
        uint16_t e_phnum = 0;

        // 64-bit offsets: e_phoff is at 32, e_phentsize at 54, e_phnum at 56
        constexpr std::size_t offset_x64_e_phoff = 32;
        constexpr std::size_t offset_x64_e_phentsize = 54;
        constexpr std::size_t offset_x64_e_phnum = 56;
        // 32-bit offsets: e_phoff at 28, e_phentsize at 42, e_phnum at 44
        constexpr std::size_t offset_x32_e_phoff = 28;
        constexpr std::size_t offset_x32_phentsize = 42;
        constexpr std::size_t offset_x32_phnum = 44;

        if (elf_class == ElfClass::Elf64)
        {
            e_phoff = read_u64(data, offset_x64_e_phoff, elf_data);
            e_phentsize = read_u16(data, offset_x64_e_phentsize, elf_data);
            e_phnum = read_u16(data, offset_x64_e_phnum, elf_data);
        }
        else
        {
            e_phoff = read_u32(data, offset_x32_e_phoff, elf_data);
            e_phentsize = read_u16(data, offset_x32_phentsize, elf_data);
            e_phnum = read_u16(data, offset_x32_phnum, elf_data);
        }

        uint64_t dynamic_offset = 0;
        uint64_t dynamic_size = 0;

        // If program header table is present
        if (e_phnum > 0 && e_phentsize > 0)
        {
            // Loop over program headers
            for (uint16_t i = 0; i < e_phnum; ++i)
            {
                std::size_t ph_offset = static_cast<std::size_t>(e_phoff + i * e_phentsize);
                // Read p_type (first 4 bytes of program header)
                uint32_t p_type = read_u32(data, ph_offset, elf_data);

                // For NX: check PT_GNU_STACK
                if (p_type == PT_GNU_STACK)
                {
                    // Read p_flags (offset depends on 32/64-bit)
                    uint32_t p_flags = 0;
                    if (elf_class == ElfClass::Elf64)
                    {
                        p_flags = read_u32(data, ph_offset + 4, elf_data);
                    }
                    else
                    {
                        p_flags = read_u32(data, ph_offset + 24, elf_data);
                    }
                    // If PF_X is not set, NX is enabled
                    info.nx_enabled = !(p_flags & PF_X);
                }

                // For RELRO: check PT_GNU_RELRO
                if (p_type == PT_GNU_RELRO)
                {
                    info.relro_partial = true; // at least partial RELRO is present
                    // Full RELRO requires DT_BIND_NOW in dynamic section, we won't check now,
                    // but we can later scan PT_DYNAMIC for that flag.
                }

                // Full RELRO detection: we need to scan dynamic section for DT_BIND_NOW
                if (p_type == PT_DYNAMIC)
                {
                    if (elf_class == ElfClass::Elf64)
                    {
                        dynamic_offset = read_u64(data, ph_offset + 8, elf_data);
                        dynamic_size = read_u64(data, ph_offset + 32, elf_data); // p_filesz
                    }
                    else
                    {
                        dynamic_offset = read_u32(data, ph_offset + 4, elf_data);
                        dynamic_size = read_u32(data, ph_offset + 16, elf_data); // p_filesz
                    }
                }
            }
        }

        // Check for full RELRO (DT_BIND_NOW or DT_FLAGS/DF_BIND_NOW)
        constexpr uint64_t DT_BIND_NOW = 24;
        constexpr uint64_t DT_FLAGS = 30;
        constexpr uint64_t DF_BIND_NOW = 0x8;

        if (info.relro_partial && dynamic_offset > 0 && dynamic_size > 0)
        {
            const std::size_t entry_size = (elf_class == ElfClass::Elf64) ? 16 : 8;
            const uint64_t num_entries = dynamic_size / entry_size;
            for (uint64_t j = 0; j < num_entries; ++j)
            {
                std::size_t off = static_cast<std::size_t>(dynamic_offset + j * entry_size);
                uint64_t d_tag = 0;
                uint64_t d_val = 0;
                if (elf_class == ElfClass::Elf64) {
                    d_tag = read_u64(data, off, elf_data);
                    d_val = read_u64(data, off + 8, elf_data);
                } else {
                    d_tag = read_u32(data, off, elf_data);
                    d_val = read_u32(data, off + 4, elf_data);
                }

                if (d_tag == DT_BIND_NOW || (d_tag == DT_FLAGS && (d_val & DF_BIND_NOW))) {
                    info.relro_full = true;
                    break;
                }
            }
        }

        info.canary_enabled = has_stack_canary(data, elf_class, elf_data);

        return info;
    }

    /**
     * @brief Parse an ELF file and print basic information.
     * @param path Path to the file.
     */
    void parse_elf(const std::string &path)
    {
        MappedFile mapped(path);
        if (!mapped.is_valid())
        {
            std::cerr << "Failed to map file " << path << '\n';
            return;
        }

        const std::byte *data = mapped.data();
        const std::size_t size = mapped.size();

        if (!is_elf(data, size))
        {
            std::cout << path << " is not an ELF file.\n";
            return;
        }

        // We know the first 16 bytes (e_ident) are present; check that
        if (size < ELF_IDENT_SIZE)
        {
            std::cerr << "Error: ELF file is too short " << size << " bytes (less than " << ELF_IDENT_SIZE << " bytes).\n";
            return;
        }

        // Read the class and data encoding
        const unsigned char elf_class_byte = static_cast<unsigned char>(data[EI_CLASS]);
        const unsigned char elf_data_byte = static_cast<unsigned char>(data[EI_DATA]);

        // Interpret
        ElfClass elf_class = to_elf_class(elf_class_byte);
        ElfData elf_data = to_elf_data(elf_data_byte);

        // Print basic info
        std::cout << path << " is an ELF file. Size: " << size << " bytes\n";
        std::cout << "  Class: " << elf_class_to_string(elf_class) << '\n';
        std::cout << "  Data Encoding: " << elf_data_to_string(elf_data) << '\n';

        // Continue only if we know class and endianness
        if (elf_class == ElfClass::None || elf_data == ElfData::None)
        {
            std::cerr << "Unsupported ELF class or data encoding.\n";
            return;
        }

        // Offsets in ELF header (64-bit vs 32-bit)
        // e_type: 2 bytes at offset 16
        // e_machine: 2 bytes at offset 18
        // e_version: 4 bytes at offset 20
        // e_entry: 8 bytes (64-bit) or 4 bytes (32-bit) at offset 24
        constexpr std::size_t offset_e_type = 16;
        constexpr std::size_t offset_e_machine = 18;
        constexpr std::size_t offset_e_version = 20;
        constexpr std::size_t offset_e_entry = 24;

        const uint16_t e_type = read_u16(data, offset_e_type, elf_data);
        const uint16_t e_machine = read_u16(data, offset_e_machine, elf_data);
        const uint32_t e_version = read_u32(data, offset_e_version, elf_data);

        uint64_t e_entry = 0;
        if (elf_class == ElfClass::Elf64)
        {
            e_entry = read_u64(data, offset_e_entry, elf_data);
        }
        else
        {
            e_entry = read_u32(data, offset_e_entry, elf_data);
        }

        // Print type
        std::cout << "  Type: " << elf_type_to_string(static_cast<ElfType>(e_type)) << '\n';
        // Print machine
        std::cout << "  Machine: " << elf_machine_to_string(static_cast<ElfMachine>(e_machine)) << '\n';
        std::cout << "  Version: " << e_version << '\n';
        std::cout << "  Entry point: 0x" << std::hex << e_entry << std::dec << '\n';

        // Now read program headers
        ElfSecurityInfo sec_info = check_security_features(data, elf_class, elf_data, e_type);

        // Output security findings
        std::cout << "  Security checks:\n";
        std::cout << "    NX: " << (sec_info.nx_enabled ? "Enabled" : "Disabled") << '\n';
        std::cout << "    PIE: " << (sec_info.pie_enabled ? "Enabled" : "Disabled") << '\n';
        std::cout << "    RELRO: " << (sec_info.relro_full ? "Full" : (sec_info.relro_partial ? "Partial" : "Disabled")) << '\n';
        std::cout << "    Canary: " << (sec_info.canary_enabled ? "Enabled" : "Disabled") << '\n';
    }

} // namespace runtimexray