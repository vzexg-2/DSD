#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

// formatting macros
#define OUTPUT(fmt, ...) fprintf(output_file, fmt "\n", ##__VA_ARGS__)
#define DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

// entries
#define MAX_SECTIONS 1024
#define MAX_SYMBOLS 4096
#define MAX_DYNAMIC_SYMBOLS 2048
#define MAX_GOT_ENTRIES 1024
#define MAX_PLT_ENTRIES 1024
#define MAX_ASSEMBLY_LINES 4096
#define MAX_STRING_TABLE_SIZE (1024 * 1024)  // 1MB for string table

/*

Version: 1.d2
Last updated: December 19, 2024, time: 10:08 AM
Discord server: https://discord.gg/JD9K97MJKx
Personal: @sxc_qq1 | vzexg-2 | sunshinexjuhari@protonmail.com
*/

/*


Copyright © 2024 sxc_qq1

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS"
BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing
permissions and limitations under the License.

## Additional Terms

1. **Modification and Redistribution**: You are permitted to modify and redistribute copies of this software, provided that all copies include this license text in its entirety without alteration.

2. **Attribution**: Any redistribution must retain the original copyright notice and provide appropriate credit to the author(s).

3. **No Endorsement**: You may not use the name of sxc_qq or any contributors without prior written permission to endorse or promote products derived from this software.

4. **Limitation of Liability**: In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

By using this software, you acknowledge that you have read and understood this license agreement and agree to be bound by its terms.


*/

typedef struct {
    char name[256];  // name buffer
    uint64_t offset;
    uint64_t address;
    uint64_t size;
    uint32_t type;
    uint32_t flags;
    uint32_t link;
    uint32_t info;
} Section;

typedef struct {
    char name[256];  // name buffer
    uint64_t address;
    uint64_t size;
    uint64_t value;
    uint8_t type;
    uint8_t bind;
    uint16_t section_index;
} Symbol;

typedef struct {
    uint64_t offset;
    uint64_t address;
    uint64_t size;
    char symbol_name[256];
    uint64_t type;
} GOTEntry;

typedef struct {
    uint64_t offset;
    uint64_t address;
    uint64_t size;
    char symbol_name[256];
    uint64_t got_entry_offset;
} PLTEntry;

typedef struct {
    Section sections[MAX_SECTIONS];
    Symbol symbols[MAX_SYMBOLS];
    GOTEntry got_entries[MAX_GOT_ENTRIES];
    PLTEntry plt_entries[MAX_PLT_ENTRIES];
    
    char *string_table;
    size_t string_table_size;
    
    int section_count;
    int symbol_count;
    int got_count;
    int plt_count;
    
    uint64_t got_plt_addr;
    uint64_t plt_addr;
} ELFAnalysis;

// read string from string table
const char* get_string(const char *string_table, size_t string_table_size, uint32_t offset) {
    if (offset >= string_table_size) {
        return "<invalid string>";
    }
    return &string_table[offset];
}

void check_file_open(FILE *file, const char *file_name) {
    if (!file) {
        ERROR("unable to open file %s: %s", file_name, strerror(errno));
        exit(1);
    }
}

void dump_elf_header(FILE *output_file, Elf64_Ehdr *header) {
    OUTPUT("ELF Header Analysis:");
    OUTPUT("  Magic:              %.2x %.2x %.2x %.2x", 
           header->e_ident[EI_MAG0], header->e_ident[EI_MAG1],
           header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    OUTPUT("  Class:              %s", 
           header->e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "ELF32");
    OUTPUT("  Data:               %s",
           header->e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : "2's complement, big endian");
    OUTPUT("  Version:            %d", header->e_ident[EI_VERSION]);
    OUTPUT("  OS/ABI:            %d", header->e_ident[EI_OSABI]);
    OUTPUT("  Type:              0x%x", header->e_type);
    OUTPUT("  Machine:           0x%x", header->e_machine);
    OUTPUT("  Entry Point:       0x%016llx", (unsigned long long)header->e_entry);
    OUTPUT("  Program Headers:   offset 0x%016llx", (unsigned long long)header->e_phoff);
    OUTPUT("  Section Headers:   offset 0x%016llx", (unsigned long long)header->e_shoff);
    OUTPUT("  Flags:             0x%x", header->e_flags);
    OUTPUT("");
}

void analyze_string_table(FILE *elf, Elf64_Shdr *sh_strtab, ELFAnalysis *analysis) {
    analysis->string_table_size = sh_strtab->sh_size;
    analysis->string_table = (char *)malloc(analysis->string_table_size);
    
    if (!analysis->string_table) {
        ERROR("failed : allocate string table");
        exit(1);
    }
    
    fseek(elf, sh_strtab->sh_offset, SEEK_SET);
    fread(analysis->string_table, 1, analysis->string_table_size, elf);
}

void analyze_sections(FILE *elf, Elf64_Ehdr *header, ELFAnalysis *analysis) {
    Elf64_Shdr sections[MAX_SECTIONS];
    fseek(elf, header->e_shoff, SEEK_SET);
    fread(sections, sizeof(Elf64_Shdr), header->e_shnum, elf);
    
    // load string table
    analyze_string_table(elf, &sections[header->e_shstrndx], analysis);
    
    for (int i = 0; i < header->e_shnum && i < MAX_SECTIONS; i++) {
        Section *section = &analysis->sections[i];
        const char *name = get_string(analysis->string_table, analysis->string_table_size, 
                                    sections[i].sh_name);
        
        strncpy(section->name, name, sizeof(section->name) - 1);
        section->address = sections[i].sh_addr;
        section->offset = sections[i].sh_offset;
        section->size = sections[i].sh_size;
        section->type = sections[i].sh_type;
        section->flags = sections[i].sh_flags;
        section->link = sections[i].sh_link;
        section->info = sections[i].sh_info;
        
        // GOT and PLT addresses
        if (strcmp(name, ".got.plt") == 0) {
            analysis->got_plt_addr = sections[i].sh_addr;
        } else if (strcmp(name, ".plt") == 0) {
            analysis->plt_addr = sections[i].sh_addr;
        }
    }
    
    analysis->section_count = header->e_shnum;
}

void dump_section_table(FILE *output_file, ELFAnalysis *analysis) {
    OUTPUT("Section Table:");
    OUTPUT("%-20s %-16s %-16s %-8s %-8s %-8s %-8s", 
           "Name", "Address", "Size", "Type", "Flags", "Link", "Info");
    OUTPUT("--------------------------------------------------------------------------------");
    
    for (int i = 0; i < analysis->section_count; i++) {
        Section *section = &analysis->sections[i];
        OUTPUT("%-20.20s 0x%014llx 0x%-14llx %-8x %-8x %-8x %-8x",
               section->name,
               (unsigned long long)section->address,
               (unsigned long long)section->size,
               section->type,
               section->flags,
               section->link,
               section->info);
    }
    OUTPUT("");
}

void analyze_symbols(FILE *elf, Elf64_Ehdr *header, ELFAnalysis *analysis) {
    Elf64_Shdr sections[MAX_SECTIONS];
    fseek(elf, header->e_shoff, SEEK_SET);
    fread(sections, sizeof(Elf64_Shdr), header->e_shnum, elf);
    
    for (int i = 0; i < header->e_shnum; i++) {
        if (sections[i].sh_type == SHT_SYMTAB || sections[i].sh_type == SHT_DYNSYM) {
            // load associated string table .
            Elf64_Shdr *strtab = &sections[sections[i].sh_link];
            char *symbol_strtab = malloc(strtab->sh_size);
            if (!symbol_strtab) {
                ERROR("failed : allocate symbol string table");
                continue;
            }
            
            fseek(elf, strtab->sh_offset, SEEK_SET);
            fread(symbol_strtab, 1, strtab->sh_size, elf);
            
            // read symbols, <3
            fseek(elf, sections[i].sh_offset, SEEK_SET);
            size_t count = sections[i].sh_size / sizeof(Elf64_Sym);
            Elf64_Sym *symbols = malloc(sections[i].sh_size);
            if (!symbols) {
                ERROR("failed:: allocate symbol table");
                free(symbol_strtab);
                continue;
            }
            
            fread(symbols, sizeof(Elf64_Sym), count, elf);
            
            for (size_t j = 0; j < count && analysis->symbol_count < MAX_SYMBOLS; j++) {
                Symbol *sym = &analysis->symbols[analysis->symbol_count++];
                const char *name = get_string(symbol_strtab, strtab->sh_size, symbols[j].st_name);
                
                strncpy(sym->name, name, sizeof(sym->name) - 1);
                sym->address = symbols[j].st_value;
                sym->size = symbols[j].st_size;
                sym->type = ELF64_ST_TYPE(symbols[j].st_info);
                sym->bind = ELF64_ST_BIND(symbols[j].st_info);
                sym->section_index = symbols[j].st_shndx;
            }
            
            free(symbols);
            free(symbol_strtab);
        }
    }
}

void analyze_dynamic_section(FILE *elf, Elf64_Ehdr *header, ELFAnalysis *analysis) {
    Elf64_Shdr sections[MAX_SECTIONS];
    fseek(elf, header->e_shoff, SEEK_SET);
    fread(sections, sizeof(Elf64_Shdr), header->e_shnum, elf);
    
    for (int i = 0; i < header->e_shnum; i++) {
        if (sections[i].sh_type == SHT_DYNAMIC) {
            fseek(elf, sections[i].sh_offset, SEEK_SET);
            size_t count = sections[i].sh_size / sizeof(Elf64_Dyn);
            Elf64_Dyn *dynamics = malloc(sections[i].sh_size);
            
            if (!dynamics) {
                ERROR("failed : allocate dynamic section");
                continue;
            }
            
            fread(dynamics, sizeof(Elf64_Dyn), count, elf);
            
            // process dynamic entries to find GOT/PLT information
            for (size_t j = 0; j < count; j++) {
                switch (dynamics[j].d_tag) {
                    case DT_PLTGOT:
                        analysis->got_plt_addr = dynamics[j].d_un.d_ptr;
                        break;
                    case DT_PLTRELSZ:
                        // could be used to calculate PLT entry count, up to you if you want to modify it.
                        break;
                }
            }
            
            free(dynamics);
            break;
        }
    }
}

void dump_symbol_table(FILE *output_file, ELFAnalysis *analysis) {
    OUTPUT("Symbol Table:");
    OUTPUT("%-32s %-16s %-8s %-8s %-8s %-8s",
           "Name", "Value", "Size", "Type", "Bind", "Section");
    OUTPUT("--------------------------------------------------------------------------------");
    
    for (int i = 0; i < analysis->symbol_count; i++) {
        Symbol *sym = &analysis->symbols[i];
        OUTPUT("%-32.32s 0x%014llx %-8llu %-8u %-8u %-8u",
               sym->name,
               (unsigned long long)sym->address,
               (unsigned long long)sym->size,
               sym->type,
               sym->bind,
               sym->section_index);
    }
    OUTPUT("");
}

void disassemble_code(FILE *output_file, const char *file_path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), 
             "objdump -d -M intel --no-show-raw-insn --demangle %s", file_path);
    
    FILE *disasm = popen(cmd, "r");
    if (!disasm) {
        ERROR("Failed to run objdump: %s", strerror(errno));
        return;
    }
    
    OUTPUT("Disassembly:");
    OUTPUT("--------------------------------------------------------------------------------");
    
    char line[1024];
    while (fgets(line, sizeof(line), disasm)) {
        OUTPUT("%s", line);
    }
    
    pclose(disasm);
}

void dump_so(const char *file_path) {
    FILE *elf = fopen(file_path, "rb");
    check_file_open(elf, file_path);
    
    char output_path[1024];
    snprintf(output_path, sizeof(output_path), "%s.dump", file_path);
    FILE *output_file = fopen(output_path, "w");
    check_file_open(output_file, output_path);
    
    // verify elf
    unsigned char magic[4];
    fread(magic, 1, 4, elf);
    if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        ERROR("?, Not a valid ELF file");
        fclose(elf);
        fclose(output_file);
        return;
    }
    
    fseek(elf, 0, SEEK_SET);
    Elf64_Ehdr header;
    fread(&header, sizeof(header), 1, elf);
    
    // check file .so
    if (header.e_type != ET_DYN) {
       // ERROR("Warning: File is not a shared object (.so)");
    }
    
    ELFAnalysis analysis = {0};
    
    OUTPUT("Analysis of: %s", file_path);
    OUTPUT("--------------------------------------------------------------------------------");
    OUTPUT("");
    
    dump_elf_header(output_file, &header);
    analyze_sections(elf, &header, &analysis);
    analyze_dynamic_section(elf, &header, &analysis);
    dump_section_table(output_file, &analysis);
    analyze_symbols(elf, &header, &analysis);
    dump_symbol_table(output_file, &analysis);
    
    // disassembly
    OUTPUT("");
    disassemble_code(output_file, file_path);
    
    // cleanup
    if (analysis.string_table) {
        free(analysis.string_table);
    }
    
    fclose(elf);
    fclose(output_file);
    
    printf("dumps completed, file: %s\n", output_path);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        ERROR("%s <shared-object-file>", argv[0]);
        return 1;
    }
    
    // permission, : file existence
    if (access(argv[1], F_OK) == -1) {
        ERROR("File does not exist: %s", argv[1]);
        return 1;
    }
    
    // permission, : read permission
    if (access(argv[1], R_OK) == -1) {
        ERROR("No read permission for file: %s", argv[1]);
        return 1;
    }
    
    dump_so(argv[1]);
    return 0;
}
