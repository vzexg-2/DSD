#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_SECTIONS 256
#define MAX_SYMBOLS 1024
#define MAX_STRINGS 2056
#define MAX_RELOCATIONS 512
#define MAX_DYNAMIC_ENTRIES 256
#define MAX_BUFFER_SIZE 8192

// Enum, section types
typedef enum {
    SECTION_HEADER,
    SECTION_DISASSEMBLY,
    SECTION_STRINGS,
    SECTION_SYMBOLS,
    SECTION_RELOCATIONS,
    SECTION_DYNAMIC
} SectionType;

// Struct, symbol entry
typedef struct {
    char name[128];
    unsigned long address;
    char type;
    bool is_global;
} SymbolEntry;

// Struct, relocation entry
typedef struct {
    char symbol[128];
    unsigned long offset;
    unsigned long info;
    char type[32];
} RelocationEntry;

// Struct, dynamic entry
typedef struct {
    char tag[64];
    unsigned long value;
} DynamicEntry;

// Main SO
typedef struct {
    char filename[256];
    
    // Header section
    struct {
        char elf_class[16];
        char data_encoding[16];
        char version[16];
        char os_abi[32];
        unsigned long entry_point;
        unsigned long program_header_offset;
    } header;

    // Sections
    struct {
        SectionType type;
        char raw_data[MAX_BUFFER_SIZE];
    } sections[MAX_SECTIONS];
    int section_count;

    // Extracted information
    struct {
        SymbolEntry symbols[MAX_SYMBOLS];
        int symbol_count;

        char extracted_strings[MAX_STRINGS][128];
        int string_count;

        RelocationEntry relocations[MAX_RELOCATIONS];
        int relocation_count;

        DynamicEntry dynamic_entries[MAX_DYNAMIC_ENTRIES];
        int dynamic_entry_count;
    } analysis;
} SharedObjectAnalysis;

// Function prototypes
SharedObjectAnalysis* shared_object(const char* so_file);
void free_analysis(SharedObjectAnalysis* analysis);
void prn_analysis(const SharedObjectAnalysis* analysis);

// Utility function to run shell commands and capture output
char* run_command_capture(const char* cmd) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return NULL;

    static char buffer[MAX_BUFFER_SIZE];
    char* result = fgets(buffer, sizeof(buffer), pipe);
    pclose(pipe);

    return result ? buffer : NULL;
}

// header information
void populate_header_info(SharedObjectAnalysis* analysis, const char* so_file) {
    char cmd[MAX_BUFFER_SIZE];
    snprintf(cmd, sizeof(cmd), "readelf -h %s", so_file);
    
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return;

    char line[256];
    while (fgets(line, sizeof(line), pipe)) {
        if (strstr(line, "Class:")) 
            sscanf(line, "  Class: %s", analysis->header.elf_class);
        else if (strstr(line, "Data:")) 
            sscanf(line, "  Data: %s", analysis->header.data_encoding);
        else if (strstr(line, "Version:")) 
            sscanf(line, "  Version: %s", analysis->header.version);
        else if (strstr(line, "OS/ABI:")) 
            sscanf(line, "  OS/ABI: %[^\n]", analysis->header.os_abi);
        else if (strstr(line, "Entry point address:")) 
            sscanf(line, "  Entry point address: %lx", &analysis->header.entry_point);
    }
    pclose(pipe);
}

// nm command
void populate_symbols(SharedObjectAnalysis* analysis, const char* so_file) {
    char cmd[MAX_BUFFER_SIZE];
    snprintf(cmd, sizeof(cmd), "nm -n %s | grep ' T '", so_file);
    
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return;

    char line[256];
    while (fgets(line, sizeof(line), pipe) && analysis->analysis.symbol_count < MAX_SYMBOLS) {
        SymbolEntry* symbol = &analysis->analysis.symbols[analysis->analysis.symbol_count];
        sscanf(line, "%lx %c %[^\n]", 
               &symbol->address, 
               &symbol->type, 
               symbol->name);
        symbol->is_global = (symbol->type >= 'A' && symbol->type <= 'Z');
        analysis->analysis.symbol_count++;
    }
    pclose(pipe);
}

// shared object, return analysis structure
SharedObjectAnalysis* shared_object(const char* so_file) {
    SharedObjectAnalysis* analysis = calloc(1, sizeof(SharedObjectAnalysis));
    strncpy(analysis->filename, so_file, sizeof(analysis->filename) - 1);

    populate_header_info(analysis, so_file);
    populate_symbols(analysis, so_file);

    return analysis;
}

// analysis structure
void free_analysis(SharedObjectAnalysis* analysis) {
    if (analysis) free(analysis);
}

void prn_analysis(const SharedObjectAnalysis* analysis) {
    printf("Shared Object Analysis: %s\n", analysis->filename);
    
    printf("Header Information:\n");
    printf("  ELF Class: %s\n", analysis->header.elf_class);
    printf("  Data Encoding: %s\n", analysis->header.data_encoding);
    printf("  Version: %s\n", analysis->header.version);
    printf("  OS/ABI: %s\n", analysis->header.os_abi);
    printf("  Entry Point: 0x%lx\n", analysis->header.entry_point);

    printf("\nSymbols (%d):\n", analysis->analysis.symbol_count);
    for (int i = 0; i < analysis->analysis.symbol_count; i++) {
        printf("  %lx %c %s (%s)\n", 
               analysis->analysis.symbols[i].address,
               analysis->analysis.symbols[i].type,
               analysis->analysis.symbols[i].name,
               analysis->analysis.symbols[i].is_global ? "Global" : "Local");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("%s <input.so>\n", argv[0]);
        return 1;
    }

    SharedObjectAnalysis* so_analysis = shared_object(argv[1]);
    prn_analysis(so_analysis);
    
    free_analysis(so_analysis);
    return 0;
}
