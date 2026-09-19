#include "wizard_core.hpp"

#include <cmath>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <algorithm>
#include <cxxabi.h>

extern "C" {

int wizard_native_version(void) {
    return 200; // v2.0.0
}

double wizard_calculate_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return 0.0;
    }

    size_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    double inv_len = 1.0 / static_cast<double>(len);

    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) * inv_len;
            entropy -= p * std::log2(p);
        }
    }

    return std::round(entropy * 10000.0) / 10000.0;
}

int wizard_sliding_window_entropy(
    const uint8_t* data,
    size_t len,
    size_t window_size,
    size_t step_size,
    double* out_entropy,
    size_t max_out
) {
    if (!data || len == 0 || window_size == 0 || step_size == 0 || !out_entropy || max_out == 0) {
        return 0;
    }

    size_t points = 0;
    for (size_t offset = 0; offset + window_size <= len && points < max_out; offset += step_size) {
        out_entropy[points++] = wizard_calculate_entropy(data + offset, window_size);
    }

    // Include last partial chunk if needed and space allows
    if (points < max_out && (len < window_size || (len % step_size != 0 && points == 0))) {
        out_entropy[points++] = wizard_calculate_entropy(data, len);
    }

    return static_cast<int>(points);
}

struct BytePatternToken {
    uint8_t byte_val;
    bool is_wildcard;
};

static std::vector<BytePatternToken> parse_hex_pattern(const char* pattern_hex) {
    std::vector<BytePatternToken> tokens;
    if (!pattern_hex) return tokens;

    std::istringstream stream(pattern_hex);
    std::string token;
    while (stream >> token) {
        if (token == "??" || token == "?") {
            tokens.push_back({0, true});
        } else {
            char* end = nullptr;
            unsigned long val = std::strtoul(token.c_str(), &end, 16);
            if (end != token.c_str()) {
                tokens.push_back({static_cast<uint8_t>(val & 0xFF), false});
            }
        }
    }
    return tokens;
}

int wizard_pattern_scan(
    const uint8_t* data,
    size_t len,
    const char* pattern_hex,
    uint64_t* out_offsets,
    size_t max_out
) {
    if (!data || len == 0 || !pattern_hex || !out_offsets || max_out == 0) {
        return 0;
    }

    std::vector<BytePatternToken> tokens = parse_hex_pattern(pattern_hex);
    if (tokens.empty() || tokens.size() > len) {
        return 0;
    }

    size_t pattern_len = tokens.size();
    size_t match_count = 0;

    for (size_t i = 0; i <= len - pattern_len && match_count < max_out; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; ++j) {
            if (!tokens[j].is_wildcard && data[i + j] != tokens[j].byte_val) {
                match = false;
                break;
            }
        }
        if (match) {
            out_offsets[match_count++] = static_cast<uint64_t>(i);
        }
    }

    return static_cast<int>(match_count);
}

// ---------------------------------------------------------------------------
// ROP Gadget Finder
// ---------------------------------------------------------------------------

struct DisasmRule {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask; // 0xFF = exact match, 0x00 = wildcard
    std::string mnemonic;
    std::string category;
};

static std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (static_cast<unsigned char>(c) <= 0x1f) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
        } else {
            o << c;
        }
    }
    return o.str();
}

static const char* categorize_gadget(const std::string& disasm) {
    if (disasm.find("syscall") != std::string::npos || disasm.find("int 0x80") != std::string::npos || disasm.find("svc") != std::string::npos) {
        return "syscall";
    }
    if (disasm.find("leave") != std::string::npos || disasm.find("xchg rsp") != std::string::npos || disasm.find("xchg esp") != std::string::npos || disasm.find("mov rsp") != std::string::npos || disasm.find("mov esp") != std::string::npos) {
        return "stack_pivot";
    }
    if (disasm.find("pop") != std::string::npos || disasm.find("mov") != std::string::npos) {
        return "register_setter";
    }
    if (disasm.find("call") != std::string::npos || disasm.find("jmp") != std::string::npos) {
        return "control_flow";
    }
    if (disasm.find("xor") != std::string::npos || disasm.find("add") != std::string::npos || disasm.find("sub") != std::string::npos || disasm.find("inc") != std::string::npos || disasm.find("dec") != std::string::npos) {
        return "arithmetic_logic";
    }
    return "general";
}

int wizard_find_rop_gadgets(
    const uint8_t* code,
    size_t code_len,
    uint64_t base_vaddr,
    const char* arch,
    char* out_json,
    size_t max_json_len
) {
    if (!code || code_len == 0 || !out_json || max_json_len < 10) {
        if (out_json && max_json_len >= 3) {
            std::strcpy(out_json, "[]");
        }
        return 0;
    }

    bool is_x64 = true;
    if (arch && (std::strcmp(arch, "x86") == 0 || std::strcmp(arch, "i386") == 0 || std::strcmp(arch, "i686") == 0)) {
        is_x64 = false;
    }

    // Map of common x86/x64 instruction prefixes ending in RET (0xC3)
    struct OpInfo {
        std::vector<uint8_t> opcodes;
        std::string text;
    };

    std::vector<OpInfo> prefix_ops;
    if (!is_x64) {
        prefix_ops = {
            {{0x58}, "pop eax"},
            {{0x59}, "pop ecx"},
            {{0x5a}, "pop edx"},
            {{0x5b}, "pop ebx"},
            {{0x5e}, "pop esi"},
            {{0x5f}, "pop edi"},
            {{0x5d}, "pop ebp"},
            {{0x5f, 0x5e}, "pop edi ; pop esi"},
            {{0xc9}, "leave"},
            {{0x31, 0xc0}, "xor eax, eax"},
            {{0x31, 0xdb}, "xor ebx, ebx"},
            {{0x31, 0xc9}, "xor ecx, ecx"},
            {{0x31, 0xd2}, "xor edx, edx"},
            {{0x90}, "nop"}
        };
    } else {
        prefix_ops = {
            // x86_64 64-bit pops
        {{0x5f}, "pop rdi"},
        {{0x5e}, "pop rsi"},
        {{0x5a}, "pop rdx"},
        {{0x58}, "pop rax"},
        {{0x59}, "pop rcx"},
        {{0x5b}, "pop rbx"},
        {{0x5d}, "pop rbp"},
        {{0x41, 0x58}, "pop r8"},
        {{0x41, 0x59}, "pop r9"},
        {{0x41, 0x5a}, "pop r10"},
        {{0x41, 0x5b}, "pop r11"},
        {{0x41, 0x5c}, "pop r12"},
        {{0x41, 0x5d}, "pop r13"},
        {{0x41, 0x5e}, "pop r14"},
        {{0x41, 0x5f}, "pop r15"},
        // x86_64 multi-pops
        {{0x5f, 0x5e}, "pop rdi ; pop rsi"},
        {{0x5e, 0x5a}, "pop rsi ; pop rdx"},
        {{0x58, 0x5f}, "pop rax ; pop rdi"},
        // Stack pivots
        {{0xc9}, "leave"},
        {{0x48, 0x87, 0xe0}, "xchg rsp, rax"},
        {{0x48, 0x89, 0xe0}, "mov rax, rsp"},
        {{0x48, 0x89, 0xc4}, "mov rsp, rax"},
        {{0x94}, "xchg esp, eax"},
        // Arithmetic / clears
        {{0x48, 0x31, 0xc0}, "xor rax, rax"},
        {{0x48, 0x31, 0xff}, "xor rdi, rdi"},
        {{0x48, 0x31, 0xf6}, "xor rsi, rsi"},
        {{0x48, 0x31, 0xd2}, "xor rdx, rdx"},
        {{0x31, 0xc0}, "xor eax, eax"},
        {{0x31, 0xff}, "xor edi, edi"},
        {{0x31, 0xf6}, "xor esi, esi"},
        {{0x31, 0xd2}, "xor edx, edx"},
        // Syscalls
        {{0x0f, 0x05}, "syscall"},
        {{0xcd, 0x80}, "int 0x80"},
        {{0x0f, 0x34}, "sysenter"},
        // Memory / movs
        {{0x48, 0x8b, 0x07}, "mov rax, qword ptr [rdi]"},
        {{0x48, 0x89, 0x07}, "mov qword ptr [rdi], rax"},
        {{0x8b, 0x07}, "mov eax, dword ptr [rdi]"},
        {{0x89, 0x07}, "mov dword ptr [rdi], eax"},
        {{0x90}, "nop"},
    };
    }

    struct FoundGadget {
        uint64_t address;
        std::string instructions;
        std::string hex_bytes;
        std::string category;
        int length;
    };

    std::vector<FoundGadget> gadgets;
    std::unordered_map<std::string, bool> seen_gadgets;

    // Scan for 0xC3 (RET)
    for (size_t i = 0; i < code_len; ++i) {
        // Direct RET
        if (code[i] == 0xC3) {
            uint64_t ret_addr = base_vaddr + i;
            if (seen_gadgets.find("ret") == seen_gadgets.end()) {
                seen_gadgets["ret"] = true;
                gadgets.push_back({ret_addr, "ret", "c3", "control_flow", 1});
            }

            // Check prefixes ending right before this 0xC3
            for (const auto& p : prefix_ops) {
                size_t p_len = p.opcodes.size();
                if (i >= p_len) {
                    bool match = true;
                    for (size_t k = 0; k < p_len; ++k) {
                        if (code[i - p_len + k] != p.opcodes[k]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        uint64_t g_addr = base_vaddr + (i - p_len);
                        std::string instr = p.text + " ; ret";
                        if (seen_gadgets.find(instr) == seen_gadgets.end()) {
                            seen_gadgets[instr] = true;
                            std::ostringstream hex_s;
                            for (size_t k = 0; k < p_len; ++k) {
                                hex_s << std::hex << std::setw(2) << std::setfill('0') << (int)p.opcodes[k] << " ";
                            }
                            hex_s << "c3";
                            gadgets.push_back({
                                g_addr,
                                instr,
                                hex_s.str(),
                                categorize_gadget(instr),
                                static_cast<int>(p_len + 1)
                            });
                        }
                    }
                }
            }
        }

        // Direct SYSCALL (0x0F 0x05)
        if (i + 1 < code_len && code[i] == 0x0F && code[i + 1] == 0x05) {
            uint64_t sys_addr = base_vaddr + i;
            std::string instr = "syscall";
            if (seen_gadgets.find(instr) == seen_gadgets.end()) {
                seen_gadgets[instr] = true;
                gadgets.push_back({sys_addr, "syscall", "0f 05", "syscall", 2});
            }
        }

        // Direct INT 0x80 (0xCD 0x80)
        if (i + 1 < code_len && code[i] == 0xCD && code[i + 1] == 0x80) {
            uint64_t int_addr = base_vaddr + i;
            std::string instr = "int 0x80";
            if (seen_gadgets.find(instr) == seen_gadgets.end()) {
                seen_gadgets[instr] = true;
                gadgets.push_back({int_addr, "int 0x80", "cd 80", "syscall", 2});
            }
        }

        // ARM64 SVC #0 (0x01 0x00 0x00 0xD4)
        if (i + 3 < code_len && code[i] == 0x01 && code[i+1] == 0x00 && code[i+2] == 0x00 && code[i+3] == 0xD4) {
            uint64_t arm_addr = base_vaddr + i;
            std::string instr = "svc #0";
            if (seen_gadgets.find(instr) == seen_gadgets.end()) {
                seen_gadgets[instr] = true;
                gadgets.push_back({arm_addr, "svc #0", "01 00 00 d4", "syscall", 4});
            }
        }
    }

    // Serialize to JSON
    std::ostringstream json_out;
    json_out << "[";
    for (size_t idx = 0; idx < gadgets.size(); ++idx) {
        const auto& g = gadgets[idx];
        if (idx > 0) json_out << ",";
        json_out << "{\"address\":" << g.address
                 << ",\"instructions\":\"" << escape_json(g.instructions) << "\""
                 << ",\"bytes\":\"" << escape_json(g.hex_bytes) << "\""
                 << ",\"category\":\"" << escape_json(g.category) << "\""
                 << ",\"length\":" << g.length << "}";
    }
    json_out << "]";

    std::string result_str = json_out.str();
    if (result_str.size() >= max_json_len) {
        // Output buffer too small, truncate safely to empty json or error
        if (max_json_len >= 3) {
            std::strcpy(out_json, "[]");
        }
        return -1;
    }

    std::strcpy(out_json, result_str.c_str());
    return static_cast<int>(result_str.size());
}

// ---------------------------------------------------------------------------
// Shellcode & Exploit Heuristics Scanner
// ---------------------------------------------------------------------------

int wizard_scan_shellcode_heuristics(
    const uint8_t* data,
    size_t len,
    char* out_json,
    size_t max_json_len
) {
    if (!data || len == 0 || !out_json || max_json_len < 10) {
        if (out_json && max_json_len >= 3) {
            std::strcpy(out_json, "[]");
        }
        return 0;
    }

    struct HeuristicHit {
        std::string type;
        size_t offset;
        std::string confidence;
        std::string description;
        std::string evidence;
    };

    std::vector<HeuristicHit> hits;

    // 1. NOP Sled Detection (16 or more consecutive 0x90 bytes)
    size_t nop_count = 0;
    size_t nop_start = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] == 0x90) {
            if (nop_count == 0) nop_start = i;
            nop_count++;
        } else {
            if (nop_count >= 16) {
                hits.push_back({
                    "nop_sled",
                    nop_start,
                    nop_count > 64 ? "high" : "medium",
                    "Detected consecutive NOP (0x90) sled sequence often used in exploit landing pads.",
                    "Consecutive NOP count: " + std::to_string(nop_count)
                });
            }
            nop_count = 0;
        }
    }
    if (nop_count >= 16) {
        hits.push_back({
            "nop_sled",
            nop_start,
            nop_count > 64 ? "high" : "medium",
            "Detected consecutive NOP (0x90) sled sequence often used in exploit landing pads.",
            "Consecutive NOP count: " + std::to_string(nop_count)
        });
    }

    // 2. Syscall Patterns (x86_64, x86, AArch64)
    for (size_t i = 0; i + 1 < len; ++i) {
        if (data[i] == 0x0F && data[i+1] == 0x05) {
            hits.push_back({
                "raw_syscall_x64",
                i,
                "medium",
                "Direct x86_64 syscall instruction found in byte stream.",
                "0f 05 (syscall)"
            });
            if (hits.size() > 100) break;
        } else if (data[i] == 0xCD && data[i+1] == 0x80) {
            hits.push_back({
                "raw_syscall_x86",
                i,
                "medium",
                "Direct x86 legacy int 0x80 interrupt found in byte stream.",
                "cd 80 (int 0x80)"
            });
            if (hits.size() > 100) break;
        }
    }

    // 3. Egg Hunter Heuristics (Repeated 4-byte signature search)
    // Common pattern: 8-byte consecutive tag search like 'w00t' or 'egg!'
    for (size_t i = 0; i + 8 <= len; ++i) {
        if (data[i] == data[i+4] && data[i+1] == data[i+5] &&
            data[i+2] == data[i+6] && data[i+3] == data[i+7]) {
            // Check if ASCII printable tag
            bool printable = true;
            for (int k = 0; k < 4; ++k) {
                if (data[i+k] < 0x20 || data[i+k] > 0x7E) {
                    printable = false;
                    break;
                }
            }
            if (printable && data[i] != data[i+1]) { // ignore "AAAA"
                char tag[5] = { (char)data[i], (char)data[i+1], (char)data[i+2], (char)data[i+3], '\0' };
                hits.push_back({
                    "egg_hunter_tag",
                    i,
                    "medium",
                    "Repeated 4-byte signature tag pattern characteristic of egg hunters.",
                    std::string("Tag: ") + tag + tag
                });
                if (hits.size() > 100) break;
            }
        }
    }

    // 4. Polymorphic XOR Decoder Stub Heuristics
    // Typical pattern: loop with jmp/call pop, xor byte ptr, loop/jnz
    for (size_t i = 0; i + 10 <= len; ++i) {
        // Look for common x86 decoder patterns: e.g. 0xEB short jmp followed by call/pop
        if (data[i] == 0xeb && (data[i+2] == 0xe8 || data[i+1] < 0x20)) {
            hits.push_back({
                "polymorphic_decoder_stub",
                i,
                "low",
                "Potential polymorphic shellcode decoder loop detected.",
                "Short jump + call/pop sequence"
            });
            if (hits.size() > 100) break;
        }
    }

    // JSON format
    std::ostringstream json_out;
    json_out << "[";
    for (size_t idx = 0; idx < hits.size(); ++idx) {
        const auto& h = hits[idx];
        if (idx > 0) json_out << ",";
        json_out << "{\"type\":\"" << escape_json(h.type) << "\""
                 << ",\"offset\":" << h.offset
                 << ",\"confidence\":\"" << escape_json(h.confidence) << "\""
                 << ",\"description\":\"" << escape_json(h.description) << "\""
                 << ",\"evidence\":\"" << escape_json(h.evidence) << "\"}";
    }
    json_out << "]";

    std::string result_str = json_out.str();
    if (result_str.size() >= max_json_len) {
        if (max_json_len >= 3) std::strcpy(out_json, "[]");
        return -1;
    }

    std::strcpy(out_json, result_str.c_str());
    return static_cast<int>(result_str.size());
}

// ---------------------------------------------------------------------------
// C++ Demangler
// ---------------------------------------------------------------------------

int wizard_demangle_symbol(
    const char* mangled,
    char* out_buffer,
    size_t out_len
) {
    if (!mangled || !out_buffer || out_len == 0) {
        return -1;
    }

    int status = -1;
    char* demangled = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
    if (status == 0 && demangled) {
        std::strncpy(out_buffer, demangled, out_len - 1);
        out_buffer[out_len - 1] = '\0';
        std::free(demangled);
        return 0;
    }

    if (demangled) {
        std::free(demangled);
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Binary Similarity (Structural / Chunk Matching)
// ---------------------------------------------------------------------------

double wizard_binary_similarity(
    const uint8_t* data1,
    size_t len1,
    const uint8_t* data2,
    size_t len2
) {
    if (!data1 || !data2 || len1 == 0 || len2 == 0) {
        return 0.0;
    }

    if (len1 == len2 && std::memcmp(data1, data2, len1) == 0) {
        return 1.0;
    }

    // Rolling chunk hash matching (chunk size 32 bytes)
    const size_t chunk_size = 32;
    if (len1 < chunk_size || len2 < chunk_size) {
        // For very small files, compare byte-by-byte
        size_t min_len = std::min(len1, len2);
        size_t max_len = std::max(len1, len2);
        size_t same = 0;
        for (size_t i = 0; i < min_len; ++i) {
            if (data1[i] == data2[i]) same++;
        }
        return static_cast<double>(same) / static_cast<double>(max_len);
    }

    std::unordered_map<uint32_t, int> chunks1;
    for (size_t i = 0; i + chunk_size <= len1; i += chunk_size) {
        uint32_t hash = 5381;
        for (size_t k = 0; k < chunk_size; ++k) {
            hash = ((hash << 5) + hash) + data1[i + k];
        }
        chunks1[hash]++;
    }

    size_t total_chunks2 = 0;
    size_t matches = 0;
    for (size_t i = 0; i + chunk_size <= len2; i += chunk_size) {
        total_chunks2++;
        uint32_t hash = 5381;
        for (size_t k = 0; k < chunk_size; ++k) {
            hash = ((hash << 5) + hash) + data2[i + k];
        }
        auto it = chunks1.find(hash);
        if (it != chunks1.end() && it->second > 0) {
            matches++;
            it->second--;
        }
    }

    size_t total_chunks1 = len1 / chunk_size;
    double score = (2.0 * static_cast<double>(matches)) / static_cast<double>(total_chunks1 + total_chunks2);
    return std::round(score * 10000.0) / 10000.0;
}

} // extern "C"
