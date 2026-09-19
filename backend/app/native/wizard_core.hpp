#ifndef WIZARD_CORE_HPP
#define WIZARD_CORE_HPP

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get native engine version (e.g. 200 for v2.0.0).
 */
int wizard_native_version(void);

/**
 * Fast Shannon entropy calculation (0.0 to 8.0).
 */
double wizard_calculate_entropy(const uint8_t* data, size_t len);

/**
 * Fast sliding-window Shannon entropy curve.
 * @param data Input byte buffer.
 * @param len Total length of data.
 * @param window_size Window size (e.g. 256 or 512).
 * @param step_size Step size (e.g. 64 or 128).
 * @param out_entropy Array to hold output entropy floats.
 * @param max_out Maximum capacity of out_entropy.
 * @return Number of entropy points computed.
 */
int wizard_sliding_window_entropy(
    const uint8_t* data,
    size_t len,
    size_t window_size,
    size_t step_size,
    double* out_entropy,
    size_t max_out
);

/**
 * Fast byte pattern search with wildcards.
 * Pattern format: hex bytes separated by spaces, '??' for wildcard byte.
 * Example: "55 48 89 e5 ?? ?? c3"
 * @return Number of matches found.
 */
int wizard_pattern_scan(
    const uint8_t* data,
    size_t len,
    const char* pattern_hex,
    uint64_t* out_offsets,
    size_t max_out
);

/**
 * Fast ROP (Return-Oriented Programming) gadget finder.
 * Finds gadgets up to max_len ending with ret/syscall/call reg/jmp reg.
 * Writes a JSON string to out_json:
 * [{"address": 4198400, "instructions": "pop rdi ; ret", "bytes": "5f c3", "category": "register_setter", "length": 2}]
 * @return Length of JSON string written, or negative on error.
 */
int wizard_find_rop_gadgets(
    const uint8_t* code,
    size_t code_len,
    uint64_t base_vaddr,
    const char* arch,
    char* out_json,
    size_t max_json_len
);

/**
 * Fast Shellcode and Exploit Heuristics scanner.
 * Detects NOP sleds, syscalls, egg hunters, stack pivots, and decoder stubs.
 * Writes a JSON string to out_json.
 * @return Length of JSON string written, or negative on error.
 */
int wizard_scan_shellcode_heuristics(
    const uint8_t* data,
    size_t len,
    char* out_json,
    size_t max_json_len
);

/**
 * C++ symbol demangler using abi::__cxa_demangle.
 * @param mangled Mangled symbol name (e.g., "_Z3fooi").
 * @param out_buffer Output buffer to receive demangled name.
 * @param out_len Capacity of output buffer.
 * @return 0 on success, non-zero on failure.
 */
int wizard_demangle_symbol(
    const char* mangled,
    char* out_buffer,
    size_t out_len
);

/**
 * Calculate structural similarity coefficient between two byte sequences (0.0 to 1.0).
 */
double wizard_binary_similarity(
    const uint8_t* data1,
    size_t len1,
    const uint8_t* data2,
    size_t len2
);

#ifdef __cplusplus
}
#endif

#endif // WIZARD_CORE_HPP
