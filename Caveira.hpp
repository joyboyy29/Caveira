#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstddef>
#include <string_view>

namespace Caveira {

    #define GET_CONTAINER(ptr, type, member) \
        (reinterpret_cast<type*>(reinterpret_cast<char*>(ptr) - offsetof(type, member)))

    // --- Data Structures ---

    struct String64 {
        USHORT length;
        USHORT maximum_length;
        ULONGLONG buffer;
    };

    // only essential ones added
    struct PEB64 {
        UCHAR inherited_address_space;
        UCHAR read_image_file_exec_options;
        UCHAR being_debugged;
        union {
            UCHAR bit_field;
            struct {
                UCHAR image_uses_large_pages : 1;
                UCHAR is_protected_process : 1;
                UCHAR is_image_dynamically_relocated : 1;
                UCHAR skip_patching_user32_forwarders : 1;
                UCHAR is_packaged_process : 1;
                UCHAR is_app_container : 1;
                UCHAR is_protected_process_light : 1;
                UCHAR is_long_path_aware_process : 1;
            };
        };
        UCHAR padding0[4];
        ULONGLONG mutant;
        ULONGLONG image_base_address;
        PPEB_LDR_DATA ldr;
        // ...
    };

    struct RTL_BALANCED_NODE {
        RTL_BALANCED_NODE* children[2];
        union {
            struct {
                UCHAR red : 1;
                UCHAR balance : 2;
            };
            ULONGLONG parent_value;
        };
    };

    struct LdrDataTableEntry {
        LIST_ENTRY in_load_order_links;
        LIST_ENTRY in_memory_order_links;
        LIST_ENTRY in_initialization_order_links;
        void* dll_base;
        void* entry_point;
        ULONG size_of_image;
        UNICODE_STRING full_dll_name;
        UNICODE_STRING base_dll_name;
        // ...
    };

    // --- Compile-Time Randomization Utilities ---
    // pseudorandom seed
    #define CT_RANDOM_SEED \
        (unsigned)(__TIME__[7] - '0' + __TIME__[6] - '0' + __TIME__[4] - '0' + \
                   __TIME__[3] - '0' + __TIME__[1] - '0' + __TIME__[0] - '0' + \
                   __FILE__[sizeof(__FILE__) - 1] - '0' + (__LINE__ % 100) + __COUNTER__ + (7 * __COUNTER__))
    #define CT_RANDOM_NUMBER \
        (unsigned)((((__TIME__[6] - '0') * 10 + (7 * __COUNTER__)) + (__TIME__[7] - '0')) % 10) * __COUNTER__

    template <unsigned N, unsigned Seed>
    struct RandomGenerator {
        static constexpr unsigned value = (1103515245u * RandomGenerator<N - 1, Seed>::value + 12345u) % 0x80000000u;
    };

    template <unsigned Seed>
    struct RandomGenerator<0, Seed> {
        static constexpr unsigned value = Seed;
    };

    __forceinline consteval unsigned generate_seed() {
        return RandomGenerator<CT_RANDOM_NUMBER, CT_RANDOM_SEED>::value;
    }

    // --- Compile-Time Hash Function ---
    template <uint64_t Seed>
    struct CompileTimeHash {

        static constexpr uint32_t to_upper(char c) {
            return (c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c;
        }

        // 33 multiplicative recursive hash
        static constexpr uint64_t hash(const char* str, uint32_t index = 0) {
            return (str[index] == '\0')
                ? Seed
                : (hash(str, index + 1) * 33u) ^ to_upper(str[index]);
        }
    };

    template <uint64_t Seed>
    __forceinline LPVOID parse_export_table(uintptr_t module_base, uint64_t target_hash) {
        auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
        auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);
        auto& export_dir_data = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (!export_dir_data.VirtualAddress)
            return nullptr;

        auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + export_dir_data.VirtualAddress);
        auto function_array = reinterpret_cast<uint32_t*>(module_base + export_dir->AddressOfFunctions);
        auto name_array = reinterpret_cast<uint32_t*>(module_base + export_dir->AddressOfNames);
        auto ordinal_array = reinterpret_cast<uint16_t*>(module_base + export_dir->AddressOfNameOrdinals);

        for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
            const char* func_name = reinterpret_cast<const char*>(module_base + name_array[i]);
            if (CompileTimeHash<Seed>::hash(func_name) == target_hash)
                return reinterpret_cast<LPVOID>(module_base + function_array[ordinal_array[i]]);
        }
        return nullptr;
    }

    // --- Import Resolver ---
    template <uint64_t Seed>
    class ImportResolver {
    public:
        __forceinline static uintptr_t resolve_import(uint64_t target_hash) {
            PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));
            LIST_ENTRY* module_list = &peb->ldr->InMemoryOrderModuleList;

            for (LIST_ENTRY* entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
                auto ldr_entry = GET_CONTAINER(entry, LdrDataTableEntry, in_memory_order_links);
                auto base = reinterpret_cast<uint64_t>(ldr_entry->dll_base);
                auto result = parse_export_table<Seed>(base, target_hash);
                if (result)
                    return (uintptr_t)result;
            }
            return 0;
        }
    };

    __forceinline uintptr_t get_module_by_name(std::wstring_view target_name);

    template <uint64_t Seed>
    __forceinline uintptr_t get_export_by_hash(uintptr_t module_base, uint64_t hash) {
        return reinterpret_cast<uintptr_t>(parse_export_table<Seed>(module_base, hash));
    }

    // --- Macro Helpers ---
    #define CAVEIRA_HASH(func_str, seed) ([]() consteval -> uint64_t { \
        return Caveira::CompileTimeHash<seed>::hash(func_str); \
    }())

    #define CAVEIRA_IMPORT(func) ([]() -> decltype(&func) { \
        constexpr auto seed = Caveira::generate_seed(); \
        constexpr auto hash_val = Caveira::CompileTimeHash<seed>::hash(#func); \
        return reinterpret_cast<decltype(&func)>(Caveira::ImportResolver<seed>::resolve_import(hash_val)); \
    }())

    #define CAVEIRA_IMPORT_NAME(func_str) ([]() -> uintptr_t { \
        constexpr auto seed = Caveira::generate_seed(); \
        constexpr auto hash_val = Caveira::CompileTimeHash<seed>::hash(func_str); \
        return Caveira::ImportResolver<seed>::resolve_import(hash_val); \
    }())

    #define CAVEIRA_IMPORT_FROM(dll_name, func_str) ([]() -> uintptr_t { \
        constexpr auto seed = Caveira::generate_seed(); \
        constexpr auto hash_val = Caveira::CompileTimeHash<seed>::hash(func_str); \
        uintptr_t mod = Caveira::get_module_by_name(L ## dll_name); \
        return Caveira::get_export_by_hash<seed>(mod, hash_val); \
    }())

    __forceinline uintptr_t get_module_by_name(std::wstring_view target_name) {
        PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));
        LIST_ENTRY* module_list = &peb->ldr->InMemoryOrderModuleList;

        for (LIST_ENTRY* entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
            auto ldr_entry = GET_CONTAINER(entry, LdrDataTableEntry, in_memory_order_links);
            std::wstring_view mod_name(
                ldr_entry->base_dll_name.Buffer,
                ldr_entry->base_dll_name.Length / sizeof(wchar_t)
            );
            if (_wcsnicmp(mod_name.data(), target_name.data(), target_name.length()) == 0)
                return reinterpret_cast<uintptr_t>(ldr_entry->dll_base);
        }
        return 0;
    }

}
