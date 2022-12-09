#include <Windows.h>
#include <string>
#include <wincrypt.h>
#include <TlHelp32.h>
#include <iostream>

using namespace std;

BOOL caca(int key)
{
    BYTE keyStates[256] = { 0 };
    GetKeyboardState(keyStates);
    return (keyStates[key] & 0x8000) != 0;
}

// Function to inject a DLL into a process
BOOL injectDLL(DWORD procID, const char* dllPath)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (hProc == NULL)
        return FALSE;

    HCRYPTPROV hCryptProv;
    BYTE randomKey[16];
    CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0);
    CryptGenRandom(hCryptProv, sizeof(randomKey), randomKey);
    CryptReleaseContext(hCryptProv, 0);


    DWORD dllPathSize = strlen(dllPath);
    BYTE* encryptedDllPath = (BYTE*)malloc(dllPathSize + 1);
    CryptEncrypt(hCryptProv, 0, true, 0, encryptedDllPath, &dllPathSize, dllPathSize + 1);


    LPVOID memAddr = VirtualAllocEx(hProc, NULL, dllPathSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if (memAddr == NULL)
        return FALSE;


    SIZE_T bytesWritten;
    WriteProcessMemory(hProc, memAddr, (LPVOID)encryptedDllPath, dllPathSize + 1, &bytesWritten);

    LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (loadLibAddr == NULL)
        return FALSE;
    // Create a thread starting at LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, loadLibAddr, memAddr, 0, NULL);
    if (hThread == NULL)
        return FALSE;

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProc, memAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

   
    DWORD oldProtection;
    VirtualProtectEx(hProc, memAddr, dllPathSize + 1, PAGE_EXECUTE_READWRITE, &oldProtection);
    for (int i = 0; i < dllPathSize + 1; i++)
    {
        BYTE randomByte = rand() % 0xFF;
        WriteProcessMemory(hProc, (LPVOID)((DWORD)memAddr + i), &randomByte, sizeof(BYTE), NULL);
    }
    VirtualProtectEx(hProc, memAddr, dllPathSize + 1, oldProtection, NULL);

   
    DWORD kernelID;
    GetWindowThreadProcessId(GetDesktopWindow(), &kernelID);

  
    HANDLE hKernel = OpenProcess(PROCESS_ALL_ACCESS, FALSE, kernelID);
    LPVOID baseAddress = (LPVOID)GetModuleHandleA(NULL);

 
    LPVOID memAddr2 = VirtualAllocEx(hKernel, NULL, dllPathSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if (memAddr2 == NULL)
        return FALSE;


    SIZE_T bytesWritten2;
    WriteProcessMemory(hKernel, memAddr2, (LPVOID)encryptedDllPath, dllPathSize + 1, &bytesWritten2);


    FlushInstructionCache(hKernel, memAddr2, dllPathSize + 1);


    MODULEENTRY32 me;

    CHAR szModule[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, szModule, MAX_PATH, NULL, NULL);
    me.dwSize = sizeof(me);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procID);
    Module32First(hSnapshot, &me);

    do {
        if (strcmp(szModule, "injector.dll") == 0) {
            DWORD oldProtection;
            VirtualProtectEx(hProc, me.modBaseAddr, me.modBaseSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            for (int i = 0; i < me.modBaseSize; i++) {
                BYTE randomByte = rand() % 0xFF;
                WriteProcessMemory(hProc, (LPVOID)((DWORD)me.modBaseAddr + i), &randomByte, sizeof(BYTE), NULL);
            }
            VirtualProtectEx(hProc, me.modBaseAddr, me.modBaseSize, oldProtection, NULL);
        }
    } while (Module32Next(hSnapshot, &me));

    CloseHandle(hSnapshot);
    CloseHandle(hKernel);

   
    LPVOID engineBaseAddr = (LPVOID)GetModuleHandleA("UE5Game-Win64-Shipping.dll");


    LPVOID engineMemAddr = VirtualAllocEx(hProc, NULL, dllPathSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if (engineMemAddr == NULL)
        return FALSE;

    
    SIZE_T bytesWritten3;
    WriteProcessMemory(hProc, engineMemAddr, (LPVOID)encryptedDllPath, dllPathSize + 1, &bytesWritten3);

 
    FlushInstructionCache(hProc, engineMemAddr, dllPathSize + 1);


    LPTHREAD_START_ROUTINE engineLoadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateRemoteThread");
    if (engineLoadLibAddr == NULL)
        return FALSE;

    HANDLE hEngineThread = CreateRemoteThread(hProc, NULL, 0, engineLoadLibAddr, engineMemAddr, 0, NULL);
    if (hEngineThread == NULL)
        return FALSE;


    WaitForSingleObject(hEngineThread, INFINITE);
    VirtualFreeEx(hProc, engineMemAddr, 0, MEM_RELEASE);
    CloseHandle(hEngineThread);
    CloseHandle(hProc);

    return TRUE;
}

int main()
{
    if (caca(VK_F1)) {
        cout << "a";
    }
    DWORD procID = 0;
    HWND hwnd = FindWindowA(NULL, "NAME");
    GetWindowThreadProcessId(hwnd, &procID);

    string dllPath = "C:\\path\\to\\injector.dll";

    // Inject the DLL
    injectDLL(procID, dllPath.c_str());

    cin.ignore();
}