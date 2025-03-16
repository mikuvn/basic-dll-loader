#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <cwchar>
#include <wchar.h>
#include <tlhelp32.h> // for process snapshot

// function to get the process ID based on the executable name
DWORD GetProcessIDByName(const std::string& processName) {
    PROCESSENTRY32W pe32 = { 0 };  // use wide-character version of PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    if (!Process32FirstW(hProcessSnap, &pe32)) {  // use wide version
        std::cerr << "Error retrieving process info. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        return 0;
    }

    std::wstring wProcessName(processName.begin(), processName.end()); // convert to wide string

    do {
        if (wcscmp(pe32.szExeFile, wProcessName.c_str()) == 0) { // compare wide strings
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32NextW(hProcessSnap, &pe32)); // use wide version

    CloseHandle(hProcessSnap);
    return 0;
}

bool InjectDLL(DWORD processID, const std::string& dllPath) {
    // open the target process with necessary permissions
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Error opening process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // convert DLL path to wide string
    std::wstring wDllPath(dllPath.begin(), dllPath.end());

    // allocate memory in the target process to store the DLL path
    LPVOID allocatedMemory = VirtualAllocEx(hProcess, NULL, (wDllPath.size() + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (allocatedMemory == NULL) {
        std::cerr << "Error allocating memory. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, allocatedMemory, wDllPath.c_str(), (wDllPath.size() + 1) * sizeof(wchar_t), NULL)) {
        std::cerr << "Error writing to process memory. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // get the address of LoadLibraryA for GetProcAddress
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Error getting LoadLibraryW address. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // create a remote thread in the target process to execute LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Error creating remote thread. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // clean up resources
    VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdminGroup;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminGroup)) {
        if (!CheckTokenMembership(NULL, pAdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(pAdminGroup);
    }
    return isAdmin;
}

void RelaunchAsAdmin() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(SHELLEXECUTEINFOW) };
    sei.lpVerb = L"runas";  // use wide string literal
    sei.lpFile = exePath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteExW(&sei)) { // use the wide version
        MessageBoxW(NULL, L"Failed to elevate privileges!", L"Error", MB_OK | MB_ICONERROR);
    }
}

int main() {
    if (!IsRunningAsAdmin()) {
        std::cerr << "The program is NOT running as an administrator!" << std::endl;
        RelaunchAsAdmin();
        return 0;  // exit current instance
    }
    std::cout << "Running with administrator privileges." << std::endl;
    

    std::string executableName;
    std::string dllPath;

    std::cout << "Enter the executable name (e.g., target.exe): ";
    std::cin >> executableName;
    std::cout << "Enter the full path to the DLL to inject: ";
    std::cin >> dllPath;

    // obtain process ID based on the executable name
    DWORD targetProcessID = GetProcessIDByName(executableName);

    if (targetProcessID == 0) {
        std::cerr << "Failed to find process with name: " << executableName << std::endl;
        return 1;
    }

    std::cout << "Found process with ID: " << targetProcessID << std::endl;

    // attempt to inject DLL into the target process
    if (InjectDLL(targetProcessID, dllPath)) {
        std::cout << "DLL injected successfully!" << std::endl;
    } else {
        std::cerr << "Failed to inject DLL." << std::endl;
    }

    system("pause"); // use this so that the terminal doesnt exit and you can read error code and diagnostics.
    return 0;
}
