# Phrack 40th Anniversary CTF Challenge Solution


# Spoilers Below

# Initial Looks
After opening the driver in binary ninja, i immediately noticed the driver entry allocates a [ListEntry type structure](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry) and stores it in the [DeviceExtension](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/device-extensions) field of the DeviceObject. 

Driver extensions allow developers to store the 'state' of the driver throughout its lifetime. 

<img width="809" height="304" alt="image" src="https://github.com/user-attachments/assets/f23c9146-3ec9-4181-9e91-b51570853b22" />

Also the driver only has a few IOCTLS, the most interesting being the dispatch cleanup and the main ioctl handler.

<img width="520" height="55" alt="image" src="https://github.com/user-attachments/assets/00a7a662-279e-4a8a-8520-960c2c070681" />

# Ioctls
Taking a look at the ioctl handler its what you would expect a simple switch case with each handler.
<img width="591" height="921" alt="image" src="https://github.com/user-attachments/assets/b9cc679c-95f9-4b93-bab8-a49ceceefeb1" />

Peeking at the first one shows that this function takes the user supplied buffer and creates a NODE of some structure type 


consisting of metadata such as the pid of the calling process etc then appends the userdata (our buffer) to that struct and 


adds that as a node to the linked list the linked list being the global driver state
<img width="1363" height="803" alt="image" src="https://github.com/user-attachments/assets/98d1a25e-7540-4de0-a6d7-05a8fce33d7a" />

<img width="744" height="503" alt="image" src="https://github.com/user-attachments/assets/22a5ac44-5deb-4373-b937-e09d32f6d9c2" />

The driver state can now be thought of like this a doubly linked list with some metadata plus the user buffer
```
void* flink
void* blink
struct metadata
void* userbuffer
```
```
[HEAD] -> <- [NODE1] -> <- [NODE2] -> <- [HEAD]
```
The rest of the ioctls are quite interesting there is a function that allows you to read the flag 
into a global kernel buffer that is allocated in the driver entry function 
<img width="1041" height="595" alt="image" src="https://github.com/user-attachments/assets/e24c10e5-3831-4c44-8cd2-897aa2f0105d" />

One that allocates an MDL for a user buffer, allowing us to specify an address in our own userland process space 

that gets mapped into kernel memory. And allows the kernel to read and write to it.

<img width="979" height="568" alt="image" src="https://github.com/user-attachments/assets/16fac13c-735c-414a-8a85-830df7bf2eb8" />

As well as three others, one that reads from the kernel buffer into the mapped user buffer

one that writes from our user buffer to the kernel buffer and one that frees the MDL.
<img width="700" height="500" alt="image" src="https://github.com/user-attachments/assets/06240a3b-2c13-40d8-be07-0144977c680f" />
<img width="644" height="453" alt="image" src="https://github.com/user-attachments/assets/d0d4015e-7e67-4e26-815e-c8adbcc1a8a7" />
<img width="619" height="497" alt="image" src="https://github.com/user-attachments/assets/7b36a1cb-60d2-4a94-8e8b-4c0c02e98908" />



After spending a couple days reversing i was able to come up with this structure for the user's node that is stored.
```
{
LIST_ENTRY* entry
UINT64 PID
UINT64 IsFreed
MDL* Mdl
UINT64 MappedPhysicalPages
UINT64 LengthOfUserData
VOID* UserData
}
```
It all added up but i was not able to actually exploit this functionality in any way.


I was able to map a user buffer and copy data to the kernel buffer but i didnt really have


full control over what was going on. So i took a step back and decided to look at the cleanup function.

# Use After Free
Taking a look at the cleanup function at a glance shows the driver

checking if the calling process matches the pid in the linkedlist then attempts to free the MDL if still valid then performs a check

that removes the node from the linked list. then frees the pool allocation for the whole node but there is a bug in the check.

if the user buffer contains 0x70 then the node will not be removed. But will still be freed giving us a UAF bug.


<img width="707" height="942" alt="image" src="https://github.com/user-attachments/assets/16c181a1-8b51-414f-9e00-9a5cf3b2d79e" />


# Exploitation Thought Process
The current process i was thinking of the perform the exploit was the following

We connect to the driver and allocate a node of size 0xC0

```
[HEAD] -> <- [PID1] -> [HEAD]
```
We can close the handle to the driver triggering the cleanup
```
[HEAD] -> <- [FREE] -> [HEAD]
```
Then we can spray the heap so something we control gets put there

```
[HEAD] -> <- [Something we control] -> [HEAD]
```

Ideally we would be able to fake object the driver expects and keep the same pid


so the driver knows its our node. As well as setting the IsFreed variable to be a value that bypasses this check 
<img width="533" height="39" alt="image" src="https://github.com/user-attachments/assets/87da5bb7-3070-4307-a579-54b8e860480a" />

This would allow us to read the file into the global kernel buffer.

From there we should be able to read that kernel buffer into an address we control using the read ioctl
<img width="666" height="473" alt="image" src="https://github.com/user-attachments/assets/4dd9dc42-0e2f-432e-805c-82dfa65a5f46" />

Below are the values we need to control

```
{
LIST_ENTRY* entry <- flink & blink should point to zero'd buffers so we the driver doesnt free the node again which can crash the system
UINT64 PID <- we need to keep it the same
UINT64 IsFreed <- we need to set it to a value that passes the check
MDL* Mdl
UINT64 MappedPhysicalPages <- we need to set it to a user mode address that we control to see the output of the flag.
UINT64 LengthOfUserData
VOID* UserData
}
```

# Heap Spray
Having never performed a kernel heap exploit, i naturally scoured google for information on the topic and found alot of research done on the subject.

But they all seemed to reference work by [Alex Ionescu](www.alex-ionescu.com/kernel-heap-spraying-like-its-2015-swimming-in-the-big-kids-pool/) where he uses named pipes to spray the heap.
This approach works great because you can control the size of the allocation of the objects. But the problem is it adds a header to the allocation

The first 0x48 bytes consist of the following data
```
{
    LIST_ENTRY QueueEntry;
    ULONG DataEntryType;
    PIRP Irp;
    ULONG QuotaInEntry;
    PSECURITY_CLIENT_CONTEXT ClientSecurityContext;
    ULONG DataSize;
} NP_DATA_QUEUE_ENTRY, *PNP_DATA_QUEUE_ENTRY;

```

Which doesnt work because we need the DataEntryType to be our PID.  So i continued my search attempting to find a spray that fully controls the data.


Eventually i found [this article](https://medium.com/reverence-cyber/cve-2023-36802-mssksrv-sys-local-privilege-escalation-reverence-cyber-d54316eaf118) where robel campbell uses a similar technique


leveraging named pipes but by setting them to be unbuffered named pipes you fully control the data and the size of the allocation.

He also included code showing exactly how to perform the spray. Please Check that article for the full writeup on the technique.

# Exploit

After some trial and error debugging using !pool and !poolused 2 NtFs i got the size of the allocations to match up perfectly 

i was able to get my kernel object to be replaced by data we have full control over.

<img width="618" height="461" alt="image" src="https://github.com/user-attachments/assets/d83028c7-0c96-442c-9365-0dc1fe217f0c" />

Our fake object with correct variables to bypass checks and exfiltrate the flag.
<img width="511" height="182" alt="image" src="https://github.com/user-attachments/assets/092503a1-196b-4054-a15b-554564200371" />

# References
* https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation&ved=2ahUKEwjEoKOV67-PAxVPSjABHeJsJEcQFnoECBcQAQ&usg=AOvVaw2WpS4aLLeq9QtCeg4NUAc-
* https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
* https://wetw0rk.github.io/posts/0x03-approaching-the-modern-windows-kernel-heap/
* www.alex-ionescu.com/kernel-heap-spraying-like-its-2015-swimming-in-the-big-kids-pool/
* https://www.ibm.com/think/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service
* https://github.com/xforcered/PhrackCTF
* https://medium.com/reverence-cyber/cve-2023-36802-mssksrv-sys-local-privilege-escalation-reverence-cyber-d54316eaf11
