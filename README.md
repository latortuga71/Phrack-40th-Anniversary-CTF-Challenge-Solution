# Phrack 40th Anniversary CTF Challenge Solution


# Spoilers Below

# Intro

# Using Binary ninja
After opening the driver in binary ninja, i immediately noticed the driver entry allocates a [ListEntry type structure](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry) and stores it in the [DeviceExtension](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/device-extensions) field of the DeviceObject. 

Driver extensions allow developers to store the 'state' of the driver throughout its lifetime. 

<img width="809" height="304" alt="image" src="https://github.com/user-attachments/assets/f23c9146-3ec9-4181-9e91-b51570853b22" />

Also the driver only has a few IOCTLS, the most interesting being the dispatch cleanup and the main ioctl handler.

<img width="520" height="55" alt="image" src="https://github.com/user-attachments/assets/00a7a662-279e-4a8a-8520-960c2c070681" />

# IOCTLS

# Noticing odd things
IOCTLS (read file, gFileBuffer etc)
Driver Extension etc.
Structure of linked list etc
Notice that theres a check that allows us to read the file. into our bufffer.

# UAF
confirmed the UAF

# exploiting by spraying
spray
read file

# got flag, thoughts on kaslr windows 11 etc.



----- preliminary notes start -----
# first thing i did

I decided to use binary ninja to reverse the driver,
because ive had good results with it in the past.

i immediately took a look at the driver entry point and immediately
notices a couple things. 

it allocates a buffer to a global variable from the non paged pool
(screenshot of the global variable here)

the device object accesses the driver extension offset and seems to initialize a LIST_ENTRY type

further investigating the driver extension via documentation 
it seems to be used to hold driver state throughout the lifetime of the driver

i kept this in mind while reviewing the ioctls 
pivoting to the IOCTLS one by one they started to paint a picture

the first one in the switch statement takes a user provided length
and allocates a structure from the non paged pool and initializes some
variables then it appends it to the LIST_ENTRY variable taken from the driver extension pointer
(screenshot here)

at this point its safe to say the driverextension is the LIST HEAD
and contains LIST_ENTRYS to the processes that connect to it

basically

HEAD -> PID1 -> PID2 -> PID3

the driver allocates a node in the list per PROCESS ID and sets some values

using binary ninja i created a struct that looked like this and it seemed to make sense


struct DeviceExtensionHdr __packed
{
    LIST_ENTRY entry;
    UINT64 pid;
    UINT64 zeroIfFree;
    MDL* MdlBuffer;
    UINT64 MappedPagesAddr;
    UINT64 length;
    UINT64 UserBuffer;
};

the most important variables are pid, zeroifFree,MdlBuffer,and MappedPagesAddr (all names i made up btw)
(was able to deduce this after looking through all the ioctls including the next one)

this next ioctl checks to see if the calling process has an MDL associated with it. if not it will allocate one controlled by the user and map the pages into kernel space.
(screenshot)
1400011c4            else if (*(uint32_t*)(*(uint64_t*)((char*)Irp->Tail + 0x40) + 0x10) >= 0x10)
1400011db            {
1400011ff                MDL* UserControlledMdl;
1400011ff                UserControlledMdl = IoAllocateMdl(*(uint64_t*)Irp->AssociatedIrp, 0x1000, 0, 0, nullptr);
1400011ff                
14000120b                if (UserControlledMdl)
14000120b                {
140001214                    MDL* MdlBuffer = StoredBuffer->MdlBuffer;
140001214                    
14000121b                    if (MdlBuffer)
14000121b                    {
14000121d                        MmUnlockPages(MdlBuffer);
140001227                        IoFreeMdl(StoredBuffer->MdlBuffer);
14000121b                    }
14000121b                    
140001234                    KPROCESSORMODE = 1;
140001239                    MmProbeAndLockPages(UserControlledMdl, KPROCESSORMODE, IoModifyAccess);
14000123f                    StoredBuffer->MdlBuffer = UserControlledMdl;
14000125b                    UINT64 MappedPagesAddress;
14000125b                    MappedPagesAddress = MmMapLockedPagesSpecifyCache(UserControlledMdl, 0, MmNonCached, nullptr, 0, 0x10);
140001261                    StoredBuffer->MappedPagesAddr = MappedPagesAddress;


at this point i thought the vulnerability was in the way the MmProbeAndLockPages is called but it correctly sets the processor mode to 1 which does not allow us to pass kernel mode addresses. 
still we can pass a userland addres and it is mapped into kernel space which is interesting


there were two more ioctls one that reads data from the global kernel address noticed in the driver entry function and writes it to the kernel address that is mapped from our userland address. and one that does the opposite it writes from our user address to the kernel buffer.

the last ioctl worth mentioning is really important. 
it performs a check on the calling processes driver extension node entry
and if a value is set. it will read the flag into the target mapped address in our struct.

the only issue is the check is out of our control (for now)


else if (*(uint8_t*)((char*)StoredBuffer->zeroIfFree)[1])

the flag only gets set to 1 once we allocate our buffer,
and 0 once a different ioctl is called to free it. but the check
checks if the byte after is set so our value needs to be greater than
0xFF

around this time my mental model for the problem was.

we need to pass this check to read the flag.
but there is no way for us to control the flag value directly.
but perhaps there is a way for us to control INDIRECTLY

after going back to the driver entry i noticed this 

14000106a        DriverObject->MajorFunction[0x12] = FreesListEntryOnDeviceCloseCouldHaveUAF;

it looked like a function that is called when closing the handle to the driver
to perform cleanup.
upon further inspection thats exactly what it does
(screenshot)

but there is a check that allows the node to not be removed from the linked list but still freed 

    if (!Next->zeroIfFree || !Next->length || *(uint8_t*)((char*)Next->length)[4] != 0x70)

at first glance it looks like all we need to do is pass 0x70 to our buffer that is appened to the struct metadata from above since length is always set and zeroiffree can be set to 1

after changing my payload to be 0x70 it indeed passed the check and the buffer is freed but we can still reopen the handle to the driver after closing it.

giving us a UAF vulnerability. 

the next steps were to find out how to spray the heap and set it up so that when we freed our node it can be replaced with something we control.

(perhaps explanation of heap spraying here)

[X] [X] [OUR NODE] [X]
[X] [X] [] [X]
[X] [X] [SOMETHING WE CONTROL NOW] [X]

after googling i found many articles using named pipe).
(list articles here)

this method is extremely effective because it allows you to set the size of the allocation arbitrarily.
which is needed when spraying as the objects need to be the same or similar sizes so the heap reuses the location of the originally freed object.

but they all included DATA_ENTRY metadata for the first 0x48 bytes.
and did not allow us to fully control the PID variable in the struct
which we needed to match our original calling process that freed the node

since we control the size of the payload we send, we can have it match our pipe buffer extremely easily after some tweaks.

i was able to consistently get the sprayd objects to be in the location of our freed node.

but i could not reuse the new object because of the aformentioned metadata
after looking for different kernel objects that i could use they all ran into the same issue. Until i found this article
(mention article that uses unbuffered pipe)

that uses the same pipe technique but allows you to set it to be unbuffered
which gives full control over the data and has no headers.

after looking at the POC it seemed pretty simple and similar to the original approach.

sprayed again then we can see that the buffer is fully controlled by us.
(image here maybe)


now when we spray we can properly set the values to things we control
the pid, the flag to bypass the check to actually read the flag etc.

after doing this we actually bypass the flag check!
(screenshot?)

the next step was to include an address in our address space that the kernel can write the flag to and call the IOCTL to write it to that address

(screenshot of the flag redacted)!


this worked perfectly and the only thing left to do was to fill the holes
so that when we close the handle again our node is not freed again which can crash the system. so i choose to set the flink and blink members of the fake object to point to a buffer we control in user land that effectively points to NULL signaling the end of the linkedlist and does not free the node.

here is the full exploit code.


# thoughts
first time exploiting kernel heap, really fun,
couldnt have done it with all the previous articles and research out there

was thinking perhaps its possible to get RCE? my virtual machine is running
windows 11 and KASLR bypasses seem to be killed off. the only one i found is the prefetch attack (link here)

that could be research for another time.









# References
* https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation&ved=2ahUKEwjEoKOV67-PAxVPSjABHeJsJEcQFnoECBcQAQ&usg=AOvVaw2WpS4aLLeq9QtCeg4NUAc-
* https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
* https://wetw0rk.github.io/posts/0x03-approaching-the-modern-windows-kernel-heap/
* www.alex-ionescu.com/kernel-heap-spraying-like-its-2015-swimming-in-the-big-kids-pool/
* https://www.ibm.com/think/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service
* https://github.com/xforcered/PhrackCTF
* https://medium.com/reverence-cyber/cve-2023-36802-mssksrv-sys-local-privilege-escalation-reverence-cyber-d54316eaf11
