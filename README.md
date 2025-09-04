# Phrack 40th Anniversary CTF Challenge Solution


# Spoilers Below

# Intro

# Using Binary ninja

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



# References
* https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation&ved=2ahUKEwjEoKOV67-PAxVPSjABHeJsJEcQFnoECBcQAQ&usg=AOvVaw2WpS4aLLeq9QtCeg4NUAc-
* https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
* https://wetw0rk.github.io/posts/0x03-approaching-the-modern-windows-kernel-heap/
* www.alex-ionescu.com/kernel-heap-spraying-like-its-2015-swimming-in-the-big-kids-pool/
* https://www.ibm.com/think/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service
* https://github.com/xforcered/PhrackCTF
* https://medium.com/reverence-cyber/cve-2023-36802-mssksrv-sys-local-privilege-escalation-reverence-cyber-d54316eaf11
