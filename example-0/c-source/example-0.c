#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


int main(int argc, char * argv[]) {
    // Read in one byte all shellcode will be XORed with
    uint8_t xor_byte;
    if (read(0, &xor_byte, 1) != 1) { return -1; }

    // Create some RWX memory
    uint8_t * executable_memory = mmap(0,
                                       4096,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_ANONYMOUS | MAP_PRIVATE,
                                       -1,
                                       0);

    // Read in shellcode
    ssize_t bytes_read = read(0, executable_memory, 4096);

    // Deobfuscate shellcode
    ssize_t i;
    for (i = 0; i < bytes_read; i++) {
        executable_memory[i] ^= xor_byte;
        if (i + 1 < bytes_read)
            executable_memory[i] ^= executable_memory[i + 1];
        if (i > 0)
            executable_memory[i] ^= executable_memory[i - 1];
    }

    // Run shellcode
    ((void (*) ()) executable_memory)();

    // Return cleanly if shellcode doesn't crash/exit
    return 0;
}