import base64
from pwn import *
import subprocess
import sys

# Get path to target binary and shellcode
binary_path = sys.argv[1]
shellcode_path = sys.argv[2]

log.info("Running symbolic executor")

# Run our symbolic executor over the binary to deobfuscate the shellcode
cmd = "example/target/release/example-0 {} {}".format(binary_path, shellcode_path)
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

# Read and parse the shellcode output
(stdout, stderr) = proc.communicate()

log.info("Symbolic executor done")

solution = stdout.strip().split('\n')[-1]

shellcode = base64.b16decode(solution)

log.info("Saving shellcode to /tmp/shellcode.deobfuscated")

fh = open("/tmp/shellcode.deobfuscated", "wb")
fh.write(shellcode)
fh.close()

# Run the process, and feed our shellcode into it
s = process(binary_path)
s.send(shellcode)
s.interactive()