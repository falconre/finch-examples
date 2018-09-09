# Finch Example-0

This example Finch program symbolically executes amd64 code to deobfuscate shellcode.

You can find the source to the program this example executes in `c-source/example-0.c`

The binary this example executes can also be found in `c-source/example-0`.

# Running

You are encouraged to build and run this example program in the Dockerfile contained in the root of the `finch-examples` repository.

```
cd example
cargo run -- ../c-source/example-0 ../shellcode
```

If you have pwntools installed, try:

```
cd example
cargo build --release
cd ..
python solve.py
```