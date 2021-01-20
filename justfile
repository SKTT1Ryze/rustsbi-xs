target := "riscv64gc-unknown-none-elf"
mode := "release"
build-path := "./target/" + target + "/" + mode + "/"
m-firmware-file := build-path + "rustsbi-xs"
m-bin-file := build-path + "rustsbi-xs.bin"
asm-file := build-path + "rustsbi-xs.asm"

objdump := "rust-objdump"
objcopy := "rust-objcopy --binary-architecture=riscv64"

emu := env_var("NOOP_HOME") + "/build/" + "emu"

run: build
    @{{emu}} -I 1000000 -i {{m-bin-file}}

build: firmware
    @{{objcopy}} {{m-firmware-file}} --strip-all -O binary {{m-bin-file}}

firmware:
    @cargo build --target={{target}} --{{mode}}
    @{{objdump}} -D {{m-firmware-file}} | less > {{asm-file}}

asm: build
    @{{objdump}} -D {{m-firmware-file}} | less

clean:
    @rm -rf {{build-path}}