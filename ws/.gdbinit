################################### m4_debug
# file ./m4_debug
# target remote :1235

# set $pc=0x08005315
# b gpio_init
# c
# delete breakpoints
# b stm32_clock_init
# c
# delete breakpoints
# b *0x8166952

# # heap region: 0x20000000 – 0x2002FFFF
# set $pc=0x804f614

################################### gs3
# file ./gs3_new.elf
target remote :1235

# the following is set when vector table address is specified in qemu -global armv7m.init-nsvtor=<addr> flag
# set $sp=0x20000600
# set $pc=0x080002e1
# set $sp=0x20000600
# set $pc=0x2e1

b *0x8003018
c

delete breakpoints
set $pc=0x80655ac
c