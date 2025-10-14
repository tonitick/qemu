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
# target remote :1235
# set $sp=0x20000600

# # the following is set when vector table address is specified in qemu -global armv7m.init-nsvtor=<addr> flag
# # set $sp=0x20000600
# # set $pc=0x080002e1
# # set $sp=0x20000600
# # set $pc=0x2e1

# # break to a safe point (seems needed)
# b *0x8003018
# c

# delete breakpoints
# set $pc=0x80655ac
# c

################################### rover2
target remote :1235
set $sp=0x20000600

# # break to a safe point (seems not needed)
# b *0x08114a12
# c

# # test
# set $pc=0x8101e84
# set $r0=0x30000200
# set $r1=1
# set *((unsigned char *)0x30000202) = 2
# set *((int *)0x30000204) = 0x30000400
# # set *((unsigned int *)0x30000204) = 0x30000400
# set *((float *)0x30000400) = 3.14
# set *((float *)0x30000404) = 9.42
# b * 0x08101e9e
# c
# # 6.28
# p/f $r0

delete breakpoints
set $pc=0x8101e84
c