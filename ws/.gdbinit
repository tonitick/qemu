file ./m4_debug
target remote :1235

set $pc=0x08005315
b gpio_init
c
delete breakpoints
b stm32_clock_init
c
delete breakpoints
b *0x8166952

# heap region: 0x20000000 – 0x2002FFFF
set $pc=0x804f614
# set $r0=0x20000020
# set $s0 = 2.0f
# set *((float *)0x20000020) = 3.14
# set *((float *)0x20000024) = 6.28