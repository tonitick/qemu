################################### gs3
# file ./gs3_new.elf
target remote :1235


################################### boom
# file ./boom
# target remote :1235
# # monitor system_reset
# # set arm fallback-mode thumb
# # thb Reset_Handler
# # c

# # set $pc=0x08005315
# # b gpio_init
# # c
# # delete breakpoints
# # b stm32_clock_init
# # c
# # delete breakpoints
# # b *0x8166952

# # # heap region: 0x20000000 – 0x2002FFFF
# # set $pc=0x804f614