#ifndef VIRTUAL_H
#define VIRTUAL_H

#include <qemu-plugin.h>


typedef void (*cb_func_t)(unsigned int cpu_index, void *userdata);

typedef struct {
    const char *name;
    cb_func_t func;
} cb_entry_t;

typedef struct {
    unsigned long long address;
    cb_func_t func;        // function pointer, NOT the name
    char args[384];
} rule_t;

bool find_rule_by_address(unsigned long long addr, rule_t **out_rule);

typedef enum {
    ARM_V7M_REG_INVALID = -1,
    ARM_V7M_REG_R0 = 0,
    ARM_V7M_REG_R1 = 1,
    ARM_V7M_REG_R2 = 2,
    ARM_V7M_REG_R3 = 3,
    ARM_V7M_REG_R4 = 4,
    ARM_V7M_REG_R5 = 5,
    ARM_V7M_REG_R6 = 6,
    ARM_V7M_REG_R7 = 7,
    ARM_V7M_REG_R8 = 8,
    ARM_V7M_REG_R9 = 9,
    ARM_V7M_REG_R10 = 10,
    ARM_V7M_REG_R11 = 11,
    ARM_V7M_REG_R12 = 12,
    ARM_V7M_REG_R13 = 13, // Stack Pointer (SP)
    ARM_V7M_REG_R14 = 14, // Link Register (LR)
    ARM_V7M_REG_R15 = 15, // Program Counter (PC)

    ARM_V7M_S0 = 26, // Floating-point register s0
    ARM_V7M_S1 = 27,
    ARM_V7M_S2 = 28,
    ARM_V7M_S3 = 29,
    ARM_V7M_S4 = 30,
    ARM_V7M_S5 = 31,
    ARM_V7M_S6 = 32,
    ARM_V7M_S7 = 33,
    ARM_V7M_S8 = 34,
    ARM_V7M_S9 = 35,
    ARM_V7M_S10 = 36,
    ARM_V7M_S11 = 37,
    ARM_V7M_S12 = 38,
    ARM_V7M_S13 = 39,
    ARM_V7M_S14 = 40,
    ARM_V7M_S15 = 41, // Floating-point register s15
    ARM_V7M_S16 = 42,
    ARM_V7M_S17 = 43,
    ARM_V7M_S18 = 44,
    ARM_V7M_S19 = 45,
    ARM_V7M_S20 = 46,
    ARM_V7M_S21 = 47,
    ARM_V7M_S22 = 48,
    ARM_V7M_S23 = 49,
    ARM_V7M_S24 = 50,
    ARM_V7M_S25 = 51,
    ARM_V7M_S26 = 52,
    ARM_V7M_S27 = 53,
    ARM_V7M_S28 = 54,
    ARM_V7M_S29 = 55,
    ARM_V7M_S30 = 56,
    ARM_V7M_S31 = 57,

    // ARM_V7M_D0 = 26,
    // ARM_V7M_D1 = 27,
    // ARM_V7M_D2 = 28,
    // ARM_V7M_D3 = 29,
    // ARM_V7M_D4 = 30,
    // ARM_V7M_D5 = 31,
    // ARM_V7M_D6 = 32,
    // ARM_V7M_D7 = 33,
    // ARM_V7M_D8 = 34,
    // ARM_V7M_D9 = 35,
    // ARM_V7M_D10 = 36,
    // ARM_V7M_D11 = 37,
    // ARM_V7M_D12 = 38,
    // ARM_V7M_D13 = 39,
    // ARM_V7M_D14 = 40,
    // ARM_V7M_D15 = 41
    ARM_V7M_D0 = 58,
    ARM_V7M_D1 = 59,
    ARM_V7M_D2 = 60,
    ARM_V7M_D3 = 61,
    ARM_V7M_D4 = 62,
    ARM_V7M_D5 = 63,
    ARM_V7M_D6 = 64,
    ARM_V7M_D7 = 65,
    ARM_V7M_D8 = 66,
    ARM_V7M_D9 = 67,
    ARM_V7M_D10 = 68,
    ARM_V7M_D11 = 69,
    ARM_V7M_D12 = 70,
    ARM_V7M_D13 = 71,
    ARM_V7M_D14 = 72,
    ARM_V7M_D15 = 73
} ARM_V7M_REG;

ARM_V7M_REG get_reg_by_name(const char *name);
ARM_V7M_REG get_reg_by_name(const char *name) {
    if (strcmp(name, "r0") == 0) return ARM_V7M_REG_R0;
    if (strcmp(name, "r1") == 0) return ARM_V7M_REG_R1;
    if (strcmp(name, "r2") == 0) return ARM_V7M_REG_R2;
    if (strcmp(name, "r3") == 0) return ARM_V7M_REG_R3;
    if (strcmp(name, "r4") == 0) return ARM_V7M_REG_R4;
    if (strcmp(name, "r5") == 0) return ARM_V7M_REG_R5;
    if (strcmp(name, "r6") == 0) return ARM_V7M_REG_R6;
    if (strcmp(name, "r7") == 0) return ARM_V7M_REG_R7;
    if (strcmp(name, "r8") == 0) return ARM_V7M_REG_R8;
    if (strcmp(name, "r9") == 0) return ARM_V7M_REG_R9;
    if (strcmp(name, "r10") == 0) return ARM_V7M_REG_R10;
    if (strcmp(name, "r11") == 0) return ARM_V7M_REG_R11;
    if (strcmp(name, "r12") == 0) return ARM_V7M_REG_R12;
    if (strcmp(name, "sp") == 0 || strcmp(name, "r13") == 0) return ARM_V7M_REG_R13; // SP
    if (strcmp(name, "lr") == 0 || strcmp(name, "r14") == 0) return ARM_V7M_REG_R14; // LR
    if (strcmp(name, "pc") == 0 || strcmp(name, "r15") == 0) return ARM_V7M_REG_R15; // PC

    if (strcmp(name, "s0") == 0) return ARM_V7M_S0;
    if (strcmp(name, "s1") == 0) return ARM_V7M_S1;
    if (strcmp(name, "s2") == 0) return ARM_V7M_S2;
    if (strcmp(name, "s3") == 0) return ARM_V7M_S3;
    if (strcmp(name, "s4") == 0) return ARM_V7M_S4;
    if (strcmp(name, "s5") == 0) return ARM_V7M_S5;
    if (strcmp(name, "s6") == 0) return ARM_V7M_S6;
    if (strcmp(name, "s7") == 0) return ARM_V7M_S7;
    if (strcmp(name, "s8") == 0) return ARM_V7M_S8;
    if (strcmp(name, "s9") == 0) return ARM_V7M_S9;
    if (strcmp(name, "s10") == 0) return ARM_V7M_S10;
    if (strcmp(name, "s11") == 0) return ARM_V7M_S11;
    if (strcmp(name, "s12") == 0) return ARM_V7M_S12;
    if (strcmp(name, "s13") == 0) return ARM_V7M_S13;
    if (strcmp(name, "s14") == 0) return ARM_V7M_S14;
    if (strcmp(name, "s15") == 0) return ARM_V7M_S15;
    if (strcmp(name, "s16") == 0) return ARM_V7M_S16;
    if (strcmp(name, "s17") == 0) return ARM_V7M_S17;
    if (strcmp(name, "s18") == 0) return ARM_V7M_S18;
    if (strcmp(name, "s19") == 0) return ARM_V7M_S19;
    if (strcmp(name, "s20") == 0) return ARM_V7M_S20;
    if (strcmp(name, "s21") == 0) return ARM_V7M_S21;
    if (strcmp(name, "s22") == 0) return ARM_V7M_S22;
    if (strcmp(name, "s23") == 0) return ARM_V7M_S23;
    if (strcmp(name, "s24") == 0) return ARM_V7M_S24;
    if (strcmp(name, "s25") == 0) return ARM_V7M_S25;
    if (strcmp(name, "s26") == 0) return ARM_V7M_S26;
    if (strcmp(name, "s27") == 0) return ARM_V7M_S27;
    if (strcmp(name, "s28") == 0) return ARM_V7M_S28;
    if (strcmp(name, "s29") == 0) return ARM_V7M_S29;
    if (strcmp(name, "s30") == 0) return ARM_V7M_S30;
    if (strcmp(name, "s31") == 0) return ARM_V7M_S31;

    if (strcmp(name, "d0") == 0) return ARM_V7M_D0;
    if (strcmp(name, "d1") == 0) return ARM_V7M_D1;
    if (strcmp(name, "d2") == 0) return ARM_V7M_D2;
    if (strcmp(name, "d3") == 0) return ARM_V7M_D3;
    if (strcmp(name, "d4") == 0) return ARM_V7M_D4;
    if (strcmp(name, "d5") == 0) return ARM_V7M_D5;
    if (strcmp(name, "d6") == 0) return ARM_V7M_D6;
    if (strcmp(name, "d7") == 0) return ARM_V7M_D7;
    if (strcmp(name, "d8") == 0) return ARM_V7M_D8;
    if (strcmp(name, "d9") == 0) return ARM_V7M_D9;
    if (strcmp(name, "d10") == 0) return ARM_V7M_D10;
    if (strcmp(name, "d11") == 0) return ARM_V7M_D11;
    if (strcmp(name, "d12") == 0) return ARM_V7M_D12;
    if (strcmp(name, "d13") == 0) return ARM_V7M_D13;
    if (strcmp(name, "d14") == 0) return ARM_V7M_D14;
    if (strcmp(name, "d15") == 0) return ARM_V7M_D15;

    return ARM_V7M_REG_INVALID; // Invalid register name
}

#endif // VIRTUAL_H
