#ifndef CAPSTONE_UTIL_H
#define CAPSTONE_UTIL_H

#include <capstone/capstone.h>

int arm_insn_accesses_mem(const cs_insn *ins);
int arm_insn_accesses_mem(const cs_insn *ins) {
    if (!ins || !ins->detail) return 0;
    const cs_arm *a = &ins->detail->arm;

    // common case: explicit memory operand present
    for (int i = 0; i < a->op_count; i++)
        if (a->operands[i].type == ARM_OP_MEM) return 1;

    // also treat PUSH/POP/LDM/STM as memory (Capstone may encode via regs)
    switch (ins->id) {
    case ARM_INS_PUSH: case ARM_INS_POP:
    case ARM_INS_LDM:  case ARM_INS_LDMDA: case ARM_INS_LDMDB: case ARM_INS_LDMIB:
    case ARM_INS_STM:  case ARM_INS_STMDA: case ARM_INS_STMDB: case ARM_INS_STMIB:
        return 1;
    default: break;
    }
    return 0;
}

int arm_insn_is_fp_mem_access(const cs_insn *ins);
int arm_insn_is_fp_mem_access(const cs_insn *ins)
{
    if (!ins || !ins->detail) {
        return 0;
    }

    const cs_arm *a = &ins->detail->arm;

    /* Must be floating-point: mnemonic starts with 'v' AND has .f32 suffix */
    // if (!(ins->mnemonic[0] == 'v' && strstr(ins->mnemonic, ".f32"))) {
    if (!(ins->mnemonic[0] == 'v')) {
        return 0;
    }

    /* Common case: explicit ARM_OP_MEM operand present */
    for (int i = 0; i < a->op_count; i++) {
        if (a->operands[i].type == ARM_OP_MEM) {
            return 1;
        }
    }

    /* Also cover FP multi-load/store */
    // switch (ins->id) {
    // case ARM_INS_VLDM: case ARM_INS_VLDMIA: case ARM_INS_VLDMDB:
    // case ARM_INS_VSTM: case ARM_INS_VSTMIA: case ARM_INS_VSTMDB:
    //     return 1;
    // default:
    //     break;
    // }

    return 0;
}


#endif // CAPSTONE_UTIL_H