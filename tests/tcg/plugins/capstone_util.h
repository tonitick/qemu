#ifndef CAPSTONE_UTIL_H
#define CAPSTONE_UTIL_H

#include <capstone/capstone.h>
#include <capstone/arm.h>

int arm_insn_accesses_mem(const cs_insn *ins);
int arm_insn_accesses_mem(const cs_insn *ins) {
    if (!ins || !ins->detail) return 0;
    const cs_arm *a = &ins->detail->arm;

    // common case: explicit memory operand present
    for (int i = 0; i < a->op_count; i++)
        if (a->operands[i].type == ARM_OP_MEM) return 1;

    // also treat PUSH/POP/LDM/STM as memory (Capstone may encode via regs)
    switch (ins->id) {
    // case ARM_INS_PUSH: case ARM_INS_POP: # zz: not handle stack for now
    case ARM_INS_LDM:  case ARM_INS_LDMDA: case ARM_INS_LDMDB: case ARM_INS_LDMIB:
    case ARM_INS_STM:  case ARM_INS_STMDA: case ARM_INS_STMDB: case ARM_INS_STMIB:
        return 1;
    default: break;
    }
    return 0;
}


static inline int arm_reg_is_fp(unsigned r) {
    return (r >= ARM_REG_S0 && r <= ARM_REG_S31) ||
           (r >= ARM_REG_D0 && r <= ARM_REG_D31) ||
           (r >= ARM_REG_Q0 && r <= ARM_REG_Q15);
}

int arm_insn_is_fp(const cs_insn *ins);
int arm_insn_is_fp(const cs_insn *ins) {
    if (!ins || !ins->detail) return 0;

    const cs_detail *d = ins->detail;

    // 1) Prefer Capstone groups
    for (uint8_t i = 0; i < d->groups_count; i++) {
        switch (d->groups[i]) {
            case ARM_GRP_VFP2:      // scalar VFP/FP
            case ARM_GRP_VFP3:      // scalar VFP/FP
            case ARM_GRP_VFP4:      // scalar VFP/FP
            case ARM_GRP_FPARMV8:  // FP-ARMv8 scalar
            case ARM_GRP_NEON:     // Advanced SIMD (include if you consider vector FP as "FP")
                return 1;
        }
    }

    // 2) Fallback: look at operands for FP regs or FP immediates
    const cs_arm *a = &d->arm;
    for (uint8_t i = 0; i < a->op_count; i++) {
        const cs_arm_op *op = &a->operands[i];
        if ((op->type == ARM_OP_REG && arm_reg_is_fp(op->reg)) ||
            (op->type == ARM_OP_FP))  // floating-point immediate
            return 1;
    }

    return 0;
}


int arm_insn_is_fp_mem_access(const cs_insn *ins);
int arm_insn_is_fp_mem_access(const cs_insn *ins)
{
    if (!ins || !ins->detail) {
        return 0;
    }

    if (!arm_insn_is_fp(ins)) {
        return 0;
    }

    const cs_arm *a = &ins->detail->arm;

    // /* Must be floating-point: mnemonic starts with 'v' AND has .f32 suffix */
    // // if (!(ins->mnemonic[0] == 'v' && strstr(ins->mnemonic, ".f32"))) {
    // if (!(ins->mnemonic[0] == 'v')) {
    //     return 0;
    // }

    /* Common case: explicit ARM_OP_MEM operand present */
    for (int i = 0; i < a->op_count; i++) {
        if (a->operands[i].type == ARM_OP_MEM) {
            return 1;
        }
    }

    /* Also cover FP multi-load/store (VLDM/VSTM). Capstone exposes these as a
     * base register + register list rather than an ARM_OP_MEM operand, so the
     * loop above misses them (verified: `vldmia r2!,{s2}` has op_count=2, both
     * ARM_OP_REG, no ARM_OP_MEM). arm_insn_is_fp() above still returns true
     * (VFP2 group / s-reg operand), so we reach here. Without this, the body of
     * an array-walk loop (e.g. getAverage's `vldmia r2!,{s2}` at 0x8000274 --
     * the only instruction that dereferences the _array pointer) is invisible to
     * the plugin, so _array never gets promoted to a pointer and is wrongly
     * demoted to a float scalar. All four forms are FP memory accesses; only the
     * IA/DB variants exist in this Capstone (no plain ARM_INS_VLDM/VSTM). */
    switch (ins->id) {
    case ARM_INS_VLDMIA: case ARM_INS_VLDMDB:
    case ARM_INS_VSTMIA: case ARM_INS_VSTMDB:
        return 1;
    default:
        break;
    }

    return 0;
}

#endif // CAPSTONE_UTIL_H