/*
 * CORTEXM SoC
 *
 * Copyright (c) 2014 Alistair Francis <alistair@alistair23.me>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef HW_ARM_CORTEXM_SOC_H
#define HW_ARM_CORTEXM_SOC_H

#include "hw/or-irq.h"
#include "hw/arm/armv7m.h"
#include "qom/object.h"

#define TYPE_CORTEXM_SOC "cortexm-soc"
OBJECT_DECLARE_SIMPLE_TYPE(CORTEXMState, CORTEXM_SOC)


#define FLASH_BASE_ADDRESS 0x00000000
#define FLASH_SIZE (512 *1024 * 1024)
#define SRAM_SIZE (512 * 1024 * 1024)
#define SRAM_BASE_ADDRESS 0x20000000

struct CORTEXMState {
    SysBusDevice parent_obj;
	char * cpu_string;

    ARMv7MState armv7m;

    MemoryRegion sram;
    MemoryRegion flash;
    MemoryRegion flash_alias;

	HostMemoryBackend * ram_backend;
	HostMemoryBackend * shram_backend;

	uint32_t ram_baseaddr;
	uint32_t shram_baseaddr;

    Clock *sysclk;
    Clock *refclk;
};

#endif
