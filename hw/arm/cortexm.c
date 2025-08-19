/*
 *
 * Copyright (c) 2022 Felipe Balbi <balbi@kernel.org>
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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "qemu/error-report.h"
#include "hw/arm/cortexm_soc.h"
#include "hw/arm/boot.h"
#include "qemu/units.h"
#include "system/address-spaces.h"

/* olimex-stm32-h405 implementation is derived from netduinoplus2 */

/* Main SYSCLK frequency in Hz (168MHz) */
#define SYSCLK_FRQ 168000000ULL

static void cortexm_init(MachineState *machine)
{
    DeviceState *dev;
	MachineClass *mc = MACHINE_GET_CLASS(machine);
    Clock *sysclk;
    /* This clock doesn't need migration because it is fixed-frequency */
    sysclk = clock_new(OBJECT(machine), "SYSCLK");
    clock_set_hz(sysclk, SYSCLK_FRQ);

	const char *cpu_type = mc->default_cpu_type;
	printf("%s", cpu_type);


    dev = qdev_new(TYPE_CORTEXM_SOC);
    object_property_add_child(OBJECT(machine), "soc", OBJECT(dev));
    qdev_connect_clock_in(dev, "sysclk", sysclk);


    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

	if (!machine->ram) {
        if (!machine->ram_size) {
            machine->ram_size = 512 * KiB;
        }

        error_report("No memdev provided. Use -machine memdev=...");
        exit(1);
    }

	memory_region_add_subregion(get_system_memory(), object_property_get_uint(OBJECT(dev), "ram_baseaddr", &error_fatal), machine->ram);

    armv7m_load_kernel(CORTEXM_SOC(dev)->armv7m.cpu,
                       machine->kernel_filename,
                       0, FLASH_SIZE);
}

static void cortexm_machine_init(MachineClass *mc)
{
    static const char * const valid_cpu_types[] = {
		ARM_CPU_TYPE_NAME("cortex-m0"),
		ARM_CPU_TYPE_NAME("cortex-m3"),
        ARM_CPU_TYPE_NAME("cortex-m4"),
		ARM_CPU_TYPE_NAME("cortex-m7"),
		ARM_CPU_TYPE_NAME("cortex-m33"),
		ARM_CPU_TYPE_NAME("cortex-m55"),
        NULL
    };

    mc->desc = "Cortex-M Generic";
    mc->init = cortexm_init;
    mc->valid_cpu_types = valid_cpu_types;

    /* SRAM pre-allocated as part of the SoC instantiation */
    mc->default_ram_size = 0;

	machine_class_allow_dynamic_sysbus_dev(mc, "stm32f2xx-usart");
}

DEFINE_MACHINE("cortexm", cortexm_machine_init)
