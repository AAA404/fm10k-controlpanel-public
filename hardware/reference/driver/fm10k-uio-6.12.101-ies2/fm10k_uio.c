// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2013 - 2019 Intel Corporation. */

#include "fm10k.h"

static inline struct fm10k_intfc *to_fm10k_intfc(struct uio_info *uio)
{
	return container_of(uio, struct fm10k_intfc, uio);
}

static irqreturn_t fm10k_msix_uio(int irq, void *data)
{
	struct uio_info *uio = data;

	fm10k_write_reg(&to_fm10k_intfc(uio)->hw, FM10K_EICR,
			FM10K_EICR_SWITCHINTERRUPT);
	uio_event_notify(uio);

	return IRQ_HANDLED;
}

static void fm10k_uio_set_irq(struct fm10k_intfc *interface, bool on)
{
	struct msix_entry *entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	u32 itr = FM10K_ITR_AUTOMASK;

	itr |= on ? FM10K_ITR_MASK_CLEAR : FM10K_ITR_MASK_SET;
	fm10k_write_reg(&interface->hw, FM10K_ITR(entry->entry), itr);
}

static void fm10k_uio_irq_task(struct work_struct *work)
{
	struct fm10k_intfc *interface;

	interface = container_of(work, struct fm10k_intfc, uio_task);
	if (test_bit(__FM10K_RESETTING, interface->state)) {
		queue_work(fm10k_workqueue, &interface->uio_task);
		return;
	}

	fm10k_uio_set_irq(interface, interface->uio_int_enable);
}

static int fm10k_uio_irqcontrol(struct uio_info *uio, s32 irq_on)
{
	struct fm10k_intfc *interface = to_fm10k_intfc(uio);

	interface->uio_int_enable = irq_on != 0;
	queue_work(fm10k_workqueue, &interface->uio_task);
	return 0;
}

int fm10k_uio_request_irq(struct fm10k_intfc *interface)
{
	struct msix_entry *entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	struct uio_info *uio = &interface->uio;
	struct fm10k_hw *hw = &interface->hw;
	int err;

	if (!test_bit(FM10K_FLAG_UIO_REGISTERED, interface->flags))
		return 0;

	err = request_irq(entry->vector, fm10k_msix_uio, 0, uio->name, uio);
	if (err)
		return err;

	fm10k_uio_set_irq(interface, interface->uio_int_enable);
	fm10k_write_reg(hw, FM10K_INT_MAP(fm10k_int_switch_event),
			FM10K_INT_MAP_IMMEDIATE | entry->entry);
	fm10k_write_reg(hw, FM10K_EIMR, FM10K_EIMR_ENABLE(SWITCHINTERRUPT));
	return 0;
}

void fm10k_uio_free_irq(struct fm10k_intfc *interface)
{
	struct uio_info *uio = &interface->uio;
	struct fm10k_hw *hw = &interface->hw;
	struct msix_entry *entry;

	if (!test_bit(FM10K_FLAG_UIO_REGISTERED, interface->flags) ||
	    !interface->msix_entries)
		return;

	entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	fm10k_write_reg(hw, FM10K_EIMR, FM10K_EIMR_DISABLE(SWITCHINTERRUPT));
	fm10k_write_reg(hw, FM10K_INT_MAP(fm10k_int_switch_event),
			FM10K_INT_MAP_DISABLE);
	fm10k_write_reg(hw, FM10K_ITR(entry->entry), FM10K_ITR_MASK_SET);
	fm10k_write_flush(hw);
	free_irq(entry->vector, uio);
}

int fm10k_uio_probe(struct fm10k_intfc *interface)
{
	struct msix_entry *entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	struct uio_info *uio = &interface->uio;
	struct fm10k_hw *hw = &interface->hw;
	int err;

	if (!interface->sw_addr)
		return -ENODEV;

	INIT_WORK(&interface->uio_task, fm10k_uio_irq_task);
	uio->name = "fm10k";
	uio->version = fm10k_driver_version;
	uio->irq = UIO_IRQ_CUSTOM;
	uio->irqcontrol = fm10k_uio_irqcontrol;
	uio->mem[0].name = "BAR4";
	uio->mem[0].addr = pci_resource_start(interface->pdev, 4);
	uio->mem[0].size = pci_resource_len(interface->pdev, 4);
	uio->mem[0].internal_addr = interface->sw_addr;
	uio->mem[0].memtype = UIO_MEM_PHYS;

	err = uio_register_device(&interface->pdev->dev, uio);
	if (err)
		return err;

	err = request_irq(entry->vector, fm10k_msix_uio, 0, uio->name, uio);
	if (err) {
		uio_unregister_device(uio);
		return err;
	}

	interface->uio_int_enable = false;
	fm10k_uio_set_irq(interface, false);
	fm10k_write_reg(hw, FM10K_INT_MAP(fm10k_int_switch_event),
			FM10K_INT_MAP_IMMEDIATE | entry->entry);
	fm10k_write_reg(hw, FM10K_EIMR, FM10K_EIMR_ENABLE(SWITCHINTERRUPT));
	set_bit(FM10K_FLAG_UIO_REGISTERED, interface->flags);

	return 0;
}

void fm10k_uio_remove(struct fm10k_intfc *interface)
{
	if (!test_bit(FM10K_FLAG_UIO_REGISTERED, interface->flags))
		return;

	fm10k_uio_free_irq(interface);
	clear_bit(FM10K_FLAG_UIO_REGISTERED, interface->flags);
	uio_unregister_device(&interface->uio);
	cancel_work_sync(&interface->uio_task);
}
