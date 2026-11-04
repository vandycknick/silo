/* SPDX-License-Identifier: GPL-2.0-only
 * Isolated commit11 proof instrumentation, never a production kernel input.
 * Apply native_generation_partial.patch to the production driver, not on top
 * of commit10's different fault patch. The production low-last helper remains
 * the only publisher; this gate interrupts it after ID/high and before low.
 */
static unsigned int proof_mode;
module_param(proof_mode, uint, 0400);
MODULE_PARM_DESC(proof_mode, "DIAGNOSTIC ONLY: 4=staged ID/high before low commit");

static bool silo_partial_before_low(struct silo_vmgenid *g,
				    const struct silo_request *r)
{
	if (proof_mode != 4 || (r->flags & SILO_CLOCK_ONLY))
		return true;
	WRITE_ONCE(g->proof_gate, 0);
	WRITE_ONCE(g->proof_phase, 1);
	wait_event_timeout(g->stop_wait,
		READ_ONCE(g->stopping) || READ_ONCE(g->proof_gate) == 1,
		msecs_to_jiffies(4500));
	if (READ_ONCE(g->stopping) || READ_ONCE(g->proof_gate) != 1)
		return false;
	WRITE_ONCE(g->proof_phase, 0);
	return true;
}

static ssize_t generation_proof_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct silo_vmgenid *g = dev_to_virtio(dev)->priv;

	return sysfs_emit(buf, "mode=%u phase=%u gate=%u\n", proof_mode,
		READ_ONCE(g->proof_phase), READ_ONCE(g->proof_gate));
}

static ssize_t generation_proof_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct silo_vmgenid *g = dev_to_virtio(dev)->priv;

	if (proof_mode != 4 || READ_ONCE(g->proof_phase) != 1 ||
	    !sysfs_streq(buf, "advance"))
		return -EINVAL;
	WRITE_ONCE(g->proof_gate, 1);
	wake_up(&g->stop_wait);
	return count;
}
static DEVICE_ATTR_RW(generation_proof);
