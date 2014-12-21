/*
 * Copyright (C) 2010-2011 Neil Brown
 * Copyright (C) 2010-2014 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/log2.h>

#include "md.h"
#include "raid1.h"
#include "raid5.h"
#include "raid10.h"
#include "bitmap.h"

#include <linux/device-mapper.h>
#include <linux/raid/md_p.h>

#define DM_MSG_PREFIX		"raid"
#define	MAX_RAID_DEVICES	64

static bool devices_handle_discard_safely = false;

static void super_sync(struct mddev *mddev, struct md_rdev *rdev);

/*
 * The following flags are used by dm-raid.c to set up the RAID set state.
 * They must be cleared before md_run is called.
 */
#define FirstUse 10             /* temorary rdev flag to indicate new device */

struct raid_dev {
	/*
	 * Two DM devices, one to hold metadata and one to hold the
	 * actual data/parity.  The reason for this is to not confuse
	 * ti->len and give more flexibility in altering size and
	 * characteristics.
	 *
	 * While it is possible for this device to be associated
	 * with a different physical device than the data_dev, it
	 * is intended for it to be the same.
	 *    |--------- Physical Device ---------|
	 *    |- meta_dev -|------ data_dev ------|
	 */
	struct dm_dev *meta_dev;
	struct dm_dev *data_dev;
	struct md_rdev rdev;
};

/*
 * Flags for rs->flags field.
 */
#define DM_RAID_SYNC              0x1
#define DM_RAID_NOSYNC            0x2
#define DM_RAID_REBUILD           0x4
#define DM_RAID_DAEMON_SLEEP      0x8
#define DM_RAID_MIN_RECOVERY_RATE 0x10
#define DM_RAID_MAX_RECOVERY_RATE 0x20
#define DM_RAID_MAX_WRITE_BEHIND  0x40
#define DM_RAID_STRIPE_CACHE      0x80
#define DM_RAID_REGION_SIZE       0x100
#define DM_RAID_RAID10_COPIES     0x200
#define DM_RAID_RAID10_FORMAT     0x400
#define DM_RAID_IGNORE_DISCARD    0x800
#define DM_RAID_SET_STARTED	  0x1000
#define DM_RAID_RESHAPE           0x2000
#define DM_RAID_DELTA_DISKS       0x4000
#define DM_RAID_DATA_OFFSET       0x8000

struct raid_set {
	struct dm_target *ti;

	bool bitmap_loaded;
	uint32_t flags;
	int delta_disks;
	int raid_disks;

	struct mddev md;
	struct raid_type *raid_type;
	struct dm_target_callbacks callbacks;

	struct raid_dev rds[0];
};

#define	for_each_rd(rd, rs) \
	for ((rd) = (rs)->rds + 0; (rd) < (rs)->rds + (rs)->md.raid_disks; (rd)++)

/* Supported raid types and properties. */
static struct raid_type {
	const char *name;		/* RAID algorithm. */
	const char *descr;		/* Descriptor text for logging. */
	const unsigned parity_devs;	/* # of parity devices. */
	const unsigned minimal_devs;	/* minimal # of devices in set. */
	const unsigned level;		/* RAID level. */
	const unsigned algorithm;	/* RAID algorithm. */
} raid_types[] = {
	{"raid0",      "RAID0 (striping)",            		 0, 2, 0, 0 /* NONE */},
	{"raid1",      "RAID1 (mirroring)",            		 0, 2, 1, 0 /* NONE */},
	{"raid10",     "RAID10 (striped mirrors)",	         0, 2, 10, UINT_MAX /* Varies */},
	{"raid4",      "RAID4 (dedicated first parity disk)",	 1, 2, 5, ALGORITHM_PARITY_0},
	{"raid4_n",    "RAID4 (dedicated last parity disk)",	 1, 2, 4, ALGORITHM_PARITY_N}, /* Native raid4 layout */
	{"raid5_0",    "RAID5 (dedicated first parity disk)",	 1, 2, 5, ALGORITHM_PARITY_0},
	{"raid5_n",    "RAID5 (dedicated last parity disk)",	 1, 2, 5, ALGORITHM_PARITY_N},
	{"raid5_ls",   "RAID5 (left symmetric)",		 1, 2, 5, ALGORITHM_LEFT_SYMMETRIC},
	{"raid5_rs",   "RAID5 (right symmetric)",		 1, 2, 5, ALGORITHM_RIGHT_SYMMETRIC},
	{"raid5_la",   "RAID5 (left asymmetric)",		 1, 2, 5, ALGORITHM_LEFT_ASYMMETRIC},
	{"raid5_ra",   "RAID5 (right asymmetric)",		 1, 2, 5, ALGORITHM_RIGHT_ASYMMETRIC},
	{"raid6_zr",   "RAID6 (zero restart)",			 2, 4, 6, ALGORITHM_ROTATING_ZERO_RESTART},
	{"raid6_nr",   "RAID6 (N restart)",			 2, 4, 6, ALGORITHM_ROTATING_N_RESTART},
	{"raid6_nc",   "RAID6 (N continue)",			 2, 4, 6, ALGORITHM_ROTATING_N_CONTINUE},
	{"raid6_ls_6", "RAID6 (left symmetric dedicated Q 6)",	 2, 4, 6, ALGORITHM_LEFT_SYMMETRIC_6},
	{"raid6_rs_6", "RAID6 (right symmetric dedicated Q 6)",	 2, 4, 6, ALGORITHM_RIGHT_SYMMETRIC_6},
	{"raid6_la_6", "RAID6 (left asymmetric dedicated Q 6)",	 2, 4, 6, ALGORITHM_LEFT_ASYMMETRIC_6},
	{"raid6_ra_6", "RAID6 (right asymmetric dedicated Q 6)", 2, 4, 6, ALGORITHM_RIGHT_ASYMMETRIC_6},
	{"raid6_0_6",  "RAID6 (dedicated parity/Q 0/6)",	 2, 4, 6, ALGORITHM_PARITY_0_6},
	{"raid6_n_6",  "RAID6 (dedicated parity/Q n/6)",	 2, 4, 6, ALGORITHM_PARITY_N_6}
};

/* Return raid_type for @name */
static struct raid_type *get_raid_type(const char *name)
{
	struct raid_type *rtp = raid_types + ARRAY_SIZE(raid_types);

	while (rtp-- > raid_types)
		if (!strcasecmp(rtp->name, name))
			return rtp;

	return NULL;
}

/* Return raid_type for @name */
static struct raid_type *get_raid_type_by_ll(const int level, const int layout)
{
	int i;
	struct raid_type *rt = raid_types;

	for (i = 0; i < ARRAY_SIZE(raid_types); i++, rt++)
		if (rt->level == level &&
		    rt->algorithm == layout)
			return rt;

	return NULL;
}

/* Return @raid_level name for @rt */
static int get_raid_level_name(struct raid_type *rt, char *raid_level_name, size_t len)
{
	size_t l = (rt->level == 10) ? strlen(rt->name) : 5;

	if (l + 1 > len)
		return -ENOMEM;

	strncpy(raid_level_name, rt->name, l);
	raid_level_name[l] = '\0';

	return 0;
}

/* True, if @v is in range [@min, @max] inclusive */
static bool __in_range(long v, long min, long max)
{
	return v >= min && v <= max;
}

/* Set the mddev porperties in @rs to the nre ones passed in by the ctr */
static void rs_set_new(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	mddev->level = mddev->new_level;
	mddev->layout = mddev->new_layout;
	mddev->chunk_sectors = mddev->new_chunk_sectors;
	mddev->delta_disks = 0;
}

/* Conditionally enable bitmap based on @level */
static void enable_bitmap(struct raid_set *rs, int level)
{
	struct mddev *mddev = &rs->md;

	/* Enable bitmap creation unless level is raid0 */
	mddev->bitmap_info.file = NULL;
	mddev->bitmap_info.offset = level ? to_sector(4096) : 0;
	mddev->bitmap_info.default_offset = mddev->bitmap_info.offset;
}

/* Return true, if raid set in @rs is raid0 */
static bool is_raid0(struct raid_set *rs)
{
	return !rs->md.level;
}

/* Return true, if raid set in @rs is level 0 or 10 */
static bool is_raid0_or_10(struct raid_set *rs)
{
	return is_raid0(rs) || rs->md.level == 10;
}

/* Return true, if raid set in @rs is level 4,5 or 6 */
static bool is_raid456(struct raid_set *rs)
{
	return __in_range(rs->md.level, 4, 6);
}

/* Return true, if raid set in @rs is raid0 */
static bool is_striped(struct raid_set *rs)
{
	return is_raid0(rs) || is_raid456(rs);
}

static int ti_error_ret(struct dm_target *ti, const char *errmsg, int r)
{
	/* HM FIXME: REMOVEME? just devel error log or in release??? */
	DMERR("%s [%d]", errmsg, r);
	ti->error = (char *) errmsg;
	return r;
}

static int ti_error_einval(struct dm_target *ti, const char *errmsg)
{
	return ti_error_ret(ti, errmsg, -EINVAL);
}

/* Set daemon sleep schedule timeout on @rs to @value */
static int set_daemon_sleep(struct raid_set *rs, unsigned value)
{
	if (is_raid0(rs))
		return ti_error_einval(rs->ti, "daemon_sleep not applicable to RAID0");

	if (!__in_range(value, 1, MAX_SCHEDULE_TIMEOUT))
		return ti_error_einval(rs->ti, "Daemon sleep period out of range");

	rs->md.bitmap_info.daemon_sleep = value;
	smp_wmb();
	return 0;
}

/* Set max write behind on @rs raid1 set to @value */
static int set_max_write_behind(struct raid_set *rs, unsigned value)
{
	if (rs->raid_type->level != 1)
		return ti_error_einval(rs->ti, "max_write_behind option is only valid for RAID1");

	/*
	 * In device-mapper, we specify things in sectors, but
	 * MD records this value in kB
	 */
	value /= 2;
	if (value > COUNTER_MAX)
		return ti_error_einval(rs->ti, "Max write-behind limit out of range");

	rs->md.bitmap_info.max_write_behind = value;
	smp_wmb();
	return 0;
}

/* Set min/max recovery rates on @rs redundant raid set (i.e. all levels but raid0) to @value */
static int set_recovery_rate(struct raid_set *rs, int value, bool min_recovery_rate)
{
	if (is_raid0(rs))
		return ti_error_einval(rs->ti, "recovery_rate not applicable to RAID0");

	if (value > INT_MAX)
		return ti_error_einval(rs->ti, "recovery_rate out of range");

	value /= 2; /* Recovery rate is in KiB, not sectors */
	if (min_recovery_rate) {
		if (value > rs->md.sync_speed_max)
			return ti_error_einval(rs->ti, "min recovery_rate cannot be greater than max_recovery_rate");

		rs->md.sync_speed_min = value;

	} else {
		if (value < rs->md.sync_speed_min)
			return ti_error_einval(rs->ti, "max recovery_rate cannot be smaller than min_recovery_rate");

		rs->md.sync_speed_max = value;
	}

	smp_wmb();
	return 0;
}

/* Return md raid10 layout string for @layout */
static char *raid10_md_layout_to_format(int layout)
{
	/*
	 * Bit 16 and 17 stand for "offset" and "use_far_sets"
	 * Refer to MD's raid10.c for details
	 */
	if ((layout & 0x10000) && (layout & 0x20000))
		return "offset";

	if ((layout & 0xFF) > 1)
		return "near";

	return "far";
}

/* Return md raid10 copies for @layout */
static unsigned raid10_md_layout_to_copies(int layout)
{
	if ((layout & 0xFF) > 1)
		return layout & 0xFF;

	return (layout >> 8) & 0xFF;
}

/* Return md raid10 format id for @format string */
static int raid10_format_to_md_layout(const char *format, unsigned copies)
{
	unsigned n = 1, f = 1;

	if (!strcasecmp("near", format))
		n = copies;
	else
		f = copies;

	if (!strcasecmp("offset", format))
		return 0x30000 | (f << 8) | n;

	if (!strcasecmp("far", format))
		return 0x20000 | (f << 8) | n;

	return (f << 8) | n;
}

/*
 * Remove @rd releasing refcounts on devs and removing the rdev from the mddev
 */
static void raid_dev_remove(struct dm_target *ti, struct raid_dev *rd)
{
	struct md_rdev *rdev = &rd->rdev;

	if (rd->meta_dev)
		dm_put_device(ti, rd->meta_dev);

	rd->meta_dev = NULL;
	rdev->meta_bdev = NULL;

	if (rdev->sb_page) {
		put_page(rdev->sb_page);
		rdev->sb_page = NULL;
	}

	rdev->sb_loaded = 0;

	/*
	 * We might be able to salvage the data device
	 * even though the meta device has failed.  For
	 * now, we behave as though '- -' had been
	 * set for this device in the table.
	 */
	if (rd->data_dev) {
		dm_put_device(ti, rd->data_dev);
		rd->data_dev = NULL;
	}

	rdev->bdev = NULL;

	if (!list_empty(&rdev->same_set))
		list_del_init(&rdev->same_set);
}

/* Return # of data stipes of @rs */
static unsigned rs_data_stripes(struct raid_set *rs)
{
	return rs->md.raid_disks - rs->raid_type->parity_devs;
}

/* Return true if target length of @rs is divisible by number of data disks */
static bool is_divisible_by_data_devs(struct raid_set *rs)
{
	bool r = true;
	sector_t sectors_per_dev = rs->ti->len;

	if (is_striped(rs)) {
		r = !sector_div(sectors_per_dev, rs_data_stripes(rs));
		rs->md.dev_sectors = sectors_per_dev;
	}

	return r;
}

static void do_table_event(struct work_struct *ws)
{
	struct raid_set *rs = container_of(ws, struct raid_set, md.event_work);

	dm_table_event(rs->ti->table);
}

static int raid_is_congested(struct dm_target_callbacks *cb, int bits)
{
	struct raid_set *rs = container_of(cb, struct raid_set, callbacks);

	if (rs->raid_type->level == 1)
		return md_raid1_congested(&rs->md, bits);

	if (rs->raid_type->level == 10)
		return md_raid10_congested(&rs->md, bits);

	return md_raid5_congested(&rs->md, bits);
}

/* For out-of_place reshape, we need free space at the beginning of each RAID disk
 * and at the end.
 * Because growing reshapes of a RAID array are more likely than shrinking ones.
 * return 2/3 of new chunks for growing
 */
static unsigned _split_begin_end_chunks(struct raid_set *rs, sector_t additional_sectors)
{
	sector_t chunks = additional_sectors;

	sector_div(chunks, rs_data_stripes(rs));
	BUG_ON(chunks < 16);

	return chunks * 2 / 3;
}

/* True if @rs requested to be taken over */
static bool rs_takeover_requested(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	return mddev->new_level != mddev->level;
}

/* True if @rs requested to reshape */
static bool rs_reshape_requested(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	return mddev->new_layout != mddev->layout ||
	       mddev->new_chunk_sectors != mddev->chunk_sectors ||
	       rs->delta_disks;
}

/* True if @rs requested to resize */
static bool rs_resize_requested(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	return mddev->array_sectors && rs->ti->len != mddev->array_sectors;
}

/* True if @rs needs a resize */
/* HM FIXME: finalize */
static int rs_new_data_offset_requested(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	if (!rs_resize_requested(rs))
		return 0;

	if (rs->ti->len > mddev->array_sectors &&
	    (rs->flags & DM_RAID_DATA_OFFSET)) {
		unsigned begin_chunks;
		struct md_rdev *rdev;
		sector_t new_data_offset = rs->ti->len - mddev->array_sectors;

		/* Ensure at least 16 chunks to allow for 8 shrinks and 8 grows w/o mandatory additional shifting reshape */
		if (new_data_offset < 16 * mddev->chunk_sectors)
			return -EINVAL;

		begin_chunks = _split_begin_end_chunks(rs, new_data_offset);
		new_data_offset = begin_chunks * mddev->chunk_sectors;
		BUG_ON(sector_div(new_data_offset, rs_data_stripes(rs)));

		rdev_for_each(rdev, mddev)
			rdev->new_data_offset = new_data_offset;

		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	}

	return 0;
}

/* Convenience funtion to check if either takeover, reshape or resize is requested on @rs */
static bool rs_conversion_requested(struct raid_set *rs)
{
	return rs_takeover_requested(rs) || rs_reshape_requested(rs) || rs_resize_requested(rs);
}

static int read_disk_sb(struct md_rdev *rdev)
{
	BUG_ON(!rdev->sb_page);

	if (rdev->sb_loaded)
		return 0;

	if (!sync_page_io(rdev, 0, rdev->sb_size, rdev->sb_page, READ, 1)) {
		DMERR("Failed to read superblock of device at position %d",
		      rdev->raid_disk);
		md_error(rdev->mddev, rdev);
		return -EINVAL;
	}

	rdev->sb_loaded = 1;

	return 0;
}

static void free_raid_dev(struct raid_set *rs, struct raid_dev *rd)
{
	if (rd->meta_dev)
		dm_put_device(rs->ti, rd->meta_dev);

	if (rd->rdev.badblocks.page)
		md_rdev_clear(&rd->rdev);

	if (rd->data_dev)
		dm_put_device(rs->ti, rd->data_dev);

	if (!list_empty(&rd->rdev.same_set))
		list_del(&rd->rdev.same_set);
}

static void context_free(struct raid_set *rs)
{
	struct raid_dev *rd;

	for_each_rd(rd, rs)
		free_raid_dev(rs, rd);

	kfree(rs);
}

static struct raid_set *context_alloc(struct dm_target *ti, struct raid_type *raid_type, unsigned raid_devs)
{
	unsigned i;
	struct raid_set *rs;
	size_t sz = sizeof(*rs) + raid_devs * sizeof(*rs->rds);

	if (raid_devs <= raid_type->parity_devs)
		return ERR_PTR(ti_error_einval(ti, "Insufficient number of devices"));

	rs = kzalloc(sz, GFP_KERNEL);
	if (!rs)
		return ERR_PTR(ti_error_ret(ti, "Cannot allocate raid context", -ENOMEM));

	mddev_init(&rs->md);

	rs->ti = ti;
	rs->md.gendisk = dm_disk(dm_table_get_md(ti->table));
	INIT_WORK(&rs->md.event_work, do_table_event);
	rs->md.sync_super = super_sync;
	rs->callbacks.congested_fn = raid_is_congested;
	dm_table_add_target_callbacks(ti->table, &rs->callbacks);

	ti->private = rs;
	ti->num_flush_bios = 1;

	/* The following members are subject to change in load_and_analyzse_superblocks */
	rs->raid_type = raid_type;
	rs->md.raid_disks = raid_devs;
	rs->md.new_level = raid_type->level;
	rs->md.new_layout = raid_type->algorithm;
	rs->md.delta_disks = 0;
	rs->md.recovery_cp = MaxSector;
	rs->md.reshape_position = MaxSector;
	/* END: The following members are subject... */

	rs->delta_disks = 0;
	rs->raid_disks = raid_devs;

	for (i = 0; i < raid_devs; i++) {
		if (md_rdev_init(&rs->rds[i].rdev)) {
			context_free(rs);
			rs = NULL;
			break;
		}
	}

	/*
	 * Remaining items to be initialized by further RAID params:
	 *  rs->md.persistent
	 *  rs->md.external
	 *  rs->md.chunk_sectors
	 *  rs->md.new_chunk_sectors
	 *  rs->md.dev_sectors
	 */

	return rs;
}

static int get_metadata_device(struct raid_set *rs, const char *dev_name,
			       struct md_rdev *rdev, struct dm_dev **meta_dev)
{
	int r = dm_get_device(rs->ti, dev_name,
			      dm_table_get_mode(rs->ti->table), meta_dev);

	if (r)
		return ti_error_ret(rs->ti, "RAID metadata device lookup failure", r);

	rdev->sb_page = alloc_page(GFP_KERNEL);
	if (rdev->sb_page)
		memset(page_address(rdev->sb_page), 0, PAGE_SIZE);
	else
		r = -ENOMEM;

	return r;
}

static sector_t dev_size_read(struct dm_dev *dm_dev)
{
	return to_sector(i_size_read(dm_dev->bdev->bd_inode));
}

#if 1
/* HM FIXME: REMOVME: devel logging */
static void print_argv(const char *caller, int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; i++)
		DMERR("%s -- argv[%d]=\"%s\"", caller, i, argv[i]);
}

#define DUMP_MEMBER(m, f) DMINFO("%s="f, #m, m)
static void dump_mddev(struct mddev *mddev, const char *msg)
{
	DMINFO("*** %s ***", msg);
	DUMP_MEMBER(mddev->level, "%u");
	DUMP_MEMBER(mddev->layout, "%u");
       	DUMP_MEMBER(mddev->chunk_sectors, "%u");
       	DUMP_MEMBER(mddev->raid_disks, "%u");
       	DUMP_MEMBER(mddev->flags, "%lX");
       	DUMP_MEMBER((unsigned long long) mddev->dev_sectors, "%llu");
       	DUMP_MEMBER((unsigned long long) mddev->array_sectors, "%llu");
       	DUMP_MEMBER((unsigned long long) mddev->reshape_position, "%llu");
       	DUMP_MEMBER(mddev->reshape_backwards, "%d");
       	DUMP_MEMBER((unsigned long long) mddev->recovery_cp, "%llu");

       	DUMP_MEMBER(mddev->delta_disks, "%d");
	DUMP_MEMBER(mddev->new_level, "%u");
	DUMP_MEMBER(mddev->new_layout, "%u");
       	DUMP_MEMBER(mddev->new_chunk_sectors, "%u");
}
#endif

/* Resize RAID set to @new_dev_sectors w/o changing number of RAID disk */
static int __raid_resize(struct raid_set *rs, sector_t new_dev_sectors)
{
	int r;
	sector_t dev_sectors;
	struct mddev *mddev = &rs->md;

	/*
	 * The "new_dev_sectors" is the number of sectors of each device that
	 * is used.  This can only make sense for RAID sets with redundancy.
	 * linear and raid0 always use whatever space is available. We can only
	 * consider changing this number if no resync or reconstruction is
	 * happening, the raid set is fully operational and the new size is
	 * acceptable.
	 */
	mutex_lock(&mddev->reconfig_mutex);
	dev_sectors = mddev->dev_sectors;
	r = md_resize(mddev, new_dev_sectors);
	mutex_unlock(&mddev->reconfig_mutex);

	if (r)
		return ti_error_ret(rs->ti, "RAID set resize failed", r);

	return r;
}

static int raid_resize(struct raid_set *rs)
{
	sector_t new_dev_sectors = rs->ti->len;

	if (is_striped(rs) &&
	    sector_div(new_dev_sectors, rs_data_stripes(rs)))
		return ti_error_einval(rs->ti, "Target length not divisible by number"
					       " of data devices on resize request");

	return __raid_resize(rs, new_dev_sectors);
}

/*
 * Reshape changes RAID algorithm of @rs to new one within personality
 * (e.g. raid6_zr -> raid6_nc), changes stripe size, adds/removes
 * disks from a RAID set thus growing/shrinking it or resizes the set
 */
static int raid_reshape(struct raid_set *rs)
{
	int r;
	struct mddev *mddev = &rs->md;
	struct md_personality *pers = mddev->pers;

	if (!pers->check_reshape)
		return ti_error_einval(rs->ti, "reshape not supported");

	mddev->reshape_backwards = (mddev->delta_disks < 0) ? 1 : 0;

	// set_bit(MD_UPDATE_SB_FLAGS, &mddev->flags);
	r = pers->check_reshape(mddev);
	if (r)
		return ti_error_ret(rs->ti, "check_reshape failed", r);

	/*
	 * Personality may not provide start reshape method in which
	 * case check_reshape above has already covered everything
	 */
	if (pers->start_reshape) {
		r = pers->start_reshape(mddev);
		if (r)
			return ti_error_ret(rs->ti, "start_reshape failed", r);
	}

	return 0;
}

/* Takeover tries switching RAID level between personalities */
static int raid_takeover(struct raid_set *rs, const char *raid_level_name)
{
	int r;
	struct mddev *mddev = &rs->md;
#if 1
	/* HM FIXME: REMOVME: devel logging */
	dump_mddev(mddev, "before takeover");
#endif
	mutex_lock(&mddev->reconfig_mutex);
	set_bit(MD_UPDATE_SB_FLAGS, &mddev->flags);
	r = md_takeover(mddev, raid_level_name);
	mutex_unlock(&mddev->reconfig_mutex);

	if (r)
		return ti_error_ret(rs->ti, "raid takeover failed", r);

	/* Set new raid type after successfull takeover */
	rs->raid_type = get_raid_type_by_ll(mddev->new_level, mddev->new_layout);
	BUG_ON(!rs->raid_type);

#if 1
	/* HM FIXME: REMOVME: devel logging */
	dump_mddev(mddev, "after takeover");
#endif
	return 0;
}

/* Remoe the last rdev from the disks list of @mddev */
static struct md_rdev *rdev_unlist_last(struct mddev *mddev)
{
	struct md_rdev *rdev = list_entry(mddev->disks.prev, struct md_rdev, same_set);

	list_del_init(&rdev->same_set);
	return rdev;
}

/*
 * For @rs, either check valid reshape request and start
 * - or -
 * try takeover from one RAID level to another.
 * - or -
 * resize a RAID set
 */
static int rs_takeover_or_reshape_or_resize(struct raid_set *rs)
{
	bool reshape = false;
	int delta_disks = 0, r;
	struct mddev *mddev = &rs->md;
	struct raid_dev *rd = rs->rds + mddev->raid_disks - 1; /* Set here because mddev->raiddisk changes in takeover */
	struct bitmap *bitmap = mddev->bitmap;

	if (mddev->degraded)
		return ti_error_einval(rs->ti, "can't takeover/reshape/resize degraded RAID set");

	/* Force writing of superblocks to disk */
	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	/* HM FIXME: raid_resize() does not occur, because md_run() already copes with resizing */

	/* Check for resize first */
	if (rs_resize_requested(rs)) {
		r = raid_resize(rs);
		if (r)
			return r;

	}

	/* Takeover: i.e. switch from one RAID level to another */
	if (rs_takeover_requested(rs)) {
		int d;
		bool raid6_down_to_raid5 = mddev->level == 6 && mddev->new_level == 5;
		bool raid5_down_to_raid0 = mddev->level == 5 && !mddev->new_level;

		bool raid1_down_to_raid0 = mddev->level == 1 && !mddev->new_level;
		bool raid5_down_to_raid1 = mddev->level == 5 && mddev->new_level == 1;
		bool raid1_up_to_raid5 = mddev->level == 1 && mddev->new_level == 5;
		char raid_level_name[8];

		r = get_raid_level_name(rs->raid_type, raid_level_name, sizeof(raid_level_name));
		BUG_ON(r);

		/*
		 * Configure takeover prerequisites
		 */
		if (raid6_down_to_raid5) {
			delta_disks = -1;

			/* HM FIXME: TESTME: suspend needed? stable under load? */
			mddev_suspend(mddev);

			/*
			 * md's raid5_takeover_raid6 requires
			 * the Q syndrome disk to be removed
			 */
			mutex_lock(&mddev->reconfig_mutex);
			rdev_unlist_last(mddev);
			mutex_unlock(&mddev->reconfig_mutex);

		} else if (raid5_down_to_raid0) {
			delta_disks = -1;

			/* HM FIXME: TESTME: suspend needed? stable under load? */
			mddev_suspend(mddev);

			/*
			 * md's raid0_takeover_raid45 needs degraded
			 * to be set, the bitmap disabled and the
			 * parity disk removed
			 */
			mutex_lock(&mddev->reconfig_mutex);
			mddev->degraded = 1;
			mddev->bitmap = NULL;
			rdev_unlist_last(mddev);
			mutex_unlock(&mddev->reconfig_mutex);


		/* HM FIXME: correct the following conversions */
		} else if (raid1_up_to_raid5) {
			/* HM FIXME: go figure area size/mapping (i.e. raid5 has le_count = sum(data area sizes) */
			if (mddev->raid_disks != 2)
				return -EINVAL;

		} else if (raid5_down_to_raid1) {
			if (mddev->raid_disks != 3)
				return -EINVAL;

			delta_disks = -1;

			/* HM FIXME: TESTME: stable under load? */
			mddev_suspend(mddev);

			mutex_lock(&mddev->reconfig_mutex);
			// mddev->degraded = 1;
			mddev->raid_disks--;
			rdev_unlist_last(mddev);
			mutex_unlock(&mddev->reconfig_mutex);

		} else if (raid1_down_to_raid0) {
			delta_disks = 1 - mddev->raid_disks;

			/* HM FIXME: TESTME: suspend needed? stable under load? */
			mddev_suspend(mddev);

			mutex_lock(&mddev->reconfig_mutex);
			mddev->degraded = -delta_disks;
			mddev->bitmap = NULL;

			d = delta_disks;
			while (d++)
				rdev_unlist_last(mddev);

			mutex_unlock(&mddev->reconfig_mutex);
		}

		/* Resume on up conversions if suspended before calling the md takeover function */
		if (delta_disks < 0 && mddev->suspended)
			mddev_resume(mddev);

		r = raid_takeover(rs, raid_level_name);

		/* Resume on down conversions if suspended after calling the md takeover function */
		if (mddev->suspended)
			mddev_resume(mddev);


	} else if (rs_reshape_requested(rs)) {
		/* Reshape: i.e. layout changes wrt algoritm, stripe_size, raid_disks w/o level switch */
		reshape = true;
		delta_disks = mddev->delta_disks = rs->delta_disks;
		r = raid_reshape(rs);
	}

	mddev->bitmap = bitmap;

	if (!r) {
		/* raid0 doesn't keep bitmaps */
		if (!mddev->new_level)
			bitmap_destroy(mddev);

		/* HM FIXME: can't remove here on shrinking reshape, because it's still performing */
		if (delta_disks < 0 && !reshape)
			while (delta_disks++)
				raid_dev_remove(rs->ti, rd--);

		if (!mddev->suspended)
			md_wakeup_thread(mddev->thread);
	}

	return r;
}

/*
 * For every device we have two words
 *  <meta_dev>: meta device name or '-' if missing
 *  <data_dev>: data device name or '-' if missing
 *
 * The following are permitted:
 *    - -
 *    - <data_dev>
 *    <meta_dev> <data_dev>
 *
 * The following is not allowed:
 *    <meta_dev> -
 *
 * This code parses those words.  If there is a failure,
 * the caller must use context_free to unwind the operations.
 */
static int parse_dev_params(struct raid_set *rs, struct dm_arg_set *as)
{
	int r = 0;
	int rebuild = 0;
	int metadata_available = 0;
	unsigned i = 0;
	const char *arg;
	struct raid_dev *rd;
	struct md_rdev *rdev;

	for_each_rd(rd, rs) {
		rdev = &rd->rdev;
		rdev->raid_disk = i++;

		rd->meta_dev = rd->data_dev = NULL;

		/*
		 * There are no offsets, since there is a separate device
		 * for data and metadata.
		 */
		rdev->data_offset = 0;
		rdev->mddev = &rs->md;

		arg = dm_shift_arg(as);
		if (strcmp(arg, "-")) {
			r = get_metadata_device(rs, arg, rdev, &rd->meta_dev);
			if (r)
				return ti_error_ret(rs->ti, "RAID metadata device lookup failure", r);
		}

		arg = dm_shift_arg(as);
		if (!strcmp(arg, "-")) {
			if (!test_bit(In_sync, &rdev->flags) &&
			    !rdev->recovery_offset)
				return ti_error_einval(rs->ti, "Drive designated for rebuild not specified");

			if (rd->meta_dev)
				return ti_error_einval(rs->ti, "No data device supplied with metadata device");

			continue;
		}

		r = dm_get_device(rs->ti, arg, dm_table_get_mode(rs->ti->table), &rd->data_dev);
		if (r)
			return ti_error_ret(rs->ti, "RAID device lookup failure", r);

		if (rd->meta_dev) {
			metadata_available = 1;
			rdev->meta_bdev = rd->meta_dev->bdev;
		}

		rdev->bdev = rd->data_dev->bdev;
		rdev->sectors = dev_size_read(rd->data_dev);
		list_add_tail(&rdev->same_set, &rs->md.disks);
		if (!test_bit(In_sync, &rdev->flags))
			rebuild++;
	}

	if (metadata_available) {
		rs->md.external = 0;
		rs->md.persistent = 1;
		rs->md.major_version = 2;
	} else if (rebuild) {
		/*
		 * Without metadata, we will not be able to tell if the RAID set
		 * is in-sync or not - we must assume it is not.  Therefore,
		 * it is impossible to rebuild a drive.
		 *
		 * Even if there is metadata, the on-disk information may
		 * indicate that the RAID set is not in-sync and it will then
		 * fail at that time.
		 *
		 * User could specify 'nosync' option if desperate.
		 */
		DMERR("Unable to rebuild drive while RAID set is not in-sync");
		return ti_error_einval(rs->ti, "RAID device lookup failure");
	}

	return 0;
}

/*
 * validate_region_size
 * @rs
 * @region_size:  region size in sectors.  If 0, pick a size (4MiB default).
 *
 * Set rs->md.bitmap_info.chunksize (which really refers to 'region size').
 * Ensure that (ti->len/region_size < 2^21) - required by MD bitmap.
 *
 * Returns: 0 on success, -EINVAL on failure.
 */
static int validate_region_size(struct raid_set *rs, unsigned long region_size)
{
	unsigned long min_region_size = rs->ti->len / (1 << 21);

	if (!region_size) {
		/*
		 * Choose a reasonable default.  All figures in sectors.
		 */
		if (min_region_size > (1 << 13)) {
			/* If not a power of 2, make it the next power of 2 */
			region_size = roundup_pow_of_two(min_region_size);
			DMINFO("Choosing region size of %lu sectors", region_size);
		} else {
			region_size = 1 << 13; /* sectors */
			DMINFO("Choosing default region size of 4MiB");
		}
	} else {
		/*
		 * Validate user-supplied value.
		 */
		if (region_size > rs->ti->len)
			return ti_error_einval(rs->ti, "Supplied region size is too large");

		if (region_size < min_region_size) {
			DMERR("Supplied region_size (%lu sectors) below minimum (%lu)",
			      region_size, min_region_size);
			return ti_error_einval(rs->ti, "Supplied region size is too small");
		}

		if (!is_power_of_2(region_size))
			return ti_error_einval(rs->ti, "Region size is not a power of 2");

		if (region_size < rs->md.chunk_sectors)
			return ti_error_einval(rs->ti, "Region size is smaller than the chunk size");
	}

	/*
	 * Convert sectors to bytes.
	 */
	rs->md.bitmap_info.chunksize = to_bytes(region_size);

	return 0;
}

/*
 * validate_raid_redundancy
 * @rs
 *
 * Determine if there are enough devices in the RAID set that haven't
 * failed (or are being rebuilt) to form a usable RAID set.
 *
 * Returns: 0 on success, -EINVAL on failure.
 */
static int validate_raid_redundancy(struct raid_set *rs)
{
	int raid_disks = 0;
	unsigned i = 0, rebuild_cnt = 0;
	unsigned rebuilds_per_group = 0, copies;
	unsigned group_size, last_group_start;
	struct mddev *mddev = &rs->md;
	struct md_rdev *rdev;

	rdev_for_each(rdev, mddev) {
		raid_disks++;
		if (!test_bit(In_sync, &rdev->flags) ||
		    !rdev->sb_page)
			rebuild_cnt++;
	}

	switch (mddev->level) {
	case 0:
		if (rebuild_cnt > 1)
			goto too_many;
		break;
	case 1:
		if (rebuild_cnt >= raid_disks)
			goto too_many;
		break;
	case 4:
	case 5:
	case 6:
		if (rebuild_cnt > rs->raid_type->parity_devs)
			goto too_many;
		break;
	case 10:
		copies = raid10_md_layout_to_copies(rs->md.layout);
		if (rebuild_cnt < copies)
			break;

		/*
		 * It is possible to have a higher rebuild count for RAID10,
		 * as long as the failed devices occur in different mirror
		 * groups (i.e. different stripes).
		 *
		 * When checking "near" format, make sure no adjacent devices
		 * have failed beyond what can be handled.  In addition to the
		 * simple case where the number of devices is a multiple of the
		 * number of copies, we must also handle cases where the number
		 * of devices is not a multiple of the number of copies.
		 * E.g.    dev1 dev2 dev3 dev4 dev5
		 *          A    A    B    B    C
		 *          C    D    D    E    E
		 */
		if (!strcasecmp("near", raid10_md_layout_to_format(rs->md.layout))) {
			for (i = 0; i < raid_disks * copies; i++) {
				if (!(i % copies))
					rebuilds_per_group = 0;
				rdev = &(rs->rds + (i & raid_disks))->rdev;
				if ((!rdev->sb_page ||
				     !test_bit(In_sync, &rdev->flags)) &&
				     ++rebuilds_per_group >= copies)
					goto too_many;
			}
			break;
		}

		/*
		 * When checking "far" and "offset" formats, we need to ensure
		 * that the device that holds its copy is not also dead or
		 * being rebuilt.  (Note that "far" and "offset" formats only
		 * support two copies right now.  These formats also only ever
		 * use the 'use_far_sets' variant.)
		 *
		 * This check is somewhat complicated by the need to account
		 * for RAID sets that are not a multiple of (far) copies.  This
		 * results in the need to treat the last (potentially larger)
		 * set differently.
		 */
		group_size = (rs->md.raid_disks / copies);
		last_group_start = (rs->md.raid_disks / group_size) - 1;
		last_group_start *= group_size;
		i = 0;
		rdev_for_each(rdev, mddev) {
			if (!(i % copies) && !(i > last_group_start))
				rebuilds_per_group = 0;
			if ((!rdev->sb_page ||
			     !test_bit(In_sync, &rdev->flags)) &&
			    (++rebuilds_per_group >= copies))
					goto too_many;
			i++;
		}

		break;
	default:
		if (rebuild_cnt)
			return -EINVAL;
	}

	if (mddev->raid_disks > raid_disks)
		mddev->raid_disks = raid_disks;

	return 0;

too_many:
	return -EINVAL;
}

/*
 * Possible arguments are...
 *	<chunk_size> [optional_args]
 *
 * Argument definitions
 *    <chunk_size>			The number of sectors per disk that
 *                                      will form the "stripe"
 *    [data_offset]			Reshape: request data offset change on each
 *    					raid disk image; offset calculated from
 *    					ti->len vs. given array size
 *    [ignore_discard]                  Ignore any discards;
 *                                      can be used in cases of bogus TRIM/UNMAP
 *                                      support on RAID set legs (e.g. discard_zeroes_data
 *                                      flaw causing RAID4/5/6 corruption)
 *    [[no]sync]			Force or prevent recovery of the
 *                                      entire RAID set; ürohibited with reshape_{add,remove}
 *    [delta_disks #+/-disks]		Reshape: add/remove the amount of disks to the RAID set
 *                                      listed at the end of the table line
 *    [rebuild <idx>]			Rebuild the drive indicated by the index
 *    [daemon_sleep <ms>]		Time between bitmap daemon work to
 *                                      clear bits
 *    [min_recovery_rate <kB/sec/disk>]	Throttle RAID initialization
 *    [max_recovery_rate <kB/sec/disk>]	Throttle RAID initialization
 *    [write_mostly <idx>]		Indicate a write mostly drive via index
 *    [max_write_behind <sectors>]	See '-write-behind=' (man mdadm)
 *    [stripe_cache <sectors>]		Stripe cache size for higher RAIDs
 *    [region_size <sectors>]           Defines granularity of bitmap
 *
 * RAID10-only options:
 *    [raid10_copies <# copies>]        Number of copies.  (Default: 2)
 *    [raid10_format <near|far|offset>] Layout algorithm.  (Default: near)
 */
static int parse_raid_params(struct raid_set *rs, struct dm_arg_set *as,
			     unsigned num_raid_params)
{
	unsigned raid10_copies = 2, rebuilds = 0, writemostly = 0;
	unsigned i;
	int value, region_size = 0;
	const char *arg, *key, *raid10_format = "near";
	sector_t sectors_per_dev = rs->ti->len;
	sector_t max_io_len;
	struct raid_dev *rd;
	struct dm_arg _args = { 0, UINT_MAX, "Bad chunk size"};

	/*
	 * First, parse the in-order required arguments
	 * "chunk_size" is the only argument of this type.
	 */
	if (dm_read_arg(&_args, as, &value, &rs->ti->error))
		return -EINVAL;

	num_raid_params--;
	if (rs->raid_type->level == 1) {
		if (value)
			DMERR("Ignoring chunk size parameter for RAID 1");
		value = 0;
	} else if (value < 8)
		/* HM FIXME: workaround for userspace passing in 0 for takeover from raid1 -> raid4 */
		value = 8;
	else if (!is_power_of_2(value))
		return ti_error_einval(rs->ti, "Chunk size must be a power of 2");
	else if (value < 8)
		return ti_error_einval(rs->ti, "Chunk size value is too small");

	rs->md.new_chunk_sectors = value;

	/* HM FIXME: add reshape/takeover/shrink related comments */
	/*
	 * We set each individual device as In_sync with a completed
	 * 'recovery_offset'.  If there has been a device failure or
	 * replacement then one of the following cases applies:
	 *
	 *
	 *   1) User specifies 'rebuild'.
	 *      - Device is reset when param is read.
	 *   2) A new device is supplied.
	 *      - No matching superblock found, resets device.
	 *   3) Device failure was transient and returns on reload.
	 *      - Failure noticed, resets device for bitmap replay.
	 *   4) Device hadn't completed recovery after previous failure.
	 *      - Superblock is read and overrides recovery_offset.
	 *
	 * What is found in the superblocks of the devices is always
	 * authoritative, unless 'rebuild' or '[no]sync' was specified
	 */
	for_each_rd(rd, rs) {
		set_bit(In_sync, &rd->rdev.flags);
		rd->rdev.recovery_offset = MaxSector;
	}

	/*
	 * Second, parse the unordered optional arguments
	 */
	for (i = 0; i < num_raid_params; i++) {
		arg = dm_shift_arg(as);

		if (!strcasecmp(arg, "date_offset")) {
			rs->flags |= DM_RAID_DATA_OFFSET;
			continue;
		}
		if (!strcasecmp(arg, "ignore_discard")) {
			rs->flags |= DM_RAID_IGNORE_DISCARD;
			continue;
		}
		if (!strcasecmp(arg, "nosync")) {
			rs->flags |= DM_RAID_NOSYNC;
			continue;
		}
		if (!strcasecmp(arg, "sync")) {
			rs->flags |= DM_RAID_SYNC;
			continue;
		}

		/* The rest of the optional arguments come in key/value pairs */
		if (i > num_raid_params)
			return ti_error_einval(rs->ti, "Wrong number of raid parameters given");

		i++; /* Account for the pairs */
		key = arg;
		arg = dm_shift_arg(as);

		/* Parameters that take a string value are checked here. */
		if (!strcasecmp(key, "raid10_format")) {
			if (rs->flags & DM_RAID_RAID10_FORMAT)
				return ti_error_einval(rs->ti, "Only one raid10_format argument set allowed");

			if (rs->raid_type->level != 10)
				return ti_error_einval(rs->ti, "'raid10_format' is an invalid parameter for this RAID type");

			if (strcasecmp("near", arg) &&
			    strcasecmp("far", arg) &&
			    strcasecmp("offset", arg))
				return ti_error_einval(rs->ti, "Invalid 'raid10_format' value given");

			raid10_format = arg;
			rs->flags |= DM_RAID_RAID10_FORMAT;
			continue;
		}

		/* Parameters that take a numeric value are checked here */
		if (kstrtoint(arg, 10, &value) < 0)
			return ti_error_einval(rs->ti, "Bad numerical argument given in raid params");

		if (!strcasecmp(key, "daemon_sleep")) {
			if (rs->flags & DM_RAID_DAEMON_SLEEP)
				return ti_error_einval(rs->ti, "Only one daemon_sleep argument set allowed");

			rs->flags |= DM_RAID_DAEMON_SLEEP;
			if (set_daemon_sleep(rs, value))
				return -EINVAL;

		} else if (!strcasecmp(key, "delta_disks")) {
			if (rs->flags & DM_RAID_RESHAPE)
				return ti_error_einval(rs->ti, "Only one delta_disks argument set allowed");

			/* Ensure MAX_RAD_DEVICES and raid type minimal_devs! */
			if (!__in_range(value, 1, MAX_RAID_DEVICES - rs->md.raid_disks) &&
			    !__in_range(value, rs->raid_type->minimal_devs - rs->raid_disks, -1))
				return ti_error_einval(rs->ti, "Too many delta_disk requested");

			rs->delta_disks = value;
			rs->flags |= DM_RAID_RESHAPE | DM_RAID_DELTA_DISKS;
			
		} else if (!strcasecmp(key, "min_recovery_rate")) {
			if (rs->flags & DM_RAID_MIN_RECOVERY_RATE)
				return ti_error_einval(rs->ti, "Only one min_recovery_rate argument set allowed");

			rs->flags |= DM_RAID_MIN_RECOVERY_RATE;
			if (set_recovery_rate(rs, value, true))
				return -EINVAL;

		} else if (!strcasecmp(key, "max_recovery_rate")) {
			if (rs->flags & DM_RAID_MAX_RECOVERY_RATE)
				return ti_error_einval(rs->ti, "Only one max_recovery_rate argument set allowed");

			rs->flags |= DM_RAID_MAX_RECOVERY_RATE;
			if (set_recovery_rate(rs, value, false))
				return -EINVAL;

		} else if (!strcasecmp(key, "max_write_behind")) {
			if (rs->flags & DM_RAID_MAX_WRITE_BEHIND)
				return ti_error_einval(rs->ti, "Only one max_write_behind argument set allowed");

			rs->flags |= DM_RAID_MAX_WRITE_BEHIND;
			if (set_max_write_behind(rs, value))
				return -EINVAL;

		} else if (!strcasecmp(key, "raid10_copies") &&
			   (rs->raid_type->level == 10)) {
			if (rs->flags & DM_RAID_RAID10_COPIES)
				return ti_error_einval(rs->ti, "Only one raid10_copies argument set allowed");

			if (value < 2 || value > 0xFF)
				return ti_error_einval(rs->ti, "Bad value for 'raid10_copies'");

			rs->flags |= DM_RAID_RAID10_COPIES;
			raid10_copies = value;

		} else if (!strcasecmp(key, "rebuild")) {
			if (!__in_range(value, 0, rs->md.raid_disks - 1))
				return ti_error_einval(rs->ti, "Invalid rebuild index given");

			rd = rs->rds + value;
			clear_bit(In_sync, &rd->rdev.flags);
			rd->rdev.recovery_offset = 0;
			rebuilds++;
			rs->flags |= DM_RAID_REBUILD;

		} else if (!strcasecmp(key, "region_size")) {
			if (rs->flags & DM_RAID_REGION_SIZE)
				return ti_error_einval(rs->ti, "Only one region_size argument set allowed");

			rs->flags |= DM_RAID_REGION_SIZE;
			region_size = value;

		} else if (!strcasecmp(key, "stripe_cache")) {
			if (rs->flags & DM_RAID_STRIPE_CACHE)
				return ti_error_einval(rs->ti, "Only one stripe_cache argument set allowed");

			if (!is_raid456(rs))
				return ti_error_einval(rs->ti, "Inappropriate argument: stripe_cache");

			rs->flags |= DM_RAID_STRIPE_CACHE;

			/*
			 * In device-mapper, we specify things in sectors, but
			 * MD records this value in kB
			 */
			value /= 2;

			if (raid5_set_cache_size(&rs->md, (int)value)) 
				return ti_error_einval(rs->ti, "Bad stripe_cache size");

		} else if (!strcasecmp(key, "write_mostly")) {
			if (rs->raid_type->level != 1)
				return ti_error_einval(rs->ti, "write_mostly option is only valid for RAID1");

			if (!__in_range(value, 0, rs->md.raid_disks - 1))
				return ti_error_einval(rs->ti, "Invalid write_mostly drive index given");

			rd = rs->rds + value;
			writemostly++;
			set_bit(WriteMostly, &rd->rdev.flags);

		} else
			return ti_error_einval(rs->ti, "Unable to parse RAID parameters");
	}

	/* Prevent all raid disks from being set write_mostly */
	if (writemostly == rs->md.raid_disks)
		return ti_error_einval(rs->ti, "Can't set all raid disks write_mostly");


	/* Prevent all raid disks from being requested to rebuild */
	if (rebuilds == rs->md.raid_disks)
		return ti_error_einval(rs->ti, "Can't rebuild all raid disks");

	if ((rs->flags & DM_RAID_SYNC) &&
	    (rs->flags & DM_RAID_NOSYNC))
		return ti_error_einval(rs->ti, "Nosync and sync are mutually exclusive");

	/* Check for invalid RAID0 arguments */
	if (!rs->raid_type->level &&
	    rs->flags & (DM_RAID_DATA_OFFSET |
			 DM_RAID_DELTA_DISKS |
			 DM_RAID_NOSYNC |
			 DM_RAID_SYNC |
			 DM_RAID_REBUILD |
		 	 DM_RAID_DAEMON_SLEEP |
			 DM_RAID_MIN_RECOVERY_RATE |
			 DM_RAID_MAX_RECOVERY_RATE |
			 DM_RAID_MAX_WRITE_BEHIND |
			 DM_RAID_STRIPE_CACHE |
			 DM_RAID_REGION_SIZE |
			 DM_RAID_RAID10_COPIES |
			 DM_RAID_RAID10_FORMAT))
		return ti_error_einval(rs->ti,
				       "data_offset/delta_disks/sync/nosync/rebuild/recovery_rate/reshape/max_write_behind/"
				       "stripe_cache/region_size/raid10_copies/raid10_fromat are invalid with RAID0");

	/* Check for invalid RAID1 arguments */
	if (rs->raid_type->level == 1 &&
	    rs->flags & (DM_RAID_DATA_OFFSET |
			 DM_RAID_DELTA_DISKS |
			 DM_RAID_STRIPE_CACHE |
			 DM_RAID_RAID10_COPIES |
			 DM_RAID_RAID10_FORMAT))
		return ti_error_einval(rs->ti,
				       "data_offset/delta_disks/stripe_cache/raid10_copies/raid10_fromat are invalid with RAID1");

	/* Check for invalid RAID10 arguments */
	if (rs->raid_type->level == 10 &&
	    rs->flags & (DM_RAID_DELTA_DISKS |
			 DM_RAID_DELTA_DISKS |
			 DM_RAID_STRIPE_CACHE))
		return ti_error_einval(rs->ti,
				       "delta_disks/reshape/stripe_cache are invalid with RAID10");

	/* Check for RAID 10 arguments supplied with other levels */
	if (rs->raid_type->level != 10 &&
	    rs->flags & (DM_RAID_RAID10_COPIES |
			 DM_RAID_RAID10_FORMAT))
		return ti_error_einval(rs->ti, "copies/format only suitable with RAID10");

	/* Check for arguments unsuitable to reshape */
	if ((rs->flags & DM_RAID_DELTA_DISKS) &&
	    (rs->flags & (DM_RAID_SYNC|DM_RAID_NOSYNC)))
		return ti_error_einval(rs->ti, "Sync/nosync and reshape are mutually exclusive");

	if (rs->raid_type->level &&
	    validate_region_size(rs, region_size))
		return -EINVAL;

	max_io_len = rs->md.chunk_sectors ?: region_size;

	if (dm_set_target_max_io_len(rs->ti, max_io_len))
		return -EINVAL;

	if (rs->raid_type->level == 10) {
		if (raid10_copies > rs->md.raid_disks)
			return ti_error_einval(rs->ti, "Not enough devices to satisfy specification");

		/*
		 * If the format is not "near", we only support
		 * two copies at the moment.
		 */
		if (strcasecmp("near", raid10_format) && (raid10_copies > 2))
			return ti_error_einval(rs->ti, "Too many copies for given RAID10 format.");

		/* (Len * #mirrors) / #devices */
		sectors_per_dev = rs->ti->len * raid10_copies;
		sector_div(sectors_per_dev, rs->md.raid_disks);

		rs->md.layout = raid10_format_to_md_layout(raid10_format,
							   raid10_copies);
		rs->md.new_layout = rs->md.layout;

		rs->md.dev_sectors = sectors_per_dev;
	}
#if 0
	/*
	 * HM FIXME: this one has to move to start of raid set to
	 *	     allow for takeover down conversions.
	 *
	 *	     The other ones above, e.g. for raid10 need checking
	 *	     as well once I get to the repective conversions!
	 */
	} else if (is_striped(rs)) &&
		   sector_div(sectors_per_dev, rs_data_stripes(rs))) 
		/* FIXME: workaround -> return once fixed */
		return ti_error_einval(rs->ti, "Target length not divisible by number of data devices");

	rs->md.dev_sectors = sectors_per_dev;
#endif

	/* Assume there are no metadata devices until the drives are parsed */
	rs->md.persistent = 0;
	rs->md.external = 1;

	return 0;
}

/*  Features */
#define	DM_RAID_SUPPORTS_RESHAPE	0x1

/* State flags */
#define	DM_RAID_RESHAPE_ACTIVE		0x1
#define	DM_RAID_RESHAPE_BACKWARDS	0x2

/*
 * This structure is never routinely used by userspace, unlike md superblocks.
 * Devices with this superblock should only ever be accessed via device-mapper.
 */
#define DM_RAID_MAGIC 0x64526D44
struct dm_raid_superblock {
	__le32 magic;		/* "DmRd" */
	__le32 features;	/* Used to indicate possible future changes */

	__le32 num_devices;	/* Number of devices in this RAID set. (Max 64) */
	__le32 array_position;	/* The position of this drive in the RAID set */

	__le64 events;		/* Incremented by md when superblock updated */
	__le64 failed_devices;	/* Bit field of devices to indicate failures */

	/*
	 * This offset tracks the progress of the repair or replacement of
	 * an individual drive.
	 */
	__le64 disk_recovery_offset;

	/*
	 * This offset tracks the progress of the initial RAID set
	 * synchronisation/parity calculation.
	 */
	__le64 array_resync_offset;

	/*
	 * RAID characteristics
	 */
	__le32 level;
	__le32 layout;
	__le32 stripe_sectors;

	/*
	 * BELOW FOLLOW ADDITIONS TO THE PRISTINE SUPERBLOCK FORMAT!!!
	 *
	 * DM_RAID_SUPPORTS_RESHAPE indicates those exist in the features member
	 */

	/* Flags defining array states for reshaping */
	__le32 flags;

	/*
	 * This offset tracks the progress of a RAID
	 * set reshape in order to be able to restart it
	 */
	__le64 array_reshape_position;

	/*
	 * These define the properties of the array in case of an interrupted reshape
	 */
	__le32 new_layout;
	__le32 delta_disks;
	__le32 new_level;
	__le32 new_stripe_sectors;

	/* Array size in sectors */
	__le64 array_sectors;

	/*
 	 * Sector offsets to data on devices (reshaping)
 	 */
	__le64 data_offset;
	__le64 new_data_offset;
	/* Used device size in sectors */
	__le64 sectors;

	/* Always set rest up to logical block size to 0 when writing (see super_sync() below). */
} __packed;

static void super_sync(struct mddev *mddev, struct md_rdev *rdev)
{
	unsigned i = 0;
	uint64_t failed_devices;
	struct dm_raid_superblock *sb;
	struct raid_set *rs = container_of(mddev, struct raid_set, md);
	struct raid_dev *rd;

	sb = page_address(rdev->sb_page);
	memset(sb, 0, sizeof(*sb));

	failed_devices = le64_to_cpu(sb->failed_devices);

	for_each_rd(rd, rs)
		if (!rd->data_dev || test_bit(Faulty, &rd->rdev.flags))
			failed_devices |= (1ULL << i++);

	sb->magic = cpu_to_le32(DM_RAID_MAGIC);
	sb->features = cpu_to_le32(DM_RAID_SUPPORTS_RESHAPE);

	sb->num_devices = cpu_to_le32(mddev->raid_disks);
	sb->array_position = cpu_to_le32(rdev->raid_disk);

	sb->events = cpu_to_le64(mddev->events);
	sb->failed_devices = cpu_to_le64(failed_devices);

	sb->disk_recovery_offset = cpu_to_le64(rdev->recovery_offset);
	sb->array_resync_offset = cpu_to_le64(mddev->recovery_cp);
	sb->array_reshape_position = cpu_to_le64(mddev->reshape_position);

	sb->level = cpu_to_le32(mddev->level);
	sb->layout = cpu_to_le32(mddev->layout);
	sb->stripe_sectors = cpu_to_le32(mddev->chunk_sectors);

	sb->new_level = cpu_to_le32(mddev->new_level);
	sb->new_layout = cpu_to_le32(mddev->new_layout);
	sb->new_stripe_sectors = cpu_to_le32(mddev->new_chunk_sectors);

	sb->delta_disks = cpu_to_le32(mddev->delta_disks);

	if (mddev->reshape_position != MaxSector) {
		/* Flag ongoing reshape */
		sb->flags |= cpu_to_le32(DM_RAID_RESHAPE_ACTIVE);

		if (mddev->delta_disks < 0 ||
		    (!mddev->delta_disks && mddev->reshape_backwards))
			sb->flags |= cpu_to_le32(DM_RAID_RESHAPE_BACKWARDS);
	} else
		/* Flag no reshape */
		sb->flags &= cpu_to_le32(~(DM_RAID_RESHAPE_ACTIVE|DM_RAID_RESHAPE_BACKWARDS));

	sb->array_sectors = cpu_to_le64(mddev->array_sectors);
	sb->data_offset = cpu_to_le64(rdev->data_offset);
	sb->new_data_offset = cpu_to_le64(rdev->new_data_offset);
	sb->sectors = cpu_to_le64(rdev->sectors);
}

/*
 * super_load
 *
 * This function creates a superblock if one is not found on the device
 * and will decide which superblock to use if there's a choice.
 *
 * Return: 1 if use rdev, 0 if use refdev, -Exxx otherwise
 */
static int super_load(struct raid_set *rs, struct md_rdev *rdev, struct md_rdev *refdev)
{
	struct dm_raid_superblock *sb = page_address(rdev->sb_page);
	struct dm_raid_superblock *refsb;
	uint64_t events_sb, events_refsb;

	/* Superblock is at offset 0 on metadata device */
	rdev->sb_start = 0;

	/* Make sure to cope with 4K sectored devices */
	rdev->sb_size = bdev_logical_block_size(rdev->meta_bdev);
	if (rdev->sb_size < sizeof(*sb) || rdev->sb_size > PAGE_SIZE) {
		DMERR("superblock size missmatch");
		return -EINVAL;
	}

	if (read_disk_sb(rdev))
		return -EIO;

	/*
	 * Two cases that we want to write new superblocks and rebuild:
	 * 1) New device (no matching magic number)
	 * 2) Device specified for rebuild (!In_sync w/ offset == 0)
	 */
	if ((sb->magic != cpu_to_le32(DM_RAID_MAGIC)) ||
	    (!test_bit(In_sync, &rdev->flags) && !rdev->recovery_offset)) {
		struct mddev *mddev = rdev->mddev;

		rs_set_new(rs);
		super_sync(mddev, rdev);

		set_bit(FirstUse, &rdev->flags);

		/* Force writing of superblocks to disk */
		set_bit(MD_CHANGE_DEVS, &mddev->flags);

		/* Any superblock is better than none, choose that if given */
		return refdev ? 0 : 1;
	}

	if (!refdev)
		return 1;

	events_sb = le64_to_cpu(sb->events);
	refsb = page_address(refdev->sb_page);
	events_refsb = le64_to_cpu(refsb->events);

	return (events_sb > events_refsb) ? 1 : 0;
}

/*
 * Validate the freshest raid device passed in
 */
static int super_validate_freshest(struct raid_set *rs, struct md_rdev *rdev)
{
	int role;
	struct mddev *mddev = &rs->md;
	uint64_t events_sb;
	uint64_t failed_devices;
	struct dm_raid_superblock *sb;
	uint32_t new_devs = 0;
	uint32_t rebuilds = 0;
	struct md_rdev *r;
	struct dm_raid_superblock *sb2;

	sb = page_address(rdev->sb_page);
	events_sb = le64_to_cpu(sb->events);
	failed_devices = le64_to_cpu(sb->failed_devices);

	/*
	 * Initialise to 1 if this is a new superblock.
	 */
	mddev->events = events_sb ? : 1;

	/*
	 * Reshaping is supported, i.e. array_reshape_position is valid in superblock
	 * Superblock content is authoritative.
	 */
	if (DM_RAID_SUPPORTS_RESHAPE & le32_to_cpu(sb->features)) {
		/* Superblock is authoritative wrt given layout! */
		mddev->raid_disks = le32_to_cpu(sb->num_devices);
		mddev->level = le32_to_cpu(sb->level);
		mddev->layout = le32_to_cpu(sb->layout);
		mddev->chunk_sectors = le32_to_cpu(sb->stripe_sectors);
		mddev->delta_disks = le32_to_cpu(sb->delta_disks);

		/* RAID was reshaping and got interrupted */
		if (le32_to_cpu(sb->flags) & DM_RAID_RESHAPE_ACTIVE) {
			if (rs->flags & DM_RAID_RESHAPE) {
				DMERR("Reshape requested but RAID set is still reshaping");
				return -EINVAL;
			}

			mddev->new_level = le32_to_cpu(sb->new_level);
			mddev->new_layout = le32_to_cpu(sb->new_layout);
			mddev->new_chunk_sectors = le32_to_cpu(sb->new_stripe_sectors);
			mddev->delta_disks = le32_to_cpu(sb->delta_disks);

			if (mddev->delta_disks < 0 ||
			    (!mddev->delta_disks && (le32_to_cpu(sb->flags) & DM_RAID_RESHAPE_BACKWARDS)))
				mddev->reshape_backwards = 1;

			mddev->reshape_position = le64_to_cpu(sb->array_reshape_position);
			rs->raid_type = get_raid_type_by_ll(mddev->level, mddev->layout);
		} else
			mddev->array_sectors = le64_to_cpu(sb->array_sectors);

	} else {
		/* Table line is checked vs. authoritative superblock */
		rs_set_new(rs);

		/*
		 * Reshaping is not allowed, bacause we don't have the appropriate metadata
		 */
		if (le32_to_cpu(sb->level) != mddev->level) {
			DMERR("Reshaping RAID sets not yet supported. (RAID level/stripes/size change)");
			return -EINVAL;
		}
		if (le32_to_cpu(sb->layout) != mddev->layout) {
			DMERR("Reshaping RAID sets not yet supported. (RAID layout change)");
			DMERR("  0x%X vs 0x%X", le32_to_cpu(sb->layout), mddev->layout);
			DMERR("  Old layout: %s w/ %d copies",
			      raid10_md_layout_to_format(le32_to_cpu(sb->layout)),
			      raid10_md_layout_to_copies(le32_to_cpu(sb->layout)));
			DMERR("  New layout: %s w/ %d copies",
			      raid10_md_layout_to_format(mddev->layout),
			      raid10_md_layout_to_copies(mddev->layout));
			return -EINVAL;
		}
		if (le32_to_cpu(sb->stripe_sectors) != mddev->chunk_sectors) {
			DMERR("Reshaping RAID sets not yet supported. (stripe sectors change)");
			return -EINVAL;
		}

		/* We can only change the number of devices in RAID1 right now */
		if ((rs->raid_type->level != 1) &&
		    (le32_to_cpu(sb->num_devices) != mddev->raid_disks)) {
			DMERR("Reshaping RAID sets not yet supported. (device count change from %u to %u)",
			      sb->num_devices, mddev->raid_disks);
			return -EINVAL;
		}
	}

	if (!(rs->flags & DM_RAID_NOSYNC))
		mddev->recovery_cp = le64_to_cpu(sb->array_resync_offset);

#if 1
	dump_mddev(mddev, __func__);
#endif

	/* HM FIXME: logic below wrong for reshape?! */
	/*
	 * During load, we set FirstUse if a new superblock was written.
	 * There are two reasons we might not have a superblock:
	 * 1) The RAID set is brand new - in which case, all of the
	 *    devices must have their In_sync bit set.  Also,
	 *    recovery_cp must be 0, unless forced.
	 * 2) This is a new device being added to an old RAID set
	 *    and the new device needs to be rebuilt - in which
	 *    case the In_sync bit will /not/ be set and
	 *    recovery_cp must be MaxSector.
	 */
	rdev_for_each(r, mddev) {
		if (test_bit(FirstUse, &r->flags))
			new_devs++;
		else if (!test_bit(In_sync, &r->flags)) {
			DMINFO("Device %d specified for rebuild: "
			       "Clearing superblock", r->raid_disk);
			rebuilds++;
		}
	}

	if (!rebuilds) {
		if (new_devs == 1 && !rs->delta_disks)
			;
		else if (new_devs == mddev->raid_disks) {
			DMINFO("Superblocks created for new RAID set");
			set_bit(MD_ARRAY_FIRST_USE, &mddev->flags);
			if (mddev->new_level)
				mddev->recovery_cp = 0;
		} else if (new_devs && !(rs->flags & DM_RAID_RESHAPE) && !(rs->flags & DM_RAID_REBUILD)) {
			DMERR("New device injected into existing RAID set without "
			      "'delta_disks' or 'rebuild' parameter specified");
			return -EINVAL;
		}
	} else if (new_devs) {
		DMERR("'rebuild' devices cannot be injected into"
		      " an RAID set with other first-time devices");
		return -EINVAL;
	} else if (mddev->recovery_cp != MaxSector) {
		DMERR("'rebuild' specified while RAID set is not in-sync");
		return -EINVAL;
	} else if (mddev->reshape_position != MaxSector) {
		DMERR("'rebuild' specified while RAID set is being reshaped");
		return -EINVAL;
	}

	/*
	 * Now we set the Faulty bit for those devices that are
	 * recorded in the superblock as failed.
	 */
	rdev_for_each(rdev, mddev) {
		if (!r->sb_page)
			continue;
		sb2 = page_address(r->sb_page);
		sb2->failed_devices = 0;

		/*
		 * Check for any device re-ordering.
		 */
		if (!test_bit(FirstUse, &r->flags) && (r->raid_disk >= 0)) {
			role = le32_to_cpu(sb2->array_position);
			if (role != r->raid_disk) {
				if (rs->raid_type->level != 1)
					return ti_error_einval(rs->ti, "Cannot change device positions in RAID set");

				DMINFO("RAID1 device #%d now at position #%d",
				       role, r->raid_disk);
			}

			/*
			 * Partial recovery is performed on
			 * returning failed devices.
			 */
			if (failed_devices & (1 << role))
				set_bit(Faulty, &r->flags);
		}
	}

	return 0;
}

static int super_validate(struct raid_set *rs, struct md_rdev *rdev)
{
	struct dm_raid_superblock *sb = page_address(rdev->sb_page);

	if (!test_and_clear_bit(FirstUse, &rdev->flags)) {
		rdev->recovery_offset = le64_to_cpu(sb->disk_recovery_offset);
		if (rdev->recovery_offset != MaxSector)
			clear_bit(In_sync, &rdev->flags);
	}

	/*
	 * If a device comes back, set it as not In_sync and no longer faulty.
	 */
	if (test_and_clear_bit(Faulty, &rdev->flags)) {
		clear_bit(In_sync, &rdev->flags);
		rdev->saved_raid_disk = rdev->raid_disk;
		rdev->recovery_offset = 0;
	}

	if (DM_RAID_SUPPORTS_RESHAPE & le32_to_cpu(sb->features)) {
		rdev->data_offset = le64_to_cpu(sb->data_offset);
		rdev->new_data_offset = le64_to_cpu(sb->new_data_offset);
		rdev->sectors = le64_to_cpu(sb->sectors);
	}

	return 0;
}

/*
 * Load any superblocks from all RAID devices
 */
static struct md_rdev *superblocks_load(struct raid_set *rs)
{
	struct raid_dev *rd;
	struct md_rdev *freshest = NULL;

	for_each_rd(rd, rs) {
		int r;
		struct md_rdev *rdev = &rd->rdev;

		if (!rdev->meta_bdev)
			continue;

		r = super_load(rs, rdev, freshest);
		switch (r) {
		case 1:
			freshest = rdev;
		case 0:
			break;
		default:
			/* IO error -> remove the raid disk */
			raid_dev_remove(rs->ti, rd);
		}
	}

	return freshest;
}

/*
 * Validation of the freshest device provides the source of
 * validation for the remaining devices.
 */
static int superblocks_validate(struct raid_set *rs, struct md_rdev *freshest)
{
	struct md_rdev *rdev;

	if (super_validate_freshest(rs, freshest))
		return ti_error_einval(rs->ti, "Unable to assemble RAID set: Invalid freshest superblock");


	rdev_for_each(rdev, &rs->md)
		if (super_validate(rs, rdev))
			return ti_error_einval(rs->ti, "Unable to assemble RAID set: Invalid superblock");

	if (validate_raid_redundancy(rs))
		return ti_error_einval(rs->ti, "Insufficient redundancy to activate RAID set");

	return 0;
}

/*
 * Load and analyse superblocks and selecting the freshest,
 * which is the one with the largest sb->events counter.
 */
static int load_and_analyse_superblocks(struct raid_set *rs)
{
	int r;
	struct mddev *mddev = &rs->md;
	struct md_rdev *freshest;

	/* If !freshest then no valid superblock found -> new RAID set to construct. */
	freshest = superblocks_load(rs);
	if (!freshest) {
		rs->md.dev_sectors = rs->rds[0].rdev.sectors;
		return -ENODATA;
	}

	rs->md.dev_sectors = freshest->sectors;

	/* Validate all superblocks thus initiating &rs->md (i.e. the mddev) from the freshest */
	r = superblocks_validate(rs, freshest);
	if (r)
		return r;

	/*
	 * When reshaping the "sync/nosync" directives are disallowed
	 */
	if (rs->flags & (DM_RAID_SYNC | DM_RAID_NOSYNC)) {
		if (rs_conversion_requested(rs))
			return ti_error_einval(rs->ti, "Invalid sync request whilst RAID set conversion requested");

		if (rs->flags & DM_RAID_SYNC) {
			mddev->recovery_cp = 0;
			set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		} else {
			mddev->recovery_cp = MaxSector;
			clear_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		}

	} else if (!rs->raid_type->level) {
			mddev->recovery_cp = MaxSector;
			clear_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	}

	return 0;
}

/*
 * Enable/disable discard support on RAID set depending
 * on RAID level and discard properties of underlying devices
 * (i.e. the legs of the set).
 */
static void configure_discard_support(struct raid_set *rs)
{
	struct raid_dev *rd;
	struct dm_target *ti = rs->ti;
	bool discard_supported, raid0_or_10, raid456;
 
	/* Assume discards not supported until after checks below. */
 	ti->discards_supported = false;
 
	/* Assume 'discard_supported = true' unless table argument 'ignore_discard' given */
	discard_supported = !(rs->flags & DM_RAID_IGNORE_DISCARD);
	if (!discard_supported)
		return;

	/* RAID level 4,5,6 request discard_zeroes_data for data integrity! */
	raid0_or_10 = is_raid0_or_10(rs);
	raid456 = is_raid456(rs);
	for_each_rd(rd, rs) {
		struct request_queue *q;

		if (!rd->data_dev)
			continue;
 
		q = bdev_get_queue(rd->data_dev->bdev);
		if (!q || !blk_queue_discard(q))
 			return;
 
		/* raid level 0 or 10 don't rely on discard_zeroes_data */
		if (raid0_or_10)
			continue;

		if (raid456) {
			if (!q->limits.discard_zeroes_data)
				return;
			if (!devices_handle_discard_safely) {
				DMERR("raid456 discard support disabled due to discard_zeroes_data uncertainty.");
				DMERR("Set dm-raid.devices_handle_discard_safely=Y to override.");
				return;
			}
		}
 	}
 
	/* All RAID members properly support discards */
 	ti->discards_supported = true;
 
 	/*
 	 * RAID1 and RAID10 personalities require bio splitting,
	 * RAID0/4/5/6 don't and process large discard bios properly.
 	 */
	ti->split_discard_bios = !!(rs->md.level == 1 || rs->md.level == 10);
 	ti->num_discard_bios = 1;
}

struct rs_layout {
	bool backup;
	struct list_head disks;
	int new_level;
	int new_layout;
	int new_chunk_sectors;
	int delta_disks;
};

static void rs_layout_backup(struct raid_set *rs, struct rs_layout *l)
{
	struct mddev *mddev = &rs->md;

	l->backup = true;
	INIT_LIST_HEAD(&l->disks);

	/*
	 * In case of an up takeover or reshape, we need to unlist the additonal
	 * (i.e. FirstUse) data device(s) temporarily to be able to run the pregiven
	 * raid set alright before adding it/them back in to carry out the operation
	 */
	if (rs_takeover_requested(rs)) {
		unsigned d;

		for (d = mddev->raid_disks; d < rs->raid_disks; d++) {
			struct md_rdev *rdev = rdev_unlist_last(mddev);

			list_add(&rdev->same_set, &l->disks);
		}
	}

	l->new_level = mddev->new_level;
	l->new_layout = mddev->new_layout;
	l->new_chunk_sectors = mddev->new_chunk_sectors;
	l->delta_disks = mddev->delta_disks;

	mddev->new_level = mddev->level;
	mddev->new_layout = mddev->layout;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	mddev->delta_disks = 0;
}

static void rs_layout_restore(struct raid_set *rs, struct rs_layout *l)
{
	struct mddev *mddev = &rs->md;

	mddev->new_level = l->new_level;
	mddev->new_layout = l->new_layout;
	mddev->new_chunk_sectors = l->new_chunk_sectors;
	mddev->delta_disks = l->delta_disks;

	/*
	 * In case of an up takeover or reshape, we add the
	 * previously removed last raid disk(s) back in
	 */
	list_splice_tail(&l->disks, &mddev->disks);
}

/*
 * Run a raid set (i.e. make accessible to submit io)
 *
 * Check superblocks for raid set @rs
 *
 * If valid ones present, use them:
 * - check if a processing reshape got interrupted (e.g. by a
 *   system crash) and allow it to restart from where it stopped
 * - if not interrupted reshape, check for a new takeover/reshape
 *   request and prepare it to start
 *
 * If no valid ones present (i.e. all FirstUse devices),
 * allow a new raid set to be created on start
 *
 * Then start the raid set defined in @rs via md_run()
 *
 */
static int rs_run(struct raid_set *rs)
{
	int r;
	struct rs_layout rs_layout = { .backup = false };
	struct mddev *mddev = &rs->md;

	r = load_and_analyse_superblocks(rs);
	if (r == -ENODATA) {
		/*
		 * We don't have any (valid) superblocks, so we
		 * presume a new raid set is being requested to
		 * build and set the mddev properties here
		 */
		rs_set_new(rs);

	} else if (r < 0)
		return ti_error_einval(rs->ti, "Superblock validation failed!");

	if (!is_divisible_by_data_devs(rs))
		return ti_error_einval(rs->ti, "Target length not divisible by number of data devices");

	/* Now that we have any existing superblock data at hand, check for invalid ctr flags passed in */
	if (rs_conversion_requested(rs) &&
	    (rs->flags & (DM_RAID_SYNC|DM_RAID_NOSYNC)))
		return ti_error_einval(rs->ti, "sync/nosync prohibited on takeover/reshape/resize request");

	mutex_lock(&mddev->reconfig_mutex);
	mddev->ro = 0;

	/* Check for any interrupted reshape */
	if (mddev->reshape_position != MaxSector)
		/* Must be read-only for interrupted reshapes to be restarted */
		mddev->ro = 1;

	else if (mddev->recovery_cp == MaxSector) {
		/*
		 * Neither reshaping nor recovery may be pending in order
		 * to allow for a takeover, reshape or resize request
		 */
		if (rs_conversion_requested(rs)) {
			/*
		  	 * If a new reshape is needed, save new members in order to be
		  	 * able to start the RAID set and kick off the reshape afterwards
		  	 */
			if (mddev->degraded) {
				DMWARN("Takeover/reshape/resize on degraded raid set prohibited");
				return -EPERM;
			}

			/* Check for any new data offset requested */
			r = rs_new_data_offset_requested(rs);
			if (r < 0)
				return ti_error_einval(rs->ti, "Invalid new data offset requested");

			/* HM FIXME: needed in case of new_data_offset? */
			rs_layout_backup(rs, &rs_layout);
		}
	}

#if 1
	/* HM FIXME: REMOVME: devel logging */
	dump_mddev(mddev, "before md_run");
#endif

	enable_bitmap(rs, rs->md.level);
	r = md_run(mddev);
	mddev->in_sync = 0; /* Assume already marked dirty */
	mutex_unlock(&mddev->reconfig_mutex);

	if (r)
		return r;

	/* New reshape requested; restarted reshape is being processed in md_run() already */
	if (rs_layout.backup) {
		/*
		 * Try initiating a reshape or a level takeover.
		 *
		 * In case of takeover, check if bitmaps have to
		 * be enabled or disabled for the new raid level.
		 *
		 * If userspace requested bogus layout, don't return an error
		 * because the array is continuing to run with the previous layout.
		 *
		 * This allows access to the RAID set rather than hangs
		 * for the development time being.
		 */
		mutex_lock(&mddev->reconfig_mutex);
		rs_layout_restore(rs, &rs_layout);
		mutex_unlock(&mddev->reconfig_mutex);
		r = rs_takeover_or_reshape_or_resize(rs);
	}

	if (!r)
		/* Disable/enable discard support on RAID set */
		configure_discard_support(rs);

	return 0;
}
/*
 * Construct a RAID0/1/10/4/5/6 mapping:
 * Args:
 *	<raid_type> <#raid_params> <raid_params>{0,} <#raid_devs> [<meta_dev1> <dev1>]{1,}
 *
 * <raid_params> varies by <raid_type>.  See 'parse_raid_params' for
 * details on possible <raid_params>.
 *
 * The ctr arguments are advisory and will be overwritten by superblock parameters in
 * load_and_analyse_superblocks() in order to enforce activation of existing RAID sets
 * and thus prevent data loss.
 *
 * Userspace is free to initialize the metadata devices, hence the superblocks to
 * enforce recreation based on the passed in table parameters.
 */
/*
 * HM FIXME: do I need dev_offset args or can I possibly handle mandatory
 *           data shifts during reshape transparently inside the target?
 *           Make ti->len a bit smaller for reshapes and use the free
 *           space to write reshaped stripes out of place.
 */
static int raid_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	unsigned num_raid_params, num_raid_devs;
	const char *arg;
	struct raid_set *rs = NULL;
	struct raid_type *rt;
	struct dm_arg_set as = { argc, argv }, as_nrd;
	struct dm_arg _args[] = {
		{0, as.argc, "Cannot understand number of RAID parameters or supplied arguments do not match the count given"},
		{1, 254, "Cannot understand number of RAID devices or supplied RAID device tupples do not match the count given"}
	};

#if 1
	/* HM FIXME: REMOVEME: devel output */
	print_argv(__func__, as.argc, as.argv);
#endif

	/* raid type */
	arg = dm_shift_arg(&as);
	if (!arg)
		return ti_error_einval(ti, "Too few arguments");

	rt = get_raid_type(arg);
	if (!rt)
		return ti_error_einval(ti, "Unrecognised raid_type");

	/* number of RAID parameters */
	if (dm_read_arg_group(_args, &as, &num_raid_params, &ti->error))
		return -EINVAL;

	as_nrd = as;
	dm_consume_args(&as_nrd, num_raid_params);
	if (dm_read_arg(_args + 1, &as_nrd, &num_raid_devs, &ti->error))
		return -EINVAL;

	if (as_nrd.argc != num_raid_devs * 2)
		return ti_error_einval(ti, "Supplied RAID devices do not match the count given");

	if (num_raid_devs > MAX_RAID_DEVICES)
		return ti_error_einval(ti, "Too many supplied RAID devices");

	rs = context_alloc(ti, rt, num_raid_devs);
	if (IS_ERR(rs))
		return PTR_ERR(rs);

	r = parse_raid_params(rs, &as, num_raid_params);
	if (r)
		goto bad;

	dm_shift_arg(&as); /* Shift the number of raid devices argument */

	r = parse_dev_params(rs, &as);
	if (r)
		goto bad;

	/*
	 * Array will be started in preresume() in order to access any
	 * preexisting up to date superblocks and bitmaps on a table switch
	 */
	return 0;

bad:
	context_free(rs);
	return r;
}

static void raid_dtr(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;

	list_del_init(&rs->callbacks.list);

	if (rs->md.ready)
		md_stop(&rs->md);

	context_free(rs);
}

static int raid_map(struct dm_target *ti, struct bio *bio)
{
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;

	mddev->pers->make_request(mddev, bio);

	return DM_MAPIO_SUBMITTED;
}

static const char *decipher_sync_action(struct mddev *mddev)
{
	if (test_bit(MD_RECOVERY_FROZEN, &mddev->recovery))
		return "frozen";

	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
	    (!mddev->ro && test_bit(MD_RECOVERY_NEEDED, &mddev->recovery))) {
		if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
			return "reshape";

		if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
			if (!test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
				return "resync";
			else if (test_bit(MD_RECOVERY_CHECK, &mddev->recovery))
				return "check";
			return "repair";
		}

		if (test_bit(MD_RECOVERY_RECOVER, &mddev->recovery))
			return "recover";
	}

	return "idle";
}

static void raid_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	struct raid_set *rs = ti->private;
	int array_in_sync = 0;
	unsigned raid_param_cnt = 1; /* at least 1 for chunksize */
	unsigned sz = 0;
	sector_t sync;
	struct raid_dev *rd;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%s %d ", rs->raid_type->name, rs->md.raid_disks);

		if (rs->md.level) {
			if (test_bit(MD_RECOVERY_RUNNING, &rs->md.recovery))
				sync = rs->md.curr_resync_completed;
			else
				sync = rs->md.recovery_cp;

			if (sync >= rs->md.resync_max_sectors) {
				/*
				 * Sync complete.
				 */
				array_in_sync = 1;
				sync = rs->md.resync_max_sectors;
			} else if (test_bit(MD_RECOVERY_REQUESTED, &rs->md.recovery)) {
				/*
				 * If "check" or "repair" is occurring, the RAID set has
				 * undergone an initial sync and the health characters
				 * should not be 'a' anymore.
				 */
				array_in_sync = 1;
			} else {
				/*
				 * The RAID set may be doing an initial sync, or it may
				 * be rebuilding individual components.  If all the
				 * devices are In_sync, then it is the RAID set that is
				 * being initialized.
				 */
				for_each_rd(rd, rs)
					if (!test_bit(In_sync, &rd->rdev.flags))
						array_in_sync = 1;
			}

		} else { /* RAID0 */
			sync = rs->md.resync_max_sectors;
			array_in_sync = 1;
		}

		/*
		 * HM FIXME: do we want another state char for RAID0? It shows 'D' or 'A' now
		 *
		 * Status characters:
		 *  'D' = Dead/Failed device
		 *  'a' = Alive but not in-sync
		 *  'A' = Alive and in-sync
		 */
		for_each_rd(rd, rs) {
			if (test_bit(Faulty, &rd->rdev.flags))
				DMEMIT("D");
			else if (!array_in_sync ||
				 !test_bit(In_sync, &rd->rdev.flags))
				DMEMIT("a");
			else
				DMEMIT("A");
		}

		/*
		 * In-sync ratio:
		 *  The in-sync ratio shows the progress of:
		 *   - Initializing the RAID set
		 *   - Rebuilding a subset of devices of the RAID set
		 *  The user can distinguish between the two by referring
		 *  to the status characters.
		 */
		DMEMIT(" %llu/%llu",
		       (unsigned long long) sync,
		       (unsigned long long) rs->md.resync_max_sectors);

		/*
		 * Sync action:
		 *   See Documentation/device-mapper/dm-raid.txt for
		 *   information on each of these states.
		 */
		DMEMIT(" %s", decipher_sync_action(&rs->md));

		/*
		 * resync_mismatches/mismatch_cnt
		 *   This field shows the number of discrepancies found when
		 *   performing a "check" of the RAID set.
		 */
		DMEMIT(" %llu",
		       (strcasecmp(rs->md.last_sync_action, "check")) ? 0 :
		       (unsigned long long) atomic64_read(&rs->md.resync_mismatches));
		break;
	case STATUSTYPE_TABLE:
		/* The string you would use to construct this RAID set */
		for_each_rd(rd, rs) {
			if (rd->data_dev) {
				if ((rs->flags & DM_RAID_REBUILD) &&
				    !test_bit(In_sync, &rd->rdev.flags))
					raid_param_cnt += 2; /* for rebuilds */
				if (test_bit(WriteMostly, &rd->rdev.flags))
					raid_param_cnt += 2;
			}
		}

		raid_param_cnt += (hweight32(rs->flags & ~DM_RAID_REBUILD & ~DM_RAID_RESHAPE) * 2);
		if (rs->flags & (DM_RAID_SYNC | DM_RAID_NOSYNC))
			raid_param_cnt--;

		DMEMIT("%s %u %u", rs->raid_type->name,
		       raid_param_cnt, rs->md.chunk_sectors);

		if ((rs->flags & DM_RAID_SYNC) &&
		    rs->md.recovery_cp == MaxSector)
			DMEMIT(" sync");
		if (rs->flags & DM_RAID_NOSYNC)
			DMEMIT(" nosync");
		if (rs->flags & DM_RAID_IGNORE_DISCARD)
			DMEMIT(" ignore_discard");

		for_each_rd(rd, rs)
			if ((rs->flags & DM_RAID_REBUILD) &&
			    rd->data_dev &&
			    !test_bit(In_sync, &rd->rdev.flags))
				DMEMIT(" rebuild %u", rd->rdev.raid_disk);

		if (rs->flags & DM_RAID_DAEMON_SLEEP)
			DMEMIT(" daemon_sleep %lu",
			       rs->md.bitmap_info.daemon_sleep);

		if (rs->flags & DM_RAID_MIN_RECOVERY_RATE)
			DMEMIT(" min_recovery_rate %d", rs->md.sync_speed_min);

		if (rs->flags & DM_RAID_MAX_RECOVERY_RATE)
			DMEMIT(" max_recovery_rate %d", rs->md.sync_speed_max);

		for_each_rd(rd, rs)
			if (rd->data_dev &&
			    test_bit(WriteMostly, &rd->rdev.flags))
				DMEMIT(" write_mostly %u", rd->rdev.raid_disk);

		if (rs->flags & DM_RAID_DELTA_DISKS)
			DMEMIT(" delta_disks %d", rs->delta_disks);

		if (rs->flags & DM_RAID_MAX_WRITE_BEHIND)
			DMEMIT(" max_write_behind %lu",
			       rs->md.bitmap_info.max_write_behind);

		if (rs->flags & DM_RAID_STRIPE_CACHE) {
			struct r5conf *conf = rs->md.private;

			/* convert from kiB to sectors */
			DMEMIT(" stripe_cache %d",
			       conf ? conf->max_nr_stripes * 2 : 0);
		}

		if (rs->flags & DM_RAID_REGION_SIZE)
			DMEMIT(" region_size %lu",
			       to_sector(rs->md.bitmap_info.chunksize));

		if (rs->flags & DM_RAID_RAID10_COPIES)
			DMEMIT(" raid10_copies %u",
			       raid10_md_layout_to_copies(rs->md.layout));

		if (rs->flags & DM_RAID_RAID10_FORMAT)
			DMEMIT(" raid10_format %s",
			       raid10_md_layout_to_format(rs->md.layout));

		DMEMIT(" %d", rs->md.raid_disks);
		for_each_rd(rd, rs) {
			DMEMIT(" %s", rd->meta_dev ? rd->meta_dev->name : "-");
			DMEMIT(" %s", rd->data_dev ? rd->data_dev->name : "-");
		}
	}
}

enum action { noop = 0, min_recovery_rate, max_recovery_rate, max_write_behind, daemon_sleep };
static int raid_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = 0;
	enum action action;
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;
	struct dm_arg_set as = { argc, argv };
	const char *cmd = dm_shift_arg(&as);

#if 1
	/* HM FIXME: REMOVEME: devel output */
	print_argv(__func__, argc, argv);

	if (!strcasecmp(cmd, "dump")) {
		dump_mddev(mddev, "dump message");
		return 0;
	}
#endif

	if (!mddev->pers || !mddev->pers->sync_request)
		return -EINVAL;

	if (!strcasecmp(cmd, "min_recovery_rate"))
		action = min_recovery_rate;
	else if (!strcasecmp(cmd, "max_recovery_rate"))
		action = max_recovery_rate;
	else if (!strcasecmp(cmd, "max_write_behind"))
		action = max_write_behind;
	else if (!strcasecmp(cmd, "daemon_sleep"))
		action = daemon_sleep;
	else
		action = noop;

	if (action != noop) {
		int value;

		if (kstrtoint(dm_shift_arg(&as), 10, &value) < 0)
			return ti_error_einval(rs->ti, "Bad numerical argument given");

		switch (action) {
		case min_recovery_rate:
			return set_recovery_rate(rs, value, true);
		case max_recovery_rate:
			return set_recovery_rate(rs, value, false);
		case max_write_behind:
			return set_max_write_behind(rs, value);
		case daemon_sleep:
			return set_daemon_sleep(rs, value);
		default:
			BUG();
		}
	}

	if (!strcasecmp(cmd, "frozen"))
		set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
	else
		clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);

	if (!strcasecmp(cmd, "idle") || !strcasecmp(cmd, "frozen")) {
		if (mddev->sync_thread) {
			set_bit(MD_RECOVERY_INTR, &mddev->recovery);
			md_reap_sync_thread(mddev);
		}
	} else if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
		   test_bit(MD_RECOVERY_NEEDED, &mddev->recovery))
		return -EBUSY;
	else if (!strcasecmp(cmd, "resync"))
		; /* happening below: set_bit(MD_RECOVERY_NEEDED, &mddev->recovery); */
	else if (!strcasecmp(cmd, "recover"))
		set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	else {
		if (!strcasecmp(argv[0], "check"))
			set_bit(MD_RECOVERY_CHECK, &mddev->recovery);
		else if (!!strcasecmp(argv[0], "repair"))
			return -EINVAL;
		set_bit(MD_RECOVERY_REQUESTED, &mddev->recovery);
		set_bit(MD_RECOVERY_SYNC, &mddev->recovery);
	}

	if (mddev->ro == 2) {
		/* A write to sync_action is enough to justify
		 * canceling read-auto mode
		 */
		mddev->ro = 0;
		smp_wmb();
		if (!mddev->suspended)
			md_wakeup_thread(mddev->sync_thread);
	}

	if (!r) {
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		smp_wmb();
		if (!mddev->suspended)
			md_wakeup_thread(mddev->thread);
	}

	return r;
}

static int raid_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	int r = 0;
	struct raid_set *rs = ti->private;
	struct raid_dev *rd;

	for_each_rd(rd, rs) {
		if (rd->data_dev)
			r = fn(ti, rd->data_dev,
			        0, /* No offset on data devs */
				rs->md.dev_sectors, data);
		if (r)
			break;
	}

	return r;
}

/* HM FIXME: passed in properties sufficient? */
static void raid_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct raid_set *rs = ti->private;
	unsigned chunk_size = to_bytes(rs->md.new_chunk_sectors);

	blk_limits_io_min(limits, chunk_size);
	blk_limits_io_opt(limits, chunk_size * (rs->md.raid_disks + rs->md.delta_disks - rs->raid_type->parity_devs));
}

static void raid_presuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;

	md_stop_writes(&rs->md);
}

static void raid_postsuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;

	mddev_suspend(&rs->md);
}

static void attempt_restore_of_faulty_devices(struct raid_set *rs)
{
	unsigned i = 0;
	uint64_t failed_devices, cleared_failed_devices = 0;
	unsigned long flags;
	struct raid_dev *rd;
	struct dm_raid_superblock *sb;
	struct md_rdev *rdev;

	for_each_rd(rd, rs) {
		rdev = &rd->rdev;

		if (test_bit(Faulty, &rdev->flags) && rdev->sb_page &&
		    sync_page_io(rdev, 0, rdev->sb_size, rdev->sb_page, READ, 1)) {
			DMINFO("Faulty %s device #%d has readable super block."
			       "  Attempting to revive it.",
			       rs->raid_type->name, i);

			/*
			 * Faulty bit may be set, but sometimes the RAID set can
			 * be suspended before the personalities can respond
			 * by removing the device from the RAID set (i.e. calling
			 * 'hot_remove_disk').  If they haven't yet removed
			 * the failed device, its 'raid_disk' number will be
			 * '>= 0' - meaning we must call this function
			 * ourselves.
			 */
			if ((rdev->raid_disk >= 0) &&
			    (rs->md.pers->hot_remove_disk(&rs->md, rdev) != 0)) {
				/* Failed to revive this device, try next */
				i++;
				continue;
			}

			rdev->raid_disk = i;
			rdev->saved_raid_disk = i;
			flags = rdev->flags;
			clear_bit(Faulty, &rdev->flags);
			clear_bit(WriteErrorSeen, &rdev->flags);
			clear_bit(In_sync, &rdev->flags);

			if (rs->md.pers->hot_add_disk(&rs->md, rdev)) {
				rdev->raid_disk = -1;
				rdev->saved_raid_disk = -1;
				rdev->flags = flags;
			} else {
				rdev->recovery_offset = 0;
				cleared_failed_devices |= 1 << i;
			}
		}

		i++;
	}

	/* If any cleared devices, clear them in the superblock as well */
	if (cleared_failed_devices) {
		rdev_for_each(rdev, &rs->md) {
			sb = page_address(rdev->sb_page);
			failed_devices = le64_to_cpu(sb->failed_devices);
			failed_devices &= ~cleared_failed_devices;
			sb->failed_devices = cpu_to_le64(failed_devices);
		}
	}
}

static int raid_preresume(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	int r;

	/* This is a resume after a suspend of the set -> it's already started */
	if (rs->flags & DM_RAID_SET_STARTED)
		return 0;

	r = rs_run(rs);
	if (r)
		DMERR("failed to start %s set", rs->raid_type->descr);

	else {
		rs->flags |= DM_RAID_SET_STARTED;
		DMINFO("started %s set", rs->raid_type->descr);
	}

	return r;
}

static void raid_resume(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;

	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	if (!rs->bitmap_loaded) {
		int r = bitmap_load(mddev);

		if (!r)
			rs->bitmap_loaded = true;
	} else {
		/*
		 * A secondary resume while the device is active.
		 * Take this opportunity to check whether any failed
		 * devices are reachable again.
		 */
		attempt_restore_of_faulty_devices(rs);
	}

	clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
	mddev->ro = 0;
	mddev_resume(mddev);
}

static struct target_type raid_target = {
	.name = "raid",
	.version = {1, 7, 0},
	.module = THIS_MODULE,
	.ctr = raid_ctr,
	.dtr = raid_dtr,
	.map = raid_map,
	.status = raid_status,
	.message = raid_message,
	.iterate_devices = raid_iterate_devices,
	.io_hints = raid_io_hints,
	.presuspend = raid_presuspend,
	.postsuspend = raid_postsuspend,
	.preresume = raid_preresume,
	.resume = raid_resume,
};

static int __init dm_raid_init(void)
{
	DMINFO("Loading target version %u.%u.%u",
	       raid_target.version[0],
	       raid_target.version[1],
	       raid_target.version[2]);
	return dm_register_target(&raid_target);
}

static void __exit dm_raid_exit(void)
{
	dm_unregister_target(&raid_target);
}

module_init(dm_raid_init);
module_exit(dm_raid_exit);

module_param(devices_handle_discard_safely, bool, 0644);
MODULE_PARM_DESC(devices_handle_discard_safely,
		 " set to Y if all devices in each array reliably return zeroes on reads from discarded regions");
MODULE_DESCRIPTION(DM_NAME " raid0/1/10/4/5/6 target");
MODULE_ALIAS("dm-raid0");
MODULE_ALIAS("dm-raid1");
MODULE_ALIAS("dm-raid10");
MODULE_ALIAS("dm-raid4");
MODULE_ALIAS("dm-raid5");
MODULE_ALIAS("dm-raid6");
MODULE_AUTHOR("Neil Brown <dm-devel@redhat.com>");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");
