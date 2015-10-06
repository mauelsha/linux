/*
 * Copyright (C) 2010-2011 Neil Brown
 * Copyright (C) 2010-2015 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

/* HM FIXME: REMOVME: devel logging */
#define DEVEL_OUTPUT 1

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/log2.h>

#include "dm.h"
#include "md.h"
#include "raid1.h"
#include "raid5.h"
#include "raid10.h"
#include "bitmap.h"

#include <linux/device-mapper.h>
#include <linux/raid/md_p.h>

#define DM_MSG_PREFIX		"raid"
#define	MAX_raid_DEVICES	253 /* MD raid limit */

/*
 * Minimum sectors of free reshape space per raid device
 */
#define	MIN_FREE_RESHAPE_SPACE to_sector(4096)

static bool devices_handle_discard_safely = false;

static void super_sync(struct mddev *mddev, struct md_rdev *rdev);

#if DEVEL_OUTPUT
/* HM FIXME: REMOVME: devel logging */
static void print_argv(const char *caller, int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; i++)
		DMERR("%s -- argv[%d]=\"%s\"", caller, i, argv[i]);
}

#define DUMP_MEMBER(m, f) DMINFO(#m "=" f, m)
#define DUMP_MEMBERS(m1, f1, m2, f2) DMINFO(#m1 "=" f1 "/" #m2 "=" f2, m1, m2)
static void dump_mddev(struct mddev *mddev, const char *msg)
{
	struct md_rdev *rdev;

	DMINFO("*** %s ***", msg);
	DUMP_MEMBER(mddev->flags, "%lX");
	DUMP_MEMBER(mddev->recovery, "%lX");
	DUMP_MEMBERS(mddev->level, "%u", mddev->new_level, "%u");
	DUMP_MEMBERS(mddev->layout, "%u", mddev->new_layout, "%u");
	DUMP_MEMBERS(mddev->chunk_sectors, "%u", mddev->new_chunk_sectors, "%u");
	DUMP_MEMBER(mddev->raid_disks, "%u");
	DUMP_MEMBER(mddev->delta_disks, "%d");
	DUMP_MEMBER(mddev->reshape_backwards, "%d");
	DUMP_MEMBER((unsigned long long) mddev->dev_sectors, "%llu");
	DUMP_MEMBER((unsigned long long) mddev->array_sectors, "%llu");
	DUMP_MEMBER((unsigned long long) mddev->recovery_cp, "%llu");
	DUMP_MEMBER((unsigned long long) mddev->reshape_position, "%llu");
	DUMP_MEMBER((unsigned long long) mddev->resync_max_sectors, "%llu");
	DUMP_MEMBER(mddev->degraded, "%d");
	DUMP_MEMBER(mddev->persistent, "%d");
	rdev_for_each(rdev, mddev)
		DMINFO("rdev=%d sectors=%llu flags=%lX recovery_offset=%llu data_offset=%llu new_data_offset=%llu",
			rdev->raid_disk, (unsigned long long) rdev->sectors, rdev->flags,
			(unsigned long long) rdev->recovery_offset,
			(unsigned long long) rdev->data_offset, (unsigned long long) rdev->new_data_offset);
}
#endif

/*
 * The following flags are used by dm-raid.c to set up the raid set state.
 * They must be cleared before md_run is called.
 */
#define FirstUse 31 /* temporary rdev flag to indicate new device */

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
 * Flags for rs->ctr_flags field.
 *
 * These are all being set via table line arguments
 * (CTR_FLAG prefix meaning "constructor flag").
 */
						/* # of arguments */
#define CTR_FLAG_SYNC              0x1		/* 1 */
#define CTR_FLAG_NOSYNC            0x2		/* 1 */
#define CTR_FLAG_REBUILD           0x4		/* 2 */
#define CTR_FLAG_WRITE_MOSTLY      0x8		/* 2 */
#define CTR_FLAG_DAEMON_SLEEP      0x10		/* 2 */
#define CTR_FLAG_MIN_RECOVERY_RATE 0x20		/* 2 */
#define CTR_FLAG_MAX_RECOVERY_RATE 0x40		/* 2 */
#define CTR_FLAG_MAX_WRITE_BEHIND  0x80		/* 2 */
#define CTR_FLAG_STRIPE_CACHE      0x100	/* 2 */
#define CTR_FLAG_REGION_SIZE       0x200	/* 2 */
#define CTR_FLAG_RAID10_COPIES     0x400	/* 2 */
#define CTR_FLAG_RAID10_FORMAT     0x800	/* 2 */
/* New in v1.6.0 */
#define CTR_FLAG_IGNORE_DISCARD    0x1000	/* 1 */
/* New in v1.8.0 */
#define CTR_FLAG_DELTA_DISKS       0x2000	/* 2 */
#define CTR_FLAG_DATA_OFFSET       0x4000	/* 2 */

/* Used in dm_raid_status() for table line number of parameters calculation */
/* Define bitset of options without argument */
#define	CTR_FLAG_OPTIONS_NO_ARGS	(CTR_FLAG_SYNC | \
					 CTR_FLAG_NOSYNC | \
					 CTR_FLAG_IGNORE_DISCARD)
#define	CTR_FLAGS_ANY_SYNC		(CTR_FLAG_SYNC | \
					 CTR_FLAG_NOSYNC)
/* Define bitset of options with one argument */
#define CTR_FLAG_OPTIONS_ONE_ARG (CTR_FLAG_REBUILD | \
				  CTR_FLAG_WRITE_MOSTLY | \
				  CTR_FLAG_DAEMON_SLEEP | \
				  CTR_FLAG_MIN_RECOVERY_RATE | \
				  CTR_FLAG_MAX_RECOVERY_RATE | \
				  CTR_FLAG_MAX_WRITE_BEHIND | \
				  CTR_FLAG_STRIPE_CACHE | \
				  CTR_FLAG_REGION_SIZE | \
				  CTR_FLAG_RAID10_COPIES | \
				  CTR_FLAG_RAID10_FORMAT | \
				  CTR_FLAG_DELTA_DISKS | \
				  CTR_FLAG_DATA_OFFSET)

/*
 * Define bitsets of invalid arguments for individual
 * raid levels to check against in parse_raid_params()
 */
/* "raid0" does not accept any optional arguments! */
#define ALL_CTR_FLAGS		(CTR_FLAG_OPTIONS_NO_ARGS | \
				 CTR_FLAG_OPTIONS_ONE_ARG)
#define RAID0_INVALID_FLAGS ALL_CTR_FLAGS

/*
 * All flags which cause an immediate reload once they have their way to raid metadata
 */
#define	ALL_FREEZE_FLAGS (ALL_CTR_FLAGS & ~(CTR_FLAG_REGION_SIZE | CTR_FLAGS_ANY_SYNC | \
					    CTR_FLAG_RAID10_FORMAT | CTR_FLAG_RAID10_COPIES))

/* "raid1" does not accept stripe cache or any raid10 or reshape arguments */
#define RAID1_INVALID_FLAGS	(CTR_FLAG_STRIPE_CACHE | \
				 CTR_FLAG_RAID10_COPIES | \
				 CTR_FLAG_RAID10_FORMAT | \
				 CTR_FLAG_DELTA_DISKS | \
				 CTR_FLAG_DATA_OFFSET)
/* "raid10" does not accept any raid1 or stripe cache or reshape arguments */
#define RAID10_INVALID_FLAGS	(CTR_FLAG_WRITE_MOSTLY | \
				 CTR_FLAG_MAX_WRITE_BEHIND | \
				 CTR_FLAG_STRIPE_CACHE )
/* "raid456" does not accept any raid1 or raid10 specific arguments */
#define RAID456_INVALID_FLAGS	(CTR_FLAG_WRITE_MOSTLY | \
				 CTR_FLAG_MAX_WRITE_BEHIND | \
				 CTR_FLAG_RAID10_FORMAT | \
				 CTR_FLAG_RAID10_COPIES)


/*
 * Flags for rs->runtime_flags field
 * (RT_FLAG prefix meaning "runtime flag")
 *
 * These are all internal and used to define runtime state,
 * e.g. to prevent another resume from starting the raid
 * set all over again
 */
#define RT_FLAG_SET_STARTED	0x1
#define RT_FLAG_SET_RESUMED	0x2
#define RT_FLAG_BITMAP_LOADED	0x4
#define RT_FLAG_RESHAPE		0x8

/* All optional table line arguments are defined here */
struct arg_name_flag {
	const uint32_t flag;
	const char *name;
} _arg_name_flags[] = {
	{ CTR_FLAG_SYNC, "sync"},
	{ CTR_FLAG_NOSYNC, "nosync"},
	{ CTR_FLAG_REBUILD, "rebuild"},
	{ CTR_FLAG_DAEMON_SLEEP, "daemon_sleep"},
	{ CTR_FLAG_MIN_RECOVERY_RATE, "min_recovery_rate"},
	{ CTR_FLAG_MAX_RECOVERY_RATE, "max_recovery_rate"},
	{ CTR_FLAG_MAX_WRITE_BEHIND, "max_write_behind"},
	{ CTR_FLAG_STRIPE_CACHE, "stripe_cache"},
	{ CTR_FLAG_REGION_SIZE, "region_size"},
	{ CTR_FLAG_RAID10_COPIES, "raid10_copies"},
	{ CTR_FLAG_RAID10_FORMAT, "raid10_format"},
	{ CTR_FLAG_IGNORE_DISCARD, "ignore_discard"},
	{ CTR_FLAG_DELTA_DISKS, "delta_disks"},
	{ CTR_FLAG_DATA_OFFSET, "data_offset"},
	{ CTR_FLAG_WRITE_MOSTLY, "writemostly"},
};

/* Array elements of 64 bit needed for rebuold/write_mostyl bits */
#define DISKS_ARRAY_ELEMS ((MAX_raid_DEVICES + (sizeof(uint64_t) * 8 - 1)) / sizeof(uint64_t) / 8)

struct raid_set {
	struct dm_target *ti;

	uint32_t ctr_flags;
	uint32_t runtime_flags;
	uint64_t rebuild_disks[DISKS_ARRAY_ELEMS];
	uint64_t writemostly_disks[DISKS_ARRAY_ELEMS];
	int delta_disks;
	int raid_disks;
	int failed_disks;
	int data_offset;
	int raid10_copies;

	struct mddev md;
	struct raid_type *raid_type;
	struct dm_target_callbacks callbacks;

	struct raid_dev dev[0];
};

/* Convenience macro to walk the rs->dev[] array */
#define	for_each_rd(rd, rs) \
	for ((rd) = (rs)->dev + 0; (rd) < (rs)->dev + (rs)->raid_disks; (rd)++)

/* Supported raid types and properties (raid5_0, and raid6_0_6 not supported). */
static struct raid_type {
	const char *name;		/* raid algorithm. */
	const char *descr;		/* Descriptor text for logging. */
	const unsigned parity_devs;	/* # of parity devices. */
	const unsigned minimal_devs;	/* minimal # of devices in set. */
	const unsigned level;		/* raid level. */
	const unsigned algorithm;	/* raid algorithm. */
} raid_types[] = {
	{"raid0",      "raid0 (striping)",			 0, 2, 0, 0 /* NONE */},
	{"raid1",      "raid1 (mirroring)",			 0, 2, 1, 0 /* NONE */},
	{"raid10",     "raid10 (striped mirrors)",		 0, 2, 10, UINT_MAX /* Alogorithm varies */},
	{"raid4",      "raid4 (dedicated last parity disk)",	 1, 2, 4, ALGORITHM_PARITY_N}, /* Native MD raid4 layout */
	{"raid5_n",    "raid5 (dedicated last parity disk)",	 1, 2, 5, ALGORITHM_PARITY_N},
	{"raid5_ls",   "raid5 (left symmetric)",		 1, 2, 5, ALGORITHM_LEFT_SYMMETRIC},
	{"raid5_rs",   "raid5 (right symmetric)",		 1, 2, 5, ALGORITHM_RIGHT_SYMMETRIC},
	{"raid5_la",   "raid5 (left asymmetric)",		 1, 2, 5, ALGORITHM_LEFT_ASYMMETRIC},
	{"raid5_ra",   "raid5 (right asymmetric)",		 1, 2, 5, ALGORITHM_RIGHT_ASYMMETRIC},
	{"raid6_zr",   "raid6 (zero restart)",			 2, 4, 6, ALGORITHM_ROTATING_ZERO_RESTART},
	{"raid6_nr",   "raid6 (N restart)",			 2, 4, 6, ALGORITHM_ROTATING_N_RESTART},
	{"raid6_nc",   "raid6 (N continue)",			 2, 4, 6, ALGORITHM_ROTATING_N_CONTINUE},
	{"raid6_ls_6", "raid6 (left symmetric dedicated Q 6)",	 2, 4, 6, ALGORITHM_LEFT_SYMMETRIC_6},
	{"raid6_rs_6", "raid6 (right symmetric dedicated Q 6)",	 2, 4, 6, ALGORITHM_RIGHT_SYMMETRIC_6},
	{"raid6_la_6", "raid6 (left asymmetric dedicated Q 6)",	 2, 4, 6, ALGORITHM_LEFT_ASYMMETRIC_6},
	{"raid6_ra_6", "raid6 (right asymmetric dedicated Q 6)", 2, 4, 6, ALGORITHM_RIGHT_ASYMMETRIC_6},
	{"raid6_n_6",  "raid6 (dedicated parity/Q n/6)",	 2, 4, 6, ALGORITHM_PARITY_N_6}
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

/* Return raid_type for @name based derived from @level and @layout */
static struct raid_type *get_raid_type_by_ll(const int level, const int layout)
{
	struct raid_type *rtp = raid_types + ARRAY_SIZE(raid_types);

	while (rtp-- > raid_types)
		if (rtp->level == level &&
		    (rtp->level == 10 ||
		     rtp->algorithm == layout))
			return rtp;

	return NULL;
}

/* True, if @v is in inclusive range [@min, @max] */
static bool _in_range(long v, long min, long max)
{
	return v >= min && v <= max;
}

/* Count maximum of set bits in @bitset (256 bits max) */
static unsigned _count_bits(uint64_t *bitset)
{
	int n = DISKS_ARRAY_ELEMS;
	unsigned r = 0;

	while (n--)
		r += hweight64(bitset[n]);

	return r;
}

/* Set single @flag in @flags */
static void _set_flag(uint32_t flag, uint32_t *flags)
{
	BUG_ON(hweight32(flag) != 1);

	*flags |= flag;
}

/* Test single @flag in @flags */
static bool _test_flag(uint32_t flag, uint32_t *flags)
{
	BUG_ON(hweight32(flag) != 1);

	return flag & *flags;
}


/* Return true if single @flag is set in @*flags, else set it and return false */
static bool _test_and_set_flag(uint32_t flag, uint32_t *flags)
{
	if (_test_flag(flag, flags))
		return true;

	*flags |= flag;
	return false;
}

/* Return size of @rd in sectors */
static sector_t _dev_size(struct raid_dev *rd)
{
	return to_sector(i_size_read(rd->data_dev->bdev->bd_inode));
}

/*
 * Conditionally change bdev capacity of @rs
 * in case of a disk add/remove reshape
 */
static void rs_set_capacity(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	/* Make sure we access most actual mddev properties */
	smp_rmb();
	if (rs->ti->len != mddev->array_sectors &&
	    mddev->reshape_position == MaxSector) {
		struct gendisk *gendisk = dm_disk(dm_table_get_md(rs->ti->table));

		set_capacity(gendisk, mddev->array_sectors);
		revalidate_disk(gendisk);
	}
}

/*
 * Set the mddev properties in @rs to the current
 * ones retrieved from the freshest superblock
 */
static void rs_set_cur(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	mddev->new_level = mddev->level;
	mddev->new_layout = mddev->layout;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
}

/* Set the mddev properties in @rs to the new ones requested by the ctr */
static void rs_set_new(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	mddev->level = mddev->new_level;
	mddev->layout = mddev->new_layout;
	mddev->chunk_sectors = mddev->new_chunk_sectors;
	mddev->delta_disks = 0;
}

/*
 * Conditionally enable bitmap on @rs based on the raid level.
 *
 * All levels but raid0 do have a bitmap to resync/recover.
 */
static void rs_config_bitmap(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	/*
	 * Enable bitmap creation at offset 4K on
	 * the metadata devs unless level is raid0
	 */
	mddev->bitmap_info.file = NULL;
	mddev->bitmap_info.offset = mddev->level ? to_sector(4096) : 0;
	mddev->bitmap_info.default_offset = mddev->bitmap_info.offset;
}

/*
 * bool helpers to test for various raid levels of a raid set
 */
/* Return true, if raid set in @rs is raid0 */
static bool rs_is_raid0(struct raid_set *rs)
{
	return !rs->md.level;
}

/* Return true, if raid set in @rs is raid1 */
static bool rs_is_raid1(struct raid_set *rs)
{
	return rs->md.level == 1;
}

/* Return true, if raid set in @rs is raid10 */
static bool rs_is_raid10(struct raid_set *rs)
{
	return rs->md.level == 10;
}

/* Return true, if raid set in @rs is level 4, 5 or 6 */
static bool rs_is_raid456(struct raid_set *rs)
{
	return _in_range(rs->md.level, 4, 6);
}

/* Return true, if raid set in @rs is level 0 or 10 */
static bool rs_is_raid0_or_10(struct raid_set *rs)
{
	return rs_is_raid0(rs) || rs_is_raid10(rs);
}

/* Return true, if raid set in @rs is reshapable */
static bool rs_is_reshapable(struct raid_set *rs)
{
	return rs_is_raid456(rs) || rs_is_raid10(rs);
}

/*
 * bool helpers to test for various raid levels of a raid type
 */

/* Return true, if raid type in @rt is raid0 */
static bool rt_is_raid0(struct raid_type *rt)
{
	return !rt->level;
}

/* Return true, if raid type in @rt is raid1 */
static bool rt_is_raid1(struct raid_type *rt)
{
	return rt->level == 1;
}

/* Return true, if raid type in @rt is raid10 */
static bool rt_is_raid10(struct raid_type *rt)
{
	return rt->level == 10;
}

/* Return true, if raid type in @rt is raid4/5/6 */
static bool rt_is_raid456(struct raid_type *rt)
{
	return _in_range(rt->level, 4, 6);
}
/* END: raid level bools */

/*
 * Convenience functions to set ti->error to @errmsg and
 * return @r in order to shorten code in a lot of places
 */
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

static int ti_error_flag(struct dm_target *ti, const char *flag_name)
{
	/* HM FIXME: REMOVEME? just devel error log or in release??? */
	DMERR("Invalid flag %s combined", flag_name);
	ti->error = "Invalid flag combined";
	return -EINVAL;
}
/* END: ti->error convenience functions */

/* Return argument name string for given @flag */
static const char *_argname_by_flag(const uint32_t flag)
{
	struct arg_name_flag *anf = _arg_name_flags + ARRAY_SIZE(_arg_name_flags);

	BUG_ON(hweight32(flag) != 1);

	while (anf-- > _arg_name_flags)
		if (flag & anf->flag)
			return anf->name;

	return NULL;
}

/* Return invalid ctr flags for the raid level of @rs */
static uint32_t _invalid_flags(struct raid_set *rs)
{
#if 0
	struct {
		bool (*fn)(struct raid_type *rt);
		uint64_t flags;
	} _f[] = {
		{ rt_is_RAID0, raid0_INVALID_FLAGS },
		{ rt_is_RAID1, raid1_INVALID_FLAGS },
		{ rt_is_RAID10, raid10_INVALID_FLAGS },
		{ rt_is_RAID456, raid456_INVALID_FLAGS },
	}, *f = _f + ARRAY_SIZE(_f);

	while (f-- > _f)
		if (f->fn(rs->raid_type))
			return f->flags;
#else
	if (rt_is_raid0(rs->raid_type))
		return RAID0_INVALID_FLAGS;
	else if (rt_is_raid1(rs->raid_type))
		return RAID1_INVALID_FLAGS;
	else if (rt_is_raid10(rs->raid_type))
		return RAID10_INVALID_FLAGS;
	else if (rt_is_raid456(rs->raid_type))
		return RAID456_INVALID_FLAGS;
#endif
	BUG();
}

/* Check for any invalid flags set on @rs defined by bitset @invalid_flags */
static int rs_check_for_invalid_flags(struct raid_set *rs, const uint32_t invalid_flags)
{
	uint32_t flag = 1 << (sizeof(flag) * 8 - 1);

	for (; flag; flag >>= 1)
		if ((flag & invalid_flags) &&
		    (rs->ctr_flags & flag))
			return ti_error_flag(rs->ti, _argname_by_flag(flag));

	return 0;
}

/* Set daemon sleep schedule timeout on @rs to @value unless "raid0" */
static int rs_set_daemon_sleep(struct raid_set *rs, unsigned value)
{
	if (rs_is_raid0(rs))
		return ti_error_einval(rs->ti, "daemon_sleep not applicable to raid0");

	/* MAX_SCHEDULE_TIMEOUT is LONG_MAX; but better be safe */
	if (!_in_range(value, 1, MAX_SCHEDULE_TIMEOUT))
		return ti_error_einval(rs->ti, "Daemon sleep period out of range");

	rs->md.bitmap_info.daemon_sleep = value;
	smp_wmb(); /* Make sure MD uses actual properties */

	return 0;
}

/* Set max write behind on @rs raid1 set to @value */
static int rs_set_max_write_behind(struct raid_set *rs, unsigned value)
{
	if (!rt_is_raid1(rs->raid_type))
		return ti_error_einval(rs->ti, "max_write_behind option is only valid for raid1");

	/*
	 * In device-mapper, we specify things in sectors, but
	 * MD records this value in kB
	 */
	value /= 2;
	if (value > COUNTER_MAX)
		return ti_error_einval(rs->ti, "Max write-behind limit out of range");

	rs->md.bitmap_info.max_write_behind = value;
	smp_wmb(); /* Make sure MD uses actual properties */

	return 0;
}

/* Set min/max recovery rates on @rs redundant raid set (i.e. all levels but raid0) to @value */
enum recovery_rate { min_rate, max_rate };
static int rs_set_recovery_rate(struct raid_set *rs, int value, enum recovery_rate rate)
{
	if (rs_is_raid0(rs))
		return ti_error_einval(rs->ti, "recovery_rate not applicable to raid0");

	if (value > INT_MAX)
		return ti_error_einval(rs->ti, "recovery_rate out of range");

	value /= 2; /* Recovery rate is in KiB, not sectors */

	switch (rate) {
	case min_rate:
		if (value > rs->md.sync_speed_max)
			return ti_error_einval(rs->ti, "min_recovery_rate cannot be greater than max_recovery_rate");

		rs->md.sync_speed_min = value;
		break;

	case max_rate:
		if (value < rs->md.sync_speed_min)
			return ti_error_einval(rs->ti, "max_recovery_rate cannot be smaller than min_recovery_rate");

		rs->md.sync_speed_max = value;
		break;

	default:
		BUG();
	}

	smp_wmb(); /* Make sure MD uses actual properties */

	return 0;
}

/* Set raid4/5/6 cache size */
static int rs_set_raid456_stripe_cache(struct raid_set *rs, int value)
{
	int nr_stripes_min;

	if (!rs_is_raid456(rs))
		return ti_error_einval(rs->ti, "Inappropriate argument: stripe_cache");

	/* Enforce minimum of 32 cache entries if stripe size does not require more anyway */
	nr_stripes_min = max(32, max(rs->md.chunk_sectors, rs->md.new_chunk_sectors) / 2);
	if (value < nr_stripes_min)
		return ti_error_einval(rs->ti, "Invalid small stripe cache size requested");

	/* Try setting number of stripes in raid456 stripe cache */
	if (raid5_set_cache_size(&rs->md, value))
		return ti_error_einval(rs->ti, "Failed to set raid4/5/6 stripe cache size");

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
	/* "near" */
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

/* Return # of data stripes of @mddev */
static unsigned mddev_data_stripes(struct raid_set *rs)
{
	return rs->md.raid_disks - rs->raid_type->parity_devs;
}

/* Calculate the sectors per device and per array used for @rs */
static int rs_set_dev_and_array_sectors(struct raid_set *rs)
{
	int delta_disks = rs->delta_disks ?: rs->md.delta_disks;
	unsigned data_stripes = mddev_data_stripes(rs);
	sector_t dev_sectors = rs->ti->len;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u ti->len=%llu data_stripes=%u", __func__, __LINE__, (unsigned long long) rs->ti->len, data_stripes);
#endif
	if (rt_is_raid1(rs->raid_type)) {
		data_stripes = 1;
		delta_disks = 0;

	} else if (rt_is_raid10(rs->raid_type)) {
		/* HM FIXME: reshape? */
		rs->md.array_sectors = dev_sectors;

		dev_sectors *= rs->raid10_copies;
		if (sector_div(dev_sectors, data_stripes))
			dev_sectors++;

		rs->md.dev_sectors = dev_sectors;

	} else if (!sector_div(dev_sectors, data_stripes)) {
		rs->md.dev_sectors = dev_sectors;
		rs->md.array_sectors = (data_stripes + (delta_disks > 0 ? -delta_disks : delta_disks)) * dev_sectors;

	} else 
		return ti_error_einval(rs->ti, "Target length not divisible by number of data devices");

	rs->md.dev_sectors = dev_sectors;
	rs->md.array_sectors = (data_stripes + (delta_disks > 0 ? -delta_disks : delta_disks)) * dev_sectors;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u dev_sectors=%llu array_sectors=%llu", __func__, __LINE__, (unsigned long long) dev_sectors, (unsigned long long) rs->md.array_sectors);
#endif

	return 0;
}

/*
 * Catch an event @ws thrown by the MD md_misq_wq worker
 *
 * Optionally sets the block device capacity in case the
 * array size has changed after a disk adding/removing reshape
 */
static void do_table_event(struct work_struct *ws)
{
	struct raid_set *rs = container_of(ws, struct raid_set, md.event_work);

	rs_set_capacity(rs);
	dm_table_event(rs->ti->table);
}

/* raid congestion function inquiring md's */
static int raid_is_congested(struct dm_target_callbacks *cb, int bits)
{
	struct raid_set *rs = container_of(cb, struct raid_set, callbacks);

	return mddev_congested(&rs->md, bits);
}

/* True if raid set @rs is currently in the process of reshaping */
static int rs_is_reshaping(struct raid_set *rs)
{
	smp_rmb(); /* Make sure we access recent reshape position */
	return rs->md.reshape_position != MaxSector;
}

/*
 * Make sure a valid takover (level switch) is being requested on @rs
 *
 * Conversions of raid sets from one MD personality to another
 * have to conform to restrictions which are enforced here.
 *
 * Degration is already checked for in rs_check_conversion() below.
 */
static int rs_check_takeover(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	switch (mddev->level) {
	case 0:
		/* raid0 -> raid1/5 with one disk */
		if ((mddev->new_level == 1 || mddev->new_level == 5) &&
		    mddev->raid_disks == 1)
			return 0;

		/* raid0 -> raid10 */
		if (mddev->new_level == 10)
			return 0;

		/* raid0 with multiple disks -> raid4/5/6 */
		if (_in_range(mddev->new_level, 4, 6) &&
		    mddev->new_layout == ALGORITHM_PARITY_N &&
		    mddev->raid_disks > 1)
			return 0;

		break;

	case 10:
		/* raid10 -> raid0 */
		if (mddev->new_level == 0) {
			if (mddev->raid_disks % 2)
				break;

			mddev->raid_disks /= 2;
			mddev->delta_disks = mddev->raid_disks;
			return 0;
		}

		/* raid10 with 2 disks -> raid1/4/5 */
		if ((mddev->new_level == 1 || _in_range(mddev->new_level, 4, 5)) &&
		    mddev->raid_disks == 2)
			return 0;
		break;

	case 1:
		/* raid1 with 2 disks -> raid4/5 */
		if (_in_range(mddev->new_level, 4, 5) &&
		    mddev->raid_disks == 2) {
			mddev->degraded = 1;
			return 0;
		}

		/* raid1 -> raid0/10 */
		if (mddev->new_level == 0 ||
		    mddev->new_level == 10)
			return 0;
		break;

	case 4:
		/* raid4 -> raid0 */
		if (mddev->new_level == 0)
			return 0;

		/* raid4 -> raid1/5 with 2 disks */
		if ((mddev->new_level == 1 || mddev->new_level == 5) &&
		    mddev->raid_disks == 2)
			return 0;

		/* raid4 -> raid5/6 with parity N */
		if (_in_range(mddev->new_level, 5, 6) &&
		    mddev->layout == ALGORITHM_PARITY_N)
			return 0;
		break;

	case 5:
		/* raid5 with parity N -> raid0 */
		if (mddev->new_level == 0 &&
		    mddev->layout == ALGORITHM_PARITY_N)
			return 0;

		/* raid5 with parity N -> raid4 */
		if (mddev->new_level == 4 &&
		    mddev->layout == ALGORITHM_PARITY_N)
			return 0;

		/* raid5 with 2 disks -> raid1/4/10 */
		if ((mddev->new_level == 1 || mddev->new_level == 4 || mddev->new_level == 10) &&
		    mddev->raid_disks == 2)
			return 0;

		/* raid5 with parity N -> raid6 with parity N */
		if (mddev->new_level == 6 &&
		    ((mddev->layout == ALGORITHM_PARITY_N && mddev->new_layout == ALGORITHM_PARITY_N) ||
		      _in_range(mddev->new_layout, ALGORITHM_LEFT_ASYMMETRIC_6, ALGORITHM_RIGHT_SYMMETRIC_6)))
			return 0;
		break;

	case 6:
		/* raid6 with parity N -> raid0 */
		if (mddev->new_level == 0 &&
		    mddev->layout == ALGORITHM_PARITY_N)
			return 0;

		/* raid6 with parity N -> raid4 */
		if (mddev->new_level == 4 &&
		    mddev->layout == ALGORITHM_PARITY_N)
			return 0;

		/* raid6_*_n with parity N -> raid5_* */
		if (mddev->new_level == 5 &&
		    ((mddev->layout == ALGORITHM_PARITY_N && mddev->new_layout == ALGORITHM_PARITY_N) ||
		     _in_range(mddev->new_layout, ALGORITHM_LEFT_ASYMMETRIC, ALGORITHM_RIGHT_SYMMETRIC)))
			return 0;

		break;

	default:
		break;
	}

	return ti_error_einval(rs->ti, "takeover not possible");
}

/* True if @rs requested to be taken over */
static bool rs_takeover_requested(struct raid_set *rs)
{
	return rs->md.new_level != rs->md.level;
}

/* True if @rs is requested to reshape by ctr */
static bool rs_reshape_requested(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	if (!mddev->level)
		return false;

	return  mddev->new_layout != mddev->layout ||
		mddev->new_chunk_sectors != mddev->chunk_sectors ||
		rs->raid_disks + rs->delta_disks != mddev->raid_disks;
}

/* True if @rs requested to resize by ctr */
static bool rs_resize_requested(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;

	return mddev->array_sectors &&
	       mddev->raid_disks == rs->raid_disks &&
	       rs->ti->len != mddev->array_sectors;
}

/* True if either takeover, reshape or resize is requested on @rs */
static bool rs_conversion_requested(struct raid_set *rs)
{
	return rs_takeover_requested(rs) ||
	       rs_reshape_requested(rs)  ||
	       rs_resize_requested(rs);
}

/*
 * Check for reshape constraints on raid set @rs:
 *
 * - reshape function non-existent
 * - degraded set
 * - ongoing recovery
 * - ongoing reshape
 *
 * Returns 0 if none or -EPERM if given constraint
 * and error message reference in @errmsg
 */
static int rs_check_reshape(struct raid_set *rs, const char **errmsg)
{
	struct mddev *mddev = &rs->md;

	if (!mddev->pers->check_reshape)
		*errmsg = "Reshape not supported";
	else if (mddev->degraded)
		*errmsg = "Can't convert degraded raid set";
	else if (mddev->recovery_cp && mddev->recovery_cp != MaxSector)
		*errmsg = "Convert request on recovering raid set prohibited";
	else if (rs_is_reshaping(rs))
		*errmsg = "raid set already converting!";
	else if (!(rs_is_raid10(rs) || rs_is_raid456(rs)))
		*errmsg = "Reshaping only supported for raid4/5/6/10";
	else {
		*errmsg = NULL;
		return 0;
	}

	return -EPERM;
}

/* Read the superblock on @rdev */
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

/* Free resources of device @rd in radi set @rs */
static void free_raid_dev(struct raid_set *rs, struct raid_dev *rd)
{
	if (rd->meta_dev)
		dm_put_device(rs->ti, rd->meta_dev);

	if (rd->rdev.badblocks.page)
		md_rdev_clear(&rd->rdev);

	if (rd->data_dev)
		dm_put_device(rs->ti, rd->data_dev);
}

/* Free raid context of raid set @rs */
static void context_free(struct raid_set *rs)
{
	struct raid_dev *rd;

	for_each_rd(rd, rs)
		free_raid_dev(rs, rd);

	kfree(rs);
}

/* Allocate and return raid context of a raid set */
static struct raid_set *context_alloc(struct dm_target *ti, struct raid_type *raid_type, unsigned raid_devs)
{
	unsigned i;
	struct raid_set *rs;
	struct mddev *mddev;
	size_t sz = sizeof(*rs) + raid_devs * sizeof(*rs->dev);

	if (raid_devs <= raid_type->parity_devs)
		return ERR_PTR(ti_error_einval(ti, "Insufficient number of devices"));

	rs = kzalloc(sz, GFP_KERNEL);
	if (!rs)
		return ERR_PTR(ti_error_ret(ti, "Cannot allocate raid context", -ENOMEM));

	mddev = &rs->md;
	mddev_init(mddev);

	rs->ti = ti;

	/* Has to be reset on md_stop_writes()! */
	INIT_WORK(&mddev->event_work, do_table_event);

	mddev->sync_super = super_sync;
	rs->callbacks.congested_fn = raid_is_congested;
	dm_table_add_target_callbacks(ti->table, &rs->callbacks);

	ti->private = rs;
	ti->num_flush_bios = 1;

	/* The following members are subject to change in load_and_analyse_superblocks */
	rs->raid_type = raid_type;
	mddev->raid_disks = raid_devs;
	mddev->new_level = raid_type->level;
	mddev->new_layout = raid_type->algorithm;
	mddev->delta_disks = 0;
	mddev->recovery_cp = MaxSector;
	mddev->reshape_position = MaxSector;
	/* END: The following members are subject... */

	rs->delta_disks = 0;
	rs->raid_disks = raid_devs;

	for (i = 0; i < raid_devs; i++)
		if (md_rdev_init(&rs->dev[i].rdev)) {
			context_free(rs);
			rs = NULL;
			break;
		}

	/*
	 * Remaining items to be initialized by further raid params:
	 *  mddev->persistent
	 *  mddev->external
	 *  mddev->chunk_sectors
	 *  mddev->new_chunk_sectors
	 *  mddev->dev_sectors
	 */

	return rs;
}

/*
 * Get reference on metadata device @meta_dev for data
 * device @rdev on path @dev_name in raid set @rs and
 * allocate superblock metadata page
 */
static int get_metadata_device(struct raid_set *rs, const char *dev_name,
			       struct md_rdev *rdev, struct dm_dev **meta_dev)
{
	int r = dm_get_device(rs->ti, dev_name,
			      dm_table_get_mode(rs->ti->table), meta_dev);

	if (r)
		return ti_error_ret(rs->ti, "raid metadata device lookup failure", r);

	rdev->sb_page = alloc_page(GFP_KERNEL);
	if (rdev->sb_page)
		memset(page_address(rdev->sb_page), 0, PAGE_SIZE);
	else
		r = -ENOMEM;

	return r;
}

/*
 * Setup raid set @rs fro resize w/o changing number of raid disk.
 * 
 * I.e. component data images have changed size
 */
static int rs_setup_resize(struct raid_set *rs)
{
	int r;
	struct mddev *mddev = &rs->md;
	struct md_rdev *rdev = &rs->dev[0].rdev;
	struct raid_dev *rd;

	if (rs_is_reshaping(rs))
		return -EPERM;

	r = rs_set_dev_and_array_sectors(rs);
	if (r)
		return r;

	/*
	 * On extension unless raid0 or new raid set:
	 *
	 * resynchronize the extended part of the raid set
	 */
	if (!rs_is_raid0(rs) &&
	    rdev->sectors &&
	    mddev->dev_sectors > rdev->sectors) {
		DMINFO("Resynchronizing extended part or raid set");
		mddev->recovery_cp = rdev->sectors;
	}

	for_each_rd(rd, rs)
		rd->rdev.sectors = mddev->dev_sectors;

	return 0;
}

/*
 * Adjust data_offset and new_data_offset on all disk members of @rs
 * for out of place reshaping if requested by contructor
 *
 * We need free space at the beginning of each raid disk for forward
 * and at the end for backward reshapes which userspace has to provide
 * via remapping/reordering of space.
 */
static int rs_adjust_data_offsets(struct raid_set *rs)
{
	sector_t data_offset = 0, new_data_offset = 0;
	struct raid_dev *rd;

	/* Constructor did not request data offset change */
	if (!_test_flag(CTR_FLAG_DATA_OFFSET, &rs->ctr_flags)) {
		if (!rs_is_reshapable(rs))
			goto out;

		return 0;
	}

	/* HM FIXME: get InSync raid_dev? */
	rd = &rs->dev[0];

	if (rs->delta_disks < 0) {
		/*
		 * Removing disks (reshaping backwards):
		 *
		 * - before reshape: data is at offset 0 and free space
		 *		     is at end of each component LV
		 *
		 * - after reshape: data is at offset rs->data_offset != 0 on each component LV
		 */
		data_offset = 0;
		new_data_offset = rs->data_offset;

	} else if (rs->delta_disks > 0) {
		/*
		 * Adding disks (reshaping forwards):
		 *
		 * - before reshape: data is at offset rs->data_offset != 0 and
		 *		     free space is at begin of each component LV
		 *
		 * - after reshape: data is at offset 0 on each component LV
		 */
		data_offset = rs->data_offset;
		new_data_offset = 0;

	} else {
		/*
		 * Changing RAID layout or chunk size -> toggle offsets
		 *
		 * - before reshape: data is at offset rs->data_offset != 0 and
		 *		     free space is at begin of each component LV
		 *
		 * - after reshape: data is at offset 0 on each component LV
		 */
		data_offset = rd->rdev.data_offset;
		new_data_offset = data_offset ? 0 : rs->data_offset;
	}

	/*
	 * Make sure we got a minimum amount of free sectors per device
	 */
	if (_dev_size(rd) - rd->rdev.sectors < MIN_FREE_RESHAPE_SPACE)
		return ti_error_ret(rs->ti, data_offset ? "No space for forward reshape" :
							  "No space for backward reshape",
				   -ENOSPC);

out:
	for_each_rd(rd, rs) {
		rd->rdev.data_offset = data_offset;
		rd->rdev.new_data_offset = new_data_offset;
	}

	return 0;
}

/*
 * Setup @rs for takeover to a different raid level
 */
static int rs_setup_takeover(struct raid_set *rs)
{
	struct mddev *mddev = &rs->md;
	unsigned d = mddev->raid_disks = rs->raid_disks;

	if (rt_is_raid10(rs->raid_type)) {
		int i = 0;
		struct raid_dev *rd;

		if (d % 2) {
			DMERR("Invalid odd number of raid10 disks supplied");
			return -EINVAL;
		}

		/* 1 far (i.e. _no_ division of disks into far copies) and 2 near copies */
		mddev->layout = mddev->new_layout = (1<<8) + 2;
		mddev->delta_disks = d / 2;

		/* Userpace reordered disks -> adjust raid_disk indexes */
		for_each_rd(rd, rs) {
			rd->rdev.raid_disk = i;
			rd->rdev.saved_raid_disk = rd->rdev.new_raid_disk = -1;
			i++;
		}
	}

	/* Bitmap has to be created */
	if (rs_is_raid0(rs))
		set_bit(MD_ARRAY_FIRST_USE, &mddev->flags);

	while (d--) {
		struct raid_dev *rd = rs->dev + d;

		if (test_bit(d, (void *) rs->rebuild_disks)) {
#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u Clearing dev=%u raid_disk=%u In_sync...", __func__, __LINE__, d, rd->rdev.raid_disk);
#endif
			clear_bit(In_sync, &rd->rdev.flags);
			clear_bit(Faulty, &rd->rdev.flags);
			rd->rdev.recovery_offset = 0;
		}

		if (rs->dev[0].rdev.data_offset)
			rd->rdev.new_data_offset = 0;
		else
			rd->rdev.new_data_offset = rs->data_offset;
	}

	return 0;
}

/*
 * Setup raid4/5/6 raid set @rs for reshaping (i.e. not raid level change):
 *
 * - change raid layout
 * - change chunk size
 * - add disks
 * - remove disks
 */
static int rs_setup_reshape(struct raid_set *rs)
{
	int r = 0;
	unsigned d;
	struct mddev *mddev = &rs->md;
	struct md_rdev *rdev;

	mddev->raid_disks = rs->raid_disks;
	mddev->delta_disks = rs->delta_disks;

	/* Ignore impossible layout change whilst adding/removing disks */
	if (mddev->delta_disks &&
	    mddev->layout != mddev->new_layout) {
		DMINFO("Ignoring invalid layout change with delta_disks=%d", rs->delta_disks);
		mddev->new_layout = mddev->layout;
	}

	/* Force writing of superblocks to disk */
	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	/*
	 * Adjust array size:
	 *
	 * - in case of adding disks, array size has
	 *   to grow after the disk adding reshape,
	 *   which'll hapen in the event handler;
	 *   reshape will happen forward, so space has to
	 *   be available at the beginning of each disk
	 *
	 * - in case of removing disks, array size
	 *   has to shrink before starting the reshape,
	 *   which'll happen here;
	 *   reshape will happen backward, so space has to
	 *   be available at the end of each disk
	 *
	 * - data_offset and new_data_offset are
	 *   adjusted for afreentioned out of place
	 *   reshaping based on userspace passing in
	 *   the "data_offset <sectors>" key/value
	 *   pair via te constructor
	 */
	if (mddev->delta_disks < 0) {
		r = rs_set_dev_and_array_sectors(rs);
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u shrink mddev->delta_disks=%d", __func__, __LINE__, mddev->delta_disks);
		WARN_ON(r);
#endif
		mddev->reshape_backwards = 1; /* removing disk(s) -> forward reshape */

	} else if (mddev->delta_disks > 0) {
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u grow mddev->delta_disks=%d", __func__, __LINE__, mddev->delta_disks);
#endif
		/* Prepare disks for check in raid4/5/6 start_reshape */
		for (d = mddev->raid_disks - mddev->delta_disks; d < mddev->raid_disks; d++) {
			rdev = &rs->dev[d].rdev;
#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u rdev[%u]", __func__, __LINE__, d);
#endif
			clear_bit(In_sync, &rdev->flags);
			rdev->recovery_offset = MaxSector;
			rdev->saved_raid_disk = rdev->raid_disk;
			rdev->raid_disk = -1;
			rdev->sectors = mddev->dev_sectors;
		}

		mddev->reshape_backwards = 0; /* adding disks -> forward reshape */

	} else {
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u layout change from=%d to=%d", __func__, __LINE__, mddev->layout, mddev->new_layout);
#endif
		/*
		 * Takeover:
		 *
		 * keeping number of disks and do layout change ->
		 *
		 * toggle reshape_backward depending on data_offset:
		 *
		 * - free space upfront -> reshape forward
		 *
		 * - free space at the end -> reshape backward
		 *
		 *
		 * This utilizes free reshape space avoiding the need
		 * for userspace to move (parts of) LV segments in
		 * case of takeover (for disk adding/removing reshape
		 * space has to be at the proper address;
		 * add: begin / remove: end)
		 *
		 */
		mddev->reshape_backwards = rs->dev[0].rdev.data_offset ? 0 : 1;
	}

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	rdev_for_each(rdev, mddev)
		DMINFO("%s %u rdev[%d]->flags=%lu", __func__, __LINE__, rdev->raid_disk, rdev->flags);
#endif

	return r;
}

/*
 * Reshape changes raid algorithm of @rs to new one within personality
 * (e.g. raid6_zr -> raid6_nc), changes stripe size, adds/removes
 * disks from a raid set thus growing/shrinking it or resizes the set
 *
 * Call mddev_lock() before!
 */
static int rs_start_reshape(struct raid_set *rs)
{
	int r;
	const char *errmsg;
	struct mddev *mddev = &rs->md;
	struct md_personality *pers = mddev->pers;
	struct r5conf *conf = mddev->private;

	BUG_ON(!conf);

	r = rs_check_reshape(rs, &errmsg);
	if (r)
		return ti_error_einval(rs->ti, errmsg);

	r = rs_setup_reshape(rs);
	if (r)
		return r;
#if DEVEL_OUTPUT
	dump_mddev(mddev, __func__);
#endif
	mddev_unlock(mddev);
	/* Need to be resumed to be able to start reshape, recovery is frozen until raid_resume() though */
	mddev_resume(mddev);

	/* Try to adjust the raid4/5/6 stripe cache size to the stripe size */
	/* HM FIXME: I'd rather be able to do it earlier (in the constructor) */
	if (rs_is_raid456(rs)) {
		int nr_stripes_needed = max(mddev->chunk_sectors, mddev->new_chunk_sectors) / 2;

		if (conf->min_nr_stripes < nr_stripes_needed) {
			r = rs_set_raid456_stripe_cache(rs, nr_stripes_needed);
			if (r)
				return r;
		}
	}
		
	/*
	 * Check any reshape constraints enforced by the personalility
	 *
	 * May as well already kick the reshape off so that
	 * pers->start_reshape() becomes optional.
	 */
	r = pers->check_reshape(mddev);
	if (r)
		return ti_error_ret(rs->ti, "pers->check_reshape() failed", r);

	/*
	 * Personality may not provide start reshape method in which
	 * case check_reshape above has already covered everything
	 */
	if (pers->start_reshape) {
		r = pers->start_reshape(mddev);
		if (r)
			return ti_error_ret(rs->ti, "pers->start_reshape() failed", r);
	}

	/* Suspend because resume will happen in raid_resume() */
	mddev_suspend(mddev);

	return 0;
}

/*
 * Select appropriate conversion of
 *
 * - takeover
 * - reshape
 * - resize
 *
 * for @rs and set it up
 */
static int rs_setup_conversion(struct raid_set *rs)
{
	int r = 0;
	struct mddev *mddev = &rs->md;

	/*
	 * Now that a conversion has been requested via the
	 * changed table line and we have any existing superblock
	 * data at hand, check for incompatible ctr flags passed in
	 *
	 * This is being checked for in the constructor path,
	 * but better be cautious.
	 */
	if (!rs_resize_requested(rs) &&
	    (CTR_FLAGS_ANY_SYNC & rs->ctr_flags)) {
		DMINFO("Ignoring any sync arguments on takeover/reshape reques!");
		rs->ctr_flags &= ~CTR_FLAGS_ANY_SYNC;
	}

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	/*
	 * If a takeover is needed, just set the level to
	 * the new requested one and allow the raid set to run.
	 */
	if (rs_takeover_requested(rs)) {
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u *** takeover ***", __func__, __LINE__);
#endif
		r = rs_check_takeover(rs);
		if (r)
			return r;

		r = rs_setup_takeover(rs);
		rs_set_new(rs);

	/*
	 * In case of reshape, start up set with current
	 * config and initiate the reshape afterwards
	 * via the MD personalities reshape method(s)
	 */
	} else if (rs_reshape_requested(rs)) {
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u *** reshape ***", __func__, __LINE__);
#endif
		if (rs_is_raid456(rs) || rs_is_raid10(rs))
			_set_flag(RT_FLAG_RESHAPE, &rs->runtime_flags);

		else if (rs_is_raid1(rs))
			mddev->raid_disks = rs->raid_disks;

		rs_set_cur(rs);

	/*
	 * resize requested:
	 *
	 * set dev_sectors and array_sectors and start the array.
	 */
	} else if (rs_resize_requested(rs)) {
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u *** resize ***", __func__, __LINE__);
#endif
		r = rs_setup_resize(rs);
		if (!r)
			rs_set_new(rs);

	} else
		BUG();

	return r;
}

/*
 * Parse the "<meta_dev> <data_dev>" pairs passed in by the constructor
 *
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

	/* Put off the number of raid devices argument to get to dev pairs */
	dm_shift_arg(as);

	for_each_rd(rd, rs) {
		rdev = &rd->rdev;
		rdev->raid_disk = i++;
		rd->meta_dev = rd->data_dev = NULL;
		rdev->mddev = &rs->md;

		arg = dm_shift_arg(as);
		if (strcmp(arg, "-")) {
			r = get_metadata_device(rs, arg, rdev, &rd->meta_dev);
			if (r)
				return ti_error_ret(rs->ti, "raid metadata device lookup failure", r);
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
			return ti_error_ret(rs->ti, "raid device lookup failure", r);

		if (rd->meta_dev) {
			metadata_available = 1;
			rdev->meta_bdev = rd->meta_dev->bdev;
#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u meta_bdev=%s", __func__, __LINE__, rd->meta_dev->name);
#endif
		}

		rdev->bdev = rd->data_dev->bdev;
		rdev->sectors = rs->md.dev_sectors;

		if (!test_bit(In_sync, &rdev->flags))
			rebuild++;

		list_add_tail(&rdev->same_set, &rs->md.disks);
	}

	if (metadata_available) {
		rs->md.external = 0;
		rs->md.persistent = 1;
		rs->md.major_version = 2;
	} else if (rebuild) {
		/*
		 * Without metadata, we will not be able to tell if the raid set
		 * is in-sync or not - we must assume it is not.  Therefore,
		 * it is impossible to rebuild a drive.
		 *
		 * Even if there is metadata, the on-disk information may
		 * indicate that the raid set is not in-sync and it will then
		 * fail at that time.
		 *
		 * User could specify 'nosync' option if desperate.
		 */
		return ti_error_einval(rs->ti, "Unable to rebuild a drive w/o any metadata device");
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
 * validate_raid_redundancy of raid set @rs
 *
 * Determine if there are enough devices in the raid set that haven't
 * failed (or are being rebuilt) to form a usable raid set.
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
	struct raid_dev *rd;

	for_each_rd(rd, rs) {
		rdev = &rd->rdev;
		if (raid_disks == mddev->raid_disks - mddev->delta_disks)
			break;

		raid_disks++;
		if (rdev->recovery_offset == MaxSector &&
		    (!test_bit(In_sync, &rdev->flags) ||
		     !rdev->sb_page))
			rebuild_cnt++;
	}

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %d rebuild_cnt=%u", __func__, __LINE__, rebuild_cnt);
#endif

	switch (mddev->level) {
	case 1:
		if (rebuild_cnt >= raid_disks)
			goto too_many;
		break;
	case 0:
	case 4:
	case 5:
	case 6:
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %d rt=%s rc=%u pd=%u", __func__, __LINE__, rs->raid_type->name, rebuild_cnt, rs->raid_type->parity_devs);
#endif
		if (rebuild_cnt > rs->raid_type->parity_devs)
			goto too_many;
		break;
	case 10:
		copies = raid10_md_layout_to_copies(rs->md.layout);
		if (rebuild_cnt < copies)
			break;

		/*
		 * It is possible to have a higher rebuild count for raid10,
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
				rdev = &(rs->dev + (i & raid_disks))->rdev;
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
		 * for raid sets that are not a multiple of (far) copies.  This
		 * results in the need to treat the last (potentially larger)
		 * set differently.
		 */
		group_size = (rs->md.raid_disks / copies);
		last_group_start = (rs->md.raid_disks / group_size) - 1;
		last_group_start *= group_size;
		i = 0;
		for_each_rd(rd, rs) {
			rdev = &rd->rdev;

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

	return 0;

too_many:
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %d", __func__, __LINE__);
#endif
	return -EINVAL;
}

/*
 * Parse all raid parameters passed in by the constructor
 *
 * Possible arguments are...
 *	<chunk_size> [optional_args]
 *
 * Argument definitions
 *    <chunk_size>			The number of sectors per disk that
 *                                      will form the "stripe"
 *    [data_offset <sectors>]		Reshape:
 *					request data offset change on each raid disk image;
 *					used to pass new offset in after uspace (al|re)located
 *					space at the begin/end of each data disk
 *    [ignore_discard]                  Ignore any discards;
 *                                      can be used in cases of bogus TRIM/UNMAP
 *                                      support on raid set legs (e.g. discard_zeroes_data
 *                                      flaw causing raid4/5/6 corruption)
 *    [[no]sync]			Force or prevent recovery of the
 *                                      entire raid set; ürohibited with reshape_{add,remove}
 *    [delta_disks #+/-disks]		Reshape: add/remove the amount of disks to the raid set
 *                                      listed at the end of the table line
 *    [rebuild <idx>]			Rebuild the drive indicated by the index
 *    [daemon_sleep <ms>]		Time between bitmap daemon work to
 *                                      clear bits
 *    [min_recovery_rate <kB/sec/disk>]	Throttle raid initialization
 *    [max_recovery_rate <kB/sec/disk>]	Throttle raid initialization
 *    [write_mostly <idx>]		Indicate a write mostly drive via index
 *    [max_write_behind <sectors>]	See '-write-behind=' (man mdadm)
 *    [stripe_cache <sectors>]		Stripe cache size for higher raids
 *    [region_size <sectors>]           Defines granularity of bitmap
 *
 * raid10-only options:
 *    [raid10_copies <# copies>]        Number of copies.  (Default: 2)
 *    [raid10_format <near|far|offset>] Layout algorithm.  (Default: near)
 */

/* Helper fn to adjust chunk_size of @rs in @value depending on raid level (takeover) */
static int _check_adjust_chunksize(struct raid_set *rs, int *chunk_size)
{
	if (rt_is_raid1(rs->raid_type)) {
		if (*chunk_size)
			DMERR("Ignoring chunk size parameter for raid 1");
		*chunk_size = 0;
	} else if (*chunk_size < to_sector(PAGE_SIZE))
		/* Adjust for userspace passing in 0 for takeover from raid1 -> raid4/5 */
		*chunk_size = 64;
	else if (!is_power_of_2(*chunk_size))
		return ti_error_einval(rs->ti, "Chunk size must be a power of 2");
	else if (*chunk_size < 8)
		return ti_error_einval(rs->ti, "Chunk size value is too small");

	return 0;
}

/* Helper fn to check for the single argument in @arg */
static bool _check_single_args(struct raid_set *rs, const char *arg)
{
	uint32_t flag = 1 << (sizeof(flag) * 8 - 1);
	static const uint32_t single_args = CTR_FLAG_OPTIONS_NO_ARGS;

	for (; flag; flag >>= 1) {
		if ((flag & single_args) &&
		    !strcasecmp(arg, _argname_by_flag(flag))) {
			rs->ctr_flags |= flag;
			return true;
		}
	}

	return false;
}

/* raid argument parsing for raid set @rs of @num_raid_params argument (pairs) in @as */
static int parse_raid_params(struct raid_set *rs, struct dm_arg_set *as,
			     unsigned num_raid_params)
{
	int r, region_size = 0, value;
	unsigned rebuilds = 0;
	unsigned i;
	const char *arg, *key, *raid10_format = "near";
	sector_t sectors_per_dev = rs->ti->len;
	sector_t max_io_len;
	struct raid_dev *rd;

	/*
	 * First, parse the in-order required arguments
	 * "chunk_size" is the only argument of this type.
	 */
	arg = dm_shift_arg(as);
	num_raid_params--; /* Account for chunk_size argument */

	if (kstrtoint(arg, 10, &value) < 0)
		return ti_error_einval(rs->ti, "Bad numerical argument given for chunk_size");

	r = _check_adjust_chunksize(rs, &value);
	if (r < 0)
		return r;

	rs->md.chunk_sectors = value;
	rs->md.new_chunk_sectors = value;

	rs->raid10_copies = 2;

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
	 * authoritative, unless 'rebuild', "'delta_disks' or '[no]sync'
	 * was specified
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
		if (!arg)
			return ti_error_einval(rs->ti, "Not enough raid parameters given");

		/* Check for the single arguments first */
		if (_check_single_args(rs, arg))
			continue;

		/* The rest of the optional arguments come in key/value pairs */
		if (i > num_raid_params)
			return ti_error_einval(rs->ti, "Wrong number of raid parameters given");

		key = arg;
		arg = dm_shift_arg(as);
		i++; /* Account for the argument pairs */

		/* Parameter "raid10_format" which takes a string value is checked here. */
		if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_RAID10_FORMAT))) {
			if (rs->ctr_flags & CTR_FLAG_RAID10_FORMAT)
				return ti_error_einval(rs->ti, "Only one raid10_format argument pair allowed");

			if (strcasecmp("near", arg) &&
			    strcasecmp("far", arg) &&
			    strcasecmp("offset", arg))
				return ti_error_einval(rs->ti, "Invalid 'raid10_format' value given");

			raid10_format = arg;
			rs->ctr_flags |= CTR_FLAG_RAID10_FORMAT;
			continue;
		}

		/* All other parameters take a numeric argument and are checked here */
		if (kstrtoint(arg, 10, &value) < 0)
			return ti_error_einval(rs->ti, "Bad numerical argument given in raid params");

		if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_DAEMON_SLEEP))) {
			if (_test_and_set_flag(CTR_FLAG_DAEMON_SLEEP, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one daemon_sleep argument pair allowed");

			if (rs_set_daemon_sleep(rs, value))
				return -EINVAL;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_DATA_OFFSET))) {
			/* Userspace passes new data_offset after having extended the the data image LV */
			if (_test_and_set_flag(CTR_FLAG_DATA_OFFSET, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one data_offset argument pair allowed");

			/* Ensure sensible data offset */
			if (value < 0)
				return ti_error_einval(rs->ti, "Bogus data_offset value");

			rs->data_offset = value;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_DELTA_DISKS))) {
			/* Define the +/-# of disks to add to/remove from the given raid set */
			if (_test_and_set_flag(CTR_FLAG_DELTA_DISKS, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one delta_disks argument pair allowed");

			/* Ensure MAX_raid_DEVICES and raid type minimal_devs! */
			if (!_in_range(abs(value), 1, MAX_raid_DEVICES - rs->raid_type->minimal_devs))
				return ti_error_einval(rs->ti, "Too many delta_disk requested");

			rs->delta_disks = value;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_MIN_RECOVERY_RATE))) {
			if (_test_and_set_flag(CTR_FLAG_MIN_RECOVERY_RATE, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one min_recovery_rate argument pair allowed");

			r = rs_set_recovery_rate(rs, value, min_rate);
			if (r)
				return r;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_MAX_RECOVERY_RATE))) {
			if (_test_and_set_flag(CTR_FLAG_MAX_RECOVERY_RATE, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one max_recovery_rate argument pair allowed");

			r = rs_set_recovery_rate(rs, value, max_rate);
			if (r)
				return r;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_MAX_WRITE_BEHIND))) {
			if (_test_and_set_flag(CTR_FLAG_MAX_WRITE_BEHIND, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one max_write_behind argument pair allowed");

			r = rs_set_max_write_behind(rs, value);
			if (r)
				return r;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_RAID10_COPIES))) {
			if (_test_and_set_flag(CTR_FLAG_RAID10_COPIES, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one raid10_copies argument pair allowed");

			if (!_in_range(value, 2, 0xFF))
				return ti_error_einval(rs->ti, "Bad value for 'raid10_copies'");

			rs->raid10_copies = value;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_REBUILD))) {
			/*
			 * "rebuild" is being passed in by userspace to provide
			 * indexes of replaced devices and to set up additional
			 * devices on raid level takeover.
			 */
			if (!_in_range(value, 0, rs->md.raid_disks - 1))
				return ti_error_einval(rs->ti, "Invalid rebuild index given");

			if (test_and_set_bit(value, (void *) rs->rebuild_disks))
				return ti_error_einval(rs->ti, "rebuild for this index already given");

			rd = rs->dev + value;
			clear_bit(In_sync, &rd->rdev.flags);
			clear_bit(Faulty, &rd->rdev.flags);
			rd->rdev.recovery_offset = 0;
			rebuilds++;
			rs->ctr_flags |= CTR_FLAG_REBUILD;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_REGION_SIZE))) {
			if (_test_and_set_flag(CTR_FLAG_REGION_SIZE, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one region_size argument pair allowed");

			region_size = value;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_STRIPE_CACHE))) {
			if (_test_and_set_flag(CTR_FLAG_STRIPE_CACHE, &rs->ctr_flags))
				return ti_error_einval(rs->ti, "Only one stripe_cache argument pair allowed");

			r = rs_set_raid456_stripe_cache(rs, value);
			if (r)
				return r;

		} else if (!strcasecmp(key, _argname_by_flag(CTR_FLAG_WRITE_MOSTLY))) {
			if (!rt_is_raid1(rs->raid_type))
				return ti_error_einval(rs->ti, "write_mostly option is only valid for raid1");

			if (!_in_range(value, 0, rs->md.raid_disks - 1))
				return ti_error_einval(rs->ti, "Invalid write_mostly index given");

			if (test_and_set_bit(value, (void *) rs->writemostly_disks))
				return ti_error_einval(rs->ti, "writemostly for this index already given");

			rd = rs->dev + value;
			set_bit(WriteMostly, &rd->rdev.flags);
			rs->ctr_flags |= CTR_FLAG_WRITE_MOSTLY;

		} else
			return ti_error_einval(rs->ti, "Unable to parse raid parameters");
	}

	/* Prevent all raid disks from being set write_mostly */
	if (_count_bits(rs->writemostly_disks) == rs->md.raid_disks)
		return ti_error_einval(rs->ti, "Can't set all raid disks write_mostly");

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("rebuilds=%u", rebuilds);
#endif

	/* Check sensefull amount of disks to rebuild got requested */
	if (rebuilds) {
		/* Prevent all raid disks from being requested to rebuild */
		if (rebuilds == rs->md.raid_disks)
			return ti_error_einval(rs->ti, "Can't rebuild all raid disks");

		if (rs_is_raid456(rs) &&
		    rebuilds > rs->raid_type->parity_devs)
			return ti_error_einval(rs->ti, "Can't rebuild that many raid disks in a raid4/5/6 set");

		if (rs_is_raid0(rs))
			return ti_error_einval(rs->ti, "Can't rebuild disk in a raid0 set");
	}

	if ((rs->ctr_flags & CTR_FLAGS_ANY_SYNC) == CTR_FLAGS_ANY_SYNC)
		return ti_error_einval(rs->ti, "Nosync and sync are mutually exclusive");

	/* "delta_disks": check for invalid arguments */
	if ((rs->ctr_flags & CTR_FLAG_DELTA_DISKS) &&
	    (rs->ctr_flags & CTR_FLAGS_ANY_SYNC))
		return ti_error_einval(rs->ti, "Sync/nosync and delta_disks are mutually exclusive");

	/* Check, if any invalid ctr arguments have been passed in for the raid level */
	r = rs_check_for_invalid_flags(rs, _invalid_flags(rs));
	if (r)
		return r;

	/* "region_size": check it's valid unless "raid0", which does not have a bitmap, thus no region_size */
	if (!rt_is_raid0(rs->raid_type) &&
	    validate_region_size(rs, region_size))
		return -EINVAL;

	max_io_len = rs->md.chunk_sectors ?: region_size;

	if (dm_set_target_max_io_len(rs->ti, max_io_len))
		return -EINVAL;

	/* "raid10": check for invalid format/copies */
	if (rt_is_raid10(rs->raid_type)) {
		/* Check for "near" constraint */
		if (!strcmp(raid10_format, "near") &&
		    rs->md.raid_disks > 2 &&
		    rs->raid10_copies > rs->md.raid_disks) //  - 1)
			return ti_error_einval(rs->ti, "Not enough devices to satisfy specification");

		rs->md.new_layout = raid10_format_to_md_layout(raid10_format, rs->raid10_copies);
	}

	/* Assume there are no metadata devices until the drives are parsed */
	rs->md.persistent = 0;
	rs->md.external = 1;

	return 0;
}

/*  Features */
#define	FEATURE_FLAG_SUPPORTS_RESHAPE	0x1

/* State flags */
#define	SB_FLAG_RESHAPE_ACTIVE		0x1
#define	SB_FLAG_RESHAPE_BACKWARDS	0x2

/*
 * This structure is never routinely used by userspace, unlike md superblocks.
 * Devices with this superblock should only ever be accessed via device-mapper.
 */
#define DM_raid_MAGIC 0x64526D44
struct dm_raid_superblock {
	__le32 magic;		/* "DmRd" */
	__le32 features;	/* Used to indicate possible future changes */

	__le32 num_devices;	/* Number of devices in this raid set. (Max 64) */
	__le32 array_position;	/* The position of this drive in the raid set */

	__le64 events;		/* Incremented by md when superblock updated */
	__le64 failed_devices;	/* Bit field of devices to indicate failures */

	/*
	 * This offset tracks the progress of the repair or replacement of
	 * an individual drive.
	 */
	__le64 disk_recovery_offset;

	/*
	 * This offset tracks the progress of the initial raid set
	 * synchronisation/parity calculation.
	 */
	__le64 array_resync_offset;

	/*
	 * raid characteristics
	 */
	__le32 level;
	__le32 layout;
	__le32 stripe_sectors;

	/*
	 * BELOW FOLLOW V1.8.0 ADDITIONS TO THE PRISTINE SUPERBLOCK FORMAT!!!
	 *
	 * FEATURE_FLAG_SUPPORTS_RESHAPE in the features member indicates that those exist
	 */

	/* Flags defining array states for reshaping */
	__le32 flags;

	/*
	 * This offset tracks the progress of a raid
	 * set reshape in order to be able to restart it
	 */
	__le64 reshape_position;

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

	/*
	 * Additonal Bit field of devices indicating failures to support
	 * up to 256 devices with the 1.8.0 on-disk metadata format
	 */
	__le64 extended_failed_devices[DISKS_ARRAY_ELEMS - 1];

	/* Always set rest up to logical block size to 0 when writing (see super_sync() below). */
} __packed;

/* Helper to retrieve all failed devices bits from @sb */
static void sb_retrieve_failed_devices(struct dm_raid_superblock *sb, uint64_t *failed_devices)
{
	failed_devices[0] = le64_to_cpu(sb->failed_devices);
	memset(failed_devices + 1, 0, sizeof(sb->extended_failed_devices));

	if (FEATURE_FLAG_SUPPORTS_RESHAPE & le32_to_cpu(sb->features)) {
		int i = ARRAY_SIZE(sb->extended_failed_devices);

		while (i--)
			failed_devices[i+1] = le64_to_cpu(sb->extended_failed_devices[i]);
	}
}

/* Helper to update all failed devices bits in @sb */
static void sb_update_failed_devices(struct dm_raid_superblock *sb, uint64_t *failed_devices)
{
	int i = ARRAY_SIZE(sb->extended_failed_devices);

	sb->failed_devices = cpu_to_le64(failed_devices[0]);
	while (i--)
		sb->extended_failed_devices[i] = cpu_to_le64(failed_devices[i+1]);
}

/*
 * Synchronize the superblock members with the raid set properties
 *
 * All superblock data is little endian.
 */
static void super_sync(struct mddev *mddev, struct md_rdev *rdev)
{
	unsigned i;
	uint64_t failed_devices[DISKS_ARRAY_ELEMS];
	struct dm_raid_superblock *sb;
	struct raid_set *rs = container_of(mddev, struct raid_set, md);

	/* No metadata device, no superblock */
	if (!rdev->meta_bdev)
		return;

	sb = page_address(rdev->sb_page);
	sb_retrieve_failed_devices(sb, failed_devices);

	for (i = 0; i < rs->raid_disks; i++)
		if (!rs->dev[i].data_dev || test_bit(Faulty, &rs->dev[i].rdev.flags))
			set_bit(i, (void *) failed_devices);

	/* Zero out the rest of the payload after the size of the superblock */
	memset(sb + 1, 0, rdev->sb_size - sizeof(*sb));

	sb->magic = cpu_to_le32(DM_raid_MAGIC);
	sb->features = cpu_to_le32(FEATURE_FLAG_SUPPORTS_RESHAPE);

	sb->num_devices = cpu_to_le32(mddev->raid_disks);
	sb->array_position = cpu_to_le32(rdev->raid_disk);

	sb->events = cpu_to_le64(mddev->events);

	sb_update_failed_devices(sb, failed_devices);

	sb->disk_recovery_offset = cpu_to_le64(rdev->recovery_offset);
	sb->array_resync_offset = cpu_to_le64(mddev->recovery_cp);
	sb->reshape_position = cpu_to_le64(mddev->reshape_position);

	sb->level = cpu_to_le32(mddev->level);
	sb->layout = cpu_to_le32(mddev->layout);
	sb->stripe_sectors = cpu_to_le32(mddev->chunk_sectors);

	sb->new_level = cpu_to_le32(mddev->new_level);
	sb->new_layout = cpu_to_le32(mddev->new_layout);
	sb->new_stripe_sectors = cpu_to_le32(mddev->new_chunk_sectors);

	sb->delta_disks = cpu_to_le32(mddev->delta_disks);

	smp_rmb(); /* Make sure we access most recent reshape position */
	if (mddev->reshape_position != MaxSector) {
		/* Flag ongoing reshape */
		sb->flags |= cpu_to_le32(SB_FLAG_RESHAPE_ACTIVE);

		if (mddev->delta_disks < 0 || mddev->reshape_backwards)
			sb->flags |= cpu_to_le32(SB_FLAG_RESHAPE_BACKWARDS);
	} else
		/* Flag no reshape */
		sb->flags &= cpu_to_le32(~(SB_FLAG_RESHAPE_ACTIVE|SB_FLAG_RESHAPE_BACKWARDS));

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

	/*
	 * We got a dedicated metadata device, so
	 * the superblock is at offset 0 on it.
	 */
	rdev->sb_start = 0;

	/*
	 * Make sure to cope with 4K sectored devices.
	 *
	 * We allocate a payload of PAGE_SIZE for it,
	 * so check if the in-core superblock fits
	 * and the logical block size is not larger
	 * than a page.
	 */
	rdev->sb_size = bdev_logical_block_size(rdev->meta_bdev);
	if (!_in_range(rdev->sb_size, sizeof(*sb), PAGE_SIZE)) {
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
	if ((sb->magic != cpu_to_le32(DM_raid_MAGIC)) ||
	    (!test_bit(In_sync, &rdev->flags) && !rdev->recovery_offset)) {
		struct mddev *mddev = rdev->mddev;

		rs_set_new(rs);
		super_sync(mddev, rdev);

		/*
		 * Set dm-raid private flag to indicate first use of device.
		 * Will be reset before running the array.
		 */
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
 * Validate the freshest raid device @rdev of raid set @rs
 *
 * Return: 0 if ok, -EINVAL otherwise
 */
static int super_validate_freshest(struct raid_set *rs, struct md_rdev *rdev)
{
	int role;
	unsigned d;
	struct mddev *mddev = &rs->md;
	uint64_t events_sb;
	uint64_t failed_devices[DISKS_ARRAY_ELEMS];
	struct dm_raid_superblock *sb;
	uint32_t new_devs = 0;
	uint32_t rebuilds = 0;
	struct md_rdev *r;
	struct raid_dev *rd;
	struct dm_raid_superblock *sb2;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	sb = page_address(rdev->sb_page);
	events_sb = le64_to_cpu(sb->events);

	/*
	 * Initialise to 1 if this is a new superblock.
	 */
	mddev->events = events_sb ? : 1;

	mddev->reshape_position = MaxSector;

	/*
	 * Reshaping is supported, e.g. reshape_position is valid
	 * in superblock and superblock content is authoritative.
	 */
	if (FEATURE_FLAG_SUPPORTS_RESHAPE & le32_to_cpu(sb->features)) {
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u", __func__, __LINE__);
#endif
		/* Superblock is authoritative wrt given raid set layout! */
		mddev->raid_disks = le32_to_cpu(sb->num_devices);
		mddev->level = le32_to_cpu(sb->level);
		mddev->layout = le32_to_cpu(sb->layout);
		mddev->chunk_sectors = le32_to_cpu(sb->stripe_sectors);
		mddev->new_level = le32_to_cpu(sb->new_level);
		mddev->new_layout = le32_to_cpu(sb->new_layout);
		mddev->new_chunk_sectors = le32_to_cpu(sb->new_stripe_sectors);
		mddev->delta_disks = le32_to_cpu(sb->delta_disks);
		mddev->array_sectors = le64_to_cpu(sb->array_sectors);

		/* raid was reshaping and got interrupted */
		if (SB_FLAG_RESHAPE_ACTIVE & le32_to_cpu(sb->flags)) {
#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u", __func__, __LINE__);
#endif
			if (rs->ctr_flags & CTR_FLAG_DELTA_DISKS) {
				DMERR("Reshape requested but raid set is still reshaping");
				return -EINVAL;
			}

			if (mddev->delta_disks < 0 ||
			    (!mddev->delta_disks && (le32_to_cpu(sb->flags) & SB_FLAG_RESHAPE_BACKWARDS)))
				mddev->reshape_backwards = 1;
			else
				mddev->reshape_backwards = 0;

			mddev->reshape_position = le64_to_cpu(sb->reshape_position);
			rs->raid_type = get_raid_type_by_ll(mddev->level, mddev->layout);
#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u reshape_backwards=%u reshape_position=%llu raid_type=%s", __func__, __LINE__, mddev->reshape_backwards, (unsigned long long) mddev->reshape_position, rs->raid_type->name);
#endif
		}

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, __func__);
#endif

	} else {
		/*
		 * Reshaping is not allowed, bacause we don't have the appropriate metadata
		 */
		if (le32_to_cpu(sb->level) != mddev->level) {
			DMERR("Reshaping raid sets not yet supported. (raid level/stripes/size change)");
			return -EINVAL;
		}
		if (le32_to_cpu(sb->layout) != mddev->layout) {
			DMERR("Reshaping raid sets not yet supported. (raid layout change)");
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
			DMERR("Reshaping raid sets not yet supported. (stripe sectors change)");
			return -EINVAL;
		}

		/* We can only change the number of devices in raid1 with old (i.e. pre 1.0.7) metadata */
		if (!rt_is_raid1(rs->raid_type) &&
		    (le32_to_cpu(sb->num_devices) != mddev->raid_disks)) {
			DMERR("Reshaping raid sets not yet supported. (device count change from %u to %u)",
			      sb->num_devices, mddev->raid_disks);
			return -EINVAL;
		}

		/* Table line is checked vs. authoritative superblock */
		rs_set_new(rs);
	}

	if (!(rs->ctr_flags & CTR_FLAG_NOSYNC))
		mddev->recovery_cp = le64_to_cpu(sb->array_resync_offset);
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, __func__);
#endif

	/* HM FIXME: logic below wrong for reshape?! */
	/*
	 * During load, we set FirstUse if a new superblock was written.
	 * There are two reasons we might not have a superblock:
	 * 1) The raid set is brand new - in which case, all of the
	 *    devices must have their In_sync bit set.  Also,
	 *    recovery_cp must be 0, unless forced.
	 * 2) This is a new device being added to an old raid set
	 *    and the new device needs to be rebuilt - in which
	 *    case the In_sync bit will /not/ be set and
	 *    recovery_cp must be MaxSector.
	 */
	d = 0;
	for_each_rd(rd, rs) {
		r = &rd->rdev;

#if 1
		if (test_bit(FirstUse, &r->flags))
			new_devs++;
#else
		if (test_bit(FirstUse, &r->flags) && !test_bit(d, (void *) rs->rebuild_disks))
{
DMINFO("%s %u %u=%d", __func__, __LINE__, d, test_bit(d, (void *) rs->rebuild_disks));
			new_devs++;
}
#endif
		else if (!test_bit(In_sync, &r->flags)) {
			DMINFO("Device %d specified for rebuild\nClearing superblock",
				r->raid_disk);
			rebuilds++;
		}

		d++;
	}
DMINFO("%s %u new_devs=%u rs->rebuild_disks=%llX", __func__, __LINE__, new_devs, (unsigned long long) rs->rebuild_disks[0]);

	if (new_devs == rs->raid_disks || !rebuilds) {
		/* Replace a broken device */
		if (new_devs == 1 && !rs->delta_disks)
			;
		if (new_devs == rs->raid_disks) {
			DMINFO("Superblocks created for new raid set");
			set_bit(MD_ARRAY_FIRST_USE, &mddev->flags);
			mddev->recovery_cp = 0;
		} else if (new_devs && !(rs->ctr_flags & (CTR_FLAG_DELTA_DISKS|CTR_FLAG_REBUILD))) {
			DMERR("New device injected into existing raid set without "
			      "'delta_disks' or 'rebuild' parameter specified");
			return -EINVAL;
		}
	} else if (new_devs) {
		DMERR("'rebuild' devices cannot be injected into"
		      " a raid set with other first-time devices");
		return -EINVAL;
	} else if (rebuilds) {
		if (mddev->recovery_cp != MaxSector) {
			DMERR("'rebuild' specified while raid set is not in-sync");
			return -EINVAL;
		}
		if (mddev->reshape_position != MaxSector) {
			DMERR("'rebuild' specified while raid set is being reshaped");
			return -EINVAL;
		}
	}

	/*
	 * Now we set the Faulty bit for those devices that are
	 * recorded in the superblock as failed.
	 */
	sb_retrieve_failed_devices(sb, failed_devices);
	rdev_for_each(r, mddev) {
		if (!r->sb_page)
			continue;
		sb2 = page_address(r->sb_page);
		sb2->failed_devices = 0;
		memset(sb2->extended_failed_devices, 0, sizeof(sb2->extended_failed_devices));

		/*
		 * Check for any device re-ordering.
		 */
		if (!test_bit(FirstUse, &r->flags) && (r->raid_disk >= 0)) {
			role = le32_to_cpu(sb2->array_position);
#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u role=%d raid_disk=%d", __func__, __LINE__, role, r->raid_disk);
#endif
			if (role < 0)
				continue;

			if (role != r->raid_disk) {
				if (!(rs_is_raid10(rs) && rt_is_raid0(rs->raid_type)) &&
				    !(rs_is_raid0(rs) && rt_is_raid10(rs->raid_type)) &&
				    !rt_is_raid1(rs->raid_type))
					return ti_error_einval(rs->ti, "Cannot change device positions in raid set");

				DMINFO("raid1 device #%d now at position #%d",
				       role, r->raid_disk);
			}

			/*
			 * Partial recovery is performed on
			 * returning failed devices.
			 */
			if (test_bit(role, (void *) failed_devices))
				set_bit(Faulty, &r->flags);
		}
	}

	return 0;
}

/*
 * Validate superblock of @rdev
 */
static int super_validate(struct raid_set *rs, struct md_rdev *rdev)
{
	struct dm_raid_superblock *sb;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	if (!rdev->sb_page)
		return 0;

	sb = page_address(rdev->sb_page);

	if (!test_and_clear_bit(FirstUse, &rdev->flags)) {
		rdev->recovery_offset = le64_to_cpu(sb->disk_recovery_offset);
		if (rdev->recovery_offset == MaxSector)
			set_bit(In_sync, &rdev->flags);
		/*
		 * If no reshape in progress -> we're recovering single
		 * disk(s) and have to set the device(s) to out-of-sync
		 */
		else if (rs->md.reshape_position == MaxSector)
			clear_bit(In_sync, &rdev->flags); /* Mandatory for recovery */

#if DEVEL_OUTPUT
			/* HM FIXME REMOVEME: devel */
			DMINFO("%s %u recovery_offset=%llu raid_disk=%d", __func__, __LINE__, (unsigned long long) rdev->recovery_offset, rdev->raid_disk);
#endif
	}

	/*
	 * If a device comes back, set it as not In_sync and no longer faulty.
	 */
	if (test_and_clear_bit(Faulty, &rdev->flags)) {
		rdev->recovery_offset = 0;
		clear_bit(In_sync, &rdev->flags);
		rdev->saved_raid_disk = rdev->raid_disk;
	}

	/* Reshape support -> restore repective members */
	if (FEATURE_FLAG_SUPPORTS_RESHAPE & le32_to_cpu(sb->features)) {
		rdev->data_offset = le64_to_cpu(sb->data_offset);
		rdev->new_data_offset = le64_to_cpu(sb->new_data_offset);
		rdev->sectors = le64_to_cpu(sb->sectors);
	}

	return 0;
}

/*
 * Load any superblocks from all raid devices of raid set @rs
 * and return frehest one (may be NULL for new raid set)
 */
static struct md_rdev *superblocks_load(struct raid_set *rs)
{
	unsigned d = 0;
	struct raid_dev *rd;
	struct md_rdev *freshest = NULL;

	for_each_rd(rd, rs) {
		int r;
		struct md_rdev *rdev = &rd->rdev;

		d++;

		/* No metadata device -> ignore */
		if (!rdev->meta_bdev)
			continue;
#if 0
		/* HM FIXME: find a way to avoid _clear_lvs() in uspace() */
		/* Rebuild data image dev -> ignore metadata */
		if (test_bit(d - 1, (void *) rs->rebuild_disks)) {
			set_bit(FirstUse, &rdev->flags);
			continue;
		}
#endif
		r = super_load(rs, rdev, freshest);
		switch (r) {
		case 1:
			freshest = rdev;
		case 0:
			break;
		default:
			/* IO error -> remove the raid disk */
			raid_dev_remove(rs->ti, rd);
			rs->failed_disks++;
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
	struct raid_dev *rd;

	/* Be cautious: given in case of "raid0" w/o metadata */
	if (!freshest->sb_page)
		return 0;

	if (super_validate_freshest(rs, freshest))
		return ti_error_einval(rs->ti, "Unable to assemble raid set: Invalid freshest superblock");

	for_each_rd(rd, rs)
		if (super_validate(rs, &rd->rdev))
			return ti_error_einval(rs->ti, "Unable to assemble raid set: Invalid superblock");

	if (validate_raid_redundancy(rs))
		return ti_error_einval(rs->ti, "Insufficient redundancy to activate raid set");

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
	struct md_rdev *freshest = superblocks_load(rs);

	/* All raid disks failed */
	if (rs->failed_disks == rs->raid_disks)
		return -EIO;

	/* In case of no metadata devices present (i.e. raid0) */
	if (!freshest) {
		struct raid_dev *rd;

		/* Pick an available one */
		for_each_rd(rd, rs)
			if (rd->rdev.bdev) {
				freshest = &rd->rdev;
				break;
			}

		if (!freshest)
			return -EINVAL;

		set_bit(MD_ARRAY_FIRST_USE, &mddev->flags);
	}

	/* New array */
	if (test_bit(FirstUse, &freshest->flags))
		set_bit(MD_ARRAY_FIRST_USE, &mddev->flags);

	mddev->dev_sectors = freshest->sectors;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u mddev->dev_sectors=%llu flags=%lX", __func__, __LINE__, (unsigned long long) mddev->dev_sectors, freshest->flags);
#endif
	/* Validate all superblocks thus initiating &rs->md (i.e. the mddev) from the freshest */
	r = superblocks_validate(rs, freshest);
	if (r)
		return r;
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif

	/*
	 * When reshaping the "sync/nosync" directives are disallowed
	 *
	 * No need to set MD_RECOVERY_NEEDED flag, because mddev_resume() will
	 */
	if (rs->ctr_flags & CTR_FLAGS_ANY_SYNC) {
		if (rs_conversion_requested(rs) && !rs_resize_requested(rs))
			return ti_error_einval(rs->ti, "Invalid sync request whilst raid set conversion requested");

		mddev->recovery_cp = (rs->ctr_flags & CTR_FLAG_SYNC) ? 0 : MaxSector;

	} else if (rs->ctr_flags & CTR_FLAG_REBUILD)
		mddev->recovery_cp = 0;

	else if (rt_is_raid0(rs->raid_type))
		mddev->recovery_cp = MaxSector;

	return 0;
}

/*
 * Enable/disable discard support on raid set depending
 * on raid level and discard properties of underlying devices
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
	discard_supported = !(rs->ctr_flags & CTR_FLAG_IGNORE_DISCARD);
	if (!discard_supported)
		return;

	/* raid level 4,5,6 request discard_zeroes_data for data integrity! */
	raid0_or_10 = rs_is_raid0_or_10(rs);
	raid456 = rs_is_raid456(rs);
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

	/* All raid members properly support discards */
	ti->discards_supported = true;

	/*
	 * raid1 and raid10 personalities require bio splitting,
	 * raid0/4/5/6 don't and process large discard bios properly.
	 */
	ti->split_discard_bios = rs_is_raid1(rs) || rs_is_raid10(rs);
	ti->num_discard_bios = 1;
}

/*
 * raid set level, layout and chuk sectors backup/restore
 */
struct rs_layout {
	int new_level;
	int new_layout;
	int new_chunk_sectors;
};

static void rs_config_backup(struct raid_set *rs, struct rs_layout *l)
{
	struct mddev *mddev = &rs->md;

	l->new_level = mddev->new_level;
	l->new_layout = mddev->new_layout;
	l->new_chunk_sectors = mddev->new_chunk_sectors;
}

static void rs_config_restore(struct raid_set *rs, struct rs_layout *l)
{
	struct mddev *mddev = &rs->md;

	mddev->new_level = l->new_level;
	mddev->new_layout = l->new_layout;
	mddev->new_chunk_sectors = l->new_chunk_sectors;
}

/*
 * Run a raid set (i.e. make accessible to submit io)
 *
 * Check superblocks for raid set @rs
 *
 * If no valid ones present (i.e. all FirstUse devices),
 * allow a new raid set to be created on start
 *
 * If  valid ones present, use them:
 *
 * - check if a processing reshape got interrupted (e.g. by a
 *   system crash) and allow it to restart from where it stopped
 *
 * - if not an interrupted reshape, check for any new
 *   takeover/reshape/resize request and prepare it to start
 *
 * - else just start the raid set
 *
 */
static int rs_run(struct raid_set *rs)
{
	int r;
	sector_t recovery_cp;
	struct rs_layout rs_layout;
	struct mddev *mddev = &rs->md;

	/*
	 * Backup raid set level, layout, ... from
	 * constructor to be able to compare to
	 * superblock members for conversion decision
	 */
	rs_config_backup(rs, &rs_layout);
	r = load_and_analyse_superblocks(rs);
	if (r < 0)
		return ti_error_ret(rs->ti, "Superblock validation failed!", r);

	rs_config_restore(rs, &rs_layout);

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, "After load_and_analyse_superblocks()");
#endif

	if (test_bit(MD_ARRAY_FIRST_USE, &mddev->flags)) {
		/*
		 * We don't have any (valid) superblocks, so we
		 * presume a new raid set is being requested to
		 * build, thus we set the mddev properties here
		 */
		rs_set_new(rs);

		/* raid0 does not have any superblocks and does not want a bitmap */
		if (rs_is_raid0(rs))
			clear_bit(MD_ARRAY_FIRST_USE, &mddev->flags);

		/*
		 * Check that device size is divisable by number of data
		 * devices on new raid set and set mddev->(array|dev)_sectors
		 */
		r = rs_set_dev_and_array_sectors(rs);
		if (r)
			return r;
	}

	/* If userspace does not want to resync */
	if (rs->ctr_flags & CTR_FLAG_NOSYNC)
		mddev->recovery_cp = MaxSector;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, "Before rs_is_reshaping()");
#endif

	/* Check for interrupted reshape first in order to restart it */
	if (rs_is_reshaping(rs)) {
		if (rs->ctr_flags & CTR_FLAGS_ANY_SYNC)
			return ti_error_einval(rs->ti, "Invalid sync request during reshaping");

		DMINFO("Continuing with interrupted reshape");
		if (mddev->delta_disks)
			rs_set_cur(rs);

	/* Check for takeover,reshape or resize */
	} else if (rs_conversion_requested(rs)) {
		r = rs_setup_conversion(rs);
		if (r)
			return r;
	}

	/* Enable bitmap unless raid0 */
	rs_config_bitmap(rs);

	/* Prohibit any recovery/reshape activity until raid_resume(). */
	set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);

	/*
	 * md_run() will fail on takeover/reshape if recovery_cp set to 0,
	 * so reset it and restore afterwards
	 */
	recovery_cp = mddev->recovery_cp;

	if (!rs_resize_requested(rs))
		mddev->recovery_cp = MaxSector;

	/* If constructor requested it, change data and new_data offsets */
	r = rs_adjust_data_offsets(rs);
	if (r)
		return r;

	/* Start raid set read-only and assumed marked dirty to be changed in raid_resume()! */
	mddev->ro = 1;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, "before md_run");
#endif
	mddev_lock_nointr(mddev); /* Must be held on calling md_run() */
	r = md_run(mddev);
	if (r)
		return r;

	mddev->in_sync = 0;
	mddev_suspend(mddev);
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, "after md_run");
#endif
	/* Be prepared for mddev_resume() in raid_resume() */
	set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
	mddev->recovery_cp = recovery_cp;

	rs_set_capacity(rs);
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	dump_mddev(mddev, "before reshape");
#endif
	/* New reshape requested; restarted reshape is being processed in md_run() already */
	if (!mddev->degraded &&
	    _test_flag(RT_FLAG_RESHAPE, &rs->runtime_flags)) {
		/* Initiate a reshape. */
		rs_config_restore(rs, &rs_layout);
		r = rs_start_reshape(rs); /* Will unlock mddev */
		if (r) {
			DMWARN("Failed to check/start reshape -> continuing w/o change");
			r = 0;
		}
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		dump_mddev(mddev, "After rs_start_reshape");
#endif
	} else
		mddev_unlock(mddev);

	/*
	 * Disable/enable discard support on raid set after any
	 * conversion, because devices can have been added
	 */
	if (!r)
		configure_discard_support(rs);

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("--> %s %u r=%d", __func__, __LINE__, r);
#endif
	return r;
}

/*
 * Construct a raid0/1/10/4/5/6 mapping:
 * Args:
 *	<raid_type> <#raid_params> <raid_params>{0,} <#raid_devs> [<meta_dev1> <dev1>]{1,}
 *
 * <raid_params> varies by <raid_type>.  See 'parse_raid_params' for
 * details on possible <raid_params>.
 *
 * The ctr arguments are advising and will be overwritten by superblock parameters in
 * load_and_analyse_superblocks() _before_ any teakeover/reshape changes happen in rs_run().
 *
 * Userspace is free to initialize the metadata devices, hence the superblocks to
 * enforce recreation based on the passed in table parameters.
 */
static int raid_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	unsigned num_raid_params, num_raid_devs;
	const char *arg;
	struct raid_set *rs;
	struct raid_type *rt;
	struct dm_arg_set as = { argc, argv }, as_nrd;
	struct dm_arg _args[] = {
		{0, as.argc, "Cannot understand number of raid parameters or supplied arguments do not match the count given"},
		{1, 254, "Cannot understand number of raid devices or supplied raid device tupples do not match the count given"}
	};

#if DEVEL_OUTPUT
	/* HM FIXME: REMOVEME: devel */
	print_argv(__func__, as.argc, as.argv);
	DMINFO("%s %u ti->len=%llu DISKS_ARRAY_ELEMS=%lu sizeof(sb)=%lu", __func__, __LINE__, (unsigned long long) ti->len, DISKS_ARRAY_ELEMS, sizeof (struct dm_raid_superblock));
#endif
	/* raid type */
	arg = dm_shift_arg(&as);
	if (!arg)
		return ti_error_einval(ti, "No arguments");

	rt = get_raid_type(arg);
	if (!rt)
		return ti_error_einval(ti, "Unrecognised raid_type");

	/* number of raid parameters */
	if (dm_read_arg_group(_args, &as, &num_raid_params, &ti->error))
		return -EINVAL;
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u raid_type=%s num_raid_params=%u", __func__, __LINE__, rt->name, num_raid_params);
#endif

	as_nrd = as;
	dm_consume_args(&as_nrd, num_raid_params);
	if (dm_read_arg(_args + 1, &as_nrd, &num_raid_devs, &ti->error))
		return -EINVAL;

	if (as_nrd.argc != num_raid_devs * 2)
		return ti_error_einval(ti, "Supplied raid devices do not match the count given");

	if (num_raid_devs > MAX_raid_DEVICES)
		return ti_error_einval(ti, "Too many supplied raid devices");

	rs = context_alloc(ti, rt, num_raid_devs);
	if (IS_ERR(rs))
		return PTR_ERR(rs);

	r = parse_raid_params(rs, &as, num_raid_params);
	if (r)
		goto bad;

	r = rs_set_dev_and_array_sectors(rs);
	if (r)
		return r;

	r = parse_dev_params(rs, &as);
	if (r)
		goto bad;
	/*
	 * Array will be started and bitmaps read in raid_preresume
	 * (i.e. after any active mapping has been suspended) in
	 * order to access any preexisting superblocks/bitmap
	 * up to date on a table switch
	 */
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif

	return 0;

bad:
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
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
#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
}

static int raid_map(struct dm_target *ti, struct bio *bio)
{
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;

	/*
	 * If we're reshaping to add disk(s)), ti->len and
	 * mddev->array_sectors will differ during the process
	 * (i->len > mddev->array_sectors), so we have to requeue
	 * bios with addresses > mddev->array_sectors here or
	 * or there will occur accesses past EOD of the component
	 * data images thus erroring the raid set
	 */
	if (unlikely(bio_end_sector(bio) > mddev->array_sectors))
		return DM_MAPIO_REQUEUE;

	mddev->pers->make_request(mddev, bio);

	return DM_MAPIO_SUBMITTED;
}

/* Return string describing the current sync action of @mddev */
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

/*
 * Return status string @rdev
 *
 * Status characters:
 *
 *  'D' = Dead/Failed device
 *  'a' = Alive but not in-sync
 *  'A' = Alive and in-sync
 */
static const char *_raid_dev_status(struct md_rdev *rdev, bool array_in_sync)
{
	if (test_bit(Faulty, &rdev->flags))
		return "D";
	else if (!array_in_sync || !test_bit(In_sync, &rdev->flags))
		return "a";
	else
		return "A";
}

/*
 * Emit any key/value pairs for @keyname for disks if index of disk set in @bitset
 *
 * E.g. "rebuild N" if N-th bit is set in the rebuild bitset
 */
static unsigned _rs_emit_any_key_value_for_disks(const char *keyname, uint64_t *bitset,
						 char *result, unsigned maxlen, unsigned sz)
{
	unsigned d, sz_start = sz;

	for (d = 0; d < MAX_raid_DEVICES; d++)
		if (test_bit(d, (void *) bitset))
			DMEMIT(" %s %u", keyname, d);

	return sz - sz_start;
}

/* Helper to return resync/reshape progress for @rs and @array_in_sync */
static sector_t rs_get_progress(struct raid_set *rs,
				sector_t resync_max_sectors, bool *array_in_sync)
{
	struct mddev *mddev = &rs->md;
	sector_t r, recovery_cp, curr_resync_completed;

	curr_resync_completed = mddev->curr_resync_completed;
	recovery_cp = mddev->recovery_cp;
	*array_in_sync = false;

	if (rs_is_raid0(rs)) {
		r = resync_max_sectors;
		*array_in_sync = true;

	} else {
		r = mddev->reshape_position;

		/* Reshape is relative to the array size */
		if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) ||
		    r != MaxSector) {
			if (r == MaxSector) {
				*array_in_sync = true;
				r = resync_max_sectors;
			} else {
				/* Got to reverse on backward reshape */
				if (mddev->reshape_backwards)
					r = mddev->array_sectors - r;

				/* Devide by # of data stripes */
				sector_div(r, mddev->raid_disks - rs->raid_type->parity_devs);
			}

		/* Sync is relative to the component device size */
		} else if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
			r = curr_resync_completed;
		else
			r = recovery_cp;

		if (r == MaxSector) {
			/*
			 * Sync complete.
			 */
			*array_in_sync = true;
			r = resync_max_sectors;
		} else if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
			/*
			 * If "check" or "repair" is occurring, the raid set has
			 * undergone an initial sync and the health characters
			 * should not be 'a' anymore.
			 */
			*array_in_sync = true;
		} else {
			struct raid_dev *rd;

			/*
			 * The raid set may be doing an initial sync, or it may
			 * be rebuilding individual components.  If all the
			 * devices are In_sync, then it is the raid set that is
			 * being initialized.
			 */
			for_each_rd(rd, rs)
				if (!test_bit(In_sync, &rd->rdev.flags))
					*array_in_sync = true;
			// r = 0; /* HM FIXME: TESTME: https://bugzilla.redhat.com/show_bug.cgi?id=1210637 ? */
		}
	}

	return r;
}

/* Helper to return @dev name or "-" if !@dev */
static const char *_get_dev_name(struct dm_dev *dev)
{
	return dev ? dev->name : "-";
}

/* EMIT helper macros to shorten raid_status() */
/* Emit the argument if its flag is set */
#define	__EMIT_IF_SET(flag) \
	do {							 \
		if (rs->ctr_flags & (flag))			 \
			DMEMIT(" %s", _argname_by_flag((flag))); \
	} while (0)

/* Emit the argument together with a value if its flag is set */
#define	__EMIT_VAL_IF_SET(flag, format, arg) \
	do {									\
		if (rs->ctr_flags & (flag))					\
			DMEMIT(" %s " format, _argname_by_flag((flag)), (arg));	\
	} while (0)

static void raid_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;
	struct r5conf *conf = mddev->private;
	int max_nr_stripes = conf ? conf->max_nr_stripes : 0;
	bool array_in_sync;
	unsigned raid_param_cnt = 1; /* at least 1 for chunksize */
	unsigned sz = 0;
	sector_t progress, resync_max_sectors, resync_mismatches;
	const char *sync_action;
	struct raid_type *rt;
	struct md_rdev *rdev;
	struct raid_dev *rd;

	switch (type) {
	case STATUSTYPE_INFO:
		/* *Should* always succeed */
		rt = get_raid_type_by_ll(mddev->new_level, mddev->new_layout);
		DMEMIT("%s %d ", rt ? rt->name : "unknown", mddev->raid_disks);

		/* Access most recent mddev properties for status output */
		smp_rmb();
		/* Get sensible max sectors even if raid set not yet started */
		resync_max_sectors = _test_flag(RT_FLAG_SET_STARTED, &rs->runtime_flags) ?
				      mddev->resync_max_sectors : mddev->dev_sectors;
		progress = rs_get_progress(rs, resync_max_sectors, &array_in_sync);
		resync_mismatches = (mddev->last_sync_action && !strcasecmp(mddev->last_sync_action, "check")) ?
				    (unsigned long long) atomic64_read(&mddev->resync_mismatches) : 0;
		sync_action = decipher_sync_action(&rs->md);

		/* HM FIXME: do we want another state char for raid0? It shows 'D' or 'A' now */
		rdev_for_each(rdev, mddev)
			DMEMIT(_raid_dev_status(rdev, array_in_sync));

		/*
		 * In-sync/Reshape ratio:
		 *  The in-sync ratio shows the progress of:
		 *   - Initializing the raid set
		 *   - Rebuilding a subset of devices of the raid set
		 *  The user can distinguish between the two by referring
		 *  to the status characters.
		 *
		 *  The reshape ratio shows the progress of
		 *  changing the raid layout or the number of
		 *  disks of a raid set
		 */
		DMEMIT(" %llu/%llu", (unsigned long long) progress,
				     (unsigned long long) resync_max_sectors);

		/*
		 * v1.5.0+:
		 *
		 * Sync action:
		 *   See Documentation/device-mapper/dm-raid.txt for
		 *   information on each of these states.
		 */
		DMEMIT(" %s", sync_action);

		/*
		 * v1.5.0+:
		 *
		 * resync_mismatches/mismatch_cnt
		 *   This field shows the number of discrepancies found when
		 *   performing a "check" of the raid set.
		 */
		DMEMIT(" %llu", (unsigned long long) resync_mismatches);

		/*
		 * v1.8.0+:
		 *
		 * data_offset (needed for reshaping)
		 *   This field shows the data offset into the data
		 *   image LV where the stripe data starts.
		 *
		 * We keep data_offset, new_data_offset and dev_sector
		 * equal on all raid disks of the set, so retrieving
		 * it from the first raid disk is sufficient.
		 */
		DMEMIT(" %llu", (unsigned long long) rs->dev[0].rdev.data_offset);
		break;

	case STATUSTYPE_TABLE:
		/* Report the table line string you would use to construct this raid set */

		/* Calculate raid parameter count */
		raid_param_cnt += _count_bits(rs->rebuild_disks) +
				  _count_bits(rs->writemostly_disks) +
				  hweight32(rs->ctr_flags & CTR_FLAG_OPTIONS_NO_ARGS) +
				  hweight32(rs->ctr_flags & CTR_FLAG_OPTIONS_ONE_ARG) * 2;
		DMEMIT("%s %u %u", rs->raid_type->name, raid_param_cnt, mddev->new_chunk_sectors);
		__EMIT_IF_SET(CTR_FLAG_SYNC);
		__EMIT_IF_SET(CTR_FLAG_NOSYNC);
		__EMIT_IF_SET(CTR_FLAG_IGNORE_DISCARD);
		sz += _rs_emit_any_key_value_for_disks(_argname_by_flag(CTR_FLAG_REBUILD), rs->rebuild_disks,
						       result, maxlen, sz);
		__EMIT_VAL_IF_SET(CTR_FLAG_DAEMON_SLEEP, "%lu", mddev->bitmap_info.daemon_sleep);
		__EMIT_VAL_IF_SET(CTR_FLAG_MIN_RECOVERY_RATE, "%d", mddev->sync_speed_min);
		__EMIT_VAL_IF_SET(CTR_FLAG_MAX_RECOVERY_RATE, "%d", mddev->sync_speed_max);
		__EMIT_VAL_IF_SET(CTR_FLAG_DELTA_DISKS, "%d", rs->delta_disks);
		__EMIT_VAL_IF_SET(CTR_FLAG_DATA_OFFSET, "%d", rs->data_offset);
		__EMIT_VAL_IF_SET(CTR_FLAG_MAX_WRITE_BEHIND, "%lu", mddev->bitmap_info.max_write_behind);
		sz += _rs_emit_any_key_value_for_disks(_argname_by_flag(CTR_FLAG_WRITE_MOSTLY),
									rs->writemostly_disks, result, maxlen, sz);
		__EMIT_VAL_IF_SET(CTR_FLAG_STRIPE_CACHE, "%d", max_nr_stripes);
		__EMIT_VAL_IF_SET(CTR_FLAG_REGION_SIZE, "%lu", to_sector(mddev->bitmap_info.chunksize));
		__EMIT_VAL_IF_SET(CTR_FLAG_RAID10_FORMAT, "%s", raid10_md_layout_to_format(mddev->layout));
		__EMIT_VAL_IF_SET(CTR_FLAG_RAID10_COPIES, "%u", raid10_md_layout_to_copies(mddev->layout));

		DMEMIT(" %d", rs->raid_disks - rs->delta_disks);
		for_each_rd(rd, rs)
			DMEMIT(" %s %s", _get_dev_name(rd->meta_dev), _get_dev_name(rd->data_dev));
	}
}

static int raid_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = 0;
	uint32_t action = 0;
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;
	struct dm_arg_set as = { argc, argv };
	const char *cmd = dm_shift_arg(&as);

#if DEVEL_OUTPUT
	/* HM FIXME: REMOVEME: devel output */
	print_argv(__func__, argc, argv);

	if (!strcasecmp(cmd, "dump")) {
		dump_mddev(mddev, "dump message");
		return 0;
	}
#endif

	/*
	 * Handle {min/max}_recovery_rate, max_write_behind,
	 * daemon_sleep and cache size messages
	 */
	if (!strcasecmp(cmd, _argname_by_flag(CTR_FLAG_MIN_RECOVERY_RATE)))
		action = CTR_FLAG_MIN_RECOVERY_RATE;
	else if (!strcasecmp(cmd, _argname_by_flag(CTR_FLAG_MAX_RECOVERY_RATE)))
		action = CTR_FLAG_MAX_RECOVERY_RATE;
	else if (!strcasecmp(cmd, _argname_by_flag(CTR_FLAG_MAX_WRITE_BEHIND)))
		action = CTR_FLAG_MAX_WRITE_BEHIND;
	else if (!strcasecmp(cmd, _argname_by_flag(CTR_FLAG_DAEMON_SLEEP)))
		action = CTR_FLAG_DAEMON_SLEEP;
	else if (!strcasecmp(cmd, _argname_by_flag(CTR_FLAG_STRIPE_CACHE)))
		action = CTR_FLAG_STRIPE_CACHE;

	if (action) {
		int value;

		if (kstrtoint(dm_shift_arg(&as), 10, &value) < 0)
			return ti_error_einval(rs->ti, "Bad numerical argument given");

		switch (action) {
		case CTR_FLAG_MIN_RECOVERY_RATE:
			return rs_set_recovery_rate(rs, value, min_rate);
		case CTR_FLAG_MAX_RECOVERY_RATE:
			return rs_set_recovery_rate(rs, value, max_rate);
		case CTR_FLAG_MAX_WRITE_BEHIND:
			return rs_set_max_write_behind(rs, value);
		case CTR_FLAG_DAEMON_SLEEP:
			return rs_set_daemon_sleep(rs, value);
		case CTR_FLAG_STRIPE_CACHE:
			return rs_set_raid456_stripe_cache(rs, value);
		default:
			BUG();
		}
	}

	if (!mddev->pers || !mddev->pers->sync_request)
		return -EINVAL;

	/* Toggle "frozen" array state */
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

	mddev_lock_nointr(mddev);
	if (mddev->ro == 2) {
		/* A write to sync_action is enough to justify
		 * canceling read-auto mode
		 */
		mddev->ro = 0;
		if (!mddev->suspended)
			md_wakeup_thread(mddev->sync_thread);
	}

	if (!r) {
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		if (!mddev->suspended)
			md_wakeup_thread(mddev->thread);
	}

	mddev_unlock(mddev);

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
				rd->rdev.data_offset,
				rd->rdev.sectors, data);
		if (r)
			break;
	}

	return r;
}

static void raid_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct raid_set *rs = ti->private;
	unsigned chunk_size = to_bytes(rs->md.new_chunk_sectors);

	if (!chunk_size)
		chunk_size = rs->md.bitmap_info.chunksize;

DMINFO("chunk_size=%u", chunk_size);
	blk_limits_io_min(limits, chunk_size);
	blk_limits_io_opt(limits, chunk_size * (mddev_data_stripes(rs) + rs->md.delta_disks));
}

static void raid_presuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;
	struct raid_dev *rd;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	if (mddev->suspended)
		mddev_resume(mddev);

	/*
	 * Address a teardown race when calling
	 * raid_(pre|post)suspend followed by raid_dtr:
	 *
	 * MD's call chain md_stop_writes()->md_reap_sync_thread()
	 * causes work to be queued on the md_misc_wq queue
	 * intentionally not flushing it, hence the callback
	 * can occur after a potential destruction of the raid set
	 *
	 * HM FIXME: this ain't safe, because there may be work queued by the time
	 *	     neew e.g. use a flag to pass on to md_stop_writes->md_reap_sync_thread
	 *	     to pay attention to as pictured bellow
	 */
#if 1
	mddev->event_work.func = NULL;
#else
	set_bit(MD_RECOVERY_DONT_CALLBACK, $mddev->recovery);
#endif

	/*
	 * Mandatory to enforce superblock updates in case of any
	 * non-insync devices, e.g. reflecting correct recovery_cp
	 */
	for_each_rd(rd, rs)
		if (!test_bit(In_sync, &rd->rdev.flags)) {
			mddev->in_sync = 0;
			break;
		}

	/* Stop any resynchronization/reshaping io */
	mddev->ro = 0;
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	md_stop_writes(mddev);
}

static void raid_postsuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	mddev_suspend(&rs->md);
}

static void attempt_restore_of_faulty_devices(struct raid_set *rs)
{
	unsigned i = 0;
	uint64_t cleared_failed_devices[DISKS_ARRAY_ELEMS];
	unsigned long flags;
	bool found_cleared_failed_device = false;
	struct raid_dev *rd;
	struct dm_raid_superblock *sb;
	struct md_rdev *rdev;

	memset(cleared_failed_devices, 0, sizeof(cleared_failed_devices));

	for_each_rd(rd, rs) {
		rdev = &rd->rdev;

		if (test_bit(Faulty, &rdev->flags) && rdev->sb_page &&
		    sync_page_io(rdev, 0, rdev->sb_size, rdev->sb_page, READ, 1)) {
			DMINFO("Faulty %s device #%d has readable super block. Attempting to revive it.",
			       rs->raid_type->name, i);

			/*
			 * Faulty bit may be set, but sometimes the raid set can
			 * be suspended before the personalities can respond
			 * by removing the device from the raid set (i.e. calling
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
				set_bit(i, (void *) cleared_failed_devices);
				found_cleared_failed_device = true;
			}
		}

		i++;
	}

	/* If any cleared devices, clear them in the superblock as well */
	if (found_cleared_failed_device) {
		uint64_t failed_devices[DISKS_ARRAY_ELEMS];

		for_each_rd(rd, rs) {
			rdev = &rd->rdev;
			if (!rdev->sb_page)
				continue;

			sb = page_address(rdev->sb_page);
			sb_retrieve_failed_devices(sb, failed_devices);

			failed_devices[0] &= ~cleared_failed_devices[0];

			for (i = 0; i < ARRAY_SIZE(sb->extended_failed_devices); i++)
				failed_devices[i+1] &= ~cleared_failed_devices[i+1];

			sb_update_failed_devices(sb, failed_devices);
		}
	}
}

static int _bitmap_load(struct raid_set *rs)
{
	int r = 0;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	/* Try loading the bitmap unless "raid0", which does not have one */
	if (!rt_is_raid0(rs->raid_type)) {
		struct mddev *mddev = &rs->md;

#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("%s %u bitmap->count.chunk=%lu", __func__, __LINE__, mddev->bitmap->counts.chunks);
#endif

		if (!_test_and_set_flag(RT_FLAG_BITMAP_LOADED, &rs->runtime_flags)) {
			r = bitmap_load(mddev);
			if (r)
				DMERR("Failed to load bitmap");
		}
	}

	return r;
}

/*
 * Start raid set here in order to have any
 * previous active mapping suspended and thus
 * all superblock/bitmap metadata flushed
 * and inactive.
 *
 * Bind resurces all resources to be able
 * to perfrom raid_resume() successfully
 * or to be able to report back any failure
 * to userspace.
 */
static int raid_preresume(struct dm_target *ti)
{
	int r;
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;

	/*
	 * See "Address a teardown race" in raid_presuspend()
	 *
	 * HM FIXME: unsafe, use e.g. flag as pictured bellow.
	 */
#if 1
	mddev->event_work.func = do_table_event;
#else
	clear_bit(MD_RECOVERY_DONT_CALLBACK, $mddev->recovery);
#endif

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	/* This is a resume after a suspend of the set -> it's already started */
	if (_test_and_set_flag(RT_FLAG_SET_STARTED, &rs->runtime_flags))
		return 0;

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("%s %u", __func__, __LINE__);
#endif
	/* Start the raid set making sure we get bounded resources */
	r = rs_run(rs);
	if (r) {
		DMERR("failed to start %s set", rs->raid_type->descr);
		return r;
	}

	DMINFO("started %s set", rs->raid_type->descr);

	/*
	 * The superblocks need to be updated on disk if the
	 * array is new or _bitmap_load will overwrite them
	 * in core with old data.
	 */
	mddev->ro = 0;
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	md_update_sb(mddev, 1);
	mddev->ro = 1;

	/* Load the bitmap from disk unless raid0 */
	return _bitmap_load(rs);
}

static void raid_resume(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct mddev *mddev = &rs->md;

	if (_test_and_set_flag(RT_FLAG_SET_RESUMED, &rs->runtime_flags)) {
		/*
		 * A secondary resume while the device is active.
		 * Take this opportunity to check whether any failed
		 * devices are reachable again.
		 */
		attempt_restore_of_faulty_devices(rs);
		clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);

	} else {
		mddev->ro = 0;
		/*
		 * If any of the constructor flags got paased in
		 * but "region_size" (gets always passed in for
		 * mappings with bitmap), we expect userspace to
		 * reset them and reload the mapping anyway.
		 *
		 * -> don't unfreeze resynchronization
		 *    until imminant reload
		 */
#if DEVEL_OUTPUT
		/* HM FIXME REMOVEME: devel */
		DMINFO("--> %s %u ctr_flags=%x ctr_flags &=%x", __func__, __LINE__, rs->ctr_flags, ALL_FREEZE_FLAGS & rs->ctr_flags);
#endif
		if (!(ALL_FREEZE_FLAGS & rs->ctr_flags))
			clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
	}

	mddev_resume(mddev);

#if DEVEL_OUTPUT
	/* HM FIXME REMOVEME: devel */
	DMINFO("--> %s %u", __func__, __LINE__);
#endif
}

#if 0
static int raid_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
		      struct bio_vec *biovec, int max_size)
{
	struct raid_set *rs = ti->private;
	struct md_personality *pers = rs->md.pers;

	if (pers && pers->mergeable_bvec)
		return min(max_size, pers->mergeable_bvec(&rs->md, bvm, biovec));

	/*
	 * In case we can't request the personality because
	 * the raid set is not running yet
	 *
	 * -> return safe minimum
	 */
	return rs->md.chunk_sectors;
}
#endif

static struct target_type raid_target = {
	.name = "raid",
	.version = {1, 8, 0},
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
#if 0
	.merge = raid_merge
#endif
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
MODULE_AUTHOR("Heinz Mauelshagen <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
