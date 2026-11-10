#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif

#include "ksu.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#include "kernel_compat.h"
#include "allowlist.h"
#include "manager.h"

#define FILE_MAGIC 0x7f4b5355 // ' KSU', u32
#define FILE_FORMAT_VERSION 3 // u32

#define KSU_APP_PROFILE_PRESERVE_UID 9999 // NOBODY_UID
#define KSU_DEFAULT_SELINUX_DOMAIN "u:r:su:s0"

static DEFINE_MUTEX(allowlist_mutex);

// default profiles, these may be used frequently, so we cache it
static struct root_profile default_root_profile;
static struct non_root_profile default_non_root_profile;

static int allow_list_arr[PAGE_SIZE / sizeof(int)] __read_mostly __aligned(PAGE_SIZE);
static int allow_list_pointer __read_mostly = 0;

static void remove_uid_from_arr(uid_t uid)
{
    int i;
    int j = 0;

    /*
     * AETHON: callers must hold allowlist_mutex.
     * Remove UIDs in place without allocating memory.
     */
    for (i = 0; i < allow_list_pointer; i++) {
        if (allow_list_arr[i] != uid)
            allow_list_arr[j++] = allow_list_arr[i];
    }

    allow_list_pointer = j;

    for (; j < ARRAY_SIZE(allow_list_arr); j++)
        allow_list_arr[j] = -1;
}

static void init_default_profiles()
{
	kernel_cap_t full_cap = CAP_FULL_SET;

	default_root_profile.uid = 0;
	default_root_profile.gid = 0;
	default_root_profile.groups_count = 1;
	default_root_profile.groups[0] = 0;
	memcpy(&default_root_profile.capabilities.effective, &full_cap,
		sizeof(default_root_profile.capabilities.effective));
	default_root_profile.namespaces = 0;
	strcpy(default_root_profile.selinux_domain, KSU_DEFAULT_SELINUX_DOMAIN);

	// This means that we will umount modules by default!
	default_non_root_profile.umount_modules = true;
}

struct perm_data {
	struct list_head list;
	struct app_profile profile;
};

static struct list_head allow_list;

static uint8_t allow_list_bitmap[PAGE_SIZE] __read_mostly __aligned(PAGE_SIZE);
#define BITMAP_UID_MAX ((sizeof(allow_list_bitmap) * BITS_PER_BYTE) - 1)

#define KERNEL_SU_ALLOWLIST "/data/adb/ksu/.allowlist"

static struct work_struct ksu_save_work;
static struct work_struct ksu_load_work;

bool persistent_allow_list(void);

void ksu_show_allow_list(void)
{
    struct perm_data *p;

    mutex_lock(&allowlist_mutex);

    pr_info("ksu_show_allow_list\n");

    list_for_each_entry(p, &allow_list, list) {
        pr_info("uid: %d, allow: %d\n",
                p->profile.current_uid,
                p->profile.allow_su);
    }

    mutex_unlock(&allowlist_mutex);
}

#ifdef CONFIG_KSU_DEBUG
static void ksu_grant_root_to_shell()
{
	struct app_profile profile = {
		.version = KSU_APP_PROFILE_VER,
		.allow_su = true,
		.current_uid = 2000,
	};
	strcpy(profile.key, "com.android.shell");
	strcpy(profile.rp_config.profile.selinux_domain, KSU_DEFAULT_SELINUX_DOMAIN);
	ksu_set_app_profile(&profile, false);
}
#endif

bool ksu_get_app_profile(struct app_profile *profile)
{
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	bool found = false;

	mutex_lock(&allowlist_mutex);
	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		bool uid_match = profile->current_uid == p->profile.current_uid;
		if (uid_match) {
			// found it, override it with ours
			memcpy(profile, &p->profile, sizeof(*profile));
			found = true;
			goto exit;
		}
	}

exit:
	mutex_unlock(&allowlist_mutex);
	return found;
}

static inline bool forbid_system_uid(uid_t uid) {
	#define SHELL_UID 2000
	#define SYSTEM_UID 1000
	return uid < SHELL_UID && uid != SYSTEM_UID;
}

static bool profile_valid(struct app_profile *profile)
{
	if (!profile) {
		return false;
	}

	/* AETHON: reject unterminated profile keys. */
	if (strnlen(profile->key, sizeof(profile->key)) ==
	    sizeof(profile->key)) {
	    pr_err("AETHON: invalid profile key\n");
	    return false;
	}

	if (profile->version < KSU_APP_PROFILE_VER) {
		pr_info("Unsupported profile version: %d\n", profile->version);
		return false;
	}

	if (profile->allow_su) {
		size_t domain_len = strnlen(
			profile->rp_config.profile.selinux_domain,
			sizeof(profile->rp_config.profile.selinux_domain));
		if (profile->rp_config.profile.groups_count < 0 ||
		    profile->rp_config.profile.groups_count > KSU_MAX_GROUPS) {
			return false;
		}

		if (domain_len == 0 ||
		    domain_len == sizeof(profile->rp_config.profile.selinux_domain)) {
			return false;
		}
	}

	return true;
}

bool ksu_set_app_profile(struct app_profile *profile, bool persist)
{
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	bool result = false;
	bool uid_registered = false;
	int i;

	if (!profile_valid(profile)) {
		pr_err("Failed to set app profile: invalid profile!\n");
		return false;
	}

	mutex_lock(&allowlist_mutex);

	/* AETHON: validate high UID capacity before modifying profiles. */
	if (profile->allow_su && profile->current_uid > BITMAP_UID_MAX) {
		for (i = 0; i < allow_list_pointer; i++) {
			if (allow_list_arr[i] == profile->current_uid) {
				uid_registered = true;
				break;
			}
		}
		if (!uid_registered &&
		    allow_list_pointer >= ARRAY_SIZE(allow_list_arr)) {
			pr_err("AETHON: allowlist UID array full\n");
			goto unlock;
		}
	}

	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		// both uid and package must match, otherwise it will break multiple package with different user id
		if (profile->current_uid == p->profile.current_uid &&
		    !strcmp(profile->key, p->profile.key)) {
			// found it, just override it all!
			memcpy(&p->profile, profile, sizeof(*profile));
			result = true;
			goto out;
		}
	}

	// not found, alloc a new node!
	p = (struct perm_data *)kmalloc(sizeof(struct perm_data), GFP_KERNEL);
	if (!p) {
		pr_err("ksu_set_app_profile alloc failed\n");
		goto unlock;
	}

	memcpy(&p->profile, profile, sizeof(*profile));
	if (profile->allow_su) {
		pr_info("set root profile, key: %s, uid: %d, gid: %d, context: %s\n",
			profile->key, profile->current_uid,
			profile->rp_config.profile.gid,
			profile->rp_config.profile.selinux_domain);
	} else {
		pr_info("set app profile, key: %s, uid: %d, umount modules: %d\n",
			profile->key, profile->current_uid,
			profile->nrp_config.profile.umount_modules);
	}
	list_add_tail(&p->list, &allow_list);

out:
	if (profile->current_uid <= BITMAP_UID_MAX) {
		if (profile->allow_su)
			allow_list_bitmap[profile->current_uid / BITS_PER_BYTE] |= 1 << (profile->current_uid % BITS_PER_BYTE);
		else
			allow_list_bitmap[profile->current_uid / BITS_PER_BYTE] &= ~(1 << (profile->current_uid % BITS_PER_BYTE));
	} else {
		if (profile->allow_su) {
			/*
			 * 1024 apps with uid higher than BITMAP_UID_MAX
			 * registered to request superuser?
			 */
			if (!uid_registered)
				allow_list_arr[allow_list_pointer++] = profile->current_uid;
		} else {
			remove_uid_from_arr(profile->current_uid);
		}
	}
	result = true;

	// check if the default profiles is changed, cache it to a single struct to accelerate access.
	if (unlikely(!strcmp(profile->key, "$"))) {
		// set default non root profile
		memcpy(&default_non_root_profile, &profile->nrp_config.profile,
		       sizeof(default_non_root_profile));
	}

	if (unlikely(!strcmp(profile->key, "#"))) {
		// set default root profile
		memcpy(&default_root_profile, &profile->rp_config.profile,
		       sizeof(default_root_profile));
	}

unlock:
	mutex_unlock(&allowlist_mutex);

	if (persist && result)
		persistent_allow_list();

	return result;
}

bool __ksu_is_allow_uid(uid_t uid)
{
    bool allowed = false;
    int i;

    if (unlikely(uid == 0))
        return is_ksu_domain();

    if (forbid_system_uid(uid))
        return false;

    if (likely(ksu_is_manager_uid_valid()) &&
        unlikely(ksu_get_manager_uid() == uid))
        return true;

    /* AETHON: synchronize UID cache reads with profile updates. */
    mutex_lock(&allowlist_mutex);

    if (likely(uid <= BITMAP_UID_MAX)) {
        allowed = !!(allow_list_bitmap[uid / BITS_PER_BYTE] &
                     (1 << (uid % BITS_PER_BYTE)));
    } else {
        for (i = 0; i < allow_list_pointer; i++) {
            if (allow_list_arr[i] == uid) {
                allowed = true;
                break;
            }
        }
    }

    mutex_unlock(&allowlist_mutex);
    return allowed;
}

bool ksu_uid_should_umount(uid_t uid)
{
	struct app_profile profile = { .current_uid = uid };
	if (likely(ksu_is_manager_uid_valid()) && unlikely(ksu_get_manager_uid() == uid)) {
		// we should not umount on manager!
		return false;
	}
	bool found = ksu_get_app_profile(&profile);
	if (!found) {
		// no app profile found, it must be non root app
		return default_non_root_profile.umount_modules;
	}
	if (profile.allow_su) {
		// if found and it is granted to su, we shouldn't umount for it
		return false;
	} else {
		// found an app profile
		if (profile.nrp_config.use_default) {
			return default_non_root_profile.umount_modules;
		} else {
			return profile.nrp_config.profile.umount_modules;
		}
	}
}

bool ksu_get_root_profile(uid_t uid, struct root_profile *out)
{
    struct perm_data *p;

    if (!out)
        return false;

    mutex_lock(&allowlist_mutex);

    list_for_each_entry(p, &allow_list, list) {
        if (uid == p->profile.current_uid &&
            p->profile.allow_su &&
            !p->profile.rp_config.use_default) {
            memcpy(out, &p->profile.rp_config.profile, sizeof(*out));
            goto unlock;
        }
    }

    memcpy(out, &default_root_profile, sizeof(*out));

unlock:
    mutex_unlock(&allowlist_mutex);
    return true;
}

bool ksu_get_allow_list(int *array, int *length, bool allow, int capacity)
{
    struct perm_data *p;
    int i = 0;
    bool success = true;

    if (!array || !length || capacity < 0)
        return false;

    mutex_lock(&allowlist_mutex);

    list_for_each_entry(p, &allow_list, list) {
        if (p->profile.allow_su != allow)
            continue;

        if (i >= capacity) {
            success = false;
            break;
        }

        array[i++] = p->profile.current_uid;
    }

    *length = i;
    mutex_unlock(&allowlist_mutex);

    return success;
}

void do_save_allow_list(struct work_struct *work)
{
    u32 magic = FILE_MAGIC;
    u32 version = FILE_FORMAT_VERSION;
    struct perm_data *p;
    struct app_profile *snapshot = NULL;
    struct file *fp;
    size_t count = 0;
    size_t i = 0;
    loff_t off = 0;

    /*
     * AETHON: copy profiles under the allowlist mutex.
     * Never perform file I/O while holding this mutex.
     */
    mutex_lock(&allowlist_mutex);

    list_for_each_entry(p, &allow_list, list)
        count++;

    if (count > ((size_t)-1) / sizeof(*snapshot)) {
        pr_err("AETHON: allowlist snapshot size overflow\n");
        mutex_unlock(&allowlist_mutex);
        return;
    }

    if (count) {
        snapshot = vmalloc(count * sizeof(*snapshot));
        if (!snapshot) {
            pr_err("AETHON: allowlist snapshot allocation failed\n");
            mutex_unlock(&allowlist_mutex);
            return;
        }
    }

    list_for_each_entry(p, &allow_list, list)
        memcpy(&snapshot[i++], &p->profile, sizeof(*snapshot));

    mutex_unlock(&allowlist_mutex);

    fp = ksu_filp_open_compat(KERNEL_SU_ALLOWLIST,
                              O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        pr_err("AETHON: allowlist save open failed\n");
        goto out_free;
    }

    if (ksu_kernel_write_compat(fp, &magic, sizeof(magic), &off) !=
        sizeof(magic)) {
        pr_err("AETHON: allowlist magic write failed\n");
        goto out_close;
    }

    if (ksu_kernel_write_compat(fp, &version, sizeof(version), &off) !=
        sizeof(version)) {
        pr_err("AETHON: allowlist version write failed\n");
        goto out_close;
    }

    for (i = 0; i < count; i++) {
        if (ksu_kernel_write_compat(fp, &snapshot[i],
                                    sizeof(snapshot[i]), &off) !=
            sizeof(snapshot[i])) {
            pr_err("AETHON: allowlist profile write failed\n");
            goto out_close;
        }
    }

out_close:
    filp_close(fp, 0);
out_free:
    vfree(snapshot);
}

void do_load_allow_list(struct work_struct *work)
{
	loff_t off = 0;
	ssize_t ret = 0;
	struct file *fp = NULL;
	u32 magic;
	u32 version;

#ifdef CONFIG_KSU_DEBUG
	// always allow adb shell by default
	ksu_grant_root_to_shell();
#endif

	// load allowlist now!
	fp = ksu_filp_open_compat(KERNEL_SU_ALLOWLIST, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("load_allow_list open file failed: %ld\n", PTR_ERR(fp));
		return;
	}

	// verify magic
	if (ksu_kernel_read_compat(fp, &magic, sizeof(magic), &off) !=
		    sizeof(magic) ||
	    magic != FILE_MAGIC) {
		pr_err("allowlist file invalid: %d!\n", magic);
		goto exit;
	}

	if (ksu_kernel_read_compat(fp, &version, sizeof(version), &off) !=
	    sizeof(version)) {
		pr_err("allowlist read version: %d failed\n", version);
		goto exit;
	}

	/* AETHON: reject unsupported allowlist file formats. */
	if (version != FILE_FORMAT_VERSION) {
	    pr_err("AETHON: unsupported allowlist format: %u\n", version);
	    goto exit;
	}

	pr_info("allowlist version: %d\n", version);

	while (true) {
		struct app_profile profile;

		ret = ksu_kernel_read_compat(fp, &profile, sizeof(profile),
					     &off);

		if (ret == 0)
		    break;

		if (ret != sizeof(profile)) {
		    pr_err("AETHON: incomplete allowlist profile: %zd/%zu\n",
		           ret, sizeof(profile));
		    break;
		}

		/* Validate the key before printing it. */
		if (strnlen(profile.key, sizeof(profile.key)) ==
		    sizeof(profile.key)) {
		    pr_err("AETHON: invalid stored profile key\n");
		    break;
		}

		pr_info("load_allow_uid, name: %s, uid: %d, allow: %d\n",
			profile.key, profile.current_uid, profile.allow_su);
		ksu_set_app_profile(&profile, false);
	}

exit:
	ksu_show_allow_list();
	filp_close(fp, 0);
}

void ksu_prune_allowlist(bool (*is_uid_valid)(uid_t, char *, void *), void *data)
{
	struct perm_data *np = NULL;
	struct perm_data *n = NULL;

	bool modified = false;
	// TODO: use RCU!
	mutex_lock(&allowlist_mutex);
	list_for_each_entry_safe (np, n, &allow_list, list) {
		uid_t uid = np->profile.current_uid;
		char *package = np->profile.key;
		// we use this uid for special cases, don't prune it!
		bool is_preserved_uid = uid == KSU_APP_PROFILE_PRESERVE_UID;
		if (!is_preserved_uid && !is_uid_valid(uid, package, data)) {
			modified = true;
			pr_info("prune uid: %d, package: %s\n", uid, package);
			list_del(&np->list);
			if (likely(uid <= BITMAP_UID_MAX)) {
				allow_list_bitmap[uid / BITS_PER_BYTE] &= ~(1 << (uid % BITS_PER_BYTE));
			}
			remove_uid_from_arr(uid);
			smp_mb();
			kfree(np);
		}
	}
	mutex_unlock(&allowlist_mutex);

	if (modified) {
		persistent_allow_list();
	}
}

// make sure allow list works cross boot
bool persistent_allow_list(void)
{
	return ksu_queue_work(&ksu_save_work);
}

bool ksu_load_allow_list(void)
{
	return ksu_queue_work(&ksu_load_work);
}

void ksu_allowlist_init(void)
{
	int i;

	BUILD_BUG_ON(sizeof(allow_list_bitmap) != PAGE_SIZE);
	BUILD_BUG_ON(sizeof(allow_list_arr) != PAGE_SIZE);

	for (i = 0; i < ARRAY_SIZE(allow_list_arr); i++)
		allow_list_arr[i] = -1;

	INIT_LIST_HEAD(&allow_list);

	INIT_WORK(&ksu_save_work, do_save_allow_list);
	INIT_WORK(&ksu_load_work, do_load_allow_list);

	init_default_profiles();
}

void ksu_allowlist_exit(void)
{
	struct perm_data *np = NULL;
	struct perm_data *n = NULL;

	do_save_allow_list(NULL);

	// free allowlist
	mutex_lock(&allowlist_mutex);
	list_for_each_entry_safe (np, n, &allow_list, list) {
		list_del(&np->list);
		kfree(np);
	}
	mutex_unlock(&allowlist_mutex);
}
