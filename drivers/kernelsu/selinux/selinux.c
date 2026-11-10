#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/string.h>
#include "../ksu.h"
#include "selinux.h"
#include "objsec.h"
#include "linux/version.h"
#include "../klog.h" // IWYU pragma: keep
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

#define KERNEL_SU_DOMAIN "u:r:su:s0"

int setup_selinux(struct cred *cred, const char *domain)
{
        struct task_security_struct *tsec;
        size_t len;
        u32 sid = 0;
        int error;

        if (!cred || !domain)
                return -EINVAL;

        tsec = cred->security;
        if (!tsec)
                return -EINVAL;

        len = strnlen(domain, KSU_SELINUX_DOMAIN);
        if (!len || len == KSU_SELINUX_DOMAIN)
                return -EINVAL;

        error = security_secctx_to_secid(domain, len, &sid);
        if (error)
                return error;

        if (!sid)
                return -EINVAL;

        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;

        return 0;
}

void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	selinux_state.enforcing = enforce;
#else
	selinux_enforcing = enforce;
#endif
#endif
}

bool getenforce()
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	if (selinux_state.disabled) {
#else
	if (selinux_disabled) {
#endif
		return false;
	}
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	return selinux_state.enforcing;
#else
	return selinux_enforcing;
#endif
#else
	return true;
#endif
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) &&                         \
	!defined(KSU_COMPAT_HAS_CURRENT_SID)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
	const struct task_security_struct *tsec = current_security();

	return tsec->sid;
}
#endif

bool is_ksu_domain()
{
	char *domain;
	u32 seclen;
	bool result;
	int err = security_secid_to_secctx(current_sid(), &domain, &seclen);
	if (err) {
		return false;
	}
	result = strncmp(KERNEL_SU_DOMAIN, domain, seclen) == 0;
	security_release_secctx(domain, seclen);
	return result;
}

bool is_zygote(void *sec)
{
	struct task_security_struct *tsec = (struct task_security_struct *)sec;
	if (!tsec) {
		return false;
	}
	char *domain;
	u32 seclen;
	bool result;
	int err = security_secid_to_secctx(tsec->sid, &domain, &seclen);
	if (err) {
		return false;
	}
	result = strncmp("u:r:zygote:s0", domain, seclen) == 0;
	security_release_secctx(domain, seclen);
	return result;
}

#define DEVPTS_DOMAIN "u:object_r:ksu_file:s0"

u32 ksu_get_devpts_sid()
{
	u32 devpts_sid = 0;
	int err = security_secctx_to_secid(DEVPTS_DOMAIN, strlen(DEVPTS_DOMAIN),
					   &devpts_sid);
	if (err) {
		pr_info("get devpts sid err %d\n", err);
	}
	return devpts_sid;
}
