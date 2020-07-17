#include <stdio.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <libaudit.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

static int avc_netlink_fd = -1;
static int audit_fd = -1;
static volatile int watch_status[2] = { 1, 1 };
static volatile int status_type = 0;

static int policy_reload_callback(int);
static int policy_setenforce_callback(int);

static int __attribute__ ((format(printf, 2, 3))) log_callback(int type, const char *fmt, ...);

static void cancel_watch_loop(int);

/*
 * Test program for sestatus and netlink interoperability.
 */
int
main (int argc, char *argv[])
{
	int rc = 0;

	signal(SIGINT, cancel_watch_loop);

	rc = avc_open (NULL, 0);
	if (rc < 0)
	{
		log_callback(SELINUX_ERROR, "failed to start avc: %s", strerror(errno));
		goto error;
	}
	else
	{
		log_callback(SELINUX_INFO, "opened avc successfully");
	}

	selinux_set_callback(SELINUX_CB_POLICYLOAD, (union selinux_callback) policy_reload_callback);
	selinux_set_callback(SELINUX_CB_SETENFORCE, (union selinux_callback) policy_setenforce_callback);
	selinux_set_callback (SELINUX_CB_LOG, (union selinux_callback) log_callback);

	/* open netlink socket */
	avc_netlink_fd = avc_netlink_acquire_fd ();
	if (avc_netlink_fd < 0)
	{
		log_callback(SELINUX_ERROR, "could not acquire avc netlink fd: %s", strerror(errno));
		rc = avc_netlink_fd;
		goto error;
	}
	log_callback(SELINUX_INFO, "got netlink socket: %d", avc_netlink_fd);

	/* open audit fd */
	audit_fd = audit_open();
	if (audit_fd < 0)
	{
		log_callback(SELINUX_ERROR, "failed to open audit fd: %s", strerror(errno));
	}

	/* begin netlink watch */
	log_callback(SELINUX_INFO, "watching netlink socket for events");
	while (watch_status[0])
	{
		if (avc_netlink_check_nb() < 0)
		{
			log_callback(SELINUX_ERROR, "failed to watch netlink socket: %s", strerror(errno));
			break;
		}
	}

	/* begin sestatus watch */
	log_callback(SELINUX_INFO, "watching sestatus page for events");
	while (watch_status[1])
	{
		if (selinux_status_updated() < 0)
		{
			log_callback(SELINUX_ERROR, "failed to watch status page: %s", strerror(errno));
			break;
		}
	}

error:
	if (avc_netlink_fd >= 0)
	{
		log_callback(SELINUX_INFO, "closing netlink socket: %d", avc_netlink_fd);
		avc_netlink_release_fd ();
		avc_netlink_fd = -1;
	}

	printf("destroying avc\n");
	avc_destroy ();

	printf("goodbye\n");
	return rc;
}

static void
cancel_watch_loop(int sig)
{
	watch_status[status_type++] = 0;
}

static int
policy_reload_callback(int seqno)
{
	log_callback(SELINUX_INFO, "policy reload notice received (seqno=%d)", seqno);
	return 0;
}

static int
policy_setenforce_callback(int seqno)
{
	log_callback(SELINUX_INFO, "policy setenforce notice received\n");
	return 0;
}

static int
log_callback (int type, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);

  if (audit_fd >= 0)
  {
    char buf[PATH_MAX*2];

    vsnprintf(buf, sizeof(buf), fmt, ap);
    audit_log_user_avc_message(audit_fd, AUDIT_USER_AVC, buf, NULL, NULL,
                             NULL, getuid());
    goto out;
  }

  vsyslog (LOG_USER | LOG_INFO, fmt, ap);

out:
  va_end(ap);

  return 0;
}

