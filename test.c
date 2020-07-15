#include <stdio.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

static int avc_netlink_fd = -1;
static volatile int watch_status[2] = { 1, 1};
static volatile int status_type = 0;

static int policy_reload_callback(int);
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
		printf("failed to start avc: %s\n", strerror(errno));
		goto error;
	}
	else
	{
		printf("opened avc successfully\n");
	}

	selinux_set_callback(SELINUX_CB_POLICYLOAD, (union selinux_callback) policy_reload_callback);

	avc_netlink_fd = avc_netlink_acquire_fd ();
	if (avc_netlink_fd < 0)
	{
		printf("could not acquire avc netlink fd: %s\n", strerror(errno));
		rc = avc_netlink_fd;
		goto error;
	}
	printf("got netlink socket: %d\n", avc_netlink_fd);

	/* begin netlink watch */
	printf("\n");
	printf("watching netlink socket for events\n");
	while (watch_status[0])
	{
		if (avc_netlink_check_nb() < 0)
		{
			printf("failed to watch netlink socket: %s\n", strerror(errno));
			break;
		}
	}

	/* begin sestatus watch */
	printf("\n");
	printf("watching sestatus page for events\n");
	while (watch_status[1])
	{
		if (selinux_status_updated() < 0)
		{
			printf("failed to watch status page: %s\n", strerror(errno));
			break;
		}
	}

error:
	if (avc_netlink_fd >= 0)
	{
		printf("closing netlink socket: %d\n", avc_netlink_fd);
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
	printf("policy reload notice received\n");
	return 0;
}
