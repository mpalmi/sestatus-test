# sestatus test

Simple test program to test default use of SELinux status page alongside the
netlink avc. There is a single SELinux callback registered to print a
policyreload notice.

The program will loop on `avc_netlink_check_nb()`, displaying policyreload
notices until a SIGINT is issued, at which point it will do the same for
`selinux_status_updated()`. The second SIGINT will exit the program and close
the status page and netlink socket.

## To build

`make`

## To run

1) `./test`
2) Run `load_policy` in another terminal
3) SIGINT (ctrl+c) once to switch from netlink to sestatus
4) Run `load_policy` in another terminal
5) SIGINT (ctrl+c) a second time to exit

