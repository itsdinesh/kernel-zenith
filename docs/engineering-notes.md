# Engineering Notes

## KernelSU Compilation Failure on Zenith Kernel

### Issue Description
During compilation of the Zenith kernel, the build failed in `KernelSU/kernel/selinux/sepolicy.c` due to missing members in `struct policydb`:
```
error: no member named 'android_netlink_route' in 'struct policydb'
error: use of undeclared identifier 'POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE'
error: no member named 'android_netlink_getneigh' in 'struct policydb'
error: use of undeclared identifier 'POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH'
```
These fields are Android GKI-specific additions that do not exist on the Zenith kernel.

### Resolution
We wrapped the config fixup blocks inside preprocessor guards:
```c
#ifdef POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE
        if (old_pol->policydb.android_netlink_route) {
            pr_info("adding POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE\n");
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        }
#endif
#ifdef POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH
        if (old_pol->policydb.android_netlink_getneigh) {
            pr_info("adding POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH\n");
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        }
#endif
```
This ensures the fields are only referenced and fixups applied if the target kernel configuration actually defines `POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE` and `POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH`.
