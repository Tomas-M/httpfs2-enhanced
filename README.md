# httpfs

Modified version of http filesystem (httpfs2 as downloaded on December 2016),
with added support for MD5 checking and caching data in local file.

Developed for Slax

Author of patches: mike621 (freelancer from Russian Federation)

Sponsor (paid for the modifications): Tomas M via www.slax.org

It is possible to compile this statically against uclibc with buildroot.
If you use this to mount root filesystem over http, you may also need to
patch uclibc's open_config function to never reopen /etc/hosts,
/etc/resolv.conf, etc ... because reopening those on reconnection while
the root filesystem is mounted will cause lock if those files are not yet
cached by the kernel.
