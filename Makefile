MAIN_CFLAGS :=  -g -Os -Wall $(shell pkg-config fuse --cflags)
MAIN_CPPFLAGS := -Wall -Wno-unused-function -Wconversion -Wtype-limits -DUSE_AUTH -D_XOPEN_SOURCE=700 -D_ISOC99_SOURCE
THR_CPPFLAGS := -DUSE_THREAD
THR_LDFLAGS := -lpthread
MAIN_LDFLAGS := $(shell pkg-config fuse --libs | sed -e s/-lrt// -e s/-ldl// -e s/-pthread// -e "s/  / /g")
variants := -mt
intermediates =

ifeq ($(shell pkg-config --atleast-version 2.10 gnutls ; echo $$?), 0)

    variants += -ssl -ssl-mt

    CERT_STORE := /etc/ssl/certs/ca-certificates.crt
    SSL_CPPFLAGS := -DUSE_SSL $(shell pkg-config gnutls --cflags) -DCERT_STORE=\"$(CERT_STORE)\"
    SSL_LDFLAGS := $(shell pkg-config gnutls --libs)
endif

binbase = httpfs2

binaries = $(addsuffix $(binsuffix),$(binbase))

manpages = $(addsuffix .1,$(binaries))

intermediates += $(addsuffix .xml,$(manpages))

targets = $(binaries) $(manpages)

full:
	$(MAKE) all $(addprefix all,$(variants))

all: $(targets)

httpfs2$(binsuffix): httpfs2.c
	$(CC) $(MAIN_CPPFLAGS) $(CPPFLAGS) $(MAIN_CFLAGS) $(CFLAGS) httpfs2.c $(MAIN_LDFLAGS) $(LDFLAGS) -o $@

httpfs2%.1: httpfs2.1
	ln -sf httpfs2.1 $@

clean: clean-recursive-full

clean-recursive:
	rm -f $(targets) $(intermediates)

%-full:
	$(MAKE) $* $(addprefix $*,$(variants))

%.1: %.1.txt
	a2x -f manpage $<

%-ssl: $*
	$(MAKE) CPPFLAGS='$(CPPFLAGS) $(SSL_CPPFLAGS)' LDFLAGS='$(LDFLAGS) $(SSL_LDFLAGS)' binsuffix=-ssl$(binsuffix) $*

%-mt: $*
	$(MAKE) CPPFLAGS='$(CPPFLAGS) $(THR_CPPFLAGS)' LDFLAGS='$(LDFLAGS) $(THR_LDFLAGS)' binsuffix=-mt$(binsuffix) $*

%-lstr: $*
	$(MAKE) CPPFLAGS='$(CPPFLAGS) -DNEED_STRNDUP -U_XOPEN_SOURCE -D_XOPEN_SOURCE=500' binsuffix=-lstr$(binsuffix) $*

%-rst: $*
	$(MAKE) CPPFLAGS='$(CPPFLAGS) -DRETRY_ON_RESET' binsuffix=-rst$(binsuffix) $*

# Rules to automatically make a Debian package

package = $(shell dpkg-parsechangelog | grep ^Source: | sed -e s,'^Source: ',,)
version = $(shell dpkg-parsechangelog | grep ^Version: | sed -e s,'^Version: ',, -e 's,-.*,,')
revision = $(shell dpkg-parsechangelog | grep ^Version: | sed -e -e 's,.*-,,')
architecture = $(shell dpkg --print-architecture)
tar_dir = $(package)-$(version)
tar_gz   = $(tar_dir).tar.gz
pkg_deb_dir = pkgdeb
unpack_dir  = $(pkg_deb_dir)/$(tar_dir)
orig_tar_gz = $(pkg_deb_dir)/$(package)_$(version).orig.tar.gz
pkg_deb_src = $(pkg_deb_dir)/$(package)_$(version)-$(revision)_source.changes
pkg_deb_bin = $(pkg_deb_dir)/$(package)_$(version)-$(revision)_$(architecture).changes

deb_pkg_key = CB8C5858

debclean:
	rm -rf $(pkg_deb_dir)

deb: debsrc debbin

debbin: $(unpack_dir)
	cd $(unpack_dir) && dpkg-buildpackage -b -k$(deb_pkg_key)

debsrc: $(unpack_dir)
	cd $(unpack_dir) && dpkg-buildpackage -S -k$(deb_pkg_key)

$(unpack_dir): $(orig_tar_gz)
	tar -zxf $(orig_tar_gz) -C $(pkg_deb_dir)

$(pkg_deb_dir):
	mkdir $(pkg_deb_dir)

$(pkg_deb_dir)/$(tar_gz): $(pkg_deb_dir)
	hg archive -t tgz $(pkg_deb_dir)/$(tar_gz)

$(orig_tar_gz): $(pkg_deb_dir)/$(tar_gz)
	ln -s $(tar_gz) $(orig_tar_gz)

