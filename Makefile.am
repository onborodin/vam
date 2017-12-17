#
# $Id: Makefile.am 633 2017-04-15 13:51:07Z ziggi $
#
AUTOMAKE_OPTIONS = foreign no-dependencies no-installinfo

EXTRA_DIST = \
	LICENSE

install-data-hook:
if FREEBSD_OS
	chmod a+x $(DESTDIR)/${etcdir}/rc.d/vam
endif
	$(INSTALL) -d -m 750 -o $(APP_USER) -g $(APP_GROUP) $(DESTDIR)$(APP_LOGDIR)
	$(INSTALL) -d -m 750 -o $(APP_USER) -g $(APP_GROUP) $(DESTDIR)$(APP_RUNDIR)
	for data in $(nobase_conf_DATA);do \
	  chmod 0644 $(DESTDIR)$(APP_CONFDIR)/$$data; \
	done

if FREEBSD_OS
etcdir = @prefix@/etc
nobase_etc_SCRIPTS = rc.d/vam
endif

sbin_SCRIPTS = vam vam-helper

confdir = @APP_CONFDIR@
dist_conf_DATA = \
	vam.pw.example \
	vam.crt.example \
	vam.conf.example \
	vam.key.example

nobase_dist_pkgdata_DATA = \
	schema.sql \
	create-pg-db.sql \
	public/css/app.css \
	public/css/datatables.css \
	public/css/datatables.min.css \
	public/css/foundation-float.css \
	public/css/foundation-float.min.css \
	public/css/foundation.css \
	public/css/foundation.min.css \
	public/favicon.ico \
	public/favicon.png \
	public/icons/foundation-icons.css \
	public/icons/foundation-icons.eot \
	public/icons/foundation-icons.svg \
	public/icons/foundation-icons.ttf \
	public/icons/foundation-icons.woff \
	public/icons/preview.html \
	public/images/sort_asc_disabled.png \
	public/images/sort_asc.png \
	public/images/sort_both.png \
	public/images/sort_desc_disabled.png \
	public/images/sort_desc.png \
	public/js/app.js \
	public/js/datatables.js \
	public/js/datatables.min.js \
	public/js/foundation.js \
	public/js/foundation.min.js \
	public/js/jquery.js \
	public/js/jquery.min.js \
	public/js/what-input.js \
	\
	templs/user-list.html.ep \
	templs/user-add-form.html.ep \
	templs/user-add-handler.html.ep \
	templs/user-delete-form.html.ep \
	templs/user-delete-handler.html.ep \
	templs/user-update-form.html.ep \
	templs/user-update-handler.html.ep \
	templs/user-rename-form.html.ep \
	templs/user-rename-handler.html.ep \
	\
	templs/exception.development.html.ep \
	templs/exception.production.html.ep \
	templs/hello.html.ep \
	templs/layouts/default.html.ep \
	templs/not_found.development.html.ep \
	templs/not_found.production.html.ep \
	templs/login.html.ep

#EOF
