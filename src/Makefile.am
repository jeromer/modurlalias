mod_url_alias_la_SOURCES = mod_url_alias.c
mod_url_alias_la_CFLAGS = -Wall ${MODULE_CFLAGS}
mod_url_alias_la_LDFLAGS = -rpath ${AP_LIBEXECDIR} -module -avoid-version ${MODULE_LDFLAGS}

mod_LTLIBRARIES = mod_url_alias.la
moddir=${AP_LIBEXECDIR}

install: install-am
	rm -f $(DESTDIR)${AP_LIBEXECDIR}/mod_url_alias.a
	rm -f $(DESTDIR)${AP_LIBEXECDIR}/mod_url_alias.la