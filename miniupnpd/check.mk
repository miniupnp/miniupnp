# (c) 2020-2026 Thomas BERNARD

check:	validateupnppermissions validategetifaddr validatessdppktgen \
	validateupnphttp \
	validateversion

validateversion:	miniupnpd $(SRCDIR)/VERSION
	./miniupnpd --version
	[ "`./miniupnpd --version | head -1 | cut -d' ' -f-2`" = "miniupnpd `cat $(SRCDIR)/VERSION`" ]
	touch $@

validate%:	$(SRCDIR)/test%.sh test%
	$(SHELL) $<
	touch $@

validatessdppktgen:	testssdppktgen
	./$<
	touch $@
