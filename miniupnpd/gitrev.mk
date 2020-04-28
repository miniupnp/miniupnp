# (c) 2019-2020 Thomas Bernard
# For GNU Make

ISGITREPO := $(shell git rev-parse --is-inside-work-tree)
ifeq ($(ISGITREPO),true)
GITREF := $(shell git rev-parse --short HEAD)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
CPPFLAGS += -DMINIUPNPD_GIT_REF=\"$(GITBRANCH)-$(GITREF)\"
endif
