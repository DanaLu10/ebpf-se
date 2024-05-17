SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) verify

.PHONY: $(TOPTARGETS) $(SUBDIRS)
