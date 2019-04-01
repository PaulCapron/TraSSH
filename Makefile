CC = musl-gcc
CFLAGS += -std=c89 -pedantic -Wall -Wextra
CFLAGS += -O2 -march=native -static -fstack-protector-strong
SHA1SUM ?= openssl sha1
PREFIX ?= /usr/local
SD_PREFIX ?= /etc/systemd/system

.PHONY: install service

sshtarp: sshtarp.c
	$(CC) $(CFLAGS) -o $@ $<
	strip $@
	$(SHA1SUM) $@
	wc -c <$@

install: $(PREFIX)/bin/sshtarp

$(PREFIX)/bin/sshtarp: sshtarp
	install $< $@

service: $(PREFIX)/bin/sshtarp $(SD_PREFIX)/sshtarp.service $(SD_PREFIX)/sshtarp.socket
	systemctl daemon-reload
	systemctl enable sshtarp.socket
	systemctl restart sshtarp.socket
	systemctl stop sshtarp.service

$(SD_PREFIX)/sshtarp.service: sshtarp.service
	sed 's,$$MAKEFILE_PREFIX,$(PREFIX),' <$< >$@

$(SD_PREFIX)/sshtarp.socket: sshtarp.socket
	cp $< $@
