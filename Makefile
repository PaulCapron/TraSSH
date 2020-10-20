# For the “trassh” target (the executable, part of “build”)
# To get Musl <https://musl.libc.org>:  apt install musl-tools
CC      = musl-gcc
CFLAGS += -std=c89 -Wall -Wextra -O2 -march=native -static -s -Wl,--gc-sections

# For the “trassh.dat” target (part of “build”)
# KEYTYPE is ‘rsa<SIZE_IN_BITS>’ or ‘ecdsa384’ (elliptic curve nistp384)
BANNER  = SSH-2.0-TraSSH\r\n
KEYTYPE = rsa8192

# For the “run” and “test” targets
PORT = 2222

# For the “[un]install” and “[un]service” targets
BIN_DIR = /usr/local/bin
DAT_DIR = /usr/local/share
SD_DIR  = /etc/systemd/system

.PHONY: build clean install uninstall service unservice run test cloc speed

build: trassh trassh.dat

clean:
	rm -rf trassh trassh.dat

trassh: trassh.c
	$(CC) $(CFLAGS) -o $@ $?
	size $@

trassh.dat: packcraft.pl
	printf "$(BANNER)" >$@
	./$? kexinit $(KEYTYPE) >>$@ </dev/urandom
	./$? kexdhreply $(KEYTYPE) >>$@ </dev/urandom
	./$? newkeys >>$@
	wc -c $@

install: $(BIN_DIR)/trassh $(DAT_DIR)/trassh.dat

uninstall:
	rm $(BIN_DIR)/trassh $(DAT_DIR)/trassh.dat

$(BIN_DIR)/trassh: trassh
	install -o root -m 0755 $? $@

$(DAT_DIR)/trassh.dat: trassh.dat
	cp $? $@

service: install $(SD_DIR)/trassh.service $(SD_DIR)/trassh.socket
	systemctl daemon-reload
	systemctl stop --quiet trassh.socket
	systemctl enable --now trassh.socket

unservice:
	systemctl stop trassh.service
	systemctl disable --now trassh.socket
	rm $(SD_DIR)/trassh.service $(SD_DIR)/trassh.socket
	systemctl daemon-reload

$(SD_DIR)/trassh.service: trassh.service
	sed -e 's,/usr/local/bin,$(BIN_DIR),' -e 's,/usr/local/share,$(DAT_DIR),' $? >$@

$(SD_DIR)/trassh.socket: trassh.socket
	cp $? $@

run: build
	./sockbinder.pl $(PORT) ./trassh <trassh.dat

test: # in one terminal, “make run” in another
	go run ./client_goxssh.go $(PORT) || echo; sleep 2
	./client_openssh.sh $(PORT) || echo; sleep 2
	./client_libssh2.pl $(PORT) || echo; sleep 2
	./client_libssh.py $(PORT) || echo; sleep 2
	./client_paramiko.py $(PORT) || true

cloc:
	cloc --force-lang=ini,socket --force-lang=ini,service .

speed:
	openssl speed -seconds 5 ecdsap256 ecdsap384 ecdsap521 rsa4096 rsa7680 rsa15360
