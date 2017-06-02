all: portal ptlctl

portal: auth.o client_list.o commandline.o conf.o debug.o \
	fw_iptables.o gateway.o http.o httpd_thread.o util.o \
	ptlctl_thread.o safe.o tc.o firewall.o libhttpd/api.o \
	libhttpd/ip_acl.o libhttpd/protocol.o libhttpd/version.o
	$(CC) -o $@ $^ $(LDFLAGS)

ptlctl: ptlctl.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o libhttpd/*.o tags portal ptlctl
