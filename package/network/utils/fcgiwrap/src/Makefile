all: fcgiwrap

fcgiwrap: fcgiwrap.o
	$(CC) -o $@ $< $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o tags fcgiwrap
