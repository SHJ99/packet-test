CC = g++
CFLAGS = -Wall -Wextra -std=c++11
LIBS = -lpcap -lnet

all: packet-stat

packet-stat: packet-stat.cpp
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f packet-stat
