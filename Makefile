CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib
CPPFLAGS = -I/opt/homebrew/opt/openssl@3/include
LDLIBS += -lssl -lcrypto -lsqlite3

SERVER_TARGET = server
CLIENT_TARGET = client

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): main.o hashing.o
	$(CC) $(CFLAGS) -o $@ main.o hashing.o $(LDFLAGS) $(LDLIBS)

$(CLIENT_TARGET): client.o hashing.o
	$(CC) $(CFLAGS) -o $@ client.o hashing.o $(LDFLAGS) $(LDLIBS)

main.o: main.cpp hashing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main.cpp

hashing.o: hashing.cpp hashing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c hashing.cpp

client.o: client.cpp
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client.cpp

clean:
	rm -rf *.o $(SERVER_TARGET) $(CLIENT_TARGET)
