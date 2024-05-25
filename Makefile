CC = g++
CFLAGS = -std=c++11 -Wall

all: MyProject

MyProject: main.cpp
	$(CC) $(CFLAGS) -o MyProject main.cpp -lsqlite3 -L"ws2_32"

clean:
	rm -f MyProject
