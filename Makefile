CC=gcc
CFLAGS=

EXE = Analyzer

LD = gcc
# Flags for linking
LDFLAGS = -g

# Libraries to link with
# lcurl needed for curl
# ljson-c needed for json operations
LIBS = -lcurl -ljson-c -lpthread

OBJECTS = main.o pcap.o elasticSearch.o glbs.o stringBuilder.o LinkedList.o

default: all

all: $(OBJECTS)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $(EXE) $(LIBS) 
	-rm -rf *.o

main.o: main.c
	$(CC) -c -g main.c

pcap.o: pcap.c pcap.h
	$(CC) -c -g pcap.c

elasticSearch.o: elasticSearch.c elasticSearch.h
	$(CC) -c -g elasticSearch.c

glbs.o: glbs.c glbs.h
	$(CC) -c -g glbs.c

stringBuilder.o: tools/stringBuilder.c tools/stringBuilder.h
	$(CC) -c -g tools/stringBuilder.c

LinkedList.o: tools/LinkedList.c tools/LinkedList.h
	$(CC) -c -g tools/LinkedList.c

clean:
	-rm -f $(EXE)
	-rm -rf *.o