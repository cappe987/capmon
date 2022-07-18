


CC = gcc

OBJ = capdump.o

EXE = capdump

all: $(OBJ)
	$(CC) $(OBJ) -o $(EXE)


clean:
	rm $(OBJ)
	rm $(EXE)

