

.DEFAULT_GOAL := all

EXENAME=capmon
IDIR =include
CC=gcc
CFLAGS=-I$(IDIR)

#_DEPS = 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

ODIR=obj
SDIR=src
#LDIR =lib

#LIBS=


_OBJ = capmon.o libcapmon.o capabilities.o kprobes.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

obj:
	mkdir -p obj

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS) | obj
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJ)
	$(CC) -o $(EXENAME) $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ $(LEXC)
	rm -f $(EXENAME)
	rmdir obj
