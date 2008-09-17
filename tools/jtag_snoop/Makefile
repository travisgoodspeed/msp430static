NAME=jtag_snoop

PKG_INSTALL_DIR = `pwd`

## This sets the compiler to i386 PC.
XCC = gcc

## Build flags.
CFLAGS = -g -Wall -I$(PKG_INSTALL_DIR)/include
LDFLAGS = -L$(PKG_INSTALL_DIR)/lib -Wl,--gc-sections -Wl,--Map -Wl,server.map
LIBS = 
LD = $(XCC)

## Build rules.
all: $(NAME)

OBJECT_FILES     = obj/jtag.o

obj/%.o: src/%.c
	$(XCC) -c -o obj/$*.o $(CFLAGS) $<

$(NAME): $(OBJECT_FILES)
	$(LD) $(LDFLAGS) -o $@ $(OBJECT_FILES) $(LIBS)

clean:
	rm -f obj/*.o jtag jtag.map $(NAME)
