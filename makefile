CC=gcc
CFLAGS=-fPIC
LDFLAGS = -shared 

BITPUNCHDIR= BitPunch/lib/src/
TARGET=bpmecs.so
SOURCES = \
	src/compile.c
OBJECTS = \
	engine.o
OPENSSLDIR= \
	/usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines/pwd/

all: $(TARGET)
	   @true
    
 $(OBJECTS) : $(SOURCES)
	@echo "============="
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -o  $(OBJECTS) -c  $(SOURCES) -I $(BITPUNCHDIR)
    
$(TARGET): $(OBJECTS)
	@echo "======================="
	@echo "Creating engine library $@"
	@echo "======================="
	@$(CC)  $(LDFLAGS) -o $(TARGET)  $(OBJECTS) -ltasn1 -lbpumecs -lm
	@echo "-- $@ created --"
	@sudo mv $(TARGET) $(addprefix $(OPENSSLDIR), $(TARGET))
	
.PHONY : clean

clean: 
	@find ./ -type f -name '*.o' -exec rm -v {} \;
	
