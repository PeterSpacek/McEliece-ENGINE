CC=gcc
CFLAGS=-fPIC
LDFLAGS = -shared 

TARGET=bpmecs.so
SOURCES = \
	compile.c
OBJECTS = \
	engine.o

all: $(TARGET)
	   @true
    
 $(OBJECTS) : $(SOURCES)
	@echo "============="
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -o  $(OBJECTS) -c  $(SOURCES) -I ../../BitPunch/lib/src/
    
$(TARGET): $(OBJECTS)
	@echo "======================="
	@echo "Creating engine library $@"
	@echo "======================="
	@$(CC)  $(LDFLAGS) -o $(TARGET)  $(OBJECTS) -ltasn1 -lbpumecs -lm
	@echo "-- $@ created --"
	
clean: 
	find ./ -type f -name '*.o' -exec rm -v {} \;
	
