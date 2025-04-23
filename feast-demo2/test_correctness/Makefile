# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -I../hash  # Include the hash folder for header files
LIBS =  # If you need additional libraries, add them here, e.g., -lssl -lcrypto

# Target and object files
TARGET = test_hash
OBJ = test_hash.o ../hash/sha256.o ../hash/ripemd160.o  # Object files for linking

# Compile target
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

# Compile test_hash.c into test_hash.o
test_hash.o: test_hash.c
	$(CC) $(CFLAGS) -c test_hash.c

# Compile sha256.c into sha256.o (located in the hash folder)
../hash/sha256.o: ../hash/sha256.c  # Ensure the path is correct
	$(CC) $(CFLAGS) -c ../hash/sha256.c -o ../hash/sha256.o

# Compile ripemd160.c into ripemd160.o (located in the hash folder)
../hash/ripemd160.o: ../hash/ripemd160.c  # Ensure the path is correct
	$(CC) $(CFLAGS) -c ../hash/ripemd160.c -o ../hash/ripemd160.o

# Clean up object files and the executable
clean: 
	rm -f $(OBJ) $(TARGET) ../hash/sha256.o ../hash/ripemd160.o  # Clean generated files

# Phony targets
.PHONY: all clean
