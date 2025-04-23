# 这是我在test_chall2下得Makefile
CC = gcc
CFLAGS = -Wall -g -I./hash  # 假设你的 sha256.c、ripemd160.c 和 compound_hash.c 在 hash 文件夹里
LIBS = -lm  # 链接数学库

# 目标文件和可执行文件
TARGET = test_efficiency
OBJ = test_efficiency.o ./gen_extend_witness.o \
      ../hash/sha256.o ../hash/ripemd160.o ../hash/compound_hash.o  # 使用相对路径引用对象文件

# 编译目标
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

# 编译 test_efficiency.c
test_efficiency.o: ./test_efficiency.c
	$(CC) $(CFLAGS) -c ./test_efficiency.c -o test_efficiency.o

# 编译 gen_extend_witness.c 为对象文件
test_chall2/gen_extend_witness.o: ./gen_extend_witness.c
	$(CC) $(CFLAGS) -c ./gen_extend_witness.c -o ./gen_extend_witness.o

# 编译 hash/sha256.c 为对象文件
./hash/sha256.o: ../hash/sha256.c ./hash/sha256.h
	$(CC) $(CFLAGS) -c ../hash/sha256.c -o ../hash/sha256.o

# 编译 hash/ripemd160.c 为对象文件
./hash/ripemd160.o: ../hash/ripemd160.c ../hash/ripemd160.h
	$(CC) $(CFLAGS) -c ../hash/ripemd160.c -o ../hash/ripemd160.o

# 编译 hash/compound_hash.c 为对象文件
./hash/compound_hash.o: ../hash/compound_hash.c ../hash/compound_hash.h
	$(CC) $(CFLAGS) -c ../hash/compound_hash.c -o ../hash/compound_hash.o

# 清理文件
clean:
	rm -f $(OBJ) $(TARGET) ../hash/sha256.o ../hash/ripemd160.o ../hash/compound_hash.o  # 清理生成的文件
