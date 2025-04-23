CC = gcc
CFLAGS = -Wall -g -I../hash  # 假设你的 compound_hash.c 在上级目录的 hash 文件夹里
LIBS = -lssl -lcrypto

# 目标文件和可执行文件
TARGET = test_owf
OBJ = test_owf.o ../hash/compound_hash.o ../hash/ripemd160.o  # 使用相对路径 ./ripemd160.o

# 编译目标
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

# 编译 test_owf.c
test_owf.o: test_owf.c
	$(CC) $(CFLAGS) -c test_owf.c

# 编译 ripemd160.c 为 ripemd160.o
./ripemd160.o: ../hash/ripemd160.c  # 确保文件路径正确
	$(CC) $(CFLAGS) -c ../hash/ripemd160.c -o ../hash/ripemd160.o  # 使用相对路径生成 ripemd160.o

# 清理文件
clean:
	rm -f $(OBJ) $(TARGET) ./ripemd160.o  # 清理生成的文件
