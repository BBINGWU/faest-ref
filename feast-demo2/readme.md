# 项目结构说明
hash文件夹中实现了SHA-256，RIPEMD-160以及RIPEMD-160和SHA-256的复合哈希函数。
其中，SHA-256，RIPEMD-160函数实现正确，在test_correctness文件夹下的运行make即可检验。

test_owf文件夹的测试文件对比了AES和复合哈希函数的效率，这个也是对签名方案的说明。

test_chall2 文件夹中的测试文件测试了用复合哈希函数生成extende_witness的效率。可以和faest 签名中的对AES做extended_witness的效率做对比。

