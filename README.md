# YuS流密码实现项目

## 项目介绍
本项目基于论文《YuS: A FHE-friendly Stream Cipher Based on New Quadratic Permutations》实现了YuS流密码，支持80/128位安全级别，兼容HElib（BGV）和SEAL（BFV）同态加密方案。

## 项目特性
- ✅ **FHE友好设计**：专门为全同态加密优化的流密码结构
- ✅ **双方案支持**：同时支持HElib（BGV）和SEAL（BFV）方案
- ✅ **高性能**：优化的内存管理和并行计算支持
- ✅ **跨平台**：支持Windows和Linux环境
- ✅ **完整测试**：包含单元测试和性能基准测试

## 环境依赖
- **操作系统**：Windows 10/11 或 Linux (Ubuntu 22.04+)
- **编译器**：MSVC 2019+ 或 GCC 11.4+（支持C++17）
- **CMake**：3.16+
- **OpenMP**：并行计算支持

## 项目结构
```
Yus_cipher/
├── src/                        # 核心源代码
│   ├── sbox.cpp                # S盒实现
│   ├── linear_layer.cpp        # 线性层实现
│   ├── round_key.cpp           # 轮密钥生成
│   ├── yus_core.cpp            # YuS核心算法
│   ├── utils.cpp               # 工具函数
│   └── fhe_wrapper.cpp         # FHE封装层
├── include/yus/                # 头文件
│   ├── yus_core.h              # YuS核心算法接口
│   ├── sbox.h                  # S盒实现
│   ├── linear_layer.h          # 线性层实现  
│   ├── round_key.h             # 轮密钥生成
│   ├── fhe_wrapper.h           # FHE封装接口
│   └── utils.h                 # 工具函数
├── examples/                   # 示例代码
│   └── yus_demo.cpp            # YuS密码演示程序
├── tests/                      # 单元测试
│   ├── test_main.cpp           # 测试主程序
│   ├── test_sbox.cpp           # S盒测试
│   ├── test_linear_layer.cpp   # 线性层测试
│   ├── test_round_key.cpp      # 轮密钥测试
│   ├── test_yus_core.cpp       # YuS核心测试
│   └── test_fhe.cpp            # FHE功能测试
├── plugins/                    # 第三方库（已预编译）
│   ├── openssl/                # OpenSSL密码学库
│   ├── GMP/                    # GNU多精度算术库
│   ├── mpfr/                   # 多精度浮点运算库
│   ├── ntl/                    # 数论库
│   ├── HElib/                  # HElib全同态加密库（BGV方案）
│   ├── SEAL/                   # SEAL全同态加密库（BFV方案）
│   ├── googletest/             # GoogleTest单元测试框架
│   ├── zlib/                   # 数据压缩库
│   └── zstd/                   # Zstandard压缩库
└── build/                      # 构建目录
```

## 编译步骤

### Windows环境编译
```cmd
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake ..

# 编译项目
cmake --build . --config Release

# 运行示例程序
.\yus_example.exe

# 运行测试
.\yus_test.exe
```

### Linux环境编译
```bash
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake ..

# 编译项目
make -j$(nproc)

# 运行示例程序
./yus_example

# 运行测试
./yus_test
```

## 测试结果

### 示例程序性能 (yus_example.exe)

```bash
=== Yus Cipher Demo with Debug Mode ===
[DEBUG] Program started
[STAGE 1] Generating prime p...
[MEMORY] Before prime generation - Working Set: 6 MB, Pagefile: 1 MB
[SUCCESS] Generated prime p: 76991
[MEMORY] After prime generation - Working Set: 8 MB, Pagefile: 1 MB
[DEBUG] Press Enter to continue to Stage 2...
[STAGE 2] Initializing YuS cipher...
[SUCCESS] YuS cipher initialized
[MEMORY] After YuS initialization - Working Set: 8 MB, Pagefile: 1 MB
[STAGE 3] Generating master key...
[PROGRESS] Generated 0/36 key elements
[PROGRESS] Generated 10/36 key elements
[PROGRESS] Generated 20/36 key elements
[PROGRESS] Generated 30/36 key elements
[SUCCESS] Master key generated
[MEMORY] After master key generation - Working Set: 8 MB, Pagefile: 1 MB
[STAGE 4] Setting nonce...
[STAGE 5] Initializing YuS with key and nonce...
[SUCCESS] YuS initialized
[MEMORY] After YuS init - Working Set: 8 MB, Pagefile: 1 MB
[DEBUG] Press Enter to continue to Stage 6...
[STAGE 6] Generating keystream...
[SUCCESS] Generated keystream with 24 elements
  [0]: 28597
  [1]: 14153
  [2]: 36707
  [3]: 25559
  [4]: 56393
  ... and 19 more elements
[MEMORY] After keystream generation - Working Set: 9 MB, Pagefile: 2 MB
[DEBUG] Press Enter to continue to FHE operations...
[STAGE 7] Starting FHE operations with optimized parameters...
[FHE PARAMS] Security: 80, Poly degree: 4096, Cipher bits: 200
[FHE] Initializing FHE wrapper...
[SUCCESS] FHE wrapper initialized
[MEMORY] After FHE wrapper init - Working Set: 13 MB, Pagefile: 7 MB
[FHE] Generating keys...
[SUCCESS] FHE keys generated
[MEMORY] After FHE key generation - Working Set: 13 MB, Pagefile: 7 MB
[DEBUG] Press Enter to continue to encryption...
[FHE] Encrypting keystream...
[SUCCESS] Keystream encrypted (1 ciphertexts)
[MEMORY] After keystream encryption - Working Set: 14 MB, Pagefile: 7 MB
[FHE] Encrypting master key (first 8 elements)...
[SUCCESS] Master key encrypted (1 ciphertexts)
[MEMORY] After master key encryption - Working Set: 14 MB, Pagefile: 7 MB
[DEBUG] Press Enter to continue to homomorphic evaluation...
[FHE] Starting homomorphic evaluation...
[SUCCESS] FHE evaluation completed
[RESULTS] Evaluation time: 5.04 ms
[RESULTS] Throughput: 9.3006 KiB/s
[MEMORY] After FHE evaluation - Working Set: 15 MB, Pagefile: 9 MB
[DEBUG] Program completed successfully!
Press Enter to exit...
```

### 单元测试结果 (yus_test.exe)

```bash
=== Yus Cipher FHE Tests with Debug Mode ===
[DEBUG] Starting test suite with 1 arguments
[==========] Running 16 tests from 5 test suites.
[----------] Global test environment set-up.
[----------] 5 tests from FHEWrapperTest
[ RUN      ] FHEWrapperTest.InitBGV
[TEST START] FHEWrapperTest.InitBGV
[TEST INFO] Testing BGV scheme initialization...
[PARAMS] Security: 80, Poly degree: 2048, Cipher bits: 100
[TIME] Wrapper construction: 211 ms
[TIME] Key generation: 3 ms
[SUCCESS] BGV initialization completed
[TEST PASSED] FHEWrapperTest.InitBGV
[       OK ] FHEWrapperTest.InitBGV (224 ms)
[ RUN      ] FHEWrapperTest.InitBFV
[TEST START] FHEWrapperTest.InitBFV
[TEST INFO] Testing BFV scheme initialization...
[PARAMS] Security: 80, Poly degree: 4096, Cipher bits: 200
[TIME] Wrapper construction: 8 ms
[TIME] Key generation: 2 ms
[SUCCESS] BFV initialization completed
[TEST PASSED] FHEWrapperTest.InitBFV
[       OK ] FHEWrapperTest.InitBFV (13 ms)
[ RUN      ] FHEWrapperTest.EncryptDecryptBGV
[TEST START] FHEWrapperTest.EncryptDecryptBGV
[TEST INFO] Testing BGV encryption and decryption...
[PARAMS] Security: 80, Poly degree: 2048, Cipher bits: 100
[TIME] Key generation: 2 ms
[DATA] Plaintext vector size: 4
[TIME] Encryption: 4 ms
[DATA] Ciphertext vector size: 4
[TIME] Decryption: 1 ms
[DATA] Decrypted vector size: 4
[SUCCESS] BGV encryption/decryption test completed
[TEST PASSED] FHEWrapperTest.EncryptDecryptBGV
[       OK ] FHEWrapperTest.EncryptDecryptBGV (215 ms)
[ RUN      ] FHEWrapperTest.EncryptDecryptBFV
[TEST START] FHEWrapperTest.EncryptDecryptBFV
[TEST INFO] Testing BFV encryption and decryption...
[PARAMS] Security: 80, Poly degree: 4096, Cipher bits: 200
[TIME] Key generation: 2 ms
[DATA] Plaintext vector size: 4
[TIME] Encryption: 0 ms
[DATA] Ciphertext vector size: 1
[TIME] Decryption: 1 ms
[DATA] Decrypted vector size: 4096
[SUCCESS] BFV encryption/decryption test completed
[TEST PASSED] FHEWrapperTest.EncryptDecryptBFV
[       OK ] FHEWrapperTest.EncryptDecryptBFV (14 ms)
[ RUN      ] FHEWrapperTest.MemoryTest
[TEST START] FHEWrapperTest.MemoryTest
[TEST INFO] Testing memory usage with minimal parameters...
```

## 内存使用情况
- **启动时**：6 MB工作集，1 MB页面文件
- **素数生成后**：8 MB工作集，1 MB页面文件  
- **FHE初始化后**：13 MB工作集，7 MB页面文件
- **FHE评估后**：15 MB工作集，9 MB页面文件

## 核心功能

### YuS流密码核心
- 基于二次置换的FHE友好流密码设计
- 支持80位和128位安全级别
- 优化的密钥生成和密钥流产生

### FHE集成
- **HElib (BGV方案)**：支持多项式次数2048，密文比特数100
- **SEAL (BFV方案)**：支持多项式次数4096，密文比特数200
- 同态加密/解密操作
- 同态评估功能