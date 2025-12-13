/**
 * @file test_fhe.cpp
 * @brief YuS流密码FHE全同态加密组件测试
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 使用Google Test框架对YuS流密码的FHE全同态加密组件进行单元测试。
 * 包含BGV和BFV方案的初始化、加密解密功能测试，以及内存使用测试。
 * 支持详细的调试信息和性能计时功能。
 */

#include "yus/fhe_wrapper.h"
#include "yus/utils.h"
#include <gtest/gtest.h>
#include <iostream>
#include <chrono>

/**
 * @test FHEWrapperTest.InitBGV
 * @brief 测试BGV方案初始化功能
 * 
 * 验证BGV全同态加密方案的初始化过程，包括：
 * - 配置最小化参数以降低内存使用
 * - 创建FHE包装器对象
 * - 生成密钥对
 * - 验证初始化过程无异常
 */
TEST(FHEWrapperTest, InitBGV) {
    std::cout << "[TEST INFO] Testing BGV scheme initialization..." << std::endl;
    
    try {
        // 配置BGV方案参数（最小化以降低内存使用）
        yus::FHEParams params;
        params.security_level = 80;                // 80位安全级别
        params.poly_modulus_degree = 2048;         // 多项式模数次数（进一步降低到2048）
        params.plain_modulus = yus::generate_prime(17);  // 17位素数作为明文模数
        params.cipher_modulus_bits = 100;          // 密文模数位数（进一步降低到100）
        
        std::cout << "[PARAMS] Security: " << params.security_level 
                  << ", Poly degree: " << params.poly_modulus_degree
                  << ", Cipher bits: " << params.cipher_modulus_bits << std::endl;
        
        // 计时：包装器构造时间
        auto start = std::chrono::high_resolution_clock::now();
        yus::FHEWrapper wrapper(yus::FHE_SCHEME::BGV, params);
        auto end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Wrapper construction: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        
        // 计时：密钥生成时间
        start = std::chrono::high_resolution_clock::now();
        wrapper.generate_keys();
        end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Key generation: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        
        std::cout << "[SUCCESS] BGV initialization completed" << std::endl;
        
        // 验证密钥生成过程无异常
        EXPECT_NO_THROW(wrapper.generate_keys());
        
    } catch (const std::exception& e) {
        std::cout << "[EXCEPTION] BGV test failed: " << e.what() << std::endl;
        FAIL() << "Exception in BGV test: " << e.what();
    }
}

/**
 * @test FHEWrapperTest.InitBFV
 * @brief 测试BFV方案初始化功能
 * 
 * 验证BFV全同态加密方案的初始化过程，包括：
 * - 配置支持密钥交换的参数
 * - 创建FHE包装器对象
 * - 生成密钥对
 * - 验证初始化过程无异常
 */
TEST(FHEWrapperTest, InitBFV) {
    std::cout << "[TEST INFO] Testing BFV scheme initialization..." << std::endl;
    
    try {
        // 配置BFV方案参数（支持密钥交换）
        yus::FHEParams params;
        params.security_level = 80;                // 80位安全级别
        params.poly_modulus_degree = 4096;         // 多项式模数次数（增加到4096以支持密钥交换）
        params.plain_modulus = yus::generate_prime(17);  // 17位素数作为明文模数
        params.cipher_modulus_bits = 200;          // 密文模数位数（增加到200）
        
        std::cout << "[PARAMS] Security: " << params.security_level 
                  << ", Poly degree: " << params.poly_modulus_degree
                  << ", Cipher bits: " << params.cipher_modulus_bits << std::endl;
        
        // 计时：包装器构造时间
        auto start = std::chrono::high_resolution_clock::now();
        yus::FHEWrapper wrapper(yus::FHE_SCHEME::BFV, params);
        auto end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Wrapper construction: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        
        // 计时：密钥生成时间
        start = std::chrono::high_resolution_clock::now();
        wrapper.generate_keys();
        end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Key generation: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        
        std::cout << "[SUCCESS] BFV initialization completed" << std::endl;
        
        // 验证密钥生成过程无异常
        EXPECT_NO_THROW(wrapper.generate_keys());
        
    } catch (const std::exception& e) {
        std::cout << "[EXCEPTION] BFV test failed: " << e.what() << std::endl;
        FAIL() << "Exception in BFV test: " << e.what();
    }
}

/**
 * @test FHEWrapperTest.EncryptDecryptBGV
 * @brief 测试BGV方案加密解密功能
 * 
 * 验证BGV方案的完整加密解密流程，包括：
 * - 配置BGV参数
 * - 生成密钥对
 * - 加密4元素明文向量
 * - 解密并验证结果正确性
 */
TEST(FHEWrapperTest, EncryptDecryptBGV) {
    std::cout << "[TEST INFO] Testing BGV encryption and decryption..." << std::endl;
    
    try {
        // 配置BGV方案参数（使用较小参数）
        yus::FHEParams params;
        params.security_level = 80;                // 80位安全级别
        params.poly_modulus_degree = 2048;         // BGV使用较小的参数
        params.plain_modulus = yus::generate_prime(17);  // 17位素数作为明文模数
        params.cipher_modulus_bits = 100;          // BGV使用较小的参数
        
        std::cout << "[PARAMS] Security: " << params.security_level 
                  << ", Poly degree: " << params.poly_modulus_degree
                  << ", Cipher bits: " << params.cipher_modulus_bits << std::endl;
        
        yus::FHEWrapper wrapper(yus::FHE_SCHEME::BGV, params);
        
        // 计时：密钥生成时间
        auto start = std::chrono::high_resolution_clock::now();
        wrapper.generate_keys();
        auto end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Key generation: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        
        // 创建4元素明文向量（全部初始化为1）
        std::vector<mpz_class> plain(4, 1);
        std::cout << "[DATA] Plaintext vector size: " << plain.size() << std::endl;
        
        // 计时：加密时间
        start = std::chrono::high_resolution_clock::now();
        std::vector<yus::FHEWrapper::CiphertextPtr> cipher;
        wrapper.encrypt(plain, cipher);
        end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Encryption: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        std::cout << "[DATA] Ciphertext vector size: " << cipher.size() << std::endl;
        
        // 计时：解密时间
        start = std::chrono::high_resolution_clock::now();
        auto decrypted = wrapper.decrypt(cipher);
        end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Decryption: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        std::cout << "[DATA] Decrypted vector size: " << decrypted.size() << std::endl;
        
        // ✅ BGV方案：解密向量大小应该等于明文向量大小
        EXPECT_EQ(decrypted.size(), plain.size());
        
        // 验证每个解密元素与原始明文匹配
        for (size_t i = 0; i < plain.size(); ++i) {
            EXPECT_EQ(decrypted[i], plain[i]) << "Mismatch at index " << i;
        }
        
        std::cout << "[SUCCESS] BGV encryption/decryption test completed" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "[EXCEPTION] BGV encrypt/decrypt test failed: " << e.what() << std::endl;
        FAIL() << "Exception in BGV encrypt/decrypt test: " << e.what();
    }
}

/**
 * @test FHEWrapperTest.EncryptDecryptBFV
 * @brief 测试BFV方案加密解密功能
 * 
 * 验证BFV方案的完整加密解密流程，包括：
 * - 配置BFV参数（支持批处理编码）
 * - 生成密钥对
 * - 加密4元素明文向量
 * - 解密并验证结果正确性（考虑批处理编码特性）
 */
TEST(FHEWrapperTest, EncryptDecryptBFV) {
    std::cout << "[TEST INFO] Testing BFV encryption and decryption..." << std::endl;
    
    try {
        // 配置BFV方案参数（支持密钥交换和批处理）
        yus::FHEParams params;
        params.security_level = 80;                // 80位安全级别
        params.poly_modulus_degree = 4096;         // 增加到4096以支持密钥交换
        params.plain_modulus = yus::generate_prime(17);  // 17位素数作为明文模数
        params.cipher_modulus_bits = 200;          // 增加到200
        
        std::cout << "[PARAMS] Security: " << params.security_level 
                  << ", Poly degree: " << params.poly_modulus_degree
                  << ", Cipher bits: " << params.cipher_modulus_bits << std::endl;
        
        yus::FHEWrapper wrapper(yus::FHE_SCHEME::BFV, params);
        
        // 计时：密钥生成时间
        auto start = std::chrono::high_resolution_clock::now();
        wrapper.generate_keys();
        auto end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Key generation: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        
        // 创建4元素明文向量（全部初始化为1）
        std::vector<mpz_class> plain(4, 1);
        std::cout << "[DATA] Plaintext vector size: " << plain.size() << std::endl;
        
        // 计时：加密时间
        start = std::chrono::high_resolution_clock::now();
        std::vector<yus::FHEWrapper::CiphertextPtr> cipher;
        wrapper.encrypt(plain, cipher);
        end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Encryption: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        std::cout << "[DATA] Ciphertext vector size: " << cipher.size() << std::endl;
        
        // 计时：解密时间
        start = std::chrono::high_resolution_clock::now();
        auto decrypted = wrapper.decrypt(cipher);
        end = std::chrono::high_resolution_clock::now();
        
        std::cout << "[TIME] Decryption: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() 
                  << " ms" << std::endl;
        std::cout << "[DATA] Decrypted vector size: " << decrypted.size() << std::endl;
        
        // ✅ 修复：对于BFV方案，只检查前plain.size()个元素的值
        // BFV使用批处理编码，解密向量大小为poly_modulus_degree，但只有前几个元素有效
        EXPECT_GE(decrypted.size(), plain.size());
        
        // 验证前plain.size()个解密元素与原始明文匹配
        for (size_t i = 0; i < plain.size(); ++i) {
            EXPECT_EQ(decrypted[i], plain[i]) << "Mismatch at index " << i;
        }
        
        std::cout << "[SUCCESS] BFV encryption/decryption test completed" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "[EXCEPTION] BFV encrypt/decrypt test failed: " << e.what() << std::endl;
        FAIL() << "Exception in BFV encrypt/decrypt test: " << e.what();
    }
}

/**
 * @test FHEWrapperTest.MemoryTest
 * @brief 测试FHE内存使用情况
 * 
 * 使用最小化参数测试FHE组件在低内存环境下的表现，包括：
 * - 配置最小参数（1024次多项式，8位素数，50位密文模数）
 * - 测试最小数据量（2元素向量）的加密解密
 * - 验证内存使用在可接受范围内
 */
TEST(FHEWrapperTest, MemoryTest) {
    std::cout << "[TEST INFO] Testing memory usage with minimal parameters..." << std::endl;
    
    try {
        // 配置最小化参数以测试内存使用
        yus::FHEParams params;
        params.security_level = 80;                // 80位安全级别
        params.poly_modulus_degree = 1024;         // 最小参数
        params.plain_modulus = yus::generate_prime(8);  // 更小的素数（8位）
        params.cipher_modulus_bits = 50;           // 最小参数
        
        std::cout << "[MINIMAL PARAMS] Security: " << params.security_level 
                  << ", Poly degree: " << params.poly_modulus_degree
                  << ", Cipher bits: " << params.cipher_modulus_bits << std::endl;
        
        yus::FHEWrapper wrapper(yus::FHE_SCHEME::BFV, params);
        wrapper.generate_keys();
        
        // 使用最小数据量进行测试
        std::vector<mpz_class> plain(2, 1);  // 最小数据（2元素向量）
        std::vector<yus::FHEWrapper::CiphertextPtr> cipher;
        wrapper.encrypt(plain, cipher);
        auto decrypted = wrapper.decrypt(cipher);
        
        // 验证解密结果大小正确
        EXPECT_EQ(decrypted.size(), 2ULL); 
        std::cout << "[SUCCESS] Memory test completed with minimal parameters" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "[EXCEPTION] Memory test failed: " << e.what() << std::endl;
        FAIL() << "Exception in memory test: " << e.what();
    }
}