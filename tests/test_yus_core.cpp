/**
 * @file test_yus_core.cpp
 * @brief YuS流密码核心算法测试
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 使用Google Test框架对YuS流密码核心算法进行单元测试。
 * 包含YuSCipher类的初始化和密钥流生成功能测试。
 */

#include "yus/yus_core.h"
#include "yus/utils.h"
#include <gtest/gtest.h>

/**
 * @test YuSCipherTest.Init
 * @brief 测试YuS密码初始化功能
 * 
 * 验证YuSCipher类的初始化过程是否正常，包括：
 * - 素数生成
 * - 密码对象构造
 * - 主密钥和随机数设置
 * - 初始化过程无异常抛出
 */
TEST(YuSCipherTest, Init) {
    // 生成17位满足条件的素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建YuS密码对象（80位安全级别，截断12位）
    yus::YuSCipher yus(p, yus::SecurityLevel::SEC80, 12);
    
    // 创建36元素的主密钥（全部初始化为1）
    std::vector<mpz_class> master_key(36, 1);
    
    // 创建4字节随机数
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    
    // 验证初始化过程无异常抛出
    EXPECT_NO_THROW(yus.init(master_key, nonce));
}

/**
 * @test YuSCipherTest.GenerateKeystream
 * @brief 测试密钥流生成功能
 * 
 * 验证YuSCipher类的密钥流生成功能是否正常，包括：
 * - 密码初始化
 * - 生成1个密钥流块
 * - 验证密钥流大小（24个元素，截断后输出）
 */
TEST(YuSCipherTest, GenerateKeystream) {
    // 生成17位满足条件的素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建YuS密码对象（80位安全级别，截断12位）
    yus::YuSCipher yus(p, yus::SecurityLevel::SEC80, 12);
    
    // 创建36元素的主密钥（全部初始化为1）
    std::vector<mpz_class> master_key(36, 1);
    
    // 创建4字节随机数
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    
    // 初始化密码
    yus.init(master_key, nonce);
    
    // 生成1个密钥流块
    auto keystream = yus.generate_keystream(1);
    
    // 验证密钥流大小：截断后输出24位
    EXPECT_EQ(keystream.size(), 24ULL); 
}