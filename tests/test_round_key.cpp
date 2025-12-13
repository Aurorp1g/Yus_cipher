/**
 * @file test_round_key.cpp
 * @brief YuS流密码轮密钥生成组件测试
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 使用Google Test框架对YuS流密码的轮密钥生成组件进行单元测试。
 * 包含轮常量生成、轮密钥生成和轮密钥加法操作功能测试。
 */

#include "yus/round_key.h"
#include "yus/utils.h"
#include <gtest/gtest.h>

/**
 * @test RoundKeyTest.GenerateRoundConstant
 * @brief 测试轮常量生成功能
 * 
 * 验证轮常量生成器是否正确生成轮常量，包括：
 * - 生成17位素数
 * - 创建轮密钥生成器（4字节随机数，5轮）
 * - 生成第0轮第0步的轮常量
 * - 验证轮常量大小和非零性
 */
TEST(RoundKeyTest, GenerateRoundConstant) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建4字节随机数
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    
    // 创建轮密钥生成器（5轮）
    yus::RoundKeyGenerator rk_gen(nonce, 5);
    
    // 生成第0轮第0步的轮常量
    auto rc = rk_gen.generate_round_constant(0, 0, p);
    
    // 验证轮常量大小为36个元素
    EXPECT_EQ(rc.size(), 36ULL);
    
    // 验证轮常量所有元素非零（rc ∈ F_p^*）
    for (const auto& elem : rc) {
        EXPECT_NE(elem, 0);
    }
}

/**
 * @test RoundKeyTest.GenerateRoundKey
 * @brief 测试轮密钥生成功能
 * 
 * 验证轮密钥生成器是否正确生成轮密钥，包括：
 * - 生成轮常量
 * - 生成轮密钥（rc * master_key mod p）
 * - 验证轮密钥大小和计算正确性
 */
TEST(RoundKeyTest, GenerateRoundKey) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建4字节随机数
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    
    // 创建轮密钥生成器（5轮）
    yus::RoundKeyGenerator rk_gen(nonce, 5);
    
    // 创建36元素主密钥（全部初始化为1）
    std::vector<mpz_class> master_key(36, 1);
    
    // 生成轮常量
    auto rc = rk_gen.generate_round_constant(0, 0, p);
    
    // 生成轮密钥
    auto rk = rk_gen.generate_round_key(master_key, rc, p);
    
    // 验证轮密钥大小为36个元素
    EXPECT_EQ(rk.size(), 36ULL);
    
    // 验证轮密钥计算正确：rk = rc * master_key mod p
    for (size_t i = 0; i < 36; ++i) {
        EXPECT_EQ(rk[i], yus::mod(rc[i] * 1, p)); 
    }
}

/**
 * @test RoundKeyTest.AddRoundKey
 * @brief 测试轮密钥加法操作
 * 
 * 验证轮密钥加法操作是否正确执行，包括：
 * - 创建状态向量和轮密钥向量
 * - 执行轮密钥加法操作
 * - 验证输出大小和计算结果
 */
TEST(RoundKeyTest, AddRoundKey) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建36元素状态向量（全部初始化为1）
    std::vector<mpz_class> state(36, 1);
    
    // 创建36元素轮密钥向量（全部初始化为2）
    std::vector<mpz_class> rk(36, 2);
    
    // 执行轮密钥加法操作：state + rk mod p
    auto output = yus::add_round_key(state, rk, p);
    
    // 验证输出大小为36个元素
    EXPECT_EQ(output.size(), 36ULL);
    
    // 验证计算结果：1 + 2 = 3 mod p
    for (const auto& elem : output) {
        EXPECT_EQ(elem, yus::mod(3, p));
    }
}