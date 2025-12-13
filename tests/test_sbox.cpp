/**
 * @file test_sbox.cpp
 * @brief YuS流密码S盒组件测试
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 使用Google Test框架对YuS流密码的S盒组件进行单元测试。
 */

#include "yus/sbox.h"
#include "yus/utils.h"
#include <gtest/gtest.h>

/**
 * @test SBoxTest.Apply
 * @brief 测试S盒应用功能
 * 
 * 验证S盒对输入向量的变换是否正确，包括：
 * - 生成17位素数
 * - 创建S盒对象
 * - 应用S盒变换到输入向量[1,2,3]
 * - 验证变换结果符合预期公式
 */
TEST(SBoxTest, Apply) {
    // 生成17位素数（如65537）
    mpz_class p = yus::generate_prime(17);
    
    // 创建S盒对象
    yus::SBox sbox(p);
    
    // 创建输入向量[1,2,3]
    std::vector<mpz_class> input = {1, 2, 3};
    
    // 应用S盒变换
    auto output = sbox.apply(input);

    // 验证S(1,2,3) = (1, 1*3+2=5, -1*2 +1*3 +3=4)
    EXPECT_EQ(output[0], 1);
    EXPECT_EQ(output[1], yus::mod(5, p));
    EXPECT_EQ(output[2], yus::mod(4, p));
}

/**
 * @test SBoxTest.IsPermutation
 * @brief 测试S盒置换特性
 * 
 * 验证S盒是否具有置换特性，即是否为双射函数。
 */
TEST(SBoxTest, IsPermutation) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建S盒对象
    yus::SBox sbox(p);
    
    // 验证S盒具有置换特性
    EXPECT_TRUE(sbox.is_permutation());
}

/**
 * @test SBoxTest.DifferentialUniformity
 * @brief 测试S盒差分均匀性
 * 
 * 验证S盒的差分均匀性指标。
 */
TEST(SBoxTest, DifferentialUniformity) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建S盒对象
    yus::SBox sbox(p);
    
    // 验证差分均匀性为p²（最大可能值）
    EXPECT_EQ(sbox.differential_uniformity(), p*p);
}

/**
 * @test SBoxTest.SBoxLayer
 * @brief 测试S盒层应用功能
 * 
 * 验证对整个36元素状态向量的S盒层变换是否正确，包括：
 * - 生成36元素状态向量
 * - 应用S盒层变换
 * - 验证输出大小和第一个S盒的变换结果
 */
TEST(SBoxTest, SBoxLayer) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建36元素状态向量，初始化为1-36
    std::vector<mpz_class> state(36);
    for (size_t i = 0; i < 36; ++i) {
        state[i] = static_cast<int>(i + 1); 
    }
    
    // 应用S盒层变换
    auto output = yus::apply_sbox_layer(state, p);
    
    // 验证输出大小
    EXPECT_EQ(output.size(), 36ULL);
    
    // 验证第一个S盒的输出结果
    EXPECT_EQ(output[0], 1);
    EXPECT_EQ(output[1], yus::mod(1*3 + 2, p));
    EXPECT_EQ(output[2], yus::mod(-1*2 +1*3 +3, p));
}