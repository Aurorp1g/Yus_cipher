/**
 * @file test_linear_layer.cpp
 * @brief YuS流密码线性层组件测试
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 使用Google Test框架对YuS流密码的线性层组件进行单元测试。
 * 包含线性层应用和分支数计算功能测试。
 */

#include "yus/linear_layer.h"
#include "yus/utils.h"
#include <gtest/gtest.h>

/**
 * @test LinearLayerTest.Apply
 * @brief 测试线性层应用功能
 * 
 * 验证线性层对状态向量的变换是否正确，包括：
 * - 生成17位素数
 * - 创建线性层对象
 * - 创建36元素状态向量（全部初始化为1）
 * - 应用线性层变换
 * - 验证输出大小和非零性
 */
TEST(LinearLayerTest, Apply) {
    // 生成17位素数
    mpz_class p = yus::generate_prime(17);
    
    // 创建线性层对象
    yus::LinearLayer ll;
    
    // 创建36元素状态向量，全部初始化为1
    std::vector<mpz_class> state(36);
    for (size_t i = 0; i < 36; ++i) {
        state[i] = 1;  // 常量1不需要转换
    }
    
    // 应用线性层变换
    auto output = ll.apply(state, p);
    
    // 验证输出大小
    EXPECT_EQ(output.size(), 36ULL);
    
    // 验证线性层输出非空（确保变换有效）
    EXPECT_NE(output[0], 0);
}

/**
 * @test LinearLayerTest.BranchNumber
 * @brief 测试线性层分支数计算
 * 
 * 验证线性层的线性分支数和差分分支数是否符合预期值：
 * - 线性分支数：6
 * - 差分分支数：10
 */
TEST(LinearLayerTest, BranchNumber) {
    // 创建线性层对象
    yus::LinearLayer ll;
    
    // 验证线性分支数为6
    EXPECT_EQ(ll.linear_branch_number(), 6ULL);
    
    // 验证差分分支数为10
    EXPECT_EQ(ll.differential_branch_number(), 10ULL);
}