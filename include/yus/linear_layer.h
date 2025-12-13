/**
 * @file linear_layer.h
 * @brief YuS流密码线性层组件头文件
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 定义YuS流密码的线性层组件接口，包括LinearLayer类声明和分支数计算功能。
 * 使用36x36二进制矩阵和四俄罗斯人算法优化，提供高效的线性变换。
 */

#ifndef YUS_LINEAR_LAYER_H
#define YUS_LINEAR_LAYER_H

#include <cstdint>
#include <vector>
#include <gmpxx.h>

namespace yus {

/**
 * @class LinearLayer
 * @brief YuS流密码线性层组件类
 * 
 * 实现YuS流密码的线性层变换，使用36x36二进制矩阵定义线性映射。
 * 采用四俄罗斯人算法优化矩阵乘法，支持并行处理。
 */
class LinearLayer {
public:
    /**
     * @brief 构造函数
     * 
     * 初始化36x36二进制矩阵，验证矩阵维度，并预计算四俄罗斯人算法表。
     */
    LinearLayer();

    /**
     * @brief 应用线性变换
     * @param state 36元素的状态向量
     * @param p 素数模数
     * @return 线性变换后的状态向量
     * 
     * 对输入状态向量应用36x36二进制矩阵的线性变换。
     * 使用四俄罗斯人算法优化计算，支持并行处理。
     */
    std::vector<mpz_class> apply(const std::vector<mpz_class>& state, const mpz_class& p) const;

    /**
     * @brief 获取线性分支数
     * @return 线性分支数
     * 
     * 线性分支数衡量线性层的扩散特性，值越大表示扩散性越好。
     * 对于YuS流密码，线性分支数为6。
     */
    uint32_t linear_branch_number() const;

    /**
     * @brief 获取差分分支数
     * @return 差分分支数
     * 
     * 差分分支数衡量线性层抵抗差分攻击的能力，值越大表示安全性越高。
     * 对于YuS流密码，差分分支数为10。
     */
    uint32_t differential_branch_number() const;

private:
    std::vector<std::vector<uint8_t>> matrix_; ///< 36x36二进制矩阵，定义线性变换

    /**
     * @brief 预计算四俄罗斯人算法表
     * 
     * 使用四俄罗斯人算法优化矩阵乘法，将36列分成9组，每组4列。
     */
    void precompute_four_russians();
    
    std::vector<std::vector<mpz_class>> four_russians_table_; ///< 四俄罗斯人算法预计算表
};

} // namespace yus

#endif // YUS_LINEAR_LAYER_H