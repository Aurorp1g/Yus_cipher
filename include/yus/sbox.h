/**
 * @file sbox.h
 * @brief YuS流密码S盒组件头文件
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 定义YuS流密码的S盒组件接口，包括SBox类声明和批量S盒应用函数。
 * 提供S盒变换、置换性验证和差分均匀性计算功能。
 */

#ifndef YUS_SBOX_H
#define YUS_SBOX_H

#include <cstdint>
#include <vector>
#include <gmpxx.h>

namespace yus {

/**
 * @class SBox
 * @brief YuS流密码S盒组件类
 * 
 * 实现YuS流密码的S盒变换，定义在有限域F_p^3上。
 * S盒变换公式：S(x0,x1,x2) = (x0, x0x2 + x1, -x0x1 + x0x2 + x2)
 * 要求素数p满足p ≡ 2 mod 3且p > 2^16。
 */
class SBox {
public:
    /**
     * @brief 构造函数
     * @param p 素数模数，必须满足p ≡ 2 mod 3且p > 2^16
     */
    explicit SBox(const mpz_class& p);

    /**
     * @brief 应用S盒变换
     * @param input 输入向量，包含3个F_p元素
     * @return 变换后的输出向量，包含3个F_p元素
     * 
     * 对输入向量应用S盒变换，输出向量计算公式：
     * y0 = x0 mod p
     * y1 = (x0 * x2 + x1) mod p
     * y2 = (-x0 * x1 + x0 * x2 + x2) mod p
     */
    std::vector<mpz_class> apply(const std::vector<mpz_class>& input) const;

    /**
     * @brief 验证S盒是否为置换
     * @return 如果S盒是双射（置换）返回true，否则返回false
     * 
     * 验证S盒变换是否为F_p^3到F_p^3的双射映射。
     * 对于大素数使用行列式方法，对于小素数使用穷举法验证。
     */
    bool is_permutation() const;

    /**
     * @brief 获取差分均匀性
     * @return 差分均匀性值
     * 
     * 返回S盒的差分均匀性，这是衡量S盒抵抗差分攻击能力的重要指标。
     * 对于YuS流密码的S盒，其差分均匀性为p^2。
     */
    mpz_class differential_uniformity() const;

private:
    mpz_class p_; ///< 素数域参数，定义有限域F_p
};

/**
 * @brief 批量应用S盒层
 * @param state 36元素的状态向量
 * @param p 素数模数
 * @return 应用S盒层后的状态向量
 * 
 * YuS流密码中每轮包含12个S盒，将36元素状态向量分成12组，
 * 每组3个元素分别应用S盒变换，支持并行处理提高性能。
 */
std::vector<mpz_class> apply_sbox_layer(const std::vector<mpz_class>& state, const mpz_class& p);

} // namespace yus

#endif // YUS_SBOX_H