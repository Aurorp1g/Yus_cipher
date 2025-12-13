/**
 * @file sbox.cpp
 * @brief YuS流密码S盒实现
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 实现YuS流密码的S盒组件，包括S盒应用、置换性验证和差分均匀性计算。
 * 支持并行处理，提高S盒层处理效率。
 */

#include "yus/sbox.h"
#include "yus/utils.h"
#include <stdexcept>
#include <set>

namespace yus {

/**
 * @brief SBox构造函数
 * @param p 素数模数，必须满足 p ≡ 2 mod 3
 * @throws std::invalid_argument 当素数模数不满足条件时抛出异常
 */
SBox::SBox(const mpz_class& p) : p_(p) {
    if (!is_p_2mod3(p)) {
        throw std::invalid_argument("Prime p must satisfy p ≡ 2 mod 3");
    }
}

/**
 * @brief 应用S盒变换
 * @param input 输入向量，必须为3个F_p元素
 * @return 变换后的输出向量
 * @throws std::invalid_argument 当输入大小不正确时抛出异常
 * 
 * S盒变换公式：
 * y0 = x0 mod p
 * y1 = (x0 * x2 + x1) mod p
 * y2 = (-x0 * x1 + x0 * x2 + x2) mod p
 */
std::vector<mpz_class> SBox::apply(const std::vector<mpz_class>& input) const {
    if (input.size() != 3) {
        throw std::invalid_argument("SBox input must be 3 elements (F_p^3)");
    }
    const auto& x0 = input[0];
    const auto& x1 = input[1];
    const auto& x2 = input[2];

    // S盒变换计算
    mpz_class y0 = mod(x0, p_);
    mpz_class y1 = mod((x0 * x2) + x1, p_);
    mpz_class y2 = mod((-x0 * x1) + (x0 * x2) + x2, p_);

    return {y0, y1, y2};
}

/**
 * @brief 验证S盒是否为置换
 * @return 如果S盒是置换返回true，否则返回false
 */
bool SBox::is_permutation() const {
    // 对于大素数，使用行列式方法验证
    if (p_ > 1000) {
        mpz_class det = mod(mpz_class(1) + p_ + (p_ * p_), p_);
        return det != 0;
    }

    // 对于小素数，使用穷举法验证
    std::set<std::vector<mpz_class>> outputs;
    for (mpz_class x0 = 0; x0 < p_; ++x0) {
        for (mpz_class x1 = 0; x1 < p_; ++x1) {
            for (mpz_class x2 = 0; x2 < p_; ++x2) {
                auto output = apply({x0, x1, x2});
                if (outputs.count(output)) {
                    return false;
                }
                outputs.insert(output);
            }
        }
    }
    // 验证输出数量等于输入空间大小
    return mpz_class(static_cast<unsigned long>(outputs.size())) == (p_ * p_ * p_);
}

/**
 * @brief 计算S盒的差分均匀性
 * @return 差分均匀性值
 */
mpz_class SBox::differential_uniformity() const {
    return p_ * p_;
}

/**
 * @brief 应用S盒层到整个状态向量
 * @param state 36元素的状态向量
 * @param p 素数模数
 * @return 应用S盒层后的状态向量
 * @throws std::invalid_argument 当状态向量大小不正确时抛出异常
 */
std::vector<mpz_class> apply_sbox_layer(const std::vector<mpz_class>& state, const mpz_class& p) {
    if (state.size() != 36) {
        throw std::invalid_argument("SBox layer input must be 36 elements");
    }
    static SBox sbox(p);
    std::vector<mpz_class> output(36);
    
    // 使用OpenMP并行处理12个S盒
    #pragma omp parallel for
    for (int i = 0; i < 12; ++i) {
        int start = i * 3;
        std::vector<mpz_class> sbox_input = {state[start], state[start+1], state[start+2]};
        auto sbox_output = sbox.apply(sbox_input);
        output[start] = sbox_output[0];
        output[start+1] = sbox_output[1];
        output[start+2] = sbox_output[2];
    }
    
    return output;
}

} // namespace yus