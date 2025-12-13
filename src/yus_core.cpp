/**
 * @file yus_core.cpp
 * @brief YuS流密码核心算法实现
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 实现YuS流密码的核心算法。
 * 支持80位和128位安全级别，兼容HElib和SEAL同态加密库。
 */

#include "yus/yus_core.h"
#include "yus/utils.h"
#include "yus/sbox.h"
#include "yus/round_key.h"
#include <stdexcept>
#include <algorithm>

namespace yus {

/**
 * @brief YuSCipher构造函数
 * @param p 素数模数，必须满足 p ≡ 2 mod 3
 * @param level 安全级别（80位或128位）
 * @param trunc_m 截断参数，必须 ≤ 36
 * @throws std::invalid_argument 当参数不满足条件时抛出异常
 */
YuSCipher::YuSCipher(const mpz_class& p, SecurityLevel level, uint32_t trunc_m)
    : p_(p), level_(level), trunc_m_(trunc_m),
      sbox_(p), linear_layer_(),
      rk_gen_(std::vector<uint8_t>(), static_cast<uint32_t>(level)) {
    // 验证素数模数条件：p ≡ 2 mod 3
    if (!is_p_2mod3(p)) {
        throw std::invalid_argument("Prime p must satisfy p ≡ 2 mod 3");
    }
    // 验证截断参数范围
    if (trunc_m > 36) {
        throw std::invalid_argument("Truncation m must be ≤36");
    }
    // 验证素数大小
    if (p < (1 << 16)) {
        throw std::invalid_argument("Prime p must be > 16 bits");
    }
}

/**
 * @brief 初始化YuS密码实例
 * @param master_key 主密钥，36个F_p元素的向量
 * @param nonce 随机数向量
 * @throws std::invalid_argument 当主密钥大小不正确时抛出异常
 */
void YuSCipher::init(const std::vector<mpz_class>& master_key, const std::vector<uint8_t>& nonce) {
    if (master_key.size() != 36) {
        throw std::invalid_argument("Master key must be 36 elements (F_p^36)");
    }
    master_key_ = master_key;
    // 重新初始化轮密钥生成器
    rk_gen_ = RoundKeyGenerator(nonce, static_cast<uint32_t>(level_));
}

/**
 * @brief 执行单轮变换
 * @param state 当前状态向量
 * @param round_key 轮密钥
 * @return 变换后的状态向量
 */
std::vector<mpz_class> YuSCipher::round_transform(
    const std::vector<mpz_class>& state, 
    const std::vector<mpz_class>& round_key) {
    // RF = AK ∘ LP ∘ SL
    auto sbox_out = apply_sbox_layer(state, p_);
    auto linear_out = linear_layer_.apply(sbox_out, p_);
    auto ak_out = add_round_key(linear_out, round_key, p_);
    return ak_out;
}

/**
 * @brief 截断状态向量
 * @param state 36元素的状态向量
 * @return 截断后的状态向量
 * @throws std::invalid_argument 当输入状态大小不正确时抛出异常
 */
std::vector<mpz_class> YuSCipher::truncate(const std::vector<mpz_class>& state) const {
    if (state.size() != 36) {
        throw std::invalid_argument("Truncation input must be 36 elements");
    }
    std::vector<mpz_class> truncated(state.begin() + trunc_m_, state.end());
    return truncated;
}

/**
 * @brief 密钥白化操作
 * @param state 初始状态向量
 * @param block_index 块索引
 * @return 白化后的状态向量
 */
std::vector<mpz_class> YuSCipher::key_whitening(const std::vector<mpz_class>& state, uint32_t block_index) {
    auto rc0 = rk_gen_.generate_round_constant(0, block_index, p_);
    auto rk0 = rk_gen_.generate_round_key(master_key_, rc0, p_);
    return add_round_key(state, rk0, p_);
}

/**
 * @brief 生成密钥流
 * @param block_count 要生成的块数量
 * @return 生成的密钥流向量
 * @throws std::runtime_error 当密码实例未初始化时抛出异常
 * 
 * 生成指定数量的密钥流块。每个块的处理流程：
 * 1. 构建计数器向量CV_j = (1+j, 2+j, ..., 36+j)
 * 2. 密钥白化
 * 3. 多轮变换（根据安全级别）
 * 4. 最终线性层和截断操作
 */
std::vector<mpz_class> YuSCipher::generate_keystream(uint32_t block_count) {
    if (master_key_.empty()) {
        throw std::runtime_error("YuSCipher not initialized with master key");
    }

    std::vector<mpz_class> keystream;
    uint32_t rounds = static_cast<uint32_t>(level_);

    for (uint32_t j = 0; j < block_count; ++j) {
        // 正确构建CV: CV_j = (1+j, 2+j, ..., 36+j)
        std::vector<mpz_class> cv(36);
        for (int i = 0; i < 36; ++i) {
            cv[i] = mod(mpz_class(i + 1) + j, p_);
        }

        // 密钥白化
        auto state = key_whitening(cv, j);

        // 轮变换
        for (uint32_t r = 1; r <= rounds; ++r) {
            auto rc = rk_gen_.generate_round_constant(r, j, p_);
            auto rk = rk_gen_.generate_round_key(master_key_, rc, p_);
            state = round_transform(state, rk);
        }

        // 最终线性层+截断
        auto final_linear = linear_layer_.apply(state, p_);
        auto block = truncate(final_linear);
        keystream.insert(keystream.end(), block.begin(), block.end());
    }

    return keystream;
}

} // namespace yus