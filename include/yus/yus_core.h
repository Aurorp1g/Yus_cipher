/**
 * @file yus_core.h
 * @brief YuS流密码核心算法头文件
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 定义YuS流密码的核心算法接口，包括安全级别枚举、YuSCipher类声明和主要算法组件。
 * 支持80位和128位安全级别，提供密钥流生成和同态加密兼容性。
 */

#ifndef YUS_YUS_CORE_H
#define YUS_YUS_CORE_H

#include <cstdint>
#include <vector>
#include <gmpxx.h>
#include "sbox.h"
#include "linear_layer.h"
#include "round_key.h"

namespace yus {

/**
 * @enum SecurityLevel
 * @brief YuS流密码安全级别枚举
 * 
 * 定义YuS流密码支持的安全级别，对应不同的轮数配置：
 * - SEC80: 5轮变换，提供80位安全级别
 * - SEC128: 6轮变换，提供128位安全级别
 */
enum class SecurityLevel {
    SEC80 = 5,  ///< 5轮变换，80位安全级别
    SEC128 = 6  ///< 6轮变换，128位安全级别
};

/**
 * @class YuSCipher
 * @brief YuS流密码核心算法类
 * 
 * 实现YuS流密码的核心算法。
 * 支持80位和128位安全级别，兼容HElib和SEAL同态加密库。
 */
class YuSCipher {
public:
    /**
     * @brief 构造函数
     * @param p 素数模数，必须满足 p > 2^16 且 p ≡ 2 mod 3
     * @param level 安全级别（SEC80或SEC128）
     * @param trunc_m 截断位数，默认12，推荐24位
     */
    YuSCipher(const mpz_class& p, SecurityLevel level, uint32_t trunc_m = 12);

    /**
     * @brief 密钥初始化
     * @param master_key 主密钥向量，包含36个F_p元素
     * @param nonce 随机数向量
     * 
     * 初始化YuS密码实例的主密钥和随机数，重新配置轮密钥生成器。
     */
    void init(const std::vector<mpz_class>& master_key, const std::vector<uint8_t>& nonce);

    /**
     * @brief 生成密钥流
     * @param block_count 要生成的密钥流块数量
     * @return 生成的密钥流向量，包含(36-trunc_m)个F_p元素
     * 
     * 生成指定数量的密钥流块，每个块经过多轮变换和截断操作。
     * 推荐截断位数为24位，输出12个F_p元素。
     */
    std::vector<mpz_class> generate_keystream(uint32_t block_count);

private:
    mpz_class p_;                  ///< 素数域参数，定义有限域F_p
    SecurityLevel level_;          ///< 安全级别，决定轮数（5或6轮）
    uint32_t trunc_m_;             ///< 截断位数，决定输出密钥流长度
    std::vector<mpz_class> master_key_; ///< 主密钥，36个F_p元素的向量
    SBox sbox_;                    ///< S盒组件实例
    LinearLayer linear_layer_;     ///< 线性层组件实例
    RoundKeyGenerator rk_gen_;     ///< 轮密钥生成器实例

    /**
     * @brief 单轮变换函数
     * @param state 当前状态向量
     * @param round_key 轮密钥向量
     * @return 变换后的状态向量
     * 
     * 执行单轮变换：RF = AK ∘ LP ∘ SL
     * 依次应用S盒层(SL)、线性层(LP)和轮密钥加(AK)操作。
     */
    std::vector<mpz_class> round_transform(
        const std::vector<mpz_class>& state, 
        const std::vector<mpz_class>& round_key);

    /**
     * @brief 截断函数
     * @param state 36元素的状态向量
     * @return 截断后的状态向量
     * 
     * 执行截断操作：TF_m(v0..35) = (vm..35)
     * 从第m个元素开始截断，保留剩余元素。
     */
    std::vector<mpz_class> truncate(const std::vector<mpz_class>& state) const;

    /**
     * @brief 密钥白化操作
     * @param state 初始状态向量
     * @param block_index 块索引
     * @return 白化后的状态向量
     * 
     * 使用第0轮的轮常数和轮密钥对初始状态进行白化处理。
     */
    std::vector<mpz_class> key_whitening(const std::vector<mpz_class>& state, uint32_t block_index);
};

} // namespace yus

#endif // YUS_YUS_CORE_H