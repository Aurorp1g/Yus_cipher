/**
 * @file round_key.h
 * @brief YuS流密码轮密钥生成头文件
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 定义YuS流密码的轮密钥生成组件接口。
 * 使用SHAKE128 XOF函数生成伪随机轮常数。
 */

#ifndef YUS_ROUND_KEY_H
#define YUS_ROUND_KEY_H

#include <cstdint>
#include <vector>
#include <gmpxx.h>
#include <openssl/evp.h>

namespace yus {

/**
 * @class RoundKeyGenerator
 * @brief YuS流密码轮密钥生成器类
 * 
 * 实现YuS流密码的轮密钥生成功能，基于SHAKE128 XOF函数生成伪随机轮常数。
 * 支持80位（5轮）和128位（6轮）安全级别的轮密钥生成。
 */
class RoundKeyGenerator {
public:
    /**
     * @brief 构造函数
     * @param nonce 随机数向量
     * @param rounds 轮数（80位安全=5轮，128位安全=6轮）
     * 
     * 初始化轮密钥生成器，设置随机数和轮数参数。
     */
    RoundKeyGenerator(const std::vector<uint8_t>& nonce, uint32_t rounds);

    /**
     * @brief 生成轮常数
     * @param i 轮索引
     * @param j 块索引
     * @param p 素数模数
     * @return 36个F_p元素的轮常数向量
     * 
     * 使用SHAKE128 XOF函数基于随机数、轮索引和块索引生成轮常数。
     * 轮常数计算公式：rc^i = XOF(nonce || j || i)
     */
    std::vector<mpz_class> generate_round_constant(uint32_t i, uint32_t j, const mpz_class& p) const;

    /**
     * @brief 生成轮密钥
     * @param master_key 主密钥向量
     * @param round_constant 轮常数向量
     * @param p 素数模数
     * @return 36个F_p元素的轮密钥向量
     * 
     * 通过主密钥和轮常数的逐元素乘法生成轮密钥。
     * 轮密钥计算公式：rk^i = (rc0^i * k0, ..., rc35^i * k35) mod p
     */
    std::vector<mpz_class> generate_round_key(
        const std::vector<mpz_class>& master_key, 
        const std::vector<mpz_class>& round_constant, 
        const mpz_class& p) const;

private:
    std::vector<uint8_t> nonce_; ///< 随机数向量，用于轮常数生成
    uint32_t rounds_;           ///< 轮数，决定密钥生成次数

    /**
     * @brief SHAKE128 XOF函数实现
     * @param input 输入数据
     * @param output_len 输出数据长度
     * @param output 输出数据向量
     * 
     * 使用OpenSSL的SHAKE128 XOF函数生成指定长度的伪随机输出。
     * SHAKE128是SHA-3家族的可扩展输出函数，适用于密钥派生。
     */
    void shake128_xof(const std::vector<uint8_t>& input, uint32_t output_len, std::vector<uint8_t>& output) const;
};

/**
 * @brief 轮密钥加操作
 * @param state 当前状态向量
 * @param round_key 轮密钥向量
 * @param p 素数模数
 * @return 轮密钥加后的状态向量
 * 
 * 执行轮密钥加操作：状态向量与轮密钥向量逐元素相加。
 * 轮密钥加公式：AK_rk(v) = (v0 + rk0, ..., v35 + rk35) mod p
 */
std::vector<mpz_class> add_round_key(
    const std::vector<mpz_class>& state, 
    const std::vector<mpz_class>& round_key, 
    const mpz_class& p);

} // namespace yus

#endif // YUS_ROUND_KEY_H