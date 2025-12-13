/**
 * @file round_key.cpp
 * @brief YuS流密码轮密钥生成实现
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 实现YuS流密码的轮密钥生成组件，包括轮常数生成、轮密钥计算和轮密钥加操作。
 * 使用SHAKE128 XOF函数生成伪随机数，确保密钥的安全性。
 */

#include "yus/round_key.h"
#include "yus/utils.h"
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>

namespace yus {

/**
 * @brief RoundKeyGenerator构造函数
 * @param nonce 随机数向量
 * @param rounds 轮数
 * 
 * 初始化轮密钥生成器，设置随机数和轮数参数。
 */
RoundKeyGenerator::RoundKeyGenerator(const std::vector<uint8_t>& nonce, uint32_t rounds)
    : nonce_(nonce), rounds_(rounds) {}

/**
 * @brief SHAKE128 XOF函数实现
 * @param input 输入数据
 * @param output_len 输出数据长度
 * @param output 输出数据向量
 * @throws std::runtime_error 当OpenSSL操作失败时抛出异常
 * 
 * 使用OpenSSL的SHAKE128 XOF函数生成指定长度的伪随机输出。
 * SHAKE128是SHA-3家族的可扩展输出函数，适用于密钥派生。
 */
void RoundKeyGenerator::shake128_xof(const std::vector<uint8_t>& input, 
                                     uint32_t output_len, 
                                     std::vector<uint8_t>& output) const {
    output.resize(output_len);
    
    // 创建EVP上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP context");
    
    // 获取SHAKE128算法
    EVP_MD* shake128 = EVP_MD_fetch(nullptr, "SHAKE128", nullptr);
    if (!shake128) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHAKE128 not supported");
    }
    
    // 执行SHAKE128 XOF操作
    if (EVP_DigestInit_ex(ctx, shake128, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinalXOF(ctx, output.data(), output_len) != 1) {
        EVP_MD_free(shake128);
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHAKE128 operation failed");
    }
    
    // 清理资源
    EVP_MD_free(shake128);
    EVP_MD_CTX_free(ctx);
}

/**
 * @brief 生成轮常数
 * @param i 轮索引
 * @param j 块索引
 * @param p 素数模数
 * @return 36个F_p元素的轮常数向量
 * 
 * 使用SHAKE128 XOF函数基于随机数、轮索引和块索引生成轮常数。
 * 确保每个轮常数都是非零的F_p元素。
 */
std::vector<mpz_class> RoundKeyGenerator::generate_round_constant(uint32_t i, uint32_t j, const mpz_class& p) const {
    std::vector<uint8_t> input;
    // 构建输入数据：随机数 + 块索引 + 轮索引
    input.insert(input.end(), nonce_.begin(), nonce_.end());
    
    // 将索引转换为字节数组
    uint8_t j_bytes[4];
    uint8_t i_bytes[4];
    for(int k = 0; k < 4; ++k) {
        j_bytes[k] = (j >> (k * 8)) & 0xFF;
        i_bytes[k] = (i >> (k * 8)) & 0xFF;
    }
    
    input.insert(input.end(), j_bytes, j_bytes + 4);
    input.insert(input.end(), i_bytes, i_bytes + 4);

    // 使用SHAKE128生成288字节的随机数据（36个元素 × 8字节）
    std::vector<uint8_t> rc_bytes(36 * 8);
    shake128_xof(input, rc_bytes.size(), rc_bytes);

    // 将字节数据转换为F_p元素
    std::vector<mpz_class> rc(36);
    for (int k = 0; k < 36; ++k) {
        std::vector<uint8_t> elem_bytes(rc_bytes.begin() + k*8, rc_bytes.begin() + (k+1)*8);
        rc[k] = mod(bytes_to_mpz(elem_bytes), p);
        // 确保轮常数非零
        if (rc[k] == 0) {
            rc[k] = 1;
        }
    }
    return rc;
}

/**
 * @brief 生成轮密钥
 * @param master_key 主密钥向量
 * @param round_constant 轮常数向量
 * @param p 素数模数
 * @return 36个F_p元素的轮密钥向量
 * @throws std::invalid_argument 当输入向量大小不正确时抛出异常
 * 
 * 通过主密钥和轮常数的逐元素乘法生成轮密钥。
 * 每个轮密钥元素 = 主密钥元素 × 轮常数元素 mod p。
 */
std::vector<mpz_class> RoundKeyGenerator::generate_round_key(
    const std::vector<mpz_class>& master_key, 
    const std::vector<mpz_class>& round_constant, 
    const mpz_class& p) const {
    if (master_key.size() != 36 || round_constant.size() != 36) {
        throw std::invalid_argument("Master key/round constant must be 36 elements");
    }
    std::vector<mpz_class> rk(36);
    for (int k = 0; k < 36; ++k) {
        rk[k] = mod(master_key[k] * round_constant[k], p);
    }
    return rk;
}

/**
 * @brief 轮密钥加操作
 * @param state 当前状态向量
 * @param round_key 轮密钥向量
 * @param p 素数模数
 * @return 轮密钥加后的状态向量
 * @throws std::invalid_argument 当输入向量大小不正确时抛出异常
 * 
 * 执行轮密钥加操作：状态向量与轮密钥向量逐元素相加。
 * 每个输出元素 = 状态元素 + 轮密钥元素 mod p。
 */
std::vector<mpz_class> add_round_key(
    const std::vector<mpz_class>& state, 
    const std::vector<mpz_class>& round_key, 
    const mpz_class& p) {
    if (state.size() != 36 || round_key.size() != 36) {
        throw std::invalid_argument("State/round key must be 36 elements");
    }
    std::vector<mpz_class> output(36);
    for (int k = 0; k < 36; ++k) {
        output[k] = mod(state[k] + round_key[k], p);
    }
    return output;
}

} // namespace yus