/**
 * @file utils.cpp
 * @brief YuS流密码工具函数实现
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 实现YuS流密码的通用工具函数，包括素数生成、数据转换、模运算和性能计时器。
 * 使用GMP库进行大数运算，OpenSSL提供密码学安全随机数。
 */

#include "yus/utils.h"
#include <stdexcept>
#include <chrono>
#include <gmpxx.h>
#include <openssl/rand.h>

namespace yus {

/**
 * @brief 验证素数是否满足 p ≡ 2 mod 3 条件
 * @param p 待验证的素数
 * @return 如果满足条件返回true，否则返回false
 * 
 * YuS流密码要求素数模数满足 p ≡ 2 mod 3 条件，这是S盒正确工作的必要条件。
 */
bool is_p_2mod3(const mpz_class& p) {
    return (p % 3) == 2;
}

/**
 * @brief 生成满足条件的密码学安全素数
 * @param bits 素数位数
 * @return 生成的素数
 * @throws std::runtime_error 当随机数生成失败时抛出异常
 * 
 * 生成满足 p ≡ 2 mod 3 条件且大于16位的密码学安全素数。
 * 使用OpenSSL提供密码学安全随机种子，GMP库生成大素数。
 */
mpz_class generate_prime(uint32_t bits) {
    mpz_class p;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    // 密码学安全随机种子
    unsigned long seed;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&seed), sizeof(seed)) != 1) {
        gmp_randclear(state);
        throw std::runtime_error("Failed to generate secure random seed");
    }
    gmp_randseed_ui(state, seed);
    
    // 生成满足条件的素数
    do {
        mpz_urandomb(p.get_mpz_t(), state, bits);
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
    } while (!is_p_2mod3(p) || p < (1 << 16));
    
    gmp_randclear(state);
    return p;
}

/**
 * @brief 将大整数转换为字节数组
 * @param num 待转换的大整数
 * @return 转换后的字节数组
 * 
 * 使用GMP库的mpz_export函数将mpz_class对象转换为字节数组。
 * 用于密钥和数据的序列化。
 */
std::vector<uint8_t> mpz_to_bytes(const mpz_class& num) {
    size_t len = mpz_sizeinbase(num.get_mpz_t(), 2) / 8 + 1;
    std::vector<uint8_t> bytes(len);
    mpz_export(bytes.data(), nullptr, 1, 1, 0, 0, num.get_mpz_t());
    return bytes;
}

/**
 * @brief 将字节数组转换为大整数
 * @param bytes 待转换的字节数组
 * @return 转换后的大整数
 * 
 * 使用GMP库的mpz_import函数将字节数组转换为mpz_class对象。
 * 用于密钥和数据的反序列化。
 */
mpz_class bytes_to_mpz(const std::vector<uint8_t>& bytes) {
    mpz_class num;
    mpz_import(num.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
    return num;
}

/**
 * @brief 安全的模运算
 * @param a 被除数
 * @param p 模数（素数）
 * @return a mod p 的结果，保证非负
 * 
 * 执行安全的模运算，处理负数情况，确保结果在[0, p-1]范围内。
 */
mpz_class mod(const mpz_class& a, const mpz_class& p) {
    mpz_class res = a % p;
    if (res < 0) {
        res += p;  // 处理负数情况
    }
    return res;
}

/**
 * @brief Timer构造函数
 * 
 * 初始化计时器，设置起始和结束时间戳为0。
 */
Timer::Timer() : start_ticks_(0), stop_ticks_(0) {}

/**
 * @brief 开始计时
 * 
 * 记录当前时间作为起始时间戳，使用高精度时钟。
 */
void Timer::start() {
    start_ticks_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

/**
 * @brief 停止计时
 * 
 * 记录当前时间作为结束时间戳，使用高精度时钟。
 */
void Timer::stop() {
    stop_ticks_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

/**
 * @brief 获取经过的时间（毫秒）
 * @return 经过的时间（毫秒）
 * 
 * 计算从开始计时到停止计时的时间间隔，转换为毫秒单位。
 */
double Timer::elapsed_ms() const {
    return static_cast<double>(stop_ticks_ - start_ticks_) / 1000.0;
}

} // namespace yus