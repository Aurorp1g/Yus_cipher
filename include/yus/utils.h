/**
 * @file utils.h
 * @brief YuS流密码工具函数头文件
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 定义YuS流密码的通用工具函数接口。
 * 使用GMP库进行大数运算，提供密码学安全的功能实现。
 */

#ifndef YUS_UTILS_H
#define YUS_UTILS_H

#include <cstdint>
#include <vector>
#include <gmpxx.h>

namespace yus {

/**
 * @brief 验证素数是否满足 p ≡ 2 mod 3 条件
 * @param p 待验证的素数
 * @return 如果满足条件返回true，否则返回false
 * 
 * YuS流密码要求素数模数满足 p ≡ 2 mod 3 条件。
 */
bool is_p_2mod3(const mpz_class& p);

/**
 * @brief 生成满足条件的密码学安全素数
 * @param bits 素数位数，默认17位
 * @return 生成的素数
 * 
 * 生成满足 p ≡ 2 mod 3 条件且大于16位的密码学安全素数。
 * 使用OpenSSL提供密码学安全随机种子，GMP库生成大素数。
 */
mpz_class generate_prime(uint32_t bits = 17);

/**
 * @brief 将大整数转换为字节数组
 * @param num 待转换的大整数
 * @return 转换后的字节数组
 * 
 * 使用GMP库的mpz_export函数将mpz_class对象转换为字节数组。
 * 用于密钥和数据的序列化。
 */
std::vector<uint8_t> mpz_to_bytes(const mpz_class& num);

/**
 * @brief 将字节数组转换为大整数
 * @param bytes 待转换的字节数组
 * @return 转换后的大整数
 * 
 * 使用GMP库的mpz_import函数将字节数组转换为mpz_class对象。
 * 用于密钥和数据的反序列化。
 */
mpz_class bytes_to_mpz(const std::vector<uint8_t>& bytes);

/**
 * @brief 安全的模运算
 * @param a 被除数
 * @param p 模数（素数）
 * @return a mod p 的结果，保证非负
 * 
 * 执行安全的模运算，处理负数情况，确保结果在[0, p-1]范围内。
 */
mpz_class mod(const mpz_class& a, const mpz_class& p);

/**
 * @class Timer
 * @brief 性能计时器类
 * 
 * 提供高精度的性能计时功能，用于测量算法执行时间。
 * 使用C++高精度时钟。
 */
class Timer {
public:
    /**
     * @brief 构造函数
     * 
     * 初始化计时器，设置起始和结束时间戳为0。
     */
    Timer();

    /**
     * @brief 开始计时
     * 
     * 记录当前时间作为起始时间戳，使用高精度时钟。
     */
    void start();

    /**
     * @brief 停止计时
     * 
     * 记录当前时间作为结束时间戳，使用高精度时钟。
     */
    void stop();

    /**
     * @brief 获取经过的时间（毫秒）
     * @return 经过的时间（毫秒）
     * 
     * 计算从开始计时到停止计时的时间间隔，转换为毫秒单位。
     */
    double elapsed_ms() const;

private:
    uint64_t start_ticks_; ///< 起始时间戳（微秒）
    uint64_t stop_ticks_;  ///< 结束时间戳（微秒）
};

} // namespace yus

#endif // YUS_UTILS_H