/**
 * @file fhe_wrapper.h
 * @brief YuS流密码FHE封装接口头文件
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 定义YuS流密码的同态加密封装接口，支持HElib(BGV方案)和SEAL(BFV方案)两种同态加密库。
 * 提供统一的接口进行密钥生成、加密、解密、同态评估和性能测量。
 */

#ifndef YUS_FHE_WRAPPER_H
#define YUS_FHE_WRAPPER_H

#include <cstdint>
#include <vector>
#include <gmpxx.h>
#include <memory>
#include <helib/helib.h>
#include <seal/seal.h>

namespace yus {

/**
 * @enum FHE_SCHEME
 * @brief 同态加密方案枚举
 * 
 * 定义支持的同态加密方案：
 * - BGV: 使用HElib实现的BGV方案
 * - BFV: 使用SEAL实现的BFV方案
 */
enum class FHE_SCHEME { BGV, BFV };

/**
 * @struct FHEParams
 * @brief FHE参数配置结构体
 * 
 * 定义同态加密的参数配置，包括安全级别、多项式模数次数等。
 */
struct FHEParams {
    uint32_t security_level;        ///< 安全级别（80或128位）
    uint32_t poly_modulus_degree;   ///< 多项式模数次数
    mpz_class plain_modulus;        ///< 明文模数，必须满足p ≡ 2 mod 3
    uint32_t cipher_modulus_bits;   ///< 密文模数位数
};

/**
 * @class FHEWrapper
 * @brief YuS流密码FHE封装类
 * 
 * 实现YuS流密码的同态加密封装接口，支持HElib和SEAL两种同态加密库。
 * 提供统一的接口进行密钥管理、加密解密和同态评估操作。
 */
class FHEWrapper {
public:
    /**
     * @brief 构造函数
     * @param scheme 同态加密方案（BGV或BFV）
     * @param params FHE参数配置
     */
    FHEWrapper(FHE_SCHEME scheme, const FHEParams& params);
    
    /**
     * @brief 析构函数
     */
    ~FHEWrapper();

    /**
     * @brief 生成密钥对
     * 
     * 生成同态加密的密钥对，包括公钥和私钥。
     * 支持BGV和BFV两种方案的密钥生成。
     */
    void generate_keys();

    /**
     * @brief 打包明文数据
     * @param data 原始明文数据向量
     * @return 打包后的明文数据向量
     * 
     * 对于BGV方案，将多个明文元素打包到单个密文槽中。
     * 对于BFV方案，直接返回原始数据（支持批处理）。
     */
    std::vector<mpz_class> pack_plaintext(const std::vector<mpz_class>& data) const;

    /**
     * @brief 密文指针类型定义
     * 
     * 使用void指针封装不同加密库的密文类型，提供统一的接口。
     */
    using CiphertextPtr = std::shared_ptr<void>;

    /**
     * @brief 加密明文数据
     * @param plain 明文数据向量
     * @param cipher 输出密文向量
     * 
     * 使用配置的同态加密方案对明文数据进行加密。
     * BGV方案逐个元素加密，BFV方案支持批处理加密。
     */
    void encrypt(const std::vector<mpz_class>& plain, std::vector<CiphertextPtr>& cipher);

    /**
     * @brief 解密密文数据
     * @param cipher 密文向量
     * @return 解密后的明文数据向量
     * 
     * 使用对应的私钥对密文数据进行解密。
     * BGV方案逐个元素解密，BFV方案支持批处理解密。
     */
    std::vector<mpz_class> decrypt(const std::vector<CiphertextPtr>& cipher) const;

    /**
     * @brief 同态评估YuS流密码
     * @param cipher_key 加密的密钥向量
     * @param cipher_keystream 加密的密钥流向量
     * @return 评估时间（毫秒）
     * 
     * 在密文状态下执行YuS流密码的同态评估，支持并行处理。
     * 测量评估性能并返回执行时间。
     */
    double evaluate_yus(const std::vector<CiphertextPtr>& cipher_key, 
                        const std::vector<CiphertextPtr>& cipher_keystream);

    /**
     * @brief 计算吞吐量
     * @param data_size 数据大小（字节）
     * @param eval_time 评估时间（毫秒）
     * @return 吞吐量（KB/s）
     * 
     * 根据数据大小和评估时间计算同态加密的吞吐量性能指标。
     */
    double get_throughput(uint32_t data_size, double eval_time) const;

private:
    FHE_SCHEME scheme_; ///< 同态加密方案（BGV或BFV）
    FHEParams params_;  ///< FHE参数配置

    // HElib对象管理（使用shared_ptr）
    std::shared_ptr<helib::Context> helib_context_; ///< HElib加密上下文
    std::shared_ptr<helib::SecKey> helib_seckey_;   ///< HElib私钥
    std::shared_ptr<helib::PubKey> helib_pubkey_;   ///< HElib公钥

    // SEAL对象管理（使用unique_ptr）
    std::unique_ptr<seal::SEALContext> seal_context_;      ///< SEAL加密上下文
    std::unique_ptr<seal::SecretKey> seal_seckey_;         ///< SEAL私钥
    std::unique_ptr<seal::PublicKey> seal_pubkey_;         ///< SEAL公钥
    std::unique_ptr<seal::RelinKeys> seal_relin_keys_;     ///< SEAL重线性化密钥
    std::unique_ptr<seal::Encryptor> seal_encryptor_;      ///< SEAL加密器
    std::unique_ptr<seal::Decryptor> seal_decryptor_;      ///< SEAL解密器
    std::unique_ptr<seal::Evaluator> seal_evaluator_;      ///< SEAL评估器
    std::unique_ptr<seal::BatchEncoder> seal_batch_encoder_; ///< SEAL批处理编码器

    /**
     * @brief 初始化HElib(BGV方案)
     * 
     * 配置HElib的BGV方案参数，生成密钥对并初始化加密上下文。
     */
    void init_helib();

    /**
     * @brief 初始化SEAL(BFV方案)
     * 
     * 配置SEAL的BFV方案参数，生成密钥对、重线性化密钥，并初始化各种操作器。
     */
    void init_seal();
};

} // namespace yus

#endif // YUS_FHE_WRAPPER_H