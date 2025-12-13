/**
 * @file fhe_wrapper.cpp
 * @brief YuS流密码FHE封装接口实现
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 实现YuS流密码的同态加密封装接口，支持HElib(BGV方案)和SEAL(BFV方案)两种同态加密库。
 * 提供密钥生成、加密、解密、同态评估和性能测量等功能。
 */

#include "yus/fhe_wrapper.h"
#include "yus/utils.h"
#include <helib/helib.h>
#include <seal/seal.h>
#include <stdexcept>
#include <chrono>
#include <cmath>
#include <omp.h>

namespace yus {

/**
 * @brief FHEWrapper构造函数
 * @param scheme 同态加密方案（BGV或BFV）
 * @param params FHE参数配置
 * @throws std::invalid_argument 当参数不满足条件时抛出异常
 * 
 * 初始化FHE封装实例，验证安全级别和明文模数条件，并根据方案初始化相应的加密库。
 */
FHEWrapper::FHEWrapper(FHE_SCHEME scheme, const FHEParams& params)
    : scheme_(scheme), params_(params) {
    
    // 验证安全级别
    if (params.security_level != 80 && params.security_level != 128) {
        throw std::invalid_argument("Security level must be 80 or 128");
    }
    // 验证明文模数条件
    if (!is_p_2mod3(params.plain_modulus)) {
        throw std::invalid_argument("Plain modulus must satisfy p ≡ 2 mod 3");
    }

    // 根据方案初始化相应的加密库
    if (scheme == FHE_SCHEME::BGV) {
        init_helib();
    } else if (scheme == FHE_SCHEME::BFV) {
        init_seal();
    }
}

/**
 * @brief FHEWrapper析构函数
 * 
 * 默认析构函数，自动清理智能指针管理的资源。
 */
FHEWrapper::~FHEWrapper() = default;

/**
 * @brief 初始化HElib(BGV方案)
 * 
 * 配置HElib的BGV方案参数
 * 生成密钥对并初始化加密上下文。
 */
void FHEWrapper::init_helib() {
    unsigned long m = params_.poly_modulus_degree;
    unsigned long p = params_.plain_modulus.get_ui();
    unsigned long r = 1;
    unsigned long bits = params_.cipher_modulus_bits;

    // 构建HElib上下文
    helib_context_.reset(
        helib::ContextBuilder<helib::BGV>()
            .m(m)
            .p(p)
            .r(r)
            .bits(bits)
            .c(params_.security_level)
            .buildPtr() 
    );

    // 生成密钥对
    helib_seckey_ = std::make_shared<helib::SecKey>(*helib_context_);
    helib_seckey_->GenSecKey();
    helib_pubkey_ = std::make_shared<helib::PubKey>(*helib_seckey_);
}

/**
 * @brief 初始化SEAL(BFV方案)
 * 
 * 配置SEAL的BFV方案参数
 * 生成密钥对、重线性化密钥，并初始化各种操作器。
 */
void FHEWrapper::init_seal() {
    // 配置加密参数
    seal::EncryptionParameters enc_params(seal::scheme_type::bfv);
    enc_params.set_poly_modulus_degree(params_.poly_modulus_degree);
    enc_params.set_coeff_modulus(
        seal::CoeffModulus::BFVDefault(params_.poly_modulus_degree));
    enc_params.set_plain_modulus(
        seal::PlainModulus::Batching(params_.poly_modulus_degree, 20));

    // 初始化SEAL上下文
    seal_context_ = std::make_unique<seal::SEALContext>(enc_params);
    
    // 生成密钥对
    seal::KeyGenerator keygen(*seal_context_);
    seal_seckey_ = std::make_unique<seal::SecretKey>(keygen.secret_key());
    seal_pubkey_ = std::make_unique<seal::PublicKey>();
    keygen.create_public_key(*seal_pubkey_);
    
    // 生成重线性化密钥
    seal_relin_keys_ = std::make_unique<seal::RelinKeys>();
    keygen.create_relin_keys(*seal_relin_keys_);

    // 初始化各种操作器
    seal_encryptor_ = std::make_unique<seal::Encryptor>(*seal_context_, *seal_pubkey_);
    seal_decryptor_ = std::make_unique<seal::Decryptor>(*seal_context_, *seal_seckey_);
    seal_evaluator_ = std::make_unique<seal::Evaluator>(*seal_context_);
    seal_batch_encoder_ = std::make_unique<seal::BatchEncoder>(*seal_context_);
}

/**
 * @brief 生成密钥对
 * 
 * 重新生成同态加密的密钥对，支持BGV和BFV两种方案。
 * 用于密钥轮换或重新初始化。
 */
void FHEWrapper::generate_keys() {
    if (scheme_ == FHE_SCHEME::BGV) {
        helib_seckey_->GenSecKey();
        helib_pubkey_ = std::make_shared<helib::PubKey>(*helib_seckey_);
    } else {
        seal::KeyGenerator keygen(*seal_context_);
        *seal_seckey_ = keygen.secret_key();
        keygen.create_public_key(*seal_pubkey_);
        keygen.create_relin_keys(*seal_relin_keys_);
        
        // 重新初始化加密器和解密器
        seal_encryptor_ = std::make_unique<seal::Encryptor>(*seal_context_, *seal_pubkey_);
        seal_decryptor_ = std::make_unique<seal::Decryptor>(*seal_context_, *seal_seckey_);
    }
}

/**
 * @brief 打包明文数据
 * @param data 原始明文数据向量
 * @return 打包后的明文数据向量
 * 
 * 对于BGV方案，将多个明文元素打包到单个密文槽中以提高效率。
 * 对于BFV方案，直接返回原始数据（支持批处理）。
 */
std::vector<mpz_class> FHEWrapper::pack_plaintext(const std::vector<mpz_class>& data) const {
    if (scheme_ == FHE_SCHEME::BFV) {
        return data;
    }
    
    std::vector<mpz_class> packed;
    long nslots = helib_context_->getNSlots();
    uint32_t batch_size = nslots;
    uint32_t num_batches = (data.size() + batch_size - 1) / batch_size;

    // 将数据分批打包
    for (uint32_t i = 0; i < num_batches; ++i) {
        mpz_class batch(0);
        uint32_t start = i * batch_size;
        uint32_t end = std::min(start + batch_size, (uint32_t)data.size());
        uint32_t elem_bits = mpz_sizeinbase(params_.plain_modulus.get_mpz_t(), 2);
        
        // 将多个元素打包到单个大整数中
        for (uint32_t j = start; j < end; ++j) {
            batch = (batch << elem_bits) | data[j];
        }
        packed.push_back(batch);
    }
    return packed;
}

/**
 * @brief 加密明文数据
 * @param plain 明文数据向量
 * @param cipher 输出密文向量
 * 
 * 使用配置的同态加密方案对明文数据进行加密。
 * BGV方案逐个元素加密，BFV方案支持批处理加密。
 */
void FHEWrapper::encrypt(const std::vector<mpz_class>& plain, std::vector<CiphertextPtr>& cipher) {
    cipher.clear();

    if (scheme_ == FHE_SCHEME::BGV) {
        // BGV方案：逐个元素加密
        for (const auto& p : plain) {
            helib::Ptxt<helib::BGV> ptxt(*helib_context_);
            ptxt[0] = p.get_si();
            
            auto ctxt = std::make_shared<helib::Ctxt>(*helib_pubkey_);
            helib_pubkey_->Encrypt(*ctxt, ptxt);
            cipher.push_back(ctxt);
        }
    } else {
        // BFV方案：批处理加密
        std::vector<uint64_t> seal_plain(plain.size());
        for (size_t i = 0; i < plain.size(); ++i) {
            seal_plain[i] = plain[i].get_ui();
        }
        
        seal::Plaintext ptxt;
        seal_batch_encoder_->encode(seal_plain, ptxt);
        
        auto ctxt = std::make_shared<seal::Ciphertext>();
        seal_encryptor_->encrypt(ptxt, *ctxt);
        cipher.push_back(ctxt);
    }
}

/**
 * @brief 解密密文数据
 * @param cipher 密文向量
 * @return 解密后的明文数据向量
 * 
 * 使用对应的私钥对密文数据进行解密。
 * BGV方案逐个元素解密，BFV方案支持批处理解密。
 */
std::vector<mpz_class> FHEWrapper::decrypt(const std::vector<CiphertextPtr>& cipher) const {
    std::vector<mpz_class> plain;

    if (scheme_ == FHE_SCHEME::BGV) {
        // BGV方案：逐个元素解密
        for (const auto& c : cipher) {
            helib::Ctxt* ctxt = static_cast<helib::Ctxt*>(c.get());
            helib::Ptxt<helib::BGV> ptxt(*helib_context_);
            
            helib_seckey_->Decrypt(ptxt, *ctxt);
            plain.push_back(mpz_class(static_cast<long>(ptxt[0])));
        }
    } else {
        // BFV方案：批处理解密
        if (cipher.empty()) return plain;
        
        seal::Ciphertext* ctxt = static_cast<seal::Ciphertext*>(cipher[0].get());
        seal::Plaintext ptxt;
        seal_decryptor_->decrypt(*ctxt, ptxt);
        
        std::vector<uint64_t> seal_plain;
        seal_batch_encoder_->decode(ptxt, seal_plain);
        
        for (auto val : seal_plain) {
            plain.push_back(mpz_class(static_cast<unsigned long>(val)));
        }
    }
    
    return plain;
}

/**
 * @brief 同态评估YuS流密码
 * @param cipher_key 加密的密钥向量
 * @param cipher_keystream 加密的密钥流向量
 * @return 评估时间（毫秒）
 * 
 * 在密文状态下执行YuS流密码的同态评估，支持并行处理。
 * 测量评估性能并返回执行时间。
 */
double FHEWrapper::evaluate_yus(const std::vector<CiphertextPtr>& cipher_key, 
                                const std::vector<CiphertextPtr>& cipher_keystream) {
    Timer timer;
    timer.start();

    if (scheme_ == FHE_SCHEME::BGV) {
        // BGV方案：并行同态乘法
        #pragma omp parallel for
        for (size_t i = 0; i < cipher_key.size(); ++i) {
            helib::Ctxt* key = static_cast<helib::Ctxt*>(cipher_key[i].get());
            helib::Ctxt* ks = static_cast<helib::Ctxt*>(cipher_keystream[i].get());
            
            *ks *= *key;  // 同态乘法
            ks->reLinearize();  // 重线性化
        }
    } else {
        // BFV方案：批处理同态操作
        if (cipher_key.empty() || cipher_keystream.empty()) return 0.0;
        
        seal::Ciphertext* key = static_cast<seal::Ciphertext*>(cipher_key[0].get());
        seal::Ciphertext* ks = static_cast<seal::Ciphertext*>(cipher_keystream[0].get());
        
        seal_evaluator_->multiply_inplace(*ks, *key);  // 同态乘法
        seal_evaluator_->relinearize_inplace(*ks, *seal_relin_keys_);  // 重线性化
    }

    timer.stop();
    return timer.elapsed_ms();
}

/**
 * @brief 计算吞吐量
 * @param data_size 数据大小（字节）
 * @param eval_time 评估时间（毫秒）
 * @return 吞吐量（KB/s）
 * 
 * 根据数据大小和评估时间计算同态加密的吞吐量性能指标。
 */
double FHEWrapper::get_throughput(uint32_t data_size, double eval_time) const {
    double eval_time_sec = eval_time / 1000.0;
    return eval_time_sec > 0 ? (data_size / 1024.0) / eval_time_sec : 0.0;
}

} // namespace yus