/**
 * @file yus_demo.cpp
 * @brief YuS流密码演示程序
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * YuS流密码的完整演示程序，展示从素数生成、密钥初始化到同态评估的完整流程。
 * 包含内存使用监控、进度显示和错误处理功能，支持Windows和Linux平台。
 */

#include "yus/yus_core.h"
#include "yus/fhe_wrapper.h"
#include "yus/utils.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

/**
 * @brief 打印内存使用情况
 * @param stage 当前执行阶段标识
 * 
 * 监控程序在不同阶段的内存使用情况，支持Windows和Linux平台。
 * Windows平台显示工作集和页面文件使用量，Linux平台显示最大驻留集大小。
 */
void print_memory_usage(const std::string& stage) {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        std::cout << "[MEMORY] " << stage << " - Working Set: " 
                  << pmc.WorkingSetSize / 1024 / 1024 << " MB, Pagefile: " 
                  << pmc.PagefileUsage / 1024 / 1024 << " MB" << std::endl;
    }
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        std::cout << "[MEMORY] " << stage << " - Max RSS: " 
                  << usage.ru_maxrss / 1024 << " MB" << std::endl;
    }
#endif
}

/**
 * @brief 主函数 - YuS流密码演示程序入口
 * @return 程序退出代码（0表示成功，非0表示错误）
 * 
 * 演示程序的完整执行流程，分为7个主要阶段：
 * 1. 素数生成
 * 2. YuS密码初始化
 * 3. 主密钥生成
 * 4. 随机数设置
 * 5. YuS密码完整初始化
 * 6. 密钥流生成
 * 7. FHE同态操作
 */
int main() {
    std::cout << "=== Yus Cipher Demo with Debug Mode ===" << std::endl;
    std::cout << "[DEBUG] Program started" << std::endl;
    
    try {
        // 阶段1: 生成素数
        std::cout << "[STAGE 1] Generating prime p..." << std::endl;
        print_memory_usage("Before prime generation");
        
        // 生成17位满足条件的素数（p ≡ 2 mod 3且p > 2^16）
        mpz_class p = yus::generate_prime(17);
        std::cout << "[SUCCESS] Generated prime p: " << p << std::endl;
        print_memory_usage("After prime generation");
        
        // 等待用户确认继续
        std::cout << "[DEBUG] Press Enter to continue to Stage 2...";
        std::cin.get();

        // 阶段2: 初始化YuS密码
        std::cout << "[STAGE 2] Initializing YuS cipher..." << std::endl;
        yus::YuSCipher yus(p, yus::SecurityLevel::SEC80, 12);  // 80位安全，截断12位
        std::cout << "[SUCCESS] YuS cipher initialized" << std::endl;
        print_memory_usage("After YuS initialization");

        // 阶段3: 生成主密钥
        std::cout << "[STAGE 3] Generating master key..." << std::endl;
        std::vector<mpz_class> master_key(36);
        for (int i = 0; i < 36; ++i) {
            master_key[i] = yus::mod(i + 1, p);  // 使用简单序列作为主密钥
            if (i % 10 == 0) {
                std::cout << "[PROGRESS] Generated " << i << "/36 key elements" << std::endl;
            }
        }
        std::cout << "[SUCCESS] Master key generated" << std::endl;
        print_memory_usage("After master key generation");

        // 阶段4: 设置随机数
        std::cout << "[STAGE 4] Setting nonce..." << std::endl;
        std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        
        // 阶段5: 初始化YuS密码
        std::cout << "[STAGE 5] Initializing YuS with key and nonce..." << std::endl;
        yus.init(master_key, nonce);
        std::cout << "[SUCCESS] YuS initialized" << std::endl;
        print_memory_usage("After YuS init");

        std::cout << "[DEBUG] Press Enter to continue to Stage 6...";
        std::cin.get();

        // 阶段6: 生成密钥流
        std::cout << "[STAGE 6] Generating keystream..." << std::endl;
        auto keystream = yus.generate_keystream(1);  // 生成1个密钥流块
        std::cout << "[SUCCESS] Generated keystream with " << keystream.size() << " elements" << std::endl;
        // 显示前5个密钥流元素
        for (size_t i = 0; i < keystream.size() && i < 5; ++i) {
            std::cout << "  [" << i << "]: " << keystream[i] << std::endl;
        }
        if (keystream.size() > 5) {
            std::cout << "  ... and " << (keystream.size() - 5) << " more elements" << std::endl;
        }
        print_memory_usage("After keystream generation");

        std::cout << "[DEBUG] Press Enter to continue to FHE operations...";
        std::cin.get();

        // 阶段7: FHE同态操作
        std::cout << "[STAGE 7] Starting FHE operations with optimized parameters..." << std::endl;
        
        // 配置FHE参数
        yus::FHEParams fhe_params;
        fhe_params.security_level = 128;           // 128位安全级别
        fhe_params.poly_modulus_degree = 8192;    // 多项式模数次数
        fhe_params.plain_modulus = p;             // 明文模数
        fhe_params.cipher_modulus_bits = 300;     // 密文模数位数

        std::cout << "[FHE PARAMS] Security: " << fhe_params.security_level 
                  << ", Poly degree: " << fhe_params.poly_modulus_degree
                  << ", Cipher bits: " << fhe_params.cipher_modulus_bits << std::endl;

        // FHE包装器初始化
        std::cout << "[FHE] Initializing FHE wrapper..." << std::endl;
        yus::FHEWrapper fhe(yus::FHE_SCHEME::BFV, fhe_params);  // 使用BFV方案
        std::cout << "[SUCCESS] FHE wrapper initialized" << std::endl;
        print_memory_usage("After FHE wrapper init");

        // 密钥生成
        std::cout << "[FHE] Generating keys..." << std::endl;
        fhe.generate_keys();
        std::cout << "[SUCCESS] FHE keys generated" << std::endl;
        print_memory_usage("After FHE key generation");

        std::cout << "[DEBUG] Press Enter to continue to encryption...";
        std::cin.get();

        // 加密密钥流
        std::cout << "[FHE] Encrypting keystream..." << std::endl;
        std::vector<yus::FHEWrapper::CiphertextPtr> cipher_ks;
        fhe.encrypt(keystream, cipher_ks);
        std::cout << "[SUCCESS] Keystream encrypted (" << cipher_ks.size() << " ciphertexts)" << std::endl;
        print_memory_usage("After keystream encryption");

        // 加密主密钥（只加密前8个元素以节省内存）
        std::cout << "[FHE] Encrypting master key (first 8 elements)..." << std::endl;
        std::vector<mpz_class> key_part(master_key.begin(), master_key.begin() + 8);
        std::vector<yus::FHEWrapper::CiphertextPtr> cipher_key;
        fhe.encrypt(key_part, cipher_key);
        std::cout << "[SUCCESS] Master key encrypted (" << cipher_key.size() << " ciphertexts)" << std::endl;
        print_memory_usage("After master key encryption");

        std::cout << "[DEBUG] Press Enter to continue to homomorphic evaluation...";
        std::cin.get();

        // 同态评估
        std::cout << "[FHE] Starting homomorphic evaluation..." << std::endl;
        double eval_time = fhe.evaluate_yus(cipher_key, cipher_ks);
        double throughput = fhe.get_throughput(8 * mpz_sizeinbase(p.get_mpz_t(), 8), eval_time);
        
        std::cout << "[SUCCESS] FHE evaluation completed" << std::endl;
        std::cout << "[RESULTS] Evaluation time: " << eval_time << " ms" << std::endl;
        std::cout << "[RESULTS] Throughput: " << throughput << " KiB/s" << std::endl;
        print_memory_usage("After FHE evaluation");

        std::cout << "[DEBUG] Program completed successfully!" << std::endl;
        std::cout << "Press Enter to exit...";
        std::cin.get();

    } catch (const std::exception& e) {
        // 异常处理：标准异常
        std::cerr << "[FATAL ERROR] Exception caught: " << e.what() << std::endl;
        std::cerr << "[DEBUG] Program will exit with error code 1" << std::endl;
        print_memory_usage("At error");
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    } catch (...) {
        // 异常处理：未知异常
        std::cerr << "[FATAL ERROR] Unknown exception caught!" << std::endl;
        std::cerr << "[DEBUG] Program will exit with error code 2" << std::endl;
        print_memory_usage("At unknown error");
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 2;
    }

    return 0;  // 程序成功执行
}