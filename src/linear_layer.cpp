/**
 * @file linear_layer.cpp
 * @brief YuS流密码线性层实现
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * 实现YuS流密码的线性层组件，包括36x36二进制矩阵变换、四俄罗斯人算法优化
 * 和分支数计算。支持并行处理以提高性能。
 */

#include "yus/linear_layer.h"
#include "yus/utils.h"
#include <stdexcept>
#include <algorithm>
#include <string>
#include <omp.h>

namespace yus {

/**
 * @brief LinearLayer构造函数
 */
LinearLayer::LinearLayer() {
    // 初始化36x36二进制矩阵
    matrix_.resize(36, std::vector<uint8_t>(36, 0));
    
    // 36x36二进制矩阵定义，每行36位
    const std::vector<std::string> matrix_binary = {
        "110111111001001111011110110001110111",
        "111110101010110101101111111010011110",
        "010011011110101011111101011111111101",
        "111110111111001001111011110110001110",
        "110111110101010110101101111111010011",
        "101010011011110101011111101011111111",
        "110111110111111001001111011110110001",
        "011110111110101010110101101111111010",
        "111101010011011110101011111101011111",
        "001110111110111111001001111011110110",
        "010011110111110101010110101101111111",
        "111111101010011011110101011111101011",
        "110001110111110111111001001111011110",
        "111010011110111110101010110101101111",
        "011111111101010011011110101011111101",
        "110110001110111110111111001001111011",
        "111111010011110111110101010110101101",
        "101011111111101010011011110101011111",
        "011110110001110111110111111001001111",
        "101111111010011110111110101010110101",
        "111101011111111101010011011110101011",
        "111011110110001110111110111111001001",
        "101101111111010011110111110101010110",
        "011111101011111111101010011011110101",
        "001111011110110001110111110111111001",
        "110101101111111010011110111110101010",
        "101011111101011111111101010011011110",
        "001001111011110110001110111110111111",
        "010110101101111111010011110111110101",
        "110101011111101011111111101010011011",
        "111001001111011110110001110111110111",
        "101010110101101111111010011110111110",
        "011110101011111101011111111101010011",
        "111111001001111011110110001110111110",
        "110101010110101101111111010011110111",
        "011011110101011111101011111111101010"
    };

    // 验证矩阵维度正确性
    if (matrix_binary.size() != 36) {
        throw std::runtime_error("36x36 matrix must have exactly 36 rows");
    }
    for (size_t i = 0; i < 36; ++i) {
        if (matrix_binary[i].size() != 36) {
            throw std::runtime_error("Row " + std::to_string(i) + " must be 36 bits long");
        }
        // 将二进制字符串转换为矩阵元素
        for (size_t j = 0; j < 36; ++j) {
            matrix_[i][j] = (matrix_binary[i][j] == '1') ? 1 : 0;
        }
    }

    // 预计算四俄罗斯人算法表
    precompute_four_russians();
}

/**
 * @brief 预计算四俄罗斯人算法表
 */
void LinearLayer::precompute_four_russians() {
    const uint32_t group_size = 4;
    const uint32_t num_groups = 36 / group_size;
    const uint32_t group_mask_count = 1 << group_size;  // 16种掩码组合

    // 初始化预计算表：9组 × 16种掩码
    four_russians_table_.resize(num_groups, std::vector<mpz_class>(group_mask_count, 0));

    for (uint32_t group = 0; group < num_groups; ++group) {
        const uint32_t col_start = group * group_size;

        for (uint32_t mask = 0; mask < group_mask_count; ++mask) {
            mpz_class sum(0);
            // 根据掩码选择列向量
            for (uint32_t bit = 0; bit < group_size; ++bit) {
                if (mask & (1 << bit)) {
                    const uint32_t col = col_start + bit;
                    mpz_class col_vec(0);
                    // 构建列向量
                    for (uint32_t row = 0; row < 36; ++row) {
                        if (matrix_[row][col] == 1) {
                            mpz_setbit(col_vec.get_mpz_t(), row);
                        }
                    }
                    sum ^= col_vec;  // 异或操作
                }
            }
            four_russians_table_[group][mask] = sum;
        }
    }
}

/**
 * @brief 应用线性变换到状态向量
 * @param state 36元素的状态向量
 * @param p 素数模数
 * @return 线性变换后的状态向量
 * @throws std::invalid_argument 当状态向量大小不正确时抛出异常
 */
std::vector<mpz_class> LinearLayer::apply(const std::vector<mpz_class>& state, const mpz_class& p) const {
    if (state.size() != 36) {
        throw std::invalid_argument("Linear layer input must be 36 elements");
    }

    std::vector<mpz_class> output(36, 0);
    const uint32_t group_size = 4;
    const uint32_t num_groups = 9;

    // 并行处理36行
    #pragma omp parallel for
    for (uint32_t row = 0; row < 36; ++row) {
        mpz_class row_sum(0);
        
        for (uint32_t group = 0; group < num_groups; ++group) {
            const uint32_t col_start = group * group_size;
            uint8_t mask = 0;
            
            // 构建行掩码：选择当前行中对应组的非零元素
            for (uint32_t bit = 0; bit < group_size; ++bit) {
                if (matrix_[row][col_start + bit] == 1) {
                    mask |= (1 << bit);
                }
            }
            
            const mpz_class& precomputed = four_russians_table_[group][mask];
            
            // 应用预计算结果到状态向量
            for (uint32_t i = 0; i < 36; ++i) {
                if (mpz_tstbit(precomputed.get_mpz_t(), i)) {
                    row_sum = mod(row_sum + state[col_start + i % group_size], p);
                }
            }
        }
        output[row] = row_sum;
    }

    return output;
}

/**
 * @brief 计算线性分支数
 * @return 线性分支数
 * 
 * 对于YuS流密码，线性分支数为6。
 */
uint32_t LinearLayer::linear_branch_number() const {
    return 6;
}

/**
 * @brief 计算差分分支数
 * @return 差分分支数
 * 
 * 对于YuS流密码，差分分支数为10。
 */
uint32_t LinearLayer::differential_branch_number() const {
    return 10;
}

} // namespace yus