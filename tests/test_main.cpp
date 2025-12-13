/**
 * @file test_main.cpp
 * @brief YuS流密码测试主程序
 * @author Aurorp1g
 * @date 2025-11-07
 * 
 * Google Test框架的主测试程序，包含自定义测试监听器用于详细测试进度输出。
 * 支持调试模式，提供测试开始、失败和结束的详细日志信息。
 */

#include <gtest/gtest.h>
#include <iostream>

/**
 * @class DebugTestListener
 * @brief 自定义测试监听器类
 * 
 * 继承自Google Test的EmptyTestEventListener，提供详细的测试进度输出功能。
 * 在测试开始、失败和结束时输出相应的调试信息。
 */
class DebugTestListener : public ::testing::EmptyTestEventListener {
public:
    /**
     * @brief 测试开始时的回调函数
     * @param test_info 测试信息对象，包含测试套件名和测试名
     * 
     * 当测试开始时输出测试套件名和测试名，便于跟踪测试进度。
     */
    void OnTestStart(const ::testing::TestInfo& test_info) override {
        std::cout << "[TEST START] " << test_info.test_suite_name() 
                  << "." << test_info.name() << std::endl;
    }
    
    /**
     * @brief 测试部分结果回调函数
     * @param test_part_result 测试部分结果对象
     * 
     * 当测试失败时输出详细的失败信息，包括文件名、行号和失败摘要。
     */
    void OnTestPartResult(const ::testing::TestPartResult& test_part_result) override {
        if (test_part_result.failed()) {
            std::cout << "[TEST FAILURE] " << test_part_result.file_name() 
                      << ":" << test_part_result.line_number() << " - " 
                      << test_part_result.summary() << std::endl;
        }
    }
    
    /**
     * @brief 测试结束时的回调函数
     * @param test_info 测试信息对象
     * 
     * 根据测试结果输出通过或失败信息，便于快速识别测试状态。
     */
    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        if (test_info.result()->Failed()) {
            std::cout << "[TEST FAILED] " << test_info.test_suite_name() 
                      << "." << test_info.name() << std::endl;
        } else {
            std::cout << "[TEST PASSED] " << test_info.test_suite_name() 
                      << "." << test_info.name() << std::endl;
        }
    }
};

/**
 * @brief 主函数 - YuS流密码测试程序入口
 * @param argc 命令行参数个数
 * @param argv 命令行参数数组
 * @return 测试执行结果（0表示所有测试通过，非0表示有测试失败）
 * 
 * 初始化Google Test框架，添加自定义调试监听器，并执行所有测试用例。
 * 支持调试模式，提供详细的测试进度和结果输出。
 */
int main(int argc, char **argv) {
    std::cout << "=== Yus Cipher FHE Tests with Debug Mode ===" << std::endl;
    std::cout << "[DEBUG] Starting test suite with " << argc << " arguments" << std::endl;
    
    // 初始化Google Test框架
    ::testing::InitGoogleTest(&argc, argv);
    
    // 获取默认的测试监听器列表
    ::testing::TestEventListeners& listeners = 
        ::testing::UnitTest::GetInstance()->listeners();
    
    // 添加自定义调试监听器
    listeners.Append(new DebugTestListener);
    
    // 执行所有测试用例
    return RUN_ALL_TESTS();
}