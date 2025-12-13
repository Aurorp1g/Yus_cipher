# 项目基本信息配置
cmake_minimum_required(VERSION 3.16)
project(yus-cipher VERSION 1.0 LANGUAGES CXX)

# C++标准配置
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译器特定的C++17支持
if(MSVC)
    add_compile_options(/std:c++17)
else()
    add_compile_options(-std=c++17)
endif()

# 默认构建类型设置
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# 编译器警告和链接选项配置
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -pedantic -Wno-deprecated -Wno-unused-parameter -Wno-deprecated-copy)
    if(WIN32)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
elseif(MSVC)
    add_compile_options(/W4 /wd4100 /wd4996)
    if(WIN32)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MT")
    endif()
endif()

# OpenMP并行计算支持
find_package(OpenMP REQUIRED)
if(OpenMP_FOUND)
    message(STATUS "找到OpenMP: ${OpenMP_CXX_VERSION}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${OpenMP_SHARED_LINKER_FLAGS}")
else()
    message(WARNING "未找到OpenMP，并行计算功能将不可用")
endif()

# 构建选项配置
option(BUILD_TESTS "Build tests" ON)
option(ENABLE_FHE "Enable Fully Homomorphic Encryption support" ON)

# 第三方库路径配置
set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/openssl)
set(GMP_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/GMP)
set(MPFR_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/mpfr)
set(HELIB_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/HElib)
set(SEAL_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/SEAL)
set(NTL_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/ntl)
set(GTEST_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/googletest)

# GMP数学库配置
set(GMP_INCLUDE_DIR ${GMP_ROOT_DIR}/include)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(GMP_LIBRARIES ${GMP_ROOT_DIR}/lib/x64/libgmp.a ${GMP_ROOT_DIR}/lib/x64/libgmpxx.a)
else()
    set(GMP_LIBRARIES ${GMP_ROOT_DIR}/lib/x86/libgmp.a ${GMP_ROOT_DIR}/lib/x86/libgmpxx.a)
endif()

# MPFR高精度数学库配置
set(MPFR_INCLUDE_DIR ${MPFR_ROOT_DIR}/src)
set(MPFR_LIBRARIES ${MPFR_ROOT_DIR}/src/.libs/libmpfr.a)

# NTL数论库配置
set(NTL_INCLUDE_DIR ${NTL_ROOT_DIR}/include)
set(NTL_LIBRARIES ${NTL_ROOT_DIR}/lib/libntl.a)

# OpenSSL密码学库配置
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib64/libcrypto.a ${OPENSSL_ROOT_DIR}/lib64/libssl.a)

# GoogleTest测试框架配置
set(GTEST_INCLUDE_DIRS ${GTEST_ROOT_DIR}/include)
set(GTEST_LIBRARIES ${GTEST_ROOT_DIR}/lib/libgtest.a)
set(GTEST_MAIN_LIBRARIES ${GTEST_ROOT_DIR}/lib/libgtest_main.a)
set(GTEST_FOUND TRUE)

# 全同态加密库检测和配置
if(ENABLE_FHE)
    if(EXISTS "${HELIB_ROOT_DIR}/lib/libhelib.a")
        set(HELIB_INCLUDE_DIR ${HELIB_ROOT_DIR}/include)
        set(HELIB_LIBRARIES ${HELIB_ROOT_DIR}/lib/libhelib.a)
        set(HELIB_FOUND TRUE)
        message(STATUS "找到HElib库")
    else()
        set(HELIB_FOUND FALSE)
        message(WARNING "未找到HElib库，禁用FHE支持")
        set(ENABLE_FHE OFF)
    endif()
    
    if(ENABLE_FHE)
        if(EXISTS "${SEAL_ROOT_DIR}/lib/libseal-4.1.a")
            set(SEAL_INCLUDE_DIR ${SEAL_ROOT_DIR}/include)
            set(SEAL_LIBRARIES ${SEAL_ROOT_DIR}/lib/libseal-4.1.a)
            set(SEAL_FOUND TRUE)
            message(STATUS "找到SEAL库: libseal-4.1.a")
        elseif(EXISTS "${SEAL_ROOT_DIR}/lib/libseal.a")
            set(SEAL_INCLUDE_DIR ${SEAL_ROOT_DIR}/include)
            set(SEAL_LIBRARIES ${SEAL_ROOT_DIR}/lib/libseal.a)
            set(SEAL_FOUND TRUE)
            message(STATUS "找到SEAL库: libseal.a")
        else()
            set(SEAL_FOUND FALSE)
            message(WARNING "未找到SEAL库，禁用FHE支持")
            set(ENABLE_FHE OFF)
        endif()
    endif()
endif()

# 创建YuS流密码静态库
add_library(yus STATIC)

# 核心源文件配置
target_sources(yus PRIVATE
    src/sbox.cpp
    src/linear_layer.cpp
    src/round_key.cpp
    src/yus_core.cpp
    src/utils.cpp
)

# 可选FHE封装源文件
if(ENABLE_FHE AND HELIB_FOUND AND SEAL_FOUND)
    target_sources(yus PRIVATE src/fhe_wrapper.cpp)
    target_compile_definitions(yus PUBLIC ENABLE_FHE)
endif()

# 主包含目录配置
target_include_directories(yus PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${GMP_INCLUDE_DIR}
    ${MPFR_INCLUDE_DIR}
    ${NTL_INCLUDE_DIR}
)

# 目标特定的编译器警告抑制
target_compile_options(yus PRIVATE 
    $<$<CXX_COMPILER_ID:MSVC>:/wd4100 /wd4996>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-unused-parameter -Wno-deprecated-copy>
)

# FHE库包含目录配置
if(ENABLE_FHE AND HELIB_FOUND AND SEAL_FOUND)
    target_include_directories(yus PUBLIC
        ${HELIB_INCLUDE_DIR}
        ${SEAL_INCLUDE_DIR}
    )
endif()

# OpenMP链接配置
if(OpenMP_FOUND)
    target_link_libraries(yus PRIVATE OpenMP::OpenMP_CXX)
endif()

# Windows平台依赖库链接
if(WIN32)
    target_link_libraries(yus PRIVATE
        ${HELIB_LIBRARIES}
        ${SEAL_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${NTL_LIBRARIES}
        ${MPFR_LIBRARIES}
        ${GMP_ROOT_DIR}/lib/x64/libgmpxx.a
        ${GMP_ROOT_DIR}/lib/x64/libgmp.a
        ${CMAKE_SOURCE_DIR}/plugins/zlib/lib/x64/libz.a
        ${CMAKE_SOURCE_DIR}/plugins/zstd/lib/x64/libzstd.a
        bcrypt
        crypt32
        ws2_32
    )
else()
    # Linux/Mac平台依赖库链接
    target_link_libraries(yus PRIVATE
        ${HELIB_LIBRARIES}
        ${SEAL_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${NTL_LIBRARIES}
        ${MPFR_LIBRARIES}
        ${GMP_ROOT_DIR}/lib/x64/libgmp.a
        ${GMP_ROOT_DIR}/lib/x64/libgmpxx.a
        ${CMAKE_SOURCE_DIR}/plugins/zlib/lib/x64/libz.a
        ${CMAKE_SOURCE_DIR}/plugins/zstd/lib/x64/libzstd.a
        pthread
    )
endif()

# 示例程序配置
add_executable(yus_example examples/yus_demo.cpp)
target_link_libraries(yus_example PRIVATE 
    yus
    ${GMP_ROOT_DIR}/lib/x64/libgmpxx.a
    ${GMP_ROOT_DIR}/lib/x64/libgmp.a
)

# 示例程序OpenMP支持
if(OpenMP_FOUND)
    target_link_libraries(yus_example PRIVATE OpenMP::OpenMP_CXX)
endif()

# 测试程序配置
if(BUILD_TESTS AND GTEST_FOUND)
    message(STATUS "启用测试")
    
    add_executable(yus_test)
    
    # 测试源文件配置
    target_sources(yus_test PRIVATE
        tests/test_sbox.cpp
        tests/test_linear_layer.cpp
        tests/test_round_key.cpp
        tests/test_yus_core.cpp
        tests/test_main.cpp
    )
    
    # 测试程序编译器选项
    target_compile_options(yus_test PRIVATE 
        $<$<CXX_COMPILER_ID:MSVC>:/wd4100 /wd4996>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-unused-parameter -Wno-deprecated-copy>
    )
    
    # 示例程序编译器选项
    target_compile_options(yus_example PRIVATE 
        $<$<CXX_COMPILER_ID:MSVC>:/wd4100 /wd4996>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-unused-parameter -Wno-deprecated-copy>
    )
    
    # 可选FHE测试配置
    if(ENABLE_FHE AND HELIB_FOUND AND SEAL_FOUND)
        target_sources(yus_test PRIVATE tests/test_fhe.cpp)
        target_compile_definitions(yus_test PRIVATE ENABLE_FHE)
    endif()
    
    target_include_directories(yus_test PRIVATE ${GTEST_INCLUDE_DIRS})
    
    # 测试程序OpenMP支持
    if(OpenMP_FOUND)
        target_link_libraries(yus_test PRIVATE OpenMP::OpenMP_CXX)
    endif()
    
    # Windows平台测试程序链接
    if(WIN32)
        target_link_libraries(yus_test PRIVATE
            yus
            ${GTEST_LIBRARIES}
            ${GTEST_MAIN_LIBRARIES}
            ${CMAKE_SOURCE_DIR}/plugins/zlib/lib/x64/libz.a
            ${CMAKE_SOURCE_DIR}/plugins/zstd/lib/x64/libzstd.a
            ${GMP_ROOT_DIR}/lib/x64/libgmp.a
            bcrypt
            crypt32
            ws2_32
        )
    else()
        # Linux/Mac平台测试程序链接
        target_link_libraries(yus_test PRIVATE
            yus
            ${GTEST_LIBRARIES}
            ${GTEST_MAIN_LIBRARIES}
            ${CMAKE_SOURCE_DIR}/plugins/zlib/lib/x64/libz.a
            ${CMAKE_SOURCE_DIR}/plugins/zstd/lib/x64/libzstd.a
            pthread
        )
    endif()
else()
    message(STATUS "禁用测试")
endif()

# 安装配置
install(TARGETS yus yus_example
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

if(TARGET yus_test)
    install(TARGETS yus_test
        RUNTIME DESTINATION bin
    )
endif()

install(DIRECTORY include/yus
    DESTINATION include
)

# 配置摘要输出
message(STATUS "========================================")
message(STATUS "配置摘要:")
message(STATUS "  项目: ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  编译器: ${CMAKE_CXX_COMPILER}")
message(STATUS "  构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++标准: ${CMAKE_CXX_STANDARD}")
message(STATUS "  启用测试: ${BUILD_TESTS}")
message(STATUS "  启用FHE: ${ENABLE_FHE}")
message(STATUS "  启用OpenMP: ${OpenMP_FOUND}")
if(OpenMP_FOUND)
    message(STATUS "  OpenMP版本: ${OpenMP_CXX_VERSION}")
endif()
message(STATUS "========================================")