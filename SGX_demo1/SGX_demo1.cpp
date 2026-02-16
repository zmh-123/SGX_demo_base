#include "SGX_demo1_t.h"  // 自动生成的头文件
#include "sgx_tcrypto.h"  // SGX 密码库
#include <string.h>

// 1. 定义一个固定的密钥 (128位 = 16字节)
// 在真实场景中，这个密钥应该通过远程认证(Remote Attestation)交换，而不是写死
const sgx_aes_gcm_128bit_key_t p_key = {
    0x22, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

// 2. 定义初始向量 (IV) - 12字节
// 真实场景中每次加密都应该随机生成一个新的 IV
const uint8_t p_iv[12] = { 0,0,0,0,0,0,0,0,0,0,0,0 };

// 实现 EDL 里定义的函数
sgx_status_t encrypt_message(const char* str,
    uint8_t* output_cipher,
    uint8_t* output_mac,
    size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;

    // 调用 SGX 提供的 AES-GCM 加密函数
    // 参数说明：
    // 1. 密钥
    // 2. 输入明文, 明文长度
    // 3. 输出密文
    // 4. IV, IV长度
    // 5. AAD (附加验证数据), AAD长度 (这里设为 NULL)
    // 6. 输出 MAC (验证标签)
    ret = sgx_rijndael128GCM_encrypt(&p_key,
        (const uint8_t*)str, (uint32_t)len,
        output_cipher,
        p_iv, 12,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)output_mac);

    return ret;
}

// 新增：解密函数
sgx_status_t decrypt_message(const uint8_t* cipher,
    size_t len,
    const uint8_t* mac,
    char* output_str)
{
    sgx_status_t ret = SGX_SUCCESS;

    // 1. 清空输出缓冲区 (是个好习惯)
    memset(output_str, 0, len + 1);

    // 2. 调用 AES-GCM 解密
    // 注意：解密时会同时验证 MAC 标签。如果密文被篡改，这里会直接返回错误！
    ret = sgx_rijndael128GCM_decrypt(&p_key,
        cipher, (uint32_t)len,
        (uint8_t*)output_str, // 输出明文
        p_iv, 12,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)mac);

    return ret;
}