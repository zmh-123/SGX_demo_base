#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>
#include "sgx_urts.h"
#include "SGX_demo1_u.h" // 自动生成的不可信桥接头文件

#define ENCLAVE_FILE _T("SGX_demo1.signed.dll")

// 辅助函数：打印十六进制数组
void print_hex(const char* label, const uint8_t* buffer, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buffer[i]);
    }
    printf("\n");
}

int main()
{
    // ... 初始化和加载 Enclave 的代码保持不变 ...
    sgx_enclave_id_t eid;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = { 0 };
    int updated = 0;
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) { printf("Load Failed\n"); return -1; }
    printf("App: Enclave loaded! ID: %llu\n", eid);

    // 1. 准备数据
    const char* original_msg = "Intel SGX is amazing!";
    size_t len = strlen(original_msg);

    // 分配内存
    uint8_t* cipher_buffer = new uint8_t[len];
    uint8_t mac_buffer[16] = { 0 };
    char* decrypted_buffer = new char[len + 1]; // +1 为了放字符串结束符 '\0'
    memset(decrypted_buffer, 0, len + 1);

    sgx_status_t ecall_ret;

    printf("\n--- Step 1: Encryption ---\n");
    printf("Original: %s\n", original_msg);

    // 2. 加密
    ret = encrypt_message(eid, &ecall_ret, original_msg, cipher_buffer, mac_buffer, len);

    if (ret == SGX_SUCCESS && ecall_ret == SGX_SUCCESS) {
        printf("Encrypt Success!\n");
        print_hex("Cipher", cipher_buffer, len);
        print_hex("MAC   ", mac_buffer, 16);
    }
    else {
        printf("Encrypt Failed!\n");
        return -1;
    }

    printf("\n--- Step 2: Decryption ---\n");

    // 3. 解密 (把刚才生成的密文和MAC传回去)
    ret = decrypt_message(eid, &ecall_ret, cipher_buffer, len, mac_buffer, decrypted_buffer);

    if (ret == SGX_SUCCESS && ecall_ret == SGX_SUCCESS) {
        printf("Decrypt Success!\n");
        printf("Restored: %s\n", decrypted_buffer);

        // 简单的正确性校验
        if (strcmp(original_msg, decrypted_buffer) == 0) {
            printf("\n[RESULT] Verification PASSED! Data matches perfectly.\n");
        }
        else {
            printf("\n[RESULT] Verification FAILED! Data mismatch.\n");
        }
    }
    else {
        printf("Decrypt Failed! Error code: 0x%x\n", ecall_ret);
        // 如果你修改了 mac_buffer 里的任意一个字节再解密，这里就会报错，你可以试试！
    }

    // 清理
    delete[] cipher_buffer;
    delete[] decrypted_buffer;
    sgx_destroy_enclave(eid);

    getchar();
    return 0;
}