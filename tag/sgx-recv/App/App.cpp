#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstring>
#include <sstream>
#include <fstream>
#include <sys/time.h>
using namespace std;
using namespace std::chrono;

#include "common.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#define PORT 8080

#include "Enclave_u.h"
#include "sgx_urts.h"

#ifndef TRUE
#   define TRUE 1
#endif

#ifndef FALSE
#   define FALSE 0
#endif


sgx_enclave_id_t global_eid = 0;

void print_error_message(sgx_status_t ret) {
    printf("SGX error code: %d\n", ret);
}

void ocall_print(unsigned char *data)
{
    std::cout << data << std::endl;
}

string hexStr(uint8_t *data, int len)
{
    stringstream ss;
    ss << hex;

    for (int i(0); i < len; ++i)
    {
        ss << setw(2) << setfill('0') << (int)data[i] << " ";
    }
    return ss.str();
}

void ocall_print_uint8_array(uint8_t* array, size_t len) {
    for (int i = 0; i < len; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", array[i]);
    }
    printf("\n");
}

std::string makeFixedLength(const int i, const int length)
{
    std::ostringstream ostr;

    if (i < 0)
        ostr << '-';

    ostr << std::setfill('0') << std::setw(length) << (i < 0 ? -i : i);

    return ostr.str();
}

void print_time(){
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();

    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
    std::cout << nanoseconds << std::endl;

}


int initialize_enclave(sgx_enclave_id_t* eid, const std::string& launch_token_path, const std::string& enclave_name) {
    const char* token_path = launch_token_path.c_str();
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    FILE* fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

bool is_ecall_successful(sgx_status_t sgx_status, const std::string& err_msg,
        sgx_status_t ecall_return_value) {
    if (sgx_status != SGX_SUCCESS || ecall_return_value != SGX_SUCCESS) {
        printf("%s\n", err_msg.c_str());
        print_error_message(sgx_status);
        print_error_message(ecall_return_value);
        return false;
    }
    return true;
}


int main(int argc, char const *argv[])
{
    int result;

    result = initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so");
    if (result < 0)
    {
        std::cout << "Initialization error" << std::endl;
        return 1;
    }

    int sock = 0, valread, client_fd;
    struct sockaddr_in serv_addr;
    char buffer[4096] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Error1\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "IP ADDR", &serv_addr.sin_addr) <= 0)
    {
        printf("Error 2\n");
        return -1;
    }

    if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0)
    {
        printf("Error 3\n");
        return -1;
    }

    sgx_status_t ecall_status;
    sgx_status_t status;

    status = manage_rsa(global_eid, &ecall_status);

    size_t encMessageLen = 20;
    valread = read(sock, buffer, encMessageLen);

    /* public key sending */
    size_t pbkeyMessageLen = sizeof(struct pk_send_s);
    char *pbkeyMessage = (char *) malloc((pbkeyMessageLen*sizeof(char)));
    cout << "Send PK " << endl;
    print_time();
    status = send_pbkey(global_eid, &ecall_status, pbkeyMessage, pbkeyMessageLen);
    print_time();

    send(sock, pbkeyMessage, pbkeyMessageLen, 0);

    /* Encrypting symmetric key with public key */
    size_t symkey_send_s_size = sizeof(struct symkey_send_s);
    size_t symMessageLen = symkey_send_s_size;
    char *symMessage = (char *) malloc((symMessageLen)*sizeof(char));

    valread = read(sock, buffer, symMessageLen);

    /* Receive symmetric key */
    cout << "Receiving Symmetric Key" << endl;
    print_time();
    status = receive_symkey(global_eid, &ecall_status, buffer, symMessageLen);
    print_time();

    /* Sending Info message */
    //cout << "Sending info messages" << endl;
    size_t messageLen = sizeof(struct info_msg_s) + 28; // + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;
    char *message = (char *) malloc(messageLen * sizeof(char));
    //status = send_infomessage(global_eid, &ecall_status, message, messageLen);
    //print_time();

    valread = read(sock, buffer, messageLen);

    /* Receiving Info message */
    cout << "Receiving info messages" << endl;
    print_time();
    size_t rcvdMessageLen = sizeof(struct info_msg_s) + 28;
    char *rcvdMessage = (char *)malloc((rcvdMessageLen)*sizeof(char));

    status = rcvd_infomessage(global_eid, &ecall_status, buffer, messageLen);

    print_time();

    char finalMsg[10] = "Done\0";
    send(sock, finalMsg, strlen(finalMsg), 0);

    sgx_destroy_enclave(global_eid);
    free (rcvdMessage);
    free (symMessage);
    free (message);
    free (pbkeyMessage);
    return 0;
}
