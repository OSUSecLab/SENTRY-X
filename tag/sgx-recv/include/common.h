#ifndef COMMON_H_
#define COMMON_H_

#define KEY_SIZE 16
#define KEYSEAL_FILE "DSK-VRK.seal"
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12
#define MAX_ENC_MSG_SIZE 2048
//#define BSM_SIZE 2100
#define SIG_SIZE 400
#define RSA_SIZE 4096

#include "sgx_tcrypto.h"
#include "signmsg/src/signmsg.h"

struct GPSloc{
    float latitude;
    float longitude;
};

struct info_s
{
    // default 100
    char bsm[100];
    int ts;
    struct GPSloc loc;
    int tag;
};

struct pk_send_s
{
    int payload;
    uint8_t pubmod[1000];
    uint8_t pube[100];
    uint8_t sig[SIG_SIZE];
    size_t sig_size;
};

struct symkey_send_s
{
    int payload;
    uint8_t symkey[512];
    size_t symkeylen;
    uint8_t sig[512];
    size_t sig_size;
};

struct info_msg_s
{
    int tag;
    struct info_s info;
};

struct hash_s
{
    uint8_t symkey[16];
    int rand;
};
#endif // COMMON_H
