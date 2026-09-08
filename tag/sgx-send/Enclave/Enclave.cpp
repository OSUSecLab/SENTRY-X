
#ifdef __cplusplus
extern "C" {
#endif
#include "signmsg/src/signmsg.h"
#include "verifysig/src/verifysig.h"
#include "openssl/crypto.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "sgx_tcrypto.h"
}
#include <map>
#include "prng.h"
#include "sgx_trts.h"
#include "common.h"
#include "Enclave_t.h"

EpidCaCertificate cacert = {
    0X02, 0X00, 0X00, 0X11, 0xE3, 0XF5, 0X5A, 0XBF, 0XF9, 0XE1, 0X8E, 0XAD, 0XC0, 0X38, 0XC0, 0XAB, 0X28, 0XA4, 0X80, 0X2A,
    0X09, 0X0D, 0X4D, 0XBE, 0X0C, 0X4F, 0X31, 0X92, 0X15, 0X1F, 0X2C, 0X9D, 0XB7, 0X12, 0X91, 0XC4, 0XE2, 0XE9, 0XAC, 0X1D,
    0X52, 0X29, 0X29, 0XDE, 0XE1, 0X1D, 0XFF, 0X40, 0XE2, 0XFC, 0X1A, 0X87, 0X0B, 0X17, 0XCF, 0X9C, 0XB7, 0X7E, 0X95, 0X9C,
    0XD6, 0X8B, 0X23, 0X93, 0XFE, 0XE1, 0X0C, 0XD6, 0XFF, 0XFF, 0XFF, 0XFF, 0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X00, 0X00,
    0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
    0XFF, 0XFF, 0XFF, 0XFF, 0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
    0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFC, 0X5A, 0XC6, 0X35, 0XD8, 0XAA, 0X3A, 0X93, 0XE7,
    0XB3, 0XEB, 0XBD, 0X55, 0X76, 0X98, 0X86, 0XBC, 0X65, 0X1D, 0X06, 0XB0, 0XCC, 0X53, 0XB0, 0XF6, 0X3B, 0XCE, 0X3C, 0X3E,
    0X27, 0XD2, 0X60, 0X4B, 0X6B, 0X17, 0XD1, 0XF2, 0XE1, 0X2C, 0X42, 0X47, 0XF8, 0XBC, 0XE6, 0XE5, 0X63, 0XA4, 0X40, 0XF2,
    0X77, 0X03, 0X7D, 0X81, 0X2D, 0XEB, 0X33, 0XA0, 0XF4, 0XA1, 0X39, 0X45, 0XD8, 0X98, 0XC2, 0X96, 0X4F, 0XE3, 0X42, 0XE2,
    0XFE, 0X1A, 0X7F, 0X9B, 0X8E, 0XE7, 0XEB, 0X4A, 0X7C, 0X0F, 0X9E, 0X16, 0X2B, 0XCE, 0X33, 0X57, 0X6B, 0X31, 0X5E, 0XCE,
    0XCB, 0XB6, 0X40, 0X68, 0X37, 0XBF, 0X51, 0XF5, 0XFF, 0XFF, 0XFF, 0XFF, 0X00, 0X00, 0X00, 0X00, 0XFF, 0XFF, 0XFF, 0XFF,
    0XFF, 0XFF, 0XFF, 0XFF, 0XBC, 0XE6, 0XFA, 0XAD, 0XA7, 0X17, 0X9E, 0X84, 0XF3, 0XB9, 0XCA, 0XC2, 0XFC, 0X63, 0X25, 0X51,
    0X5F, 0X96, 0XDC, 0XA2, 0X64, 0X58, 0X85, 0X67, 0X02, 0XBE, 0X71, 0X37, 0X4D, 0XE6, 0X80, 0X64, 0XAC, 0X57, 0X9B, 0XAC,
    0X24, 0X85, 0X48, 0X62, 0XBC, 0X38, 0X1A, 0XEC, 0X8E, 0X44, 0X02, 0XC3, 0XC1, 0XD6, 0X26, 0XBA, 0X1B, 0XB2, 0XBC, 0X23,
    0XD4, 0XFB, 0X4A, 0X4C, 0X20, 0X71, 0X13, 0X5E, 0XCD, 0X04, 0X1B, 0X6D, 0X8A, 0XDD, 0X35, 0XC7, 0X70, 0XEA, 0XA3, 0X37,
    0X5A, 0X24, 0X45, 0XD8
};

unsigned char pubkey[] = {
    0X02, 0X00, 0X00, 0X0C, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
    0X45, 0XCB, 0X06, 0X04, 0XB3, 0XF7, 0X23, 0XB2, 0XD1, 0XD1, 0X0D, 0X4F, 0X51, 0X7B, 0XBB, 0X8F, 0X71, 0X15, 0XD7, 0XF1,
    0XDC, 0X15, 0X37, 0XC8, 0XB8, 0X3D, 0X68, 0X0A, 0X18, 0XA5, 0X34, 0X14, 0X0C, 0XDC, 0XD9, 0X15, 0X7E, 0XBA, 0X56, 0XC5,
    0XE5, 0X61, 0XFA, 0X6A, 0X86, 0XA0, 0XAC, 0X6A, 0X81, 0X36, 0X6D, 0X01, 0X5F, 0X86, 0XC0, 0X04, 0X8B, 0X1E, 0XFF, 0X49,
    0XD9, 0X37, 0X96, 0X66, 0XF1, 0XC3, 0X16, 0XB5, 0XC5, 0X1C, 0X67, 0XB6, 0XFF, 0X28, 0X23, 0X79, 0X59, 0XEA, 0X80, 0XE6,
    0X09, 0X07, 0XE7, 0XD3, 0X38, 0XEC, 0XB9, 0X16, 0X83, 0X88, 0XDA, 0X64, 0XDD, 0XC4, 0X9D, 0X6A, 0X5C, 0XB2, 0X1C, 0X88,
    0X97, 0XEA, 0XAF, 0XA9, 0XF3, 0X3E, 0X07, 0XEA, 0XB6, 0X2A, 0XD5, 0X7A, 0XED, 0X32, 0XD9, 0X3D, 0X90, 0XD7, 0XB9, 0X91,
    0X08, 0X05, 0X9E, 0XE3, 0X22, 0X75, 0X06, 0X35, 0XE5, 0XC4, 0X77, 0XAD, 0X52, 0XB9, 0X7C, 0X04, 0X2D, 0X7E, 0X81, 0XF2,
    0X5D, 0X5D, 0X52, 0X7D, 0XD7, 0X1D, 0X29, 0XFB, 0X6A, 0XA7, 0XBC, 0XB5, 0XA9, 0X1A, 0XA6, 0XFD, 0X20, 0XEA, 0XF2, 0X98,
    0XE2, 0X67, 0X33, 0X28, 0X67, 0X5F, 0XBE, 0X23, 0XA0, 0X43, 0XE8, 0X71, 0XAA, 0XAB, 0XF6, 0XF0, 0X6A, 0X2B, 0X52, 0XA8,
    0X61, 0X51, 0X22, 0X44, 0X00, 0X91, 0XD7, 0XF1, 0X7E, 0X05, 0X48, 0XDC, 0X51, 0X0C, 0XEF, 0XA0, 0XF3, 0X72, 0XCD, 0X59,
    0XD4, 0X7A, 0X2A, 0X60, 0XA3, 0X62, 0X54, 0XA8, 0XB6, 0X8F, 0XED, 0X90, 0XDF, 0X3E, 0X94, 0XE8, 0XA4, 0X89, 0X32, 0XAA,
    0X52, 0X5A, 0X97, 0XAE, 0X4C, 0X86, 0XF4, 0XBA, 0XEC, 0XC6, 0X36, 0X13, 0X87, 0X42, 0X5D, 0X16, 0X49, 0X12, 0X66, 0XC5,
    0XE0, 0XE4, 0X9B, 0XF9, 0X68, 0XAA, 0XA9, 0X95, 0X81, 0X16, 0X5C, 0XD2, 0XCA, 0XD4, 0X2E, 0X61, 0X49, 0X2F, 0XBC, 0X95,
    0XAD, 0XF2, 0X74, 0XDB, 0X4A, 0X48, 0XA1, 0X88, 0XDB, 0XB1, 0X9D, 0X31, 0X9C, 0XD6, 0XC3, 0X93, 0X93, 0XFC, 0X55, 0XBD,
    0X54, 0XA6, 0X93, 0XC4, 0X49, 0XE1, 0XEE, 0XC3, 0XA4, 0X72, 0X43, 0X54, 0XD0, 0XD4, 0XE7, 0XD9, 0X09, 0X01, 0XCD, 0X3E,
    0XBF, 0XA5, 0X69, 0XC0, 0X16, 0X21, 0X5B, 0XC2, 0XEA, 0X5F, 0X21, 0XE2, 0XD8, 0X2B, 0X7F, 0XDD, 0XAD, 0X02, 0X6D, 0XCE
};

unsigned char privkey[] = {
0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X80, 0XA9, 0XCC, 0X67,
0X50, 0XCC, 0XAA, 0X0D, 0X65, 0X62, 0X24, 0X45, 0X73, 0X7C, 0XC5, 0X33, 0X4D, 0X69, 0XEA, 0X60, 0X65, 0XA9, 0XCD, 0X68,
0X28, 0X8D, 0X65, 0X6D, 0XDB, 0XBC, 0XA0, 0XB1, 0XEF, 0X18, 0X08, 0XED, 0X6B, 0XC0, 0X53, 0X51, 0XB9, 0XFA, 0X43, 0XA5,
0XB6, 0X4A, 0X05, 0XEC, 0XA3, 0XDB, 0X48, 0XDC, 0XDF, 0X38, 0XA6, 0X61, 0XEC, 0XB8, 0XB8, 0X6F, 0XE9, 0XA2, 0X10, 0X83,
0X27, 0X31, 0X1B, 0XD6, 0X36, 0XC9, 0X5D, 0X21, 0X9C, 0XBC, 0X81, 0XC0, 0XE2, 0XEF, 0XCC, 0X21, 0X19, 0X07, 0X42, 0X05,
0XF0, 0XB1, 0XC9, 0X9B, 0XC3, 0XA2, 0X8E, 0XD0, 0XD1, 0X2B, 0X58, 0X39, 0X49, 0XB7, 0XBE, 0X72, 0XF4, 0XA1, 0XB1, 0X0D,
0X3D, 0X73, 0XB1, 0X4C, 0XAF, 0XA7, 0XC4, 0X33, 0X5C, 0XA7, 0X85, 0X5F, 0XC8, 0XE1, 0X02, 0X9D, 0XD4, 0X9F, 0X8A, 0XB8,
0XF6, 0XA7, 0XA6, 0XC9
};


static unsigned int payload = 0;
static uint8_t rcvd_key[16];

struct sig_sym_s
{
    uint8_t sig[400];
    uint8_t sym[16];
};
std::vector<sig_sym_s> sig_sym_list;

struct symkey_store_s
{
    uint8_t key[16];
    int ts;
};
std::map<int, symkey_store_s> symkey_list;

struct pub_key_s
{
    uint8_t pubmod[1000];
    uint8_t pube[100];
    int ts;
};
std::vector<pub_key_s> pubkey_list;
void* curr_priv_key;
uint8_t pubmod[1000];
uint8_t pube[100];

int printf(const char* fmt, ...)
{
    char buf[1024] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return (int)strnlen(buf, 1024 - 1) + 1;
}

void* signed_priv_rl = NULL;
size_t signed_priv_rl_size = 0;

void* signed_grp_rl = NULL;
size_t signed_grp_rl_size = 0;

VerifierRl* ver_rl = NULL;
size_t ver_rl_size = 0;

void* verifier_precmp = NULL;
size_t vprecmpi_file_size = 0;

static char* basename_str = "vehicle";
size_t basename_size = sizeof(basename_str);

unsigned char* signed_sig_rl = NULL;
size_t signed_sig_rl_size = 0;



unsigned char* signed_pubkey = pubkey;
size_t signed_pubkey_size = sizeof(pubkey);

unsigned char* mprivkey = privkey;
size_t mprivkey_size = sizeof(privkey);

MemberPrecomp* member_precmp_ptr = NULL;

EpidSignature* sig = NULL;
size_t sig_size = 0;
uint8_t temp_key[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

sgx_status_t manage_rsa(void)
{
    verify_init(basename_str, basename_size, signed_priv_rl, signed_priv_rl_size,
            signed_sig_rl, signed_sig_rl_size, signed_grp_rl, signed_grp_rl_size,
            signed_pubkey, signed_pubkey_size, &cacert, &verifier_precmp, &vprecmpi_file_size);

    sign_init(basename_str, basename_size, signed_sig_rl,
            signed_sig_rl_size, signed_pubkey, signed_pubkey_size, mprivkey,
            mprivkey_size, member_precmp_ptr, &sig, &sig_size, &cacert);


    EpidStatus result = kEpidErr;
    result = SignMsg(temp_key, sizeof(temp_key), basename_str, basename_size, signed_sig_rl,
            &sig, &sig_size);
    return;
}


sgx_status_t send_symkey(char *MessageIn, size_t MessageInLen, char *encMessageOut, size_t encMessageOutLen)
{
    struct pk_send_s *message = (pk_send_s *)MessageIn;
    EpidStatus result = kEpidErr;
    char *symkey = (char *)temp_key;

    EpidSignature *ver_sig = NULL;
    size_t ver_sig_size;
    ver_sig = (EpidSignature *)message->sig;
    ver_sig_size = (size_t)message->sig_size;

    uint8_t *pube = message->pube;
    //size_t pube_size = SGX_RSA3072_PUB_EXP_SIZE;
    size_t pube_size = 4;

    result = Verify(ver_sig, ver_sig_size, pube, pube_size, signed_priv_rl,
        signed_sig_rl, signed_grp_rl, ver_rl, ver_rl_size);

    if (kEpidNoErr != result)
    {
        printf("verify fails %d\n", result);
    }


    pub_key_s pubkey_t;
    std::copy(std::begin(message->pubmod), std::end(message->pubmod), std::begin(pubkey_t.pubmod));
    std::copy(std::begin(message->pube), std::end(message->pube), std::begin(pubkey_t.pube));
    pubkey_t.ts = 10; // current time

    pubkey_list.push_back(pubkey_t);

    void *pub_key;
    sgx_status_t ret = sgx_create_rsa_pub1_key(512, 4,
            (unsigned char*)message->pubmod, (unsigned char*)message->pube,
            (void**)&pub_key);

    uint8_t pout[512] = {0, };
    size_t pout_size = sizeof(pout); //384;

    char comb[20];
    int tag = 1;
    memcpy(comb, temp_key, 16);
    memcpy(comb+16, &tag, 4);

    ret = sgx_rsa_pub_encrypt_sha256((void *)pub_key, (unsigned char*)pout, &pout_size, (unsigned char *)comb, 20); // 16 size of key

    unsigned char temp[512] = {0, };
    size_t temp_size = sizeof(temp);
    ret = sgx_rsa_pub_encrypt_sha256((void *)pub_key, temp, &temp_size, (unsigned char *)sig, sig_size);

    struct symkey_send_s sendmessage;
    size_t msg_size = sizeof(symkey_send_s);
    sendmessage.payload = message->payload;
    memcpy(sendmessage.symkey, pout, pout_size);
    sendmessage.symkeylen = pout_size;
    memcpy(sendmessage.sig, temp, temp_size);
    sendmessage.sig_size = sig_size;

    memcpy(encMessageOut, &sendmessage, encMessageOutLen);

    return SGX_SUCCESS;
}




sgx_status_t send_infomessage(char *encMessageOut, size_t encMessageLen)
{
    uint8_t temp_key[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

    char msg_str[90] = "it is the secret";
    struct info_msg_s message;
    message.tag = 1;


    struct info_s info_temp;
    memcpy(info_temp.bsm, msg_str, strlen(msg_str)+1);
    info_temp.ts = 10; // curr_time
    info_temp.loc.latitude = 1;
    info_temp.loc.longitude = 2;
    info_temp.tag = message.tag;

    uint8_t p_dst[2048] = {0};


    sgx_read_rand(p_dst + 16, 12);
    sgx_status_t status = sgx_rijndael128GCM_encrypt(
            &temp_key, (const uint8_t *) &info_temp, sizeof(info_s),
            p_dst + 16 + 12, p_dst + 16, 12, NULL, 0,
            (const sgx_aes_gcm_128bit_tag_t *) (p_dst));

    memcpy(&message.info, p_dst, sizeof(info_s) + 28);
    memcpy(encMessageOut, &message, encMessageLen);

    return status;
}

sgx_status_t rcvd_infomessage(char *messageIn, size_t MessageInLen)
{
    return SGX_SUCCESS;
}

sgx_status_t send_pbkey(char *encMessageOut, size_t encMessageOutLen)
{
    return SGX_SUCCESS;
}

sgx_status_t receive_symkey(char *encMessageIn, size_t encMessageLen)
{
    return SGX_SUCCESS;
}
