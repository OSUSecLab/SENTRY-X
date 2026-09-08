
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
#include <unordered_map>
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


struct symkey_store_s
{
    uint8_t key[16];
    uint8_t sig[400];
    int ts;
};
std::unordered_map<int, symkey_store_s> symkey_list;

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

EpidSignature *sig = NULL;
size_t sig_size = 0;

uint8_t sig_pout[100] = {0, };
size_t sig_pout_size = SGX_RSA3072_PUB_EXP_SIZE;

sgx_status_t manage_rsa(void)
{

    verify_init(basename_str, basename_size, signed_priv_rl, signed_priv_rl_size,
            signed_sig_rl, signed_sig_rl_size, signed_grp_rl, signed_grp_rl_size,
            signed_pubkey, signed_pubkey_size, &cacert, &verifier_precmp, &vprecmpi_file_size);

    sign_init(basename_str, basename_size, signed_sig_rl,
            signed_sig_rl_size, signed_pubkey, signed_pubkey_size, mprivkey,
            mprivkey_size, member_precmp_ptr, &sig, &sig_size, &cacert);

    sgx_status_t ret;

    unsigned char n[512];
    unsigned char d[512];
    unsigned char p[512];
    unsigned char q[512];
    unsigned char dmp1[512];
    unsigned char dmq1[512];
    unsigned char iqmp[512];

    int n_byte_size = 512;
    int e_byte_size = 4;
    long e = 65537;
    ret = sgx_create_rsa_key_pair(n_byte_size, e_byte_size, n, d, (unsigned char *)&e, p, q, dmp1, dmq1, iqmp);

    void* new_pri_key2;
    ret = sgx_create_rsa_priv2_key(n_byte_size, e_byte_size, (unsigned char *)&e, p, q, dmp1, dmq1, iqmp, (void **)&new_pri_key2);

    void* new_pub_key1[512];
    ret = sgx_create_rsa_pub1_key(n_byte_size, e_byte_size, n, (unsigned char *)&e, new_pub_key1);

    memcpy(pubmod, n, n_byte_size);
    memcpy(pube, (unsigned char*)&e, e_byte_size);


    if (payload == 0)
        payload = 1;
    else
        payload = 0;

    curr_priv_key = new_pri_key2;
    struct symkey_store_s temp_key;
    temp_key.key[0] = 0x1;
    temp_key.key[1] = 0x1;
    temp_key.key[2] = 0x1;
    temp_key.key[3] = 0x1;
    temp_key.key[4] = 0x1;
    temp_key.key[5] = 0x1;
    temp_key.key[6] = 0x1;
    temp_key.key[7] = 0x1;
    temp_key.key[8] = 0x1;
    temp_key.key[9] = 0x1;
    temp_key.key[10] = 0x1;
    temp_key.key[11] = 0x1;
    temp_key.key[12] = 0x1;
    temp_key.key[13] = 0x1;
    temp_key.key[14] = 0x1;
    temp_key.key[15] = 0x1;
    temp_key.ts = 10;

    int k = 100;
    for (int i=0; i<0; i++)
    {
        symkey_list[k++] = temp_key;
    }

    EpidStatus result = kEpidErr;
    memcpy(sig_pout, pube, 4);

    result = SignMsg(sig_pout, sig_pout_size, basename_str, basename_size, signed_sig_rl,
            &sig, &sig_size);
    return;
}




sgx_status_t send_pbkey(char *encMessageOut, size_t encMessageOutLen)
{
    uint8_t pout[100] = {0, };
    size_t pout_size = SGX_RSA3072_PUB_EXP_SIZE;
    memcpy(pout, pube, SGX_RSA3072_PUB_EXP_SIZE);

    // send public key
    struct pk_send_s outmessage;
    outmessage.payload = payload;
    memcpy(outmessage.pubmod, pubmod, 512);
    memcpy(outmessage.pube, pube, SGX_RSA3072_PUB_EXP_SIZE);
    memcpy(outmessage.sig, (unsigned long *)sig, sig_size);
    outmessage.sig_size = (size_t)sig_size;
    memcpy(encMessageOut, &outmessage, encMessageOutLen);
    return SGX_SUCCESS;
}

sgx_status_t send_symkey(char *MessageIn, size_t MessageInLen, char *encMessageOut, size_t encMessageOutLen)
{
    return SGX_SUCCESS;
}



sgx_status_t receive_symkey(char *encMessageIn, size_t encMessageLen)
{
    struct symkey_send_s *rcvdmessage = (symkey_send_s *)encMessageIn;
    size_t encrypt_len = 0;
    encrypt_len = rcvdmessage->symkeylen;
    uint8_t *encrypt = rcvdmessage->symkey;

    sig_size = rcvdmessage->sig_size;
    unsigned char orig_sig[512], enc_sig[512];
    uint8_t pout[512] = {0, };
    size_t pout_size = sizeof(pout);
    memcpy(enc_sig, rcvdmessage->sig, sizeof(enc_sig));

    sgx_status_t ret = sgx_rsa_priv_decrypt_sha256(curr_priv_key, (unsigned char *)orig_sig, &pout_size, (unsigned char *)enc_sig, 512);

    int payload_idx = rcvdmessage->payload;

    if (payload == payload_idx)
    {
        pout_size = 512;
        ret = sgx_rsa_priv_decrypt_sha256(curr_priv_key, (unsigned char*)pout, &pout_size, (unsigned char *)encrypt, encrypt_len);
    }
    else
    {
        return ;
    }

    symkey_store_s symkey;
    memcpy(symkey.key, pout, 16);
    int tag;
    memcpy(&tag, pout+16, 4);

    auto it = symkey_list.find(tag);

    if (it != symkey_list.end())
        return ;

    symkey_list.insert({tag, symkey});
    symkey.ts = 10; // current time

    sig = (EpidSignature *)orig_sig;

    EpidStatus result = kEpidErr;
    result = Verify(sig, sig_size, symkey.key, sizeof(symkey.key), signed_priv_rl,
            signed_sig_rl, signed_grp_rl,
            ver_rl, ver_rl_size);

    if (kEpidNoErr != result)
    {
        printf("verfiy fails %d", result);
    }

    memcpy(symkey.sig, sig, sig_size);
    return SGX_SUCCESS;
}


sgx_status_t send_infomessage(char *encMessageOut, size_t encMessageLen)
{
    return SGX_SUCCESS;
}

sgx_status_t rcvd_infomessage(char *messageIn, size_t MessageInLen)
{
    struct info_msg_s *message = (info_msg_s *)messageIn;
    sgx_status_t status;

    int tag = message->tag;

    auto it = symkey_list.find(tag);


    if (it == symkey_list.end())
        return ;

    uint8_t *rcvdEncMessage = (uint8_t *) &(message->info);
    uint8_t p_dst[2048] = {0};


    status = sgx_rijndael128GCM_decrypt(
            &(it->second.key),
            rcvdEncMessage + 16 + 12,
            sizeof(struct info_s),
            //strlen(message->bsm),
            p_dst,
            rcvdEncMessage + 16, 12, NULL, 0,
            (const sgx_aes_gcm_128bit_tag_t *) rcvdEncMessage);


    info_s *temp = (struct info_s *)p_dst;

    if (tag != int(temp->tag))
    {
        return ;
    }

    printf("Decrypted %d %s", status, temp->bsm);

    return status;
}
