#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bbs.h"
#include "hash.h"
#include "v2v.h"
#include <pbc/pbc_test.h>

#include <pthread.h>
#include <sys/socket.h>
#include <list>
#include <algorithm>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <openssl/aes.h>
#include <ctime>
#include <chrono>
#include <functional>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define N 2


using namespace std;

bbs_sys_param_t sp;
bbs_group_public_key_t gpk;
bbs_manager_private_key_t gmsk;
bbs_group_private_key_t gsk[N];
pairing_t pairing;

list <struct complete_msg> queue[N];
list <struct symkey_s> sym_list[N];
list <struct bsm_msg> bsm[N];

int total_count = 0;
pthread_mutex_t lock;

void* send_pbkey(void *arg)
{
    struct pubkey_set pub;
    memcpy(&pub, arg, sizeof(struct pubkey_set));

    int count = 0;
    int id = pub.id;
    struct pubkey_msg msg;
    msg.id = 1;
    memcpy(msg.pubkey, pub.pubkey, pub.len);
    memcpy(msg.sig, pub.sig, sp->signature_length);
    msg.pub_len = pub.len;

    struct complete_msg complete;
    memcpy(&complete, &msg, sizeof(struct pubkey_msg));
    while (1)
    {
        sleep(1);
        for (int j=0; j<N; j++)
        {
            if (j == id) continue;
            queue[j].push_back(complete);
        }
        count += 1;
    }
}

void* send_bsm(void *arg)
{
    struct bsm_send info;
    memcpy(&info, arg, sizeof(struct bsm_send));

    char *text = "I am here";
    AES_KEY enc_key;
    unsigned char enc_out[80];
    auto start = chrono::high_resolution_clock::now();
    AES_set_encrypt_key((const unsigned char *)info.key, 128, &enc_key);
    AES_encrypt((const unsigned char *)text, enc_out, &enc_key);

    struct sk_hash hash_val;
    hash_val.R = info.id;
    memcpy(hash_val.symkey, info.key, 32);

    struct bsm_msg msg;
    const size_t seed = 0;
    msg.ts = 123;
    msg.R = info.id;
    msg.hash_val = _Hash_bytes(&hash_val, sizeof(hash_val), seed);
    memcpy(msg.msg, enc_out, 80);

    if (info.id == 0)
    {
        auto stop = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::nanoseconds>(stop - start);
        printf("send bsm %ld\n", duration.count());
    }

    while (1)
    {
        sleep(3);
        for (int i=0; i<N; i++)
        {
            if (i == info.id) continue;
            bsm[i].push_back(msg);
        }
    }
}

void* recv_bsm(void *arg)
{
    int id = *(int *)arg;
    AES_KEY dec_key;
    unsigned char dec_out[80];
    const size_t seed = 0;
    int record_flag = 0;

    while (1)
    {
        if (bsm[id].size() > 0)
        {
            //printf("%d recv bsm\n", id);
            struct bsm_msg msg = bsm[id].front();
            bsm[id].pop_front();

            char key[32];
            struct sk_hash hash_val;
            hash_val.R = msg.R;
            int flag = 0;
            auto start = chrono::high_resolution_clock::now();
            for (const auto &element: sym_list[id])
            {
                memcpy(hash_val.symkey, element.key, 32);
                if (msg.hash_val == _Hash_bytes(&hash_val, sizeof(hash_val), seed))
                {
                    memcpy(key, element.key, 32);
                    flag = 1;
                }
            }

            if (flag == 0)
                continue;

            AES_set_decrypt_key((const unsigned char *)key, 128,&dec_key);
            AES_decrypt((const unsigned char*)msg.msg, dec_out, &dec_key);

            if (id == 0 && record_flag == 0)
            {
                auto stop = chrono::high_resolution_clock::now();
                auto duration = chrono::duration_cast<chrono::nanoseconds>(stop - start);
                printf("recv bsm %ld\n", duration.count());
                record_flag = 1;
            }
        }
    }
}

void* protocol(void* arg)
{
    int id = *(int *)arg;
    char key[32];
    time_t now;
    time(&now);
    srand(now+id);

    pthread_attr_t attr;
    int result = pthread_attr_init(&attr);
    result = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    for (int i=0; i<32; i++)
    {
        key[i] = (char)(rand() % 256);
    }

    size_t pri_len;
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message

    list <struct pubkey_s> pub_list;

    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    unsigned char *sig;
    sig = (unsigned char *) pbc_malloc(sp->signature_length);
    bbs_sign(sig, pub_len, pub_key, gpk, gsk[id]);

    unsigned char *sym_sig;
    sym_sig = (unsigned char *) pbc_malloc(sp->signature_length);
    bbs_sign(sym_sig, 32, key, gpk, gsk[id]);




    struct pubkey_set pub_msg;
    strncpy(pub_msg.pubkey, pub_key, pub_len);
    memcpy(pub_msg.sig, sig, sp->signature_length);
    pub_msg.len = pub_len;
    pub_msg.id = id;

    BIO* bio = BIO_new_mem_buf(pub_key, pub_len);
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

    encrypt = (char *)malloc(RSA_size(rsa));
    int encrypt_len;

    bio = BIO_new_mem_buf(pri_key, pri_len);
    RSA* priv_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    decrypt = (char *)malloc(RSA_size(priv_rsa));

    encrypt_len = RSA_public_encrypt(32, (unsigned char*)key, (unsigned char*)encrypt, rsa, RSA_PKCS1_OAEP_PADDING);



    pthread_t pub_thread;
    pthread_create(&pub_thread, &attr, send_pbkey, &pub_msg);

    struct bsm_send info;
    info.id = id;
    memcpy(info.key, key, 32);
    pthread_t bsm_send_thread;
    pthread_create(&bsm_send_thread, &attr, send_bsm, &info);

    int bsm_id = id;
    pthread_t bsm_recv_thread;
    pthread_create(&bsm_recv_thread, &attr, recv_bsm, &bsm_id);

    struct complete_msg complete;
    int msg_type;
    while (1)
    {
        if (queue[id].size() > 0)
        {
            complete = queue[id].front();
            queue[id].pop_front();
            msg_type = (int)((char *)&complete)[0];

            // pubkey received
            if (msg_type == 1)
            {
                struct pubkey_msg pub_msg;
                memcpy(&pub_msg, &complete, sizeof(pubkey_msg));

                auto start = chrono::high_resolution_clock::now();
                result = bbs_verify((unsigned char*) pub_msg.sig, pub_msg.pub_len, pub_msg.pubkey, gpk);
                if (result) {

                    struct pubkey_s received_key;
                    strncpy(received_key.key, pub_msg.pubkey, pub_msg.pub_len);

                    int flag = 0;
                    for (const auto& element : pub_list)
                    {
                        if (strncmp(element.key, pub_msg.pubkey, pub_msg.pub_len) == 0)
                        {
                            flag = 1;
                            break;
                        }
                    }

                    if (flag == 0 && id == 0)
                    {
                        auto stop = chrono::high_resolution_clock::now();
                        auto duration = chrono::duration_cast<chrono::nanoseconds>(stop - start);
                        printf("recv pub %ld\n", duration.count());
                    }


                    if (flag == 1)
                        continue;

                    pub_list.push_back(received_key);

                    BIO* bio = BIO_new_mem_buf(pub_msg.pubkey, pub_msg.pub_len);
                    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

                    start = chrono::high_resolution_clock::now();

                    encrypt_len = RSA_public_encrypt(32, (unsigned char*)key, (unsigned char*)encrypt, rsa, RSA_PKCS1_OAEP_PADDING);
                    char   *sig_encrypt1 = NULL;    // Encrypted message
                    char   *sig_encrypt2 = NULL;    // Encrypted message
                    char sig_1[350], sig_2[100];
                    int sig_encrypt_len1, sig_encrypt_len2;
                    struct symkey_msg sym_msg;


                    memcpy(sig_1, sym_sig, 200);
                    memcpy(sig_2, sym_sig+200, 94);

                    sig_encrypt1 = (char *)malloc(RSA_size(rsa));
                    sig_encrypt2 = (char *)malloc(RSA_size(rsa));
                    sig_encrypt_len1 = RSA_public_encrypt(200, (unsigned char*)sig_1, (unsigned char*)sig_encrypt1, rsa, RSA_PKCS1_OAEP_PADDING);
                    sig_encrypt_len2 = RSA_public_encrypt(94, (unsigned char*)sig_2, (unsigned char*)sig_encrypt2, rsa, RSA_PKCS1_OAEP_PADDING);

                    if (id == 0)
                    {
                        auto stop = chrono::high_resolution_clock::now();
                        auto duration = chrono::duration_cast<chrono::nanoseconds>(stop - start);
                        printf("send sym %ld\n", duration.count());
                    }

                    sym_msg.id = 2;
                    sym_msg.sym_len = encrypt_len;
                    memcpy(sym_msg.symkey, encrypt, encrypt_len);
                    memcpy(sym_msg.sig1, sig_encrypt1, 256);
                    memcpy(sym_msg.sig2, sig_encrypt2, 256);
                    struct complete_msg temp;
                    memcpy(&temp, &sym_msg, sizeof(struct symkey_msg));
                    for (int i=0; i<N; i++)
                    {
                        if (i==id) continue;
                        queue[i].push_back(temp);
                    }
                }
            }
            else if(msg_type == 2)
            {
                struct symkey_msg received_sym;
                memcpy(&received_sym, &complete, sizeof(symkey_msg));
                auto start = chrono::high_resolution_clock::now();
                if (RSA_private_decrypt(received_sym.sym_len, (unsigned char*)received_sym.symkey, (unsigned char*)decrypt, priv_rsa, RSA_PKCS1_OAEP_PADDING) != -1)
                {
                    char sig1[300], sig2[300], recv_sig[300];
                    if (RSA_private_decrypt(256, (unsigned char*)received_sym.sig1, (unsigned char*)sig1, priv_rsa, RSA_PKCS1_OAEP_PADDING) != -1)
                    {
                        if (RSA_private_decrypt(256, (unsigned char*)received_sym.sig2, (unsigned char*)sig2, priv_rsa, RSA_PKCS1_OAEP_PADDING) != -1)
                        {
                            memcpy(recv_sig, sig1, 200);
                            memcpy(recv_sig+200, sig2, 94);
                            result = bbs_verify((unsigned char*) recv_sig, 32, decrypt, gpk);
                            if (id == 0)
                            {
                                auto stop = chrono::high_resolution_clock::now();
                                auto duration = chrono::duration_cast<chrono::nanoseconds>(stop - start);
                                printf("recv sym %ld\n", duration.count());
                            }
                        }
                    }
                    if (!result)
                    {
                        printf("thread2 verify fail\n");
                        continue;
                    }
                }

                int flag = 0;
                for (const auto& element : sym_list[id])
                {
                    if (strncmp(element.key, decrypt, 32) == 0)
                    {
                        flag = 1;
                        break;
                    }
                }

                if (flag == 1)
                    continue;

                struct symkey_s received_key;
                strncpy(received_key.key, decrypt, 32);
                sym_list[id].push_back(received_key);
                pthread_mutex_lock(&lock);
                total_count += 1;
                pthread_mutex_unlock(&lock);
            }
        }
    }
}

int main(int argc, char **argv)
{
    unsigned char *sig;
    int result;

    FILE *curveFile = fopen("d201.param", "r");
    char param_string[16384];
    size_t count = fread(param_string, 1, 16384, curveFile);
    fclose(curveFile);
    pairing_init_set_buf(pairing, param_string, count);

    bbs_gen_sys_param(sp, pairing);

    bbs_gen(gpk, gmsk, N, gsk, sp);


    pthread_t threads[N];
    int ids[N];
    for (int i=0; i<N; i++)
    {
        ids[i] = i;
        pthread_create(&threads[i], NULL, protocol, &ids[i]);
    }

    for (int i=0; i<N; i++)
    {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

