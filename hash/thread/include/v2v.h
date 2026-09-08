
struct pubkey_set{
    char pubkey[450];
    char sig[300];
    int len;
    int id;
};

struct pubkey_s{
    char key[450];
};

struct symkey_s{
    char key[40];
};

struct pubkey_msg{
    int id;
    char pubkey[450];
    int pub_len;
    char sig[300];
};

struct symkey_msg{
    int id;
    char symkey[280];
    int sym_len;
    char sig1[300];
    char sig2[300];
};

struct complete_msg{
    char msg[950];
};

struct sk_hash{
    int R;
    char symkey[32];
};

struct bsm_send{
    int id;
    char key[32];
};

struct bsm_msg{
    char msg[150];
    int R;
    size_t hash_val;
    int ts;
};
