#include <openssl/evp.h>
#include <openssl/err.h>

void dump(unsigned char* data, size_t length) {
    for (int i = 0; i < length; i++) {
        unsigned char e = data[i];
        printf("%#04x ", e);
    }

    printf("%s", "\n");
}

int main() {
    EVP_PKEY* selfKey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");

    if (selfKey == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    EVP_PKEY* peerKey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");

    if (peerKey == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, selfKey, NULL);

    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    if (EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer(ctx, peerKey) != 1) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    unsigned char derivedKeyBuf[1024];
    size_t derivedKeyLen = 1024;

    if (EVP_PKEY_derive(ctx, derivedKeyBuf, &derivedKeyLen) != 1) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    dump(derivedKeyBuf, derivedKeyLen);
}