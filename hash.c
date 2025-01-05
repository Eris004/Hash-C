#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

void generate_hash(const char *text, const char *algorithm) {
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (md == NULL) {
        printf("Unknown algorithm: %s\n", algorithm);
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    EVP_DigestUpdate(mdctx, text, strlen(text));

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    EVP_MD_CTX_free(mdctx);

    printf("Hash: ");
    for (unsigned int i = 0; i < hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

int main() {
    char text[256], algorithm[50];

    printf("Enter text to hash: ");
    fgets(text, 256, stdin);
    text[strcspn(text, "\n")] = 0;

    printf("Enter hash algorithm (default sha256): ");
    fgets(algorithm, 50, stdin);
    algorithm[strcspn(algorithm, "\n")] = 0;

    if (strlen(algorithm) == 0) strcpy(algorithm, "sha256");

    generate_hash(text, algorithm);

    return 0;
}
