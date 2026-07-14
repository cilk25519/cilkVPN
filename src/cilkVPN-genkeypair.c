#include "./third_party/eTNaCl/etweetnacl.c"

int main() {
    unsigned char ed25519_secret_key[ crypto_sign_SECRETKEYBYTES ];
    unsigned char ed25519_public_key[ crypto_box_PUBLICKEYBYTES ];
    crypto_sign_keypair( ed25519_public_key, ed25519_secret_key );
	
	PRINT_HEX_NOSPACE(ed25519_secret_key, 32)
	printf("\n");
	
	PRINT_HEX_NOSPACE(ed25519_public_key, crypto_box_PUBLICKEYBYTES)
	printf("\n");
	
	PRINT_HEX_NOSPACE(ed25519_secret_key, crypto_sign_SECRETKEYBYTES)
	printf("\n");

    return 0;
}