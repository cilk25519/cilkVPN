#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tweetnacl.h"
#include "tweetnacl.c"

#define PRINT_HEX_SPACE(s_2_print, len_s_2_print) for (int i=0; i < len_s_2_print; i++) { printf("%02x ", s_2_print[i]); }
#define PRINT_HEX_NOSPACE(s_2_print, len_s_2_print) for (int i=0; i < len_s_2_print; i++) { printf("%02x", s_2_print[i]); }
#define PRINT_HEX(s_2_print, len_s_2_print, with_space) PRINT_HEX_##with_space(s_2_print, len_s_2_print)
#define PRINT_NONCE( s_2_print, with_space ) printf("Nonce (%d): ", crypto_box_NONCEBYTES); PRINT_HEX( s_2_print, crypto_box_NONCEBYTES, with_space ); printf("\n");
#define PRINT_SKIP_0_BYTES( s_2_print, len_s_2_print ) for (int i = crypto_box_ZEROBYTES; i < len_s_2_print; i++) { printf("%c", s_2_print[i] ); }
#define PRINT_STRING_WITH_LABEL( label, s_2_print, len_s_2_print ) printf("%s", label); for (int i = 0; i < len_s_2_print; i++) { printf("%c", s_2_print[i] ); } printf("\n"); 
#define PRINT_MESSAGE_SKIP_0_BYTES( s_2_print, len_s_2_print ) printf("Message: "); PRINT_SKIP_0_BYTES( s_2_print, len_s_2_print ); printf("\n"); 
#define PRINT_MESSAGE_AND_CRYPTO_BOX_AS_HEX( m_2_print, c_2_print, len_2_print, with_space ) printf("   Message (%llu): ", len_2_print); \
    PRINT_HEX( m_2_print, len_2_print, with_space ); \
	printf("\n"); \
	printf("Crypto box (%llu): ", len_2_print); \
	PRINT_HEX( c_2_print, len_2_print, with_space ); \
	printf("\n");
#define PRINT_X25519_KEYPAIR( secret_key_2_print, public_key_2_print, with_space ) printf("X25519 Secret key (%d): ", crypto_box_SECRETKEYBYTES); \
    PRINT_HEX( secret_key_2_print, crypto_box_SECRETKEYBYTES, with_space ); \
	printf("\n"); \
	printf("X25519 Public key (%d): ", crypto_box_PUBLICKEYBYTES); \
	PRINT_HEX( public_key_2_print, crypto_box_PUBLICKEYBYTES, with_space ); \
	printf("\n");
#define PRINT_ED25519_KEYPAIR( secret_key_2_print, public_key_2_print, with_space ) printf("Ed25519 Secret key (%d): ", crypto_sign_SECRETKEYBYTES); \
    PRINT_HEX( secret_key_2_print, crypto_sign_SECRETKEYBYTES, with_space ); \
	printf("\n"); \
	printf("Ed25519 Public key (%d): ", crypto_sign_PUBLICKEYBYTES); \
	PRINT_HEX( public_key_2_print, crypto_sign_PUBLICKEYBYTES, with_space ); \
	printf("\n");
#define PRINT_HEX_WITH_LABLE( label, s_2_print, len_s_2_print, with_space ) printf("%s (%llu): ", label, (unsigned long long) (len_s_2_print)); \
    PRINT_HEX(s_2_print, (unsigned long long)(len_s_2_print), with_space) \
	printf("\n");
#define PRINT_IDENTITY_PUBLIC_KEY_AND_MESSAGE( s_2_print, len_s_2_print, with_space ) \
     unsigned char* pub_2_print = s_2_print + crypto_box_PUBLICKEYBYTES; \
	 unsigned long long len_2_print = len_s_2_print - crypto_box_PUBLICKEYBYTES; \
	 printf("Ed25519 Public key (%d): ", crypto_sign_PUBLICKEYBYTES); \
	 PRINT_HEX( s_2_print, crypto_sign_PUBLICKEYBYTES, with_space ); \
	 printf("\n");\
	 PRINT_STRING_WITH_LABEL( "Message: ", pub_2_print, len_2_print )

int crypto_sign_ed25519_pk_to_curve25519(u8 *z, u8 *ed25519pk) {
    gf q[4];
    gf a, b;
    
    if (unpackneg(q, ed25519pk)) return -1;
    
    A(a, gf1, q[1]);
    Z(b, gf1, q[1]);
    inv25519(b, b);
    M(a, a, b);
    
    pack25519(z, a);
    
    return 0;
}

int crypto_sign_ed25519_sk_to_curve25519(u8 *o, u8 *ed25519sk) {
    u8 d[64];
    int i;
    
    crypto_hash(d, ed25519sk, 32);
    
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    
    FOR(i,32) o[i] = d[i];
    FOR(i,64) d[i] = 0;
    
    return 0;
}

void randombytes(u8* buf,u64 len) {
    srand( arc4random() );

    for (int i = 0; i < len; i++) {
        buf[i] = rand();
    }
}

int hex_to_bytes(const char *src, unsigned char *dst) {
    size_t len = strlen(src);
    if (len % 2 != 0) return -1;
    
    for (size_t i = 0; i < len / 2; i++) {
        if (sscanf(&src[i * 2], "%2hhx", &dst[i]) != 1) {
            return -1;
        }
    }
	
    return 0;
}

int crypto_sign_keypair_from_sk32(u8 *pk, u8 *sk, char* hex) {
    hex_to_bytes(hex, sk);
    
    u8 d[64];
    gf p[4];
    int i;
    
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    
    scalarbase(p,d);
    pack(pk,p);
    
    FOR(i,32) sk[32 + i] = pk[i];
    return 0;
}

int crypto_sign_keypair_from_sk64(u8 *pk, u8 *sk, char* hex) {
    hex_to_bytes(hex, sk);
    memcpy(pk, sk + 32, 32);
    return 0;
}