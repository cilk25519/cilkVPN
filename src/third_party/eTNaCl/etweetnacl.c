#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tweetnacl.h"
#include "tweetnacl.c"

#define PRINT_HEX(s_2_print, len_s_2_print) for (int i=0; i < len_s_2_print; i++) { printf("%02x", s_2_print[i]); }
#define PRINT_STRING_SKIP_0_BYTES_WITH_LABEL( label, s_2_print, len_s_2_print ) \
    printf("%s", label); \
	for (int i = crypto_box_ZEROBYTES; i < len_s_2_print; i++) { printf("%c", s_2_print[i] ); } \
	printf("\n");
#define PRINT_STRING_WITH_LABEL( label, s_2_print, len_s_2_print ) printf("%s", label); for (int i = 0; i < len_s_2_print; i++) { printf("%c", s_2_print[i] ); } printf("\n");
#define PRINT_NONCE( s_2_print ) printf("Nonce (%d): ", crypto_box_NONCEBYTES); PRINT_HEX( s_2_print, crypto_box_NONCEBYTES ); printf("\n");
#define PRINT_X25519_KEYPAIR( secret_key_2_print, public_key_2_print ) printf("X25519 Secret key (%d): ", crypto_box_SECRETKEYBYTES); \
    PRINT_HEX( secret_key_2_print, crypto_box_SECRETKEYBYTES ); \
	printf("\n"); \
	printf("X25519 Public key (%d): ", crypto_box_PUBLICKEYBYTES); \
	PRINT_HEX( public_key_2_print, crypto_box_PUBLICKEYBYTES ); \
	printf("\n");
#define PRINT_ED25519_KEYPAIR( secret_key_2_print, public_key_2_print ) printf("Ed25519 Secret key (%d): ", crypto_sign_SECRETKEYBYTES); \
    PRINT_HEX( secret_key_2_print, crypto_sign_SECRETKEYBYTES ); \
	printf("\n"); \
	printf("Ed25519 Public key (%d): ", crypto_sign_PUBLICKEYBYTES); \
	PRINT_HEX( public_key_2_print, crypto_sign_PUBLICKEYBYTES ); \
	printf("\n");
#define PRINT_MESSAGE_AND_CRYPTO_BOX_AS_HEX( m_2_print, c_2_print, len_2_print ) \
    printf("   Message (%llu): ", len_2_print); \
    PRINT_HEX( m_2_print, len_2_print ); \
	printf("\n"); \
	printf("Crypto box (%llu): ", len_2_print); \
	PRINT_HEX( c_2_print, len_2_print ); \
	printf("\n");
#define PRINT_HEX_WITH_LABLE( label, s_2_print, len_s_2_print ) \
    printf("%s (%llu): ", label, (unsigned long long) (len_s_2_print)); \
    PRINT_HEX(s_2_print, (unsigned long long)(len_s_2_print)) \
    printf("\n");
#define PRINT_IDENTITY_PUBLIC_KEY_AND_MESSAGE( s_2_print, len_s_2_print ) \
    unsigned char* pub_2_print = s_2_print + crypto_box_PUBLICKEYBYTES; \
    unsigned long long len_2_print = len_s_2_print - crypto_box_PUBLICKEYBYTES; \
    printf("Ed25519 Public key (%d): ", crypto_sign_PUBLICKEYBYTES); \
    PRINT_HEX( s_2_print, crypto_sign_PUBLICKEYBYTES ); \
    printf("\n");\
    PRINT_STRING_WITH_LABEL( "Message: ", pub_2_print, len_2_print )

void randombytes(u8* buf,u64 len) {
	arc4random_buf(buf, len);
}

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

int crypto_sign2(u8 *sm,const u8 *m,u64 n,const u8 *sk) {
  u8 d[64],h[64],r[64];
  i64 i,j,x[64];
  gf p[4];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  FOR(i,n) sm[64 + i] = m[i];
  FOR(i,32) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm+32, n+32);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);

  FOR(i,32) sm[i+32] = sk[i+32];
  crypto_hash(h,sm,n + 64);
  reduce(h);

  FOR(i,64) x[i] = 0;
  FOR(i,32) x[i] = (u64) r[i];
  FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
  modL(sm + 32,x);

  return 0;
}

int crypto_sign_open2(u8 *m,const u8 *sm,u64 n,const u8 *pk) {
  int i;
  u8 t[32],h[64];
  gf p[4],q[4];

  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  FOR(i,n) m[i] = sm[i];
  FOR(i,32) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    FOR(i,n) m[i] = 0;
    return -1;
  }

  FOR(i,n) m[i] = sm[i + 64];

  return 0;
}