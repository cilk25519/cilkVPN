/*
clang ./cilkVPN.2.c -O3 -o ./cilkVPN

========== Peer 1 conf ==========
[Interface]
ListenPort = 3342
PrivateKey = ff4cb24de001f7970abe632ac9eeda89452b71042b71ef8959978a49e534a7e4
Address = 10.0.0.1/24

[Peer]
PublicKey = e911c20b180ea9316e93f1e94e88269bdb0290cf24bed6f0fefb939350cfefad
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = e8c93c2a3426ea3a0e5b03dd7bb495725ddf13e23abdbf2997dba18f521d5dd0
AllowedIPs = 10.0.0.3/32
=================================
sudo ip tuntap add dev cilk0 mode tun  
sudo ip addr add 10.0.0.1/24 dev cilk0
sudo ip link set mtu 1400 dev cilk0
sudo ip link set dev cilk0 up
sudo ip route add 10.0.0.0/24 dev cilk0
sudo ./cilkVPN

========== Peer 2 conf ==========
[Interface]
ListenPort = 3343
PrivateKey = 9c5904a620c3ecfb88ff19c03f3d05ef709f66f7f0929fd9d3ddf373333012cf
Address = 10.0.0.2/24

[Peer]
PublicKey = eb119f5604eac33290f6d8a0dc0e52d82f17914995c4acc7a8211b2235a71fb1
Endpoint = 193.124.59.51:3342
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
=================================
sudo ./cilkVPN
sudo ip addr add 10.0.0.2/24 dev cilk0
sudo ip link set mtu 1400 dev cilk0
sudo ip link set dev cilk0 up

========== Peer 3 conf ==========
[Interface]
ListenPort = 3342
PrivateKey = 1ce257003246bc455931281ed68adcc1dff03a12bc1e864d810f6e3d491a8966
Address = 10.0.0.3/24

[Peer]
PublicKey = eb119f5604eac33290f6d8a0dc0e52d82f17914995c4acc7a8211b2235a71fb1
Endpoint = 193.124.59.51:3342
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
=================================
sudo ./cilkVPN
sudo ifconfig utun5 inet 10.0.0.3/32 10.0.0.3 alias
sudo ifconfig utun5 mtu 1400
sudo route add -net 10.0.0.0/24 -interface utun5
sudo ifconfig utun5 up
*/

#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/epoll.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/event.h> 
#endif
#include "./third_party/eTNaCl/etweetnacl.c"

#define CILK_VPN_TRANSPORT_TYPE 1
#define CILK_VPN_TRANSPORT_HANDSHAKE_BYTE 0x00
#define CILK_VPN_TRANSPORT_DATAGRAM_BYTE 0x01
#define CILK_VPN_TRANSPORT_KEEPALIVE_BYTE 0x02
#define CILK_VPN_PEER_INDEX 4
#define CILK_VPN_HANDSHAKE_TO_SIGN (crypto_sign_PUBLICKEYBYTES + CILK_VPN_PEER_INDEX) //32+4=36
#define CILK_VPN_HANDSHAKE_SIG (crypto_box_ZEROBYTES + crypto_sign_BYTES + CILK_VPN_HANDSHAKE_TO_SIGN) //64+32=96 signed handshake payload + 32 bytes for encryption
#define CILK_VPN_HANDSHAKE (CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_onetimeauth_BYTES + crypto_sign_BYTES + CILK_VPN_HANDSHAKE_TO_SIGN) //1+24+32+16+64+36=173
#define CILK_VPN_DATAGRAM (CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES + CILK_VPN_PEER_INDEX + crypto_onetimeauth_BYTES) //1+24+4+16=45
#define CILK_VPN_MAX_ALLOWED_IPS 256
#define CILK_VPN_UDP_BUFFER_SIZE 65535
#define CILK_VPN_TUN_BUFFER_SIZE (crypto_box_ZEROBYTES + 65535 - CILK_VPN_DATAGRAM)
#define CILK_VPN_TUN_ENCRYPTED_BUFFER (CILK_VPN_DATAGRAM + 65535)
#define CILK_VPN_OFFSET_TO_CRYPTOGRAPHY 13
#if defined(__linux__)
#define CILK_VPN_IFACE_OFFSET 0
#elif defined(__APPLE__) || defined(__FreeBSD__)
#define CILK_VPN_IFACE_OFFSET 4
#endif
#define MAX_EVENTS_PER_ONE_EVENT_POOL_WAIT 1024
#define MAX_CONF_LINE_LENGTH 512
#define MAX_CONF_KEY_LENGTH 64
#define MAX_CONF_VALUE_LENGTH 256
#define MAX_IP_AS_STRING_LENGTH 16
#define MAX_MASK_AS_LENGTH 3

typedef struct ed25519_keypair_t {
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
} ed25519_keypair;

typedef struct x25519_keypair_t {
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
} x25519_keypair;

typedef struct ip_address_t {
    uint32_t ip;
    uint32_t mask;
} ip_address;

typedef struct keepalive_timer_t {
    time_t last_sent;
    uint32_t interval;
} keepalive_timer;

typedef struct peer_t {
    unsigned char ed25519_identity_public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char x25519_identity_public_key[crypto_box_PUBLICKEYBYTES];
    int persistent_keepalive;
    struct sockaddr_in local_addr;
    struct sockaddr_in endpoint_addr;
    int has_endpoint;
    ip_address allowed_ips[CILK_VPN_MAX_ALLOWED_IPS];
    int allowed_ips_count;
    unsigned char outbound_key[crypto_box_BEFORENMBYTES];
    unsigned char inbound_key[crypto_box_BEFORENMBYTES];
    uint32_t outbound_peer_ix;
    uint32_t inbound_peer_ix;
    int init_handshake;
    keepalive_timer keepalive;
    struct peer_t* next;
} peer;

typedef struct device_t {
    ed25519_keypair ed25519_identity_keypair;
    x25519_keypair x25519_identity_keypair;
    x25519_keypair x25519_ephemeral_keypair;
    ip_address address;
    int listen_port;
    struct sockaddr_in listen_addr;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;
    peer* peers;
    int peers_count;
    int iface;
    int udp;
    int el;
    
    unsigned char outbound_hs_to_sign[CILK_VPN_HANDSHAKE_TO_SIGN];    
    unsigned char outbound_hs_sig[CILK_VPN_HANDSHAKE_SIG];
    unsigned char outbound_hs[CILK_VPN_HANDSHAKE];
    
    unsigned char keepalive_buf[crypto_box_ZEROBYTES];
    unsigned char keepalive_buf2[CILK_VPN_DATAGRAM];
    
    int outbound_nread;
    unsigned char outbound_buf[CILK_VPN_TUN_BUFFER_SIZE];
    unsigned char outbound_buf2[CILK_VPN_TUN_ENCRYPTED_BUFFER];
    unsigned char nonce[crypto_box_NONCEBYTES];
    
    int inbound_nrecv;
    unsigned char inbound_buf[CILK_VPN_UDP_BUFFER_SIZE];
    unsigned char inbound_buf2[CILK_VPN_UDP_BUFFER_SIZE];
    unsigned char inbound_hs_key[crypto_box_BEFORENMBYTES];
    unsigned char inbound_hs_to_sign[CILK_VPN_HANDSHAKE_TO_SIGN];
} device;

void update_peer_endpoint(peer *p, struct sockaddr_in peer_addr) {
    p->endpoint_addr.sin_addr.s_addr = peer_addr.sin_addr.s_addr;
    p->endpoint_addr.sin_port = peer_addr.sin_port;
    p->has_endpoint = 1;
}

int is_allowed_ips(peer* p, uint32_t ip) {
    for (int i = 0; i < p->allowed_ips_count; i++){
        if (p->allowed_ips[i].ip == ip || (ip & p->allowed_ips[i].mask) == p->allowed_ips[i].ip) {
            return 0;
        }
    }
    
    return -1;
}

peer* find_peer_by_ed25519_identity_public_key(device* d, unsigned char* public_key) {    
    peer* p = d->peers;
    
    while (p) {
        if (memcmp(public_key, p->ed25519_identity_public_key, crypto_sign_PUBLICKEYBYTES) == 0) {
            return p;
        }
        
        p = p->next;
    }
    
    return NULL;
}

peer* find_peer_by_inbound_peer_index(peer* peers, uint32_t inbound_peer_ix) {    
    peer* p = peers;
    
    while (p) {
        if (inbound_peer_ix == p->inbound_peer_ix) {
            return p;
        }
        
        p = p->next;
    }
    
    return NULL;
}

peer* find_peer_by_allowed_ip(peer* peers, uint32_t ip) {
    peer* p = peers;
    
    while (p) {
        if (is_allowed_ips(p, ip) == 0) {
            return p;
        }

        p = p->next;
    }
    
    return NULL;
}

uint32_t generate_unique_inbound_peer_index(peer* peers) {
    while (1) {
        uint32_t random_peer_index = generate_random_uint32();
        
        peer* p = find_peer_by_inbound_peer_index(peers, random_peer_index);
        if (p == NULL) {
            return random_peer_index;
        }
    }
}

void init_keepalive_timer(keepalive_timer* timer, int interval, time_t last_sent) {
    timer->last_sent = last_sent;
    timer->interval = interval;
}

int should_send_keepalive(keepalive_timer* timer) {
    if (timer->interval == 0) {
        return 0;
    }
    
    time_t now = time(NULL);
    
    return (now - timer->last_sent) >= timer->interval;
}

int fetch_timeout(device* d) {
    peer* p = d->peers;
    
    int min = -1; //no active timers
    
    while (p) {
        if (p->persistent_keepalive > 0) {
            if (p->persistent_keepalive < min || min == -1) {
                min = p->persistent_keepalive;
            }
        }
        
        p = p->next;
    }
    
    return min;
}

int send_handshake_2_peer(device* d, peer* p) {
    p->inbound_peer_ix = generate_unique_inbound_peer_index(d->peers);
    memcpy(d->outbound_hs_to_sign + crypto_sign_PUBLICKEYBYTES, &p->inbound_peer_ix, CILK_VPN_PEER_INDEX);
    crypto_sign2(d->outbound_hs_sig + crypto_box_ZEROBYTES, d->outbound_hs_to_sign, CILK_VPN_HANDSHAKE_TO_SIGN, d->ed25519_identity_keypair.secret_key); //auth
    
    crypto_box_keypair(d->x25519_ephemeral_keypair.public_key, d->x25519_ephemeral_keypair.secret_key); //gen ephemeral keypair
    crypto_box_beforenm(p->outbound_key, p->x25519_identity_public_key, d->x25519_ephemeral_keypair.secret_key); //dh    
    
    unsigned char* nonce = d->outbound_hs + CILK_VPN_TRANSPORT_TYPE;
    randombytes(nonce, crypto_box_NONCEBYTES); //gen nonce
    
    unsigned char* box = d->outbound_hs + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES; //skip 1 byte of transport header + 24 bytes of nonce + 16 zerobytes
    crypto_box_afternm(box, d->outbound_hs_sig, CILK_VPN_HANDSHAKE_SIG, nonce, p->outbound_key); //encrypt
    
    d->outbound_hs[0] = CILK_VPN_TRANSPORT_HANDSHAKE_BYTE;
    memcpy(d->outbound_hs + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES, d->x25519_ephemeral_keypair.public_key, crypto_box_PUBLICKEYBYTES); //replace 32 zero bytes on ephemeral public key
    return sendto(d->udp, d->outbound_hs, CILK_VPN_HANDSHAKE, 0, (struct sockaddr *)&p->endpoint_addr, sizeof(p->endpoint_addr));
}

void handle_handshake(device* d) {
    unsigned char* peer_ephemeral_public_key = d->inbound_buf + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES;    
    crypto_box_beforenm(d->inbound_hs_key, peer_ephemeral_public_key, d->x25519_identity_keypair.secret_key); //dh
    
    unsigned char* nonce = d->inbound_buf + CILK_VPN_TRANSPORT_TYPE;
    int inbound_len = d->inbound_nrecv - CILK_VPN_TRANSPORT_TYPE - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES;
    unsigned char* box = d->inbound_buf + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES;
    memset(box, 0, crypto_box_BOXZEROBYTES);
    if (crypto_box_open_afternm(d->inbound_buf2, box, inbound_len, nonce, d->inbound_hs_key) == -1) { //decrypt
        return;
    }
    
    memset(d->inbound_hs_to_sign, 0, CILK_VPN_HANDSHAKE_TO_SIGN);
    unsigned char* sig = d->inbound_buf2 + crypto_box_ZEROBYTES;
    if (crypto_sign_open2(d->inbound_hs_to_sign, sig, inbound_len - crypto_box_ZEROBYTES, sig + crypto_sign_BYTES) != 0) {  //auth (part 1)
        return;
    }
    
    peer* p = find_peer_by_ed25519_identity_public_key(d, d->inbound_hs_to_sign); //auth (part 2)
    if (!p){
        return;
    }
    
    update_peer_endpoint(p, d->peer_addr);
    
    memcpy(p->inbound_key, d->inbound_hs_key, crypto_box_BEFORENMBYTES);
    
    uint32_t peer_ix;
    memcpy(&peer_ix, d->inbound_hs_to_sign + crypto_sign_PUBLICKEYBYTES, CILK_VPN_PEER_INDEX);    
    p->outbound_peer_ix = peer_ix;
    
    if (p->init_handshake == 0) {
        if (send_handshake_2_peer(d, p) <= 0) {
            //log
        }
    } else {
        p->init_handshake = 0;
    }
    
    init_keepalive_timer(&p->keepalive, p->persistent_keepalive, time(NULL));
}

int encrypt_and_send_datagram_2_peer(device* d, peer* p) {
    randombytes(d->nonce, crypto_box_NONCEBYTES);
    memset(d->outbound_buf + CILK_VPN_IFACE_OFFSET, 0, crypto_box_ZEROBYTES);
    int len = d->outbound_nread + crypto_box_ZEROBYTES - CILK_VPN_IFACE_OFFSET;
    crypto_box_afternm(d->outbound_buf2 + CILK_VPN_OFFSET_TO_CRYPTOGRAPHY, d->outbound_buf + CILK_VPN_IFACE_OFFSET, len, d->nonce, p->outbound_key); //encrypt
    
    d->outbound_buf2[0] = CILK_VPN_TRANSPORT_DATAGRAM_BYTE;
    memcpy(d->outbound_buf2 + CILK_VPN_TRANSPORT_TYPE, d->nonce, crypto_box_NONCEBYTES);
    memcpy(d->outbound_buf2 + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES, &p->outbound_peer_ix, CILK_VPN_PEER_INDEX);
    return sendto(d->udp, d->outbound_buf2, CILK_VPN_DATAGRAM + d->outbound_nread - CILK_VPN_IFACE_OFFSET, 0, (struct sockaddr *)&p->endpoint_addr, sizeof(p->endpoint_addr));    
}

void handle_datagram(device* d) {
    uint32_t peer_ix = *(uint32_t *)(d->inbound_buf + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES);
    
    peer* p = find_peer_by_inbound_peer_index(d->peers, peer_ix);
    if (p == NULL) {
        return;
    }
    
    memcpy(d->nonce, d->inbound_buf + CILK_VPN_TRANSPORT_TYPE, crypto_box_NONCEBYTES);
    
    int inbound_len = d->inbound_nrecv - CILK_VPN_OFFSET_TO_CRYPTOGRAPHY;
    unsigned char* box = d->inbound_buf + CILK_VPN_OFFSET_TO_CRYPTOGRAPHY;
    memset(box, 0, crypto_box_BOXZEROBYTES);
    
    if (crypto_box_open_afternm(d->inbound_buf2, box, inbound_len, d->nonce, p->inbound_key) == -1) { //decrypt 
        return;
    }
    
    uint32_t ip_src = *(uint32_t *)(d->inbound_buf2 + crypto_box_ZEROBYTES + 12);
    if (is_allowed_ips(p, ip_src) == -1) {
        return;
    }
    
    update_peer_endpoint(p, d->peer_addr);
    
#if defined(__linux__)
    if (write(d->iface, d->inbound_buf2 + crypto_box_ZEROBYTES, inbound_len - crypto_box_ZEROBYTES) <= 0) {
        //log
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    unsigned char* on_freeBSD = d->inbound_buf2 + (crypto_box_ZEROBYTES - CILK_VPN_IFACE_OFFSET);
    on_freeBSD[0] = 0;
    on_freeBSD[1] = 0;
    on_freeBSD[2] = 0;
    on_freeBSD[3] = 2;
    
    if (write(d->iface, on_freeBSD, inbound_len - crypto_box_ZEROBYTES + CILK_VPN_IFACE_OFFSET) <= 0) {
        //log
    }
#endif
}

int send_keepalive_2_peer(device* d, peer* p) {
    randombytes(d->nonce, crypto_box_NONCEBYTES);
    memset(d->keepalive_buf, 0, crypto_box_ZEROBYTES);
    crypto_box_afternm(d->keepalive_buf2 + CILK_VPN_OFFSET_TO_CRYPTOGRAPHY, d->keepalive_buf, crypto_box_ZEROBYTES, d->nonce, p->outbound_key); //encrypt
    
    d->keepalive_buf2[0] = CILK_VPN_TRANSPORT_KEEPALIVE_BYTE;
    memcpy(d->keepalive_buf2 + CILK_VPN_TRANSPORT_TYPE, d->nonce, crypto_box_NONCEBYTES);
    memcpy(d->keepalive_buf2 + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES, &p->outbound_peer_ix, CILK_VPN_PEER_INDEX);
    return sendto(d->udp, d->keepalive_buf2, CILK_VPN_DATAGRAM, 0, (struct sockaddr *)&p->endpoint_addr, sizeof(p->endpoint_addr));
}

void handle_keepalive(device* d) {    
    uint32_t peer_ix = *(uint32_t *)(d->inbound_buf + CILK_VPN_TRANSPORT_TYPE + crypto_box_NONCEBYTES);
    
    peer* p = find_peer_by_inbound_peer_index(d->peers, peer_ix);
    if (p == NULL) {
        return;
    }
    
    memcpy(d->nonce, d->inbound_buf + CILK_VPN_TRANSPORT_TYPE, crypto_box_NONCEBYTES);
    
    int inbound_len = d->inbound_nrecv - CILK_VPN_OFFSET_TO_CRYPTOGRAPHY;
    unsigned char* box = d->inbound_buf + CILK_VPN_OFFSET_TO_CRYPTOGRAPHY;
    memset(box, 0, crypto_box_BOXZEROBYTES);
    
    if (crypto_box_open_afternm(d->inbound_buf2, box, inbound_len, d->nonce, p->inbound_key) == -1) { //decrypt 
        return;
    }
    
    update_peer_endpoint(p, d->peer_addr);
}

void check_keepalive_timers(device* d) {
    peer* p = d->peers;
    
    while (p) {
        if (p->outbound_peer_ix != 0 && should_send_keepalive(&p->keepalive)) {
            if (send_keepalive_2_peer(d, p) > 0) {
                p->keepalive.last_sent = time(NULL);
            }
        }

        p = p->next;
    }
}

void cilkVPN__recv(device* d) {
    d->inbound_nrecv = recvfrom(d->udp, d->inbound_buf, CILK_VPN_UDP_BUFFER_SIZE, 0, (struct sockaddr *)&d->peer_addr, &d->peer_addr_len);
    if (d->inbound_nrecv <= 0) {
        return;
    }
    
    if (d->inbound_buf[0] == CILK_VPN_TRANSPORT_HANDSHAKE_BYTE) {
        handle_handshake(d);
    } else if (d->inbound_buf[0] == CILK_VPN_TRANSPORT_DATAGRAM_BYTE) {
        handle_datagram(d);
    } else if (d->inbound_buf[0] == CILK_VPN_TRANSPORT_KEEPALIVE_BYTE) {
        handle_keepalive(d);
    }
}

void cilkVPN__read(device* d) {
    d->outbound_nread = read(d->iface, d->outbound_buf + crypto_box_ZEROBYTES, CILK_VPN_TUN_BUFFER_SIZE);
    if (d->outbound_nread <= 0) {
        return;
    }
    
    uint32_t ip_dst = *(uint32_t *)(d->outbound_buf + crypto_box_ZEROBYTES + CILK_VPN_IFACE_OFFSET + 16);
    peer* p = find_peer_by_allowed_ip(d->peers, ip_dst);
    if (p == NULL) {
        return;
    }
    
    if (p->outbound_peer_ix == 0) {
        return;
    }
    
    if (encrypt_and_send_datagram_2_peer(d, p) <= 0) {
        //log
    }
}

void cilkVPN__recv2(device* d) {
    while (1) {
        d->inbound_nrecv = recvfrom(d->udp, d->inbound_buf, CILK_VPN_UDP_BUFFER_SIZE, 0, (struct sockaddr *)&d->peer_addr, &d->peer_addr_len);
        if (d->inbound_nrecv == 0 || (d->inbound_nrecv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            return;
        }
        
        if (d->inbound_nrecv < 0) {
            //log
            return;
        }

        if (d->inbound_buf[0] == CILK_VPN_TRANSPORT_HANDSHAKE_BYTE) {
            handle_handshake(d);
        } else if (d->inbound_buf[0] == CILK_VPN_TRANSPORT_DATAGRAM_BYTE) {
            handle_datagram(d);
        } else if (d->inbound_buf[0] == CILK_VPN_TRANSPORT_KEEPALIVE_BYTE) {
            handle_keepalive(d);
        }
    }
}

void cilkVPN__read2(device* d) {
    while (1) {
        d->outbound_nread = read(d->iface, d->outbound_buf + crypto_box_ZEROBYTES, CILK_VPN_TUN_BUFFER_SIZE);
        if (d->outbound_nread == 0 || (d->outbound_nread < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            return;
        }
        
        if (d->outbound_nread < 0) {
            //log
            return;
        }
        
        uint32_t ip_dst = *(uint32_t *)(d->outbound_buf + crypto_box_ZEROBYTES + CILK_VPN_IFACE_OFFSET + 16);
        peer* p = find_peer_by_allowed_ip(d->peers, ip_dst);
        if (p == NULL) {
            return;
        }
        
        if (p->outbound_peer_ix == 0) {
            return;
        }
        
        if (encrypt_and_send_datagram_2_peer(d, p) <= 0) {
            //log
        }
    }
}

int make_udp(const struct sockaddr* listen_addr, size_t listen_addr_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    bind(fd, listen_addr, listen_addr_len);
    
    return fd;
}

#if defined(__linux__)
//https://www.baeldung.com/linux/tun-interface-purpose

int tun_open(char* devname) {
    struct ifreq ifr;
    int fd, err;
    
    if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
        perror("open /dev/net/tun");
        exit(1);
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // Убирает 4 байта на linux, которые к пакету не относятся, а обозначают протокол
    strncpy(ifr.ifr_name, devname, IFNAMSIZ); // devname = "tun0" or "tun1", etc
    
    /* ioctl will use ifr.if_name as the name of TUN interface to open: "tun0", etc. */
    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }
    
    fcntl(fd, F_SETFL, fcntl( fd, F_GETFL, 0) | O_NONBLOCK);
    
    /* After the ioctl call the fd is "connected" to tun device specified by devname ("tun0", "tun1", etc)*/
    
    return fd;
}

int make_epoll(int iface, int udp){
    int epfd = epoll_create1(0);
    
    struct epoll_event ev;
    ev.events = EPOLLIN; //Отслеживаем появление данных для чтения
    
    ev.data.fd = udp;
    epoll_ctl(epfd, EPOLL_CTL_ADD, udp, &ev);
    
    ev.data.fd = iface;
    epoll_ctl(epfd, EPOLL_CTL_ADD, iface, &ev);
    
    return epfd;
}

#elif defined(__APPLE__) || defined(__FreeBSD__)
//https://gist.github.com/ssrlive/0dd4776d7fc656e5bfb807a59e7f82a0

int utun_open(char name[20]) {
    struct sockaddr_ctl sc;
    struct ctl_info ctlInfo;
    int fd;
    
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
        sizeof(ctlInfo.ctl_name)) {
        fprintf(stderr,"UTUN_CONTROL_NAME too long");
        return -1;
    }
    
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd == -1) {
        perror ("socket(SYSPROTO_CONTROL)");
        return -1;
    }
    
    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
        perror ("ioctl(CTLIOCGINFO)");
        close(fd);
        return -1;
    }
    
    fcntl(fd, F_SETFL, fcntl( fd, F_GETFL, 0) | O_NONBLOCK);
    
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 0; /* create now interface, in this example... */
    
    // If the connect is successful, a tun%d device will be created, where "%d"
    // is our unit number -1
    
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
        perror ("connect(AF_SYS_CONTROL)");
        close(fd);
        return -1;
    }
    
    char ifname[20] = { 0 };
    socklen_t ifname_len = sizeof(ifname);
    getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
    strncpy(name, ifname, ifname_len);
    
    return fd;
}

int make_kqueue(int iface, int udp){
    int kq = kqueue();
    
    struct kevent evSet[2];
    EV_SET(&evSet[0], udp, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&evSet[1], iface, EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, evSet, 2, NULL, 0, NULL);
    
    return kq;
}
#endif

FILE* open_config_file(const char* config_file) {
    FILE* f = fopen(config_file, "r");
    
    if (!f) {
        size_t filename_len = strlen(config_file);
        size_t etc_path_len = filename_len + 14;
        char* etc_path = (char*)malloc(etc_path_len);
        memset(etc_path, 0, etc_path_len);
        snprintf(etc_path, etc_path_len, "/etc/cilkVPN/%s", config_file);
        
        f = fopen(etc_path, "r");
        if (!f) {
            fprintf(stderr, "Error: Cannot open config file '%s' or '/etc/cilkVPN/%s'\n", config_file, config_file);
            free(etc_path);
            return f;
        }
        
        free(etc_path);
    }
    
    return f;
}

static char* trim(char* str) {
    char* end;
    
    while(isspace((unsigned char)*str)) str++; // Удаляем пробелы в начале
    
    if(*str == 0) return str;
    
    
    end = str + strlen(str) - 1; // Удаляем пробелы в конце
    while(end > str && isspace((unsigned char)*end)) end--;
    
    end[1] = '\0';
    return str;
}

static int parse_line(const char* line, char* key, char* value) {
    char buffer[MAX_CONF_LINE_LENGTH];
    char* equals_pos;
    char* trimmed_key;
    char* trimmed_value;
    
    strncpy(buffer, line, MAX_CONF_LINE_LENGTH - 1);
    buffer[MAX_CONF_LINE_LENGTH - 1] = '\0';
    
    equals_pos = strchr(buffer, '='); // Ищем знак равенства
    if(!equals_pos) return 0;
    
    *equals_pos = '\0';
    trimmed_key = trim(buffer);
    trimmed_value = trim(equals_pos + 1);
    
    strncpy(key, trimmed_key, MAX_CONF_KEY_LENGTH - 1);
    key[MAX_CONF_KEY_LENGTH - 1] = '\0';
    strncpy(value, trimmed_value, MAX_CONF_VALUE_LENGTH - 1);
    value[MAX_CONF_VALUE_LENGTH - 1] = '\0';
    
    return 1;
}

int parse_ip_address(const char *value, ip_address *addr, int line_num) {
    if (!value || !addr) {
        return -1;
    }
    
    memset(addr, 0, sizeof(ip_address));
    
    char temp[MAX_IP_AS_STRING_LENGTH * 2];
    strncpy(temp, value, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    
    char *slash_pos = strchr(temp, '/');
    char *ip_part = temp;
    char *mask_part = NULL;
    
    if (slash_pos) {
        *slash_pos = '\0';
        mask_part = slash_pos + 1;
        
        if (*mask_part == '\0') {
            fprintf(stderr, "Warning: Invalid Address format at line %d: %s. Mask is empty.\n", line_num, value);
            return -1;
        }
    }
    
    if (*ip_part == '\0') {
        fprintf(stderr, "Warning: Invalid Address format at line %d: %s. Ip not defined.\n", line_num, value);
        return -1;
    }
    
    // Конвертируем IP в uint32_t (сетевой порядок байт)
    struct in_addr ip_addr;
    if (inet_pton(AF_INET, ip_part, &ip_addr) != 1) {
        fprintf(stderr, "Warning: Invalid Address format at line %d: %s. An error occurred while parsing IP.\n", line_num, value);
        return -1;
    }
    addr->ip = ip_addr.s_addr; // Сохраняем в сетевом порядке байт
    
    // Парсим маску
    if (mask_part) {
        // Проверяем, что маска содержит только цифры
        for (int i = 0; mask_part[i] != '\0'; i++) {
            if (!isdigit(mask_part[i])) {
                fprintf(stderr, "Warning: Invalid Address format at line %d: %s. Mask must be numeric.\n", line_num, value);
                return -1;
            }
        }
        
        int mask_val = atoi(mask_part);
        if (mask_val < 0 || mask_val > 32) {
            fprintf(stderr, "Warning: Invalid Address format at line %d: %s. Mask value must be from 0 to 32.\n", line_num, value);
            return -1;
        }
        
        // Преобразуем CIDR в маску подсети (сетевой порядок байт)
        uint32_t mask = 0;
        if (mask_val == 0) {
            mask = 0;
        } else {
            mask = htonl(0xFFFFFFFF << (32 - mask_val));
        }
        addr->mask = mask;
    } else {
        // Если маска не указана, используем /32
        addr->mask = 0xFFFFFFFF; // 255.255.255.255 в сетевом порядке
    }
    
    return 0;
}

int parse_allowed_ips(peer *p, const char *input, int line_num) {
    if (!p || !input) {
        return -1;
    }
    
    memset(p->allowed_ips, 0, sizeof(p->allowed_ips));
    
    char buffer[MAX_IP_AS_STRING_LENGTH * 2 * CILK_VPN_MAX_ALLOWED_IPS];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    int count = 0;
    char *current = buffer;
    
    current = trim(current);
    
    while (*current && count < CILK_VPN_MAX_ALLOWED_IPS) {
        char *comma_pos = NULL;
        char *end = current;
        
        while (*end) {
            if (*end == ',') {
                comma_pos = end;
                break;
            }
            end++;
        }
        
        char *element_end = comma_pos ? comma_pos : end;
        
        char *start = trim(current);
        
        if (start < element_end) {
            char temp_copy[MAX_IP_AS_STRING_LENGTH * 2];
            size_t element_len = element_end - start;
            if (element_len >= sizeof(temp_copy)) {
                fprintf(stderr, "Warning: Allowed IP too long\n");
                return -1;
            }
            
            strncpy(temp_copy, start, element_len);
            temp_copy[element_len] = '\0';
            
            char *trimmed = trim(temp_copy);
            
            if (strlen(trimmed) >= MAX_IP_AS_STRING_LENGTH) {
                fprintf(stderr, "Warning: Allowed IP too long\n");
                return -1;
            }
            
            if (parse_ip_address(trimmed, &p->allowed_ips[count], line_num) != 0) {
                return -1;
            }
            
            count++;
        }
        
        if (comma_pos) {
            current = comma_pos + 1;
            current = trim(current);
        } else {
            break;
        }
    }
    
    return count;
}

int parse_endpoint(const char *value, peer* p, int line_num) {
    if (!value) {
        return -1;
    }
    
    char temp[MAX_IP_AS_STRING_LENGTH * 2]; // Копируем строку для парсинга
    strncpy(temp, value, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    
    char *colon_pos = strchr(temp, ':'); // Ручной парсинг: ищем разделитель ':'
    char *ip_part = temp;
    char *port_part = NULL;
    
    if (colon_pos) {
        // Разделяем строку на IP и порт
        *colon_pos = '\0';  // Заменяем ':' на '\0'
        port_part = colon_pos + 1;  // Порт начинается после ':'
        
        if (*port_part == '\0') {
            fprintf(stderr, "Warning: Invalid endpoint format at line %d: %s. Port is empty.\n", line_num, value);
            return -1;
        }
    } else {
        fprintf(stderr, "Warning: Invalid endpoint format at line %d: %s. Missing port separator ':'.\n", line_num, value);
        return -1;
    }
    
    if (*ip_part == '\0') {
        fprintf(stderr, "Warning: Invalid endpoint format at line %d: %s. IP not defined.\n", line_num, value);
        return -1;
    }
    
    for (int i = 0; port_part[i] != '\0'; i++) { // Проверяем, что порт состоит только из цифр
        if (!isdigit(port_part[i])) {
            fprintf(stderr, "Warning: Invalid endpoint format at line %d: %s. Port must be numeric.\n", line_num, value);
            return -1;
        }
    }
    
    int port_val = atoi(port_part);
    if (port_val < 0 || port_val > 65535) {
        fprintf(stderr, "Warning: Invalid endpoint format at line %d: %s. Port value must be from 0 to 65535.\n", line_num, value);
        return -1;
    }
    
    memset(&p->endpoint_addr, 0, sizeof(p->endpoint_addr));
    p->endpoint_addr.sin_family = AF_INET;
    p->endpoint_addr.sin_addr.s_addr = inet_addr(ip_part);    
    p->endpoint_addr.sin_port = htons(port_val);
    p->has_endpoint = 1;
    
    return 0;
}

int init_device_from_file(device* d, FILE* f) {    
    char line[MAX_CONF_LINE_LENGTH];
    char key[MAX_CONF_KEY_LENGTH];
    char value[MAX_CONF_VALUE_LENGTH];
    char ip[MAX_IP_AS_STRING_LENGTH];
    char mask[MAX_MASK_AS_LENGTH];
    
    peer* last_peer = NULL;
    
    int is_interface_section = 0;
    int is_peer_section = 0;
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        char* trimmed_line = trim(line);
        
        if (trimmed_line[0] == '\0' || trimmed_line[0] == '#') continue; // Пропускаем пустые строки и комментарии
        
        if (strstr(trimmed_line, "[Interface]") != NULL) {
            is_interface_section = 1;
            is_peer_section = 0;
            continue;
        }
        
        if (strstr(trimmed_line, "[Peer]") != NULL) {
            is_interface_section = 0;
            is_peer_section = 1;
            
            peer* p = malloc(sizeof(peer));
            memset(p, 0, sizeof(peer));
            
            if (last_peer == NULL) {
                d->peers = last_peer = p;
            } else {
                last_peer->next = p;
                last_peer = p;
            }
            
            d->peers_count++;
            
            continue;
        }
        
        if (is_interface_section == 1 || is_peer_section == 1) {
            if (!parse_line(trimmed_line, key, value)) {
                fprintf(stderr, "LINE: '%s'. Warning: Cannot parse line %d: %s\n", trimmed_line, line_num, trimmed_line);
                return -1;
            }
        }
        
        if (is_interface_section == 1) {
            if (strcmp(key, "PrivateKey") == 0) {
                crypto_sign_keypair_from_sk32( d->ed25519_identity_keypair.public_key, d->ed25519_identity_keypair.secret_key, value );
                crypto_sign_ed25519_sk_to_curve25519( d->x25519_identity_keypair.secret_key, d->ed25519_identity_keypair.secret_key );
                crypto_sign_ed25519_pk_to_curve25519( d->x25519_identity_keypair.public_key, d->ed25519_identity_keypair.public_key );
            }
            
            if (strcmp(key, "ListenPort") == 0) {
                d->listen_port = atoi(value);
                
                if (d->listen_port <= 0 || d->listen_port > 65535) {
                    fprintf(stderr, "Warning: Invalid ListenPort at line %d: %s\n",  line_num, value);
                    d->listen_port = 0;
                    return -1;
                }
            }
            
            if (strcmp(key, "Address") == 0) {
                if (parse_ip_address(value, &d->address, line_num) == -1) {
                    return -1;
                }
            }
        }
        
        if (is_peer_section == 1) {
            if (strcmp(key, "PublicKey") == 0) {
                hex_to_bytes(value, last_peer->ed25519_identity_public_key);
                crypto_sign_ed25519_pk_to_curve25519( last_peer->x25519_identity_public_key, last_peer->ed25519_identity_public_key );
            }
            
            if (strcmp(key, "AllowedIPs") == 0) {
                last_peer->allowed_ips_count = parse_allowed_ips(last_peer, value, line_num);
            }
            
            if (strcmp(key, "Endpoint") == 0) {
                if (parse_endpoint(value, last_peer, line_num) == -1) {
                    return -1;
                }
            }
            
            if (strcmp(key, "PersistentKeepalive") == 0) {
                last_peer->persistent_keepalive = atoi(value);
            }
        }
    }
    
    return 0;
}

void destroy_device(device* d) {
    if (!d) return;
    
    if (d->udp > 0) {
        close(d->udp);
    }
    
    if (d->iface > 0) {
        close(d->iface);
    }
    
    if (d->el > 0) {
        close(d->el);
    }
    
    peer* p = d->peers;
    
    while(p) {
        peer* next = p->next;
        p->next = NULL;
        free(p);
        p = next;
    }
    
    d->peers = NULL;
    
    free(d);
}

device* make_device_from_config(const char* config_file) {
    FILE* f = open_config_file(config_file);
    if (!f) {
        return NULL;
    }
    
    device* d = malloc(sizeof(device));
    memset(d, 0, sizeof(device));
    
    int result = init_device_from_file(d, f);
    
    fclose(f);
    
    if (result == -1) {
        destroy_device(d);
        
        return NULL;
    }
    
    if (d->listen_port == 0) {
        fprintf(stderr, "Warning: ListenPort is required.\n");
        
        destroy_device(d);
                
        return NULL;
    }
    
    memcpy(d->outbound_hs_to_sign, d->ed25519_identity_keypair.public_key, crypto_sign_PUBLICKEYBYTES);
    
    memset(&d->listen_addr, 0, sizeof(d->listen_addr));
    d->listen_addr.sin_family = AF_INET;
    d->listen_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces
    d->listen_addr.sin_port = htons(d->listen_port);
    
    d->peer_addr_len = sizeof(d->peer_addr);
            
    return d;
}

int main(int argc, char **argv) {
    const char* config_file = "cilkVPN.conf";
    if( argc > 1) {
        config_file = argv[1];
    }
    
    device* d = make_device_from_config(config_file);
    if (!d) {
        return 1;
    }

    d->udp = make_udp((const struct sockaddr *)&d->listen_addr, sizeof(d->listen_addr));

#if defined(__linux__)
    d->iface = tun_open("cilk0");
    if (d->iface == -1) {
        fprintf(stderr, "Unable to establish tun descriptor - aborting\n");
        exit(1);
    }
    
    d->el = make_epoll(d->iface, d->udp);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    char name[20] = { 0 };
    d->iface = utun_open(name);
    if (d->iface == -1) {
        fprintf(stderr, "Unable to establish UTUN descriptor - aborting\n");
        exit(1);
    }
    
    fprintf(stderr, "Utun interface [%s] is up...\n", name);
    
    d->el = make_kqueue(d->iface, d->udp);
#endif
    
    peer* p = d->peers;
    
    while (p) {
        if (p->has_endpoint) {
            p->init_handshake = 1;
            send_handshake_2_peer(d, p);
        }
        
        p = p->next;
    }
    
    int timeout = fetch_timeout(d);
    
#if defined(__linux__)
    struct epoll_event events[MAX_EVENTS_PER_ONE_EVENT_POOL_WAIT];
    
    while (1) {
        int nfds = epoll_wait(d->el, events, MAX_EVENTS_PER_ONE_EVENT_POOL_WAIT, timeout);

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == d->udp) {
                cilkVPN__recv2(d);
            } else if (events[i].data.fd == d->iface) {
                cilkVPN__read2(d);
            }
        }
        
        check_keepalive_timers(d);
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    struct kevent events[MAX_EVENTS_PER_ONE_EVENT_POOL_WAIT];
    struct timespec timeout_timespec;
    timeout_timespec.tv_sec = timeout;
    
    while (1) {
        int nfds = kevent(d->el, NULL, 0, events, MAX_EVENTS_PER_ONE_EVENT_POOL_WAIT, timeout == -1 ? NULL : &timeout_timespec);
        
        for (int i = 0; i < nfds; i++) {
            if ((int)events[i].ident == d->udp) {
                cilkVPN__recv2(d);
            } else if ((int)events[i].ident == d->iface) {
                cilkVPN__read2(d);
            }
        }
        
        check_keepalive_timers(d);
    }
#endif
    
    destroy_device(d);
    
    return 0;
}