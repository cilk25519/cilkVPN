/*
Build: clang ./cilkVPN.1.c -O3 -o ./cilkVPN

Linux:
sudo ip tuntap add dev cilk0 mode tun  
sudo ip link set mtu 1400 dev cilk0
sudo ip addr add 10.0.0.1/24 dev cilk0
sudo ip link set dev cilk0 up
sudo ip route add 10.0.0.0/24 dev cilk0
ip a
ip route show
sudo ./cilkVPN

Или можно:
sudo ./cilkVPN
sudo ip link set mtu 1400 dev cilk0
sudo ip addr add 10.0.0.1/24 dev cilk0
sudo ip link set dev cilk0 up
sudo ip route add 10.0.0.0/24 dev cilk0 //Возможно тоже не обязательно
ip a

macOS:
sudo ./cilkVPN
sudo ifconfig utun5 inet 10.0.0.1/32 10.0.0.1 alias
sudo ip route add 10.0.0.0/24 dev utun5 | или sudo route add -net 10.0.0.0/24 -interface utun5
sudo ifconfig utun5 up
ip a

ping 10.0.0.2
ping -s 1400 -c 1 10.0.0.2
curl --interface cilk0 http://10.0.0.2/
curl --interface cilk0 --noproxy '*' http://10.0.0.2/
*/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h> // exit, etc.
#include <fcntl.h>
#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <sys/types.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#endif

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
    ifr.ifr_flags = IFF_TUN; // | IFF_NO_PI; Убирает 4 байта на linux, которые по идее к пакету не относятся и нужно проставлять
    strncpy(ifr.ifr_name, devname, IFNAMSIZ); // devname = "tun0" or "tun1", etc

    /* ioctl will use ifr.if_name as the name of TUN interface to open: "tun0", etc. */
    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    /* After the ioctl call the fd is "connected" to tun device specified by devname ("tun0", "tun1", etc)*/

    return fd;
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
#endif

int main(int argc, char **argv) {
#if defined(__linux__)
    int iface = tun_open("cilk0");
    if (iface == -1) {
        fprintf(stderr, "Unable to establish tun descriptor - aborting\n");
        exit(1);
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    char name[20] = { 0 };
    int iface = utun_open(name);
    if (iface == -1) {
        fprintf(stderr, "Unable to establish UTUN descriptor - aborting\n");
        exit(1);
    }
	
    fprintf(stderr, "Utun interface [%s] is up...\n", name);
#endif

    for (;;) {
        unsigned char buffer[1500];
        
        int nread  = read(iface, buffer, 1500);
		
		printf("Len: %d\n", nread);
		
        for (int i = 0; i< nread; i++) {
            printf("%02x ", buffer[i]);
        
            if ( i%16 == 15 ) {
                printf("\n");
            }
        }
        
        printf("\n");
    }
    
    return 0;
}