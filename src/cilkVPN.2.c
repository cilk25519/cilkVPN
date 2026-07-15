/*
clang ./cilkVPN.2.c -O3 -o ./cilkVPN.2
./cilkVPN.2
./cilkVPN.2 cilkVPN.conf
./cilkVPN.2 /etc/cilkVPN/cilkVPN.conf
./cilkVPN.2 peer1.conf
./cilkVPN.2 peer2.conf
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "./third_party/eTNaCl/etweetnacl.c"

#define MAX_IP_AS_STRING_LENGTH 16
#define MAX_MASK_AS_LENGTH 3
#define MAX_ALLOWED_IPS_LENGTH 32
#define PERSISTENT_KEEPALIVE_SECONDS_DEFAULT 20 

#define MAX_CONF_LINE_LENGTH 512
#define MAX_CONF_KEY_LENGTH 64
#define MAX_CONF_VALUE_LENGTH 256

typedef struct ed25519_keypair_t {
    unsigned char secret_key[ crypto_sign_SECRETKEYBYTES ];
    unsigned char public_key[ crypto_sign_PUBLICKEYBYTES ];
} ed25519_keypair;

typedef struct x25519_keypair_t {
    unsigned char secret_key[ crypto_box_SECRETKEYBYTES ];
    unsigned char public_key[ crypto_box_PUBLICKEYBYTES ];
} x25519_keypair;

typedef struct ip_address_t {
	char ip[MAX_IP_AS_STRING_LENGTH];
	char mask[MAX_MASK_AS_LENGTH];
	int ip_len;
	int mask_len;
	struct in_addr ip_addr;
} ip_address;

typedef struct endpoint_t {
    char ip[MAX_IP_AS_STRING_LENGTH];
	int ip_len;
	struct in_addr ip_addr;
	int port;
} peer_endpoint;

typedef struct peer_t {
	unsigned char ed25519_identity_public_key[ crypto_sign_PUBLICKEYBYTES ];
    unsigned char x25519_identity_public_key[ crypto_box_PUBLICKEYBYTES ];
	ip_address allowed_ips[MAX_ALLOWED_IPS_LENGTH];
	int allowed_ips_count;
	peer_endpoint endpoint;
	int persistent_keepalive;
	struct peer_t* next;
} peer;

typedef struct device_t {
    ed25519_keypair ed25519_identity_keypair;
    x25519_keypair x25519_identity_keypair;
	x25519_keypair x25519_ephemeral_keypair;
	int listen_port;
	ip_address address;
	peer* peers;
	int peers_count;
} device;

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

void print_config_file(FILE* f) {
    if (!f) {
        fprintf(stderr, "Error: File pointer is NULL\n");
        return;
    }
    
    long pos = ftell(f);
    
    rewind(f);
    
    printf("\n========== CONFIG FILE CONTENT ==========\n");
    char buffer[1024];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }
    
    printf("========== END OF CONFIG FILE ==========\n\n");
    
    fseek(f, pos, SEEK_SET); // Возвращаемся на сохраненную позицию
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

    char temp[MAX_IP_AS_STRING_LENGTH * 2]; // Копируем строку для парсинга
    strncpy(temp, value, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    
    char *slash_pos = strchr(temp, '/'); // Ручной парсинг: ищем разделитель '/'
    char *ip_part = temp;
    char *mask_part = NULL;
	
    if (slash_pos) {
        // Разделяем строку на IP и маску
        *slash_pos = '\0';  // Заменяем '/' на '\0'
        mask_part = slash_pos + 1;  // Маска начинается после '/'
        
        if (*mask_part == '\0') {
            fprintf(stderr, "Warning: Invalid Address format at line %d: %s. Mask is empty.\n", line_num, value);
            return -1;
        }
    }
    
    if (*ip_part == '\0') {
        fprintf(stderr, "Warning: Invalid Address format at line %d: %s. Ip not defined.\n", line_num, value);
        return -1;
    }
    
    strncpy(addr->ip, ip_part, MAX_IP_AS_STRING_LENGTH - 1);
    addr->ip[MAX_IP_AS_STRING_LENGTH - 1] = '\0';
    addr->ip_len = strlen(addr->ip);
    
    if (inet_pton(AF_INET, ip_part, &addr->ip_addr) != 1) {
        fprintf(stderr, "Warning: Invalid Address format at line %d: %s. An error occurred while parsing struct in_addr.\n", line_num, value);
        return -1;
    }
    
    if (mask_part) {
        strncpy(addr->mask, mask_part, MAX_MASK_AS_LENGTH - 1);
        addr->mask[MAX_MASK_AS_LENGTH - 1] = '\0';
        addr->mask_len = strlen(addr->mask);
        
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
    } else {
        strcpy(addr->mask, "32"); // Если маска не указана, используем /32
        addr->mask_len = 2;
    }
    
    return 0;
}

int parse_allowed_ips(peer *p, const char *input, int line_num) {
    if (!p || !input) {
        return -1;
    }
    
    memset(p->allowed_ips, 0, sizeof(p->allowed_ips));
    
    char buffer[MAX_IP_AS_STRING_LENGTH * 2 * MAX_ALLOWED_IPS_LENGTH];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    int count = 0;
    char *current = buffer;
    
    current = trim(current);
    
    while (*current && count < MAX_ALLOWED_IPS_LENGTH) {
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
            current = trim(current); // Обрезаем пробелы после запятой
        } else {
            break;
        }
    }
    
    return count;
}

int parse_endpoint(const char *value, peer_endpoint *endpoint, int line_num) {
    if (!value || !endpoint) {
        return -1;
    }
    
    memset(endpoint, 0, sizeof(peer_endpoint));
    
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
    
    // Проверяем, что порт состоит только из цифр
    for (int i = 0; port_part[i] != '\0'; i++) {
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
    
    strncpy(endpoint->ip, ip_part, MAX_IP_AS_STRING_LENGTH - 1);
    endpoint->ip[MAX_IP_AS_STRING_LENGTH - 1] = '\0';
    endpoint->ip_len = strlen(endpoint->ip);
    
    if (inet_pton(AF_INET, ip_part, &endpoint->ip_addr) != 1) {
        fprintf(stderr, "Warning: Invalid endpoint format at line %d: %s. An error occurred while parsing struct in_addr.\n", line_num, value);
        return -1;
    }
    
    endpoint->port = port_val;
    
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
			p->persistent_keepalive = PERSISTENT_KEEPALIVE_SECONDS_DEFAULT;
            
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
				if (parse_endpoint(value, &last_peer->endpoint, line_num) == -1) {
					return -1;
				}
			}
			
			if (strcmp(key, "PersistentKeepalive") == 0) {
				last_peer->persistent_keepalive = atoi(value);
				
                if (last_peer->persistent_keepalive <= 0) {
                    last_peer->persistent_keepalive = PERSISTENT_KEEPALIVE_SECONDS_DEFAULT;
                }
			}
		}
	}
	
	return 0;
}

void destroy_device(device* d) {
	if (!d) return;
	
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
	
	print_config_file(f);
	
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
	
	return d;
}

void print_device_info(const device* d) {
    if (!d) {
        printf("Device is NULL\n");
        return;
    }
    
	printf("========== DEVICE INFORMATION ==========\n");
	printf("ED25519 Identity Keypair:\n");
    PRINT_HEX_WITH_LABLE("   Private", d->ed25519_identity_keypair.secret_key, crypto_sign_SECRETKEYBYTES, NOSPACE);
    PRINT_HEX_WITH_LABLE("   Public", d->ed25519_identity_keypair.public_key, crypto_sign_PUBLICKEYBYTES, NOSPACE);
    printf("X25519 Identity Keypair:\n");
    PRINT_HEX_WITH_LABLE("   Private", d->x25519_identity_keypair.secret_key, crypto_box_SECRETKEYBYTES, NOSPACE);
    PRINT_HEX_WITH_LABLE("   Public", d->x25519_identity_keypair.public_key, crypto_box_PUBLICKEYBYTES, NOSPACE);
    printf("\n");
    printf("Interface Settings:\n");
    printf("   Listen Port: %d\n", d->listen_port);
    printf("   Address: %s/%s (%s)\n", d->address.ip, d->address.mask, inet_ntoa(d->address.ip_addr));
    printf("\n");
    printf("Peers (%d):\n", d->peers_count);
    
    int peer_count = 0;
    peer* p = d->peers;
    
    while (p) {
        peer_count++;
        printf(" ┌─ Peer %d ─────────────────────────────────────────────────────────\n", peer_count);
        printf(" │ Public Keys:                                                      \n");
        PRINT_HEX_WITH_LABLE(" │   ED25519", p->ed25519_identity_public_key, crypto_sign_PUBLICKEYBYTES, NOSPACE);
        PRINT_HEX_WITH_LABLE(" │   X25519", p->x25519_identity_public_key, crypto_box_PUBLICKEYBYTES, NOSPACE);
        printf(" │\n");
        printf(" │ Endpoint: %s:%d\n", p->endpoint.ip, p->endpoint.port);
        printf(" │ Keepalive: %d seconds \n", p->persistent_keepalive);
        
        if (p->allowed_ips_count > 0) {
            printf(" │ Allowed IPs:\n");
            for (int i = 0; i < p->allowed_ips_count; i++) {
                printf(" │   %d. %s/%s (%s)\n", i + 1, p->allowed_ips[i].ip, p->allowed_ips[i].mask, inet_ntoa(p->allowed_ips[i].ip_addr));
            }
        } else {
            printf(" │ Allowed IPs: (none)\n");
        }
		
        printf(" └───────────────────────────────────────────────────────────────────\n");
        
        p = p->next;
    }
    
	printf("========== END OF DEVICE INFORMATION ===\n\n");
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
	
	print_device_info(d);
	
	destroy_device(d);
	
    return 0;
}