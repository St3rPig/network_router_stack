#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_ARP_ENTRY 100

// ARP表条目结构体
typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[18];
    int is_valid;
} arp_entry_t;

arp_entry_t arp_table[MAX_ARP_ENTRY];

// 初始化ARP表
void init_arp_table() {
    memset(arp_table, 0, sizeof(arp_table));
}

// 更新ARP表
void update_arp_table(char *ip, char *mac) {
    for (int i = 0; i < MAX_ARP_ENTRY; i++) {
        if (arp_table[i].is_valid && strcmp(arp_table[i].ip, ip) == 0) {
            strcpy(arp_table[i].mac, mac);
            return;
        }
    }
    for (int i = 0; i < MAX_ARP_ENTRY; i++) {
        if (!arp_table[i].is_valid) {
            strcpy(arp_table[i].ip, ip);
            strcpy(arp_table[i].mac, mac);
            arp_table[i].is_valid = 1;
            return;
        }
    }
}

// 打印ARP表
void print_arp_table() {
    printf("\n==================== 当前ARP表 ====================\n");
    printf("%-16s | %-17s\n", "IP地址", "MAC地址");
    printf("---------------------------------------------------\n");
    for (int i = 0; i < MAX_ARP_ENTRY; i++) {
        if (arp_table[i].is_valid) {
            printf("%-16s | %-17s\n", arp_table[i].ip, arp_table[i].mac);
        }
    }
    printf("===================================================\n\n");
}

// 计算ICMP校验和（网络协议标准算法）
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 处理ICMP数据包：解析Echo Request
void handle_icmp(const u_char *packet, int len) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4;
    struct icmp *icmp_header = (struct icmp *)((u_char *)ip_header + ip_header_len);

    // 只处理ICMP Echo Request（Ping请求）
    if (icmp_header->icmp_type == ICMP_ECHO) {
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);

        printf("=====================================\n");
        printf("[ICMP包捕获成功] Ping请求\n");
        printf("源IP: %s | 目标IP: %s\n", src_ip, dst_ip);
        printf("ICMP ID: %d | 序号: %d\n", ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_seq));
        printf("=====================================\n");
    }
}

// 数据包处理主回调函数
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth_header->ether_type);

    // 处理ARP包
    if (ether_type == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        char sender_mac[18], target_mac[18];

        inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);
        sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
                arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
        sprintf(target_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
                arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

        printf("=====================================\n");
        printf("[ARP包捕获成功] 长度: %d 字节\n", pkthdr->len);
        printf("操作类型: %s\n", ntohs(arp_header->arp_op) == ARPOP_REQUEST ? "ARP请求(地址查询)" : "ARP响应(地址应答)");
        printf("发送方: IP=%s | MAC=%s\n", sender_ip, sender_mac);
        printf("目标方: IP=%s | MAC=%s\n", target_ip, target_mac);

        if (ntohs(arp_header->arp_op) == ARPOP_REPLY) {
            update_arp_table(sender_ip, sender_mac);
            print_arp_table();
        }
    }
    // 处理IP包（包含ICMP）
    else if (ether_type == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_ICMP) {
            handle_icmp(packet, pkthdr->len);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev = "eth0";

    init_arp_table();

    // 打开网卡
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "打开网卡失败 %s: %s\n", dev, errbuf);
        return 1;
    }

    // 设置过滤规则：捕获ARP或ICMP包
    struct bpf_program fp;
    char filter_exp[] = "arp or icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "过滤规则编译失败: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "过滤规则应用失败: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("=== ver1.0: ARP+ICMP双协议栈解析 ===\n");
    printf("按 Ctrl+C 停止抓包\n\n");

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
