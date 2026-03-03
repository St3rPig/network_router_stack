#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

#define MAX_ARP_ENTRY 100 // 最大ARP表条目数

// ARP表条目结构体，模拟路由器ARP表
typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[18];
    int is_valid;
} arp_entry_t;

arp_entry_t arp_table[MAX_ARP_ENTRY]; // 全局ARP表

// 初始化ARP表
void init_arp_table() {
    memset(arp_table, 0, sizeof(arp_table));
}

// 更新ARP表：新增/更新IP-MAC映射
void update_arp_table(char *ip, char *mac) {
    // 先查找是否已有该IP的条目
    for (int i = 0; i < MAX_ARP_ENTRY; i++) {
        if (arp_table[i].is_valid && strcmp(arp_table[i].ip, ip) == 0) {
            strcpy(arp_table[i].mac, mac);
            return;
        }
    }
    // 没有则新增条目
    for (int i = 0; i < MAX_ARP_ENTRY; i++) {
        if (!arp_table[i].is_valid) {
            strcpy(arp_table[i].ip, ip);
            strcpy(arp_table[i].mac, mac);
            arp_table[i].is_valid = 1;
            return;
        }
    }
}

// 打印当前ARP表，模拟路由器ARP表查看功能
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

// ARP数据包处理回调函数
void arp_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ether_arp *arp_header;
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    char sender_mac[18], target_mac[18];

    // 解析以太网二层头，只处理ARP协议包
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) {
        return;
    }

    // 解析ARP协议头
    arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    // 格式化MAC/IP地址
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);
    sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
            arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    sprintf(target_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
            arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    // 打印ARP包详情
    printf("=====================================\n");
    printf("[ARP包捕获成功] 长度: %d 字节\n", pkthdr->len);
    printf("操作类型: %s\n", ntohs(arp_header->arp_op) == ARPOP_REQUEST ? "ARP请求(地址查询)" : "ARP响应(地址应答)");
    printf("发送方: IP=%s | MAC=%s\n", sender_ip, sender_mac);
    printf("目标方: IP=%s | MAC=%s\n", target_ip, target_mac);

    // 收到ARP响应时，更新ARP表并打印
    if (ntohs(arp_header->arp_op) == ARPOP_REPLY) {
        update_arp_table(sender_ip, sender_mac);
        print_arp_table();
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev = "eth0";

    // 初始化ARP表
    init_arp_table();

    // 打开网卡，开启混杂模式抓包
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "打开网卡失败 %s: %s\n", dev, errbuf);
        return 1;
    }

    // 设置BPF过滤规则：只捕获ARP包
    struct bpf_program fp;
    char filter_exp[] = "arp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "过滤规则编译失败: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "过滤规则应用失败: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("=== 开始监听eth0网卡的ARP数据包 ===\n");
    printf("按 Ctrl+C 停止抓包\n\n");

    // 循环抓包
    pcap_loop(handle, 0, arp_handler, NULL);

    // 释放资源
    pcap_close(handle);
    return 0;
}
