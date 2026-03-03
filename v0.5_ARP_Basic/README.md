# ver0.5: ARP协议解析与动态ARP表维护

## 功能说明
- 基于libpcap实现ARP数据包的监听与解析
- 模拟路由器的地址查询与应答完整流程
- 开发动态ARP表维护模块，支持IP-MAC映射的自动更新与可视化展示

## 编译运行
```bash
gcc arp_sniffer.c -o arp_sniffer -lpcap
sudo ./arp_sniffer
```

## 技术栈
- C语言、libpcap、WSL2 (Ubuntu)、Linux网络编程
