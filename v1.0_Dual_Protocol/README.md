# ver1.0: ARP+ICMP双协议栈解析与处理

## 功能说明
- 在ver0.5基础上扩展，实现ARP+ICMP双协议的同时捕获、过滤与解析
- 完成ICMP Echo Request（Ping请求）的深度解析，实现ICMP校验和计算等网络协议标准算法
- 保留动态ARP表维护功能，支持IP-MAC映射的自动更新与可视化展示

## 编译运行
```bash
gcc icmp_arp_router.c -o icmp_arp_router -lpcap
sudo ./icmp_arp_router
```

## 技术栈
- C语言、libpcap、WSL2 (Ubuntu)、Linux网络编程、网络分层架构
