# 嵌入式网络设备协议栈模拟系统
针对路由器/网络设备场景开发的最小化核心功能模拟项目，采用版本化迭代开发，覆盖TCP/IP模型二层到三层的核心网络协议，完全匹配网络设备嵌入式软件开发岗位需求。

## 版本迭代说明
### v0.5 基础版本：ARP协议解析与动态ARP表维护
- 基于libpcap实现ARP数据包的捕获与解析
- 模拟路由器ARP请求/应答的完整交互流程
- 实现动态ARP表，支持IP-MAC映射的自动更新与可视化展示

### v1.0 扩展版本：ARP+ICMP双协议栈解析
- 在v0.5的基础上扩展，支持ARP与ICMP双协议的同时捕获、过滤与解析
- 实现ICMP Echo Request（Ping请求）的深度解析，兼容网络协议标准校验和算法
- 保留v0.5的动态ARP表维护功能，覆盖数据链路层到网络层的核心能力

## 技术栈
C/C++、libpcap、WSL2 (Ubuntu)、Linux网络编程、TCP/IP协议栈

<img width="861" height="135" alt="465bbb55ae9977ac35d8c8e453c3bfe2" src="https://github.com/user-attachments/assets/f7eb2f0a-681b-4310-9efb-829eb2046a3b" />
<img width="680" height="348" alt="92191ff8fb0ea0b896ff8eebb16faf0a" src="https://github.com/user-attachments/assets/03a4659a-a338-446a-9111-e6df5445e000" />
<img width="750" height="461" alt="7c7e439deaaa319f37b8d9398afa2b55" src="https://github.com/user-attachments/assets/c0204732-75e9-4cba-aecc-eed979ed97a7" />
