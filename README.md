dnsqps
======

show dns qps and rps
# DNS QPS TOOL

## 关于
dnsqps是一个统计DNS服务器每秒收到解析请求和回复的监控工具，此工具支持每秒解析数量以及响应数量统计

## 功能
1、支持统计qps
2、支持统计rps
3、支持UDP协议
4、支持TCP协议

## 快速开始
下载源码：

    git clone https://github.com/kingcarl/dnsqps/dnsqps.git
    cd dnsqps
    

编译源码：

    make
    
运行：
    
    ./dnsqps [-Q|-R] [device] [-d "ip1 {ip2 ... }"] 
