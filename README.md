# arppoison
arp poison 可以进行dns欺骗，流量之类的操作
使用方法：
arppoison -ip1 192.168.56.103 -ip2 192.168.56.104 -t seconds -d
    -ip1,-ip2: the ip will be attacked
    -t how many seconds to attack，default is 3000 *3600 seconds, 3000 hour
    -d print debug message