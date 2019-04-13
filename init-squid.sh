#!/bin/bash
#centos7.4安装squid脚本

chmod -R 777 /usr/local/src/
#1、时间时区同步，修改主机名
ntpdate cn.pool.ntp.org
hwclock --systohc
echo "*/30 * * * * root ntpdate -s 3.cn.poop.ntp.org" >> /etc/crontab

sed -i 's|SELINUX=.*|SELINUX=disabled|' /etc/selinux/config
sed -i 's|SELINUXTYPE=.*|#SELINUXTYPE=targeted|' /etc/selinux/config
sed -i 's|SELINUX=.*|SELINUX=disabled|' /etc/sysconfig/selinux 
sed -i 's|SELINUXTYPE=.*|#SELINUXTYPE=targeted|' /etc/sysconfig/selinux
setenforce 0 && systemctl stop firewalld && systemctl disable firewalld 

rm -rf /var/run/yum.pid 
rm -rf /var/run/yum.pid

yum -y install squid

参数 	                                         作用
http_port 3128 	                            监听的端口号
cache_mem 64M 	                            内存缓冲区的大小
cache_dir ufs /var/spool/squid 2000 16 256 	硬盘缓冲区的大小
cache_effective_user squid 	                设置缓存的有效用户
cache_effective_group squid 	              设置缓存的有效用户组
dns_nameservers IP地址 	                    一般不设置，而是用服务器默认的DNS地址
cache_access_log /var/log/squid/access.log 	访问日志文件的保存路径
cache_log /var/log/squid/cache.log 	        缓存日志文件的保存路径
visible_hostname linuxprobe.com 	          设置Squid服务器的名称

systemctl restart squid
systemctl enable squid
sed -i 's|http_port 3128|http_port 10000|'  /etc/squid/squid.conf
semanage port -a -t squid_port_t -p tcp 10000
semanage port -l | grep squid_port_t
#ACL实验1：只允许IP地址为192.168.10.20的客户端使用服务器上的Squid服务程序提供的代理服务，禁止其余所有的主机代理请求。
sed -i '/acl CONNECT method CONNECT/a\acl client src 192.168.10.20'  /etc/squid/squid.conf
sed -i '/http_access deny !Safe_ports/i\http_access allow client'  /etc/squid/squid.conf
sed -i '/http_access deny !Safe_ports/i\http_access deny all'  /etc/squid/squid.conf

#ACL实验2：禁止所有客户端访问网址中包含linux关键词的网站。
sed -i '/acl CONNECT method CONNECT/a\acl deny_keyword url_regex -i linux'  /etc/squid/squid.conf
sed -i '/http_access deny !Safe_ports/i\http_access deny deny_keyword'  /etc/squid/squid.conf

#ACL实验3：禁止所有客户端访问某个特定的网站。
sed -i '/acl CONNECT method CONNECT/a\acl deny_url url_regex http://www.linuxcool.com'  /etc/squid/squid.conf
sed -i '/http_access deny !Safe_ports/i\http_access deny deny_url'  /etc/squid/squid.conf

#ACL实验4：禁止员工在企业网内部下载带有某些后缀的文件。
sed -i '/acl CONNECT method CONNECT/a\acl badfile urlpath_regex -i \.mp3$ \.rar$'  /etc/squid/squid.conf
sed -i '/http_access deny !Safe_ports/i\http_access deny badfile'  /etc/squid/squid.conf

#透明正向代理
iptables -t nat -A POSTROUTING -p udp --dport 53 -o eno33554968 -j MASQUERADE
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p 
sed -i 's|http_port 3128|http_port 3128 transparent|'  /etc/squid/squid.conf
sed -i 's|#cache_dir ufs /var/spool/squid 100 16 256|cache_dir ufs /var/spool/squid 100 16 256|'  /etc/squid/squid.conf
squid -k parse
squid -z
iptables -t nat -A PREROUTING  -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128
iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o eno33554968 -j SNAT --to 您的桥接网卡IP地址
service iptables save

#反向代理
iptables -t nat -A POSTROUTING -p udp --dport 53 -o eno33554968 -j MASQUERADE
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p 
sed -i 's|http_port 3128|http_port 您的桥接网卡IP地址:80 vhost|'  /etc/squid/squid.conf
sed -i 's|#cache_dir ufs /var/spool/squid 100 16 256|cache_peer 网站源服务器IP地址 parent 80 0 originserver|'  /etc/squid/squid.conf
squid -k parse
squid -z
iptables -t nat -A PREROUTING  -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128
iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o eno33554968 -j SNAT --to 您的桥接网卡IP地址
service iptables save
