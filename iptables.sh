#!/bin/bash

IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
MODPROBE=/sbin/modprobe
# 
INT_NET=10.254.132.0/24
INT_INTF=eth0

###### iptables ######
#
echo "[+] Installing iptables..."
systemctl stop firewalld
systemctl mask firewalld
yum -y install iptables-services
systemctl enable iptables

###### forwarding ######
#
echo "[+] Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1
sysctl -p
#echo 1 > /proc/sys/net/ipv4/ip_forward

###### rules ######
#
### flush existing rules and set chain policy setting to DROP
echo "[+] Flushing existing iptables rules..."
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -X
# $IPTABLES -P INPUT DROP
# $IPTABLES -P OUTPUT DROP
# $IPTABLES -P FORWARD DROP

### this policy does not handle IPv6 traffic except to drop it.
#
echo "[+] Disabling IPv6 traffic..."
$IP6TABLES -P INPUT DROP
$IP6TABLES -P OUTPUT DROP
$IP6TABLES -P FORWARD DROP

### load connection-tracking modules
#
$MODPROBE ip_conntrack
$MODPROBE iptable_nat
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_nat_ftp

###### INPUT chain ######
#
echo "[+] Setting up INPUT chain..."

### state tracking rules
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### anti-spoofing rules
#$IPTABLES -A INPUT -i $INT_INTF ! -s $INT_NET -j LOG --log-prefix "SPOOFED PKT "
#$IPTABLES -A INPUT -i $INT_INTF ! -s $INT_NET -j DROP

### ACCEPT rules
$IPTABLES -A INPUT -i $INT_INTF -p tcp -s $INT_NET --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A INPUT -i $INT_INTF -p tcp -s $INT_NET --dport 5671 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

### default INPUT LOG rule
$IPTABLES -A INPUT ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### make sure that loopback traffic is accepted
$IPTABLES -A INPUT -i lo -j ACCEPT

###### OUTPUT chain ######
#
echo "[+] Setting up OUTPUT chain..."

### state tracking rules
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### ACCEPT rules for allowing connections out
$IPTABLES -A OUTPUT -p tcp --dport 21 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 43 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 4321 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 5671 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

### default OUTPUT LOG rule
$IPTABLES -A OUTPUT ! -o lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### make sure that loopback traffic is accepted
$IPTABLES -A OUTPUT -o lo -j ACCEPT

###### FORWARD chain ######
#
echo "[+] Setting up FORWARD chain..."

### state tracking rules
$IPTABLES -A FORWARD -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A FORWARD -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### anti-spoofing rules
# $IPTABLES -A FORWARD -i $INT_INTF ! -s $INT_NET -j LOG --log-prefix "SPOOFED PKT "
# $IPTABLES -A FORWARD -i $INT_INTF ! -s $INT_NET -j DROP

### ACCEPT rules
$IPTABLES -A FORWARD -p tcp -i $INT_INTF -s $INT_NET --dport 21 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INT_INTF -s $INT_NET --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INT_INTF -s $INT_NET --dport 25 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INT_INTF -s $INT_NET --dport 43 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 5671 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $INT_INTF -s $INT_NET --dport 4321 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT

### default LOG rule
$IPTABLES -A FORWARD ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

###### NAT rules ######
#
echo "[+] Setting up NAT rules..."
$IPTABLES -t nat -A POSTROUTING --out-interface $INT_INTF -j MASQUERADE

###### save iptable #####
#
service iptables save
