#!/bin/sh

IPT=/sbin/iptables
# NAT interface
NIF=enp0s9
# NAT IP address
NIP='10.0.98.100'

# Host-only interface
HIF=enp0s3
# Host-only IP addres
HIP='192.168.60.100'

# DNS nameserver 
NS='10.0.98.3'

## Reset the firewall to an empty, but friendly state

# Flush all chains in FILTER table
$IPT -t filter -F
# Delete any user-defined chains in FILTER table
$IPT -t filter -X
# Flush all chains in NAT table
$IPT -t nat -F
# Delete any user-defined chains in NAT table
$IPT -t nat -X
# Flush all chains in MANGLE table
$IPT -t mangle -F
# Delete any user-defined chains in MANGLE table
$IPT -t mangle -X
# Flush all chains in RAW table
$IPT -t raw -F
# Delete any user-defined chains in RAW table
$IPT -t raw -X

# allow tcp and udp traffic for DNS
for ip in $NS
do
	echo "Allowing DNS lookups (tcp, udp port 53) to server '$ip'"
	$IPT -A OUTPUT -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p udp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
	$IPT -A OUTPUT -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
done



# enable traffic from loopback interface
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# allow server A to ping all interfaces
$IPT -A INPUT -i enp0s3 -p icmp --icmp-type echo-reply -j ACCEPT

$IPT -A OUTPUT -o enp0s3 -p icmp --icmp-type echo-request -j ACCEPT

$IPT -A INPUT -i enp0s8 -p icmp --icmp-type echo-reply -j ACCEPT

$IPT -A OUTPUT -o enp0s8 -p icmp --icmp-type echo-request -j ACCEPT

$IPT -A INPUT -i enp0s9 -p icmp --icmp-type echo-reply -j ACCEPT

$IPT -A OUTPUT -o enp0s9 -p icmp --icmp-type echo-request -j ACCEPT





# allow server A to ping all hosts
$IPT -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

$IPT -A FORWARD -i enp0s3 -p icmp --icmp-type echo-reply -j ACCEPT

$IPT -A FORWARD -o enp0s3 -p icmp --icmp-type echo-request -j ACCEPT

$IPT -A FORWARD -i enp0s8 -p icmp --icmp-type echo-reply -j ACCEPT

$IPT -A FORWARD -o enp0s8 -p icmp --icmp-type echo-request -j ACCEPT


# Lab2 allow ah and esp protocols
$IPT  -A INPUT -p ah -j ACCEPT
$IPT  -A INPUT -p esp -j ACCEPT

$IPT  -A OUTPUT -p ah -j ACCEPT
$IPT  -A OUTPUT -p esp -j ACCEPT



$IPT  -A INPUT -p udp --dport 500  -j ACCEPT
$IPT -A OUTPUT -p udp --sport 500  -j ACCEPT

$IPT  -A INPUT -p udp --dport 4500  -j ACCEPT
$IPT -A OUTPUT -p udp --sport 4500  -j ACCEPT


# Allow all tcp connections to outside from server A
$IPT -t filter -A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -t filter -A OUTPUT -p tcp -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT


# Allow incoming ssh:
$IPT -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# Allow incoming https:
$IPT -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# Allow ping from outside Client A to server A
$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
# Allow incoiḿing sssh from client A to server A on interface enp0s3  - host only interface
$IPT -A INPUT -i enp0s3 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o enp0s3 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# allow forwarding packets
$IPT -t filter -A FORWARD -i $HIF -j ACCEPT
$IPT -t filter -A FORWARD -i $NIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# enable SNAT on Server A
$IPT -t nat -A POSTROUTING -j SNAT -o $NIF --to $NIP


# Default policy is to send to a dropping chain
$IPT -t filter -P INPUT DROP
$IPT -t filter -P OUTPUT DROP
$IPT -t filter -P FORWARD DROP


# Create logging chains
$IPT -t filter -N input_log
$IPT -t filter -N output_log
$IPT -t filter -N forward_log

# Set some logging targets for DROPPED packets
$IPT -t filter -A input_log -j LOG --log-level notice --log-prefix "input drop: " 
$IPT -t filter -A output_log -j LOG --log-level notice --log-prefix "output drop: " 
$IPT -t filter -A forward_log -j LOG --log-level notice --log-prefix "forward drop: " 
echo "Added logging"

# Return from the logging chain to the built-in chain
$IPT -t filter -A input_log -j RETURN
$IPT -t filter -A output_log -j RETURN
$IPT -t filter -A forward_log -j RETURN



# These rules must be inserted at the end of the built-in
# chain to log packets that will be dropped by the default
# DROP policy
$IPT -t filter -A INPUT -j input_log
$IPT -t filter -A OUTPUT -j output_log
$IPT -t filter -A FORWARD -j forward_log
