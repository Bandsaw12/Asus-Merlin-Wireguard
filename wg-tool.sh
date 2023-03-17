#!/bin/sh

# Wireguard Server/Client Script
# Date last revised: 2023-03-17
# Version 1.0
#
# This script can be used on select Asus AC series HND routers and AX Routers using AsusWRT Merlin firmware 386.4 and above
# without having to use Entware or an external USB Hard drive.                                                   
#
# See notes at bottom of script for other information
# Default all traffic routing is done as per https://www.wireguard.com/netns/ (Improved Rule Based Routing)
# Some firwall rules are set up as per https://www.procustodibus.com/blog/2022/01/wg-quick-firewall-rules/
#
# Origional Wireguard scripts inspired by SNBForum User @Odkrys  - https://github.com/odkrys/entware-makefile-for-merlin/tree/main/wireguard-tools/files
# Some code snipits inspired by SNBForum User @JackYaz
# IP6Tables rules inspired by SNBForum User @Martineau Wireguard Service Manager
#
# Note that IPv6 have not been tested as I don't have IPv6.  Done the best I could to implament
############################################################################################################################

#set -x # enable debugging.  Comment out when debugging is not needed

source /usr/sbin/helper.sh

TMPDIR="/tmp/wireguard"
WORKDIR="$(dirname $(find /jffs -name $(basename $0)))"
SCRIPTNAME="$(basename $0)"
PROTO=""
SET_DEFAULT="NO"
LAN_CIDR=""
LAN_ADDR=$(nvram get lan_ipaddr) 
IPV6_SERVICE=$(nvram get ipv6_service)
LAN_NETMASK=$(nvram get lan_netmask)

Regex_IPV4="(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
Regex_IPV6="(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"


### Start of output format variables ###
readonly CRIT="\\e[41m"
readonly ERR="\\e[31m"
readonly WARN="\\e[33m"
readonly PASS="\\e[32m"
readonly BOLD="\\e[1m"
readonly SETTING="${BOLD}\\e[36m"
readonly CLEARFORMAT="\\e[0m"
### End of output format variables ###

WAN_Name(){
	echo $(nvram get wan0_ifname)  
}

Get_IPv4() {
	grep -oE "$Regex_IPV4"
}

Get_IPv6() {
	grep -oE "$Regex_IPV6"
}

Get_IPv4_CIDR () {
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/(3[012]|[12]?[0-9])'
}

Is_IPv6() {
    # Note this matches compression anywhere in the address, though it won't match the loopback address ::1
    grep -oE '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'       # IPv6 format -very crude
}

Get_Network() {
	# $1 network address passed as a CIDR address (i.e. 192.168.165.200/24
	# Returns the network part of the address (i.e. for 192.168.165.200/24 -> 192.168.165.0)

	local IP no
	local o1 o2 o3 o4
	local value
	local n1 n2 n3 n4

	IP="$( echo $1 | cut -d"/" -f1 )"
	no="$( echo $1 | cut -d"/" -f2 )"

	o1="$(echo ${IP} | tr "." " " | awk '{ print $1 }')"
	o2="$(echo ${IP} | tr "." " " | awk '{ print $2 }')"
	o3="$(echo ${IP} | tr "." " " | awk '{ print $3 }')"
	o4="$(echo ${IP} | tr "." " " | awk '{ print $4 }')"

	value=$(( 0xffffffff ^ ((1 << (32 - $no)) - 1) ))
	n1="$(( (value >> 24) & 0xff ))"
	n2="$(( (value >> 16) & 0xff ))"
	n3="$(( (value >> 8) & 0xff ))"
	n4="$(( value & 0xff ))"

	ip1=$((o1 & n1))
	ip2=$((o2 & n2))
	ip3=$((o3 & n3))
	ip4=$((o4 & n4))

	echo "${ip1}.${ip2}.${ip3}.${ip4}"
}

mask2cdr() {
	# $1 is the netmask to be converted to cidr (i.e 255.255.255.0 -> /24)
	# Assumes there's no "255." after a non-255 byte in the mask
	local x=${1##*255.}
	set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
	x=${1%%$3*}
	echo \/$(( $2 + (${#x}/4) ))
}

Print_Output(){
	#   $1 = Print action (false = print to screen only, true = print to syslog only, both = print to both screen and syslog
	#   $2 = Message to print
	#   $3 = formatting, if any
	if [ "$1" = "true" ] || [ "$1" = "both" ]; then
		logger -t "$SCRIPTNAME" "$2"
	fi
	if [ "$1" = "false" ] || [ "$1" = "both" ]; then
		printf "${BOLD}${3}%s${CLEARFORMAT}\\n" "$2"
	fi
}

cmd() {
	[ "$SHOWCMD" = "TRUE" ] && echo "[#] $@" >&2
	"$@"
}

Check_Lock() {
	# Check for lock file. If exists, loop for 60 seconds, then delete stuck process and continue
	while [ -f "/tmp/$(basename $0).lock" ]; do
		ageoflock=$(($(date +%s) - $(date +%s -r /tmp/$(basename $0).lock)))
		if [ "$ageoflock" -gt 60 ]; then
			# "Stale lock file found (>60 seconds old) - kill stuck process and purge lock"
			Print_Output both "Waited for 60 seconds or more for lock file to release, killing stuck process and continuing" $WARN
			kill "$(sed -n '1p' /tmp/$(basename $0).lock)" >/dev/null 2>&1
			rm -f "/tmp/$(basename $0).lock" 2>/dev/null
			# we will sleep for a couple of seconds to give the old process time to kill and cleanup
			sleep 4
			return 0
		else
			# "Lock file found (age: $ageoflock seconds) - pause for 5 seconds and recheck"
			Print_Output both "Lock file found - waiting 5 seconds (to a maximum of 60 seconds" $WARN
			sleep 5
		fi
	done
}

Lock() {
	# create lock file
	Print_Output true "Creating lock file"
	echo "$$" > "/tmp/$(basename $0).lock"
}

Clear_Lock() {
	# Cleanup lock file
	Print_Output true "Removing lock file"
	rm -f "/tmp/$(basename $0).lock" 2>/dev/null
}

Get_AddrPort() {
	local ip v
	WGport=""
	WGaddress=""
	MTU="0"
	DNS=""
	DNS_SEARCH=""
	TABLE="auto"
	PRE_UP=""
	PRE_DOWN=""
	POST_UP=""
	POST_DOWN=""
	WGMODE=""

	mkdir -p ${TMPDIR}
	
	[ -f "${TMPDIR}/${WGIF}_PREUP" ] && rm -f "${TMPDIR}/${WGIF}_PREUP"
	[ -f "${TMPDIR}/${WGIF}_POSTUP" ] && rm -f "${TMPDIR}/${WGIF}_POSTUP"
	[ -f "${TMPDIR}/${WGIF}_PREDOWN" ] && rm -f "${TMPDIR}/${WGIF}_PREDOWN"
	[ -f "${TMPDIR}/${WGIF}_POSTDOWN" ] &&  rm -f "${TMPDIR}/${WGIF}_POSTDOWN"

	while read -r line
	do	
		stripped="${line%%\#*}"
		key="${stripped%%=*}"; key="${key##*([[:space:]])}"; key=$(echo ${key} | awk '{$1=$1};1' | tr '[a-z]' '[A-Z]')
		value="${stripped#*=}"; value="${value##*([[:space:]])}"; value=$(echo ${value} | awk '{$1=$1};1')

		case $key in
			"[PEER]") interface_section="0"; continue ;;
			"[INTERFACE]") interface_section="1"; continue ;;
		esac
		if [ "$interface_section" = "1" ]; then
			case $key in
				ADDRESS)
					for v in ${value//,/ }
					do
						t=0
						if [ -z $(echo $v | Get_IPv4) ]; then
							if [ -n $(echo $v | Get_IPv6) ]; then
								t="1"
							fi
						else
							t="1"
						fi
						if [ "$t" = "1" ];then
							WGaddress="$WGaddress ""$v"
						else	
							Print_Output false "Warning: Invaled IP Address Found in config file" $WARN
						fi
					done
					continue
					;;
				MTU)
					MTU="$value"
					continue
					;;
				DNS)
					for v in ${value//,/ }
					do
						ip=""
						ip=$(echo $v | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
						if [ $ip != "" ]; then
							DNS="$DNS "$ip
						else
							DNS_SEARCH="$DNS_SEARCH ""$v"
						fi
					done
					continue
					;;
				LISTENPORT) WGport="$value"
				continue
				;;
			TABLE)
				TABLE="$value"
				continue
				;;
			PREUP)
				echo "$value" >> ${TMPDIR}/${WGIF}_PREUP
				continue
				;;
			PREDOWN)
				echo "$value" >> ${TMPDIR}/${WGIF}_PREDOWN
				continue
					;;
			POSTUP)
				echo "$value" >> ${TMPDIR}/${WGIF}_POSTUP
				continue
				;;
			POSTDOWN)
				echo "$value" >> ${TMPDIR}/${WGIF}_POSTDOWN
				continue
				;;
			SAVECONFIG)
				SAVE_CONFIG="$value"
				continue
				;;
			esac
		fi
	done < $WGconf
	
	if [ "$WGaddress" = "" ];then
		Print_Output both "No interface address in config file found" $ERR
		return 1
	fi
	
	if [ -n "$(grep -E -i "^Endpoint" "$WGconf")" ];then
		WGMODE="client"
	fi

	MakeWGCONFfile
	return 0
}

Set_MTU(){
	local ip i1 i2 i3 mtu

	if [ "${MTU}" -gt 0 ];then
		cmd ip link set mtu $MTU up dev "${WGIF}"
		return 0
	fi

	mtu=0
	ip="$(wg show ${WGIF} endpoints | Get_IPv4)"
	[ -z ${ip} ]&& ip="$(wg show ${WGIF} endpoints | Get_IPv6)"

	if [ -n "${ip}" ]; then
		wg show "${WGIF}" endpoints > /tmp/wg0endpoints
		while read -r line
		do
			ip="$(echo ${line} | Get_IPv4)"
			[ -z "${ip}" ] && ip="$(echo ${line} | Get_IPv6)"
			if [ "$ip" != "" ];then
				i1="$(ip route get "${ip}" | awk '{for(i=1; i<=NF; i++) if($i~/mtu/) print $(i+1)}')"
				if [ "${i1}" = "" ];then
					i2="$(ip route get ${ip} | awk '{for(i=1; i<=NF; i++) if($i~/dev/) print $(i+1)}')"
					i3="$(ip link show dev ${i2} | awk '{for(i=1; i<=NF; i++) if($i~/mtu/) print $(i+1)}')"
				fi
			fi

			[ "${i3}" -gt $mtu ] && mtu="${i3}"

		done < /tmp/wg0endpoints
	fi
	
	[ "${mtu}" -eq 0 ] && mtu="$(ip link show dev ${IF_NAME} | grep 'mtu' | awk '{print $2}')"
	let mtu=$((mtu - 80))
	MTU="${mtu}"
	cmd ip link set mtu ${mtu} up dev "$WGIF"

}

Get_fwmark() {
	local fwmark
	fwmark="$(wg show "${WGIF}" fwmark)" || return 1
	if [ -n "${fwmark}" ] && [ "${fwmark}" != "off" ]; then
		printf "%d" "${fwmark}"
		return 0
	else
		return 1
	fi
}	

Add_Default() {      # Add default route (0.0.0.0/0) by overriding default route
	# This function is not currenly used.  
	# $1 is the subnet passed to routine (i.e 1.2.3.4/24)
	local table line

	PROTO="$(echo "${1}" | Get_IPv4)"
	[ -n "${PROTO}" ] && PROTO="-4" || PROTO="-6"

	if [ "$(wg show interfaces | wc -w)" -gt 1 ];then
		for iface in "$(wg show interfaces)"
		do
			ip route del 0/1   dev $iface  2>/dev/null
			ip route del 128/1 dev $iface  2>/dev/null
			if [ "$PROTO" == "-6" ];then
				ip -6 route del 0::/1    dev $iface 2>/dev/null     
				ip -6 route del 8000::/1 dev $iface 2>/dev/null     
			fi
		done
	fi 

	if [ "$PROTO" = "-4" ]; then
		if [ -z "$(ip route show 0/1 | grep "dev ${WGIF}")" ];then
			host="$(wg show ${WGIF} endpoints | sed -n 's/.*\t\(.*\):.*/\1/p')"
			ip route add $(ip route get $host | sed '/ via [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/{s/^\(.* via [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/}' | head -n 1) 2>/dev/null
			cmd ip -4 route add 0/1   dev "${WGIF}"
			cmd ip -4 route add 128/1 dev "${WGIF}"
		fi
	else	
		if [ -z "$(ip -6 route show ::/1 | grep "dev ${WGIF}")" ];then
			cmd ip -6 route add 0::/1    dev "${WGIF}"
            cmd ip -6 route add 8000::/1 dev "${WGIF}"
		fi
	fi
}

Add_Default_Policy() {      # Add default route via enhanced policy rules.
	# See https://www.wireguard.com/netns/ -> Improved rule-based routing 
	# $1 is the subnet passed to routine (i.e 1.2.3.4/24)
	local table line

	PROTO="$(echo "${1}" | Get_IPv4)"
	[ -n ${PROTO} ] && PROTO="-4" || PROTO="-6"
	if ! $(table=$(Get_fwmark)); then
		table=51820
		
		while [ -n "$(ip ${PROTO} route show table $table)" ]
		do
			let table=$((table+1))
		done
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
		wg set "${WGIF}" fwmark "${table}"
	fi		

	cmd ip "${PROTO}" route add "${1}" dev "${WGIF}" table "${table}"
	cmd ip "${PROTO}" rule add not fwmark "${table}" table "${table}"
	cmd ip "${PROTO}" rule add table main suppress_prefixlength 0
	if [ "${PROTO}" -eq "-4" ]; then
		echo 1 > /proc/sys/net/ipv4/conf/all/src_valid_mark
		echo 0 > /proc/sys/net/ipv4/conf/"${WGIF}"/rp_filter
	fi
	POLICYDEFAULT="YES"

	return 0
}

Add_Route() {

	# $1 - IP Address/Subnet to add to route
	[ "${TABLE}" = "off" ] && return 0

	if [ -n $(echo "${1}" | Get_IPv4) ]; then PROTO="-4"; else PROTO="-6";fi

	snet=$(echo "${1}" | grep '/0$')

	if [ -n "${TABLE}" ]; then
		if [ "$TABLE" != "auto" ]; then
			cmd ip "${PROTO}" route add "${1}" dev "${WGIF}" table "${TABLE}"
		elif [ -n "${snet}" ]; then
			# Add_Default "${1}"		# Uncomment this line and comment next line to use traditional default routes
			Add_Default_Policy "${1}"	# Uncomment this line and comment above line to enable Rule-Based default routes
		else
			i2="$(ip route show dev ${WGIF} match ${1})"
			if [ -z "$i2" ]; then
				cmd ip "${PROTO}" route add "${1}" dev "${WGIF}"
			fi
		fi
	fi
}

Hooks() {
	# $1 hook to execute
	local hook filename
	filename="${TMPDIR}"/"${WGIF}_${1}"
	if [ -f "${filename}" ]; then
		while read -r hook; do
			hook="${hook//%i/$WGIF}"
			(eval "$hook")
		done < $filename
	fi
}

CheckForWGIF() {
	# $1 Wireguard interface to check for
	TmpStr=$(wg show interfaces | grep $1)
	if [ -n "${TmpStr}" ]; then
		return 0
	else
		return 1
	fi
}

MakeWGCONFfile() {

	local word w
	
	mkdir -p ${TMPDIR}
	WGCONF="${TMPDIR}/${WGIF}.conf"
	
	cp -f ${WGconf} ${WGCONF}
	
	for w in Address MTU DNS Table PreUp PreDown PostUp PostDown SaveConfig
	do
		word="$(grep -oi "^${w}" $WGCONF)"
		if [ -n "$word" ];then
			sed -i "/^${word}/d" $WGCONF
		fi
	done
}

Delete_Firewall_Rules() {
	Print_Output both "Deleting firewall rules" $PASS

	iptables -D INPUT -i "${WGIF}" -j ACCEPT 2>/dev/null
	iptables -D FORWARD -i "${WGIF}" -j ACCEPT 2>/dev/null
	iptables -D FORWARD -o "${WGIF}" -j ACCEPT 2>/dev/null
	iptables -D OUTPUT -o "${WGIF}" -j ACCEPT 2>/dev/null
	iptables -D INPUT -p udp --dport $WGport -j ACCEPT 2>/dev/null
}

Add_Firewall_Rules() {
	Print_Output both "Adding firewall rules" $PASS

	cmd iptables -I INPUT -i "${WGIF}" -j ACCEPT
	cmd iptables -I FORWARD -i "${WGIF}" -j ACCEPT
	cmd iptables -I FORWARD -o "${WGIF}" -j ACCEPT
	cmd iptables -I OUTPUT -o "${WGIF}" -j ACCEPT

	[ -n "$WGport" ] &&	cmd iptables -I INPUT -p udp --dport "$WGport" -j ACCEPT
	
	if [ "${IPV6_SERVICE}" != "disabled" ]; then
		cmd ip6tables -I INPUT -i "${WGIF}" -j ACCEPT
		cmd ip6tables -I FORWARD -i "${WGIF}" -j ACCEPT
		cmd ip6tables -I FORWARD -o "${WGIF}" -j ACCEPT
		cmd ip6tables -I OUTPUT -o "${WGIF}" -j ACCEPT
		
		[ -n "$WGport" ] &&	cmd ip6tables -I INPUT -p udp --dport "$WGport" -j ACCEPT
	fi
}

Delete_NAT_Rules() {

	local nm lan lan1
	Print_Output both "Deleting NAT Rules" $PASS

	iptables -t mangle -D PREROUTING -i "${WGIF}" -j MARK --set-xmark 0x01/0x7 2>/dev/null
	iptables -t mangle -D FORWARD -o "${WGIF}" -j MARK --set-xmark 0x01/0x7 2>/dev/null
	iptables -t mangle -D FORWARD -i "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
	iptables -t mangle -D FORWARD -o "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
	iptables -t nat -D PREROUTING -p udp --dport "$WGport" -j ACCEPT 2>/dev/null
	
	iptables -t mangle -D PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
	iptables -t mangle -D POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
	iptables -t raw -D PREROUTING -d ${WGaddress} ! -i ${WGIF} -m addrtype ! --src-type LOCAL -j DROP 2>/dev/null

	iptables -t nat -D PREROUTING -p tcp -m tcp --dport 53 -j DNS${WGIF} 2>/dev/null
	iptables -t nat -D PREROUTING -p udp -m udp --dport 53 -j DNS${WGIF} 2>/dev/null
	iptables -t nat -D OUTPUT -o ${WGIF} -p tcp -m tcp --dport 53 -j "DNS${WGIF}" 2>/dev/null
	iptables -t nat -D OUTPUT -o ${WGIF} -p udp -m udp --dport 53 -j "DNS${WGIF}" 2>/dev/null
	iptables -t nat -F DNS${WGIF} 2>/dev/null
	iptables -t nat -X DNS${WGIF} 2>/dev/null

	iptables -t raw -D PREROUTING -d ${WGaddress} ! -i ${WGIF} -m addrtype ! --src-type LOCAL -j DROP 2>/dev/null
	iptables -t mangle -D PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
	iptables -t mangle -D POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
	
	if [ "$WGMODE" != "client" ]; then
		iptables -t nat -D POSTROUTING -s "$(Get_Network $WGaddress)" -o "$(WAN_Name)" -j MASQUERADE 2>/dev/null
	else	
		iptables -t nat -D POSTROUTING -s "${LAN_SUBNET}" -o "$WGIF" -j MASQUERADE 2>/dev/null
	fi
	
	if [ "${IPV6_SERVICE}" != "disabled" ]; then
		ip6tables -t mangle -D PREROUTING -i "${WGIF}" -j MARK --set-xmark 0x01/0x7 2>/dev/null
		ip6tables -t mangle -D FORWARD -o "${WGIF}" -j MARK --set-xmark 0x01/0x7 2>/dev/null
		ip6tables -t mangle -D FORWARD -i "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
		ip6tables -t mangle -D FORWARD -o "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
		ip6tables -t nat -D PREROUTING -p udp --dport "$WGport" -j ACCEPT 2>/dev/null
	
		ip6tables -t mangle -D PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
		ip6tables -t mangle -D POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
		ip6tables -t raw -D PREROUTING -d ${WGaddress} ! -i ${WGIF} -m addrtype ! --src-type LOCAL -j DROP 2>/dev/null

		ip6tables -t nat -D PREROUTING -p tcp -m tcp --dport 53 -j DNS${WGIF} 2>/dev/null
		ip6tables -t nat -D PREROUTING -p udp -m udp --dport 53 -j DNS${WGIF} 2>/dev/null
		ip6tables -t nat -D OUTPUT -o ${WGIF} -p tcp -m tcp --dport 53 -j "DNS${WGIF}" 2>/dev/null
		ip6tables -t nat -D OUTPUT -o ${WGIF} -p udp -m udp --dport 53 -j "DNS${WGIF}" 2>/dev/null
		ip6tables -t nat -F DNS${WGIF} 2>/dev/null
		ip6tables -t nat -X DNS${WGIF} 2>/dev/null

		ip6tables -t raw -D PREROUTING -d ${WGaddress} ! -i ${WGIF} -m addrtype ! --src-type LOCAL -j DROP 2>/dev/null
		ip6tables -t mangle -D PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
		ip6tables -t mangle -D POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff 2>/dev/null
	
		if [ "$WGMODE" != "client" ]; then
			ip6tables -t nat -D POSTROUTING -s "$(Get_Network $WGaddress)" -o "$(WAN_Name)" -j MASQUERADE 2>/dev/null
		else	
			ip6tables -t nat -D POSTROUTING -s "${LAN_SUBNET}" -o "$WGIF" -j MASQUERADE 2>/dev/null
		fi
	fi
}

Add_NAT_Rules() {

	local nm lan lan1

	Print_Output both "Adding NAT Rules" $PASS
	[ -z "$(wg show ${WGIF} endpoints)" ] && MODE="SERVER" || MODE="CLIENT"

	cmd iptables -t mangle -I FORWARD -o "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	cmd iptables -t mangle -I FORWARD -i "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	cmd iptables -t mangle -I FORWARD -o "${WGIF}" -j MARK --set-xmark 0x01/0x7
	cmd iptables -t mangle -I PREROUTING -i "${WGIF}" -j MARK --set-xmark 0x01/0x7
	
	if [ "${IPV6_SERVICE}" != "disabled" ]; then
		cmd ip6tables -t mangle -I FORWARD -o "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
		cmd ip6tables -t mangle -I FORWARD -i "${WGIF}" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
		cmd ip6tables -t mangle -I FORWARD -o "${WGIF}" -j MARK --set-xmark 0x01/0x7
		cmd ip6tables -t mangle -I PREROUTING -i "${WGIF}" -j MARK --set-xmark 0x01/0x7
	fi
	
	if [ "$WGMODE" != "client" ];then
		cmd iptables -t nat -I POSTROUTING -s "$(Get_Network $WGaddress)" -o "$(WAN_Name)" -j MASQUERADE
		cmd iptables -t nat -I PREROUTING -p udp --dport "$WGport" -j ACCEPT
	else
		cmd iptables -t nat -I POSTROUTING -s "${LAN_SUBNET}" -o "$WGIF" -j MASQUERADE
	fi
	
	[ -n "$DNS" ] && Add_DNS_Iptables
	
	if [ "$POLICYDEFAULT" == "YES" ];then
		if [ -z "$(iptables-save | grep '\-A PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff')" ]; then
			cmd iptables -t mangle -A PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
		fi
		if [ -z "$(iptables-save | grep '\-A POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff')" ]; then
			cmd iptables -t mangle -A POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff
		fi

		if [ "${IPV6_SERVICE}" != "disabled" ]; then
			if [ -z "$(ip6tables-save | grep '\-A PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff')" ]; then
				cmd ip6tables -t mangle -A PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
			fi
			if [ -z "$(ip6tables-save | grep '\-A POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff')" ]; then
				cmd ip6tables -t mangle -A POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff
			fi	
		fi
		
		for n in $WGaddress
		do	
			if [ "$(echo $n | Get_IPv4)" ]; then
				cmd iptables -t raw -A PREROUTING -d ${WGaddress} ! -i ${WGIF} -m addrtype ! --src-type LOCAL -j DROP
			elif [ "$(echo $n | Get_IPv6)" ]; then
				cmd ip6tables -t raw -A PREROUTING -d ${WGaddress} ! -i ${WGIF} -m addrtype ! --src-type LOCAL -j DROP
			fi
		done
	fi
	
}

Add_DNS_Iptables() {

	cmd iptables -t nat -N DNS${WGIF}
	cmd iptables -t nat -I PREROUTING -p tcp -m tcp --dport 53 -j "DNS${WGIF}" 
	cmd iptables -t nat -I PREROUTING -p udp -m udp --dport 53 -j "DNS${WGIF}" 
	cmd iptables -t nat -I OUTPUT -o ${WGIF} -p tcp -m tcp --dport 53 -j "DNS${WGIF}" 
	cmd iptables -t nat -I OUTPUT -o ${WGIF} -p udp -m udp --dport 53 -j "DNS${WGIF}" 

	if [ "${IPV6_SERVICE}" != "disabled" ]; then
		cmd ip6tables -t nat -N DNS${WGIF}
		cmd ip6tables -t nat -I PREROUTING -p tcp -m tcp --dport 53 -j "DNS${WGIF}" 
		cmd ip6tables -t nat -I PREROUTING -p udp -m udp --dport 53 -j "DNS${WGIF}" 
		cmd ip6tables -t nat -I OUTPUT -o ${WGIF} -p tcp -m tcp --dport 53 -j "DNS${WGIF}" 
		cmd ip6tables -t nat -I OUTPUT -o ${WGIF} -p udp -m udp --dport 53 -j "DNS${WGIF}" 
	fi
	for d in $DNS
	do
		cmd iptables -t nat -I DNS${WGIF} -p tcp -s "${LAN_SUBNET}" -j DNAT --to-destination "${d}:53"
		cmd iptables -t nat -I DNS${WGIF} -p udp -s "${LAN_SUBNET}" -j DNAT --to-destination "${d}:53"

		if [ "${IPV6_SERVICE}" != "disabled" ]; then
			cmd ip6tables -t nat -I DNS${WGIF} -p tcp -s "${LAN_SUBNET}" -j DNAT --to-destination "${d}:53"
			cmd ip6tables -t nat -I DNS${WGIF} -p udp -s "${LAN_SUBNET}" -j DNAT --to-destination "${d}:53"
		fi
	
	done
}

WG_UP() {
	local v line

	if CheckForWGIF ${WGIF}; then
		Print_Output both "Wireguard interface ${WGIF} appears to be already up!  To restart use the RESTART command" $WARN
		return 1
	fi
	Print_Output true "Bringing wireguard interface up"

	modprobe -q xt_set       # only required if ipset (policy) rules are required
	if modprobe -q wireguard; then
		
		Get_AddrPort
		if [ "$?" -eq 1 ]; then Leave;fi 
		Hooks PREUP

		[ -n $(echo $WGaddress | Get_IPv4) ] && PROTO="-4" || PROTO="-6"

		cmd ip link add dev "${WGIF}" type wireguard
		wg setconf "${WGIF}" "${WGCONF}"

		for v in "${WGaddress}"
		do	
			PROTO="$(echo ${v} | Get_IPv4)"
			[ -n "${PROTO}" ] && PROTO="-4" || PROTO="-6"
			cmd ip $PROTO address add dev "${WGIF}" "$WGaddress"
		done
		
		cmd ip link set up dev "${WGIF}"
		Set_MTU
		ifconfig "${WGIF}" txqueuelen 1000

		wg show ${WGIF} allowed-ips | Get_IPv4_CIDR | sort -nr -k 2 -t / > /tmp/allowed-ips.txt
		wg show ${WGIF} allowed-ips | Get_IPv6 | sort -nr -k 2 -t / >> /tmp/allowed-ips.txt

		while read -r line
		do
			for i in ${line}
			do
				Add_Route "$i"
			done
		done < /tmp/allowed-ips.txt
	
		if CheckForWGIF ${WGIF}; then
			Print_Output both "Wireguard interface ${WGIF} successfully added" $PASS
			Hooks POSTUP
			return 0
		else	
			Print_Output both "Wireguard interface ${WGIF} failed to be created" $ERR
			return 1
		fi
	else
		Print_Output both "Wireguard kernel module could not be loaded!  Exiting" $ERR
		return 1
	fi
}

WG_DOWN() {

	local table
	Print_Output true "Bringing wireguard interface down"

	if ! CheckForWGIF ${WGIF}; then
		Print_Output both "Wireguard interface ${WGIF} does not exist" $WARN
		return 1
	else
		Get_AddrPort
		Hooks PREDOWN
		
		PROTO="$(echo $WGaddress | Get_IPv4)"
		[ -n ${PROTO} ] && PROTO="-4" || PROTO="-6"
		
		if [ -z "$TABLE" ] || [ "$TABLE" = "auto" ];then
			if table=$(Get_fwmark); then
				if [ -n "$(wg show ${WGIF} allowed-ips | Get_IPv4_CIDR)" ];then
					while [ -n "$(ip -4 rule show | grep "lookup $table")" ]; do
						cmd ip -4 rule delete table $table
					done
					while [ -n "$(ip rule show | grep "from all lookup main suppress_prefixlength 0")" ]; do
						cmd ip rule delete table main suppress_prefixlength 0
					done	
				fi
				if [ -n "$(wg show ${WGIF} allowed-ips | Get_IPv6)" ];then
					while [ -n "$(ip -6 rule show | grep "lookup $table")" ]; do
						cmd ip -6 rule delete table $table
					done
					while [ -n "$(ip -6 rule show | grep "from all lookup main suppress_prefixlength 0")" ]; do
						cmd ip -6 rule delete table main suppress_prefixlength 0
					done
				fi
			fi
		else 
			host="$(wg show ${WGIF} endpoints | Get_IPv4)"
			[ -z "$host" ] && host="$(wg show ${WGIF} endpoints | Get_IPv6)"
			[ -n "$host" ] && cmd ip $PROTO route del $(ip $PROTO route get $host | sed '/ via [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/{s/^\(.* via [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/}' | head -n 1)
		fi

		cmd ip link del dev "${WGIF}"
		
		if ! CheckForWGIF ${WGIF}; then
			Hooks POSTDOWN
			Print_Output both "Wireguard interface ${WGIF} successfully deleted" $PASS
		else
			Print_Output both "Wireguard interface ${WGIF} failed to delete" $ERR
		fi

		return 0
	fi
}

Leave() {
	rm -R ${TMPDIR} 2>/dev/null
	Clear_Lock
	exit 0
}

CheckWGIFargument() {
	WGIF="${1}"

	if [ -z ${WGIF} ];then
		Print_Output both "No wg interface name provided!" $ERR
		return 1
	fi
	
	WGconf="${WORKDIR}/${WGIF}.conf"

	if [ -f "$WGconf" ]; then
		return 0
	else
		if [ -f /jffs/addons/wireguard/${WGIF}.conf ]; then
			WGconf="/jffs/addons/wireguard/"${WGIF}".conf"
			return 0
		else
			Print_Output false "Wireguard Config file ${WGconf} does not exist" $ERR
			return 1
		fi
	fi
}

Show_Help(){
	cat <<EOF

Usage: ${SCRIPTNAME} [ start | stop | restart ] [ interface ]  <show>
       ${SCRIPTNAME} [ firewall | nat ] <show>

Available commands:
  $NAME start <interface>          starts the wireguard interface
  $NAME stop  <interface>          stops the wireguard intertface
  $NAME restart <interface>        restarts the wireguard interface
  $NAME firewall                   used inside the firewall-start script 
                              to check if the any interfacs are up, and reapplies the firewall iptables rules
  $NAME nat                        used inside the natstart script
                              to check if the any interfacs are up, and reapplies the NAT iptables rules

	  The argument <show> can be added which will print additional information about the startup or shutdown
	  of an interface.
							  
	  INTERFACE is an interface name, with configuration found at either the same directory which
	  this script is located or at /jffs/addons/wireguard/INTERFACE.conf. It is to be readable
	  by wg(8)'s \`setconf' sub-command, with the exception of the following additions
	  to the [Interface] section, which are handled by $SCRIPTNAME:

	  - Address: may be specified one or more times and contains one or more
	    IP addresses (with an optional CIDR mask) to be set for the interface.
	  - DNS: an optional DNS server to use while the device is up.
	  - MTU: an optional MTU for the interface; if unspecified, auto-calculated.
	  - Table: an optional routing table to which routes will be added; if
	    unspecified or \`auto', the default table is used. If \`off', no routes
	    are added.
	  - PreUp, PostUp, PreDown, PostDown: script snippets which will be executed
	    by bash(1) at the corresponding phases of the link, most commonly used
	    to configure DNS. The string \`%i' is expanded to INTERFACE.
EOF
	printf "\\n"
}

#####################################################################################################
# Start of main script

if ! [ "$#" -ge 1 ]; then	
	Show_Help
	Leave
fi

Print_Output true "Script is starting"
# Clear_Lock  # Uncomment this line for trouble shooting purposes
Check_Lock
Lock

if [ "$IPV6_SERVICE" != "disabled" ];then
    case $IPV6_SERVICE in
        native|ipv6pt|dhcp6|6to4|6in4|6rd)
            # ip -6 addr | grep "scope global"
            USE_IPV6="Y"; IPV6_TXT="(IPv6) "   
            LAN_SUBNET_IPV6=$(nvram get ipv6_prefix) 
            LAN_ADDR_IPV6=$(nvram get ipv6_rtr_addr)
        ;;
        other)
            :
        ;;
        spoof|simulate)
            USE_IPV6="Y"; IPV6_TXT="(IPv6) Simulate "
        ;;
    esac
fi

LAN_CIDR=$(mask2cdr ${LAN_NETMASK})
LAN_SUBNET="$(Get_Network "${LAN_ADDR}""$LAN_CIDR")${LAN_CIDR}"

ACTION=$(echo "$1" | tr '[a-z]' '[A-Z]')

case "${ACTION}" in
	"START")
		Print_Output true "Script called to start wireguard interface - IFace: ${2}"
		[ "$3" = "show" ] && SHOWCMD="TRUE" || SHOWCMD="FALSE"
		if [ "$#" -ge "2" ]; then
			if CheckWGIFargument "$2"; then
				if WG_UP; then
					Add_Firewall_Rules
					Add_NAT_Rules
				else
					Print_Output both "Error reported parsing config file, not adding firewall entries" $WARN
				fi
			fi
		else	
			Print_Output false "Not enough arument... Expecting wg interface name" $WARN
			Show_Help
		fi
	;;
	"STOP")
		Print_Output true "Script called to stop wireguard interface - IFace: ${2}"
		[ "$3" = "show" ] && SHOWCMD="TRUE" || SHOWCMD="FALSE"
		if [ "$#" -ge "2" ];then
			if CheckWGIFargument "$2"; then
				if WG_DOWN; then
					Delete_Firewall_Rules
					Delete_NAT_Rules
				fi
			fi
		else	
			Print_Output false "Not enough arument... Expecting wg interface name" $WARN
			Show_Help
		fi
	;;
	"RESTART")
		Print_Output true "Script called to restart wireguard interface - IFace: ${2}"
		[ "$3" = "show" ] && SHOWCMD="TRUE" || SHOWCMD="FALSE"
		if [ "$#" -ge "2" ]; then
			if CheckWGIFargument "$2"; then
				WG_DOWN
				Delete_Firewall_Rules
				Delete_NAT_Rules
				sleep 2
				if WG_UP; then
					Add_Firewall_Rules
					Add_NAT_Rules
				else
					Print_Output both "Error reported parsing config file, not adding firewall entries" $WARN				
				fi
			fi
		else
			Print_Output false "Not enough arument... Expecting wg interface name" $WARN
			Show_Help	
		fi
	;;
	"FIREWALL")
		Print_Output both "Script called to add firewall rules for all wireguard instances"
		[ "$2" = "show" ] && SHOWCMD="TRUE" || SHOWCMD="FALSE"
		
		for i in $(wg show interfaces)
		do
			CheckWGIFargument ${i}
			if Get_AddrPort; then
				Delete_Firewall_Rules
				Add_Firewall_Rules
			else	
				Print_Output both "Error parsing config file for interface ${i}" $ERR
			fi
		done
	;;
	"NAT")
		Print_Output both "Script called to add NAT iptables rules for all wireguard interfaces"
		[ "$2" = "show" ] && SHOWCMD="TRUE" || SHOWCMD="FALSE"
		
		for i in $(wg show interfaces)
		do
			CheckWGIFargument ${i}
			if Get_AddrPort; then
				Delete_NAT_Rules
				Add_NAT_Rules
			else	
				Print_Output both "Error parsing config file for interface ${i}" $ERR
			fi
		done
	;;
	*)
		Print_Output false "Unknown argument" $ERR
		echo
		Show_Help
	;;
esac

Print_Output true "Script exiting"
Leave

##########
# Other information
#
# Parts of the code used in this script is credited to SNBForum users @JackYaz and @Odkrys

