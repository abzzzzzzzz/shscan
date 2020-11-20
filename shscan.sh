#!/bin/bash

#set -x

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

usage()
{
  echo "Usage"
  exit 2
}

NMAP_LOW=0
NMAP_FULL=0
NMAP_A=0
NMAP_VULN=0
NMAP_SAFE=0
ENUM4=0
WEB=0
EXTRA=0

PARSED_ARGUMENTS=$(getopt -n shscan -o lfavsedxuw --long everything -- "$@")

VALID_ARGUMENTS=$?
if [[ ! "$@" ]]; then
  usage
  exit 1
fi

echo "PARSED_ARGUMENTS is $PARSED_ARGUMENTS"
eval set -- "$PARSED_ARGUMENTS"
while :
do
	case "$1" in
		-l ) NMAP_LOW=1; shift ;;
		-f ) NMAP_FULL=1; shift ;;
		-a ) NMAP_A=1; shift ;;
		-v ) NMAP_VULN=1; shift;;
		-s ) NMAP_SAFE=1; shift;;
		-e ) ENUM4=1; shift;;
		-d ) DIRB=1; shift;;
		-x ) EXTRA=1; shift;;
		-u ) NMAP_UDP=1; shift;;
		-w ) WEB=1; shift;;
		--everything )
				EVERYTHING=1;  
				NMAP_LOW=1;
				NMAP_FULL=1;
				NMAP_A=1;
				NMAP_VULN=1;
				NMAP_SAFE=1;
				ENUM4=1;
				WEB=1;
				EXTRA=1;
				NMAP_UDP=1;
				shift;;
		-- ) shift; break ;;
		* ) echo "Dafuq is this?"
			usage ;;
	esac
done
HOSTS=$@
echo "NMAP_LOW: $NMAP_LOW"
echo "NMAP_FULL: $NMAP_FULL"
echo "NMAP_A: $NMAP_A"
echo "NMAP_VULN: $NMAP_VULN"
echo "NMAP_SAFE: $NMAP_SAFE"
echo "ENUM4: $ENUM4"
echo "WEB: $WEB"
echo "HOST: $HOSTS"
echo "EXTRA: $EXTRA"
echo "NMAP_UDP: $NMAP_UDP"
echo "Parameters remaining are: $@"

RDIR=shscan_results_$HOSTS
if [ ! -d $RDIR ]; then
	mkdir $RDIR
fi

if [ $NMAP_LOW -eq 1 ]; then
	printf "\n\n${GREEN}------------Running base nmap scan------------${NC}\n\n"
	/usr/bin/nmap -Pn $HOSTS -oN $RDIR/nmap_base_$HOSTS.txt
fi

if [ $NMAP_FULL -eq 1 ]; then
	printf "\n\n${GREEN}------------Running full nmap scan------------${NC}\n\n"
	/usr/bin/nmap -Pn -p- $HOSTS -oN $RDIR/nmap_full_$HOSTS.txt
fi

while IFS= read -r line
do
	if [[ $line =~ ^[-+]?[0-9]+$ ]]; then
		echo "$line" >> $RDIR/tcp_ports_$HOSTS.txt
	fi
done < <(cat $RDIR/nmap_full_$HOSTS.txt | grep "/tcp" | cut -d "/" -f 1)

sort -nu $RDIR/tcp_ports_$HOSTS.txt -o $RDIR/tcp_ports_$HOSTS.txt

if [ $NMAP_A -eq 1 ]; then
	printf "\n\n${GREEN}------------Scanning ports $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) aggresively------------${NC}\n\n"
	/usr/bin/nmap -sV -sC -A -Pn -p $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) $HOSTS -oN $RDIR/nmap_a_$HOSTS.txt
fi

if [ $ENUM4 -eq 1 ] && [ $(grep "\b445\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
	printf "\n\n${GREEN}------------Enumerating with enum4linux-ng------------${NC}\n\n"
	enum4linux-ng -A $HOSTS | tee $RDIR/enum4ng_noauth_$HOSTS.txt
	printf "\n\n${GREEN}------------Enumerating with enum4linux------------${NC}\n\n"
	/usr/bin/enum4linux -a $HOSTS | tee $RDIR/enum4_noauth_$HOSTS.txt
	printf "\n\n${GREEN}------------Enumerating with smbmap------------${NC}\n\n"
	/usr/bin/smbmap -H $HOSTS | tee $RDIR/smbmap_noauth_$HOSTS.txt
fi

if [ $NMAP_VULN -eq 1 ]; then
	printf "\n\n${GREEN}------------Scanning ports $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) for vulns------------${NC}\n\n"
	/usr/bin/nmap -Pn -sV --script "vuln" -p $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) $HOSTS -oN $RDIR/nmap_vuln_$HOSTS.txt
	if [ $(grep "\b139\b" $RDIR/tcp_ports_$HOSTS.txt) ] || [ $(grep "\b445\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "\n\n${GREEN}------------Scanning ports SMB ports for vulns------------${NC}\n\n"
		/usr/bin/nmap -p 139,445 -T4 -Pn --script 'not brute and not dos and smb-*' -vv -d $HOSTS -oN $RDIR/nmap_smb_$HOSTS.txt
	fi
fi

if [ $NMAP_SAFE -eq 1 ]; then
		printf "\n\n${GREEN}------------Scanning ports $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) for vulns------------${NC}\n\n"
		/usr/bin/nmap -Pn -sV --script "safe" -p $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) $HOSTS -oN $RDIR/nmap_safe_$HOSTS.txt
fi

if [ $WEB -eq 1  ]; then
	HTTP_PORTS=(80 8080 8000 8081 81)
	HTTPS_PORTS=(443 8443)
	printf "\n\n${GREEN}------------Dirbusting, nikto, whatweb and hakrawler scans on $HOSTS------------${NC}\n\n"
	WORDLIST="/opt/tools/all/wordlists/dicc.txt"
	EXTENSIONS=".php,.asp,.aspx,.html,.js"
	DIRBUST="ffuf -w $WORDLIST -e $EXTENSIONS -c"
	
	for HTTP_PORT in ${HTTP_PORTS[@]}; do
		if [ $(grep "\b$HTTP_PORT\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
			printf "\n\n${GREEN}------------Dirbusting on port $HTTP_PORT------------${NC}\n\n"
			$DIRBUST -u http://$HOSTS:$HTTP_PORT/FUZZ | tee $RDIR/ffuf_http_$HOSTS_$HTTP_PORT.txt
			printf "\n\n${GREEN}------------Nikto on port $HTTP_PORT------------${NC}\n\n"
			nikto2 -host $HOSTS -port $HTTP_PORT | tee $RDIR/nikto_http_$HOSTS_$HTTP_PORT.txt
			printf "\n\n${GREEN}------------Whatweb on port $HTTP_PORT------------${NC}\n\n"
			/usr/bin/whatweb http://$HOSTS:$HTTP_PORT -a 3 | tee $RDIR/whatweb_http_$HOSTS_$HTTP_PORT.txt
			printf "\n\n${GREEN}------------Hakrawler on port $HTTP_PORT------------${NC}\n\n"
			hakrawler -all -url http://$HOSTS:$HTTP_PORT | tee $RDIR/hakrawler_http_$HOSTS_$HTTP_PORT.txt
		fi
	done
	for HTTPS_PORT in ${HTTPS_PORTS[@]}; do
		if [ $(grep "\b$HTTPS_PORT\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
			printf "\n\n${GREEN}------------Dirbusting on port $HTTPS_PORT------------${NC}\n\n"
			$DIRBUST -u https://$HOSTS:$HTTPS_PORT/FUZZ | tee $RDIR/ffuf_https_$HOSTS_$HTTPS_PORT.txt
			printf "\n\n${GREEN}------------Nikto on port $HTTPS_PORT------------${NC}\n\n"
			nikto2 -host $HOSTS -port $HTTPS_PORT -ssl | tee $RDIR/nikto_https_$HOSTS_$HTTPS_PORT.txt
			printf "\n\n${GREEN}------------Whatweb on port $HTTPS_PORT------------${NC}\n\n"
			/usr/bin/whatweb https://$HOSTS:$HTTPS_PORT -a 3 | tee $RDIR/whatweb_https_$HOSTS_$HTTPS_PORT.txt
			printf "\n\n${GREEN}------------Hakrawler on port $HTTPS_PORT------------${NC}\n\n"
			hakrawler -all -url https://$HOSTS:$HTTPS_PORT | tee $RDIR/hakrawler_https_$HOSTS_$HTTPS_PORT.txt
		fi
	done
fi

# Extra tests:

if [ $EXTRA -eq 1 ]; then
	printf "\n\n${GREEN}------------Doing some extra tests for ftp,mysql,smtp,kerberos if the ports are open------------${NC}\n\n"
	if [ $(grep "\b21\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "\n\n${GREEN}------------Scanning ftp------------${NC}\n\n"
		nmap --script=ftp-* -p 21 $HOSTS -oN $RDIR/nmap_ftp_$HOSTS.txt
	fi
	if [ $(grep "\b3306\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "\n\n${GREEN}------------Scanning mysql------------${NC}\n\n"
		/usr/bin/nmap -sV -Pn -vv -script=mysql* -p 3306 $HOSTS -oN $RDIR/nmap_mysql_$HOSTS.txt
	fi
	if [ $(grep "\b25\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "\n\n${GREEN}------------Scanning smtp------------${NC}\n\n"
		/usr/bin/nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $HOSTS -oN $RDIR/nmap_smtp_$HOSTS.txt
	fi
	if [ $(grep "\b88\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "\n\n${GREEN}------------Testing kerberos------------${NC}\n\n"
		nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm=research $HOSTS -oN $RDIR/nmap_kerberos_$HOSTS.txt
	fi
fi

if [[ $NMAP_UDP -eq 1 ]]; then
	printf "\n\n${GREEN}------------Scanning for udp ports------------${NC}\n\n"
	/usr/bin/nmap -Pn -sCU $HOSTS -oN $RDIR/nmap_udp_$HOSTS.txt
fi

if [[ $EVERYTHING -eq 1 ]]; then
	printf "\n\n${GREEN}------------Doing a verbose connect scan, just to make sure everything nothing slipped------------${NC}\n"
	printf "${GREEN}------------This will probably take a lot of time------------${NC}\n\n"
	/usr/bin/nmap -Pn -v 4 -sT -p- $HOSTS -oN $RDIR/nmap_udp_$HOSTS.txt
fi

