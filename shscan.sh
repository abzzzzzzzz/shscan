#!/bin/bash

#set -x

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

PARSED_ARGUMENTS=$(getopt -n shscan -o lfavs --long everything -- "$@")

VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "1" ]; then
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
		--everything )  NMAP_LOW=1;
				NMAP_FULL=1;
				NMAP_A=1;
				NMAP_VULN=1;
				NMAP_SAFE=1;
				ENUM4=1;
				WEB=1;
				EXTRA=1;
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
echo "Parameters remaining are: $@"

RDIR=shscan_results_$HOSTS
if [ ! -d $RDIR ]; then
	mkdir $RDIR
fi

if [ $NMAP_LOW -eq 1 ]; then
	printf "Running base nmap scan.\n\n"
	/usr/bin/nmap -Pn $HOSTS -oN $RDIR/nmap_base_$HOSTS.txt
fi

if [ $NMAP_FULL -eq 1 ]; then
	printf "Running full nmap scan.\n\n"
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
	printf "Scanning ports $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) aggresively.\n\n"
	/usr/bin/nmap -sV -sC -A -Pn -p $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) $HOSTS -oN $RDIR/nmap_a_$HOSTS.txt
fi

if [ $ENUM4 -eq 1 ] && [ $(grep "\b445\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
	enum4linux-ng -a $HOSTS | tee $RDIR/enum4ng_noauth_$HOSTS.txt
	/usr/bin/enum4linux -a $HOSTS | tee $RDIR/enum4_noauth_$HOSTS.txt
	/usr/bin/smbmap -H $HOSTS | tee $RDIR/smbmap_noauth_$HOSTS.txt
fi

if [ $NMAP_VULN -eq 1 ]; then
	printf "Scanning ports $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) for vulns.\n\n"
	        if [ $(grep "\b139\b" $RDIR/tcp_ports_$HOSTS.txt) || $(grep "\b445\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
                /usr/bin/nmap -p139,445 -T4 -Pn --script 'not brute and not dos and smb-*' -vv -d $HOSTS -oN $RDIR/nmap_smb_$HOSTS.txt
		fi
	/usr/bin/nmap -Pn -sV --script "vuln" -p $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) $HOSTS -oN $RDIR/nmap_vuln_$HOSTS.txt
fi

if [ $NMAP_SAFE -eq 1 ]; then
        printf "Scanning ports $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) for vulns.\n\n"
        /usr/bin/nmap -Pn -sV --script "safe" -p $(tr '\n' , <$RDIR/tcp_ports_$HOSTS.txt) $HOSTS -oN $RDIR/nmap_safe_$HOSTS.txt
fi

if [ $WEB -eq 1  ]; then
	printf "Dirbusting $HOSTS on ports 80, 443 and 8080."
	if [ $(grep "\b80\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		/usr/bin/dirsearch -u http://$HOSTS -E --plain-text-report $RDIR/dirsearch_http_$HOSTS.txt
		/usr/bin/nikto -host $HOSTS -port 80 | tee $RDIR/nikto_http_$HOSTS.txt
		/usr/bin/whatweb http://$HOSTS -a 3 | tee $RDIR/whatweb_http_$HOSTS.txt
		hakrawler -all -linkfinder -url -robots http://$HOSTS | tee $RDIR/hakrawler_http_$HOSTS.txt
	fi
        if [ $(grep "\b443\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
                /usr/bin/dirsearch -u https://$HOSTS -E --plain-text-report $RDIR/dirsearch_https_$HOSTS.txt
		/usr/bin/nikto -host $HOSTS -port 443 | tee $RDIR/nikto_https_$HOSTS.txt
		/usr/bin/whatweb https://$HOSTS -a 3 | tee $RDIR/whatweb_https_$HOSTS.txt
		hakrawler -all -linkfinder -url -robots https://$HOSTS | tee $RDIR/hakrawler_https_$HOSTS.txt
        fi
        if [ $(grep "\b8080\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
                /usr/bin/dirsearch -u http://$HOSTS:8080 -E --plain-text-report $RDIR/dirsearch_http_8080_$HOSTS.txt
		/usr/bin/nikto -host $HOSTS -port 8080 | tee $RDIR/nikto_http_8080_$HOSTS.txt
		/usr/bin/whatweb http://$HOSTS:8080 -a 3 | tee $RDIR/whatweb_http_8080_$HOSTS.txt
		hakrawler -all -linkfinder -url -robots http://$HOSTS:8080 | tee $RDIR/hakrawler_http_8080_$HOSTS.txt
        fi
	if [ $(grep "\b8000\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
                /usr/bin/dirsearch -u http://$HOSTS:8000 -E --plain-text-report $RDIR/dirsearch_http_8000_$HOSTS.txt
                /usr/bin/nikto -host $HOSTS -port 8000 | tee $RDIR/nikto_http_8000_$HOSTS.txt
                /usr/bin/whatweb http://$HOSTS:8000 -a 3 | tee $RDIR/whatweb_http_8000_$HOSTS.txt
		hakrawler -all -linkfinder -url -robots http://$HOSTS:8000 | tee $RDIR/hakrawler_http_8000_$HOSTS.txt
        fi

fi

# Extra tests:

printf "Doing some extra tests for ftp,mysql,smtp,kerberos if the ports are open."
if [ $EXTRA -eq 1 ]; then
	if [ $(grep "\b21\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "Scanning ftp"
		nmap --script=ftp-* -p 21 $HOSTS -oN $RDIR/nmap_ftp_$HOSTS.txt
	fi
	if [ $(grep "\b3306\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "Scanning mysql"
		/usr/bin/nmap -sV -Pn -vv -script=mysql* -p 3306 $HOSTS -oN $RDIR/nmap_mysql_$HOSTS.txt
	fi
	if [ $(grep "\b25\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "Scanning smtp"
		/usr/bin/nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $HOSTS -oN $RDIR/nmap_smtp_$HOSTS.txt
	fi
	if [ $(grep "\b88\b" $RDIR/tcp_ports_$HOSTS.txt) ]; then
		printf "Testing kerberos"
		nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm=research $HOSTS -oN $RDIR/nmap_kerberos_$HOSTS.txt
	fi
fi
