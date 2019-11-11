#!/bin/bash

# amass, subfinder, snapd, aquatone, project sonar, grepcidr, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, otxurls, waybackurls, DirSearch, LinkFinder, VHostScan, spyse

#!/bin/bash


passwordx=""

[ ! -f ~/recon/$1 ] && mkdir ~/recon/$1
[ ! -f ~/recon/$1/dirsearch ] && mkdir ~/recon/$1/dirsearch
[ ! -f ~/recon/$1/default-credential ] && mkdir ~/recon/$1/default-credential
[ ! -f ~/recon/$1/whatweb ] && mkdir ~/recon/$1/whatweb
[ ! -f ~/recon/$1/virtual-hosts ] && mkdir ~/recon/$1/virtual-hosts
[ ! -f ~/recon/$1/endpoints ] && mkdir ~/recon/$1/endpoints
[ ! -f ~/recon/$1/otxurls ] && mkdir ~/recon/$1/otxurls
[ ! -f ~/recon/$1/waybackurls ] && mkdir ~/recon/$1/waybackurls
sleep 5

message () {
	telegram_bot=""
	telegram_id=""
	alert="https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text="
	[ -z $telegram_bot ] && [ -z $telegram_id ] || curl -g $alert$1 --silent > /dev/null
}

scanned () {
	cat $1 | sort -u | wc -l
}

#message "Initiating%20scan%20:%20$1"
message "[+]%20Initiating%20scan%20%3A%20$1%20[+]"

echo "[+] AMASS SCANNING [+]"
if [ ! -f ~/recon/$1/$1-amass.txt ] && [ ! -z $(which amass) ]; then
	amass enum -active -brute -d $1 -o ~/recon/$1/$1-amass.txt -config ~/config.ini
	#amass enum -passive -d $1 -o ~/recon/$1/$1-amass.txt
	amasscan=`scanned ~/recon/$1/$1-amass.txt`
	message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
	echo "[+] Amass Found $amasscan subdomains"
else
	message "[-]%20Skipping%20Amass%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] FINDOMAIN SCANNING [+]"
if [ ! -f ~/recon/$1/$1-findomain.txt ] && [ ! -z $(which findomain) ]; then
	findomain -t $1 -q -u ~/recon/$1/$1-findomain.txt
	findomainscan=`scanned ~/recon/$1/$1-findomain.txt`
	message "Findomain%20Found%20$findomainscan%20subdomain(s)%20for%20$1"
	echo "[+] Findomain Found $findomainscan subdomains"
else
	message "[-]%20Skipping%20Findomain%20$findomainscan%20previously%20discovered%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SPYSE SCANNING [+]"
if [ ! -f ~/recon/$1/$1-spyse.txt ] && [ ! -z $(which spyse) ]; then
	spyse -target $1 --subdomains | sed '1,12d' > ~/recon/$1/$1-spyse.txt
	spysescan=`scanned ~/recon/$1/$1-spyse.txt`
	message "Spyse%20Found%20$spysescan%20subdomain(s)%20for%20$1"
	echo "[+] Spyse Found $spysescan subdomains"
else
	message "[-]%20Skipping%20Spyse%20$spysescan%20previously%20discovered%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBFINDER SCANNING [+]"
if [ ! -f ~/recon/$1/$1-subfinder.txt ] && [ ! -z $(which subfinder) ]; then
	subfinder -d $1 -nW -silent -o ~/recon/$1/$1-subfinder.txt
	subfinderscan=`scanned ~/recon/$1/$1-subfinder.txt`
	message "SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$1"
	echo "[+] Subfinder Found $subfinderscan subdomains"
else
	message "[-]%20Skipping%20Subfinder%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] AQUATONE SCANNING [+]"
if [ ! -f ~/aquatone/$1/urls.txt ] && [ ! -z $(which aquatone-discover) ] && [ ! -z $(which aquatone-scan) ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; domainz="${domainx%:*}"; echo $domainz | sort -u >> ~/recon/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/recon/$1/$1-aquatone.txt`
	message "Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1"
	echo "[+] Aquatone Found $aquatonescan subdomains"
elif [  -f ~/aquatone/$1/urls.txt ]; then
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; domainz="${domainx%:*}"; echo $domainz | sort -u >> ~/recon/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/recon/$1/$1-aquatone.txt`
	message "Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1"
	echo "[+] Aquatone Found $aquatonescan subdomains"
else
	message "[-]%20Skipping%20Aquatone%20Scanning%20for%20$1"
	echo "[!] Skipping ..." 
fi
sleep 5

echo "[+] SUBLIST3R SCANNING [+]"
if [ ! -f ~/recon/$1/$1-sublist3r.txt ] && [ -e ~/tools/Sublist3r/sublist3r.py ]; then
	python ~/tools/Sublist3r/sublist3r.py -b -d $1 -o ~/recon/$1/$1-sublist3r.txt
	sublist3rscan=`scanned ~/recon/$1/$1-sublist3r.txt`
	message "Sublist3r%20Found%20$sublist3rscan%20subdomain(s)%20for%20$1"
	echo "[+] Sublist3r Found $sublist3rscan subdomains"
else
	message "[-]%20Skipping%20Sublist3r%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SCANNING SUBDOMAINS WITH PROJECT SONAR [+]"
if [ ! -f ~/recon/$1/$1-project-sonar.txt ] && [ -e ~/recon/data/fdns_cname.json.gz ]; then
	pv ~/recon/data/fdns_cname.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.name' | sort -u >> ~/recon/$1/$1-project-sonar.txt
	scanned ~/recon/$1/$1-project-sonar.txt
	#pv ~/reverse_dns.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.value' | sort -u >> ~/recon/$1/$1-project-sonar.txt
	projectsonar=$(scanned ~/recon/$1/$1-project-sonar.txt)
	message "Project%20Sonar%20Found%20$projectsonar%20subdomain(s)%20for%20$1"
	echo "[+] Project Sonar Found $projectsonar subdomains"
else
	message "[-]%20Skipping%20Project%20Sonar%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] CRT.SH SCANNING [+]"
if [ ! -f ~/recon/$1/$1-crt.txt ]; then
	[ ! -f ~/recon/scanner/crtname.txt ] && wget "https://gist.githubusercontent.com/sumgr0/58e234fb96ae30e85271634b38331912/raw/bdd9ed497bfe4741249d98fc01703e99282f1f2d/altname.txt" -O ~/recon/scanner/crtname.txt
	while read url; do
    {
        curl -s "https://crt.sh/?q=$url.$1&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/recon/$1/$1-crt.txt
    }; done < ~/recon/scanner/crtname.txt

	cat ~/recon/$1/$1-crt.txt | sort -u >> ~/recon/$1/$1-crtx.txt && rm ~/recon/$1/$1-crt.txt && mv ~/recon/$1/$1-crtx.txt ~/recon/$1/$1-crt.txt
	crt=`scanned ~/recon/$1/$1-crt.txt`
	message "CRT.SH%20Found%20$crt%20subdomain(s)%20for%20$1"
	echo "[+] CRT.sh Found $crt subdomains"
else
	message "[-]%20Skipping%20CRT.SH%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f ~/recon/$1/$1-gobuster.txt ] && [ ! -z $(which gobuster) ]; then
	[ ! -f ~/wordlists/all.txt ] && wget "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" -O ~/wordlists/all.txt
	gobuster dns -d $1 -t 300 -w ~/wordlists/all.txt --wildcard -o ~/recon/$1/$1-gobust.txt
	cat ~/recon/$1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > ~/recon/$1/$1-gobuster.txt
	rm ~/recon/$1/$1-gobust.txt
	gobusterscan=`scanned ~/recon/$1/$1-gobuster.txt`
	message "Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1"
	echo "[+] Gobuster Found $gobusterscan subdomains"
else
	message "[-]%20Skipping%20Gobuster%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

## Deleting all the results to less disk usage
cat ~/recon/$1/$1-amass.txt ~/recon/$1/$1-findomain.txt ~/recon/$1/$1-spyse.txt ~/recon/$1/$1-project-sonar.txt ~/recon/$1/$1-subfinder.txt ~/recon/$1/$1-aquatone.txt ~/recon/$1/$1-sublist3r.txt ~/recon/$1/$1-crt.txt ~/recon/$1/$1-gobuster.txt | sort -uf > ~/recon/$1/$1-final.txt
rm ~/recon/$1/$1-amass.txt ~/recon/$1/$1-findomain.txt ~/recon/$1/$1-spyse.txt ~/recon/$1/$1-project-sonar.txt ~/recon/$1/$1-subfinder.txt ~/recon/$1/$1-aquatone.txt ~/recon/$1/$1-sublist3r.txt ~/recon/$1/$1-crt.txt ~/recon/$1/$1-gobuster.txt
touch ~/recon/$1/$1-ipz.txt
sleep 5

echo "[+] DNSGEN SCANNING [+]"
if [ ! -f ~/recon/$1/$1-dnsgen.txt ] && [ ! -z $(which dnsgen) ]; then
	[ ! -f ~/recon/scanner/dnsgen.txt ] && wget "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" -O ~/recon/scanner/dnsgen.txt
	rm ~/recon/$1/$1-dnsgen.txt
	cat ~/recon/$1/$1-final.txt | dnsgen - | massdns -r ~/tools/massdns/lists/resolvers.txt -t A -o J --flush 2>/dev/null | jq -r .query_name | tee -a ~/recon/$1/$1-dnsgen.tmp
	cat ~/recon/$1/$1-dnsgen.tmp | sed 's/-\.//g' | sed 's/-\.//g' | sed 's/-\-\-\-//g' | sed 's/.$//g' | sort -u > ~/recon/$1/$1-dnsgen.txt
	rm ~/recon/$1/$1-dnsgen.tmp
	sleep 3
	dnsgens=`scanned ~/recon/$1/$1-dnsgen.txt`
	message "DNSGEN%20generates%20$dnsgens%20subdomain(s)%20for%20$1"
	echo "[+] DNSGEN generate $dnsgens subdomains"
else
	message "[-]%20Skipping%20DNSGEN%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

cat ~/recon/$1/$1-dnsgen.txt ~/recon/$1/$1-final.txt | sort -u >> ~/recon/$1/$1-fin.txt
rm ~/recon/$1/$1-final.txt && mv ~/recon/$1/$1-fin.txt ~/recon/$1/$1-final.txt
all=`scanned ~/recon/$1/$1-final.txt`
message "Almost%20$all%20Collected%20Subdomains%20for%20$1"
echo "[+] $all collected subdomains"
sleep 3

# collecting all IP from collected subdomains & segregating cloudflare IP from non-cloudflare IP
## non-sense if I scan cloudflare IP. :(
ulimit -n 800000
iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"
while read -r domain; do 
    ip=`dig +short $domain | grep -v '[[:alpha:]]'`
    grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "[!] $ip is cloudflare" || echo "$ip" >> ~/recon/$1/$1-ipf.txt &
done < ~/recon/$1/$1-final.txt

cat ~/recon/$1/$1-ipf.txt | sort -u | sed '/^[[:space:]]*$/d' > ~/recon/$1/$1-ip.txt

ip=`scanned ~/recon/$1/$1-ip.txt`
ip_old=`scanned ~/recon/$1/$1-ipf.txt`
message "$ip%20non-cloudflare%20IPs%20has%20been%20$collected%20in%20$1%20out%20of%20$ip_old%20IPs"
echo "[+] $ip non-cloudflare IPs has been collected out of $ip_old IPs!"
rm ~/recon/$1/$1-ipf.txt
cat ~/recon/$1/$1-ip.txt ~/recon/$1/$1-final.txt > ~/recon/$1/$1-all.txt
sleep 5

echo "[+] Filter-Resolved Scanning for Alive Hosts [+]"
if [ ! -f ~/recon/$1/$1-alive.txt ] && [ ! -z $(which filter-resolved) ]; then
	cat ~/recon/$1/$1-all.txt | filter-resolved > ~/recon/$1/$1-alive.txt
	aliveres=`scanned ~/recon/$1/$1-alive.txt`
	message "$aliveres%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
else
	message "[-]%20Skipping%20Filter-Resolved%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] HTTPROBE Scanning for HTTP Hosts [+]"
if [ ! -f ~/recon/$1/$1-httprobe.txt ] && [ ! -z $(which httprobe) ]; then
	cat ~/recon/$1/$1-all.txt | httprobe -c 50 > ~/recon/$1/$1-httprobe.txt
	alivesu=`scanned ~/recon/$1/$1-httprobe.txt`
	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
else
	message "[-]%20Skipping%20httprobe%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

diff --new-line-format="" --unchanged-line-format="" <(cat ~/recon/$1/$1-httprobe.txt | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort) <(sort ~/recon/$1/$1-alive.txt)  > ~/recon/$1/$1-diff.txt

echo "[+] SUBJACK for Subdomain TKO [+]"
if [ ! -f ~/recon/$1/$1-subjack.txt ] && [ ! -z $(which subjack) ]; then
	[ ! -f ~/recon/scanner/fingerprints.json ] && wget "https://raw.githubusercontent.com/sumgr0/subjack/master/fingerprints.json" -O ~/recon/scanner/fingerprints.json
	subjack -w ~/recon/$1/$1-alive.txt -a -timeout 15 -c ~/recon/scanner/fingerprints.json -v -m -o ~/recon/$1/$1-subtemp.txt
	subjack -w ~/recon/$1/$1-alive.txt -a -timeout 15 -c ~/recon/scanner/fingerprints.json -v -m -ssl -o ~/recon/$1/$1-subtmp.txt
	cat ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt | sort -u > ~/recon/$1/$1-subjack.txt
	rm ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt
	message "subjack%20scanner%20done%20for%20$1"
else
	message "[-]%20Skipping%20subjack%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] TKO-SUBS for Subdomain TKO [+]"
if [ ! -f ~/recon/$1/$1-subover.txt ] && [ ! -z $(which tko-subs) ]; then
	[ ! -f ~/recon/scanner/providers-data.csv ] && wget "https://raw.githubusercontent.com/anshumanbh/tko-subs/master/providers-data.csv" -O ~/recon/scanner/providers-data.csv
	tko-subs -domains=~/recon/$1/$1-alive.txt -data=~/recon/scanner/providers-data.csv -output=~/recon/$1/$1-tkosubs.txt
	message "TKO-Subs%20scanner%20done%20for%20$1"
	echo "[+] TKO-Subs scanner is done"
else
	message "[-]%20Skipping%20tko-subs%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] COLLECTING ENDPOINTS [+]"
for urlz in `cat ~/recon/$1/$1-httprobe.txt`; do 
	filename=`echo $urlz | sed 's/http:\/\///g' | sed 's/https:\/\//ssl-/g'`
	python ~/tools/LinkFinder/linkfinder.py -i $urlz -d -o ~/recon/$1/endpoints/$filename.html
done
message "Done%20collecting%20endpoint%20in%20$1"
echo "[+] Done collecting endpoint"
sleep 5

echo "[+] MASSDNS SCANNING [+]"
massdns -r ~/tools/massdns/lists/nameservers.txt ~/recon/$1/$1-alive.txt -o S > ~/recon/$1/$1-massdns.txt
message "Done%20Massdns%20Scanning%20for%20$1"
echo "[+] Done massdns for scanning assets"
sleep 5

echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f ~/recon/$1/$1-masscan.txt ] && [ ! -z $(which masscan) ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL ~/recon/$1/$1-ip.txt --max-rate 10000 -oG ~/recon/$1/$1-masscan.txt
	mass=`scanned ~/recon/$1/$1-ip.txt`
	message "Masscan%20Scanned%20$mass%20IPs%20for%20$1"
	echo "[+] Done masscan for scanning IPs"
else
	message "[-]%20Skipping%20Masscan%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

big_ports=`cat ~/recon/$1/$1-masscan.txt | grep 'Host:' | awk {'print $5'} | awk -F '/' {'print $1'} | sort -u | paste -s -d ','`
echo "[+] PORT SCANNING [+]"
cat ~/recon/$1/$1-alive.txt | aquatone -ports $big_ports -chrome-path /snap/bin/chromium -out ~/recon/$1/$1-ports
message "Done%20Aquatone%20Port%20Scanning%20for%20$1"
echo "[+] Done aquatone for scanning IPs"
sleep 5

echo "[+] NMAP PORT SCANNING [+]"
if [ ! -f ~/recon/$1/$1-nmap.txt ] && [ ! -z $(which nmap) ]; then
	[ ! -f ~/scanner/nmap-bootstrap.xsl ] && wget "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -O ~/scanner/nmap-bootstrap.xsl
	echo $passwordx | sudo -S nmap -sVTC -A -O -Pn -p$big_ports -iL ~/recon/$1/$1-ip.txt --stylesheet ~/scanner/nmap-bootstrap.xsl -oA ~/recon/$1/$1-nmap
	nmaps=`scanned ~/recon/$1/$1-ip.txt`
	xsltproc -o ~/recon/$1/$1-nmap.html ~/nmap-bootstrap.xsl ~/recon/$1/$1-nmap.xml
	message "Nmap%20Scanned%20$nmaps%20IPs%20for%20$1"
	echo "[+] Done nmap for scanning IPs"
else
	message "[-]%20Skipping%20Nmap%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] DEFAULT CREDENTIAL SCANNING [+]"
if [ -e ~/tools/changeme/changeme.py ] && [ "active" == `systemctl is-active redis` ]; then
	for targets in `cat ~/recon/$1/$1-masscan.txt | grep "Host:" | awk {'print $2":"$5'} | awk -F '/' {'print $1'}`; do python3 ~/tools/changeme/changeme.py --redishost redis --protocols http,snmp,ssh,ftp,memcached,mongo,mssql,mysql,postgres,telnet --portoverride $targets -d --fresh -v --ssl -o ~/recon/$1/default-credential/$targets-changeme.csv; done
	message "Default%20Credential%20done%20for%20$1"
	echo "[+] Done changeme for scanning default credentials"
else
	message "[-]%20Skipping%20Default%20Credential%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] Scanning for Sensitive Files [+]"
cp ~/recon/$1/$1-alive.txt ~/recon/$1/$1-sensitive.txt
python2 ~/tools/Sensitive-File-Explorer/sensitive.py -u ~/recon/$1-sensitive.txt
sens=`scanned ~/recon/$1-sensitive.txt`
message "Sensitive%20File%20Scanned%20$sens%20asset(s)%20for%20$1"
rm $1-sensitive.txt
sleep 5

echo "[+] WHATWEB SCANNING FOR FINGERPRINTING [+]"
if [ ! -z $(which whatweb) ]; then
	for d in `cat ~/recon/$1/$1-masscan.txt | grep "Host:" | awk {'print $2":"$5'} | awk -F "/" {'print $1'}`;do whatweb $d | sed 's/, /  \r\n/g' >> ~/recon/$1/whatweb/$d-whatweb.txt; done
	for d in `cat ~/recon/$1/$1-alive.txt`; do whatweb $d | sed 's/, /  \r\n/g' >> ~/recon/$1/whatweb/$d-whatweb.txt; done
	message "Done%20whatweb%20for%20fingerprinting%20$1"
	echo "[+] Done whatweb for fingerprinting the assets!"
else
	message "[-]%20Skipping%20whatweb%20for%20fingerprinting%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] OTXURL Scanning for Archived Endpoints [+]"
for u in `cat ~/recon/$1/$1-alive.txt`;do echo $u | otxurls | grep "$u" >> ~/recon/$1/otxurls/$u.tmp; done
cat ~/recon/$1/otxurls/*.tmp | sort -u >> ~/recon/$1/otxurls/$1-otxurl.txt 
rm ~/recon/$1/otxurls/*.tmp
message "OTXURL%20Done%20for%20$1"
echo "[+] Done otxurls for discovering useful endpoints"
sleep 5

echo "[+] WAYBACKURLS Scanning for Archived Endpoints [+]"
for u in `cat ~/recon/$1/$1-alive.txt`;do echo $u | waybackurls | grep "$u" >> ~/recon/$1/waybackurls/$u.tmp; done
cat ~/recon/$1/waybackurls/*.tmp | sort -u >> ~/recon/$1/waybackurls/$1-waybackurls.txt 
rm ~/recon/$1/waybackurls/*.tmp
message "WAYBACKURLS%20Done%20for%20$1"
echo "[+] Done waybackurls for discovering useful endpoints"
sleep 5

echo "[+] Scanning for Virtual Hosts Resolution [+]"
if [ ! -z $(which ffuf) ]; then
	[ ! -f ~/recon/scanner/virtual-host-scanning.txt ] && wget "https://raw.githubusercontent.com/codingo/VHostScan/master/VHostScan/wordlists/virtual-host-scanning.txt" -O ~/recon/scanner/virtual-host-scanning.txt
	cat ~/recon/$1/$1-final.txt | tok | cat ~/recon/scanner/virtual-host-scanning.txt | sort -u >> ~/recon/$1/$1-temp-vhost-wordlist.txt
	path=$(pwd)
	ffuf -c -w "$path/recon/$1/$1-temp-vhost-wordlist.txt:HOSTS" -w "$path/recon/$1/$1-open-ports.txt:TARGETS" -u http://TARGETS -k -H "Host: HOSTS" -mc all -fc 500-599 -o ~/recon/$1/virtual-hosts/$1.txt
	ffuf -c -w "$path/recon/$1/$1-temp-vhost-wordlist.txt:HOSTS" -w "$path/recon/$1/$1-open-ports.txt:TARGETS" -u https://TARGETS -k -H "Host: HOSTS" -mc all -fc 500-599 -o ~/recon/$1/virtual-hosts/$1-ssl.txt
	message "Virtual%20Host(s)%20done%20for%20$1"
	echo "[+] Done ffuf for scanning virtual hosts"
else
	message "[-]%20Skipping%20ffuf%20for%20vhost%20scanning"
	echo "[!] Skipping ..."
fi
rm ~/recon/$1/$1-temp-vhost-wordlist.txt 
sleep 5

echo "[+] DirSearch Scanning for Sensitive Files [+]"
[ ! -f ~/wordlists/newlist.txt ] && echo "visit https://github.com/phspade/Combined-Wordlists/"
cat ~/recon/$1/$1-httprobe.txt | xargs -P10 -I % sh -c "python3 ~/tools/dirsearch/dirsearch.py -u % -e php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -x 400,403,401,500,406,503,502 -t 100 --random-agents -b --plain-text-report ~/recon/$1/dirsearch/%-dirsearch.txt"
echo "[+] Done dirsearch for file and directory scanning"
sleep 5

[ ! -f ~/$1.out ] && mv $1.out ~/recon/$1/ 

message "Scanner%20Done%20for%20$1"
echo "[+] Done scanner :)"