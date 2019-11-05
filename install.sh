#!/bin/bash

#requirements for running scanner.sh

# amass, subfinder, snapd, aquatone, project sonar, grepcidr, gobuster, masscan, nmap, sensitive.py, curl, otxurls, waybackurls, DirSearch, LinkFinder, ffuf

apt-get install pv curl wget grepcidr snapd nmap masscan sublist3r

export PATH=$PATH:/snap/bin #setup snap
service snapd start #starting snap services
sudo snap install amass #installing amass via snap

go get github.com/subfinder/subfinder
go get github.com/OJ/gobuster
go get github.com/lc/otxurls
go get github.com/tomnomnom/waybackurls
go get github.com/tomnomnom/hacks/filter-resolved
go get github.com/tomnomnom/hacks/tok
go get github.com/ffuf/ffuf

#Sensitive-File-Explorer
git clone https://github.com/phspade/Sensitive-File-Explorer.git ~/tools/Sensitive-File-Explorer
pip install BeautifulSoup os sys commands argparse base64

#Massdns
git clone https://github.com/blechschmidt/massdns.git ~/tools/massdns
cd ~/tools/massdns
make
sudo cp ~/tools/massdns/bin/massdns /usr/bin

#CRLF-Scanner
git clone https://github.com/random-robbie/CRLF-Injection-Scanner.git ~/tools/CRLF-Injection-Scanner
cd ~/tools/CRLF-Injection-Scanner
pip3 install -r requirements.txt

#dirsearch
git clone https://github.com/maurosoria/dirsearch.git


#linkfinder
git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
cd ~/tools/LinkFinder
python setup.py install
pip3 install -r requirements.txt

#vhostscan
git clone https://github.com/codingo/VHostScan.git ~/tools/VHostScan
cd ~/tools/VHostScan
python3 setup.py install
pip3 install -r requirements.txt
