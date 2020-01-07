#!/bin/bash

#requirements for running scanner.sh

# amass, subfinder, snapd, aquatone, project sonar, grepcidr, gobuster, masscan, nmap, sensitive.py, curl, otxurls, waybackurls, DirSearch, LinkFinder, ffuf

apt-get install pv curl wget grepcidr snapd nmap masscan rust

export PATH=$PATH:/snap/bin #setup snap
service snapd start #starting snap services
sudo snap install amass #installing amass via snap

#install findomain from https://github.com/Edu4rdSHL/findomain

gem install aquatone

pip3 install spyse

go get -v github.com/projectdiscovery/subfinder/cmd/subfinderr
go get github.com/OJ/gobuster
go get github.com/lc/otxurls
go get github.com/tomnomnom/waybackurls
go get github.com/tomnomnom/hacks/filter-resolved
go get github.com/tomnomnom/hacks/tok
go get github.com/ffuf/ffuf
go get github.com/sumgr0/subjack

#Sensitive-File-Explorer
git clone https://github.com/phspade/Sensitive-File-Explorer.git ~/tools/Sensitive-File-Explorer
pip install BeautifulSoup os sys commands argparse base64

#Massdns
git clone https://github.com/blechschmidt/massdns.git ~/tools/massdns
cd ~/tools/massdns
make
sudo cp ~/tools/massdns/bin/massdns /usr/bin

#dirsearch
git clone https://github.com/maurosoria/dirsearch.git


#linkfinder
git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
cd ~/tools/LinkFinder
python setup.py install
pip3 install -r requirements.txt

#Sublist3r
git clone https://github.com/aboul3la/Sublist3r ~/tools/Sublist3r
cd ~/tools/Sublist3r
sudo pip3 install -r requirements.txt
