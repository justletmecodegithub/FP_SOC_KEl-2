clear
exit
clear
sudo passwd azureuser
clear
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
clear
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config.d/*.conf
clear
sudo systemctl restart ssh
exit
clear
exit
clear
ls
clear
docker version
clear
sudo apt update && sudo apt upgrade -y
clear
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
clear
exit
python3 -m venv venv
clear
sudo cat /home/azureuser/wazuh-passwords.txt
ls
tree
cd wazuh-install,sh
cd wazuh-install.sh
clear
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
sudo systemctl status wazuh-indexer
clear
df -h
sudo apt clean
sudo journalctl --vacuum-time=1h
sudo rm -rf /tmp/*
sudo rm -f /var/ossec/logs/alerts/alerts.log
sudo rm -f /var/ossec/logs/alerts/alerts.json
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
sudo systemctl status wazuh-indexer
clear
sudo du -ah /var 2>/dev/null | sort -rh | head -n 15
sudo systemctl stop wazuh-manager
sudo rm -rf /var/ossec/queue/vd_updater/tmp/*
sudo rm -rf /var/ossec/queue/vd/feed/*
sudo nano /var/ossec/etc/ossec.conf
clear
sudo systemctl start wazuh-manager
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
df -h
sudo systemctl status wazuh-manager
sudo reboot
clear
ls
clear
sudo systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard
sudo apt-get purge wazuh-manager wazuh-indexer wazuh-dashboard -y
sudo rm -rf /var/ossec /usr/share/wazuh-* /etc/wazuh-* /var/log/wazuh-*
sudo apt autoremove -y && sudo apt clean
df -h
clear
ls
rm wazuh-install*
ls
clear
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
sudo bash ./wazuh-install.sh -a -o
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
clear
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard
sudo systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard
sudo rm -rf /var/lib/wazuh-indexer/*
sudo rm -rf /var/log/wazuh-indexer/*
sudo bash ./wazuh-install.sh -a -o
sudo systemctl status wazuh-indexer
clear
sudo systemctl status wazuh-indexer
free -h
sudo journalctl -u wazuh-dashboard --no-pager | tail -n 15
clear
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
sudo systemctl restart wazuh-dashboard
clear
sudo /var/ossec/bin/manage_agents -r 001
sudo systemctl restart wazuh-manager
clear
sudo nano /etc/nginx/sites-available/soc-web
clear
nmap -Pn -sS -sV 20.214.172.82
nmap -Pn -sS -sV 20.214.172.82
sudo apt  install nmap 
nmap --version
# Bersihkan cache apt
sudo apt clean
sudo apt autoclean
# Hapus package yang tidak terpakai
sudo apt autoremove -y
# Cek berapa space yang tersisa
df -h
sudo apt  install nmap 
clear
nmap -Pn -sS -sV 20.214.172.82
sudo nmap -Pn -sS -sV 20.214.172.82
for i in {1..20}; do   ssh -o StrictHostKeyChecking=no wronguser@20.214.172.82 2>/dev/null; done
for i in {1..20}; do   ssh -o StrictHostKeyChecking=no wronguser@20.214.172.82 2>/dev/null; done
hydra -l azureuser -P /usr/share/wordlists/rockyou.txt -t 4 ssh://20.214.172.82
sudo apt install hydra
hydra -l azureuser -P /usr/share/wordlists/rockyou.txt -t 4 ssh://20.214.172.82
for i in {1..30}; do   sshpass -p "wrongpassword$i" ssh -o StrictHostKeyChecking=no   -o ConnectTimeout=2 azureuser@20.214.172.82 2>/dev/null;   echo "Attempt $i"; done
sudo systemctl status wazuh-manager
clear
sudo tail -f /var/log/nginx/access.log
clear
sudo tail -n 50 /var/ossec/logs/ossec.log | grep -E "ERROR|WARNING|CRITICAL"
clear
df -h
ksudo nano /var/ossec/etc/ossec.conf
clear
sudo nano /var/ossec/etc/ossec.conf
df -h
clear
df -h
sudo du -ah /var/ossec | sort -rh | head -n 10
sudo systemctl stop wazuh-manager
sudo rm -rf /var/ossec/queue/vd_updater/*
sudo rm -rf /var/ossec/queue/vd/*
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl start wazuh-manager
df -h
sudo pkill -9 -f wazuh
clear
sudo rm -rf /var/ossec/queue/vd_updater
sudo rm -rf /var/ossec/queue/vd
sudo mkdir -p /var/ossec/queue/vd_updater
sudo mkdir -p /var/ossec/queue/vd
sudo chown wazuh:wazuh /var/ossec/queue/vd_updater
sudo chown wazuh:wazuh /var/ossec/queue/vd
df -h
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl start wazuh-manager
clear
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
sudo systemctl status wazuh-manager
clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl status wazuh-manager
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest
clear
sudo journalctl -xeu wazuh-manager.service
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-control test
cat /var/ossec/etc/rules/local_rules.xml
clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo tail -50 /var/ossec/logs/ossec.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep 100102
clear
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json
sudo systemctl restart wazuh-agent
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep 10010
sudo tail -50 /var/ossec/logs/ossec.log | grep access.log
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -E "10010[2-9]"
sudo cat /var/ossec/logs/alerts/alerts.json | grep -E "100102|100103|100104|100106|100108|100109"
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo grep -A3 "nginx" /var/ossec/etc/ossec.conf
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100102|100103|100104|100106|100108|100109"
sudo /var/ossec/bin/wazuh-logtest
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100102|100103|100104|100106|100108|100109"
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep "Target-Web"
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | head -30
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100102|100103|100104|100106|100108|100109"
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep "100108"
sudo /var/ossec/bin/wazuh-logtest
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | head -20
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest
clear
sudo tail -f /var/ossec/logs/alerts/alerts.json
clear
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100102|100103|100104|100106|100108|100109"
sudo nano  /var/ossec/etc/rules/local_rules.xml
clear
cat
cat  /var/ossec/etc/rules/local_rules.xml
sudo cat  /var/ossec/etc/rules/local_rules.xml
sudo nano  /var/ossec/etc/rules/local_rules.xml
clear
nmap -sS -sV -Pn -O 20.214.172.82
clear
sudo nmap -sS -sV -Pn -O 20.214.172.82
sudo nano  /var/ossec/etc/rules/local_rules.xml
clear
sudo cat  /var/ossec/etc/rules/local_rules.xml
sudo nano  /var/ossec/etc/rules/local_rules.xml
clear
sudo nmap -sS -sV -Pn -O 20.214.172.82
sudo systemctl restart wazuh-manager
clear
sudo nmap -sS -sV -Pn -O 20.214.172.82
exit
nano /var/ossec/etc/rules/local_rules.xml
sudo nano /var/ossec/etc/rules/local_rules.xml
cat /var/ossec/etc/rules/local_rules.xml
sudo cat /var/ossec/etc/rules/local_rules.xml
exit
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
clear
sudo systemctl status wazuh-indexer
clear
sudo systemctl status wazuh-dashboard
exit
clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100110|100111"
sudo /var/ossec/bin/wazuh-logtest
sudo cat /var/ossec/etc/rules/local_rules.xml | grep -n "100110\|100111"
sudo sed -n '68,110p' /var/ossec/etc/rules/local_rules.xml
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | head -20
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100112|100113"
sudo /var/ossec/bin/wazuh-logtest
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100112|100113"
sudo nano /var/ossec/etc/rules/local_rules.xml
clear
sudo nano /var/ossec/etc/ossec.conf
clear
sudo nano /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-control test
clear
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
clear
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
clear
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
clear
ps aux | grep wazuh-integratord | grep -v grep
sudo grep -E -i "integratord|slack" /var/ossec/logs/ossec.log | tail -n 20
sudo nano /var/ossec/integrations/custom-discord
sudo chmod 750 /var/ossec/integrations/custom-discord
sudo chown root:wazuh /var/ossec/integrations/custom-discord
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
clear
sudo nano /var/ossec/integrations/custom-discord
sudo touch /var/ossec/logs/discord_debug.log
sudo chown wazuh:wazuh /var/ossec/logs/discord_debug.log
sudo systemctl restart wazuh-manager
clear
cat /var/ossec/logs/discord_debug.log
sudo cat /var/ossec/logs/discord_debug.log
clear
sudo nano /var/ossec/integrations/custom-discord
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo grep integratord /var/ossec/logs/ossec.log | tail -n 10
clear
sudo nano /var/ossec/integrations/custom-shuffle
sudo chmod 750 /var/ossec/integrations/custom-shuffle
sudo chown root:wazuh /var/ossec/integrations/custom-shuffle
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
clear
sudo nano /var/ossec/integrations/custom-shuffle
sudo touch /var/ossec/logs/shuffle_debug.log
sudo chown wazuh:wazuh /var/ossec/logs/shuffle_debug.log
clear
sudo cat /var/ossec/logs/shuffle_debug.log
clear
sudo cat /var/ossec/etc/rules/local_rules.xml
clear
sudo sed -n '/<integration>/,/<\/integration>/p' /var/ossec/etc/ossec.conf
clear
sudo cat /var/ossec/integrations/custom-shuffle
clear
sudo sed -n '/<command>/,/<\/command>/p' /var/ossec/etc/ossec.conf | grep -A 4 "firewall-drop"
sudo sed -n '/<active-response>/,/<\/active-response>/p' /var/ossec/etc/ossec.conf
clear
sudo cat /var/ossec/etc/rules/local_rules.xml
clear
sudo sed -n '/<integration>/,/<\/integration>/p' /var/ossec/etc/ossec.conf
clear
sudo cat /var/ossec/etc/rules/local_rules.xml
clear
sudo sed -n '/<integration>/,/<\/integration>/p' /var/ossec/etc/ossec.conf
clear
sudo cat /var/ossec/integrations/custom-shuffle
clear
sudo sed -n '/<command>/,/<\/command>/p' /var/ossec/etc/ossec.conf | grep -A 4 "firewall-drop"
clear
sudo cat /var/ossec/etc/rules/local_rules.xml
clear
exit
sudo cat /var/ossec/etc/rules/local_rules.xml
clear
sudo sed -n '/<integration>/,/<\/integration>/p' /var/ossec/etc/ossec.conf
clear
sudo cat /var/ossec/integrations/custom-shuffle
clear
sudo sed -n '/<command>/,/<\/command>/p' /var/ossec/etc/ossec.conf | grep -A 4 "firewall-drop"
clear
sudo cat /var/ossec/etc/rules/local_rules.xml
clear
sudo sed -n '/<integration>/,/<\/integration>/p' /var/ossec/etc/ossec.conf
clear
sudo cat /var/ossec/integrations/custom-shuffle
clear
sudo sed -n '/<command>/,/<\/command>/p' /var/ossec/etc/ossec.conf | grep -A 4 "firewall-drop"
clear
df -h
clear
                     sudo systemctl status wazuh-manager
clear
exit
clear
sudo /var/ossec/bin/manage_agents
clear
sudo systemctl restart wazuh-manager
clear
sudo /var/ossec/bin/wazuh-control info
clear
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo grep -A 10 "100112" /var/ossec/etc/rules/local_rules.xml
sudo wc -l /var/ossec/logs/alerts/alerts.json
sudo cp /var/ossec/logs/alerts/alerts.json ~/alerts_raw.json
sudo chown azureuser:azureuser ~/alerts_raw.json
clear
sudo tail -n 1 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
sudo grep -o '"id":"[0-9]*"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn | head -20
clear
date
clear
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest -t      # harus "Completed loading", tanpa error rule
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
# di Manager
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
clear
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
sudo grep -A4 "<active-response>" /var/ossec/etc/ossec.conf
clear
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
wc -l /var/ossec/logs/alerts/alerts.json
sudo wc -l /var/ossec/logs/alerts/alerts.json
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
sudo wc -l /var/ossec/logs/alerts/alerts.json
clear
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
sudo wc -l /var/ossec/logs/alerts/alerts.json
clear
python3 - << 'EOF'
import json, collections
c=collections.Counter(); tmin=tmax=None; n=0
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    n+=1
    c[a.get('rule',{}).get('id')]+=1
    ts=a.get('timestamp')
    if ts:
        tmin=ts if tmin is None or ts<tmin else tmin
        tmax=ts if tmax is None or ts>tmax else tmax
print("total alerts:", n)
print("rentang waktu:", tmin, "->", tmax)
print("--- rule.id (top 25) ---")
for rid,k in c.most_common(25):
    print(f"{k:6d}  {rid}")
EOF

clear
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter(); tmin=tmax=None; n=0
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    n+=1
    c[a.get('rule',{}).get('id')]+=1
    ts=a.get('timestamp')
    if ts:
        tmin=ts if tmin is None or ts<tmin else tmin
        tmax=ts if tmax is None or ts>tmax else tmax
print("total alerts:", n)
print("rentang waktu:", tmin, "->", tmax)
print("--- rule.id (top 25) ---")
for rid,k in c.most_common(25):
    print(f"{k:6d}  {rid}")
EOF

sudo nano /var/ossec/etc/rules/local_rules.xml 
clear
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
clear
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter()
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    r=a.get('rule',{})
    c[(r.get('id'), r.get('description','')[:55])]+=1
for (rid,desc),k in c.most_common(20):
    print(f"{k:5d}  {rid}  {desc}")
EOF

clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter()
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    r=a.get('rule',{})
    c[(r.get('id'), r.get('description','')[:50])]+=1
print("--- rule custom ---")
for (rid,desc),k in c.most_common(30):
    if str(rid).startswith("1001"):
        print(f"{k:5d}  {rid}  {desc}")
print("--- semua (top 10) ---")
for (rid,desc),k in c.most_common(10):
    print(f"{k:5d}  {rid}  {desc}")
EOF

sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
clear
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter()
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    r=a.get('rule',{})
    c[(r.get('id'), r.get('description','')[:50])]+=1
print("--- rule custom (1001xx) ---")
hit=False
for (rid,desc),k in c.most_common(30):
    if str(rid).startswith("1001"):
        print(f"{k:5d}  {rid}  {desc}"); hit=True
if not hit: print("(tidak ada — 100112/100113 belum nyala)")
print("--- web 31xxx ---")
for (rid,desc),k in c.most_common(30):
    if str(rid).startswith("31"):
        print(f"{k:5d}  {rid}  {desc}")
EOF

clear
sudo /var/ossec/bin/agent_control -lc
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t 
sudo systemctl restart wazuh-manager
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter()
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    r=a.get('rule',{})
    c[(r.get('id'), r.get('description','')[:50])]+=1
print("--- web + custom ---")
for (rid,desc),k in c.most_common(30):
    s=str(rid)
    if s.startswith("31") or s.startswith("1001"):
        print(f"{k:5d}  {rid}  {desc}")
EOF

sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
clear
sudo systemctl restart wazuh-manager
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter()
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except: continue
    r=a.get('rule',{})
    c[(r.get('id'), r.get('description','')[:50])]+=1
for (rid,desc),k in c.most_common(30):
    s=str(rid)
    if s.startswith("31") or s.startswith("1001"):
        print(f"{k:5d}  {rid}  {desc}")
EOF

clear
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t    
sudo systemctl restart wazuh-manager
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json
clear
sudo python3 - << 'EOF'
import json, collections
c=collections.Counter(); n=0
for line in open('/var/ossec/logs/alerts/alerts.json'):
    line=line.strip()
    if not line: continue
    try: a=json.loads(line); n+=1
    except: continue
    c[a.get('rule',{}).get('id')]+=1
print("total:", n)
for rid,k in c.most_common(15):
    print(f"{k:5d}  {rid}")
EOF

clear
cp /var/ossec/logs/alerts/alerts.json ~/alerts_raw.json
sudo chown azureuser:azureuser ~/alerts_raw.json
clear
sudp cp /var/ossec/logs/alerts/alerts.json ~/alerts_raw.json
sudo chown azureuser:azureuser ~/alerts_raw.json
clear
cp /var/ossec/logs/alerts/alerts.json ~/alerts_raw.json
sudo chown azureuser:azureuser ~/alerts_raw.json
clear
sudo cp /var/ossec/logs/alerts/alerts.json ~/alerts_raw.json
sudo chown azureuser:azureuser ~/alerts_raw.json
ls -lh ~/alerts_raw.json
clear
sudo cp /var/ossec/logs/alerts/alerts.json ~/alerts_raw.json
sudo chown azureuser:azureuser ~/alerts_raw.json
exit
clear
cd Downloads
cd ~/Down
exit
sudo apt update && sudo apt upgrade
clear
exit
clear
ls
exit
clear
sudo grep -A6 -i 'integration' /var/ossec/etc/ossec.conf || echo "tidak ada blok integration"
sudo ls -la /var/ossec/integrations/ 2>/dev/null
clear
sudo cat /var/ossec/integrations/custom-ml-predict
sudo cat /var/ossec/integrations/custom-ml-predict.py
clear
sudo nano /var/ossec/etc/ossec.conf
# cari dua blok <integration> bernama custom-ml-predict, HAPUS salah satu
sudo /var/ossec/bin/wazuh-control restart
curl -s -X POST http://20.41.107.48:8000/reset
clear
sudo tail -f /var/ossec/logs/ml-predictions.log
clear
ls
ls -l
tree
cat alerts_raw.json
ls
clear
ls
cat wazuh-install.sh
tree
sudo snap install tree
tree
sudo apt  install tree
ls
rm - rf snap
cd wazuh-install-files.tar
cat wazuh-install-files.tar
cd wazuh-install-files.tar
sudo dpkg --configure -a
sudo apt --fix-broken install -y
sudo apt update
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
sudo systemctl status filebeat --no-pager
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-indexer
sudo ls -l /usr/share/wazuh-indexer/bin/systemd-entrypoint
sudo chown root:root /usr/share/wazuh-indexer/bin/systemd-entrypoint
sudo chmod 755 /usr/share/wazuh-indexer/bin/systemd-entrypoint
sudo systemctl daemon-reload
sudo systemctl reset-failed wazuh-indexer
sudo systemctl start wazuh-indexer
sudo systemctl status wazuh-indexer --no-pager
sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.bak
sudo sed -i 's/^server.port:.*/server.port: 5601/' /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo systemctl daemon-reload
sudo systemctl reset-failed wazuh-dashboard
sudo systemctl restart wazuh-dashboard
sudo systemctl status wazuh-dashboard --no-pager
sudo ss -lntp | grep 5601
sudo systemctl status wazuh-indexer --no-pager
curl -k https://localhost:5601/status
sudo ss -lntp | grep -E '5601|9200|1514|1515|55000'
sudo tar -tf wazuh-install-files.tar | grep password
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
ls
cat wazuh-install.sh
ls
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
ls
tree
cat custom ml-predict.py
ls
cat custom-ml-predict
nano custom-ml-predict.py
cat custom-ml-predict.py
ls
cat insert_integration.py
sudo nano /var/ossec/etc/ossec.conf
ls
cat custom-ml-predict
cat custom-ml-predict.py
nano custom-ml-predict.py
sudo cp custom-ml-predict /var/ossec/integrations/custom-ml-predict
sudo cp custom-ml-predict.py /var/ossec/integrations/custom-ml-predict.py
sudo chown root:wazuh /var/ossec/integrations/custom-ml-predict
sudo chown root:wazuh /var/ossec/integrations/custom-ml-predict.py
sudo chmod 750 /var/ossec/integrations/custom-ml-predict
sudo chmod 750 /var/ossec/integrations/custom-ml-predict.py
sudo systemctl restart wazuh-manager
curl -s -X POST http://20.41.120.192:8000/predict   -H "Content-Type: application/json"   -d '{"rule_level":10,"rule_id":"31151","srcip":"8.8.8.8","timestamp":"2026-06-22T10:00:00Z"}'
sudo ss -lntp | grep 8000
uvicorn app:app --host 0.0.0.0 --port 8000
sudo apt install uvicorn
ls
sudo nano /var/ossec/etc/ossec.conf
curl -i --max-time 10 -X POST http://20.41.120.192:8000/predict   -H "Content-Type: application/json"   -d '{"rule_level":10,"rule_id":"31151","srcip":"203.0.113.10","timestamp":"2026-06-22T10:00:00Z"}'
sudo nano /var/ossec/etc/ossec.conf
curl http://20.41.120.192:8000/predict
sudo ufw status
sudo ufw allow from 20.41.96.43 to any port 8000 proto tcp
sudo grep -n "custom-ml-predict\|hook_url\|ossec_config" /var/ossec/etc/ossec.conf
curl -i --max-time 10 -X POST http://20.41.120.192:8000/predict   -H "Content-Type: application/json"   -d '{"rule_level":10,"rule_id":"31151","srcip":"203.0.113.10","timestamp":"2026-06-22T10:00:00Z"}'
curl -i --max-time 10 -X POST http://20.41.120.192:8000/predict   -H "Content-Type: application/json"   -d '{"rule_level":10,"rule_id":"31151","srcip":"203.0.113.10","timestamp":"2026-06-22T10:00:00Z"}'
curl -i --max-time 10 -X POST http://20.41.120.192:8000/predict   -H "Content-Type: application/json"   -d '{"rule_level":10,"rule_id":"31151","srcip":"203.0.113.10","timestamp":"2026-06-22T10:00:00Z"}'
hostname -I
nano custom-ml-predict.py
sudo cp custom-ml-predict.py /var/ossec/integrations/custom-ml-predict.py
sudo chown root:wazuh /var/ossec/integrations/custom-ml-predict.py
sudo systemctl restart wazuh-manager
ping -c 4 10.1.0.4
timeout 5 bash -c '</dev/tcp/10.1.0.4/8000' && echo "PORT 8000 TEMBUS" || echo "PORT 8000 GAGAL"
curl -i --max-time 10 http://10.1.0.4:8000/health
curl -i --max-time 10 http://20.41.120.192:8000/health
curl -i --max-time 10 http://10.1.0.4:8000/health
nano custom-ml-predict.py
curl -i --max-time 10 http://20.41.120.192:8000/health
curl -i --max-time 10 http://20.41.107.48:8000/health
curl -i --max-time 10 -X POST http://20.41.107.48:8000/predict   -H "Content-Type: application/json"   -d '{"rule_level":10,"rule_id":"31151","srcip":"203.0.113.10","timestamp":"2026-06-22T10:00:00Z"}'
grep -nE "20\.41\.120\.192|10\.1\.0\.4|20\.41\.107\.48" custom-ml-predict.py
nano custom-ml-predict.py
sudo cp custom-ml-predict.py /var/ossec/integrations/custom-ml-predict.py
sudo chmod 750 /var/ossec/integrations/custom-ml-predict.py
sudo systemctl restart wazuh-manager
sudo grep -nE "ML_API_URL|20\.41\.107\.48|20\.41\.120\.192|10\.1\.0\.4" /var/ossec/integrations/custom-ml-predict.py
sudo chown root:wazuh /var/ossec/integrations/custom-ml-predict.py
sudo chmod 750 /var/ossec/integrations/custom-ml-predict.py
sudo systemctl restart wazuh-manager
sudo tail -n 100 /var/ossec/logs/ossec.log | grep -iE "error|invalid|integration|custom-ml"
cat > /tmp/test-alert.json << 'EOF'
{
  "timestamp": "2026-06-22T10:00:00Z",
  "rule": {
    "id": "31151",
    "level": 10,
    "description": "Test web attack alert"
  },
  "agent": {
    "id": "001",
    "name": "VM-Target-Web"
  },
  "data": {
    "srcip": "203.0.113.10"
  }
}
EOF

sudo tail -n 80 /var/ossec/logs/ml-predictions.log
sudo tail -n 100 /var/ossec/logs/ossec.log | grep -iE "error|invalid|integration|custom-ml"
sudo nano /var/ossec/etc/ossec.conf
sudo rm -f /var/ossec/etc/.ossec.conf.swp
export SHUFFLE_WEBHOOK='https://shuffler.io/api/v1/hooks/webhook_7b45bafe-b50a-590f-9669-eea27bc8f791'
cat > /tmp/test-alert.json << 'EOF'
{
  "timestamp": "2026-06-22T10:00:00Z",
  "rule": {
    "id": "31151",
    "level": 10,
    "description": "Test web attack alert"
  },
  "agent": {
    "id": "001",
    "name": "VM-Target-Web"
  },
  "data": {
    "srcip": "203.0.113.10"
  }
}
EOF

/var/ossec/integrations/custom-ml-predict /tmp/test-alert.json "" "$SHUFFLE_WEBHOOK"
sudo ls -l /var/ossec/integrations/custom-ml-predict /var/ossec/integrations/custom-ml-predict.py
sudo chown root:wazuh /var/ossec/integrations/custom-ml-predict
sudo chown root:wazuh /var/ossec/integrations/custom-ml-predict.py
sudo chmod 750 /var/ossec/integrations/custom-ml-predict.py
sudo /var/ossec/integrations/custom-ml-predict /tmp/test-alert.json "" "$SHUFFLE_WEBHOOK"
sudo tail -n 80 /var/ossec/logs/ml-predictions.log
sudo cat /var/ossec/integrations/custom-ml-predict
sudo chmod +x /var/ossec/integrations/custom-ml-predict
sudo /var/ossec/integrations/custom-ml-predict /tmp/test-alert.json "" "$SHUFFLE_WEBHOOK"
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "ignore",
    "reason": "manual test ignore path",
    "ml_label": "FP",
    "confidence": 0.66,
    "prediction": 0,
    "srcip": "203.0.113.10",
    "rule_id": "31151",
    "rule_level": 10
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "block",
    "reason": "manual test block path",
    "ml_label": "TP",
    "confidence": 1.0,
    "prediction": 1,
    "srcip": "203.0.113.10",
    "rule_id": "100112",
    "rule_level": 6
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "block",
    "reason": "manual test block path",
    "ml_label": "TP",
    "confidence": 1.0,
    "prediction": 1,
    "srcip": "203.0.113.10",
    "rule_id": "100112",
    "rule_level": 6
  }'
curl -i --max-time 10 http://20.214.172.82:5001/health
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "block",
    "reason": "manual test block path",
    "ml_label": "TP",
    "confidence": 1.0,
    "prediction": 1,
    "srcip": "203.0.113.10",
    "rule_id": "100112",
    "rule_level": 6
  }'
sudo tail -f /var/ossec/logs/ml-predictions.log
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "ignore",
    "reason": "manual test ignore path",
    "ml_label": "FP",
    "confidence": 0.66,
    "prediction": 0,
    "srcip": "203.0.113.10",
    "rule_id": "31151",
    "rule_level": 10
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "block",
    "reason": "manual test block path",
    "ml_label": "TP",
    "confidence": 1.0,
    "prediction": 1,
    "srcip": "203.0.113.10",
    "rule_id": "100112",
    "rule_level": 6
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "ignore",
    "reason": "manual test ignore path",
    "ml_label": "FP",
    "confidence": 0.66,
    "prediction": 0,
    "srcip": "203.0.113.10",
    "rule_id": "31151",
    "rule_level": 10
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "ignore",
    "reason": "manual test ignore path",
    "ml_label": "FP",
    "confidence": 0.66,
    "prediction": 0,
    "srcip": "203.0.113.10",
    "rule_id": "31151",
    "rule_level": 10
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "ignore",
    "reason": "manual test ignore path",
    "ml_label": "FP",
    "confidence": 0.66,
    "prediction": 0,
    "srcip": "203.0.113.10",
    "rule_id": "31151",
    "rule_level": 10
  }'
curl -i -X POST "$SHUFFLE_WEBHOOK"   -H "Content-Type: application/json"   -d '{
    "decision": "block",
    "reason": "manual test block path",
    "ml_label": "TP",
    "confidence": 1.0,
    "prediction": 1,
    "srcip": "203.0.113.10",
    "rule_id": "100112",
    "rule_level": 6
  }'
sudo tail -f /var/ossec/logs/ml-predictions.log
sudo /var/ossec/bin/agent_control -l
sudo ss -lntp | grep 1514
sudo tail -n 500 /var/ossec/logs/alerts/alerts.json | grep -E "203.0.113.10|31101|Common web attack"
sudo tail -n 80 /var/ossec/logs/ml-predictions.log
clear
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/agent_control -l
sudo grep ML_API_URL /var/ossec/integrations/custom-ml-predict.py
sudo tail -n 5 /var/ossec/logs/ml-predictions.log
clear
sudo tail -n 3 /var/ossec/logs/ml-predictions.log
clear
sudo tail -n 3 /var/ossec/logs/ml-predictions.log
clear
sudo cat /var/ossec/integrations/custom-ml-predict.py
sudo grep -n -A8 -iE 'active-response|<command>' /var/ossec/etc/ossec.conf
sudo ls -la /var/ossec/active-response/bin/
clear
/var/ossec/integrations/custom-ml-predict.py
sudo /var/ossec/integrations/custom-ml-predict.py
sudo nano /var/ossec/integrations/custom-ml-predict.py
sudo grep -n "182.8.97.126\|ml-block.log" /var/ossec/integrations/custom-ml-predict.py
clear
sudo nano /var/ossec/etc/decoders/local_decoder.xml
nano /var/ossec/etc/rules/local_rules.xml
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo nano /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-analysisd -t      # harus "Completed ... loading", tanpa error
sudo systemctl restart wazuh-manager
clear
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -iE 'error|critical|100200|ml-block' || echo "TIDAK ada error fatal terkait rule kita"
sudo systemctl is-active wazuh-manager
# di Manager - tulis baris uji ke log (pakai IP dummy)
echo "ML_BLOCK srcip=9.9.9.9 rule_id=100113 conf=0.99" | sudo tee -a /var/ossec/logs/ml-block.log
# tunggu ~3 detik, cek apakah rule 100200 nyala
sudo tail -n 20 /var/ossec/logs/alerts/alerts.json | grep -A2 100200
clear
sudo grep -c '"id":"100200"' /var/ossec/logs/alerts/alerts.json
sudo grep '9.9.9.9' /var/ossec/logs/alerts/alerts.json | tail -n 2
echo 'ML_BLOCK srcip=9.9.9.9 rule_id=100113 conf=0.99' | sudo /var/ossec/bin/wazuh-logtes
clear
echo 'ML_BLOCK srcip=9.9.9.9 rule_id=100113 conf=0.99' | sudo /var/ossec/bin/wazuh-logtes
sudo grep -n 'ml-block.log' /var/ossec/etc/ossec.conf
clear
sudo /var/ossec/bin/wazuh-logtest
echo "ML_BLOCK srcip=8.8.8.8 rule_id=100113 conf=0.99" | sudo tee -a /var/ossec/logs/ml-block.log
sleep 4
sudo grep '8.8.8.8' /var/ossec/logs/alerts/alerts.json | tail -n 2
clear
sudo nano /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -iE 'error|critical' || echo "OK tanpa error fatal"
sudo systemctl restart wazuh-manager
# suntik sinyal block buat IP dummy
echo "ML_BLOCK srcip=9.9.9.9 rule_id=100113 conf=0.99" | sudo tee -a /var/ossec/logs/ml-block.log
sleep 5
exit
clear
sudo /var/ossec/bin/agent_control -l
sudo tail -n 3 /var/ossec/logs/ml-predictions.log
clear
#!/usr/bin/env bash
# ============================================================================
# show_config.sh - Tampilkan SEMUA konfigurasi yang KAMI ubah untuk proyek ini.
# Jalankan di VM-WAZUH-MANAGER. Buat presentasi ke dosen.
#   Pakai:  sudo bash show_config.sh
#   Simpan: sudo bash show_config.sh > konfigurasi_kami.txt
# ============================================================================
sep(){ echo; echo "============================================================"; echo " $1"; echo "============================================================"; }
sep "1. CUSTOM RULES (deteksi DoS + zona abu-abu untuk ML)"
echo "File: /var/ossec/etc/rules/local_rules.xml"
echo "------------------------------------------------------------"
sudo cat /var/ossec/etc/rules/local_rules.xml
sep "2. CUSTOM DECODER (membaca penanda keputusan ML)"
echo "File: /var/ossec/etc/decoders/local_decoder.xml"
echo "------------------------------------------------------------"
sudo cat /var/ossec/etc/decoders/local_decoder.xml
sep "3. INTEGRASI ML — pemanggil API model"
echo "File: /var/ossec/integrations/custom-ml-predict.py"
echo "------------------------------------------------------------"
sudo cat /var/ossec/integrations/custom-ml-predict.py
sep "4. KONFIGURASI WAZUH — blok yang kami tambahkan di ossec.conf"
echo "File: /var/ossec/etc/ossec.conf  (hanya bagian relevan)"
echo "------------------------------------------------------------"
echo ">>> Blok INTEGRATION (kirim alert ke ML):"
sudo grep -n -B1 -A4 'custom-ml-predict' /var/ossec/etc/ossec.conf
echo
echo ">>> Blok ACTIVE-RESPONSE (auto-block dari keputusan AI):"
sudo grep -n -A6 '<active-response>' /var/ossec/etc/ossec.conf
echo
echo ">>> LOCALFILE (Wazuh memantau log keputusan block):"
sudo grep -n -A3 'ml-block.log' /var/ossec/etc/ossec.conf
sep "5. RINGKASAN ALUR (Human-AI + SOAR)"
cat <<'TXT'
  Serangan web
    -> Rule Wazuh (31101 / 100112 / 100113) terpicu
    -> Integrasi custom-ml-predict.py kirim alert ke ML API
    -> Model Random Forest klasifikasi: TP (serangan) / FP (false alarm)
    -> Jika TP & confidence >= 0.85 -> tulis ML_BLOCK ke log
    -> Decoder 'ml-block' + Rule 100200 membacanya
    -> Active Response (firewall-drop) blokir IP di Target-Web, timeout 120s
    -> Auto-unblock setelah 2 menit
TXT

echo
echo "Selesai. (Konfigurasi sisi ML: ~/ml-api/main.py & monitor.py ada di VM-ML)"
clear
ls
nano show_config.sh
chmod +x show_config.sh
sudo ./show_config.sh
clear
ls
nano custom-ml-predict
nano custom-ml-predict.py
