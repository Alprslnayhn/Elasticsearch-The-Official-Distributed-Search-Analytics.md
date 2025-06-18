# DevSecOps Practical Guide: Elastic SIEM, Snort, UFW (VirtualBox-Based)

This guide outlines the end-to-end setup of a DevSecOps lab environment using VirtualBox, focusing on log collection, parsing, and visualization using Elastic Stack (Elasticsearch, Logstash, Kibana), Snort, UFW, and NGINX. Designed for beginners, it includes full command-line instructions, configuration files, IP assignments, and operational notes.

Each section includes specific command-line examples, file paths, testing procedures, the virtual machine (VM) where the configuration is applied, and the rationale behind each step.

---

## 🖥️ Virtual Architecture Overview

```
 Client (192.168.100.15)
        ↓
 Snort/UFW (192.168.100.14)
        ↓
   NGINX LB (192.168.100.10)
      ↙           ↘
ES Node1       ES Node2
(192.168.100.11) (192.168.100.12)
        ↓
   Kibana (192.168.100.13)
```

## 💾 VM Specifications

| VM Name              | Purpose                                    | CPU | RAM | Disk  | OS                      |
| -------------------- | ------------------------------------------ | --- | --- | ----- | ----------------------- |
| elastic-node1        | Elastic data node + Kibana                 | 4   | 8GB | 100GB | Ubuntu Server 22.04 LTS |
| elastic-node2        | Elastic data node                          | 4   | 8GB | 100GB | Ubuntu Server 22.04 LTS |
| nginx-lb-rp          | NGINX load balancer and reverse proxy      | 2   | 2GB | 20GB  | Ubuntu Server 22.04 LTS |
| snort-vm             | Snort IDS and UFW log source               | 2   | 4GB | 50GB  | Ubuntu Server 22.04 LTS |
| nginx-log-source     | NGINX access log source                    | 1   | 2GB | 20GB  | Ubuntu Server 22.04 LTS |
| custom-log-generator | Custom syslog script source (trainee logs) | 1   | 2GB | 20GB  | Ubuntu Server 22.04 LTS |

---

## 🔗 Network Design

All VMs use dual NICs: NAT (`enp0s3`) for external internet access (updates, Talos rule downloads), and Host-Only (`enp0s8`) for internal traffic.

Configuration applies to **all VMs**:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: true
      routes:
        - to: default
          via: 10.0.2.2
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.100.X/24
      routes:
        - to: default
          via: 192.168.100.1
          metric: 50
```

Set `X` uniquely for each VM. Apply using:

```bash
sudo netplan apply
```

---

## 🔐 SSH and UFW Configuration

Applies to **all VMs** for remote access:

```bash
sudo apt install openssh-server
sudo ufw allow 22/tcp
sudo ufw enable
```

For `elk-node1` and `kibana-node`, also:

```bash
sudo ufw allow 5601/tcp
sudo ufw allow 9200/tcp
```

---

## ⚙️ Elasticsearch Cluster Setup

**VMs:** `elastic-node1`, `elastic-node2`

```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg

echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install elasticsearch -y
```

Configure `/etc/elasticsearch/elasticsearch.yml` uniquely per VM:

### On `elastic-node1`:

```yaml
node.name: elk-node1
discovery.seed_hosts: ["192.168.100.12"]
```

### On `elastic-node2`:

```yaml
node.name: elk-node2
discovery.seed_hosts: ["192.168.100.11"]
```

Start service:

```bash
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

---

## 📊 Kibana Setup

**VM:** `elastic-node1` or a separate `kibana-node`

```bash
sudo apt install kibana -y
sudo nano /etc/kibana/kibana.yml
```

```yaml
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://192.168.100.11:9200", "http://192.168.100.12:9200"]
```

Start:

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

Access via:

```
http://192.168.100.11:5601
```

---

## 🔁 NGINX Load Balancer and Reverse Proxy

**VM:** `nginx-lb-rp`

```bash
sudo apt install nginx -y
```

Create config `/etc/nginx/sites-available/elasticsearch`:

```nginx
upstream es_backend {
  server 192.168.100.11:9200;
  server 192.168.100.12:9200;
}

server {
  listen 9200;
  location / {
    proxy_pass http://es_backend;
  }
}
```

Config `/etc/nginx/sites-available/kibana`:

```nginx
server {
  listen 80;
  location / {
    proxy_pass http://192.168.100.13:5601;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
  }
}
```

Enable:

```bash
sudo ln -s /etc/nginx/sites-available/elasticsearch /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## 🛡️ Snort and UFW IDS Setup

**VM:** `snort-vm`

```bash
sudo apt install snort -y
sudo nano /etc/snort/snort.conf
```

Set:

```conf
var HOME_NET 192.168.100.0/24
```

Add rule:

```bash
sudo nano /etc/snort/rules/local.rules
alert icmp any any -> any any (msg:"ICMP test detected"; sid:1000001; rev:1;)
```

Enable firewall:

```bash
sudo ufw enable
sudo ufw logging on
```

---

## 📦 Filebeat Configuration

### On `snort-vm`:

```yaml
filebeat.inputs:
  - type: log
    paths: ["/var/log/snort/alert"]
    fields:
      log_type: snort
```

### On `snort-vm` for UFW:

```yaml
- module: system
  syslog:
    enabled: true
    var.paths: ["/var/log/ufw.log"]
  auth:
    enabled: false
```

### On `nginx-log-source`:

```yaml
- module: nginx
  access:
    enabled: true
    var.paths: ["/var/log/nginx/access.log"]
  error:
    enabled: true
    var.paths: ["/var/log/nginx/error.log"]
```

All output to:

```yaml
output.elasticsearch:
  hosts: ["http://192.168.100.10:9200"]
```

---

## 🔧 Custom Syslog Generator

**VM:** `custom-log-generator`

Script `/usr/local/bin/trainee_logs.sh`:

```bash
#!/bin/bash
while true; do
  logger -t trainee "Task $(($RANDOM%5)) done"
  sleep 5
done
```

Systemd unit:

```ini
[Unit]
Description=Trainee Log Generator
[Service]
ExecStart=/usr/local/bin/trainee_logs.sh
Restart=always
[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable trainee
sudo systemctl start trainee
```

---

## 📈 Kibana Dashboarding

**VM:** `elastic-node1` or `kibana-node`

- Index Pattern: `filebeat-*`
- Dashboards:
  - Snort Alerts (filtered by `fields.log_type: snort`)
  - UFW Activity (filtered by `message: UFW`)
  - NGINX Access
  - Trainee Logs (filtered by `tag: trainee`)

---

**Created by:** Alparslan Ayhan\
**Project:** Elastic SIEM DevSecOps Lab – VirtualBox Edition

