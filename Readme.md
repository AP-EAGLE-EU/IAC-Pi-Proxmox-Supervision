# Project:

```
  Base_directory (/scripts.py/iac)
  │
  ├─── vault
  │     ├──   id_rsa                             ssh generate key
  │     ├──   id_rsa.pub                         ssh generate key
  │     └──   vault.yaml                         All passwords    
  ├─── dictionary
  │     └──   dictionary.yaml                    dictionary for substitution            
  ├─── modules
  │     ├──   config.py
  │     ├──   commands.py
  │     ├──   end.py
  │     ├──   logging.py   
  │     └──   setup.py
  ├─── playbooks
  │     ├──   proxmox.install.yaml               (Proxmox install, ...)
  │     ├──   proxmox.postinstall.yaml           (Clamav, fail2ban,download lxc image,...)
  │     ├──   supervision.install.lxc.yaml       (prometheus, alertmanager, grafana)
  │     ├──   webserver.install.lxc.yaml         (nginx, php, php-fpm install)            
  │     ├──   pgsql.install.lxc.yaml             (Install postgresql install)
  │     ├──   firewall.install.yaml              (setup firewall proxmox and lxc)  
  │     ├──   backup.yaml                        (backup VM or lxc)   
  │     ├──   restore.yaml                       (restore VM or lxc)          
  │     ├──   vulnerability.yaml                 (CVE vulnerability tests)      
  │     └──   acceptance.yaml                    (tests and acceptance)
  ├─── config
  │     ├──   proxmox
  │     ├──   promotheus
  │     ├──   grafana
  │     ├──   alertemanager
  │     ├──   nginx
  │     ├──   php
  │     ├──   php-fpm
  │     ├──   clamav
  │     ├──   fail2ban  
  │     ├──   posgresql      
  │     └──   ...
  ├──   iac.py                                     (run py iac.py <playbook.yaml>
  ├──   readme.md
  ├──   requirements.txt
  │  
  └──   log
```

![image](https://github.com/user-attachments/assets/5a8d2225-dc7a-4a7c-bc13-469a15a9f3de)

# Functions:

In this project, the focus was placed on automating the deployment of the monitoring solution with Python and applying the Infrastructure-as-Code approach in modern environments.

Main features include:

- Creation of virtual machines (KVM) and containers (LXC) on Rasberry Pi with Proxmox installed.
- Automated installation of Prometheus, Alertmanager, and Grafana, compatible with Raspberry Pi, on-premises servers, or cloud environments.
- Automated configuration to simplify the management of the monitoring stack.
- Utility scripts for backup and restoration of one or more virtual machines.
- Recipe scripts for validating the solution.
- Centralized logging of playbook runs.

The provided playbooks automate the installation of the monitoring stack and various services such as web servers and databases. Before running the playbooks, you must configure several YAML files (network addressing, IPs for Prometheus, Alertmanager, Grafana, user accounts, passwords, and other settings).

## Directory Structure

The scripts are organized into five main directories:

- **vault**: Contains all passwords and RSA keys required for the installation of the monitoring solution.
- **dictionary**: Contains the variable dictionary for value substitution.
- **modules**: Contains the Python scripts.
- **playbooks**: Contains the task sequencing files for various actions such as installing the monitoring solution, setting up a web server, configuring a database server, managing Proxmox firewalls, and adding additional features in Proxmox (including antivirus, brute force protection, backup/restore, and solution testing). The playbooks use the YAML format, which allows easy customization without requiring any knowledge of Python.
- **config**: Stores all configuration files for the monitoring solution. These are the `.conf` files typically found in the `/etc` directory on Linux. This directory allows fine-tuning of settings, such as adding alerts, modifying alert thresholds, or adding dashboards in Grafana.

## Configuration Files for Customization

- **vault/vault.yaml**: Stores all accounts and passwords used for the project.
- **dictionary/dictionary**: Contains variables used to substitute values in configuration files and playbooks.

## How to Run a Playbook

To run a playbook, use the following command:

```
py iac.py <playbook-name>.yaml
```

This approach allows you to automate and customize the installation and configuration of your IT monitoring stack in a modular and secure way.

## Pinciples substitution to handle placeholders with Jinja2 format like:
```
config.yaml:

global_config:
debug:                                       false  
job_name:                                    'IaC for Proxmox'
version:                                     '1.02.2025'
writtenby:                                   'Ambroise PETIN'
# ...............................................................
vault_file_path:                             '{{ base_directory }}/vault/vault.yaml'  
# ...............................................................
# prometheus
prometheus_version:                          '2.53.3'   # LTS
prometheus_ip:                               '192.170.1.100'
prometheus_configs:
- install:                               true
name:                                  'prometheus.yml'
local_conf:                            '{{ base_directory }}/config/prometheus/prometheus.yml'
remote_conf:                           '/etc/prometheus/prometheus.yml'  
- install:                               true
name:                                  'alert_rules.yml'
local_conf:                            '{{ base_directory }}/config/prometheus/alert_rules.yml'
remote_conf:                           '/etc/prometheus/alert_rules.yml'  
- install:                               true
name:                                  'prometheus.service'
local_conf:                            '{{ base_directory }}/config/prometheus/prometheus.service'
remote_conf:                           '/etc/systemd/system/prometheus.service'
```

## Note for proxmox ssh

Ensure that your Proxmox server is properly configured to accept SSH connection

```
# 1. check /etc/ssh/sshd_config
cat /etc/ssh/sshd_config
Port 22
PermitRootLogin yes
ListenAddress 0.0.0.0

# 2. fix 
sed -i 's/^#\?\s*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?\s*Port.*/Port 22/' /etc/ssh/sshd_config
sed -i 's/^#\?\s*ListenAddress.*/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config
    
or 
nano /etc/ssh/sshd_config

PermitRootLogin yes
Port 22
ListenAddress 0.0.0.0   

Ctrl+X Y Enter

# 3. restart ssh
systemctl restart sshd or ssh
systemctl status sshd or ssh
  
# 4. Check pve-firewall Settings
cat /etc/pve/firewall/cluster.fw

# 5. Correct Firewall Configuration (if needed)
nano /etc/pve/firewall/cluster.fw
[OPTIONS]
enable: 1

[RULES]
IN ACCEPT -p tcp --dport 22 -source 0.0.0.0/0    # Allow ssh
IN ACCEPT -p tcp --dport 8006 -source 0.0.0.0/0  # Allow Proxmox Web UI
  
# 6. Check pve-firewall Settings
cat /etc/pve/firewall/cluster.fw

pve-firewall restart
pve-firewall status               -> Status: enabled/running 
systemctl pve-firewall enable  
systemctl restart pve-firewall     
systemctl status pve-firewall     -> actif (running)

# Verify SSH connectivity from an external system
ssh root@your-proxmox-server-ip

ip a to obtain ip

# set a root password (not set by default)
sudo passwd root

# then you can use 
su -
```
