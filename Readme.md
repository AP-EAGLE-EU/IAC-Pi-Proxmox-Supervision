# project:

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

# Functions:
In this project, the focus was placed on automating the deployment of the monitoring solution with Python and applying the Infrastructure-as-Code approach in modern environments.

Main features include:
. Creation of virtual machines (KVM) and containers (LXC)

. Automated installation of Prometheus, Alertmanager, and Grafana, compatible with Raspberry Pi, on-premises servers, or cloud environments

. Automated configuration to simplify the management of the monitoring stack

. Utility scripts for backup and restoration of one or more virtual machines

. Recipe scripts for validating the solution

. Centralized logging of playbook runs


The provided playbooks automate the installation of the monitoring stack and various services such as web servers and databases. Before running the playbooks, you must configure several YAML files (network addressing, IPs for Prometheus, Alertmanager, Grafana, user accounts, passwords, and other settings).
            
            
# Pinciples substitution to handle placeholders like:

config.yaml:
# ------------------------------------------------------------------------------------------
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
    prometheus_ip:                               '10.4.1.151'
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

<playbook.yaml>:
# ------------------------------------------------------------------------------------------
playbooks:
        #********************************************************************************************************
        - name:                                       'Manage Proxmox Containers'
          host:                                       'proxmox'          
        # ______________________________________________________________________________________________________            
        # playbook                 
          tasks:  
            # ___________________________________________________________________________________________________
            # install mariadb
            - name:                                   'proxmox_mariadb_install_lxc'
              ignore_errors:                          'no'
              container_id:                           '{{ mariadb_node01_container_id }}'   
              vars: 
                mariadb_package_to_install:           'mariadb-server'

Inside configuration file:
# ------------------------------------------------------------------------------------------
# /etc/prometheus/config.yml

global:
  scrape_interval:     15s
  evaluation_interval: 15s


rule_files:
  - "/etc/prometheus/alert_rules.yml"    # We'll store the CPU / memory / service-down alerts here


alerting:
  alertmanagers:
    - static_configs:
      - targets:
        - '{{ alertmanager_ip }}:9093'   # IP of your Alertmanager LXC


scrape_configs:                        

   # job for prometheus
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090'] 

   # jobs to scrap data from exporters (PVE, NGINX, PHP-FPM, MARIADB,...)
 
 
 
 # Note for proxmox ssh
Ensure that your Proxmox server is properly configured to accept SSH connection 

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