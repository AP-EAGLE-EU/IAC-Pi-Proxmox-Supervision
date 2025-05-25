# ------------------------------------------------------------------------------------------
#    name: configurng.py
#
#    setup packages and execute tasks
#
#    ssh : yes
#
# ------------------------------------------------------------------------------------------
import paramiko
import socket
import logging
import shutil
import time
import datetime
import sys
import os
import re
import posixpath
import yaml
import template
import shlex
import json
import ipaddress
import requests
import ipaddress

from urllib.parse import quote
from jinja2 import Template
from paramiko import RSAKey
from enum import Enum
from modules.end import end
from modules.commands import windows_command, powershell_command

# Configure paramiko logger
paramiko.util.log_to_file('paramiko.log', level='ERROR')  # Set paramiko logging to ERROR level

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------------------   
class RC(Enum):
    success  = 0
    error    = 1
    warning  = 4
    flush    = 16
    critical = 99

# ------------------------------------------------------------------------------------------
def proxmox_ssh_open(dictionary):
    step = 'proxmox_ssh_open'

    try:
    
        # Check required keys
        required_keys = [
            'proxmox_host_ip',
            'proxmox_host_name',
            'proxmox_username',
            'proxmox_password',
            'proxmox_port',
            'proxmox_ssh_timeout'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        proxmox_host_ip     = dictionary.get('proxmox_host_ip')
        proxmox_host_name   = dictionary.get('proxmox_host_name')
        proxmox_username    = dictionary.get('proxmox_username')
        proxmox_password    = dictionary.get('proxmox_password')
        proxmox_port        = dictionary.get('proxmox_port')
        proxmox_ssh_timeout = dictionary.get('proxmox_ssh_timeout')

        # Attempt SSH connection via Paramiko
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logger.info(
            f"Attempting SSH connection to {proxmox_host_ip}:{proxmox_port} "
            f"with user '{proxmox_username}'",
            extra={'stepname': step}
        )
        ssh_client.connect(
            hostname=proxmox_host_ip,
            port=proxmox_port,
            username=proxmox_username,
            password=proxmox_password,
            timeout=proxmox_ssh_timeout,
            banner_timeout=proxmox_ssh_timeout
        )

        transport = ssh_client.get_transport()
        if transport and transport.is_active():
            logger.info(f"SSH connection established successfully with {proxmox_host_ip}:{proxmox_port}.", extra={'stepname': step})
            dictionary['ssh_client']    = ssh_client
            dictionary['ssh_connected'] = True
            return True
        else:
            logger.error(f"SSH connection failed. No active transport found for {proxmox_host_ip}:{proxmox_port}.", extra={'stepname': step})
            return False
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_ssh_close(dictionary):
    step = 'proxmox_ssh_close'

    # Retrieve variables (playbook or dictionary)
    try:
        ssh_client    = dictionary.get('ssh_client')
        ssh_connected = dictionary.get('ssh_connected')

        if not ssh_client:
            logger.warning("No SSH client found to close.", extra={'stepname': step})
            return True  # Nothing to close, treat as success

        # Close the SSH connection
        ssh_client.close()
        dictionary['ssh_connected'] = False
        dictionary['ssh_client']    = None
        logger.info("SSH connection closed successfully.", extra={'stepname': step})
        return True

    except paramiko.SSHException as e:
        logger.warning(f"SSH connection already closed or failed to close gracefully: {e}", extra={'stepname': step})
        dictionary['ssh_connected'] = False
        dictionary['ssh_client']    = None
        return True  # Treat as success since connection is closed

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_create_ssh_keys(dictionary):
    step = 'proxmox_create_ssh_keys'

    # Retrieve variables (playbook or dictionary)
    try:    
        required_keys = ['proxmox_ssh_local_key_path']
        for key in required_keys:
            if dictionary.get(key) is None:
                logger.error(f"Missing required parameter: {key}", extra={'stepname': step})
                return False

        local_dir = os.path.expanduser(dictionary.get('proxmox_ssh_local_key_path'))
    except Exception as e:
        logger.error(f"Unexpected error during variable retrieval: {e}", extra={'stepname': step})
        return False

    # Ensure the directory exists and is writable.
    if not os.path.exists(local_dir):
        try:
            os.makedirs(local_dir, exist_ok=True)
            logger.info(f"Created directory: {local_dir}", extra={'stepname': step})
        except Exception as e:
            logger.error(f"Failed to create directory '{local_dir}': {e}", extra={'stepname': step})
            return False
    else:
        if not os.path.isdir(local_dir):
            logger.error(f"Expected a directory for key storage, but found a file: '{local_dir}'", extra={'stepname': step})
            return False
        if not os.access(local_dir, os.W_OK):
            logger.error(f"Directory '{local_dir}' is not writable", extra={'stepname': step})
            return False
        else:
            logger.info(f"Directory '{local_dir}' exists and is writable.", extra={'stepname': step})

    # Define file paths for private/public keys
    private_key_path = os.path.join(local_dir, "id_rsa")
    public_key_path  = private_key_path + ".pub"

    # Generate a 2048-bit RSA key pair
    try:
        new_key = RSAKey.generate(bits=2048)
        new_key.write_private_key_file(private_key_path)
        logger.info(f"Generated and saved new SSH private key to '{private_key_path}'.", extra={'stepname': step})
    except Exception as e:
        logger.error(f"Failed to create SSH private key at '{private_key_path}': {e}", extra={'stepname': step})
        return False

    # Write the public key
    try:
        public_key_str = f"{new_key.get_name()} {new_key.get_base64()}"
        with open(public_key_path, 'w') as pub_file:
            pub_file.write(public_key_str + "\n")
        logger.info(f"Generated and saved new SSH public key to '{public_key_path}'.", extra={'stepname': step})
    except Exception as e:
        logger.error(f"Failed to write SSH public key to '{public_key_path}': {e}", extra={'stepname': step})
        return False

    # Set file permissions on the private key (Windows icacls usage to mimic chmod 600)
    try:
        username = os.environ.get("USERNAME", "UNKNOWN_USER")
        command = f'icacls "{private_key_path}" /inheritance:r /grant:r "{username}:(R,W)"'
        success, output = windows_command(command, step)
        if success:
            logger.info(f"Set file permissions using icacls on '{private_key_path}'.", extra={'stepname': step})
        else:
            logger.warning(f"Failed to set file permissions with icacls on '{private_key_path}': {output}", extra={'stepname': step})
    except Exception as e:
        logger.warning(f"An unexpected error occurred while setting file permissions: {e}", extra={'stepname': step})

    return True

# ------------------------------------------------------------------------------------------
def proxmox_ssh_authorized_key_upload(dictionary):
    step = 'proxmox_ssh_authorized_key_upload'

    try:   

        # Check required keys
        required_keys = [
            'proxmox_ssh_local_key_path',
            'proxmox_ssh_remote_key_path',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        local_dir              = os.path.expanduser(dictionary.get('proxmox_ssh_local_key_path'))
        local_pub_key_filepath = os.path.join(local_dir, "id_rsa.pub")
        
        remote_dir       = dictionary.get('proxmox_ssh_remote_key_path')
        remote_auth_keys = f"{remote_dir}/authorized_keys"

        # Check if the local public key file exists
        if not os.path.isfile(local_pub_key_filepath):
            logger.error(f"Local public key file not found: {local_pub_key_filepath}", extra={'stepname': step})
            return False

        # Read the public key contents
        try:
            with open(local_pub_key_filepath, 'r') as f:
                public_key = f.read().strip()
        except Exception as e:
            logger.error(f"Failed to read public key file '{local_pub_key_filepath}': {e}", extra={'stepname': step})
            return False

        # Connect to Proxmox via SSH
        if not proxmox_ssh_open(dictionary):
            logger.error("Failed to connect to Proxmox via SSH.", extra={'stepname': step})
            return False

        # Remote commands to prepare the .ssh directory and update authorized_keys
        commands = [
            f"mkdir -p {remote_dir}",
            f"chmod 700 {remote_dir}",
            f'echo "{public_key}" >> {remote_auth_keys}',
            f"chmod 600 {remote_auth_keys}"
        ]
        
        for command in commands:
            try:
                success, error, output = proxmox_command(dictionary, command, step)
                if not success:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                    logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                    logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                    proxmox_ssh_close(dictionary)
                    return False
                logger.info(f"Executed: {command}", extra={'stepname': step})    
                    
            except Exception as e:
                logger.error(f"Exception occurred while executing '{command}': {str(e)}", extra={'stepname': step})
                proxmox_ssh_close(dictionary)
                return False

        # Verify the public key was uploaded
        try:
            command = f"if [ -f {remote_auth_keys} ]; then echo 'VERSION_FILE_EXISTS'; else echo 'VERSION_FILE_NOT_FOUND'; fi"
            success, error, output = proxmox_command(dictionary, command, step)
            if 'VERSION_FILE_NOT_FOUND' in output:
                logger.error(f"Public key not found in remote file '{remote_auth_keys}'", extra={'stepname': step})
                proxmox_ssh_close(dictionary)
                return False
            else:
                logger.info(f"Public key successfully verified in remote file '{remote_auth_keys}'.", extra={'stepname': step})
                
        except Exception as e:
            logger.error(f"Exception during verification of public key upload: {str(e)}", extra={'stepname': step})
            proxmox_ssh_close(dictionary)
            return False

        # Close SSH
        if not proxmox_ssh_close(dictionary):
            logger.error("proxmox_ssh_close failed.", extra={'stepname': step})
            return False
        else:
            logger.info("SSH session closed.", extra={'stepname': step})
            return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_ssh_open_with_private_key(dictionary):
    step = 'proxmox_ssh_open_with_private_key'
    
    try:
        logger.info("Start remove...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'proxmox_host_ip',
            'proxmox_host_name',
            'proxmox_username',
            'proxmox_password',
            'proxmox_port',
            'proxmox_ssh_timeout'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        proxmox_host_ip                = dictionary.get('proxmox_host_ip')
        proxmox_host_name              = dictionary.get('proxmox_host_name')
        proxmox_username               = dictionary.get('proxmox_username')
        local_dir                      = os.path.expanduser(dictionary.get('proxmox_ssh_local_key_path'))
        proxmox_ssh_local_key_filepath = os.path.join(local_dir, "id_rsa")
        proxmox_port                   = dictionary.get('proxmox_port')
        proxmox_ssh_timeout            = dictionary.get('proxmox_ssh_timeout')

        pkey       = paramiko.RSAKey.from_private_key_file(proxmox_ssh_local_key_filepath)
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logger.info(
            f"Attempting SSH connection to {proxmox_host_ip}:{proxmox_port} "
            f"with user '{proxmox_username}' (key-based)",
            extra={'stepname': step}
        )
        ssh_client.connect(
            hostname=proxmox_host_ip,
            port=proxmox_port,
            username=proxmox_username,
            pkey=pkey,
            timeout=proxmox_ssh_timeout,
            banner_timeout=proxmox_ssh_timeout
        )

        transport = ssh_client.get_transport()
        if transport and transport.is_active():
            logger.info(f"SSH connection established successfully with {proxmox_host_ip}:{proxmox_port}.", extra={'stepname': step})
            dictionary['ssh_client']    = ssh_client
            dictionary['ssh_connected'] = True
            return True
        else:
            logger.error(f"SSH connection failed. No active transport found for {proxmox_host_ip}:{proxmox_port}.", extra={'stepname': step})
            return False

        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_command_for_lxc_with_id(dictionary, command, container_id, step):

    try:
        # Check SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.error(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False, "", ""
    
        if not container_id:
            logger.error("container_id provided in arguments.", extra={'stepname': step})
            return False, "", ""

        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
            logger.error("ssh_client found in dictionary", extra={'stepname': step})
            return False, "", ""
            
        # Issue the command
        timeout = 2048
        command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
        stdin, stdout, stderr = ssh_client.exec_command(command_lxc, timeout=timeout)
    
        # Read all stdout/stderr in blocking mode
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
    
        # Retrieve exit code
        exit_status = stdout.channel.recv_exit_status()
    
        if exit_status == 0:
            return True, err, out
        else:
            return False, err, out

    except Exception as e:
        return False, "", str(e)

# ------------------------------------------------------------------------------------------
def proxmox_command_for_lxc(dictionary, command, step):

    try:   
        # Check SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.error(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False, "", ""
            
        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
                
        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
            logger.error("ssh_client found in dictionary", extra={'stepname': step})
            return False, "", ""
            
        if not command:
            logger.error("Command is empty; cannot execute", extra={'stepname': step})
            return False, "", ""
            
        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = dictionary['task_attributes'].get('container_id', [])
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False  
            
        # Issue the command
        timeout     = 2048
        command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
        stdin, stdout, stderr = ssh_client.exec_command(command_lxc, timeout=timeout)

        # Read *all* stdout / stderr in blocking mode
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')

        # Retrieve exit code
        exit_status = stdout.channel.recv_exit_status()

        # Evaluate success
        if exit_status == 0:
            return True, err, out
        else:
            return False, err, out

    except Exception as e:
        return False, "", str(e)

# ------------------------------------------------------------------------------------------
def proxmox_command(dictionary, command, step):

    try:       

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False, "", "" 

        # Retrieve required variables
        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
            logger.error("ssh_client found in dictionary", extra={'stepname': step})
            return False, "", ""

        if not command:
            logger.error("Command is empty; cannot execute", extra={'stepname': step})
            return False, "", ""    

        # Issue the command
        timeout = 2048
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)

        # Read *all* stdout / stderr in blocking mode
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')

        # Retrieve exit code
        exit_status = stdout.channel.recv_exit_status()

        # Evaluate success
        if exit_status == 0:
            return True, err, out
        else:
            return False, err, out

    except Exception as e:
        return False, "", str(e)

# ------------------------------------------------------------------------
def proxmox_commands(dictionary):
    step = 'proxmox_commands'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys ------------------------------------------------
        required_keys   = ['task_attributes']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            if value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # --------------------------------------------------------------------
        task_attributes = dictionary.get('task_attributes', {})
        commands        = task_attributes.get('commands', [])
        ignore_errors   = task_attributes.get('ignore_errors', 'no').lower()

        # Fallback / sanity check for ignore_errors
        if ignore_errors not in ('yes', 'no'):
            logger.warning(f"Invalid ignore_errors value '{ignore_errors}', assuming 'no'",extra={'stepname': step})
            ignore_errors = 'no'

        # Validate commands structure ----------------------------------------
        if not isinstance(commands, list):
            logger.error("commands must be a list of strings", extra={'stepname': step})
            return False
        if not commands:
            logger.warning("No commands to execute", extra={'stepname': step})
            return True  # Nothing to do, but not an error

        overall_success = True

        # Execute each command -----------------------------------------------
        for command in commands:
            if not isinstance(command, str) or command.strip() == '':
                logger.error(f"Invalid command entry: {command}", extra={'stepname': step})
                return False

            success, error, output = proxmox_command(dictionary, command, step)
            if success:
                logger.info(f"Executed: {command}", extra={'stepname': step})
            else:
                # Command failed
                if ignore_errors == 'no':
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command : '{command}'", extra={'stepname': step})
                    logger.error(f"--> output  :\n'{output}'", extra={'stepname': step})
                    logger.error(f"--> error   :\n'{error}'",  extra={'stepname': step})
                    return False
                else:
                    overall_success = False
                    logger.warning(f"Command failed but continuing (ignore_errors:{ignore_errors})",
                                   extra={'stepname': step})
                    logger.error(f"--> command : '{command}'", extra={'stepname': step})
                    logger.error(f"--> output  :\n'{output}'", extra={'stepname': step})
                    logger.error(f"--> error   :\n'{error}'",  extra={'stepname': step})

        # Final result --------------------------------------------------------
        if overall_success:
            logger.info("All commands processed successfully", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more commands failed (ignored)", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_service_status_lxc(dictionary, service):
    step = "proxmox_service_status_lxc"

    try:
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        if not service:
            logger.error("service argument is empty.", extra={'stepname': step})
            return False
            
        command = f"systemctl status {service}"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : \n'{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : \n'{error}'.", extra={'stepname': step})
            return False            
        logger.info(f"Executed: {command}", extra={'stepname': step})            

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------
def proxmox_is_group_exist(dictionary, group_name):
    """
    Checks if a given group exists on the remote host.
    Returns True if the group is found, else False.
    """
    step = 'is_group_exist'
    command = f"getent group {shlex.quote(group_name)}"
    success, error, output = proxmox_command(dictionary, command, step)
    return success and bool(output.strip())

# ------------------------------------------------------------------------------------------
def proxmox_is_ssh_connected(dictionary):
    step = 'proxmox_is_ssh_connected'

    try: 
        # Retrieve variables (playbook or dictionary)
        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
           return False

        # Check if transport is active
        transport = ssh_client.get_transport()
        if transport and transport.is_active():
            return True
        else:
            logger.warning("SSH transport is inactive or not established.", extra={'stepname': step})
            return False                       
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------
def proxmox_is_lxc_exist(dictionary):
    step = 'proxmox_is_lxc_exist'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retrieve variables (playbook or dictionary)
        required_keys = ['task_attributes', 'pve_exporter_user_for_service']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
                
        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False
  
        command = f"pct status {container_id}"
        success, error, output = proxmox_command(dictionary, command, step)
        if success:
            return True
        else:
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------
def proxmox_is_lxc_access(dictionary):
    step = 'proxmox_is_lxc_access'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retrieve required variables
        for key in ['pve_exporter_user_for_service']:
            if dictionary.get(key) is None:
                logger.error(f"Missing required parameter: {key}", extra={'stepname': step})
                return False
                
        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False
  
        # Ensure we have access
        command = f"pct config {container_id}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})           
        
        return True           
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_is_service_actif_lxc(dictionary, service, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        if not service:
           logger.error("Service name is not provided.", extra={'stepname': step})
           return False

        # Verify if service is running   
        command     = f"systemctl is-active {service}"
        service_active, error, output = proxmox_command_for_lxc(dictionary, command, step)
        
        if "inactive" in output or "failed" in output:
            return False
        else: 
            return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_is_package_installed_lxc(dictionary, package):
    step = 'proxmox_is_package_installed_lxc'   

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
    
        command     = f"apt list --installed"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step) 
        if package in output:
            return True
        else:
            return False
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_is_package_installed(dictionary, package):
    step = 'proxmox_is_package_installed'   

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
    
        command     = f"apt list --installed"
        success, error, output = proxmox_command(dictionary, command, step) 
        if package in output:
            return True
        else:
            return False
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_service_operation_lxc(dictionary, service_name, action, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
    
        # Retrieve required variables
            
        # Ensure action is valid
        if action not in ['start', 'stop', 'restart']:
            logger.error(f"Invalid action '{action}' for service operation.", extra={'stepname': step})
            return False            

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
                
        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False   
 
        # Check the service status
        service_active = proxmox_is_service_actif_lxc(dictionary, service_name, step)
      
        # Handle 'start' or 'restart' action
        if action in ['start', 'restart']:
        
            if service_active and action == 'start':
                logger.info(f"--> {service_name} already started.", extra={'stepname': step})
                return True    
        
            command     = f"systemctl {action} {service_name}"
            command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}" 
            success, error, output = proxmox_command(dictionary, command_lxc, step)   
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

            # Wait for the service to change state
            time.sleep(15)

            # Check the service status
            if proxmox_is_service_actif_lxc(dictionary, service_name, step):
                logger.info(f"--> {service_name} started.", extra={'stepname': step})
                return True
            else:
                logger.error(f"Failed to {action} '{service_name}'. Error: {error}", extra={'stepname': step})
                return False
                   
        # Handle 'stop' action
        else:
            if not service_active:
                logger.info(f"--> {service_name} already stopped.", extra={'stepname': step})
                return True
            else:
                command     = f"systemctl {action} {service_name}"
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}" 
                success, error, output = proxmox_command(dictionary, command_lxc, step)   
                if not success:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                    logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                    logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                    return False
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

                # Wait for the service to change state
                time.sleep(15)

                # Check the service status
                if proxmox_is_service_actif_lxc(dictionary, service_name, step):
                    logger.error(f"Failed to {action} '{service_name}'. Error: {error}", extra={'stepname': step})
                    return False
                else:
                    logger.info(f"--> {service_name} stopped.", extra={'stepname': step})
                    return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_status_and_get_ip_lxc(dictionary, container_id, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        if not container_id:
            logger.error("container_id provided in calling function.", extra={'stepname': step})
            return False   
            
        # Checks if the container (container_id) is running
        command_lxc = f"pct status {container_id}" 
        success, error, output = proxmox_command(dictionary, command_lxc, step)   
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command:   '{command}'", extra={'stepname': step})
            logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})


        if "status: running" in output.lower():
            logger.info(f"CT {container_id} is running.", extra={'stepname': step})

            # Get IP address
            command = f"pct exec {container_id} -- ip addr show eth0"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

            ip_match = re.search(r'inet\s(\d+\.\d+\.\d+\.\d+)', output)
            if ip_match:
                ip_address = ip_match.group(1)
                logger.info(f"IP address for CT {container_id} is {ip_address}", extra={'stepname': step})
                return True, ip_address
            else:
                logger.warning(f"Could not parse IP address for CT {container_id}", extra={'stepname': step})
                return True, None
        else:
            logger.warning(f"CT {container_id} is not running.", extra={'stepname': step})
            return False, None

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_health_check(dictionary):
    step = 'proxmox_health_check'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # A list of checks to run
        checks = [
            {
                'command':     "systemctl is-active pve-cluster",
                'success':     "active",
                'error':       "pve-cluster service not active",
                'description': "Check pve-cluster up and running",
            },
            {
                'command':     "systemctl is-active pveproxy",
                'success':     "active",
                'error':       "pveproxy service not active",
                'description': "Check pveproxy up and running",
            },
            {
                'command':     "systemctl is-active pvedaemon",
                'success':     "active",
                'error':       "pvedaemon service not active",
                'description': "Check pvedaemon up and running",
            },
            {
                'command':     "systemctl is-active pve-firewall",
                'success':     "active",
                'error':       "pve-firewall service not active",
                'description': "Check pve-firewall up and running",
            },
            {
                'command':     "systemctl is-active networking",
                'success':     "active",
                'error':       "networking service not active",
                'description': "Check networking up and running",
            },
            {
                # The lambda check verifies usage is < 90%
                'command':     "df -h / --output=pcent | tail -n1",
                'success':     lambda x: int(x.strip('%')) < 90,
                'error':       "Root filesystem usage over 90%",
                'description': "Check root filesystem usage",
            },
            {
                'command':     "curl -sI -k -X GET https://localhost:8006 | head -n1",
                'success':     "200 OK",
                'error':       "Proxmox Web UI not responding",
                'description': "Check proxmox web interface access",
            },             
            {
                # This check ensures no packet loss. 
                # If partial losses occur, '0% packet loss' won't appear, and the check fails.
                'command':     "ping -c 4 8.8.8.8",
                'success':     "0% packet loss",
                'error':       "Ping to 8.8.8.8 gave packet loss",
                'description': "Check external connectivity (ICMP)",
            },       
        ]

        overall_success = True
        for check in checks:
            command = check['command']
            success, error, output = proxmox_command(dictionary, command, step)

            # If 'success' is a callable (i.e., lambda), evaluate it with the output
            if callable(check['success']):
                try:
                    check_passed = check['success'](output.strip())
                except Exception as e:
                    logger.error(f"Check failed to execute: {e}", extra={'stepname': step})
                    check_passed = False
            else:
                # Otherwise, treat 'success' as a substring that must appear in output
                check_passed = (check['success'] in output)

            if not success or not check_passed:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Description: {check['description']}", extra={'stepname': step})
                logger.error(f"--> Command: {check['command']}", extra={'stepname': step})
                logger.error(f"--> Output : \n {output}", extra={'stepname': step})
                logger.error(f"--> Error  : \n {error}", extra={'stepname': step})
                overall_success = False
            else:
                logger.info(f"Executed: {check['description']}", extra={'stepname': step})


        # --- Additional test 1: Disk usage check ---
        command = "df -h / | tail -1"
        success, error, output = proxmox_command(dictionary, command, step)
        if success:
            try:
                # Typical output: "/dev/sda1  50G 20G 28G 42% /"
                usage_percent = output.split()[4]  # "42%"
                usage_value = int(usage_percent.strip('%'))
                if usage_value >= 90:
                    logger.error(f"Disk usage too high: {usage_value}%", extra={'stepname': step})
                    overall_success = False
            except Exception as e:
                logger.error(f"Failed to parse disk usage output: {output} - {e}", extra={'stepname': step})
                overall_success = False
        else:
            logger.error(f"Disk usage command failed. Output: {output}. Error: {error}", extra={'stepname': step})
            overall_success = False


        # --- Additional test 2: Memory check ---
        mem_check_cmd = "free -m | grep Mem:"
        success, error, output = proxmox_command(dictionary, mem_check_cmd, step)
        if success:
            try:
                # Typical: "Mem:   2048  1000  500  100  200  800"
                parts = output.split()
                # The 'free' column is typically parts[3]; double-check on your distro
                free_mem = int(parts[3])
                if free_mem < 100:
                    logger.error(f"Insufficient free memory: {free_mem} MB", extra={'stepname': step})
                    overall_success = False
            except Exception as e:
                logger.error(f"Failed to parse memory usage output: {output} - {e}", extra={'stepname': step})
                overall_success = False
        else:
            logger.error(f"Memory check command failed. Output: {output}. Error: {error}", extra={'stepname': step})
            overall_success = False

        if overall_success:
            logger.info("--> All health checks passed successfully.", extra={'stepname': step})
        else:
            logger.error("One or more health checks failed.", extra={'stepname': step})
        
        return overall_success

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_post_install(dictionary):
    step = 'proxmox_post_install'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Start proxmox post install...", extra={'stepname': step})
 
        # Check required keys
        required_keys = [
            'proxmox_host_ip',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        proxmox_host_ip = dictionary.get('proxmox_host_ip')
        
        # Example: if proxmox_host_ip = "192.168.1.50", network_address = "192.168.1.0/24"
        network_address = '.'.join(proxmox_host_ip.split('.')[:3]) + '.0/24'

        # Note: "apt update -y" is not recognized on some systems. Usually "apt update" needs no -y.
        # If you see an error, consider removing "-y" or switching to "apt update".
        commands = [
            # Step 1: Disable Enterprise Repository if it exists
            ('if [ -f /etc/apt/sources.list.d/pve-enterprise.list ]; then '
             'sed -i "s|^deb https://enterprise.proxmox.com/debian/pve.*|#&|" /etc/apt/sources.list.d/pve-enterprise.list; '
             'fi'),

            # Step 2: Disable Ceph Quincy Enterprise Repository if it exists
            ('if [ -f /etc/apt/sources.list.d/ceph.list ]; then '
             'sed -i "s|^deb https://enterprise.proxmox.com/debian/ceph-quincy.*|#&|" /etc/apt/sources.list.d/ceph.list; '
             'fi'),

            # Step 3: Add the No-Subscription Proxmox Repository (assuming Bookworm)
            'echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" '
            '| tee /etc/apt/sources.list.d/pve-no-subscription.list',

            # Step 4: Add the No-Subscription Ceph Repository
            'echo "deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription" '
            '| tee /etc/apt/sources.list.d/ceph-no-subscription.list',

            # Step 5: Verify the new repos are created
            'test -f /etc/apt/sources.list.d/pve-no-subscription.list',
            'test -f /etc/apt/sources.list.d/ceph-no-subscription.list',

            # Step 6: Update packages
            'apt update -y',             # If you get an error, remove "-y" or use "apt update"
            
            # Step 7: Upgrade all packages
            'apt full-upgrade -y',
            
            # Step 8: Clean up
            'apt autoremove -y && apt clean',
            
             # Step 8: add on install
            'apt install -y netcat-openbsd zip' 
                                    
        ]

        # Execute each command
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_smtp_setup(dictionary):
    step = 'proxmox_smtp_setup'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Start proxmox notification setup...", extra={'stepname': step})
 
        # Check required keys
        required_keys = [                        
            'proxmox_smtp_endpoint',
            'proxmox_smtp_server',
            'proxmox_smtp_port',           
            'proxmox_smtp_username',
            'proxmox_smtp_password',
            'proxmox_smtp_mode',
            'proxmox_smtp_from_address',
            'proxmox_smtp_mailto',
            'proxmox_smtp_author',  
            'proxmox_smtp_comment',              
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        proxmox_smtp_endpoint       = dictionary.get('proxmox_smtp_endpoint')
        proxmox_smtp_server         = dictionary.get('proxmox_smtp_server')
        proxmox_smtp_port           = int(dictionary.get('proxmox_smtp_port') )      
        proxmox_smtp_username       = dictionary.get('proxmox_smtp_username')
        proxmox_smtp_password       = dictionary.get('proxmox_smtp_password')
        proxmox_smtp_mode           = dictionary.get('proxmox_smtp_mode')
        proxmox_smtp_from_address   = dictionary.get('proxmox_smtp_from_address')
        proxmox_smtp_mailto         = dictionary.get('proxmox_smtp_mailto')        
        proxmox_smtp_author         = dictionary.get('proxmox_smtp_author')
        proxmox_smtp_comment        = dictionary.get('proxmox_smtp_comment')

        # Remove endpoint if it already exists
        command = f"pvesh delete /cluster/notifications/endpoints/smtp/{proxmox_smtp_endpoint}"
        success, error, output = proxmox_command(dictionary, command, step)
        if success:
            logger.info(f"Deleted existing SMTP endpoint '{proxmox_smtp_endpoint}'.", extra={'stepname': step})
        else:
            logger.warning(f"Endpoint '{proxmox_smtp_endpoint}' may not exist or deletion failed (ignored).", extra={'stepname': step})

        # Create new SMTP endpoint under /cluster/notification-endpoints
        command = (
            f"pvesh create /cluster/notifications/endpoints/smtp "
            f"--name '{proxmox_smtp_endpoint}' "           
            f"--server '{proxmox_smtp_server}' "
            f"--mode '{proxmox_smtp_mode.lower()}' " 
            f"--username '{proxmox_smtp_username}' "
            f"--password '{proxmox_smtp_password}' "
            f"--from-address '{proxmox_smtp_from_address}' "
            f"--mailto '{proxmox_smtp_mailto}' "
            f"--comment '{proxmox_smtp_comment}' "
            f"--author '{proxmox_smtp_author}' "
            f"--port {proxmox_smtp_port} "                        
        )
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to create SMTP endpoint.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False

        logger.info(f"SMTP endpoint '{proxmox_smtp_endpoint}' created successfully.", extra={'stepname': step})

        if not proxmox_smtp_up(dictionary):
            return False
            
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_smtp_up(dictionary):
    step = "proxmox_smtp_up"

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Start proxmox notification check...", extra={'stepname': step})
 
        # Check required keys
        required_keys = [                        
            'proxmox_smtp_endpoint',           
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        proxmox_smtp_endpoint       = dictionary.get('proxmox_smtp_endpoint')

        # Send test notification
        command = (
            f"pvesh create /cluster/notifications/targets/{proxmox_smtp_endpoint}/test "
        )
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to send test email.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False

        logger.info(f"Test email sent successfully via '{proxmox_smtp_endpoint}'.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_xfce_remove(dictionary):
    step = 'proxmox_xfce_remove'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Removing any existing 'xfce/xrdp' ...", extra={'stepname': step})

        commands = [
            "apt-get -y purge xfce4 xrdp xfconf xorgxrdp",
            "apt autoremove -y",
        ]
        for cmd in commands:
            success, error, output = proxmox_command(dictionary, cmd, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False

        logger.info("'xfce/xrdp' removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_xfce_install(dictionary):
    step = 'proxmox_xfce_install'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start install...", extra={'stepname': step})
        
        # Optionally remove existing xfce/xrdp environment if it exists
        if not proxmox_xfce_remove(dictionary):
            logger.error("'xfce/xrdp' removal was unsuccessful.", extra={'stepname': step})
            return False

        commands = [
            "apt-get clean all",
            "apt-get -y upgrade",
            "apt-get -y update",
            
            "apt install -y xfce4 xfce4-goodies xorg dbus-x11 x11-xserver-utils",
            "apt install -y xorgxrdp xrdp",
            "apt install -y xfconf",  # ensures we can run xfconf-query
            "systemctl daemon-reload",
            "systemctl enable xrdp"
        ]
        for cmd in commands:
            success, err, out = proxmox_command(dictionary, cmd, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False

        logger.info("'xfce/xrdp' installed successfully.", extra={'stepname': step})

        # Tuning, kill old sessions, then final check
        if not proxmox_audio_video_install(dictionary):   
            return False
            
        if not proxmox_xfce_tuning(dictionary):
            return False

        # Instead of reboot, forcibly kill leftover sessions & restart xrdp
        if not proxmox_xfce_cleanup_sessions(dictionary):
            return False

        if not proxmox_xfce_up(dictionary):
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_audio_video_install(dictionary):
    step = 'proxmox_audio_video_install'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Installing Pulseaudio and Intel video drivers...", extra={'stepname': step})

        commands = [
            "apt-get clean all",
            "apt-get -y upgrade",
            "apt-get -y update",
            
            # Install Intel video VA-API driver + vainfo
            "apt install -y intel-media-va-driver vainfo",

            # Install general build requirements + Pulseaudio dev libs
            "apt install -y git build-essential autoconf libtool pkg-config libpulse-dev",

            # Install Pulseaudio + Pavucontrol for managing audio
            "apt install -y pulseaudio pavucontrol",

            # Clone + build pulseaudio-module-xrdp from source
            # Remove any previous dir and re-clone
            "cd /root && rm -rf pulseaudio-module-xrdp*",
            "git clone https://github.com/neutrinolabs/pulseaudio-module-xrdp.git",
            "cd /root/pulseaudio-module-xrdp/scripts && ./install_pulseaudio_sources_apt.sh",
            "cd /root/pulseaudio-module-xrdp && ./bootstrap",
            "cd /root/pulseaudio-module-xrdp && ./configure PULSE_DIR='/root/pulseaudio.src'",
            "cd /root/pulseaudio-module-xrdp && make",
            "cd /root/pulseaudio-module-xrdp && make install",

            # Add 'EnablePulseaudio=1' to /etc/xrdp/sesman.ini (if not already present)
            "sed -i '/^\\[Globals\\]/a EnablePulseaudio=1' /etc/xrdp/sesman.ini",

            # Securely add xrdp to ssl-cert group only if not already a member
            # This one-line command will only run adduser if xrdp is NOT in group ssl-cert
            r"getent group ssl-cert | grep -q '\bxrdp\b' || adduser xrdp ssl-cert",

            # Restart xrdp
            "systemctl restart xrdp",
            
            #Auto-Start PulseAudio on Login
            "systemctl --user enable pulseaudio",
            "systemctl --user restart pulseaudio",            
        ]

        # Execute each command with error checking
        for cmd in commands:
            success, err, out = proxmox_command(dictionary, cmd, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False

        logger.info("Audio + video packages installed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_xfce_tuning(dictionary):
    step = 'proxmox_xfce_tuning'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        required_keys = ['task_attributes']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Write .xsession and set a higher DPI
        commands = [
            r'echo "xfce4-session" > /etc/skel/.xsession',

            # Optionally set a higher DPI (120 => 125% scale)
            "xfconf-query -c xsettings -p /Xft/DPI -n -t int -s 175",

            # Ensure the Xfce settings daemon sees the new DPI
            "xfsettingsd --replace &",

            # Start xrdp if not running
            "systemctl start xrdp",
            # Sleep for a bit to ensure xrdp is actually started
            "sleep 5"
        ]

        for cmd in commands:
            success, err, out = proxmox_command(dictionary, cmd, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("'xfce/xrdp' tuning completed.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_xfce_cleanup_sessions(dictionary):
    step = 'proxmox_xfce_cleanup_sessions'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Stopping leftover XRDP/xfce sessions to force a fresh session...", extra={'stepname': step})

        commands = [
            "systemctl stop xrdp",
            "systemctl stop xrdp-sesman || true",
            "pkill -9 xfce4-session || true",
            "pkill -9 Xorg || true",
            "systemctl start xrdp",
            "systemctl start xrdp-sesman",
            "sleep 15"
        ]

        for cmd in commands:
            success, err, out = proxmox_command(dictionary, cmd, step)
            # If a 'pkill' or 'stop xrdp' fails, we may continue, 
            # but let's be strict and stop if it's essential:
            if not success and "pkill" not in cmd:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("Leftover sessions cleared; XRDP restarted. Ready for a new session.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_xfce_up(dictionary):
    step = 'proxmox_xfce_up'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
                
        required_keys = ['task_attributes']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        # Basic checks
        service = 'xrdp'   
        checks  = [
            {
                'command': "systemctl is-active xrdp",
                'success': "active",
                'error':   "xrdp service not active",
                'description': "Check xrdp up and running",
            },
            {
                # We just look for '3389' in the output
                'command': "ss -lntp",
                'success': "3389",
                'error':   "xrdp not listening on 3389",
                'description': "Check xrdp listening on port 3389",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue
            
            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Command:   {check['command']}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})              
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})             

                overall_success = False
                continue
            else:
                logger.info(f"Executed: {check['description']}", extra={'stepname': step})
           
        if overall_success:
            logger.info("'ClamAV' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            for service in ["clamav-daemon", "clamav-freshclam"]:
                command = f"systemctl status {service}"
                s, err, out = proxmox_command(dictionary, command, step)
                if s:
                    logger.info(f"--> Command: {command}", extra={'stepname': step})
                    logger.info(f"--> Output : {out}", extra={'stepname': step})
                else:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command:   {command}", extra={'stepname': step})
                    logger.error(f"--> output  : '{out}'", extra={'stepname': step})
                    logger.error(f"--> error   : '{err}'", extra={'stepname': step})

            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_remove_subscription(dictionary):
    step = 'proxmox_remove_subscription'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("proxmox remove subscription starting...", extra={'stepname': step})

        # List of commands to execute to remove subscription notice
        commands = [
            # Roll back the original JavaScript file
            'apt reinstall proxmox-widget-toolkit',
                        
            # Backup the original JavaScript file
            'cp /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js.bak',

            # Modify the proxmoxlib.js file to bypass the subscription notice
            'sed -i.bak -E "s|(function\\(orig_cmd\\) \\{)|\\1\\n    orig_cmd();\\n    return;|g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js',

            # Restart the Proxmox web proxy service to apply the changes
            'systemctl restart pveproxy.service',
        ]

        # Execute each command in sequence
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("Remove subscription completed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_rollback_subscription_notice(dictionary):
    step = 'proxmox_rollback_subscription_notice'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Rollback proxmox subscription notice starting...", extra={'stepname': step})

        # List of commands to rollback subscription notice changes
        commands = [
            # Step 1: Restore the backup JavaScript file
            'apt reinstall proxmox-widget-toolkit',
            
            # Step 2: Restart the Proxmox web proxy service to apply the changes
            'systemctl restart pveproxy.service',
        ]

        # Execute each command in sequence
        for command in commands:
            success, error, output = proxmox_command(ssh_client, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("Rollback of subscription notice completed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fix_issues(dictionary):
    step = 'proxmox_fix_issues'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start fix issues...", extra={'stepname': step})
        
        # Check for Proxmox 'inotify poll request' issue
        command = "journalctl -u pveproxy | grep 'inotify poll request in wrong process'"
        success, error, output = proxmox_command(dictionary, command, step)
        if success and "inotify poll request in wrong process" in output:
            logger.warning(
                "Detected 'inotify poll request in wrong process' issue. Initiating fix for Proxmox inotify issue...",
                extra={'stepname': step}
            )
            if not proxmox_inotify_fix(dictionary):
                logger.error("Failed to fix Proxmox inotify-related issue.", extra={'stepname': step})
                return False

        logger.info("All identified issues have been addressed (or checked) successfully.", extra={'stepname': step})

        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_inotify_fix(dictionary):
    step = 'proxmox_inotify_issue'
    
    try:
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        commands = [
            (
                "echo 'fs.inotify.max_user_instances=1024' | tee -a /etc/sysctl.conf",
                "Increasing inotify max_user_instances limit"
            ),
            (
                "echo 'fs.inotify.max_user_watches=1048576' | tee -a /etc/sysctl.conf",
                "Increasing inotify max_user_watches limit"
            ),
            (
                "sysctl -p",
                "Applying sysctl configuration"
            ),
            (
                "mkdir -p /etc/systemd/system/pveproxy.service.d/",
                "Creating custom pveproxy systemd directory"
            ),
            (
                """echo -e "[Service]\\nLimitNOFILE=1048576\\nLimitNPROC=1048576" > /etc/systemd/system/pveproxy.service.d/override.conf""",
                "Setting file and process limits for pveproxy"
            ),
            (
                "systemctl daemon-reload",
                "Reloading systemd configuration"
            ),
            (
                "systemctl restart pveproxy pvedaemon pve-cluster",
                "Restarting Proxmox services"
            )
        ]

        for command, description in commands:
            logger.info(f"Running fix step: {description}", extra={'stepname': step})
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})
        
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_reboot(dictionary):
    step = 'proxmox_reboot'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Starting to reboot proxmox server...", extra={'stepname': step})

        # Retrieve variables (playbook or dictionary)
        required_keys = ['proxmox_host_ip', 'proxmox_host_name']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Basic environment references
        proxmox_host_ip   = dictionary.get('proxmox_host_ip', 'unknown-ip')
        proxmox_host_name = dictionary.get('proxmox_host_name', proxmox_host_ip)
               
        # 1) Issue the reboot command over SSH
        logger.info(f"[{step}] Issuing reboot command to '{proxmox_host_name}'...", extra={'stepname': step})
        reboot_cmd = "sudo reboot"
        success, error, output = proxmox_command(dictionary, reboot_cmd, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        else:
            logger.info(f"[{step}] Reboot command issued successfully. Closing SSH session...", extra={'stepname': step})
            
            # Close the SSH session after issuing reboot
            if dictionary.get('ssh_client'):
                dictionary['ssh_client'].close()
            dictionary['ssh_client']    = None
            dictionary['ssh_connected'] = False

        # Wait for the server to go offline, up to a short limit
        # For a simple example: attempt a quick SSH check or ping
        # so we don't keep going if the server never actually goes down.
        offline_wait     = 60
        offline_elapsed  = 0
        offline_interval = 5

        logger.info(f"[{step}] Waiting up to {offline_wait}s for the server to go offline...", extra={'stepname': step})
        offline_start_time = time.time()

        while True:
            if (time.time() - offline_start_time) > offline_wait:
                logger.warning(f"[{step}] Server '{proxmox_host_name}' never went offline (timeout {offline_wait}s). Continuing...", extra={'stepname': step})
                break

            # Quick SSH check to see if we can still connect
            if proxmox_ssh_open_with_private_key(dictionary):
                # If we connected, it's still online, so close again and wait
                dictionary['ssh_client'].close()
                dictionary['ssh_client']    = None
                dictionary['ssh_connected'] = False
                time.sleep(offline_interval)
            else:
                logger.info(f"[{step}] Server '{proxmox_host_name}' is now offline (as expected).", extra={'stepname': step})
                break

        # Wait for the server to come back online
        max_wait   = 300   # total wait in seconds
        interval   = 10    # each SSH retry interval

        logger.info(f"[{step}] Waiting up to {max_wait}s for server '{proxmox_host_name}' to come back online...", extra={'stepname': step})
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time
            if elapsed > max_wait:
                logger.error(f"[{step}] Timeout ({max_wait}s) waiting for server '{proxmox_host_name}' to come back.", extra={'stepname': step})
                return False

            # 4) Attempt to open SSH now that we assume it's online
            if proxmox_ssh_open_with_private_key(dictionary):
                logger.info(f"[{step}] Successfully reconnected to server '{proxmox_host_name}' after reboot.", extra={'stepname': step})
                # Optionally wait some extra time for services to become fully operational
                # time.sleep(60)
                return True
            else:
                # Clean up partial session, try again next iteration
                if dictionary.get('ssh_client'):
                    dictionary['ssh_client'].close()
                dictionary['ssh_client']    = None
                dictionary['ssh_connected'] = False

            # Wait before the next retry
            time.sleep(interval)

        # We won't actually get here because of the while True + return statements.
        # If we did, we'd log an error:
        logger.error(f"Failed to reconnect to Proxmox server '{proxmox_host_name}' after reboot.", extra={'stepname': step})
  
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def combine_entries(entries_list, required_keys):
    combined = {}
    for entry in entries_list:
        if isinstance(entry, dict):
            combined.update(entry)

    # If the required keys are not present, return an empty list.
    if not all(key in combined for key in required_keys):
        return []
    return [combined]

# ------------------------------------------------------------------------------------------
def proxmox_linux_makedirs(dictionary, remote_base):
    step = "linux_makedirs"

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Retrieve required variables
        remote_base = remote_base.strip()
        if not remote_base:
            logger.error("Empty remote_base provided to linux_makedirs", extra={'stepname': step})
            return False

        # Force forward slash
        remote_base  = remote_base.replace('\\', '/')

        # If path starts with '/', we treat base as '/' for incremental building
        parts        = [p for p in remote_base.split('/') if p]
        current_path = '/' if remote_base.startswith('/') else ''

        for part in parts:
            if current_path == '/':
                current_path += part  # becomes /part
            else:
                current_path += '/' + part

            # Check if directory already exists
            command = f"test -d {shlex.quote(current_path)}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                # Directory doesn't exist, so attempt creation
                command = f"mkdir {shlex.quote(current_path)}"
                success, error, output = proxmox_command(dictionary, command, step)
                if not success:
                    logger.error("Failed to create directory:", extra={'stepname': step})
                    logger.error(f"--> command:   {command}", extra={'stepname': step})
                    logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                    logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                    return False
                else:
                    logger.info(f"Created directory: {current_path}", extra={'stepname': step})
            else:
                logger.debug(f"Directory already exists: {current_path}", extra={'stepname': step})

        # Final check to confirm the full remote_base exists
        command = f"test -d {shlex.quote(current_path)}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error(f"Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})

        return True
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def upload_files_windows_2_linux(dictionary, files_to_upload, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'ssh_client',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        ssh_client = dictionary.get('ssh_client')

        # Open SFTP client
        sftp_client = ssh_client.open_sftp()

        for local_path, remote_path in files_to_upload:
            # Check if the local file exists
            if not os.path.exists(local_path):
                logger.error(f"Local file {local_path} not found.", extra={'stepname': step})
                sftp_client.close()
                return False

            # Check if remote directory exists
            remote_dir = os.path.dirname(remote_path)
            try:
                sftp_client.stat(remote_dir)
            except IOError:
                try:
                    sftp_client.mkdir(remote_dir)
                    logger.debug(f"Created remote directory {remote_dir}.", extra={'stepname': step})
                except Exception as e:
                    logger.error(f"Failed to create remote directory {remote_dir}: {str(e)}", extra={'stepname': step})
                    sftp_client.close()
                    return False

            # Delete the existing remote file if it exists
            try:
                sftp_client.remove(remote_path)
            except IOError:
                logger.debug(f"No existing remote file {remote_path} to delete.", extra={'stepname': step})

            # Determine if the file is binary or text
            is_binary = False
            _, file_extension = os.path.splitext(local_path)
            binary_extensions = [
                '.zip', '.png', '.jpg', '.jpeg', '.gif', '.exe', '.dll',
                '.so', '.bin', '.tar', '.gz', '.bz2', '.xz', '.7z', '.iso',
                '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx',
            ]

            if file_extension.lower() in binary_extensions:
               is_binary = True

            if is_binary:
                # Handle binary file
                try:
                    with open(local_path, 'rb') as file:
                        content = file.read()

                    # Upload the binary content to the remote path
                    with sftp_client.open(remote_path, 'wb') as remote_file:
                        remote_file.write(content)

                    # Verify that the file was successfully uploaded
                    try:
                        sftp_client.stat(remote_path)
                        logger.debug(f"Uploaded binary file {remote_path} successfully.", extra={'stepname': step})
                    except IOError:
                        logger.error(f"Uploaded remote binary file {remote_path} failed.", extra={'stepname': step})
                        sftp_client.close()
                        return False

                except Exception as e:
                    logger.error(f"Exception while handling binary file {local_path}: {str(e)}", extra={'stepname': step})
                    sftp_client.close()
                    return False

            else:
                # Handle text file
                try:
                    with open(local_path, 'r') as file:
                        content = file.read()

                    # Render text file using Jinja2 with {{ variable }} placeholders
                    template         = Template(content)
                    rendered_content = template.render(**dictionary)

                    # Upload the rendered content to the remote path
                    with sftp_client.open(remote_path, 'w') as remote_file:
                        remote_file.write(rendered_content)

                    # Verify that the file was successfully uploaded
                    try:
                        sftp_client.stat(remote_path)
                        logger.info(f"Uploaded text file {remote_path} successfully.", extra={'stepname': step})
                    except IOError:
                        logger.error(f"Uploaded remote text file {remote_path} failed.", extra={'stepname': step})
                        sftp_client.close()
                        return False

                except Exception as e:
                    logger.error(f"Exception while handling text file {local_path}: {str(e)}", extra={'stepname': step})
                    sftp_client.close()
                    return False
  
        # Close the SFTP client after successful operations
        sftp_client.close()
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retrieve required variables
        required_keys = ['task_attributes', 'ssh_client']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False
          
        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
            logger.error("Missing ssh_client in dictionary", extra={'stepname': step})
            return False        

        # Open an SFTP session on the Proxmox host
        try:
            sftp_client = ssh_client.open_sftp()
        except Exception as e:
            logger.error(f"Failed to open SFTP session: {e}", extra={'stepname': step})
            return False

        for local_path, remote_path in files_to_upload:
        
            # Check local file
            if not os.path.exists(local_path):
                logger.error(f"Local file {local_path} not found.", extra={'stepname': step})
                sftp_client.close()
                return False

            # Build a tmp path
            basename         = os.path.basename(local_path)
            proxmox_tmp_path = f"/tmp/{basename}"

            # Remove existing file at that tmp path
            try:
                sftp_client.remove(proxmox_tmp_path)
            except IOError:
                pass
            except Exception as e:
                logger.warning(f"Error removing existing file {proxmox_tmp_path}: {e}", extra={'stepname': step})

            # Decide if the file is binary or text
            _, file_extension = os.path.splitext(local_path)
            binary_extensions = [
                '.zip', '.png', '.jpg', '.jpeg', '.gif', '.exe', '.dll',
                '.so', '.bin', '.tar', '.gz', '.bz2', '.xz', '.7z', '.iso',
                '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.json'
            ]
            is_binary = file_extension.lower() in binary_extensions

            # Upload to Proxmox host /tmp
            if is_binary:
                try:
                    with open(local_path, 'rb') as file_obj:
                        content = file_obj.read()
                    with sftp_client.open(proxmox_tmp_path, 'wb') as remote_file_obj:
                        remote_file_obj.write(content)
                    logger.debug(f"Uploaded binary file to {proxmox_tmp_path} successfully.", extra={'stepname': step})
                except Exception as e:
                    logger.error(f"Error uploading binary {local_path} to {proxmox_tmp_path}: {e}", extra={'stepname': step})
                    sftp_client.close()
                    return False
            else:
                # Handle text file with Jinja2 templating
                try:
                    with open(local_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    template = Template(content)
                    rendered_content = template.render(**dictionary)
                    with sftp_client.open(proxmox_tmp_path, 'w') as remote_file_obj:
                        remote_file_obj.write(rendered_content)
                except Exception as e:
                    logger.error(f"Error uploading text file {local_path} to {proxmox_tmp_path}: {e}", extra={'stepname': step})
                    sftp_client.close()
                    return False

            # Verify existence of /tmp/basename
            try:
                sftp_client.stat(proxmox_tmp_path)
            except IOError as e:
                logger.error(f"Verification failed for {proxmox_tmp_path}: {e}", extra={'stepname': step})
                sftp_client.close()
                return False

            # Create directory inside the lxc
            destination_dir = os.path.dirname(remote_path)
            command         = f"mkdir -p {shlex.quote(destination_dir)}"
            command_lxc     = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"            
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                sftp_client.close() 
                return False       
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})  
        
            # Push the file to the LXC
            command_lxc = f"pct push {container_id} {proxmox_tmp_path} {shlex.quote(remote_path)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                sftp_client.close() 
                return False
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})
                
            # If it's a *.service file, set permissions
            if remote_path.endswith('.service'):
                command     = f"chmod 644 {remote_path}"
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"            
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not success:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                    logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                    logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                    sftp_client.close() 
                    return False
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})
                
            # Check it inside the container
            command     = f"test -f {shlex.quote(remote_path)}"
            command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"            
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                sftp_client.close() 
                return False       
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

            # Remove the temporary file from the Proxmox host
            try:
                sftp_client.remove(proxmox_tmp_path)
            except Exception as e:
                logger.warning(f"Could not remove temporary file {proxmox_tmp_path}: {e}", extra={'stepname': step})

        # Close the SFTP client
        try:
            sftp_client.close()
        except Exception:
            pass

        return True
         
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_upload_folders_or_files(dictionary):
    step = 'proxmox_upload_folders'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        required_keys = ['task_attributes', 'ssh_client']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
            logger.error("Missing SSH client in dictionary", extra={'stepname': step})
            return False

        items = dictionary['task_attributes'].get('folders', [])
        if not items:
            logger.warning("No files/folders specified for upload", extra={'stepname': step})
            return True

        sftp = ssh_client.open_sftp()

        for item in items:
            local_base = os.path.normpath(item['local_folder']).replace('\\', '/')
            remote_base = item['remote_folder'].rstrip('/').replace('\\', '/')
            
            # check if local_base exist
            if not os.path.exists(local_base):
                logger.error(f"Local path not found: {local_base}", extra={'stepname': step})
                return False

            paths_to_verify = []

            if os.path.isfile(local_base):
                logger.info(f"Uploading single file: {local_base}", extra={'stepname': step})
                
                remote_parent = os.path.dirname(remote_base)
                if not proxmox_linux_makedirs(dictionary, remote_parent):
                    logger.error(f"Failed creating parent directory: {remote_parent}", extra={'stepname': step})
                    return False

                try:
                    sftp.put(local_base, remote_base)
                    paths_to_verify.append((local_base, remote_base))
                    logger.info(f"Uploaded single file to: {remote_base}", extra={'stepname': step})
                except Exception as e:
                    logger.error(f"File upload failed: {local_base} - {e}", extra={'stepname': step})
                    return False

            elif os.path.isdir(local_base):
                logger.info(f"Uploading directory: {local_base}", extra={'stepname': step})
                if not proxmox_linux_makedirs(dictionary, remote_base):
                    logger.error(f"Failed creating directory: {remote_base}", extra={'stepname': step})
                    return False

                for root, dirs, files in os.walk(local_base):
                    root = root.replace('\\', '/')
                    for dir_name in dirs:
                        remote_dir = os.path.join(remote_base, os.path.relpath(os.path.join(root, dir_name), local_base)).replace('\\', '/')
                        if not proxmox_linux_makedirs(dictionary, remote_dir):
                            logger.error(f"Failed creating remote subdirectory: {remote_dir}", extra={'stepname': step})
                            return False

                    for file_name in files:
                        local_file = os.path.join(root, file_name).replace('\\', '/')
                        remote_file = os.path.join(remote_base, os.path.relpath(local_file, local_base)).replace('\\', '/')
                        remote_parent = os.path.dirname(remote_file)
                        if not proxmox_linux_makedirs(dictionary, remote_parent):
                            logger.error(f"Failed creating remote parent dir: {remote_parent}", extra={'stepname': step})
                            return False

                        try:
                            sftp.put(local_file, remote_file)
                            paths_to_verify.append((local_file, remote_file))
                            logger.info(f"Uploaded: {local_file} -> {remote_file}", extra={'stepname': step})
                        except Exception as e:
                            logger.error(f"File upload failed: {local_file} - {e}", extra={'stepname': step})
                            return False

            else:
                logger.error(f"Invalid local path: {local_base}", extra={'stepname': step})
                return False

            # Verification step
            for local_path, remote_path in paths_to_verify:
                try:
                    local_size = os.path.getsize(local_path)
                    remote_size = sftp.stat(remote_path).st_size
                    if local_size != remote_size:
                        logger.error(f"Size mismatch after upload: {local_path} ({local_size}) != {remote_path} ({remote_size})", extra={'stepname': step})
                        return False
                    logger.info(f"Verified remote file: {remote_path}", extra={'stepname': step})
                except Exception as e:
                    logger.error(f"Remote file verification failed: {remote_path} - {e}", extra={'stepname': step})
                    return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

    finally:
        if 'sftp' in locals():
            sftp.close()

# ------------------------------------------------------------------------------------------
def proxmox_upload_folders_or_files_lxc(dictionary):
    step = 'proxmox_upload_folders_or_files_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False    
        
         # Retrieve required variables
        required_keys = ['task_attributes', 'ssh_client']
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False   

        # Get ssh_client
        ssh_client = dictionary.get('ssh_client')
        if not ssh_client:
            logger.error("Missing SSH client in dictionary", extra={'stepname': step})
            return False

        # Get container_id
        container_id = dictionary['task_attributes'].get('container_id', '')
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        # Get folders (list of dict items)
        items = dictionary['task_attributes'].get('folders', [])
        if not items:
            logger.warning("No files/folders specified for upload", extra={'stepname': step})
            return True

        # Open an SFTP session on the Proxmox host
        try:
            sftp_client = ssh_client.open_sftp()
        except Exception as e:
            logger.error(f"Failed to open SFTP session: {e}", extra={'stepname': step})
            return False

        # Helper list of extensions to treat as binary
        binary_extensions = [
            '.zip', '.png', '.jpg', '.jpeg', '.gif', '.exe', '.dll',
            '.so', '.bin', '.tar', '.gz', '.bz2', '.xz', '.7z', '.iso',
            '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.webp'
        ]

        def upload_single_file(local_file, remote_path):
            """
            Upload a single file from local_file -> Proxmox:/tmp -> LXC:remote_path
            with optional Jinja2 rendering for text files, then verify inside the container.
            """
            basename         = os.path.basename(local_file)
            proxmox_tmp_path = f"/tmp/{basename}"

            # Remove existing file from /tmp
            try:
                sftp_client.remove(proxmox_tmp_path)
            except IOError:
                pass
            except Exception as e:
                logger.warning(f"Error removing existing file {proxmox_tmp_path}: {e}", extra={'stepname': step})

            # Determine if file is binary or text
            _, ext = os.path.splitext(local_file)
            is_binary = (ext.lower() in binary_extensions)

            # Upload to /tmp with or without Jinja2 templating
            if is_binary:
                # Binary upload
                try:
                    with open(local_file, 'rb') as f:
                        content = f.read()
                    with sftp_client.open(proxmox_tmp_path, 'wb') as remote_file:
                        remote_file.write(content)
                    logger.debug(f"Uploaded binary file to {proxmox_tmp_path}", extra={'stepname': step})
                except Exception as e:
                    logger.error(f"Error uploading binary {local_file} to {proxmox_tmp_path}: {e}", extra={'stepname': step})
                    return False
            else:
                # Text file -> Jinja2
                try:
                    with open(local_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    template         = Template(content)
                    rendered_content = template.render(**dictionary)
                    with sftp_client.open(proxmox_tmp_path, 'w') as remote_file:
                        remote_file.write(rendered_content)
                    logger.debug(f"Uploaded text file (rendered) to {proxmox_tmp_path}", extra={'stepname': step})
                except Exception as e:
                    logger.error(f"Error uploading text file {local_file} to {proxmox_tmp_path}: {e}", extra={'stepname': step})
                    return False

            # Verify existence on Proxmox host
            try:
                sftp_client.stat(proxmox_tmp_path)
            except IOError as e:
                logger.error(f"Verification failed for {proxmox_tmp_path}: {e}", extra={'stepname': step})
                return False

            # Create directory inside the LXC
            destination_dir = os.path.dirname(remote_path)
            command         = f"mkdir -p {shlex.quote(destination_dir)}"
            command_lxc     = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

            # Push the file to the LXC
            command_lxc = f"pct push {container_id} {proxmox_tmp_path} {shlex.quote(remote_path)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

            # If it's *.service, set permissions inside container
            if remote_path.endswith('.service'):
                command     = f"chmod 644 {remote_path}"
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not success:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                    logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                    logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                    return False
                else:
                    logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

            # Verify file inside container
            command     = f"test -f {shlex.quote(remote_path)}"
            command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command_lxc}", extra={'stepname': step})

            # Remove tmp file on Proxmox host
            try:
                sftp_client.remove(proxmox_tmp_path)
            except Exception as e:
                logger.warning(f"Could not remove temporary file {proxmox_tmp_path}: {e}", extra={'stepname': step})

            return True  # Single file success

        # Iterate over each item (file or folder)
        for item in items:
            local_base  = os.path.normpath(item['local_folder'])
            remote_base = item['remote_folder'].rstrip('/').replace('\\', '/')

            # Convert any backslashes in local path to forward slashes
            local_base = local_base.replace('\\', '/')

            if not os.path.exists(local_base):
                logger.error(f"Local path not found: {local_base}", extra={'stepname': step})
                sftp_client.close()
                return False

            # Single file
            if os.path.isfile(local_base):
                logger.info(f"Uploading single file: {local_base}", extra={'stepname': step})
                ok = upload_single_file(local_base, remote_base)
                if not ok:
                    sftp_client.close()
                    return False

            # Directory: recurse
            elif os.path.isdir(local_base):
                logger.info(f"Uploading directory: {local_base}", extra={'stepname': step})
                for root, dirs, files in os.walk(local_base):
                    root = root.replace('\\', '/')
                    for filename in files:
                        local_file = os.path.join(root, filename).replace('\\', '/')
                        # Build the remote path by appending the relative path from local_base
                        rel_path   = os.path.relpath(local_file, local_base).replace('\\', '/')
                        remote_file = os.path.join(remote_base, rel_path).replace('\\', '/')

                        ok = upload_single_file(local_file, remote_file)
                        if not ok:
                            sftp_client.close()
                            return False
            else:
                logger.error(f"Invalid local path: {local_base}", extra={'stepname': step})
                sftp_client.close()
                return False

        # Close SFTP and return success
        sftp_client.close()
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_upload_iso(dictionary):
    step = 'proxmox_upload_iso'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start uload iso...", extra={'stepname': step})
        
        # Retrieve required variables
        required_keys = ['proxmox_iso_dir', 'task_attributes']
        for key in required_keys:
            if not dictionary.get(key):
                logger.error(f"Missing required parameter: {key}", extra={'stepname': step})
                return False    

        iso_dir = dictionary['proxmox_iso_dir'].replace("\\", "/").rstrip("/")
        
        # Get files from nested structure (task_attributes -> vars -> files)
        files = dictionary['task_attributes'].get('vars', {}).get('files', [])
        if not files:
            logger.warning("No ISO files handle missing in dictionary", extra={'stepname': step})
            return True  # Graceful exit

        # Ensure the directory exists on the remote side
        mkdir_cmd = f"mkdir -p '{iso_dir}'"
        mkdir_success, mkdir_err, mkdir_out = proxmox_command(dictionary, mkdir_cmd, step)
        if not mkdir_success:
            logger.error(f"Failed to create remote directory '{iso_dir}': {mkdir_err}", extra={'stepname': step})
            return False

        # Process each file
        for item in files:
            url = item.get('url')
            filename = item.get('name') or os.path.basename(url)
            if not url or not filename:
                logger.error(f"No URL or filename found in 'files' item: {item}", extra={'stepname': step})
                return False

            # Build the path
            destination = f"{iso_dir}/{filename}"

            logger.info(f"Uploading ISO from {url} -> {destination}", extra={'stepname': step})

            # Remote side Wget
            command = f"wget -O '{destination}' '{url}'"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False

            logger.info(f"ISO '{filename}' uploaded successfully.", extra={'stepname': step})

        logger.info("All ISO file(s) have been uploaded successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_upload_image(dictionary):
    step = 'proxmox_upload_image'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retrieve required variables
        required_keys = [
            'proxmox_template_cache_dir',
            'proxmox_download_lxc_version',
            'proxmox_download_lxc_file_ext',
            'proxmox_download_lxc_file',
            'proxmox_download_lxc_url',
            'proxmox_download_lxc_image_name'
        ]
        for key in required_keys:
            if not dictionary.get(key):
                logger.error(f"Missing required parameter: {key}", extra={'stepname': step})
                return False

        proxmox_download_lxc_version    = dictionary.get('proxmox_download_lxc_version')
        proxmox_download_lxc_file_ext   = dictionary.get('proxmox_download_lxc_file_ext')
        proxmox_download_lxc_file       = dictionary.get('proxmox_download_lxc_file')
        proxmox_download_lxc_url        = dictionary.get('proxmox_download_lxc_url')
        proxmox_download_lxc_image_name = dictionary.get('proxmox_download_lxc_image_name')
        image_path                      = f"/tmp/download/{proxmox_download_lxc_file}.{proxmox_download_lxc_file_ext}"
        proxmox_template_cache_dir      = dictionary['proxmox_template_cache_dir'].replace("\\", "/").rstrip("/")
        
        # Finalize: repackage and move to Proxmox template cache
        final_image_path                   = f"{proxmox_template_cache_dir}/{proxmox_download_lxc_image_name}.{proxmox_download_lxc_file_ext}"

        # Download image
        commands = [
            f"mkdir -p /tmp/download",
            f"wget --no-check-certificate -P /tmp/download {proxmox_download_lxc_url}",
            f"test -f {image_path}",
         ]       
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})      


        # Create temp workspace
        command = "mktemp -d /tmp/lxc_patch_XXXXXX"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})      
  
        temp_dir = output.strip()
        logger.info(f"Temp workspace: {temp_dir}", extra={'stepname': step})
        logger.info(f"Patching started ... (wait few minutes)", extra={'stepname': step})
        
        
        # Patching    
        commands = [
            # Extraction
            f"tar -xaf {shlex.quote(image_path)} -C {shlex.quote(temp_dir)} --warning=no-unknown-keyword",

            # Base network config
            f"mkdir -p {shlex.quote(temp_dir)}/etc/network",
            f"echo 'auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp' > {shlex.quote(temp_dir)}/etc/network/interfaces",
            f"chmod 644 {shlex.quote(temp_dir)}/etc/network/interfaces",

            # Remove existing symlink and copy resolv.conf explicitly
            f"rm -f {shlex.quote(temp_dir)}/etc/resolv.conf && cp /etc/resolv.conf {shlex.quote(temp_dir)}/etc/resolv.conf",

            # Device setup
            f"mkdir -p {shlex.quote(temp_dir)}/dev && rm -f {shlex.quote(temp_dir)}/dev/null && mknod -m 666 {shlex.quote(temp_dir)}/dev/null c 1 3",
            f"mkdir -p {shlex.quote(temp_dir)}/dev/pts",
            f"chmod 755 {shlex.quote(temp_dir)}/proc {shlex.quote(temp_dir)}/sys {shlex.quote(temp_dir)}/dev/pts",

            # Mount critical filesystems
            f"mount -t proc proc {shlex.quote(temp_dir)}/proc || echo 'proc mount warning'",
            f"mount -t sysfs sys {shlex.quote(temp_dir)}/sys || echo 'sys mount warning'",
            f"mount -t devpts -o gid=5,mode=620 devpts {shlex.quote(temp_dir)}/dev/pts || echo 'devpts mount warning'",

            # Verify mounts
            f"mountpoint -q {shlex.quote(temp_dir)}/proc || echo 'proc not mounted'",
            f"mountpoint -q {shlex.quote(temp_dir)}/sys || echo 'sys not mounted'",
            f"mountpoint -q {shlex.quote(temp_dir)}/dev/pts || echo 'devpts not mounted'",

            # Apt operations
            f"chroot {shlex.quote(temp_dir)} sh -c 'DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 apt update -y || apt update -y'",
            f"chroot {shlex.quote(temp_dir)} sh -c 'DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 apt install -y --no-install-recommends locales || true'",
            f"chroot {shlex.quote(temp_dir)} sh -c 'DEBIAN_FRONTEND=noninteractive LC_ALL=en_US.UTF-8 apt install -y --no-install-recommends ifupdown net-tools iproute2 || apt install -y --no-install-recommends ifupdown net-tools iproute2'",

            # Unmount
            f"umount -lf {shlex.quote(temp_dir)}/proc || true",
            f"umount -lf {shlex.quote(temp_dir)}/sys || true",
            f"umount -lf {shlex.quote(temp_dir)}/dev/pts || true",

            # Finalize
            f"tar -cvJf {shlex.quote(image_path)}.tmp -C {shlex.quote(temp_dir)} .",
            f"test -f {shlex.quote(temp_dir)}/etc/network/interfaces || (echo 'Missing interfaces file!' && false)",
            f"mv -f {shlex.quote(image_path)}.tmp {shlex.quote(final_image_path)}",
            
            # Cleaning           
            f"rm -rf {shlex.quote(temp_dir)}",
            f"rm -rf /tmp/download",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step}) 

        logger.info(f"Template '{proxmox_download_lxc_image_name}' successfully uploaded and patched.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_merge_files_lxc(dictionary):
    step = "proxmox_merge_files_lxc"

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)         
        merge_files = dictionary['task_attributes'].get('vars', {}).get('merge_files', [])
        if not merge_files:
            logger.warning("No 'merge_files' provided", extra={'stepname': step})
            return True  # No work to do

        # Process each merge item
        for item in merge_files:
            name              = item.get('name')
            local_file        = item.get('local_file')
            remote_file       = item.get('remote_file')
            remote_merge_file = item.get('remote_merge_file')
            set_chmod         = item.get('set_chmod')
            set_chown         = item.get('set_chown')

            if not all([name, local_file, remote_file, remote_merge_file]):
                logger.error(f"Missing parameters for block '{name}'", extra={'stepname': step})
                continue

            # Upload block to remote temp location
            upload_list = [(os.path.normpath(local_file), remote_file)]
            if not proxmox_upload_files_windows_2_lxc(dictionary, upload_list, step):
                logger.error(f"Failed to upload '{local_file}' to '{remote_file}'", extra={'stepname': step})
                return False

            # Ensure parent directory exists
            parent_dir = os.path.dirname(remote_merge_file)
            command = f"mkdir -p {shlex.quote(parent_dir)}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Command failed: {command}", extra={'stepname': step})
                logger.error(f"Output: {output}", extra={'stepname': step})
                logger.error(f"Error: {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

            # Ensure the target file exists
            command = f"touch {remote_merge_file}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Command failed: {command}", extra={'stepname': step})
                logger.error(f"Output: {output}", extra={'stepname': step})
                logger.error(f"Error: {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

            # Backup the target file (non-blocking)
            command = f"cp {remote_merge_file} {remote_merge_file}.bak || true"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"Executed: {command}", extra={'stepname': step})

            # Delete existing block (no-fail if not found)
            command = f"sed -i '/# block_begin: {name}/,/# block_end: {name}/d' {remote_merge_file} || true"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"Executed: {command}", extra={'stepname': step})

            # Append new block
            command = f"cat {remote_file} >> {remote_merge_file}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Command failed: {command}", extra={'stepname': step})
                logger.error(f"Output: {output}", extra={'stepname': step})
                logger.error(f"Error: {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

            # Cleanup temporary files
            cleanup_cmds = [
                f"rm -f {remote_file}",
                f"rm -f {remote_merge_file}.bak"
            ]
            for command in cleanup_cmds:
                proxmox_command_for_lxc(dictionary, command, step)
                logger.info(f"Executed cleanup: {command}", extra={'stepname': step})

            # Set permissions if needed
            if set_chmod and set_chown:
                commands = [ 
                  f"chown {set_chown} {remote_merge_file}",
                  f"chmod {set_chmod} {remote_merge_file}",
                ]  
                for command in commands:  
                    success, error, output = proxmox_command_for_lxc(dictionary, command, step)
                    if not success:
                        logger.error("Failed to execute command:", extra={'stepname': step})
                        logger.error(f"--> command :   '{command}'", extra={'stepname': step})
                        logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                        logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                        return False
                    logger.info(f"Executed: {command}", extra={'stepname': step})


        # Restart services conditionally
        services_to_check = []

        if "prometheus" in remote_merge_file.lower():
            services_to_check.append("prometheus")
        if "pgpass" in remote_merge_file.lower():
            services_to_check.extend(["postgresql", "repmgrd"])

        for service in services_to_check:
        
            # Check if service exists
            command  = f"systemctl list-unit-files | grep -qw {service}.service"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.info(f"Service '{service}' not installed or inactive. Skipping restart.", extra={'stepname': step})
                continue

            # Restart the service
            command = f"systemctl restart {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("Merge operations completed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_package_install_lxc(dictionary, package, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if the package is already installed
        if proxmox_is_package_installed_lxc(dictionary, package):
            logger.info(f"{package} is already installed.", extra={'stepname': step})
            return True

        logger.info(f"Attempting to install {package}...", extra={'stepname': step})      

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

            # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

            # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get install -y {package}",        
        ]        
        
        if package == "cockpit":
            commands.extend([
                "systemctl start cockpit",
                "systemctl enable --now cockpit.socket",
            ])

        # Execute installation commands
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command :   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})
            
        # Verify installation
        command     = f"dpkg -l | grep {package}"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if package not in output:
           return False

        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command :   '{command}'", extra={'stepname': step})
            logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"--> {package} installed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_package_remove_lxc(dictionary, package, step):

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check if the package is already removed
        if not proxmox_is_package_installed_lxc(dictionary, package):
            logger.info(f"{package} is not installed. Nothing to remove.", extra={'stepname': step})
            return True

        logger.info(f"Attempting to remove {package}...", extra={'stepname': step})

        command     = f"apt purge -y {package}"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if success and ('Removing' in output or 'done' in output):
            logger.info(f"{package} removed successfully.", extra={'stepname': step})
            return True
        else:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_get_ip_lxc(dictionary):
    step = 'proxmox_get_ip_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        # First try to get static IP from config
        command = f"cat /etc/pve/lxc/{container_id}.conf | grep -E '^net[0-9]:' | head -n1"
        success, error, output = proxmox_command(dictionary, command, step)
        
        if success and output:
            # Parse network configuration line (e.g., "net0: name=eth0,bridge=vmbr0,ip=192.168.1.100/24")
            ip_match = re.search(r'ip=([\d\.]+/\d+)', output)
            if ip_match:
                ip_address = ip_match.group(1).split('/')[0]
                logger.info(f"Found static IP in config: {ip_address}", extra={'stepname': step})
                return True, ip_address

        # If no static IP found, try to get dynamic IP from container runtime
        command     =  r"ip -4 -o addr show scope global | awk \"{print \$4}\" | cut -d/ -f1 | head -n1"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False       
        logger.info(f"Executed: {command}", extra={'stepname': step})  

        ip_address = output.strip()
        logger.info(f"Found dynamic IP from container: {ip_address}", extra={'stepname': step})
        return True, ip_address        

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_get_name_lxc(dictionary):
    step = 'proxmox_get_name_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        container_id = dictionary['task_attributes'].get('container_id')
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False, None

        # Try to get hostname from Proxmox config
        command = f"grep '^hostname: ' /etc/pve/lxc/{container_id}.conf | cut -d' ' -f2"
        success, error, output = proxmox_command(dictionary, command, step)

        if success:
            name = output.strip()
            if name:
                logger.info(f"Found hostname in config: {name}", extra={'stepname': step})
                return True, name
            else:
                logger.warning("Hostname not found in container config, trying inside container...", extra={'stepname': step})

        # Fallback to getting hostname from container
        command = "hostname"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if success:
            name = output.strip()
            if name:
                logger.info(f"Found hostname from container: {name}", extra={'stepname': step})
                return True, name
            else:
                logger.error("Hostname command returned empty output.", extra={'stepname': step})
                return False, None
        else:
            logger.error("Failed to retrieve hostname from container:", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False, None

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_bind_storage_lxc(dictionary):
    step = 'proxmox_bind_storage_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)             
        container_id = dictionary['task_attributes'].get('container_id')
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        vars         = dictionary['task_attributes'].get('vars', {})
        mount_points = vars.get('mount_points', [])
        if not mount_points:
            logger.warning("No mount points specified for binding", extra={'stepname': step})
            return True

        # Read current container config
        command = f"cat /etc/pve/lxc/{container_id}.conf"
        success, error, existing_config = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to read LXC container configuration", extra={'stepname': step})
            return False

        for mount in mount_points:
            mount_index    = mount.get('mount_point_index')
            host_path      = mount.get('path')
            lxc_mount_path = mount.get('mount_lxc')

            if not all([mount_index, host_path, lxc_mount_path]):
                logger.error("Incomplete mount point configuration.", extra={'stepname': step})
                return False

            mount_entry = f"{mount_index}: {host_path},mp={lxc_mount_path}"

            if mount_entry in existing_config:
                logger.info(f"Storage '{host_path}' already bound at {lxc_mount_path}, skipping.", extra={'stepname': step})
            else:
                # Append mount entry
                command = f"echo '{mount_entry}' >> /etc/pve/lxc/{container_id}.conf"
                success, error, output = proxmox_command(dictionary, command, step)
                if not success:
                    logger.error("Failed to add mount point entry.", extra={'stepname': step})
                    return False

        # Restart container to activate mount points
        commands = [
            f"pct stop {container_id}",
            f"pct start {container_id}",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error(f"Failed to execute '{command}'", extra={'stepname': step})
                logger.error(f"--> output : '{output}'", extra={'stepname': step})
                logger.error(f"--> error  : '{error}'", extra={'stepname': step})
                return False

        logger.info(f"Container {container_id} restarted successfully.", extra={'stepname': step})

        # Explicitly verify if mount directory exists inside LXC
        for mount in mount_points:
            lxc_mount_path = mount.get('mount_lxc')
            if lxc_mount_path:
                command = f"test -d {lxc_mount_path} && ls -ld {lxc_mount_path}"
                success, error, output = proxmox_command_for_lxc(dictionary, command, step)

                if success:
                    logger.info(f"Verified mount directory '{lxc_mount_path}' exists and is accessible.", extra={'stepname': step})
                else:
                    logger.error(f"Mount directory '{lxc_mount_path}' missing or inaccessible in container {container_id}.", extra={'stepname': step})
                    logger.error(f"--> command: '{command}'", extra={'stepname': step})
                    logger.error(f"--> output : '{output}'", extra={'stepname': step})
                    logger.error(f"--> error  : '{error}'", extra={'stepname': step})
                    return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_delete_lxc(dictionary):
    step = 'proxmox_delete_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        container_id = dictionary['task_attributes'].get('container_id')
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        vg_name     = "pve"
        lv_name     = f"vm-{container_id}-disk-0"
        lv_path     = f"/dev/{vg_name}/{lv_name}"
        rootfs_path = f"/var/lib/lxc/{container_id}/rootfs"
        config_path = f"/etc/pve/lxc/{container_id}.conf"

        def execute_cleanup():
            # 1. Immediate forced container destruction
            destroy_cmd = f"pct destroy {container_id} --force --destroy-unreferenced-disks"
            success, error, output = proxmox_command(dictionary, destroy_cmd, step)
            if success:
                return True

            # 2. Comprehensive mount point cleanup
            # Find all mounts related to container
            find_mounts = [
                f"findmnt -R -o TARGET -n -S {lv_path}",
                f"findmnt -R -o TARGET -n -S {rootfs_path}",
                f"findmnt -R -o TARGET -n /var/lib/lxc/{container_id}"
            ]
            
            all_mounts = set()
            for cmd in find_mounts:
                _, _, mounts = proxmox_command(dictionary, cmd, step)
                if mounts:
                    all_mounts.update(mounts.strip().split('\n'))

            # Unmount in reverse order (child mounts first)
            for mount in reversed(sorted(all_mounts)):
                umount_cmd = f"umount -fl {mount}"
                proxmox_command(dictionary, umount_cmd, step)

            # 3. Kernel-level resource cleanup
            cleanup_sequence = [
                # Flush page cache, dentries and inodes
                f"sync; echo 3 > /proc/sys/vm/drop_caches",
                
                # Remove device mapper entries
                f"dmsetup remove -f {lv_name} || true",
                
                # Force LV deactivation
                f"lvchange -an --yes {lv_path} || true",
                
                # Wipe filesystem signatures
                f"wipefs -a {lv_path}",
                
                # Remove block device references
                f"blockdev --flushbufs {lv_path}",
                
                # Final LV removal
                f"lvremove --force --yes {lv_path}"
            ]

            for cmd in cleanup_sequence:
                success, error, output = proxmox_command(dictionary, cmd, step)
                if not success:
                    logger.warning(f"Cleanup command failed: {cmd}", extra={'stepname': step})
                    logger.warning(f"Error: {error}", extra={'stepname': step})

            # 4. Configuration cleanup
            proxmox_command(dictionary, f"rm -f {config_path}", step)
            proxmox_command(dictionary, f"rm -rf /var/lib/lxc/{container_id}", step)

            # Final verification
            check_cmd = f"lvs {lv_path} >/dev/null 2>&1; echo $?"
            _, _, exists = proxmox_command(dictionary, check_cmd, step)
            return exists.strip() != "0"

        # Execute cleanup with retries
        for attempt in range(4):
            logger.info(f"Attempt {attempt+1}/4 to destroy container {container_id}", extra={'stepname': step})
            if execute_cleanup():
                logger.info(f"Container {container_id} successfully removed", extra={'stepname': step})
                return True
            time.sleep(2)

        logger.error(f"Failed to destroy container {container_id} after 4 attempts", extra={'stepname': step})
        return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fix_timezone_lxc(dictionary):
    step = 'proxmox_fix_timezone_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'proxmox_timezone',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        proxmox_timezone     = dictionary.get('proxmox_timezone') 
        
        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id         = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False
 
        # ----------  install package inside the container ----------
        if not proxmox_package_install_lxc(dictionary, 'tzdata', step):
           return False
 
        # ----------  fix timezone inside the container    ----------
        commands = [ 
            # set timezone (use timedatectl if available, else classic method)
            f"timedatectl set-timezone {proxmox_timezone} || true",
            f"ln -sf /usr/share/zoneinfo/{proxmox_timezone} /etc/localtime",
            f"echo '{proxmox_timezone}' > /etc/timezone",
            
            # regenerate /etc/timezone data non-interactively
            "dpkg-reconfigure -f noninteractive tzdata || true"
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # ---------- success ----------
        logger.info(f"--> Container {container_id} – timezone set to {proxmox_timezone}.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_create_lxc(dictionary):
    step = 'proxmox_create_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'proxmox_timezone',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        proxmox_timezone     = dictionary.get('proxmox_timezone') 
        
        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id         = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        # ---------- remove pre-existing CT, if any ----------
        if proxmox_is_lxc_exist(dictionary):
            logger.warning(f"Container {container_id} already exists", extra={'stepname': step})
            if not proxmox_delete_lxc(dictionary):
                logger.error("Failed to remove existing container", extra={'stepname': step})
                return False
            # Verify removal
            for _ in range(3):
                if not proxmox_is_lxc_exist(dictionary):
                    break
                time.sleep(2)
            else:
                logger.error("Container still exists after deletion", extra={'stepname': step})
                return False

        # ---------- create ----------
        command = proxmox_build_pct_create_command(dictionary)
        if not command:
            logger.error("Failed to build create command", extra={'stepname': step})
            return False          

        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})
 
        # ---------- wait until CT is reachable ----------
        for _ in range(5):
            if proxmox_is_lxc_exist(dictionary) and proxmox_is_lxc_access(dictionary):
                break
            time.sleep(5)
        else:
            logger.error("Container validation timeout", extra={'stepname': step})
            return False

        # ---------- apply custom config lines ----------
        if not proxmox_lxc_custom_config(dictionary):
            return False 


        logger.info(f"Container {container_id} created and ready to start.", extra={'stepname': step})
        return True 
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_lxc_custom_config(dictionary):
    step = 'proxmox_lxc_custom_config'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        container_id = dictionary['task_attributes'].get('container_id')
        if not container_id:
            logger.error("container_id provided.", extra={'stepname': step})
            return False        

        task_vars        = dictionary['task_attributes'].get('vars', {})
        lxc_custom_lines = task_vars.get('lxc_custom_lines', [])


        # If user provided a multiline string, split it
        if isinstance(lxc_custom_lines, str):
            lxc_custom_lines = [ln.strip() for ln in lxc_custom_lines.splitlines() if ln.strip()]

        # If no lines, skip
        if not isinstance(lxc_custom_lines, list) or not lxc_custom_lines:
            logger.info("No custom LXC config lines to apply, skipping.", extra={'stepname': step})
            return True

        # Backup container config
        conf_path   = f"/etc/pve/lxc/{container_id}.conf"
        backup_path = f"/etc/pve/lxc/{container_id}.conf.bak"
        backup_cmd  = f"cp {conf_path} {backup_path}"
        success, error, output = proxmox_command(dictionary, backup_cmd, step)
        if not success:
            logger.error(f"Failed backing up {conf_path} to {backup_path}", extra={'stepname': step})
            logger.error(f"Output: {output}", extra={'stepname': step})
            logger.error(f"Error : {error}", extra={'stepname': step})
            return False
        logger.info(f"Backed up {conf_path} -> {backup_path}", extra={'stepname': step})

        # Append lines exactly as they are
        lines_str = "\n".join(lxc_custom_lines)

        # We'll do a heredoc append
        script_to_run = f"""cat <<'EOAPPEND' >> {conf_path}
{lines_str}
EOAPPEND
"""

        success, error, output = proxmox_command(dictionary, script_to_run, step)
        if not success:
            logger.error("Failed appending lines to LXC config", extra={'stepname': step})
            logger.error(f"Command: {script_to_run}", extra={'stepname': step})
            logger.error(f"Output : {output}", extra={'stepname': step})
            logger.error(f"Error  : {error}", extra={'stepname': step})
            return False

        logger.info(f"Appended lines:\n{lines_str}", extra={'stepname': step})

        # Stop/Start container so changes take effect
        reboot_cmd = f"pct stop {container_id} && pct start {container_id}"
        success, error, output = proxmox_command(dictionary, reboot_cmd, step)
        if not success:
            logger.error(f"Failed to reboot container {container_id}", extra={'stepname': step})
            logger.error(f"Output : {output}", extra={'stepname': step})
            logger.error(f"Error  : {error}", extra={'stepname': step})
            return False

        logger.info(f"Rebooted container {container_id}, new lines should be active.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_build_pct_create_command(dictionary):
    step = 'proxmox_build_pct_create_command'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)             

        # Extract container_id
        container_id = dictionary['task_attributes'].get('container_id')
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return None

        task_vars = dictionary['task_attributes'].get('vars', {})

        # Build base command from user vars
        ostemplate = task_vars.get('os', {}).get('ostemplate')
        if not ostemplate:
            logger.error("'ostemplate' specified in 'os' block.", extra={'stepname': step})
            return None

        cmd = ['pct', 'create', str(container_id), ostemplate]

        # Hostname
        hostname = task_vars.get('hostname')
        if hostname:
            cmd.extend(['--hostname', hostname])

        # Password
        password = task_vars.get('password')
        if password:
            cmd.extend(['--password', password])

        # Memory / swap
        memory = task_vars.get('memory', 4096)
        swap   = task_vars.get('swap', 1024)
        cmd.extend(['--memory', str(memory), '--swap', str(swap)])

        # CPU cores
        cores = task_vars.get('cores')
        if cores:
            cmd.extend(['--cores', str(cores)])

        # Networking
        network = task_vars.get('network')
        if network:
            net_params = [
                f"name={network.get('name', 'eth0')}",
                f"bridge={network.get('bridge', 'vmbr0')}",
                f"firewall={1 if network.get('firewall', False) else 0}",
            ]
            ip = network.get('ip')
            if ip:
                net_params.append(f"ip={ip}")

            tag = network.get('tag')
            if tag is not None:
                net_params.append(f"tag={tag}")

            gateway = network.get('gateway')
            if gateway:
                net_params.append(f"gw={gateway}")

            cmd.extend(['--net0', ','.join(net_params)])

        # Storage
        storage = task_vars.get('storage', {}).get('rootfs')
        if storage:
            size_str    = storage.get('size', '10G')  # e.g. '10G'
            storage_name = storage.get('storage', 'local-lvm')
            storage_str  = f"{storage_name}:{size_str}"
            cmd.extend(['--rootfs', storage_str])

        # Advanced options
        advanced = task_vars.get('advanced', {})
        # Onboot
        onboot = advanced.get('onboot', True)
        cmd.extend(['--onboot', '1' if onboot else '0'])

        # Startup
        startup = advanced.get('startup', {})
        if startup:
            startup_params = []
            if 'order' in startup:
                startup_params.append(f"order={startup['order']}")
            if 'up_delay' in startup:
                startup_params.append(f"up={startup['up_delay']}")
            if 'down_delay' in startup:
                startup_params.append(f"down={startup['down_delay']}")
            if startup_params:
                cmd.extend(['--startup', ','.join(startup_params)])

        # Features
        features = advanced.get('features')
        if features:
            features_str = ','.join([f"{k}={v}" for k, v in features.items()])
            cmd.extend(['--features', features_str])

        return ' '.join(cmd)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_local_install_lxc(dictionary):
    step = 'proxmox_local_install_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 

        # Get container_id from nested structure (task_attributes -> vars -> container_id)
        container_id = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        # Configure locale non-interactively
        commands = [
            "apt-get update",
            "apt-get -y install locales locales-all debconf",
            "sed -i '/en_US.UTF-8 UTF-8/s/^# //g' /etc/locale.gen",
            "/usr/sbin/locale-gen en_US.UTF-8",
            "/usr/sbin/update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8",
            "echo 'LANG=en_US.UTF-8' >> /etc/default/locale",
            "echo 'LC_ALL=en_US.UTF-8' >> /etc/default/locale",
            "export LANG=en_US.UTF-8",
            "export LC_ALL=en_US.UTF-8",
            "source /etc/default/locale || true"
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : '{output}'", extra={'stepname': step})
                logger.error(f"--> error  : '{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info(f"locale configured.", extra={'stepname': step})
        return True               

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_remove(dictionary):
    step = 'proxmox_fail2ban_remove'

    try:
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Removing existing 'fail2ban' ...", extra={'stepname': step})

        commands = [
            "systemctl stop fail2ban || true",
            "systemctl disable fail2ban || true",
            "apt-get -y purge fail2ban || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",
            "rm -rf /etc/fail2ban",          # configuration files
            "rm -rf /var/log/fail2ban",      # log files
            "systemctl daemon-reload",
        ]

        # Optionally remove the group. If you'd rather keep the group,
        # comment this out or skip it.
        commands.append("getent group fail2ban && groupdel fail2ban || true")

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("Fail2ban removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_install(dictionary):
    step = 'proxmox_fail2ban_install'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Remove any existing installation first
        if not proxmox_fail2ban_remove(dictionary):
            logger.error("Fail2ban removal was unsuccessful.", extra={'stepname': step})
            return False

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
 
             # Install paclkage
            "apt-get -y install fail2ban",
 
            # Auto-create the fail2ban group if the package didn't do so
            "getent group fail2ban || groupadd fail2ban",
            "systemctl enable fail2ban",
            
            # Some distros might not have /var/log/auth.log by default
            "touch /var/log/auth.log",
            "chmod 640 /var/log/auth.log",
            "sleep 5",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("Fail2ban installed successfully.", extra={'stepname': step})

        if not proxmox_fail2ban_tuning(dictionary):
            return False
            
        if not proxmox_fail2ban_up(dictionary):
            return False
            
        if not proxmox_fail2ban_status(dictionary):
            return False
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_tuning(dictionary):
    step = 'proxmox_fail2ban_tuning'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'fail2ban_proxmox_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Upload configuration files in proxmox server
        files_to_upload = []
        for item in dictionary.get('fail2ban_proxmox_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not upload_files_windows_2_linux(dictionary, files_to_upload, step):
                logger.error("Failed to upload configuration files.", extra={'stepname': step})
                return False
    
        # Restart to take effect
        commands = [
            "systemctl daemon-reload",
            "systemctl restart fail2ban",
            "sleep 5"
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
            
        logger.info("'fail2ban' tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_up(dictionary):
    step = 'proxmox_fail2ban_up'

    try:    
        service = 'fail2ban'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Basic checks
        checks  = [
            # Service is running
            {
                'command':     f"systemctl is-active {service}",
                'success':      "active",
                'error':       f"{service} service not active",
                'description': f"Check {service} service status",
            },
            # Service is enabled on boot
            {
                'command':     f"systemctl is-enabled {service}",
                'success':      "enabled",
                'error':       f"{service} service not enabled",
                'description': f"Check {service} service is enabled",
            },
            # Configuration file exists
            {
                'command':     "test -f /etc/fail2ban/jail.conf",
                'success':      "",
                'error':       "jail.conf configuration file not found",
                'description': "Check presence of jail.conf file",
            },
            # Client reports overall status
            {
                'command':     "fail2ban-client status proxmox",
                'success':      "Status for the jail: proxmox",
                'error':       "fail2ban-client status check failed",
                'description': "Check fail2ban-client overall status",
            },
            # SSHd jail is active
            {
                'command':     "fail2ban-client status sshd",
                'success':      "Status for the jail: sshd",
                'error':       "sshd jail not active",
                'description': "Check sshd jail status",
            },
            # Firewall rules contain fail2ban chain (iptables)
            {
                # Group the commands so the shell runs them fully and returns the output even if the first grep fails
                'command':      "sh -c '(iptables -L -n 2>/dev/null | grep f2b-sshd) || (nft list ruleset 2>/dev/null | grep f2b-sshd)'",
                'success':      "f2b-sshd",
                'error':        "No fail2ban chain found in iptables or nftables",
                'description':  "Check firewall for fail2ban chain",
                # This tells your check logic not to fail automatically if the return code is non-zero.
                # Instead, you rely on searching 'f2b-sshd' in the output to determine success/fail.
                'allow_nonzero': True
            }
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_status(dictionary):
    step = 'proxmox_fail2ban_status'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
    
        # Restart to take effect
        commands = [
            "fail2ban-client status sshd",
            "fail2ban-client status proxmox",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"status: \n {output}", extra={'stepname': step})           

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_clamav_remove(dictionary):
    step = 'proxmox_clamav_remove'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Removing existing 'ClamAV' ...", extra={'stepname': step})

        commands = [
            # Stop and disable the daemon services
            "systemctl stop clamav-daemon || true",
            "systemctl disable clamav-daemon || true",
            "systemctl stop clamav-freshclam || true",
            "systemctl disable clamav-freshclam || true",

            # Remove packages
            "apt-get -y purge clamav clamav-daemon clamav-freshclam libclamav* || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",

            # Remove configuration directories and files
            "rm -rf /etc/clamav",    # ClamAV config files
            "rm -rf /var/lib/clamav",# ClamAV virus database
            
            "systemctl daemon-reload",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("ClamAV removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_clamav_install(dictionary):
    step = 'proxmox_clamav_install'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # First remove any existing ClamAV
        if not proxmox_clamav_remove(dictionary):
            logger.error("ClamAV removal was unsuccessful.", extra={'stepname': step})
            return False

        logger.info("Installing 'ClamAV' ...", extra={'stepname': step})
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
            
            "apt install -y clamav clamav-daemon clamav-freshclam clamdscan",

            # Stop the daemon so we can run `freshclam` manually without file-lock conflicts
            "systemctl stop clamav-freshclam || true",
            
            "mkdir -p /var/log/clamav",
            "touch /var/log/clamav/freshclam.log",
            "chown clamav:clamav /var/log/clamav",
            "chown clamav:clamav /var/log/clamav/freshclam.log",
            "chmod 755 /var/log/clamav",
            "chmod 640 /var/log/clamav/freshclam.log",

            "freshclam",  # Update the virus database without the daemon interfering

            # Restart & enable services
            "systemctl restart clamav-freshclam",
            "systemctl restart clamav-daemon",
            "systemctl enable clamav-daemon",
            "systemctl enable clamav-freshclam",

            "sleep 5",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("ClamAV installed successfully.", extra={'stepname': step})

        # If you have a proxmox_clamav_tuning function for custom config, call it here:
        if not proxmox_clamav_tuning(dictionary):
           return False

        # Validate that ClamAV is up
        if not proxmox_clamav_up(dictionary):
           return False

        # Show status
        if not proxmox_clamav_status(dictionary):
           return False
        
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_clamav_tuning(dictionary):
    step = 'proxmox_clamav_tuning'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'clamav_proxmox_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False       
   
        # If you need to upload custom ClamAV config files, do so here.
        # Example: dictionary.get('clamav_proxmox_configs') might be a list of dicts
        # that specify local/remote config paths.
        files_to_upload = []
        for item in dictionary.get('clamav_proxmox_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not upload_files_windows_2_linux(dictionary, files_to_upload, step):
                logger.error("Failed to upload configuration files.", extra={'stepname': step})
                return False

        # Create the quarantine folder and set ownership/permissions
        quarantine_path = dictionary.get('clamav_quarantine', '/var/lib/clamav/quarantine')

        # We'll collect all needed commands into one list to run in order
        commands = [
            # Create quarantine folder if it doesn't exist
            f"mkdir -p {shlex.quote(quarantine_path)}",
            # Assign to user/group clamav
            f"chown clamav:clamav {shlex.quote(quarantine_path)}",
            # Restrict permissions to something appropriate (e.g. 750)
            f"chmod 750 {shlex.quote(quarantine_path)}",
        ]

        # Restart ClamAV so config changes (if any) take effect
        #
        commands += [
            "systemctl daemon-reload",
            "systemctl restart clamav-freshclam",
            "systemctl restart clamav-daemon",
            "sleep 5",
        ]
        
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("'ClamAV' tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_clamav_up(dictionary):
    step = 'proxmox_clamav_up'

    try:
        service = 'clamav'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
    
        # Prepare EICAR test string
        eicar_test_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"    

        # Basic checks for clamav-daemon and freshclam
        checks = [
            {
                'command':     "systemctl is-active clamav-daemon",
                'success':     "active",
                'error':       "clamav-daemon service not active",
                'description': "Check clamav-daemon service status",
            },
            {
                'command':     "systemctl is-enabled clamav-daemon",
                'success':     "enabled",
                'error':       "clamav-daemon service not enabled",
                'description': "Check clamav-daemon service is enabled",
            },
            {
                'command':     "test -f /usr/bin/clamscan",
                'success':     "",
                'error':       "/usr/bin/clamscan not found",
                'description': "Check presence of clamscan binary",
            },
            {
                'command':     "clamscan --version",
                'success':     "ClamAV",
                'error':       "clamscan version check failed",
                'description': "Check clamscan version output",               
            },
            {
                'command':     f"echo -n '{eicar_test_string}' | tee /tmp/eicar.txt > /dev/null",
                'success':     "",  # no specific success substring
                'error':       "Failed to upload a test virus in /tmp",
                'description': "Upload a test virus in /tmp",
            },
            {
                'command':     "sleep 2",
                'success':     "",
                'error':       "Failed to wait for 2 seconds to ensure file is written",
                'description': "Wait for 2 seconds to ensure file is written"
            },
            {
                'command':     "test -f /tmp/eicar.txt",
                'success':     "",  
                'error':       "Failed to verify EICAR file exist",
                'description': "Verify EICAR file exists"
            },
            {
                # Adjust clamdscan if your config file is somewhere else
                # or if you need a specific socket param:
                'command':     "clamdscan /tmp/eicar.txt --config-file=/etc/clamav/clamd.conf --log=/var/log/clamav/clamdscan.log",
                'success':     "Infected files: 1",  # We'll verify output for "Infected files: 1"
                'error':       "Failed to scan a test virus with clamdscan",
                'description': "Scanning a test virus with clamdscan",
            },           
            {
                # Clean up EICAR test file
                'command':     "rm -f /tmp/eicar.txt",
                'success':     "",
                'error':       "Failed to clean EICAR test file",
                'description': "Cleaning up EICAR test file",
            }        
            
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue
            else:
                logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_clamav_status(dictionary):
    step = 'proxmox_clamav_status'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        commands = [
            "clamscan --version",
            "systemctl status clamav-daemon",
            "systemctl status clamav-freshclam",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"status: \n {output}", extra={'stepname': step})

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_firewall(dictionary):
    step = 'proxmox_firewall'

    try:
        # 1) Ensure SSH is connected
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            return False

        # 2) Check we have task_attributes
        if 'task_attributes' not in dictionary:
            logger.error("Missing 'task_attributes' in dictionary", extra={'stepname': step})
            return False

        # 3) Grab relevant data
        container_id   = dictionary['task_attributes'].get('container_id', '').strip()
        fw_opts        = dictionary['task_attributes'].get('vars', {}).get('firewall_options', {})
        firewall_rules = dictionary['task_attributes'].get('vars', {}).get('firewall_rules', [])

        # Validate firewall_rules is a list
        if not isinstance(firewall_rules, list):
            logger.error("'firewall_rules' must be a list of strings.", extra={'stepname': step})
            return False

        # Convert "Yes/No" to 1/0 or appropriate strings for the [OPTIONS] section
        firewall_enabled = 1 if fw_opts.get('firewall','No').lower() == 'yes' else 0
        dhcp_val         = 1 if fw_opts.get('dhcp','No').lower() == 'yes' else 0
        ndp_val          = 1 if fw_opts.get('ndp','No').lower() == 'yes' else 0
        radv_val         = 1 if fw_opts.get('radv','No').lower() == 'yes' else 0
        macfilter_val    = 1 if fw_opts.get('macfilter','No').lower() == 'yes' else 0
        ipfilter_val     = 1 if fw_opts.get('ipfilter','No').lower() == 'yes' else 0
        log_in           = fw_opts.get('log_level_in','nolog')
        log_out          = fw_opts.get('log_level_out','nolog')
        policy_in        = fw_opts.get('policy_in','ACCEPT').upper()
        policy_out       = fw_opts.get('policy_out','ACCEPT').upper()

        #
        # Distinguish LXC vs Host
        #
        if container_id:
            # (A) LXC
            # Verify container exists
            command = f"pct status {container_id}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error(f"Container {container_id} does not exist or is inaccessible.", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False

            # If firewall=Yes, set net0: firewall=1
            if firewall_enabled == 1:
                command = f"pct config {container_id}"
                success, error, output = proxmox_command(dictionary, command, step)
                if not success:
                    logger.error("Failed to read container config.", extra={'stepname': step})
                    logger.error(f"--> command:   {command}", extra={'stepname': step})
                    logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                    logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                    return False

                net0_match = re.search(r'^net0:\s*(.*)$', output, re.MULTILINE)
                if not net0_match:
                    logger.error(f"No 'net0' config found for container {container_id}; cannot set firewall=1.", extra={'stepname': step})
                    return False

                net0_config = net0_match.group(1).strip()
                if 'firewall=' not in net0_config.lower():
                    if not net0_config.endswith(','):
                        net0_config += ','
                    net0_config += 'firewall=1'
                else:
                    net0_config = re.sub(r'firewall=\d', 'firewall=1', net0_config, flags=re.IGNORECASE)

                command = f"pct set {container_id} --net0 \"{net0_config}\""
                success, error, out2 = proxmox_command(dictionary, command, step)
                if not success:
                    logger.error("Failed to enable firewall=1 on net0", extra={'stepname': step})
                    logger.error(f"--> command:   {command}", extra={'stepname': step})
                    logger.error(f"--> output  : '{out2}'", extra={'stepname': step})
                    logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                    return False
                else:
                    logger.info(f"net0 => firewall=1 for container {container_id}", extra={'stepname': step})

            fw_file_path = f"/etc/pve/firewall/{container_id}.fw"

        else:
            # (B) Host firewall
            logger.info("No container_id => managing the Proxmox host firewall.", extra={'stepname': step})
            if firewall_enabled == 1:
                command = "pve-firewall enable"
                success, error, output = proxmox_command(dictionary, command, step)
                if not success:
                    logger.error("Failed to enable firewall on the host", extra={'stepname': step})
                    logger.error(f"--> command:   {command}", extra={'stepname': step})
                    logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                    logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                    return False
                else:
                    logger.info("Host firewall is now enabled.", extra={'stepname': step})
            else:
                logger.info("Host firewall=No, skipping 'pve-firewall enable'.", extra={'stepname': step})

            fw_file_path = "/etc/pve/firewall/host.fw"

        #
        # Read existing .fw file
        #
        command = f"cat {fw_file_path}"
        success, error, fw_current = proxmox_command(dictionary, command, step)
        if not success:
            logger.warning(f"{fw_file_path} not found; will create from scratch.", extra={'stepname': step})
            fw_current = ""

        #
        # We'll remove all [OPTIONS] content from our prior block
        # Then remove the entire [RULES] content so we don't see duplicates in the GUI.
        #
        # Then we rebuild [OPTIONS] and [RULES].
        #
        # 1) Remove old custom [OPTIONS] block
        fw_cleaned = remove_block(fw_current, "# block_begin: my_fw_options", "# block_end: my_fw_options")
        # 2) Remove entire [RULES] section content
        fw_cleaned = clear_rules_section(fw_cleaned)

        # Ensure [OPTIONS] and [RULES] stubs exist
        if "[OPTIONS]" not in fw_cleaned:
            fw_cleaned += "\n[OPTIONS]\n"
        if "[RULES]" not in fw_cleaned:
            fw_cleaned += "\n[RULES]\n"
        if not fw_cleaned.endswith("\n"):
            fw_cleaned += "\n"

        # Build new [OPTIONS] lines from firewall_options
        # They are placed in a block between # block_begin: my_fw_options ... # block_end: my_fw_options
        options_block = [
            "# block_begin: my_fw_options",
            "# Managed automatically; do not edit manually",
            f"enable: {firewall_enabled}",
            f"policy_in: {policy_in}",
            f"policy_out: {policy_out}",
            f"dhcp: {dhcp_val}",
            f"ndp: {ndp_val}",
            f"radv: {radv_val}",
            f"macfilter: {macfilter_val}",
            f"ipfilter: {ipfilter_val}",
            f"log_level_in: {log_in}",
            f"log_level_out: {log_out}",
            "# block_end: my_fw_options"
        ]

        # Build new [RULES] lines
        # We'll just store them all in a single block, but the entire [RULES] content has been cleared, so no duplicates remain.
        rules_block = [
            "# block_begin: my_fw_rules",
            "# Managed automatically; do not edit manually"
        ]
        for rule_line in firewall_rules:
            rule_line = re.sub(r'(?<!-)-dport', '--dport', rule_line.strip(), flags=re.IGNORECASE)
            rule_line = re.sub(r'(?<!-)-sport', '--sport', rule_line, flags=re.IGNORECASE)
            if rule_line:
                rules_block.append(rule_line)
        rules_block.append("# block_end: my_fw_rules")

        # Insert the options block after [OPTIONS] heading
        fw_after_options = insert_block_in_section(
            fw_cleaned,
            section='OPTIONS',
            lines=options_block
        )

        # Insert the rules block after [RULES] heading
        final_fw = insert_block_in_section(
            fw_after_options,
            section='RULES',
            lines=rules_block
        )

        # Write final_fw to .fw file
        temp_file = f"/tmp/{'host_fw' if not container_id else container_id}.fw.tmp"
        escaped = final_fw.replace("'", "'\"'\"'")
        command = (
            f"cat > '{temp_file}' <<'EOF'\n{escaped}\nEOF\n"
            f"mv '{temp_file}' '{fw_file_path}'\n"
        )
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to update firewall file", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        else:
            logger.info(f"Wrote new firewall config to {fw_file_path}", extra={'stepname': step})

        # Compile
        command = "pve-firewall compile"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("pve-firewall compile failed", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        else:
            logger.info("pve-firewall compile done.", extra={'stepname': step})

        logger.info(f"Firewall updated in {fw_file_path} with no duplicated rules.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def remove_block(content, begin_marker, end_marker):
    """
    Removes any lines between begin_marker and end_marker, inclusive.
    Returns the updated content with a trailing newline.
    """
    pattern = re.compile(
        f"{re.escape(begin_marker)}.*?{re.escape(end_marker)}",
        flags=re.DOTALL
    )
    new_content = re.sub(pattern, "", content).rstrip("\n")
    return new_content + "\n"

# ------------------------------------------------------------------------------------------
def clear_rules_section(file_content):
    """
    Remove *all* lines in the [RULES] section.
    This ensures we don't see duplicates in the GUI if the user had pre-existing lines.
    We'll keep the "[RULES]" heading, but empty everything until the next [SECTION] or EOF.
    """
    # 1) locate [RULES]
    # 2) then remove everything until next [SOMETHING] or end of file
    pattern = re.compile(r'(\[RULES\]\s*\n)(.*?)(?=\[[A-Z]+\]|$)', flags=re.DOTALL | re.IGNORECASE)
    def replacer(match):
        # match.group(1) is the "[RULES]\n"
        # match.group(2) is everything until next bracket or EOF
        # we return just the heading with no content
        return match.group(1)

    new_content = re.sub(pattern, replacer, file_content)
    return new_content

# ------------------------------------------------------------------------------------------
def insert_block_in_section(file_content, section, lines):
    """
    Insert the given 'lines' (list of strings) right after the [section] heading.
    If the heading isn't found, just append at the end.
    """
    if not file_content.endswith("\n"):
        file_content += "\n"

    pattern = re.compile(rf"(\[{re.escape(section)}\]\s*\n)", re.IGNORECASE)
    match = pattern.search(file_content)
    if not match:
        # If [section] not found, append
        return file_content + "\n".join(lines) + "\n"

    insert_index = match.end()
    before = file_content[:insert_index]
    after  = file_content[insert_index:]
    return before + "\n".join(lines) + "\n" + after

# ------------------------------------------------------------------------------------------
def proxmox_firewall_up(dictionary):
    step = "proxmox_firewall_up"
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        if 'task_attributes' not in dictionary:
            logger.error("Missing 'task_attributes' in dictionary", extra={'stepname': step})
            return False

        # 2) Grab test scenarios
        firewall_tests = dictionary['task_attributes'].get('vars', {}).get('firewall_tests', [])
        if not firewall_tests:
            logger.info("No firewall_tests specified; nothing to do.", extra={'stepname': step})
            return True

        if not isinstance(firewall_tests, list):
            logger.error("'firewall_tests' must be a list of dictionaries.", extra={'stepname': step})
            return False

        overall_success = True

        # 3) For each test, attempt a netcat check from Proxmox host
        for test in firewall_tests:
            test_name  = test.get('name', 'Unnamed Test')
            dest_ip    = test.get('ip', '')
            dest_port  = test.get('port', '')
            expect_str = test.get('expect', '').lower().strip()  # "allow" or "block"

            logger.info(f"Running firewall test: {test_name}", extra={'stepname': step})

            # Basic validation
            if not dest_ip or not dest_port or expect_str not in ['allow','block']:
                logger.error(f"Invalid test scenario: {test}", extra={'stepname': step})
                overall_success = False
                continue

            # We'll attempt netcat: "nc -vz -w 5 IP PORT"
            # -w 5 => 5s timeout
            # success => connection allowed, else blocked
            command = f"nc -vz -w 5 {dest_ip} {dest_port}"
            success, error, output = proxmox_command(dictionary, command, step)

            # netcat exit code 0 => success => connection allowed
            # netcat exit code != 0 => refused or blocked
            connection_allowed = success

            # Compare with 'expect'
            if expect_str == 'allow' and connection_allowed:
                # Good
                logger.info(f"[PASS] {test_name}: Connection to {dest_ip}:{dest_port} is allowed as expected.", extra={'stepname': step})
            elif expect_str == 'block' and not connection_allowed:
                # Good
                logger.info(f"[PASS] {test_name}: Connection to {dest_ip}:{dest_port} is blocked as expected.", extra={'stepname': step})
            else:
                # Mismatch => fail
                logger.error(f"[FAIL] {test_name}: Connection to {dest_ip}:{dest_port} was "
                             f"{'ALLOWED' if connection_allowed else 'BLOCKED'}, "
                             f"but we expected {expect_str.upper()}.", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                overall_success = False

        return overall_success

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_backup(dictionary):
    step = 'proxmox_backup'

    try:
        logger.info("Backup process started …", extra={'stepname': step})

        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retrieve & validate play-book variables
        vars_section               = dictionary.get('task_attributes', {}).get('vars', {})
        required_keys              = (
            'proxmox_vm_ids',
            'proxmox_archive',
            'proxmox_backup_mode',
            'proxmox_backup_compress',
        )
        for key in required_keys:
            if not vars_section.get(key):
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False

        proxmox_archive            = vars_section['proxmox_archive']
        proxmox_vm_ids             = vars_section['proxmox_vm_ids']
        proxmox_backup_mode        = vars_section.get('proxmox_backup_mode', 'snapshot')
        proxmox_backup_compress    = vars_section.get('proxmox_backup_compress', 'zstd')
        proxmox_backup_exclude     = vars_section.get('proxmox_backup_exclude', '')

        # ───────────────────────────────────────────────────────────────
        # Ensure the archive directory exists on the Proxmox host
        # ───────────────────────────────────────────────────────────────
        command = f"test -d '{proxmox_archive}' || mkdir -p '{proxmox_archive}'"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error(f"Failed to ensure archive directory exists: {proxmox_archive}", extra={'stepname': step})
            logger.error(f"--> command :    '{command}'", extra={'stepname': step})
            logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
            return False

        # ──────────────────────────────────────────────────────────────────────
        # Iterate over every VM/CT
        # ──────────────────────────────────────────────────────────────────────
        for vmid in proxmox_vm_ids:
            command               = (
                f"vzdump {vmid} --mode {proxmox_backup_mode} "
                f"--compress {proxmox_backup_compress} --dumpdir '{proxmox_archive}'"
            )
            if proxmox_backup_exclude:
                command          += f" --exclude-path '{proxmox_backup_exclude}'"

            logger.info(f"Backup vmid: {vmid} started …", extra={'stepname': step})
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : {command}", extra={'stepname': step})
                logger.error(f"--> output  :\n{output}", extra={'stepname': step})
                logger.error(f"--> error   :\n{error}",  extra={'stepname': step})

                proxmox_pushgateway_notify({
                    **dictionary,
                    'task_attributes': {'vars': {
                        'metric_name':         'backup_status',
                        'metric_value':        0,
                        'job_name':            'proxmox_backup',
                        'labels':              {'vm_id': str(vmid)},
                        'pushgateway_delay':   15,
                        'wait_for_prometheus': True,
                        'delete_after_push':   False,
                    }},
                })
                return False

        # ──────────────────────────────────────────────────────────────────────
        # Success path – push one record per VM plus global record
        # ──────────────────────────────────────────────────────────────────────
        logger.info("All selected VM/LXC backed up successfully.",
                    extra={'stepname': step})

        for vmid in proxmox_vm_ids:
            proxmox_pushgateway_notify({
                **dictionary,
                'task_attributes': {'vars': {
                    'metric_name':         'backup_status',
                    'metric_value':        1,
                    'job_name':            'proxmox_backup',
                    'labels':              {'vm_id': str(vmid)},
                    'pushgateway_delay':   15,
                    'wait_for_prometheus': False,
                    'delete_after_push':   False,
                }},
            })

        proxmox_pushgateway_notify({
            **dictionary,
            'task_attributes': {'vars': {
                'metric_name':         'backup_status',
                'metric_value':        1,
                'job_name':            'proxmox_backup',
                'labels':              {},          # global series
                'pushgateway_delay':   15,
                'wait_for_prometheus': True,
                'delete_after_push':   False,
            }},
        })

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_restore(dictionary):
    step = 'proxmox_restore'

    try:
        # Log start
        logger.info("Restore process started …", extra={'stepname': step})

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(
                f"SSH client: {dictionary.get('ssh_client')}",
                extra={'stepname': step}
            )
            return False

        # Retrieve & validate play-book variables
        vars_section = dictionary.get('task_attributes', {}).get('vars', {})
        required_keys = (
            'proxmox_restore_files',
            'proxmox_archive',
            'proxmox_restore_storage',
        )
        for key in required_keys:
            if vars_section.get(key) in (None, '', []):
                logger.error(f"Missing or empty parameter: {key}", extra={'stepname': step})
                return False

        proxmox_restore_files   = vars_section['proxmox_restore_files']
        proxmox_archive         = vars_section['proxmox_archive']
        proxmox_restore_storage = vars_section['proxmox_restore_storage']
        proxmox_restore_force   = vars_section.get('proxmox_restore_force', False)

        # Iterate over every backup file to restore
        for backup_file in proxmox_restore_files:
            backup_full_path = f"{proxmox_archive}/{backup_file}"

            # Check file exists
            command = f"test -f '{backup_full_path}'"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error(
                    f"Backup file '{backup_full_path}' not found.",
                    extra={'stepname': step}
                )
                return False

            # Decide LXC vs QEMU
            if backup_file.startswith("vzdump-lxc-"):
                vmid = backup_file.split('-')[2]

                # Stop running container if needed
                command = f"pct status {vmid}"
                success, error, output = proxmox_command(dictionary, command, step)
                if success and "status: running" in output:
                    proxmox_command(dictionary, f"pct stop {vmid}", step)

                                # Cleanup old disks on the target storage (ignore any errors)
                for idx in (0, 1):
                    lv_name = f"{proxmox_restore_storage}/vm-{vmid}-disk-{idx}"
                    dev = f"/dev/{lv_name}"
                    proxmox_command(dictionary, f"umount {dev}", step)
                    proxmox_command(dictionary, f"fuser -km {dev}", step)
                    proxmox_command(dictionary, f"lvremove -f {lv_name}", step)

                # Prepare restore command for LXC
                command = (
                    f"pct restore {vmid} '{backup_full_path}' "
                    f"--storage {proxmox_restore_storage}"
                )
                if proxmox_restore_force:
                    command += " --force"

            elif backup_file.startswith("vzdump-qemu-"):
                vmid = backup_file.split('-')[2]

                # Stop running VM if needed
                command = f"qm status {vmid}"
                success, error, output = proxmox_command(dictionary, command, step)
                if success and "status: running" in output:
                    proxmox_command(dictionary, f"qm stop {vmid}", step)

                # Prepare restore command for QEMU
                command = (
                    f"qmrestore '{backup_full_path}' {vmid} "
                    f"--storage {proxmox_restore_storage}"
                )
                if proxmox_restore_force:
                    command += " --force"

            else:
                logger.error(f"Unknown backup format: {backup_file}", extra={'stepname': step})
                return False

            # Execute restore
            logger.info(f"Restore vmid: {vmid} started …", extra={'stepname': step})
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute restore command.", extra={'stepname': step})
                logger.error(f"--> command : {command}", extra={'stepname': step})
                logger.error(f"--> error   :\n{error}", extra={'stepname': step})

                # Push failure metric
                proxmox_pushgateway_notify({
                    **dictionary,
                    'task_attributes': {'vars': {
                        'metric_name': 'restore_status',
                        'metric_value': 0,
                        'job_name': 'proxmox_restore',
                        'labels': {'vm_id': str(vmid)},
                        'pushgateway_delay': 15,
                        'wait_for_prometheus': True,
                        'delete_after_push': False,
                    }}
                })
                return False

            # Start VM/CT
            if backup_file.startswith("vzdump-lxc-"):
                proxmox_command(dictionary, f"pct start {vmid}", step)
            else:
                proxmox_command(dictionary, f"qm start {vmid}", step)

            # Push success metric
            proxmox_pushgateway_notify({
                **dictionary,
                'task_attributes': {'vars': {
                    'metric_name': 'restore_status',
                    'metric_value': 1,
                    'job_name': 'proxmox_restore',
                    'labels': {'vm_id': str(vmid)},
                    'pushgateway_delay': 15,
                    'wait_for_prometheus': False,
                    'delete_after_push': False,
                }}
            })

        # Global success metric
        proxmox_pushgateway_notify({
            **dictionary,
            'task_attributes': {'vars': {
                'metric_name': 'restore_status',
                'metric_value': 1,
                'job_name': 'proxmox_restore',
                'labels': {},
                'pushgateway_delay': 15,
                'wait_for_prometheus': True,
                'delete_after_push': False,
            }}
        })

        logger.info(
            "All restore operations completed and started successfully.",
            extra={'stepname': step}
        )
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_pve_exporter_remove(dictionary):
    step = 'proxmox_pve_exporter_lxc_remove'
    
    try:
        logger.info("Start remove...", extra={'stepname': step})
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'pve_exporter_user_for_service',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        pve_exporter_user_for_service   = dictionary.get('pve_exporter_user_for_service')

        # Allow apt-get purge to fail if package is absent
        commands = [
            "systemctl stop pve_exporter || true",
            "systemctl disable pve_exporter || true",

            "apt-get -y purge pve_exporter || true",
            "apt-get -y autoremove",
            "apt-get -y clean",

            "rm -rf /opt/pve-exporter",
            "rm -rf /etc/pve-exporter",
            "rm -f /etc/systemd/system/pve_exporter.service",

            f"deluser --remove-home {pve_exporter_user_for_service} || true",
            
            "systemctl daemon-reload",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("pve-exporter and all related traces removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pve_exporter_install(dictionary):
    step = 'proxmox_pve_exporter_lxc_install'
    
    try:
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'pve_exporter_user_for_service',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        pve_exporter_user_for_service   = dictionary.get('pve_exporter_user_for_service')

        # Remove any existing installation
        if not proxmox_pve_exporter_remove(dictionary):
            logger.error("'prometheus pve_exporter' not removed successfully.", extra={'stepname': step})
            return False

        logger.info("Start install...", extra={'stepname': step}) 

        # Order apt-get update before upgrade
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
            
            "apt-get install -y wget tar curl jq",

            f"id -u {pve_exporter_user_for_service} >/dev/null 2>&1 || useradd -r -s /bin/false {pve_exporter_user_for_service}",
            "mkdir -p /opt/pve-exporter",
            "mkdir -p /opt/pve-exporter/bin",
            "mkdir -p /etc/pve-exporter",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Install Python & pip packages in a virtual environment
        commands = [
            "apt-get clean all",
            "apt-get -y update",
            "apt-get -y upgrade",
            
            # Install the required Python package
            "apt-get install -y python3 python3-venv python3-pip",
            
            # Create virtualenv and install in it directly
            "python3 -m venv /opt/pve-exporter",
            "/opt/pve-exporter/bin/pip install --upgrade pip",              # always good practice
            "/opt/pve-exporter/bin/pip install prometheus-pve-exporter"          
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("'prometheus-pve-exporter' installed.", extra={'stepname': step})

        # Continue with tuning and final checks
        if not proxmox_pve_exporter_tuning(dictionary):
            return False
        if not proxmox_pve_exporter_up(dictionary):
            return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pve_exporter_tuning(dictionary):
    step = 'proxmox_pve_exporter_lxc_tuning'

    try:
        logger.info("Start tuning...", extra={'stepname': step})   
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'pve_exporter_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        pve_exporter_user_for_service   = dictionary.get('pve_exporter_user_for_service')
        
        service                         = 'pve-exporter'
        
        # Upload custom configs in lxc
        files_to_upload = []
        for item in dictionary.get('pve_exporter_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not upload_files_windows_2_linux(dictionary, files_to_upload, step):
                logger.error("Failed to upload pve_exporter_configs files.", extra={'stepname': step})
                return False

        commands = [
          
           # Enable and start
            "systemctl daemon-reload",
           f"systemctl enable {service}",
           f"systemctl start {service}",
            "sleep 5",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False 
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

                
        logger.info(f"{service} tuning completed", extra={'stepname': step})
        return True           
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pve_exporter_up(dictionary):
    step = 'pve_exporter_lxc_up'

    try:
        logger.info("Starting health checks...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        service = 'pve-exporter'
        
        # Basic checks  
        checks  = [
            {
                'command':     f"systemctl is-active {service}",
                'success':     "active",
                'error':       f"{service} service not active",
                'description': f"Check {service} service up and running",
            },
            {
                'command':     "curl -sI -k -X GET http://localhost:9221/metrics | head -n1",
                'success':     "200 OK",
                'error':       f"{service} not responding on 9221",
                'description': f"Check {service} web access",
            },
            {
                'command':     "ss -lntp | grep 9221",
                'success':     "9221",
                'error':       f"{service} is not listening to TCP port 9221",
                'description': f"Verify that {service} is listening to TCP port 9221",
            },
            {
                'command':     "curl --silent http://127.0.0.1:9221/metrics",
                'success':     "python_gc_objects_collected_total",
                'error':       f"{service} no send metrics",
                'description': f"Verify that {service} sends metrics",
            },
            {
                'command':     "curl --silent http://127.0.0.1:9221/pve",
                'success':     "pve_up",
                'error':       f"{service} no send information",
                'description': f"Verify that {service} sends information on pve",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command:    '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_node_exporter_remove(dictionary):
    step = 'proxmox_node_exporter_remove'

    try:
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

         # Check required keys
        required_keys = [ 
            'node_exporter_user_for_service',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)    
        node_exporter_user_for_service = dictionary.get('node_exporter_user_for_service')

        commands = [
            "systemctl stop    node-exporter || true",
            "systemctl disable node-exporter || true",
            "rm -f  /etc/systemd/system/node-exporter.service",
            "rm -rf /etc/systemd/system/node-exporter.service.d",
            "rm -rf /opt/node-exporter",
            f"deluser --remove-home {node_exporter_user_for_service} || true",
            "systemctl daemon-reload",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'",  extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("node-exporter removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_node_exporter_install(dictionary):
    step = 'proxmox_node_exporter_install'

    try:
        
        logger.info("Installing node-exporter ...", extra={'stepname': step})
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Remove any existing exporter
        if not proxmox_node_exporter_remove(dictionary):
            logger.error("'node‑exporter' not removed successfully.", extra={'stepname': step})
            return False

         # Check required keys
        required_keys = [ 
            'node_exporter_user_for_service',
            'node_exporter_download_url',
            'node_exporter_textfile_dir',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary) 
        node_exporter_download_url     = dictionary.get('node_exporter_download_url')
        node_exporter_user_for_service = dictionary.get('node_exporter_user_for_service')
        node_exporter_textfile_dir     = dictionary.get('node_exporter_textfile_dir')

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
            
            "apt-get -y install wget tar curl",

            # Create user and directories
            f"id -u {node_exporter_user_for_service} >/dev/null 2>&1 || useradd -r -s /bin/false {node_exporter_user_for_service}",
            "mkdir -p /opt/node_exporter",
            f"mkdir -p {node_exporter_textfile_dir}",

            "mkdir -p /opt/node-exporter",
            "mkdir -p /opt/node-exporter/bin",
            "mkdir -p /etc/node-exporter",

            # Download and install binary
           f"wget {node_exporter_download_url} -O /tmp/node_exporter.tar.gz",
            "tar -xzf /tmp/node_exporter.tar.gz -C /opt/node-exporter/bin --strip-components=1",
            "chmod +x /opt/node-exporter/bin/",
            f"chown -R {node_exporter_user_for_service}:{node_exporter_user_for_service} /opt/node-exporter",
            f"chown -R {node_exporter_user_for_service}:{node_exporter_user_for_service} {node_exporter_textfile_dir}",
            
             "rm -f /tmp/node_exporter.tar.gz",    
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'",  extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("Binary installed.", extra={'stepname': step})

        # tuning
        if not proxmox_node_exporter_tuning(dictionary):
            return False
            
        # check    
        if not proxmox_node_exporter_up(dictionary):
            return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_node_exporter_tuning(dictionary):
    step = 'proxmox_node_exporter_tuning'

    try:
        logger.info("Start tuning...", extra={'stepname': step})       
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'node_exporter_user_for_service',
            'node_exporter_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        node_exporter_user_for_service = dictionary.get('node_exporter_user_for_service')
        service                        = 'node-exporter'
        
        # Upload any config files the user specified
        files_to_upload = []
        for item in dictionary.get('node_exporter_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not upload_files_windows_2_linux(dictionary, files_to_upload, step):
                logger.error("Failed to upload node_exporter_configs files.", extra={'stepname': step})
                return False

        commands = [            
           # Enable and start
            "systemctl daemon-reload",
           f"systemctl enable {service}",
           f"systemctl start {service}",
            "sleep 5",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"{service} tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_node_exporter_up(dictionary):
    step = 'proxmox_node_exporter_up'

    try:
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        service = 'node-exporter'
        checks  = [
            {
                'command':     f"systemctl is-active {service}",
                'success':     "active",
                'error':       f"{service} not active",
                'description': "service running",
            },
            {
                'command':     "curl -sI -X GET http://localhost:9100/metrics | head -n1",
                'success':     "200 OK",
                'error':       f"{service} no HTTP 200",
                'description': "endpoint /metrics",
            },
            {
                'command':     "ss -lntp | grep 9100",
                'success':     "9100",
                'error':       f"{service} not listening",
                'description': "port 9100",
            },
            {
                'command':     "curl --silent http://127.0.0.1:9100/metrics",
                'success':     "node_cpu_seconds_total",
                'error':       f"{service} metrics missing",
                'description': "metrics stream",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command(dictionary, check['command'], step)
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Command:   '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output : \n'{output}'", extra={'stepname': step})
                overall_success = False
            else:
                logger.info(f"OK: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("Some health checks failed.", extra={'stepname': step})
            command = f"systemctl status {service}"
            success, error, output = proxmox_command(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_exporter_remove(dictionary):
    step = 'proxmox_fail2ban_exporter_remove'

    try:
        logger.info("Start remove...", extra={'stepname': step})
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'fail2ban_exporter_user_for_service',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        fail2ban_exporter_user_for_service = dictionary.get('fail2ban_exporter_user_for_service')

        commands = [
            "systemctl stop fail2ban_exporter || true",
            "systemctl disable fail2ban_exporter || true",
            
            "rm -rf /opt/fail2ban-exporter",
            "rm -f  /etc/systemd/system/fail2ban-exporter.service",           

            f"deluser --remove-home {fail2ban_exporter_user_for_service} || true",
            
            "systemctl daemon-reload",
        ]

        for cmd in commands:
            success, error, output = proxmox_command(dictionary, cmd, step)
            if not success:
                logger.error("Failed to execute command.", extra={'stepname': step})
                logger.error(f"--> command: \n'{cmd}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'",  extra={'stepname': step})
                return False

        logger.info("'fail2ban_exporter' removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_exporter_install(dictionary):
    step = 'proxmox_fail2ban_exporter_install'
    
    # from https://salsa.debian.org/go-team/packages/fail2ban-prometheus-exporter
    
    try:
        logger.info("Installing fail2ban-exporter...", extra={'stepname': step})       
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Ensure Fail2ban is installed
        required_packages = ['fail2ban']
        for pkg in required_packages:
            if not proxmox_is_package_installed(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Remove any existing exporter
        if not proxmox_fail2ban_exporter_remove(dictionary):
            logger.error("Previous fail2ban_exporter not removed successfully.", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'fail2ban_exporter_user_for_service',
            'fail2ban_exporter_download_url',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        fail2ban_exporter_download_url     = dictionary.get('fail2ban_exporter_download_url')
        fail2ban_exporter_user_for_service = dictionary.get('fail2ban_exporter_user_for_service')
        
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
            
            "apt-get install -y wget tar curl jq",

            # Create user and directories
            f"id -u {fail2ban_exporter_user_for_service} >/dev/null 2>&1 || useradd -r -s /bin/false {fail2ban_exporter_user_for_service}",
            "mkdir -p /opt/fail2ban-exporter",
            "mkdir -p /opt/fail2ban-exporter/bin",
            "mkdir -p /etc/fail2ban-exporter",

            # Download and install binary
           f"wget {fail2ban_exporter_download_url} -O /tmp/fail2ban_exporter.tar.gz",
            "tar -xzf /tmp/fail2ban_exporter.tar.gz -C /opt/fail2ban-exporter/bin/",
            "chmod +x /opt/fail2ban-exporter/bin/",
            
            "rm -f /tmp/fail2ban_exporter.tar.gz",            
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("Binary installed.", extra={'stepname': step})

        # tuning
        if not proxmox_fail2ban_exporter_tuning(dictionary):
            return False
            
        # check
        if not proxmox_fail2ban_exporter_up(dictionary):
            return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_exporter_tuning(dictionary):
    step = 'proxmox_fail2ban_exporter_lxc_tuning'

    try:
        logger.info("Start tuning...", extra={'stepname': step})       
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Ensure Fail2ban is installed
        required_packages = ['fail2ban']
        for pkg in required_packages:
            if not proxmox_is_package_installed(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Check required keys
        required_keys = [
            'fail2ban_exporter_user_for_service',
            'fail2ban_exporter_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        fail2ban_exporter_user_for_service = dictionary.get('fail2ban_exporter_user_for_service')
        service                         = 'fail2ban-exporter'
        
        # Upload any config files the user specified
        files_to_upload = []
        for item in dictionary.get('fail2ban_exporter_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not upload_files_windows_2_linux(dictionary, files_to_upload, step):
                logger.error("Failed to upload fail2ban_exporter_configs files.", extra={'stepname': step})
                return False


        commands = [            
           # Enable and start
            "systemctl daemon-reload",
           f"systemctl enable {service}",
           f"systemctl start {service}",
            "sleep 5",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"{service} tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_fail2ban_exporter_up(dictionary):
    step = 'proxmox_fail2ban_exporter_lxc_up'

    try:
        service = 'fail2ban-exporter'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Ensure Fail2ban is installed
        required_packages = ['fail2ban']
        for pkg in required_packages:
            if not proxmox_is_package_installed(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Starting check...", extra={'stepname': step})

        checks = [
            {
                'command':     f"systemctl is-active {service}",
                'success':     "active",
                'error':       f"{service} service not active",
                'description': f"Check {service} service up and running",
            },
            {
                'command':     "curl -sI -k -X GET http://localhost:9191/metrics | head -n1",
                'success':     "200 OK",
                'error':       f"{service} not responding on 9191",
                'description': f"Check {service} web access",
            },
            {
                'command':     "ss -lntp | grep 9191",
                'success':     "9191",
                'error':       f"{service} is not listening on TCP port 9191",
                'description': f"Verify that {service} is listening on TCP port 9191",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_exporter_remove_lxc(dictionary):
    step = 'nginx_prometheus_exporter_remove'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Start remove ...", extra={'stepname': step})

        commands = [        
            "systemctl stop nginx-exporter.service || true",
            "systemctl disable nginx-exporter.service || true",

            "rm -rf /opt/nginx-exporter",
            "rm -f /etc/systemd/system/nginx-exporter.service",           

            "systemctl daemon-reload",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("--> nginx-prometheus-exporter removed.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_exporter_install_lxc(dictionary):
    step = 'nginx_prometheus_exporter_install'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_exporter_download_url',
            'nginx_exporter_download_file',
            'nginx_exporter_download_file_ext',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        nginx_exporter_download_url      = dictionary.get('nginx_exporter_download_url')
        nginx_exporter_download_file     = dictionary.get('nginx_exporter_download_file')
        nginx_exporter_download_file_ext = dictionary.get('nginx_exporter_download_file_ext')
        
        service                          = 'nginx-exporter'
        
        # Remove old installation first
        if not proxmox_nginx_exporter_remove_lxc(dictionary):
            logger.error("'nginx-exporter' not removed successfully.", extra={'stepname': step})
            return False
            
        # Check if required packages are installed
        required_packages = ['nginx']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False 

        logger.info(f"{service} installation starting ...", extra={'stepname': step})

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
            
            "apt-get install -y wget tar curl jq",
            
            # Download and extract the exporter binary
            "mkdir -p /tmp/download",
            f"wget -P /tmp/download {nginx_exporter_download_url}",
            f"tar xzf /tmp/download/{nginx_exporter_download_file}.{nginx_exporter_download_file_ext} -C /tmp/download",
              
            "mkdir -p /opt/nginx-exporter/bin",                       
            f"mv /tmp/download/nginx-prometheus-exporter /opt/nginx-exporter/bin/",
            "chmod +x /opt/nginx-exporter/bin/nginx-prometheus-exporter",
            
            "rm -rf /tmp/download",            
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        # Tuning
        if not proxmox_nginx_exporter_tuning_lxc(dictionary):
            return False
            
        if not proxmox_nginx_exporter_up_lxc(dictionary):
            return False
            
        # Check
        if not proxmox_nginx_exporter_up_lxc(dictionary):
            return False
            
        # Status
        if not proxmox_service_status_lxc(dictionary, service):
           return False
           
        logger.info(f"--> {service} installed and running.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_exporter_tuning_lxc(dictionary):
    step = 'nginx_prometheus_exporter_tuning'
    
    try:
        logger.info("Start tuning...", extra={'stepname': step})      
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_exporter_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        service  = 'nginx-exporter'

        # Upload configuration files on the proxmox server
        files_to_upload = []
        for item in dictionary.get('nginx_exporter_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload grafana configuration files.", extra={'stepname': step})
                return False

        commands = [
            "systemctl daemon-reload",
           f"systemctl enable {service}.service",
           f"systemctl start {service}.service",
            "sleep 5",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"--> {service} tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_nginx_exporter_up_lxc(dictionary):
    step = 'proxmox_nginx_exporter_up_lxc'
    
    try:
        logger.info("Starting health checks...", extra={'stepname': step})        
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Ensure required packages are installed
        required_packages = ['nginx']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        service = 'nginx-exporter'

        # Health checks
        checks = [
            {
                'command':     f"systemctl status nginx",
                'success':      "active (running)", 
                'error':       f"nginx is not running",
                'description': f"Check: NGINX is up and running",
            },  
            {
                'command':      "curl -L --head http://localhost",
                'success':      "200 OK", 
                'error':        "Nginx not serving localhost",
                'description':  "Check: NGINX is serving  http://localhost",
            },
            {
                'command':      "curl -L --get http://127.0.0.1/stub_status",
                'success':      "Active connections", 
                'error':        "Nginx is not configured properly stub_status not respond",
                'description':  "Check: NGINX is serving  http://localhost/stub_status.",
            },
            {
                'command':     f"systemctl status {service}",
                'success':      "active (running)", 
                'error':       f"{service} is not running",
                'description': f"Check: {service} is up and running",
            },
            {
                'command': "curl -sI -k -X GET http://127.0.0.1:9113/metrics | head -n1",
                'success': "200 OK",
                'error': f"{service} not expose http://127.0.0.1:9113/metrics",
                'description': f"Check {service} expose http://127.0.0.1:9113/metrics",
            },
            {
                'command': "ss -lntp | grep 9113",
                'success': "9113",
                'error': f"{service} is not listening to TCP port 9113",
                'description': f"Verify {service} is listening on TCP port 9113",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # Allow non-zero exit code if no output and flag set
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error: \n {error}", extra={'stepname': step})
                logger.error(f"--> Command: \n {check['command']}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"Executed: {command}", extra={'stepname': step})
            logger.info(f"--> output: '{output}'", extra={'stepname': step})
            logger.info(f"--> error: '{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_exporter_remove_lxc(dictionary):
    step = 'pgsql_exporter_remove'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
       
        logger.info("Start removal...", extra={'stepname': step})

        # Build the commands list
        commands = [
            "systemctl stop pgsql-exporter.service || true",
            "systemctl disable pgsql-exporter.service || true",
            "rm -rf /opt/postgres-exporter",
            "rm -f /etc/systemd/system/pgsql-exporter.service",
            
            "systemctl daemon-reload"
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("pgsql-exporter removed.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_exporter_install_lxc(dictionary):
    step = 'pgsql_exporter_install'

    try:   
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'pgsql_exporter_download_version',
            'pgsql_exporter_download_url',
            'pgsql_exporter_download_file',
            'pgsql_exporter_download_file_ext',
            'pgsql_exporter_user_for_service',
            'pgsql_exporter_group_for_service',
            'pgsql_server_version',            
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary) 
        pgsql_exporter_download_version  = dictionary.get('pgsql_exporter_download_version')
        pgsql_exporter_download_url      = dictionary.get('pgsql_exporter_download_url')
        pgsql_exporter_download_file     = dictionary.get('pgsql_exporter_download_file')
        pgsql_exporter_download_file_ext = dictionary.get('pgsql_exporter_download_file_ext')
        pgsql_exporter_group_for_service = dictionary.get('pgsql_exporter_group_for_service')
        pgsql_exporter_user_for_service  = dictionary.get('pgsql_exporter_user_for_service')

        pgsql_server_version            = dictionary.get('pgsql_server_version')
        service_postgresql_server       = f"postgresql@{pgsql_server_version}-main"       
        package_postgresql_server       = f"postgresql-{pgsql_server_version}"

        service                         = 'postgres-exporter'
        
        # Ensure required packages are installed
        required_packages = [package_postgresql_server]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Remove any previous installation
        if not proxmox_pgsql_exporter_remove_lxc(dictionary):
            logger.error("'pgsql-exporter' was not removed successfully.", extra={'stepname': step})
            return False
    
        logger.info("Start install...", extra={'stepname': step})    
                
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",
            
            "apt-get install -y wget tar curl",
            
            "mkdir -p /tmp/download",
            
            # Use --no-check-certificate to bypass the certificate hostname issue
            f"wget --no-check-certificate -P /tmp/download {pgsql_exporter_download_url}",
            f"tar xzf /tmp/download/{pgsql_exporter_download_file}.{pgsql_exporter_download_file_ext} -C /tmp/download",
            "mkdir -p /opt/postgres-exporter",
            "mkdir -p /opt/postgres-exporter/bin",
                        
            # Rename the binary to match the service file's ExecStart
            f"mv /tmp/download/{pgsql_exporter_download_file}/postgres_exporter /opt/postgres-exporter/bin/postgres-exporter",
            "chmod +x /opt/postgres-exporter/bin/postgres-exporter",
        ]

        commands.append("mkdir -p /etc/pgsql-exporter")
        commands.append("rm -rf /tmp/download")

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Tuning
        if not proxmox_pgsql_exporter_tuning_lxc(dictionary):
            return False

        # Check            
        if not proxmox_pgsql_exporter_up_lxc(dictionary):
            return False

        # Status
        if not proxmox_service_status_lxc(dictionary, service):
           return False

        logger.info(f"--> {service} installed and running.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_exporter_tuning_lxc(dictionary):
    step = 'pgsql_exporter_tuning'
    
    try:
        logger.info("Start tuning...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'pgsql_server_version',
            'pgsql_exporter_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
                
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        service_postgresql_server = f"postgresql@{pgsql_server_version}-main"       
        package_postgresql_server = f"postgresql-{pgsql_server_version}"

        service                   = 'postgres-exporter'
        
        # Ensure required packages are installed
        required_packages = [package_postgresql_server]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Upload configuration files defined in pgsql_exporter_configs
        files_to_upload = []
        for item in dictionary.get('pgsql_exporter_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload configuration files.", extra={'stepname': step})
                return False

        commands = [
            "systemctl daemon-reload",
           f"systemctl enable {service}.service",
           f"systemctl start {service}.service",
            "sleep 5",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"--> {service} tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_exporter_up_lxc(dictionary):
    step = 'pgsql_exporter_up'
    
    try:
        logger.info("Starting health checks...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'pgsql_server_version',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
                
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        service_postgresql_server = f"postgresql@{pgsql_server_version}-main"       
        package_postgresql_server = f"postgresql-{pgsql_server_version}"

        service                   = 'postgres-exporter'
        
        # Ensure required packages are installed
        required_packages = [package_postgresql_server]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False
        
        # Define health checks with expected outcomes
        checks = [
            {
                'command':     f"systemctl status  {service_postgresql_server}",
                'success':      "active (running)",
                'error':       f"{service_postgresql_server} is not running",
                'description': f"Check if {service_postgresql_server} is up and running",
            },
            {
                'command': f"systemctl is-active {service}",
                'success': "active",
                'error': f"{service} service not active",
                'description': f"Check {service} up and running",
            },
            {
                'command': "curl -sI -k -X GET http://localhost:9187/metrics | head -n1",
                'success': "200 OK",
                'error': f"{service} not responding on 9187",
                'description': f"Check {service} web access",
            },
            {
                'command': "ss -lntp | grep 9187",
                'success': "9187",
                'error': f"{service} is not listening to TCP port 9187",
                'description': f"Verify {service} is listening on TCP port 9187",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error: {error}", extra={'stepname': step})
                logger.error(f"--> Command: {check['command']}", extra={'stepname': step})
                logger.error(f"--> Output: {output}", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"Executed: {command}", extra={'stepname': step})
            logger.info(f"--> output: '{output}'", extra={'stepname': step})
            logger.info(f"--> error: '{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_fpm_exporter_remove_lxc(dictionary):
    step = 'php_fpm_prometheus_exporter_remove'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Start remove ...", extra={'stepname': step})

        commands = [        
            "systemctl stop php-fpm-exporter.service || true",
            "systemctl disable php-fpm-exporter.service || true",

            "rm -rf /opt/php-fpm-exporter",
            "rm -f /etc/systemd/system/php-fpm-exporter.service",           

            "systemctl daemon-reload",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("--> php-fpm-prometheus-exporter removed.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_fpm_exporter_install_lxc(dictionary):
    step = 'php_fpm_prometheus_exporter_install'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'php_version',
            'php_fpm_exporter_download_url',
            'php_fpm_exporter_download_file',
            'php_fpm_exporter_download_file_ext',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)
        php_fpm_exporter_download_url      = dictionary.get('php_fpm_exporter_download_url')
        php_fpm_exporter_download_file     = dictionary.get('php_fpm_exporter_download_file')
        php_fpm_exporter_download_file_ext = dictionary.get('php_fpm_exporter_download_file_ext')
        php_version                        = dictionary.get('php_version')
        service                            = 'php-fpm-exporter'

        # Check if required packages are installed
        php                                = f"php{php_version}"
        php_fpm                            = f"php{php_version}-fpm"

        required_packages = ['nginx', php, php_fpm]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Remove old installation first
        if not proxmox_php_fpm_exporter_remove_lxc(dictionary):
            logger.error("--> php-fpm-exporter not removed successfully.", extra={'stepname': step})
            return False
            
        logger.info(f"{service} installation starting ...", extra={'stepname': step})

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get install -y wget tar curl jq",
            
            # Download and extract the exporter binary
            "mkdir -p /tmp/download",
            f"wget -P /tmp/download {php_fpm_exporter_download_url}",
            f"tar xzf /tmp/download/{php_fpm_exporter_download_file}.{php_fpm_exporter_download_file_ext} -C /tmp/download",

            "mkdir -p /opt/php-fpm-exporter/bin",                       
            f"mv /tmp/download/php-fpm_exporter /opt/php-fpm-exporter/bin/",
            "chmod +x /opt/php-fpm-exporter/bin/php-fpm_exporter",
            
            "rm -rf /tmp/download",            
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        # Tuning
        if not proxmox_php_fpm_exporter_tuning_lxc(dictionary):
            return False
            
        # Check            
        if not proxmox_php_fpm_exporter_up_lxc(dictionary):
            return False

        # Status
        if not proxmox_service_status_lxc(dictionary, service):
           return False

        logger.info(f"--> {service} installed and running.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_fpm_exporter_tuning_lxc(dictionary):
    step = 'php_fpm_prometheus_exporter_tuning'
    
    try:
        logger.info("Start tuning...", extra={'stepname': step})      
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'php_version',
            'php_fpm_exporter_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        php_version           = dictionary.get('php_version')
        service               = 'php-fpm-exporter'   
        
        # Check if required packages are installed
        php     = f"php{php_version}"
        php_fpm = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Upload configuration files on the proxmox server
        files_to_upload = []
        for item in dictionary.get('php_fpm_exporter_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload php_fpm_exporter_configs configuration files.", extra={'stepname': step})
                return False

        commands = [
            "systemctl daemon-reload",
           f"systemctl enable {service}.service",
           f"systemctl start {service}.service",
            "sleep 5",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"--> {service} tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_php_fpm_exporter_up_lxc(dictionary):
    step = 'proxmox_php_fpm_exporter_up_lxc'
    
    try:
        logger.info("Starting health checks...", extra={'stepname': step})        
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'php_version',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        php_version           = dictionary.get('php_version')
        
        # Check if required packages are installed
        php               = f"php{php_version}"
        php_fpm           = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        service = 'php-fpm-exporter'

        # Health checks
        checks = [
            {
                'command':     f"systemctl status nginx",
                'success':      "active (running)", 
                'error':       f"nginx is not running",
                'description': f"Check: nginx is up and running",
            },
            {
                'command':     f"systemctl status {php_fpm}",
                'success':      "active (running)", 
                'error':       f"{php_fpm} is not running",
                'description': f"Check: {php_fpm} is up and running",
            },  
            {
                'command':      "curl -L --head http://localhost",
                'success':      "200 OK", 
                'error':        "php-fpm not serving localhost",
                'description':  "Check: php-fpm is serving  http://localhost",
            },
            {
                'command': "curl -sI -k -X GET http://127.0.0.1/php_fpm_status | head -n1",
                'success': "200 OK",
                'error': f"{service} not expose http://127.0.0.1/php_fpm_status",
                'description': f"Check {service} expose http://127.0.0.1/php_fpm_status",
            },  
            {
                'command':     f"systemctl status {service}",
                'success':      "active (running)", 
                'error':       f"{service} is not running",
                'description': f"Check: {service} is up and running",
            },
   
            {
                'command': "curl -sI -k -X GET http://127.0.0.1:9253/metrics | head -n1",
                'success': "200 OK",
                'error': f"{service} not expose http://127.0.0.1:9253/metrics",
                'description': f"Check {service} expose http://127.0.0.1:9253/metrics",
            },
            {
                'command': "ss -lntp | grep 9253",
                'success': "9253",
                'error': f"{service} is not listening to TCP port 9253",
                'description': f"Verify {service} is listening on TCP port 9253",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # Allow non-zero exit code if no output and flag set
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error: \n {error}", extra={'stepname': step})
                logger.error(f"--> Command: \n {check['command']}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"Executed: {command}", extra={'stepname': step})
            logger.info(f"--> output: '{output}'", extra={'stepname': step})
            logger.info(f"--> error: '{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_prometheus_remove_lxc(dictionary):
    step = 'proxmox_prometheus_remove_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start remove...", extra={'stepname': step})

        commands = [
                # Stop and disable the service           
                "systemctl stop prometheus || true",
                "systemctl disable prometheus || true",

                # Remove package
                "apt -y clean",
                "apt -y update",
                "apt -y purge prometheus* || true",
                "apt -y autoremove || true",
                "apt -y clean || true",
        
                 # Remove configuration directories and files      
                "if id prometheus &>/dev/null; then userdel -rf prometheus 2>/dev/null || true; fi",
                "rm -rf /usr/share/prometheus",
                "rm -rf /var/lib/prometheus",
                "rm -rf /usr/local/bin/prometheus",
                "rm -rf /usr/local/bin/promtool",
                "rm -rf /etc/prometheus",
                "rm -f /etc/systemd/system/prometheus.service",
                
                "systemctl daemon-reload"
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("'prometheus' removal completed successfully", extra={'stepname': step})
    
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False  

# ------------------------------------------------------------------------------------------
def proxmox_prometheus_install_lxc(dictionary):
    step = 'proxmox_prometheus_install_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retrieve required variables        
        required_keys = [
            'prometheus_download_url',
            'prometheus_download_file',
            'prometheus_download_file_ext',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        prometheus_download_url       = dictionary.get('prometheus_download_url')
        prometheus_download_file      = dictionary.get('prometheus_download_file')
        prometheus_download_file_ext  = dictionary.get('prometheus_download_file_ext')        

        # Remove old installation first
        if not proxmox_prometheus_remove_lxc(dictionary):
            logger.error("'prometheus' not removed successfully.", extra={'stepname': step})
            return False

        logger.info("'prometheus' installation starting ...", extra={'stepname': step})

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get install -y wget tar curl",
            
            # Create the prometheus user if it doesn't exist
            "getent passwd prometheus || useradd --no-create-home --system --shell /usr/sbin/nologin prometheus",
            
            # Install prometheus              
            f"wget -P /tmp {prometheus_download_url}",
            f"tar xzf /tmp/{prometheus_download_file}.{prometheus_download_file_ext} -C /tmp",           

            f"mkdir -p /etc/prometheus ",
            f"mkdir -p /var/lib/prometheus ",
            
            f"mv /tmp/prometheus-*/prometheus.yml /etc/prometheus/ ",
            f"mv /tmp/prometheus-*/prometheus /usr/local/bin/ ",                  
            f"mv /tmp/prometheus-*/promtool /usr/local/bin/ ",
              
            f"chown prometheus:prometheus /usr/local/bin/prometheus ",
            f"chown prometheus:prometheus /usr/local/bin/promtool ",
            f"chown -R prometheus:prometheus /etc/prometheus ",
            f"chown -R prometheus:prometheus /var/lib/prometheus ",

            # Install Pushgateway
            "apt-get install prometheus-pushgateway -y",
            "systemctl enable --now prometheus-pushgateway",

            f"rm -rf /tmp/{prometheus_download_file}*",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                   
        logger.info("'prometheus' installed.", extra={'stepname': step})

        # Tuning
        if not proxmox_prometheus_tuning_lxc(dictionary):
            return False
        # checks    
        if not proxmox_prometheus_up_lxc(dictionary):
            return False
            
        return True            
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_prometheus_tuning_lxc(dictionary):
    step = 'proxmox_prometheus_tuning_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'prometheus_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('prometheus_configs', []):
            if item.get('install') and not item.get('name', '').endswith('.job'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload Prometheus configuration files.", extra={'stepname': step})
                return False

        # Enable and start service
        commands = [
            "systemctl daemon-reload",
            "systemctl enable prometheus",
            "systemctl start prometheus",
            "sleep 5",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("'prometheus' tuning completed", extra={'stepname': step})
        
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pushgateway_notify(dictionary):
    step = "proxmox_pushgateway_notify"

    try:
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Retreive values from dictionary
        required_keys = [
              'task_attributes',
              'prometheus_ip',
        ]        
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False       

        prometheus_ip              = dictionary['prometheus_ip']
        pushgw_base                = f"http://{prometheus_ip}:9091"
        prometheus_url             = f"http://{prometheus_ip}:9090"

        # Retreive values from playbook
        vars_section               = dictionary['task_attributes'].get('vars', {})
        required_vars              = (
            'metric_name',
            'metric_value',
            'job_name',
            'labels',
            'pushgateway_delay',
            'wait_for_prometheus',
        )
        for key in required_vars:
            if key not in vars_section or vars_section[key] in (None, '', []):
                logger.error(f"Missing or empty parameter: {key}", extra={'stepname': step})
                return False

        metric_name                = vars_section['metric_name']
        metric_value               = vars_section.get('metric_value', 1)
        job_name                   = vars_section.get('job_name', 'default_job')
        labels_dict                = vars_section.get('labels', {})
        pushgateway_delay          = int(vars_section.get('pushgateway_delay', 15))
        wait_for_prometheus        = vars_section.get('wait_for_prometheus', True)
        delete_after_push          = vars_section.get('delete_after_push', False)

        # ──────────────────────────────────────────────────────────────────────
        # Build the Pushgateway path with URL‑encoded labels
        # ──────────────────────────────────────────────────────────────────────
        def enc(s: str) -> str:
            return quote(str(s), safe='')

        labels_path                = ''.join(
            f'/{enc(k)}/{enc(v)}' for k, v in labels_dict.items()
        )
        push_url                   = f"{pushgw_base}/metrics/job/{enc(job_name)}{labels_path}"
        metric_line                = f"{metric_name} {metric_value}\n"

        # ──────────────────────────────────────────────────────────────────────
        # Push the metric
        # ──────────────────────────────────────────────────────────────────────
        command_push              = (
            f"echo '{metric_line}' | "
            f"curl --silent --show-error --data-binary @- {push_url}"
        )
        logger.info(f"Pushing metric: {metric_name}={metric_value} -> {push_url}",
                    extra={'stepname': step})
        success, error, output    = proxmox_command(dictionary, command_push, step)
        if not success:
            logger.error("Failed to push metric.", extra={'stepname': step})
            logger.error(f"--> command : {command_push}", extra={'stepname': step})
            logger.error(f"--> output  :\n{output}",     extra={'stepname': step})
            logger.error(f"--> error   :\n{error}",      extra={'stepname': step})
            return False

        # ──────────────────────────────────────────────────────────────────────
        # Wait for Prometheus scrape or just sleep
        # ──────────────────────────────────────────────────────────────────────
        if wait_for_prometheus:
            prom_query_labels      = ','.join(f'{k}="{v}"' for k, v in labels_dict.items())
            prom_query             = (
                f'{metric_name}{{job="{job_name}"'
                f'{"," + prom_query_labels if prom_query_labels else ""}}}'
            )
            prom_api               = f"{prometheus_url}/api/v1/query"
            for i in range(pushgateway_delay):
                try:
                    r = requests.get(prom_api, params={'query': prom_query}, timeout=5)
                    if r.ok and r.json().get('status') == 'success' and r.json()['data']['result']:
                        logger.info(f"Scraped after {i+1}s.", extra={'stepname': step})
                        break
                except Exception as exc:
                    logger.warning(f"Prometheus query failed: {exc}", extra={'stepname': step})
                time.sleep(1)
            else:
                logger.warning("Metric not seen by Prometheus within wait time.",
                               extra={'stepname': step})
        else:
            logger.info(f"Sleeping {pushgateway_delay}s …", extra={'stepname': step})
            time.sleep(pushgateway_delay)

        # ──────────────────────────────────────────────────────────────────────
        # Optional DELETE
        # ──────────────────────────────────────────────────────────────────────
        if delete_after_push:
            command_del           = (
                f"curl --silent --show-error --write-out '%{{http_code}}' "
                f"-X DELETE {push_url}"
            )
            logger.info(f"Deleting metric: {push_url}", extra={'stepname': step})
            success, error, output = proxmox_command(dictionary, command_del, step)
            if not success or output.strip() not in ('202', '200'):
                logger.error("Failed to delete metric from Pushgateway.",
                             extra={'stepname': step})
                logger.error(f"--> command : {command_del}", extra={'stepname': step})
                logger.error(f"--> output  :\n{output}",     extra={'stepname': step})
                logger.error(f"--> error   :\n{error}",      extra={'stepname': step})
                return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_prometheus_up_lxc(dictionary):
    step = 'proxmox_prometheus_up_lxc'

    try:
        service = 'prometheus'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False         

        # Basic checks
        checks  = [
            {
                'command':     f"systemctl is-active {service}",
                'success':      "active",
                'error':       f"{service} service not active",
                'description': f"Check {service} service status",
            },
            {
                'command':      "curl -sI -k -X GET http://localhost:9090/-/ready | head -n1",
                'success':      "200 OK",
                'error':       f"{service} web not responding",
                'description': f"Check {service} up and running",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_alertmanager_remove_lxc(dictionary):
    step = 'proxmox_alertmanager_remove_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        service = "alertmanager"  
        
        logger.info(f"Start remove {service} ...", extra={'stepname': step})

        commands = [
            # Stop and disable the service
            f"systemctl stop {service} || true",
            f"systemctl disable {service} || true",

            # Remove package
            "apt-get -y clean",
            "apt-get -y update",
            f"apt-get -y purge {service} || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",
            
            # Remove configuration directories and files
            "if id alertmanager &>/dev/null; then userdel -rf alertmanager 2>/dev/null || true; fi",
            "rm -f /usr/local/bin/alertmanager",
            "rm -f /usr/local/bin/amtool",
            "rm -rf /var/lib/alertmanager",           
            "rm -rf /etc/alertmanager",
            "rm -f /etc/systemd/system/alertmanager.service",
            
            "systemctl daemon-reload"
        ]        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check if required packages are removed
        required_packages = [service]
        for pkg in required_packages:
            if proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not removed.")
                return False
        else:
            logger.info(f"--> {service} removed successfully.", extra={'stepname': step})
            return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_alertmanager_install_lxc(dictionary):
    step = 'proxmox_alertmanager_install_lxc'

    try:
        service = "alertmanager"
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'alertmanager_download_version',
            'alertmanager_download_url',
            'alertmanager_download_file',
            'alertmanager_download_file_ext',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
            
        # Retrieve required variables        
        alertmanager_download_version  = dictionary.get('alertmanager_download_version')
        alertmanager_download_url      = dictionary.get('alertmanager_download_url')
        alertmanager_download_file     = dictionary.get('alertmanager_download_file')
        alertmanager_download_file_ext = dictionary.get('alertmanager_download_file_ext')

        # Remove any existing installation first
        if not proxmox_alertmanager_remove_lxc(dictionary):
            logger.error("'alertmanager' not removed successfully.", extra={'stepname': step})
            return False

        logger.info("'alertmanager' installation starting ...", extra={'stepname': step})

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get install -y wget tar curl",
            
            f"wget -P /tmp {alertmanager_download_url}",
            f"tar xzf /tmp/{alertmanager_download_file}.{alertmanager_download_file_ext} -C /tmp",
            
            "mkdir -p /usr/local/bin",
            "mkdir -p /var/lib/alertmanager",
            "mkdir -p /etc/alertmanager",
            "mkdir -p /var/log/alertmanager",
            "mkdir -p /var/lib/alertmanager",
            
            f"mv /tmp/{alertmanager_download_file}/alertmanager /usr/local/bin/",
            f"mv /tmp/{alertmanager_download_file}/amtool /usr/local/bin/",

            # Create user
            "getent passwd alertmanager || useradd --no-create-home --shell /bin/false alertmanager",

            # Permissions
            "chown alertmanager:alertmanager /etc/alertmanager/ -R",
            "chown alertmanager:alertmanager /var/lib/alertmanager/ -R",
            "chown alertmanager:alertmanager /usr/local/bin/alertmanager",
            "chown alertmanager:alertmanager /usr/local/bin/amtool",
            
            "touch /var/log/alertmanager/alertmanager.log /var/log/alertmanager/alertmanager-error.log",
            "chown alertmanager:alertmanager /var/log/alertmanager/alertmanager*",
            "chown alertmanager:alertmanager /var/lib/alertmanager",
            
            # cleanup
            f"rm -rf /tmp/{alertmanager_download_file}*",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                   
        logger.info("--> alertmanager installed.", extra={'stepname': step})

        # Run tuning and final checks
        if not proxmox_alertmanager_tuning_lxc(dictionary):
            return False
        if not proxmox_alertmanager_up_lxc(dictionary):
            return False

        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_alertmanager_tuning_lxc(dictionary):
    step = 'proxmox_alertmanager_tuning_lxc'

    try:
        service = 'alertmanager'
         
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
 
        # Check required keys
        required_keys = [
            'task_attributes',
            'alertmanager_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('alertmanager_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload alertmanager configuration files.", extra={'stepname': step})
                return False

        # Enable and start
        commands = [
            "systemctl daemon-reload",
            "systemctl enable alertmanager",
            "systemctl restart alertmanager",
            "sleep 5",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
                
        logger.info("'alertmanager' tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_alertmanager_up_lxc(dictionary):
    step = 'proxmox_alertmanager_up_lxc'

    try:
        service = 'alertmanager'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'alertmanager_ip',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        alertmanager_ip = dictionary.get('alertmanager_ip')

        command_amtool = f"""export PATH=$PATH:/usr/local/bin && amtool alert add TestAlert alertname="TestAlert from python via amtool" severity="Test" \
    --annotation "description=\\"This is a test alert from AlertManager (amtool)\\"" \
    --annotation "summary=\\"Test email\\"" \
    --alertmanager.url=http://{alertmanager_ip}:9093"""

        # Basic checks
        checks  = [
            {
                'command':      f"systemctl is-active {service}",
                'success':      "active",
                'error':       f"{service} service not active",
                'description': f"Check {service} service up and running",
            },
            {
                'command':     "curl -sI -k -X GET http://localhost:9093/-/ready | head -n1",
                'success':     "200 OK",
                'error':       f"{service} Web not responding",
                'description': f"Check {service} up and running",
            },            
            # Send test alert using amtool
            {
                'command': f"{command_amtool}",
                'success': "",
                'error': "Failed to send test alert via amtool",
                'description': "Send a test alert via amtool",
                'allow_nonzero': True
            },
            # Send test alert using curl
            {
                'command': "curl -H \"Content-Type: application/json\" -d '[{\"labels\":{\"alertname\":\"TestAlert from Python via curl\",\"severity\":\"warning\",\"instance\":\"test.local\"}}]' http://localhost:9093/api/v2/alerts",
                'success': "",
                'error': "Failed to send test alert via curl",
                'description': "Send a test alert via curl",
                'allow_nonzero': True
            }
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_grafana_remove_lxc(dictionary):
    step = 'proxmox_grafana_remove_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start remove...", extra={'stepname': step})

        service = 'grafana-server'
        package = 'grafana'

        # Commands to remove all traces
        commands = [
            # Stop and disable the service           
           f"systemctl stop {service} || true",
           f"systemctl disable {service} || true",    
            
            # Remove package   
           f"apt-get -y purge {package} || true",
            "apt-get -y autoremove",
            "apt-get -y clean",
        
            # Remove configuration directories and files
            "rm -rf /etc/grafana",
            "rm -f /etc/apt/sources.list.d/grafana.list",
        
            "systemctl daemon-reload"
        ]        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False

            logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info(f"--> {package} removed successfully and all traces cleared.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_grafana_install_lxc(dictionary):
    step = 'proxmox_grafana_install_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        service = 'grafana-server'
        package = 'grafana'

        if not proxmox_grafana_remove_lxc(dictionary):
            logger.error(f"{package} not removed successfully.", extra={'stepname': step})
            return False
        
        logger.info("Start install...", extra={'stepname': step})
        
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get install -y apt-transport-https software-properties-common wget curl",
            "wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor > /usr/share/keyrings/grafana.gpg",
            "echo 'deb [signed-by=/usr/share/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main' > /etc/apt/sources.list.d/grafana.list",
            
            "DEBIAN_FRONTEND=noninteractive  apt-get update -y", # update again to load the new repo
            
            "apt-get install -y grafana",
            "apt-get install -y jq",
            "systemctl daemon-reload",
            "systemctl enable grafana-server",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
               logger.error("Failed to execute command:", extra={'stepname': step})
               logger.error(f"--> command : '{command}'.", extra={'stepname': step})
               logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
               logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
               return False
            logger.info(f"Executed: {command}", extra={'stepname': step})               

        # Tuning and check service
        if not proxmox_grafana_tuning_lxc(dictionary):
           return False
                
        # checks        
        if not proxmox_grafana_up_lxc(dictionary):
           return False

        logger.info(f"--> {package} installed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_grafana_tuning_lxc(dictionary):
    step = 'proxmox_grafana_tuning_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start tuning...", extra={'stepname': step})

        service = 'grafana-server'
        package = 'grafana'

        # Check required keys
        required_keys = [
            'grafana_admin_password',
            'grafana_configs',
            'alertmanager_ip',
            'prometheus_ip',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        grafana_admin_password = dictionary.get('grafana_admin_password')
        alertmanager_ip        = dictionary.get('alertmanager_ip')
        prometheus_ip          = dictionary.get('prometheus_ip')

        # Upload configuration files in LXC
        files_to_upload = []
        for item in dictionary.get('grafana_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload grafana configuration files.", extra={'stepname': step})
                return False
 
        # Restart to take effect
        commands = [
             "systemctl daemon-reload",
            f"systemctl start {service}",
            
            # Wait for Grafana web to be ready (max 30s)
            "for i in {1..6}; do curl -s http://localhost:3000/api/health && break || sleep 5; done",

            # admin password update 
            f"grafana-cli --config '/etc/grafana/grafana.ini' admin reset-admin-password '{grafana_admin_password}' ",

            # Prometheus datasource
            f"curl -s -X POST http://localhost:3000/api/datasources "
            f"-H 'Content-Type: application/json' "
            f"-u admin:'{grafana_admin_password}' "
            f"-d '{{"
            f"\"name\":\"Prometheus\","
            f"\"type\":\"prometheus\","
            f"\"access\":\"proxy\","
            f"\"url\":\"http://{prometheus_ip}:9090\","
            f"\"basicAuth\":false,"
            f"\"isDefault\":true"
            f"}}'",           
             
            # Alertmanager datasource
            f"curl -s -X POST http://localhost:3000/api/datasources "
            f"-H 'Content-Type: application/json' "
            f"-u admin:'{grafana_admin_password}' "
            f"-d '{{"
            f"\"name\":\"Alertmanager\","
            f"\"type\":\"alertmanager\","
            f"\"access\":\"proxy\","
            f"\"url\":\"http://{alertmanager_ip}:9093\","
            f"\"basicAuth\":false,"
            f"\"isDefault\":false"
            f"}}'", 

            f"systemctl restart {service}",
            
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Upload dashboards to LXC
        dashboard_files = []
        dashboard_remote_paths = []

        for item in dictionary.get('grafana_dashboards', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    dashboard_files.append((os.path.normpath(local_path), remote_path))
                    dashboard_remote_paths.append(remote_path)

        if dashboard_files:
            if not proxmox_upload_files_windows_2_lxc(dictionary, dashboard_files, step):
                logger.error("Failed to upload Grafana dashboard JSON files.", extra={'stepname': step})
                return False

        # Check presence and JSON validity of each dashboard before import
        for remote_path in dashboard_remote_paths:
            command = f"test -s {remote_path} && jq empty {remote_path}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to import Grafana dashboard.", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Import dashboards into Grafana
        for remote_path in dashboard_remote_paths:
            command = (
                f"bash -c \""
                f"jq -Rs '"
                f"{{"
                f"  dashboard: fromjson, "
                f"  overwrite: true, "
                f"  inputs: ["
                f"    {{"
                f"      name: \\\"DS_PROMETHEUS\\\", "
                f"      type: \\\"datasource\\\", "
                f"      pluginId: \\\"prometheus\\\", "
                f"      value: \\\"Prometheus\\\""
                f"    }}"
                f"  ]"
                f"}}' < {remote_path} "
                f"| curl -s -X POST http://localhost:3000/api/dashboards/import "
                f"-H 'Content-Type: application/json' "
                f"-u admin:'{grafana_admin_password}' "
                f"-d @-\""
            )
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to import Grafana dashboard.", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Imported dashboard from: {remote_path}", extra={'stepname': step})
            
            
        logger.info(f"--> {package} tuning completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_grafana_up_lxc(dictionary):
    step = 'proxmox_grafana_up_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start check...", extra={'stepname': step})
        
        service = 'grafana-server'
        package = 'grafana'
        
        # Basic checks         
        checks  = [
            {
                'command':     f"systemctl is-active {service}",
                'success':     "active",
                'error':       f"{service} service not active",
                'description': f"Check {service} up and running",
            },
            {
                # Retry up to 5 times with 5-second waits between attempts
                'command':     "for i in {1..5}; do if curl -sI -k -X GET http://localhost:3000 | grep -q '200 OK'; then exit 0; fi; sleep 5; done; exit 1",
                'success':     "",  # Exit code 0 indicates success
                'error':       "grafana Web not responding after multiple attempts",
                'description': "Check grafana web access with retries",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"--> command : '{check['command']}'", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_redis_remove_lxc(dictionary):
    step = 'proxmox_redis_remove_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start remove...", extra={'stepname': step})
        
        service = 'redis-server'
        
        # Commands to remove all traces
        commands = [
            # Stop and disable the service           
           f"systemctl stop {service} || true",
           f"systemctl disable {service} || true",    
            
            # Remove package
            "apt-get -y clean",
            "apt-get -y update",
            "apt-get -y purge redis* || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",  

            # Remove configuration directories and files          
            "rm -rf /var/lib/redis /var/log/redis /var/run/redis /etc/redis/redis.conf",
        
            "systemctl daemon-reload"
        ]        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info("'redis' removed successfully and all traces cleared.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_redis_install_lxc(dictionary):
    step = 'proxmox_redis_install_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start install...", extra={'stepname': step})       
        
        service = 'redis-server'
        
        if not proxmox_redis_remove_lxc(dictionary):
            return False
        
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
                        
           f"apt-get -y install {service} curl",
           f"systemctl enable {service}",
            "systemctl daemon-reload"
        ]        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
               logger.error("Failed to execute command:", extra={'stepname': step})
               logger.error(f"--> command : '{command}'.", extra={'stepname': step})
               logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
               logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
               return False
            else:
               logger.info(f"Executed: {command}", extra={'stepname': step})
 
        # Tuning and check service
        if not proxmox_redis_tuning_lxc(dictionary):
           return False
        if not proxmox_redis_up_lxc(dictionary):
           return False
        if not proxmox_redis_flushall_lxc(dictionary):
           return False                       
        if not proxmox_redis_bench_lxc(dictionary):
           return False  
           
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_redis_tuning_lxc(dictionary):
    step = 'proxmox_redis_tuning_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = ['redis-server']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Start tuning...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'redis_unixsocket',
            'redis_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        redis_unixsocket     = dictionary.get('redis_unixsocket')
        redis_configs        = dictionary.get('redis_configs', [])        

        # Calculate Max Memory
        command = "awk '/MemTotal:/ { printf \"%d\", $2 / 2 }' /proc/meminfo"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command : '{command}'.", extra={'stepname': step})
           logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
           logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
           return False
        else:
           logger.info(f"Executed: {command}", extra={'stepname': step})  
        
        redis_maxmemory               = f"{output}kB"
        dictionary['redis_maxmemory'] = redis_maxmemory
        logger.info(f"Configured max memory: {redis_maxmemory}.", extra={'stepname': step})

        # Calculate Max Clients
        command = "ulimit -n"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command : '{command}'.", extra={'stepname': step})
           logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
           logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
           return False
        else:
           logger.info(f"Executed: {command}", extra={'stepname': step})  
            
        redis_maxclients               = f"{int(output.strip()) - 32}"
        dictionary['redis_maxclients'] = redis_maxclients
        logger.info(f"Configured max clients: {redis_maxclients}.", extra={'stepname': step})

        # Configure HZ Value
        command    = "nproc"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command : '{command}'.", extra={'stepname': step})
           logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
           logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
           return False
        else:
           logger.info(f"Executed: {command}", extra={'stepname': step})        

        redis_hz               = f"{int(output.strip()) * 2}"
        dictionary['redis_hz'] = redis_hz
        logger.info(f"Configured HZ value: {redis_hz}.", extra={'stepname': step})


        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('redis_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))
                    
        # Upload the files via SFTP
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload redis configuration files.", extra={'stepname': step})
                return False

        # Enable and start 
        commands = [ 
            # Set directories and permissions
            "mkdir -p /var/lib/redis /var/log/redis",
            "chown redis:redis /var/lib/redis /var/log/redis",
            
           f"chown redis:redis {redis_unixsocket}",
           f"chmod 770   {redis_unixsocket}",
            # Also ensure the directory is traversable:
            "chown redis:redis /run/redis",
            "chmod 750         /run/redis",
                        
            "if [ -w /sys/kernel/mm/transparent_hugepage/enabled ]; then echo never > /sys/kernel/mm/transparent_hugepage/enabled; else echo 'Skipping transparent hugepage tuning'; fi",
            "if [ -w /proc/sys/vm/overcommit_memory ]; then echo 1 > /proc/sys/vm/overcommit_memory; else echo 'Skipping overcommit_memory tuning'; fi",

            "systemctl daemon-reload",
            "systemctl enable redis-server",
            "systemctl restart redis-server",
            "sleep 5",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
            
        logger.info("'redis-server' tuning completed", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_redis_up_lxc(dictionary):
    step = 'proxmox_redis_up_lxc'

    try:
        service = 'redis-server' 
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
 
        # Ensure required packages are installed
        required_packages = [service, 'curl']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False 
 
        logger.info("Start check...", extra={'stepname': step})   

        # Check required keys
        required_keys = [
            'task_attributes',
            'redis_unixsocket',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        redis_unixsocket     = dictionary.get('redis_unixsocket') 

        # Basic checks   
        checks  = [
            {
                'command':     f"redis-server --version",
                'success':      "Redis server", 
                'error':       f"{service} are not installed",
                'description': f"Check if {service} is installed",
            },    
            {
                'command':     f"systemctl is-active {service}",
                'success':      "active",
                'error':       f"{service} not active",
                'description': f"Check {service} up and running",
            },
            {
                'command':      f"redis-cli -s {redis_unixsocket} ping",
                'success':      "PONG", 
                'error':       f"{service} are not listening",
                'description': f"Check if {service} are listening",
            },        
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"--> command : '{check['command']}'", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_redis_bench_lxc(dictionary):
    step = 'proxmox_redis_bench_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Ensure required packages are installed
        required_packages = ['redis-server']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False 

        logger.info("Start benchmark...", extra={'stepname': step})      

        # Check required keys
        required_keys = [
            'task_attributes',
            'redis_unixsocket',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        redis_unixsocket     = dictionary.get('redis_unixsocket')

        command     = f"redis-benchmark -s {redis_unixsocket} -n 1000000 -t set,get -P 16"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command : '{command}'.", extra={'stepname': step})
           logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
           logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
           return False
        else:
           logger.info(f"Executed: {command}", extra={'stepname': step})
           return True
       
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_redis_flushall_lxc(dictionary):
    step = 'proxmox_redis_flushall_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start redis flushall...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'redis_unixsocket',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        redis_unixsocket     = dictionary.get('redis_unixsocket')
        
        command     = f"redis-cli -s {redis_unixsocket} FLUSHALL"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command : '{command}'.", extra={'stepname': step})
           logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
           logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
           return False
        else:
           logger.info(f"Executed: {command}", extra={'stepname': step})
           return True
           
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_remove_lxc(dictionary):
    step = 'proxmox_nginx_remove_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start remove...", extra={'stepname': step})

        # Commands to remove all traces
        commands = [
            # Stop and disable the service           
            "systemctl stop nginx || true",
            "systemctl disable nginx || true",    

            # Remove package
            "apt-get -y clean",
            "apt-get -y update",
            "apt-get -y purge nginx nginx-full nginx-common || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",  

            # Remove configuration directories and files
            "rm -rf /etc/nginx",                             # configuration files
            "rm -rf /var/log/nginx",                         # log files
            "rm -rf /var/www/html",                          # default web root
            "rm -rf /var/lib/nginx",                         # application data
            "rm -rf /usr/lib/systemd/system/nginx.service",  # systemd service file
            "rm -rf /usr/sbin/nginx",                        # binary (if left behind)
            "rm -rf /run/nginx",                             # runtime files (socket, pid, etc.)
            
            "systemctl daemon-reload"
        ]        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info("nginx removed successfully and all traces cleared.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_install_lxc(dictionary):
    step = 'proxmox_nginx_install_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start install...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_webserver_html_path',
            'nginx_config_base',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)  
        nginx_webserver_user      = dictionary.get('nginx_webserver_user')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        nginx_bigfiles_path       = dictionary.get('nginx_bigfiles_path')
        nginx_config_base         = dictionary.get('nginx_config_base') 

        # Ensure clean installation
        if not proxmox_nginx_remove_lxc(dictionary):
           return False
           
        # Remove residual apache  if present
        if not proxmox_apache_remove_lxc(dictionary):
            return False
            
        # Install
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get -y install nginx nginx-common nginx-full curl",
            
            "systemctl start nginx",
            "systemctl enable nginx",
                        
           f"mkdir -p {nginx_config_base}",
           f"chmod -R 775 {nginx_config_base}",            
            
           f"chown -R {nginx_webserver_user}:{nginx_webserver_user} {nginx_webserver_html_path}",
           f"chmod 775 {nginx_webserver_html_path} -R",
           
           f"mkdir -p {nginx_bigfiles_path}",
           f"chmod -R 777 {nginx_bigfiles_path}",
           f"chown {nginx_webserver_user}:{nginx_webserver_user} -R {nginx_bigfiles_path}",

           f"chown {nginx_webserver_user}:{nginx_webserver_user} -R {nginx_config_base}",
            "systemctl daemon-reload",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Get the IP address
        success, ip = proxmox_get_ip_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current IP address for container {container_id}.", extra={'stepname': step})
           return False

        if not ip:
           logger.error(f"Unable to obtain current IP address for container {container_id}.", extra={'stepname': step})
           return False         
        
        # Check if Nginx is running
        service = 'nginx'
        if proxmox_is_service_actif_lxc(dictionary, service, step):
            logger.info(f"{service} started successfully.", extra={'stepname': step})
        else:
            logger.error(f"{service} failed to start.", extra={'stepname': step})
            return False
  
        # Check if Nginx can serve requests
        command = f"curl -L --head {ip}"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})
                
        if 'HTTP/1.1' not in output and 'HTTP/2' not in output:
            logger.error(f"Site {ip} not reached. Response: {output}", extra={'stepname': step})
            return False

        status_line = output.split('\n')[0]
        logger.info(f"Site {ip} reached successfully. Status: {status_line}", extra={'stepname': step})

        # Restart to apply the changes
        service = "nginx"
        if proxmox_service_operation_lxc(dictionary,service, 'restart', step):
           logger.info(f"{service} is tuned successfully and up and running.", extra={'stepname': step})
           return True
        else:
           logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
           return False

        # tuning
        if not proxmox_nginx_tuning_lxc(dictionary):
           return False

        # Check
        if not proxmox_nginx_up_lxc(dictionary):
            return False
     
        return True
         
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_tuning_lxc(dictionary):
    step = 'proxmox_nginx_tuning_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
             
        # Check if required packages are installed
        required_packages = ['nginx']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Start tuning...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve system memory
        command     = "grep MemTotal /proc/meminfo"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command : '{command}'.", extra={'stepname': step})
           logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
           logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
           return False
        else:
           logger.info(f"Executed: {command}", extra={'stepname': step})  

        mem_total_kb = int(output.split()[1])
        mem_total_mb = mem_total_kb // 1024

        # Compute nginx_worker_connection and nginx_request_clients
        nginx_worker_connection = mem_total_mb * 4             # Example calculation, adjust as needed
        nginx_request_clients   = 1000 + (mem_total_mb // 10)  # Example fixed value, adjust as needed

        # Update the config dictionary with computed values
        dictionary['nginx_worker_connection'] = nginx_worker_connection
        dictionary['nginx_request_clients']   = nginx_request_clients

        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('nginx_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload nginx configuration files.", extra={'stepname': step})
                return False

        # Chown after uploading files
        if not proxmox_nginx_chown_lxc(dictionary):
           logger.error("flailed to chown nginx files.", extra={'stepname': step})
           return False

        # Restart to apply the changes
        service = "nginx"
        if proxmox_service_operation_lxc(dictionary,service, 'restart', step):
           logger.info(f"{service} is tuned successfully and up and running.", extra={'stepname': step})
           return True
        else:
           logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
           return False
           
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_chown_lxc(dictionary):
    step = 'proxmox_nginx_chown_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = ['nginx']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Start chown...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_webserver_user',
            'nginx_config_base',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary) 
        nginx_webserver_user      = dictionary.get('nginx_webserver_user')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        nginx_config_base         = dictionary.get('nginx_config_base')

        # Check if directories exist before running chown
        directories = [nginx_webserver_html_path, nginx_config_base]
        for directory in directories:
            command = f"test -d {nginx_webserver_html_path}"
            exists, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not exists:
                logger.error(f"Directory '{nginx_webserver_html_path}' does not exist in container.", extra={'stepname': step})
                return False

        commands = [
            f"chmod -R 775 {nginx_config_base}",       
            f"chown -R {nginx_webserver_user}:{nginx_webserver_user} {nginx_config_base}",
            f"chmod -R 775 {nginx_webserver_html_path}",            
            f"chown -R {nginx_webserver_user}:{nginx_webserver_user} {nginx_webserver_html_path}",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed command successfully: '{command}'", extra={'stepname': step})

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_update_localhosts_lxc(dictionary):
    step = 'proxmox_nginx_update_localhosts_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
       
        # Check if required packages are installed
        required_packages = ['nginx', 'php']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False      

        logger.info("Start nginx localhosts update...", extra={'stepname': step})
        
        # Retrieve required variables
        required_keys = [
           'task_attributes'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)  
        nginx_localhosts = dictionary['task_attributes'].get('vars', {}).get('nginx_localhosts', [])   
        if not nginx_localhosts:
            logger.error("nginx_localhosts in the playbook.", extra={'stepname': step})
            return False  

        # Upload file in LXC
        files_to_upload = []
        for item in nginx_localhosts:
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload nginx configuration files.", extra={'stepname': step})
                return False

        # Change ownership after uploading files
        if not proxmox_nginx_chown_lxc(dictionary):
           logger.error("Failed to chown nginx files.", extra={'stepname': step})
           return False

        # Restart nginx to apply the changes
        service = "nginx" 
        if proxmox_service_operation_lxc(dictionary,service, 'restart', step):
           logger.info(f"{service} is tuned successfully and up and running.", extra={'stepname': step})
           return True
        else:
           logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
           return False
           
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_up_lxc(dictionary):
    step = 'proxmox_nginx_up_lxc'

    try:
        service = 'nginx'  

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
 
        # Ensure required packages are installed
        service = 'nginx'  
        required_packages = ['nginx', 'curl']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False 
  
        logger.info("Start check...", extra={'stepname': step})   

        # Basic checks        
        checks  = [
            {
                'command':     f"systemctl status {service}",
                'success':      "active (running)", 
                'error':       f"{service} is not running",
                'description': f"Check if {service} is up and running",
            },    
            {
                'command':      "stat -c '%U:%G %a' /var/log/nginx",
                'success':      "root:adm 755",  # Updated expected value
                'error':        "Permission error in /var/log/nginx",
                'description':  "Checking permissions of /var/log/nginx",
            },
            {
                'command':      "grep 'ERROR' /var/log/nginx/error.log",
                'success':      "", 
                'error':        "Error in error.log",
                'description':  "Searching for errors in error.log",
                'allow_nonzero': True  # Allow nonzero exit if output is empty
            },        
            {
                'command':      "grep 'ERROR' /var/log/nginx/access.log",
                'success':      "", 
                'error':        "Error in access.log",
                'description':  "Searching for errors in access.log",
                'allow_nonzero': True  # Allow nonzero exit if output is empty
            },        
            {
                'command':      "grep 'Out of memory' /var/log/messages",
                'success':      "", 
                'error':        "'Out of memory' errors in system logs",
                'description':  "Searching for 'Out of memory' errors in system logs",
                'allow_nonzero': True  # Allow nonzero exit if output is empty
            },           
            {
                'command':      "curl -L --head http://localhost",
                'success':      "200 OK", 
                'error':        "Nginx not serving localhost",
                'description':  "Checking if Nginx is serving localhost",
            },
            {
                'command':      "curl -L --head http://localhost/stub_status",
                'success':      "200 OK", 
                'error':        "Nginx is not configured properly stub_status not respond",
                'description':  "Checking if Nginx is serving localhost/stub_status",
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nginx_sites_up_lxc(dictionary):
    step = 'proxmox_nginx_sites_up_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        service           = 'nginx'  
        required_packages = ['nginx', 'curl']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False 

        logger.info("Start check for all sites defined in nginx", extra={'stepname': step})     

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_conf_site_path',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)  
        nginx_conf_site_path   = dictionary.get('nginx_conf_site_path')
        server_name_regex      = r'server_name\s+([^;]+);'
 
        # Retrieve all server names from Nginx configuration files.
        server_names = []
        # Execute command to list all files in the nginx config directory
        command = f'ls {nginx_conf_site_path}'
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
           logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
           logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
           return False
        
        dictionary_files = output.splitlines()
        for dictionary_file in dictionary_files:
            # Skip non-.conf files
            if not dictionary_file.endswith('.conf'):
                continue
            # Read the content of each configuration file
            command     = f'cat {nginx_conf_site_path}/{dictionary_file}'
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
               continue

            # Find all server_name directives in the file
            matches = re.findall(server_name_regex, output)
            server_names.extend(matches)

        # backup and Update /etc/hosts for testing.
        command     = "cp /etc/hosts /etc/hosts.bak"  
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
           logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
           logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
           return False
        
        # Update /etc/hosts  
        command = "echo -e '\n# Generated by Infra as Code' >> /etc/hosts"
        for server_name in server_names:
            command += f"echo '127.0.0.1 {server_name}' >> /etc/hosts"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
               logger.error("Failed to execute command:", extra={'stepname': step})
               logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
               logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
               logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
               return False

        # Check servers availability in server_names list.
        check = True
        for server_name in server_names:
            if 'cloud' in server_name:
                command     = f"curl -L -k --head --connect-timeout 10 --max-time 30 {server_name}/status.php"
            else:
                command     = f"curl -L -k --head --connect-timeout 10 --max-time 30 {server_name}"
            
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)      
            if "200 OK" in output:
                logger.info(f"Website {server_name} is up.", extra={'stepname': step})
                continue            
            else:            
                    logger.warning(f"Website {server_name} is DOWN or unavailable.", extra={'stepname': step})
                    logger.warning(f"--> command: {command}", extra={'stepname': step})
                    logger.warning(f"--> output : {output}", extra={'stepname': step})                   
                    check = False
                    continue            

        # Rollback /etc/hosts after testing.
        command     = "mv /etc/hosts.bak /etc/hosts"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
           logger.error("Failed to execute command:", extra={'stepname': step})
           logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
           logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
           logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
           return False
        logger.info(f"Executed: {command}", extra={'stepname': step}) 
        
        if check:
            logger.info(f"All checks successfully executed.", extra={'stepname': step})
        else:
            logger.warning(f"Checks not complete.", extra={'stepname': step})

        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False 

# ------------------------------------------------------------------------------------------
def proxmox_php_remove_lxc(dictionary):
    step = 'proxmox_php_remove_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start remove...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'php_version',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve required variables
        php_version               = dictionary.get('php_version') 
        if not php_version :
            logger.error("php_version handle missing in dictionary", extra={'stepname': step})
            return False 

        # Commands to purge PHP packages and remove configuration, library, and log directories
        commands = [        
            # Stop parent service           
            "systemctl stop nginx || true", 

            # Remove package
            "apt-get -y clean",
            "apt-get -y update",
           f"apt-get -y purge php{php_version}* || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",  
            
            # Remove configuration directories and files
            "rm -rf /etc/php",
            "rm -rf /var/log/php-fpm",
            "rm -rf /var/lib/php",
            
            "systemctl daemon-reload",
        ]        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
               logger.error("Failed to execute command:", extra={'stepname': step})
               logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
               logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
               logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
               return False
            else:
               logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info("PHP removed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_install_lxc(dictionary):
    step='proxmox_php_install_lxc'   

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = ['nginx']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Start install...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_webserver_user',
            'nginx_webserver_html_path',
            'nginx_webserver_group',
            'nginx_config_base',
            'php_version',
            'php_fpm_log_path'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)  
        nginx_webserver_user      = dictionary.get('nginx_webserver_user')
        nginx_webserver_group     = dictionary.get('nginx_webserver_group')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')          
        nginx_config_base         = dictionary.get('nginx_config_base')   
        php_version               = dictionary.get('php_version') 
        php_fpm_log_path          = dictionary.get('php_fpm_log_path') 
       
        # Remove old PHP packages if present
        if not proxmox_php_remove_lxc(dictionary):
            return False

        # Remove residual apache  if present
        if not proxmox_apache_remove_lxc(dictionary):
            return False

        # Install from sury.org for Debian 12
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
             "apt-get install -y apt-transport-https lsb-release curl wget",
            
            # GPG key
             "curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg || "
             "wget -qO /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg",           
            
            # Add sury.org GPG key and repository            
            "echo 'deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ bookworm main' | "
            "tee /etc/apt/sources.list.d/php.list",
            
            "apt-get -y update",
            
            # Install php and php-fpm core
            f"apt-get -y install php{php_version} php{php_version}-fpm php{php_version}-common php{php_version}-cli",
            
            # Install php extensions
            f"apt-get -y install php{php_version}-ctype php{php_version}-curl php{php_version}-fileinfo",
            f"apt-get -y install php{php_version}-mbstring php{php_version}-posix",
            f"apt-get -y install php{php_version}-zip php{php_version}-redis php{php_version}-pgsql php{php_version}-apcu",
            f"apt-get -y install php{php_version}-bz2 php{php_version}-xml php{php_version}-sqlite3",     
             
            # Recommended for specific apps (optional):
            f"apt-get -y install php{php_version}-intl php{php_version}-bcmath php{php_version}-soap  php{php_version}-msgpack",            
            f"apt-get -y install php{php_version}-ldap php{php_version}-smbclient php{php_version}-ftp  php{php_version}-imap",
            
            # For image
            f"apt-get -y install php{php_version}-gd php{php_version}-gmp php{php_version}-imagick imagemagick ffmpeg exiftool",
            
            # Inside LXC containers, Imagemagick can fail to convert certain formats (like RAW, TIFF, EPS, PSD)
            "sed -i 's/rights=\"none\" pattern=\"PDF\"/rights=\"read|write\" pattern=\"PDF\"/'   /etc/ImageMagick-6/policy.xml || true",
            "sed -i 's/rights=\"none\" pattern=\"PS\"/rights=\"read|write\" pattern=\"PS\"/'     /etc/ImageMagick-6/policy.xml || true",
            "sed -i 's/rights=\"none\" pattern=\"EPS\"/rights=\"read|write\" pattern=\"EPS\"/'   /etc/ImageMagick-6/policy.xml || true",
            "sed -i 's/rights=\"none\" pattern=\"XPS\"/rights=\"read|write\" pattern=\"XPS\"/'   /etc/ImageMagick-6/policy.xml || true",
            "sed -i 's/rights=\"none\" pattern=\"PDF\"//' /etc/ImageMagick-6/policy.xml || true",
    
            # Create base /var/lib/php
            "mkdir -p /var/lib/php && chmod 1733 /var/lib/php",
            f"chown -R {nginx_webserver_user}:{nginx_webserver_group} /var/lib/php",

            # modules
            "mkdir -p /var/lib/php/modules && chmod 0755 /var/lib/php/modules",
            f"chown -R {nginx_webserver_user}:{nginx_webserver_group} /var/lib/php/modules",

            # session (sticky & writable)
            "mkdir -p /var/lib/php/session && chmod 1733 /var/lib/php/session",
            f"chown -R {nginx_webserver_user}:{nginx_webserver_group} /var/lib/php/session",

            # opcache (match session if you want disk-cache)
            "mkdir -p /var/lib/php/opcache && chmod 1733 /var/lib/php/opcache",
            f"chown -R {nginx_webserver_user}:{nginx_webserver_group} /var/lib/php/opcache",

            # wsdlcache
            "mkdir -p /var/lib/php/wsdlcache && chmod 1733 /var/lib/php/wsdlcache",
            f"chown -R {nginx_webserver_user}:{nginx_webserver_group} /var/lib/php/wsdlcache",
            
             "systemctl daemon-reload",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
                logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
                logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Ensure /etc/php/X.Y/mods-available is present
        command = f"mkdir -p /etc/php/{php_version}/mods-available"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
            logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
            logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Create .ini files if missing
        modules_map = {
            'curl':     'curl.so',
            'bz2':      'bz2.so',
            'ldap':     'ldap.so',
            'apcu':     'apcu.so',
            'gmp':      'gmp.so',
            'imagick':  'imagick.so',
            'bcmath':   'bcmath.so',
            'gd':       'gd.so',
            'soap':     'soap.so',
            'zip':      'zip.so',
            'mbstring': 'mbstring.so',
            'redis':    'redis.so',
            'xml':      'xml.so',
            'intl':     'intl.so',
        }

        for modname, sofile in modules_map.items():
            command = (
                f"if [ ! -f /etc/php/{php_version}/mods-available/{modname}.ini ]; then "
                f"echo 'extension={sofile}' > /etc/php/{php_version}/mods-available/{modname}.ini; "
                "fi"
            )
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
                logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
                logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # phpenmod each module for FPM
        for modname in modules_map.keys():
            command = f"phpenmod -v {php_version} -s fpm {modname}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
                logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
                logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Restart php-fpm
        command = f"systemctl restart php{php_version}-fpm"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
            logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
            logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check php -v
        command = "php -v"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
            logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
            logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})

        match = re.search(r'PHP (\d+\.\d+\.\d+)', output)
        if match:
            logger.info(f"PHP installed: {match.group(1)}", extra={'stepname': step})
        else:
            logger.error("Could not detect a valid PHP version from `php -v`.", extra={'stepname': step})
            return False

        # Restart nginx
        command = "systemctl restart nginx"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
            logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
            logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info("--> nginx is up and running.", extra={'stepname': step})

        if not proxmox_php_tuning_lxc(dictionary):
            return False
        if not proxmox_php_up_lxc(dictionary):
            return False
        if not proxmox_php_fpm_tuning_lxc(dictionary):
            return False
        if not proxmox_php_fpm_up_lxc(dictionary):
            return False
            
        logger.info("--> php is installed and up and running with nginx.", extra={'stepname': step})    
        return True            
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_tuning_lxc(dictionary):
    step='proxmox_php_tuning_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start tuning...", extra={'stepname': step})
 
        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_webserver_group',
            'nginx_webserver_user',
            'php_version',
            'php_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)    
        nginx_webserver_user  = dictionary.get('nginx_webserver_user')            
        nginx_webserver_group = dictionary.get('nginx_webserver_group')
        php_version           = dictionary.get('php_version') 
 
        # Check if required packages are installed
        php               = f"php{php_version}"
        required_packages = ['nginx', php]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('php_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload php configuration files.", extra={'stepname': step})
                return False

        # Restart service to apply the new configuration
        service = "nginx"
        if proxmox_service_operation_lxc(dictionary,service, 'restart', step):
           logger.info(f"{service} is tuned successfully and up and running.", extra={'stepname': step})
           return True
        else:
           logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
           return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_up_lxc(dictionary):
    step = 'proxmox_php_up_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start tuning...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'task_attributes',
            'nginx_webserver_group',
            'nginx_webserver_user',
            'php_version',
            'php_checks',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False
        
        # Retrieve variables (playbook or dictionary)    
        nginx_webserver_user  = dictionary.get('nginx_webserver_user')            
        nginx_webserver_group = dictionary.get('nginx_webserver_group')
        php_version           = dictionary.get('php_version') 

        # Check if required packages are installed
        php_service       = f"php{php_version}"
        required_packages = ['nginx', php_service, 'curl']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False        

        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('php_checks', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload php configuration files.", extra={'stepname': step})
                return False
                    
        # Basic checks
        php_service  = f"php{php_version}"
        service      = "nginx"        
        checks       = [
            # Verify php installed
            {
                'command':     f"php -v",
                'success':      f"{php_version}", 
                'error':        f"php version fialed",
                'description':  f"Check php version {php_version} successfull",
            },    
            {
                'command':      "php -i | grep 'Loaded Configuration File'",
                'success':      "",
                'error':        f"Error in {php_service} configuration file",
                'description':  f"Check {php_service} loaded configuration file",
                'allow_nonzero': True  # Allow nonzero exit if output is empty               
            },
            {
                'command':      "php /tmp/test.php",
                'success':      "PHP is up", 
                'error':        "Error executing PHP test script",
                'description':  f"Verifying that php is up by with {remote_path} ",
            },
            
            # Verify imagemagick ffmpeg exiftool installed       
            {
                'command':      "convert --version",
                'success':      "Version: ImageMagick", 
                'error':        "Error imagemagick do not return version",
                'description':  f"Verifying that imagemagick return version",
            },   
            {
                'command':      "ffmpeg -version",
                'success':      "ffmpeg version", 
                'error':        "Error ffmpeg do not return version",
                'description':  f"Verifying that ffmpeg return version",
            },
            {
                'command':      "exiftool -ver",
                'success':      ".", 
                'error':        "Error exiftool do not return version",
                'description':  f"Verifying that exiftool return version",
            },               

            # Verify opcache            
            {
                'command':      "php -r 'echo ini_get(\"opcache.enable\");'",
                'success':      "1", 
                'error':        "OpCache is not enabled",
                'description':  "Verifying opcache is on",
            },   
            {
                'command': "php -m | grep -i opcache",
                'success': "Zend OPcache",
                'error': "OPcache extension not loaded",
                'description': "Verify OPcache is listed in PHP modules",
            },
            {
                'command': "php -r 'print_r(opcache_get_status());'",
                'success': "[opcache_enabled] => 1",
                'error': "OPcache extension not enabled",
                'description': "Verify OPcache is enabled",
            },
            {
                'command':      "rm /tmp/test.php",
                'success':      "", 
                'error':        "/tmp/test.php not deleted",
                'description':  "Verifying that /tmp/test.php is deleted",
                'allow_nonzero': True  # Allow nonzero exit if output is empty
            },
            # Verify NGINX service is active
            {
                'command': "systemctl is-active nginx",
                'success': "active", 
                'error': "NGINX service is not active",
                'description': "Check NGINX service status",
            },
            # Verify session
            {
                'command': "php -r 'echo ini_get(\"session.save_path\");'",
                'success': "/var/lib/php/session",
                'error': "PHP session.save_path is not set to /var/lib/php/session",
                'description': "Check PHP session.save_path setting",
            },        
            # Session write permissions
            {
                'command': "[ -w /var/lib/php/session ] && echo OK",
                'success': "OK",
                'error': "/var/lib/php/session is not writable",
                'description': "Verify session directory is writable",
            },
            # Verify some php parms          
            {
                'command': "php -r 'echo ini_get(\"memory_limit\");'",
                'success': "M",
                'error': "PHP memory_limit is not set",
                'description': "Check PHP memory_limit setting",
            },
            {
                'command': "php -r 'echo ini_get(\"upload_max_filesize\");'",
                'success': "G",
                'error': "PHP upload_max_filesize is not set",
                'description': "Check PHP upload_max_filesize setting",
            },           
        ]
        
        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> php is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_fpm_tuning_lxc(dictionary):
    step = 'proxmox_php_fpm_tuning_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start tuning...", extra={'stepname': step})

        # Check required keys
        required_keys = [
            'php_version',
            'php_fpm_configs',
            "php_fpm_sock_path",
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        php_version           = dictionary.get('php_version') 
        php_fpm_sock_path     = dictionary.get('php_fpm_sock_path') 
        
        # Get the total memory of the VM
        command = "grep MemTotal /proc/meminfo"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})

        mem_total_kb                               = int(output.split()[1])
        mem_total_mb                               = mem_total_kb // 1024

        # Calculations based on available memory
        average_memory_per_child                   = 30  # Adjust as necessary
        php_fpm_pm_max_children                    = mem_total_mb // average_memory_per_child
        php_fpm_pm_start_servers                   = max(1, php_fpm_pm_max_children // 10)
        php_fpm_pm_min_spare_servers               = max(1, php_fpm_pm_max_children // 10)
        php_fpm_pm_max_spare_servers               = min(php_fpm_pm_max_children, php_fpm_pm_min_spare_servers * 4)
        php_fpm_pm_max_requests                    = 500

        dictionary['php_fpm_pm_max_children']      = php_fpm_pm_max_children
        dictionary['php_fpm_pm_start_servers']     = php_fpm_pm_start_servers
        dictionary['php_fpm_pm_min_spare_servers'] = php_fpm_pm_min_spare_servers
        dictionary['php_fpm_pm_max_spare_servers'] = php_fpm_pm_max_spare_servers
        dictionary['php_fpm_pm_max_requests']      = php_fpm_pm_max_requests

        # Check if required packages are installed
        php     = f"php{php_version}"
        php_fpm = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('php_fpm_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload redis configuration files.", extra={'stepname': step})
                return False

        # Create /run/php and symlink for nginx for the 1st start.       
        commands = [    
            # On reboot /run is a tmpfs add /etc/tmpfiles.d/php-fpm.conf to create /run/php and symlink for nginx
             
            # create dir for the 1st start
            f"mkdir -p /run/php", 
 
            # create log dir for php-fpm for the 1st start
            f"mkdir -p /var/log/php-fpm", 
            f"touch /var/log/php-fpm/php{php_version}-fpm.log",
            "chown -R www-data:www-data /var/log/php-fpm",
 
            # to apply it immediately without reboot:            
            "systemd-tmpfiles --create /etc/tmpfiles.d/php-fpm.conf",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: \n '{command}'.", extra={'stepname': step})
                logger.error(f"--> error  : \n '{error}'.", extra={'stepname': step})
                logger.error(f"--> output : \n '{output}'.", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})


        # Restart php-fpm to apply the changes
        service = f"php{php_version}-fpm"
        if proxmox_service_operation_lxc(dictionary, service, 'restart', step):
           logger.info("php-fpm is tuned successfully and up and running.", extra={'stepname': step})
           return True
        else:
           logger.error("Failed to restart php-fpm after tuning.", extra={'stepname': step})
           return False
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_php_fpm_up_lxc(dictionary):
    step = 'proxmox_php_fpm_up_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info("Start checks...", extra={'stepname': step})
        
        for key in ['php_fpm_log_path', 'php_fpm_sock_path', 'php_version', 'nginx_webserver_user']:
            if dictionary.get(key) is None:
                logger.error(f"Missing required parameter: {key}", extra={'stepname': step})
                return False
                
        # Check required keys
        required_keys = [
            'php_fpm_log_path',
            'php_fpm_sock_path',
            'php_version',
            'nginx_webserver_user'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        php_fpm_log_path      = dictionary.get('php_fpm_log_path')
        php_fpm_sock_path     = dictionary.get('php_fpm_sock_path')
        php_version           = dictionary.get('php_version') 
        nginx_webserver_user  = dictionary.get('nginx_webserver_user')
        nginx_webserver_group = dictionary.get('nginx_webserver_group')

        # Check if required packages are installed
        php               = f"php{php_version}"
        required_packages = ['nginx', php, 'curl']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False
                
        # Upload file in LXC
        files_to_upload = []
        for item in dictionary.get('php_fpm_checks', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload php configuration files.", extra={'stepname': step})
                return False

        # Basic checks        
        service = f"php{php_version}-fpm"
        checks = [
           # php-fpm checks
            {
                'command':     f"stat {php_fpm_sock_path}",
                'success':     f"File: {php_fpm_sock_path}",
                'error':       f"{service} unix socket not exits",
                'description': f"Check if {service} Unix socket exists",
            },           
            {
                'command':      f"systemctl status {service}",
                'success':      "active (running)",
                'error':       f"{service} is not running",
                'description': f"Check if {service} is up and running",
            },
            {
                'command':       f"grep 'ERROR' {php_fpm_log_path}",
                'success':       "",
                'error':         "Errors in php-fpm log",
                'description':   "Check if no error(s) in php-fpm log",
                'allow_nonzero': True
            },
            # nginx checks
            {
                'command':      "systemctl status nginx",
                'success':      "active (running)",
                'error':        "nginx is not running",
                'description':  "Check if nginx is up and running",
            },
            {
                'command':      "stat -c '%U:%G %a' /var/log/nginx",
                'success':      "root:adm 755",
                'error':        "Permission error in /var/log/nginx",
                'description':  "Check permissions for /var/log/nginx",
            },
            {
                'command':       "grep 'ERROR' /var/log/nginx/error.log",
                'success':       "",
                'error':         "Errors in nginx error log",
                'description':   "Check if no error(s) in nginx error log",
                'allow_nonzero': True
            },
            {
                'command':       "grep 'ERROR' /var/log/nginx/access.log",
                'success':       "",
                'error':         "Errors in nginx access log",
                'description':   "Check is no erro(s) in nginx access log",
                'allow_nonzero': True
            },
            {
                'command':       "grep 'Out of memory' /var/log/messages",
                'success':       "",
                'error':         "'Out of memory' errors in system logs",
                'description':   "Check if no 'Out of memory' in system logs",
                'allow_nonzero': True
            },
            # php checks
            {
                'command':       "php -v",
                'success':       "PHP",
                'error':         "PHP version error",
                'description':   "Check PHP version",
            },
            {
                'command':       "php -i | grep 'Loaded Configuration File'",
                'success':       "",
                'error':         "Error in PHP configuration file",
                'description':   "Check if PHP configuration file is loaded",
                'allow_nonzero': True
            },
            {
                'command':       "php -r 'echo ini_get(\"opcache.enable\");'",
                'success':       "1",
                'error':         "OpCache is not enabled",
                'description':   "Check if OpCache is on",
            },         
            # Health check PHP script
            {
                'command':       f"php /tmp/test.php",
                'success':        "All checks passed",
                'error':          "Error in health check test.php",
                'description':    "Check health check test.php",
            },
            {
                'command':       f"rm -f /tmp/test.php",
                'success':       "",
                'error':         f"/tmp/test.php not deleted",
                'description':   f"Verifying deletion of /tmp/test.php",
                'allow_nonzero': True
            },
        ]
        
        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['description']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_apache_remove_lxc(dictionary):
    step = 'proxmox_apache_remove_lxc'

    try:
        service = 'apache2'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info(f"Start {service} removal...", extra={'stepname': step})

        # Commands to remove all traces of Apache
        commands = [
            # Stop and disable the service
           f"systemctl stop {service} || true",
           f"systemctl disable {service} || true",
            
            # Purge Apache packages
           f"apt-get -y purge {service}* || true", 
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",
            "apt-get -y check || true",            
            
            # Remove configuration, log, and related directories/files
            "rm -rf /etc/apache2",                         # Apache configuration
            "rm -rf /var/log/apache2",                     # Apache logs
            "rm -rf /var/www/html",                        # Default web root (if exclusively used by Apache)
            "rm -rf /lib/systemd/system/apache2.service",  # Systemd service file
            "rm -rf /usr/sbin/apache2",                    # Apache binary
            "rm -rf /run/apache2",                         # Runtime files (socket, pid, etc.)
            
            "systemctl daemon-reload"
        ]
        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info("Apache removed successfully and all traces cleared.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_n8n_remove_lxc(dictionary):
    step = 'proxmox_n8n_remove_lxc'

    try:
        service = f"n8n"
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info(f"Start {service} removal...", extra={'stepname': step})
        
        commands = [
            # Stop and disable the service           
           f"systemctl stop {service} || true",
           f"systemctl disable {service} || true",   
            
            # Uninstall n8n from npm
           f"npm uninstall -g {service} || true",
            
            # Remove systemd service file
            "rm -f /etc/systemd/system/n8n.service || true",
            
            "systemctl daemon-reload",
            
            # Optionally remove nodejs (if you want a full cleanup)
            "apt-get -y purge nodejs || true",

            # Clean up
            "apt-get -y autoremove || true",
            "apt-get -y autoclean || true",
        ]
        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Failed to remove {service}:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})
        
        logger.info(f"{service} removed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_n8n_install_lxc(dictionary):
    step = 'proxmox_n8n_install_lxc'

    try:
        service = f"n8n"
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info(f"Start {service} installation...", extra={'stepname': step})
        
        # Remove any old n8n, if present
        if not proxmox_n8n_remove_lxc(dictionary):
            return False
 
        # Check if required packages are installed
        required_packages = ['nginx','postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Start install ...", extra={'stepname': step})    

        # Retrieve & validate play-book variables
        vars_section               = dictionary.get('task_attributes', {}).get('vars', {})
        required_keys              = (
            'n8n_host',
            'n8n_db_name',
        )
        for key in required_keys:
            if not vars_section.get(key):
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False

        n8n_host                   = vars_section['n8n_host']
        n8n_db_name                = vars_section['n8n_db_name']

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['n8n_host']     = n8n_host
        dictionary['n8n_db_name']  = n8n_db_name
 
        # List of commands to replicate the shell script
        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

            # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

            # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # Install dependencies
            "apt-get install -y curl sudo mc ca-certificates gnupg",
            
            # Prepare Node.js repository
            "mkdir -p /etc/apt/keyrings",
            "curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /etc/apt/keyrings/nodesource.gpg",
            (
                "echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] "
                "https://deb.nodesource.com/node_20.x nodistro main' "
                "> /etc/apt/sources.list.d/nodesource.list"
            ),
            "apt-get -y update",
            
            # Install Node.js
            "apt-get install nodejs -y",
            
            # Install n8n + patch-package globally
            "npm install -y --global patch-package",
           f"npm install -y --global {service}",
            
            # Clean up
            "apt-get -y autoremove",
            "apt-get -y autoclean",

        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command during n8n install:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})
       
        # Create DB        
        if not proxmox_pgsql_createdb_lxc(dictionary, n8n_db_name):
           return False
 
        # Tuning
        if not proxmox_n8n_tuning_lxc(dictionary):
           return False
 
        # Update nginx   
        if not proxmox_nginx_update_localhosts_lxc(dictionary):
           return False 
 
        # Check
        if not proxmox_n8n_up_lxc(dictionary):
           return False
  
        logger.info("--> n8n installed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_n8n_tuning_lxc(dictionary):
    step = 'proxmox_n8n_tuning_lxc'

    try:
      
        logger.info("Start tuning...", extra={'stepname': step})        
        
        service = f"n8n"        
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
 
        # Check if required packages are installed
        required_packages = ['nginx','postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        # Retrieve & validate play-book variables
        vars_section = dictionary.get('task_attributes', {}).get('vars', {})
        files        = vars_section.get('n8n_configs', [])
        
        if not files:
            logger.error("n8n_configs empty in the playbook.", extra={'stepname': step})
            return False         
        
        # Uplad files
        files_to_upload = []
        for item in files:
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload files.", extra={'stepname': step})
                return False

        # Reload and restart n8n to apply changes
        commands = [
            "systemctl daemon-reload",
            f"systemctl enable --now {service}",            
            f"systemctl restart {service}"
        ]
        for cmd in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, cmd, step)
            if not success:
                logger.error("Failed to tune or restart n8n:", extra={'stepname': step})
                logger.error(f"--> command : '{cmd}'", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {cmd}", extra={'stepname': step})

        logger.info("n8n tuning completed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_n8n_up_lxc(dictionary):
    step = 'proxmox_n8n_up_lxc'

    try: 
        service = f"n8n"
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = ['nginx','postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False

        logger.info("Checking n8n health...", extra={'stepname': step})
        
        # Basic checks  
        checks = [
            {
                'command':     f"systemctl status {service}",
                'success':      "active (running)",
                'error':       f"{service} service not running",
                'description': f"Check if {service} service is active"
            },
            {
                # By default, n8n listens on port 5678. Adjust if you've changed this port.
                'command':      "curl -I --max-time 5 http://127.0.0.1:5678",
                'success':      "HTTP",
                'error':       f"{service} is not responding on port 5678",
                'description': f"Check {service} HTTP response on localhost:5678"
            },
        ]
        
        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> {service} is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_keepalived_remove_lxc(dictionary):
    step = 'proxmox_keepalived_remove_lxc'

    try:
        service = 'keepalived'

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        logger.info(f"Start remove {service} ...", extra={'stepname': step})

        commands = [
            # Stop and disable the service
            f"systemctl stop {service} || true",
            f"systemctl disable {service} || true",

            # Remove package
            "apt-get -y clean",
            "apt-get -y update",
            f"apt-get -y purge {service} || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",

            # Remove configuration directories and files
            f"rm -rf /etc/{service}",
            f"rm -rf /usr/local/etc/{service}",
            f"rm -rf /usr/local/sbin/{service}",
            f"rm -rf /var/run/{service}.pid",

            "systemctl daemon-reload",
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check if required packages are removed
        required_packages = [service]
        for pkg in required_packages:
            if proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not removed.")
                return False
        else:
            logger.info(f"'{service}' removed successfully.", extra={'stepname': step})
            return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_keepalived_install_lxc(dictionary):
    step = 'proxmox_keepalived_install_lxc'

    try:
        service            = 'keepalived'
        package            = 'keepalived' 
        pgsql_package      = 'postgresql'
        ftp_package        = 'vsftpd'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Remove any existing keepalived installation first
        if not proxmox_keepalived_remove_lxc(dictionary):
            logger.error(f"Failed to remove existing {package} installation.", extra={'stepname': step})
            return False

        logger.info(f"Trying to install {package}...", extra={'stepname': step})

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            f"apt-get -y install {package}",
            f"systemctl enable {package}",
            
            "systemctl daemon-reload"
        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check if required packages are installed
        required_packages = [package]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={'stepname': step})
                return False
            else:
                logger.info(f"{package} installed successfully.", extra={'stepname': step})

        # Tuning and check service
        # If 'vsftpd' is installed
        if proxmox_is_package_installed_lxc(dictionary, ftp_package):
             logger.info(f"Package {ftp_package} is installed. Continued tuning and check...", extra={'stepname': step})        
             if not proxmox_keepalived_vsftpd_tuning_lxc(dictionary):
                return False
             if not proxmox_keepalived_vsftpd_up_lxc(dictionary):
                return False

        # if 'postgresql' is installed
        elif proxmox_is_package_installed_lxc(dictionary, pgsql_package):
            logger.info(f"Package {pgsql_package} is installed. Continued tuning and check...", extra={'stepname': step})
            if not proxmox_keepalived_pgsql_tuning_lxc(dictionary):
               return False
            if not proxmox_keepalived_pgsql_up_lxc(dictionary):
               return False

        # If neither is installed, log an error
        else:
            logger.error(f"Complementary package (like {ftp_package} or {pgsql_package}) not found.", extra={'stepname': step})
            return False

        # Status
        if not proxmox_service_status_lxc(dictionary, service):
           return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_keepalived_pgsql_tuning_lxc(dictionary):
    step = 'proxmox_keepalived_pgsql_tuning_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'task_attributes',
            'pgsql_server_version',
            'keepalived_pgsql_configs',
            'pgsql_node01_ip',
            'pgsql_node02_ip',            
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables        
        pgsql_server_version  = dictionary.get('pgsql_server_version')
        pgsql_node01_ip       = dictionary.get('pgsql_node01_ip')  
        pgsql_node02_ip       = dictionary.get('pgsql_node02_ip')    
        
        service               = 'keepalived'
        package               = 'keepalived'
        pgsql_package         = 'postgresql'
        pgsql_service         = f"postgresql@{pgsql_server_version}-main"  

        
        # Get the name of the node
        success, container_name = proxmox_get_name_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current name for container {container_id}.", extra={'stepname': step})
           return False

        if not container_name:
           logger.error(f"Unable to obtain current name for container {container_id}.", extra={'stepname': step})
           return False
           
        # determine the node's state MASTER or BACKUP by it's name
        if 'node01' in container_name:
            pgsql_node_id       = 1
            keepalived_state    ='MASTER'
            pgsql_host_folow_ip = pgsql_node02_ip
        else:
            pgsql_node_id       = 2
            keepalived_state    ='BACKUP'
            pgsql_host_folow_ip = pgsql_node01_ip

        # Get the container_id
        container_id = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False

        # Get the IP address of the node
        success, container_ip = proxmox_get_ip_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current IP address for container {container_id}.", extra={'stepname': step})
           return False

        if not container_ip:
           logger.error(f"Unable to obtain current IP address for container {container_id}.", extra={'stepname': step})
           return False 

        # Get the name of the node
        success, container_name = proxmox_get_name_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current name for container {container_id}.", extra={'stepname': step})
           return False

        if not container_name:
           logger.error(f"Unable to obtain current name for container {container_id}.", extra={'stepname': step})
           return False 

        # Store into the dictionary for Jinja2 substitution usage        
        dictionary['keepalived_state']    = keepalived_state 
        
        dictionary['pgsql_host_ip']       = container_ip
        dictionary['pgsql_host_name']     = container_name
        dictionary['pgsql_host_node_id']  = pgsql_node_id
        dictionary['pgsql_host_folow_ip'] = pgsql_host_folow_ip
        
        # Check if required packages are installed
        required_packages = [service, pgsql_package]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Prepare file upload
        files_to_upload = []
        keepalived_remote_check = None
        for item in dictionary.get('keepalived_pgsql_configs', []):
            if item.get('install'):
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                files_to_upload.append((os.path.normpath(local_path), remote_path))

        # Upload the files
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                return False
                
        # Set permissions for scripts
        for _, remote_path in files_to_upload:
            if remote_path.endswith('.sh'):
                commands = [
                    f"chown root:root {remote_path}",
                    f"chmod 0700 {remote_path}",         # 700 includes +x for the owner
                ]
                for command in commands:
                    success, error, output = proxmox_command_for_lxc(dictionary, command, step)
                    if not success:
                        logger.error("Failed to set permissions:", extra={'stepname': step})
                        logger.error(f"--> command: '{command}'", extra={'stepname': step})
                        logger.error(f"--> output: '{output}'", extra={'stepname': step})
                        logger.error(f"--> error: '{error}'", extra={'stepname': step})
                        return False
                    else:
                        logger.info(f"Executed: {command}", extra={'stepname': step})          

        # Restart keepalived to apply changes
        if not proxmox_service_operation_lxc(dictionary, service, 'restart', step):
            logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
            return False
        logger.info(f"{service} is tuned successfully and up and running.", extra={'stepname': step})

        # Restart pgsql_service to apply changes
        if not proxmox_service_operation_lxc(dictionary, pgsql_service, 'restart', step):
            logger.error(f"Failed to restart {pgsql_service} after tuning.", extra={'stepname': step})
            return False

        logger.info(f"{pgsql_service} is tuned successfully and up and running.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_keepalived_pgsql_up_lxc(dictionary):
    step = 'proxmox_keepalived_pgsql_up_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_server_version',
            'pgsql_vip',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        vip                   = dictionary.get('pgsql_vip')
        pgsql_server_version  = dictionary.get('pgsql_server_version')
        service               =  'keepalived'
        package               =  'keepalived'
        pgsql_package         =  'postgresql'
        pgsql_service         = f"postgresql@{pgsql_server_version}-main"     

        # Check if required packages are installed
        required_packages = [service, pgsql_package]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        logger.info("Start check...", extra={'stepname': step})

        # Basic checks
        checks = [
            {
                'command':     f"systemctl status {service}",
                'success':     "active (running)",
                'error':       f"{service} is not running",
                'description': f"Check if {service} is up and running",
            },
            {
                'command':      f"ip addr show | grep -q 'inet {vip}'",
                'success':      "",
                'error':        "VIP assignment error",
                'description':  "Checking VIP assignment",
                'allow_nonzero': True
            },
            {
                'command':     f"systemctl status {pgsql_service}",
                'success':     "active (running)",
                'error':       f"{pgsql_service} is not running",
                'description': f"Check if {pgsql_service} is up and running",
            },
            {
                'command':      "netstat -tuln | grep -q ':21 '",
                'success':      "",
                'error':        "No pgsql port listening",
                'description':  "Checking pgsql port listening",
                'allow_nonzero': True
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"--> '{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_keepalived_vsftpd_tuning_lxc(dictionary):
    step = 'proxmox_keepalived_ftp_tuning_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'keepalived_ftp_configs',
            'ftp_keepalived_configs',            
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables        
        service               = 'keepalived'
        package               = 'keepalived'
        ftp_package           = 'vsftpd'
        ftp_service           = 'vsftpd'  

        # Get the name of the node
        success, container_name = proxmox_get_name_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current name for container {container_id}.", extra={'stepname': step})
           return False

        if not container_name:
           logger.error(f"Unable to obtain current name for container {container_id}.", extra={'stepname': step})
           return False
           
        # determine the node's state MASTER or BACKUP by it's name
        if 'node01' in container_name:
            keepalived_state ='MASTER'
        else:
            keepalived_state ='BACKUP' 

        # Store into the dictionary for Jinja2 substitution usage        
        dictionary['keepalived_state']                 = keepalived_state 

        # Check if required packages are installed
        required_packages = [service, ftp_package]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Prepare file upload
        files_to_upload = []
        keepalived_remote_check = None
        for item in dictionary.get('keepalived_ftp_configs', []):
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                files_to_upload.append((os.path.normpath(local_path), remote_path))

        # Upload the files
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                return False
                
        # Set permissions for scripts
        for _, remote_path in files_to_upload:
            if remote_path.endswith('.sh'):
                commands = [
                    f"chown root:root {remote_path}",
                    f"chmod 0770 {remote_path}",
                    f"chmod +x {remote_path}",
                ]
                for command in commands:
                    success, error, output = proxmox_command_for_lxc(dictionary, command, step)
                    if not success:
                        logger.error("Failed to set permissions:", extra={'stepname': step})
                        logger.error(f"--> command: '{command}'", extra={'stepname': step})
                        logger.error(f"--> output: '{output}'", extra={'stepname': step})
                        logger.error(f"--> error: '{error}'", extra={'stepname': step})
                        return False
                    else:
                        logger.info(f"Executed: {command}", extra={'stepname': step})

        # Restart keepalived to apply changes
        if not proxmox_service_operation_lxc(dictionary, service, 'restart', step):
            logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
            return False
        logger.info(f"{service} is tuned successfully and up and running.", extra={'stepname': step})

        # Restart ftp_service to apply changes
        if not proxmox_service_operation_lxc(dictionary, ftp_service, 'restart', step):
            logger.error(f"Failed to restart {ftp_service} after tuning.", extra={'stepname': step})
            return False

        logger.info(f"{ftp_service} is tuned successfully and up and running.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_keepalived_vsftpd_up_lxc(dictionary):
    step = 'proxmox_keepalived_ftp_up_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'ftp_vip',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables        
        vip                = dictionary.get('ftp_vip')
        service            = 'keepalived'
        package            = 'keepalived'
        ftp_package        = 'vsftpd'
        ftp_service        = 'vsftpd'        

        # Check if required packages are installed
        required_packages = [service, ftp_package]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        logger.info("Start check...", extra={'stepname': step})

        # Basic checks
        checks = [
            {
                'command':     f"systemctl status {service}",
                'success':     "active (running)",
                'error':       f"{service} is not running",
                'description': f"Check if {service} is up and running",
            },
            {
                'command':      f"ip addr show | grep -q 'inet {vip}'",
                'success':      "",
                'error':        "VIP assignment error",
                'description':  "Checking VIP assignment",
                'allow_nonzero': True
            },
            {
                'command':     f"systemctl status {ftp_service}",
                'success':     "active (running)",
                'error':       f"{ftp_service} is not running",
                'description': f"Check if {ftp_service} is up and running",
            },
            {
                'command':      "netstat -tuln | grep -q ':21 '",
                'success':      "",
                'error':        "No FTP port listening",
                'description':  "Checking FTP port listening",
                'allow_nonzero': True
            },
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_remove_lxc(dictionary):
    step = 'proxmox_pgsql_remove_lxc'

    try:
            
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False         

        # Check that required keys are present
        required_keys = [
            'task_attributes',
            'pgsql_data_dir',                         
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        pgsql_data_dir = dictionary.get('pgsql_data_dir')

        commands = [
            "systemctl daemon-reload",

            # Stop PostgreSQL
            "systemctl stop postgresql || true",  # Allow command to fail
            "systemctl disable postgresql || true",   

            # Remove packages
            "apt-get -y clean",
            "apt-get -y update",
            
            # Purge PostgreSQL and related packages
            "DEBIAN_FRONTEND=noninteractive apt-get -y purge 'postgresql-*' || true",
            "apt-get -y autoremove || true",
            "apt-get -y clean || true",

            # Clean up files and directories
            "rm -rf /var/lib/postgresql",
            f"rm -rf {pgsql_data_dir}",
            "rm -rf /etc/postgresql",
            "rm -rf /var/log/postgresql",
            "rm -rf /usr/share/postgresql",
            "rm -rf /usr/lib/postgresql",
            "rm -rf /run/postgresql",
            
            "systemctl daemon-reload"
        ]
        
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output: '{output}'", extra={'stepname': step})
                logger.error(f"--> error: '{error}'", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check if required packages are removed
        required_packages = ['postgresql', 'postgresql-client']
        for pkg in required_packages:
            if proxmox_is_package_installed_lxc(dictionary, pkg):
               logger.error(f"Required package '{pkg}' is not removed.")
               return False        

        logger.info(f"PostgreSQL removed successfully.", extra={'stepname': step})
        return True        

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_install_lxc(dictionary):
    step = 'proxmox_pgsql_install_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Remove existing PostgreSQL installation
        if not proxmox_pgsql_remove_lxc(dictionary):
            logger.error("Failed to remove existing PostgreSQL installation.", extra={'stepname': step})
            return False

        # Check required keys
        required_keys = [
            'task_attributes',
            'pgsql_server_version',
            'pgsql_log_file',
            'pgsql_vip',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_data_dir',
            'proxmox_host_arch'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        pgsql_log_file            = dictionary.get('pgsql_log_file')
        pgsql_host                = dictionary.get('pgsql_host')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_data_dir            = dictionary.get('pgsql_data_dir')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        proxmox_host_arch         = dictionary.get('proxmox_host_arch')
        
        package_postgresql_client =  "postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"
        
        # Get packages to install from task attributes
        package_to_install = dictionary['task_attributes'].get('vars', {}).get('package_to_install')
        if not package_to_install:
            logger.warning("No postgresql_package_to_install specified", extra={'stepname': step})
            return False

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            "apt-get -y install curl gpg gpgconf apt-transport-https ca-certificates",
            "update-ca-certificates",
            
            # Make sure we can run 'lsb_release -cs' successfully
            "apt-get -y install lsb-release",

            # Download and store the PGDG signing key
            "curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor > /usr/share/keyrings/pgdg.gpg",

            # Use lsb_release to create the correct repo line, e.g. 'bookworm-pgdg'
            f"bash -c \"echo 'deb [arch={proxmox_host_arch} signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main' > /etc/apt/sources.list.d/pgdg.list\" ",

            # Update apt sources to include the new repository
            "apt-get -y update",
        ]
   
        # ----------------------------------------------------------------------
        # PostgreSQL client installation
        # ---------------------------------------------------------------------- 
        if package_to_install == 'postgresql-client':
                logger.info("Installing PostgreSQL client...", extra={'stepname': step})
                commands.extend([
                   f"apt -y install {package_postgresql_client}",
                ])

                # Execute commands
                for command in commands:
                    success, error, output = proxmox_command_for_lxc(dictionary, command, step)
                    if not success:
                        logger.error(f"Command failed: {command}", extra={'stepname': step})
                        logger.error(f"Output: {output}", extra={'stepname': step})
                        logger.error(f"Error: {error}", extra={'stepname': step})
                        return False

                    logger.info(f"Executed: {command}", extra={'stepname': step})

                # Check if required package is installed
                required_packages = [package_postgresql_client]
                for pkg in required_packages:
                    if not proxmox_is_package_installed_lxc(dictionary, pkg):
                        logger.error(f"Required package '{pkg}' is not installed.")
                        return False
                
                # Post-install configuration

                # Create .pgpass
                if not proxmox_pgsql_create_pgpass_lxc(dictionary):
                   logger.error("PostgreSQL .pgpass failed to create", extra={'stepname': step})
                   return False   

                # Verify pgsql-server connectivity
                if not proxmox_pgsql_up_lxc(dictionary):
                   logger.error(f"{package_postgresql_client} with pgsql-server connectivity failed", extra={'stepname': step})
                   return False
                
                # Verify DBA connectivity
                if not proxmox_pgsql_dba_up_lxc(dictionary):
                   logger.error(f"{package_postgresql_client} with DBA connectivity failed", extra={'stepname': step})
                   return False

                # Test to create 'dbtest' and drop it 
                db_dbname = 'dbtest'
                if not proxmox_pgsql_createdb_lxc(dictionary, db_dbname):
                   logger.error(f"Failled to create {db_dbname} with {package_postgresql_client}", extra={'stepname': step})
                   return False
                if not proxmox_pgsql_dropdb_lxc(dictionary, db_dbname):
                   logger.error(f"Failled to check mysql with {package_postgresql_client}", extra={'stepname': step})
                   return False
                   
                # Run sql_files defined in vars
                if not proxmox_pgsql_excute_sql_files_lxc(dictionary):
                   logger.error(f"Failled to check sqlfile(s) {package_postgresql_client}", extra={'stepname': step})
                   return False

                logger.info(f"{package_postgresql_client} installed successfully", extra={'stepname': step})
                return True
                
        # ----------------------------------------------------------------------
        # PostgreSQL server installation
        # ---------------------------------------------------------------------- 
        elif package_to_install in ('postgresql-server'):
            
                logger.info("Installing PostgreSQL server...", extra={'stepname': step})
                
                commands.extend([

                    # Install PostgreSQL packages
                    f"apt-get -y install software-properties-common postgresql-{pgsql_server_version} postgresql-contrib-{pgsql_server_version}",

                    # Verify package actually installed
                    f"dpkg -l postgresql-{pgsql_server_version} >/dev/null 2>&1",

                    # Stop service before configuration
                    "systemctl stop postgresql",
                    "sleep 5",

                    # Ensure log file directory
                    f"mkdir -p $(dirname {pgsql_log_file})",
                    f"touch {pgsql_log_file}",
                    f"chown postgres:postgres {pgsql_log_file}",
                    f"chmod 640 {pgsql_log_file}",

                    # Add logrotate configuration
                    f"install -o postgres -g postgres -m 644 /dev/null /etc/logrotate.d/postgresql",

                    # Create and secure data directory
                    f"mkdir -p {pgsql_data_dir}",
                    f"chown -R postgres:postgres {pgsql_data_dir}",
                    f"chmod -R 700 {pgsql_data_dir}",

                    # Update postgresql.conf to point to that directory
                    f"sed -i -e \"s|data_directory =.*|data_directory = '{pgsql_data_dir}'|g\" /etc/postgresql/{pgsql_server_version}/main/postgresql.conf",

                    # PostgreSQL-specific initialization with initdb
                    f"su - postgres -c '/usr/lib/postgresql/{pgsql_server_version}/bin/initdb -D {pgsql_data_dir}'",

                    # Reload and enable service
                    "systemctl daemon-reload",
                    "systemctl enable postgresql",
                    "systemctl start postgresql",
                    "sleep 5",

                    # After service start
                    "pg_isready -U postgres -h 127.0.0.1 -p 5432 -t 10",

                    # Stop again before linking
                    "systemctl stop postgresql",
                    "sleep 5",

                    # Link for package compliance
                    f"ln -s {pgsql_data_dir} /var/lib/postgresql/{pgsql_server_version}/main",
                    f"rm -rf /var/lib/postgresql/{pgsql_server_version}/main/",

                    # /etc/postgresql/{pgsql_server_version}/main/     /opt/pgsql/
                    # ├── postgresql.conf                              ├── PG_VERSION
                    # ├── pg_hba.conf                                  ├── postgresql.auto.conf
                    # ├── pg_ident.conf                                ├── postmaster.opts
                    # ├── pg_ctl.conf                                  ├── postmaster.pid
                    # └── start.conf                                   ├── base/ (data files)
                    #                                                  ├── pg_wal/ 
                    #                                                  └── pg_log/
                    
                    f"rm -f {pgsql_data_dir}/pg_hba.conf {pgsql_data_dir}/pg_ident.conf {pgsql_data_dir}/postgresql.conf",

                    "systemctl start postgresql",
                    "sleep 5",
                ])

                # Execute commands
                for command in commands:
                    success, error, output = proxmox_command_for_lxc(dictionary, command, step)
                    if not success:
                        logger.error(f"Command failed: {command}", extra={'stepname': step})
                        logger.error(f"Output: {output}", extra={'stepname': step})
                        logger.error(f"Error: {error}", extra={'stepname': step})
                        return False
                    else:
                        logger.info(f"Executed: {command}", extra={'stepname': step})

                # Post-install configuration        

                # Check if required packages are installed
                required_packages = [package_postgresql_server]
                for pkg in required_packages:
                    if not proxmox_is_package_installed_lxc(dictionary, pkg):
                        logger.error(f"Required package '{pkg}' is not installed.")
                        return False
                        
                # Create .pgpass
                if not proxmox_pgsql_create_pgpass_lxc(dictionary):
                   logger.error("PostgreSQL .pgpass failed to create", extra={'stepname': step})
                   return False   

                # secure server 
                if not proxmox_pgsql_secure_lxc(dictionary):
                   logger.error("PostgreSQL secrure failed", extra={'stepname': step})
                   return False                 

                # Create dba
                if not proxmox_pgsql_create_dba_lxc(dictionary):
                   logger.error("PostgreSQL client connection failed", extra={'stepname': step})
                   return False            

                # Create 'dbtest' and drop it 
                db_dbname = 'dbtest'
                if not proxmox_pgsql_createdb_lxc(dictionary, db_dbname):
                   logger.error(f"Failled to create {db_dbname}.", extra={'stepname': step})
                   return False
                if not proxmox_pgsql_dropdb_lxc(dictionary, db_dbname):
                   logger.error(f"Failled to drop {db_dbname}.'.", extra={'stepname': step})
                   return False

                # Run sql_files defined in vars
                if not proxmox_pgsql_excute_sql_files_lxc(dictionary):
                   return False

                # Tune PostgreSQL server
                if not proxmox_pgsql_tuning_lxc(dictionary):
                   return False

                # Status
                if not proxmox_service_status_lxc(dictionary, service):
                   return False
                   
                logger.info("PostgreSQL server installed successfully", extra={'stepname': step})
                return True
        
        else:
            logger.error("Invalid package specification in the playbook.", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_up_lxc(dictionary):
    step = 'proxmox_pgsql_up_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_port',
            'pgsql_super_user',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_node01_ip',
            'pgsql_node02_ip',          
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')    
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        pgsql_vip                 = dictionary.get('pgsql_vip')   
        pgsql_node01_ip           = dictionary.get('pgsql_node01_ip')   
        pgsql_node02_ip           = dictionary.get('pgsql_node02_ip')               
 
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')     
        
        # Check if required packages are installed
        required_packages = ['postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False             

        # Basic checks
        
        if pgsql_host  == '127.0.0.1':
           # server access
            checks = [
                {
                    'command':     f"systemctl status {service}",
                    'success':      'active (running)',
                    'error':       f"{service} service inactive",
                    'description': f"Check if {service} is up and running",
                    'fatal':       True
                },
                {
                    'command':     f"ss -tuln | grep {pgsql_port}",
                    'success':      'LISTEN',
                    'error':        f"{service} port not listening.",
                    'description':  f"Checking {service} port listening.",
                    'fatal':        True
                },          
                {
                    'command':      f"pg_isready -U postgres -h {pgsql_host} -p {pgsql_port} -t 10",
                    'success':       'accepting connections',
                    'error':        f"{service} not accepting connections.",
                    'description':  f"Checking {service} accepting connections.",
                    'fatal':        True               
                },
                {
                    'command':      f"psql -U {pgsql_super_user} -c 'SELECT 1' ",
                    'success':       '1 row',                
                    'error':        f"{service} database connection failed.",
                    'description':  f"Checking {service} database connection successfully.",
                    'fatal':        True 
                },        
            ]
        else:
            # VIP / client checks
            checks = [
                {
                    'command':      f"ping -c 3 {pgsql_vip}",
                    'success':       '0% packet loss',
                    'error':        f"Cannot reach PostgreSQL node: {pgsql_vip}.",
                    'description':  f"Pinging PostgreSQL node {pgsql_vip}.",
                    'fatal':        True
                },
                # Check that .pgpass exists before using it
                {
                    'command':     "test -f /var/lib/postgresql/.pgpass && echo 'PGPASS_EXISTS'",
                    'success':     'PGPASS_EXISTS',
                    'error':       "Missing /var/lib/postgresql/.pgpass - cannot proceed with client test.",
                    'description': "Check if .pgpass file exists for client access",
                    'fatal':       True
                },
                # Check that /var/lib/postgresql/.pgpass is mode 600
                {
                    'command': (
                        "test \"$(stat -c '%a' /var/lib/postgresql/.pgpass)\" = '600' "
                        "&& echo 'PGPASS_PERMISSIONS_OK' || echo 'PGPASS_BAD_PERMISSIONS'"
                    ),
                    'success':     'PGPASS_PERMISSIONS_OK',
                    'error':       ".pgpass is not permission 0600. Postgres will ignore it.",
                    'description': "Check if .pgpass has correct permissions (0600).",
                    'fatal':       True
                },              
                # Then attempt the actual psql test with PGPASSFILE
                {
                    'command':     f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} -d postgres -c 'SELECT 1;'",
                    'success':     '1 row',
                    'error':       f"{service} database connection failed (client mode).",
                    'description': f"Checking {service} database connection successfully (VIP).",
                    'fatal':       True
                },
            ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # Basic presence check in output
            expected_substring = check['success']
            # If success is a string, look for that in 'output'
            if isinstance(expected_substring, str) and expected_substring:
                valid = (expected_substring in output)
            else:
                # If success is empty or None, fallback to "command must succeed"
                valid = success

            if not success or not valid:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Command: '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Error  : \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Output : \n '{output}'", extra={'stepname': step})
                overall_success = False

                if check.get('fatal', True):
                    logger.error("Critical failure - aborting checks", extra={'stepname': step})
                    return False

            else:
                logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info("--> All checks successful.", extra={'stepname': step})
            return True
        else:
            # for debug
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_secure_lxc(dictionary):
    step = 'proxmox_pgsql_secure_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')        
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        package_postgresql_server = f"postgresql-{pgsql_server_version}" 
        
        package_postgresql_client  = f"postgresql-client"
        package_postgresql_server  = f"postgresql-{pgsql_server_version}"
        service                    = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_server]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Upload pg_hba.conf
        files_to_upload = []
        for item in dictionary.get('pgsql_configs'):
            if item['install'] and item['name'] == 'pg_hba.conf':
                local_path  = item['local_conf']
                remote_path = item['remote_conf']
                files_to_upload.append((os.path.normpath(local_path), remote_path))

        # Upload the files via SFTP
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload pgsql_configs configuration files.", extra={'stepname': step})
                return False

        # Restart to apply changes
        if not proxmox_service_operation_lxc(dictionary, service, 'restart', step):
            logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
            return False

        # Check pgsql_super_user connectivity use LOCAL without password according to the pg_hba.conf (no localhost or 127.0.0.1) 
        command = f"psql -U {pgsql_super_user} -d postgres -c \"SELECT 1;\" "
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success or "ERROR" in output:
            logger.error(f"Command failed: {command}", extra={'stepname': step})
            logger.error(f"Output: {output}", extra={'stepname': step})
            return False       
        logger.info(f"Executed: {command}", extra={'stepname': step})

        if not "1" in output:
           logger.error(f"Failed connectivity with {pgsql_super_user} on postgresql {pgsql_host}.", extra={'stepname': step})
           return False 
        logger.info(f"--> Successfull connectivity with {pgsql_super_user} on postgresql {pgsql_host}.", extra={'stepname': step})

        # Add passord to pgsql_super_user use LOCAL without password according to the pg_hba.conf (no localhost or 127.0.0.1) 
        sql     = f"ALTER USER {pgsql_super_user} WITH PASSWORD '{pgsql_super_user_password}';"
        command = f"psql -U {pgsql_super_user} -d postgres -c \"{sql}\" "
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success or "ERROR" in output:
            logger.error(f"Command failed: {command}", extra={'stepname': step})
            logger.error(f"Output: {output}", extra={'stepname': step})
            return False       
        logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check pgsql_super_user connectivity with password and .pgpass according to the pg_hba.conf (with localhost or 127.0.0.1) 
        command = f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_super_user} -h {pgsql_host} -p {pgsql_port} -d postgres -c \"SELECT 1;\" "
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success or "ERROR" in output:
            logger.error(f"Command failed: {command}", extra={'stepname': step})
            logger.error(f"Output: {output}", extra={'stepname': step})
            return False       
        logger.info(f"Executed: {command}", extra={'stepname': step})

        if not "1" in output:
           logger.error(f"Failed connectivity with {pgsql_super_user} on postgresql {pgsql_host}.", extra={'stepname': step})
           return False 

        logger.info(f"--> pg_hba.conf updated, {pgsql_super_user} password created with .pgpass.", extra={'stepname': step})
        
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_create_pgpass_lxc(dictionary):
    step = 'roxmox_pgsql_create_pgpass_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        root_name                 = dictionary.get('root_name')
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')        
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        package_postgresql_server = f"postgresql-{pgsql_server_version}" 
        
        package_postgresql_client  = f"postgresql-client"
        package_postgresql_server  = f"postgresql-{pgsql_server_version}"
        service                    = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Upload .pgpass
        files_to_upload = []
        pgsql_configs   = dictionary.get('pgsql_configs')
        if pgsql_configs is None:
            logger.error("Missing 'pgsql_configs' in dictionary.", extra={'stepname': step})
            return False
        
        if not isinstance(pgsql_configs, list):
            logger.error("'pgsql_configs' should be a list.", extra={'stepname': step})
            return False       
            
        for item in pgsql_configs:
            if item.get('install') and item.get('name') == 'client.pgpass':
                local_path  = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if not local_path or not remote_path:
                    logger.error(f"Missing local_conf or remote_conf in pgsql_configs entry: {item}", extra={'stepname': step})
                    return False
                files_to_upload.append((os.path.normpath(local_path), remote_path))

        # Upload the files via SFTP
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload pgsql_configs configuration files.", extra={'stepname': step})
                return False

            # Set permissions
            commands = [
                f"chown {root_name}:{root_name} {remote_path}",
                f"chmod 0600 {remote_path}",
            ]
            for command in commands:  
                success, error, output = proxmox_command_for_lxc(dictionary, command, step)
                if not success:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command :   '{command}'", extra={'stepname': step})
                    logger.error(f"--> output  : \n'{output}'", extra={'stepname': step})
                    logger.error(f"--> error   : \n'{error}'", extra={'stepname': step})
                    return False
                logger.info(f"Executed: {command}", extra={'stepname': step})

            logger.info(f"--> .pgpass created.", extra={'stepname': step})        
            return True
        else:
            logger.error(f"Failed to create .pgpass", extra={'stepname': step})        
            return False           
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_tuning_lxc(dictionary):
    step = 'proxmox_pgsql_tuning_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        service                   = f"postgresql@{pgsql_server_version}-main"
        
        package_postgresql_client = "postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_server]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False

        # ----------------------------------------------------------------------
        # Dynamic Resource Calculation
        # ----------------------------------------------------------------------
        # Gather resource info

        # Total memory (in MB)
        command = "grep MemTotal /proc/meminfo"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to retrieve system memory.", extra={'stepname': step})
            return False
            
        total_mem_kb = int(output.split()[1])
        total_mem_mb = total_mem_kb // 1024
        
        # CPU cores
        command = "nproc"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to retrieve CPU cores.", extra={'stepname': step})
            return False
            
        cpu_cores = int(output.strip())
  
        # Default heuristics for an SSD-based system:
        parallel_io_limit              = cpu_cores * 2
        session_busy_ratio             = 0.20
        avg_parallelism                = 1

        computed_max_conns             = int(min(cpu_cores, parallel_io_limit) // (session_busy_ratio * avg_parallelism) )
        
        # Put an arbitrary upper bound to avoid unbounded concurrency (capped at 256)
        computed_max_conns             = min(computed_max_conns, 256)

        # shared_buffers: 25% of total RAM (capped at 8 GB)
        shared_buffers_mb              = min(int(total_mem_mb * 0.25), 8192)

        # maintenance_work_mem: 5% of total RAM (capped at 2 GB)
        maintenance_work_mem_mb        = min(int(total_mem_mb * 0.05), 2048)

        # effective_cache_size: ~70% of total RAM
        effective_cache_size_mb        = int(total_mem_mb * 0.70)

        # work_mem per connection:
        # here we assume we want to reserve "shared_buffers_mb" from total first,
        # then divide the remainder by (max_connections * some factor).
        # Tweak to taste; a factor of 3–4 or more is common so that not all 
        # connections exhaust memory simultaneously.
        available_for_work_mem_mb       = max(128, total_mem_mb - shared_buffers_mb)  # ensure non-trivial floor
        work_mem_mb                     = max(1, available_for_work_mem_mb // (computed_max_conns * 3))

        # concurrency & parallelism
        max_worker_processes            = cpu_cores * 2
        max_parallel_workers            = cpu_cores
        max_parallel_workers_per_gather = max(2, cpu_cores // 2)

        # fixed or example-based values
        effective_io_concurrency = 200
        wal_buffers_mb           = 16  # MB

        # Additional dynamic or recommended parameters for SSD-based systems
        # Adjust as desired
        random_page_cost   = 1.1
        seq_page_cost      = 1.0
        checkpoint_timeout = "15min"
        checkpoint_completion_target = 0.9
        wal_compression    = "on"
        temp_buffers_mb    = 32  # per-session
        default_stats      = 100

        # Log the computed values
        logger.info(f"total_mem_mb                    : {total_mem_mb}", extra={'stepname': step})
        logger.info(f"cpu_cores                       : {cpu_cores}", extra={'stepname': step})
        logger.info(f"computed_max_conns              : {computed_max_conns}", extra={'stepname': step})
        logger.info(f"shared_buffers_mb               : {shared_buffers_mb}", extra={'stepname': step})
        logger.info(f"maintenance_work_mem_mb         : {maintenance_work_mem_mb}", extra={'stepname': step})
        logger.info(f"effective_cache_size_mb         : {effective_cache_size_mb}", extra={'stepname': step})
        logger.info(f"work_mem_mb                     : {work_mem_mb}", extra={'stepname': step})
        logger.info(f"max_worker_processes            : {max_worker_processes}", extra={'stepname': step})
        logger.info(f"max_parallel_workers            : {max_parallel_workers}", extra={'stepname': step})
        logger.info(f"max_parallel_workers_per_gather : {max_parallel_workers_per_gather}", extra={'stepname': step})

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['pgsql_max_connections']                 = computed_max_conns
        dictionary['pgsql_shared_buffers']                  = f"{shared_buffers_mb}MB"
        dictionary['pgsql_maintenance_work_mem']            = f"{maintenance_work_mem_mb}MB"
        dictionary['pgsql_effective_cache_size']            = f"{effective_cache_size_mb}MB"
        dictionary['pgsql_work_mem']                        = f"{work_mem_mb}MB"
        dictionary['pgsql_max_worker_processes']            = max_worker_processes
        dictionary['pgsql_max_parallel_workers']            = max_parallel_workers
        dictionary['pgsql_max_parallel_workers_per_gather'] = max_parallel_workers_per_gather

        # Upload the tuned postgresql.conf (Jinja2 template) to the container
        files_to_upload = []
        for item in dictionary.get('pgsql_configs'):
            if item['install'] and item['name'] == 'postgresql.conf.tuned':
                local_path  = item['local_conf']
                remote_path = item['remote_conf']
                files_to_upload.append((os.path.normpath(local_path), remote_path))

        # Upload the files via SFTP
        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload mariadb_configs_server configuration files.", extra={'stepname': step})
                return False

        # Restart to apply changes
        if not proxmox_service_operation_lxc(dictionary, service, 'restart', step):
            logger.error(f"Failed to restart {service} after tuning.", extra={'stepname': step})
            return False

        logger.info(f"{service} restarted sucessfully after postgresql.conf modifications.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_create_dba_lxc(dictionary):
    step = 'proxmox_pgsql_create_dba_lxc'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_server_version'
        ]
        for key in required_keys:
            if not dictionary.get(key):
                logger.error(f"Missing or empty parameter: {key}", extra={'stepname': step})
                return False

        pgsql_super_user           = dictionary['pgsql_super_user']
        pgsql_super_user_password  = dictionary['pgsql_super_user_password']
        pgsql_dba_name             = dictionary['pgsql_dba_name']
        pgsql_dba_password         = dictionary['pgsql_dba_password']
        pgsql_port                 = dictionary['pgsql_port']
        pgsql_server_version       = dictionary.get('pgsql_server_version')
        
        package_postgresql_client  = f"postgresql-client"
        package_postgresql_server  = f"postgresql-{pgsql_server_version}"
        service                    = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_server]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False
           
        # ------------------------------------------------------------
        # Create new role: using superuser for role management
        queries_sql = [
           f"DROP ROLE IF EXISTS {pgsql_dba_name};",
           f"CREATE ROLE {pgsql_dba_name} WITH LOGIN SUPERUSER CREATEDB CREATEROLE;",
           f"ALTER ROLE {pgsql_dba_name} SET client_encoding TO 'UTF8';",
           f"ALTER ROLE {pgsql_dba_name} SET default_transaction_isolation TO 'read committed';",
           f"ALTER ROLE {pgsql_dba_name} SET timezone TO 'UTC';",
           f"ALTER USER {pgsql_dba_name} WITH PASSWORD '{pgsql_dba_password}';"
        ]

        for sql in queries_sql:        
            # Notice the use of pgsql_super_user (not the DBA role) to execute the commands.
            command = (
                f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_super_user} -h {pgsql_host} -p {pgsql_port} -d postgres -c \"{sql}\""
            )
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
                
            logger.info(f"Executed: {command}", extra={'stepname': step})    

        # ------------------------------------------------------------
        # Final test: verify that the DBA role can connect
        if not proxmox_pgsql_dba_up_lxc(dictionary):
            logger.error(f"Failed to verify {pgsql_dba_name} creation", extra={'stepname': step})
            return False

        logger.info(f"--> {pgsql_dba_name} created and verified successfully", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_dba_up_lxc(dictionary):
    step = 'proxmox_pgsql_dba_up_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        pgsql_vip                 = dictionary.get('pgsql_vip')   
        
        package_postgresql_client = f"postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Basic checks
        checks = [
            # Verify DBA connectivity
                {                      
                    'command':      f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} -d postgres -c \"SELECT 1;\" ",
                    'success':      f"1",                
                    'error':        f"Basic connection failed with {pgsql_dba_name} via {pgsql_host}.",
                    'description':  f"Checking Basic connection with {pgsql_dba_name} via {pgsql_host}.",
                    'fatal':        True 
                }   
        ]

        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # Custom validation for lambda functions
            if callable(check['success']):
                valid = check['success'](output)
            else:
                valid = check['success'] in output

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['description']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if not success or not valid:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Command: '{check['command']}'", extra={'stepname': step})                
                logger.error(f"--> Error  : \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Output : \n '{output}'", extra={'stepname': step})
                overall_success = False
                
                if check.get('fatal', True):
                    logger.error("Critical failure - aborting checks")                
                    return False

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"All checks successfull.", extra={'stepname': step})
            return True
        else:
            # for debug
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------   
def proxmox_pgsql_execute_sql_file_lxc(dictionary, sql_file):
    step = 'proxmox_pgsql_execute_sql_file_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        pgsql_vip                 = dictionary.get('pgsql_vip')  
        
        package_postgresql_client = f"postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False
                
        # Check if sql_file not empty
        if not sql_file:
            logger.error("Failed sql_file empty.", extra={'stepname': step})
            return False
            
        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False

        # Check if dba is up
        if not proxmox_pgsql_dba_up_lxc(dictionary):
           logger.error(f"postgresql failed to respond with {pgsql_dba_name}.", extra={'stepname': step})
           return False
           
        # Execute SQL file content    
        command =  f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} -d postgres -f \"{sql_file}\" "
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
            
        logger.info(f"Executed: {command}", extra={'stepname': step})
        
        # First check explicitly defined success indicators
        if "USER_AND_DATABASE_CREATION_SUCCESS" in output or "TABLE_CREATION_SUCCESS" in output:
            logger.info("SQL execution succeeded explicitly.", extra={'stepname': step})
            return True, error, output

        # Explicitly check for known fatal errors
        elif any(kw in output for kw in ["ERROR", "FATAL", "could not connect"]) \
                or any(kw in error for kw in ["ERROR", "FATAL", "could not connect"]):
            logger.error(f"SQL execution failed explicitly: {error}", extra={'stepname': step})
            return False, error, output

        # Treat PostgreSQL notices as benign if explicit success indicator is present
        elif "NOTICE" in error or "warning" in error.lower():
            logger.warning(f"Non-critical notices/warnings encountered: {error}", extra={'stepname': step})
            return True, error, output

        # Fallback case, ambiguous output
        else:
            logger.warning(f"Ambiguous SQL execution result. Manual verification recommended. Output: {output}, Error: {error}", extra={'stepname': step})
            return False, error, output    

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False   

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_excute_sql_files_lxc(dictionary):
    step = 'proxmox_pgsql_excute_sql_files_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Gather the 'sql_files' list from task attributes        
        sql_files = dictionary['task_attributes'].get('vars', {}).get('sql_files', [])           
        if not sql_files:
           logger.warning("No sql_files specified in the playbook.", extra={'stepname': step})
           return False

        # Now we can safely loop over sql_files
        files_to_upload = []
        for item in sql_files:
            local_path  = item.get('local_path')
            remote_path = item.get('remote_path')
            if local_path and remote_path:
               files_to_upload.append((os.path.normpath(local_path), remote_path))
            else:
                logger.error("Failed to upload file:", extra={'stepname': step})
                logger.error(f"--> local_path : '{local_path}'.", extra={'stepname': step})
                logger.error(f"--> remote_path: '{remote_path}'.", extra={'stepname': step})
                return False            
            
            # Upload the files via SFTP
            if files_to_upload:
                if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                    logger.error("Failed to upload sql files.", extra={'stepname': step})
                    return False

            success, error, output = proxmox_pgsql_execute_sql_file_lxc(dictionary, remote_path)    
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> sql file: '{remote_path}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed sql file: '{remote_path}'.", extra={'stepname': step})

            # cleaning
            command = f"rm -f {remote_path},"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        return True 
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False  

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_createdb_lxc(dictionary, db_dbname):
    step = 'proxmox_pgsql_createdb_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')        
        pgsql_server_version      = dictionary.get('pgsql_server_version')               
        
        package_postgresql_client = f"postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False
                
        # Check if db_dbname not empty
        if not db_dbname:
            logger.error("Failed db_dbname empty.", extra={'stepname': step})
            return False
            
        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False

        # Check if dba is up
        if not proxmox_pgsql_dba_up_lxc(dictionary):
           logger.error(f"postgresql failed to respond with {pgsql_dba_name}.", extra={'stepname': step})
           return False

        # Create the database
        queries_sql = [
           f"DROP DATABASE IF EXISTS {db_dbname};",
           f"CREATE DATABASE {db_dbname};",
           f"GRANT ALL PRIVILEGES ON DATABASE {db_dbname} TO {pgsql_dba_name};",
        ]

        for sql in queries_sql:        
            command = ( f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} -d postgres -c \"{sql}\" " )
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
                
            logger.info(f"Executed: {command}", extra={'stepname': step})     
                        
        # Check if db_dbname exists
        if not proxmox_pgsql_database_up_lxc(dictionary, db_dbname):
            logger.error(f"Failed to create database {db_dbname}.", extra={'stepname': step})
            return False
            
        logger.info(f"Database {db_dbname} created successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False      

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_query_sql_lxc(dictionary, query_sql):
    step = 'proxmox_pgsql_query_sql_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')        
        pgsql_server_version      = dictionary.get('pgsql_server_version')               
        
        package_postgresql_client = f"postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False
                
        # Check if query_sql not empty
        if not query_sql:
            logger.error("Failed query_sql empty.", extra={'stepname': step})
            return False
            
        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False

        # Check if dba is up
        if not proxmox_pgsql_dba_up_lxc(dictionary):
           logger.error(f"postgresql failed to respond with {pgsql_dba_name}.", extra={'stepname': step})
           return False

        # Sanitize SQL query
        safe_query = query_sql.replace('"', '\\"')
        
        # Execute the query_sql
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' "
                   f"psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} "
                   f"-d postgres -c \"{safe_query}\"")
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})              
   
        logger.info(f"SQL query {query_sql} executed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_dropdb_lxc(dictionary, db_dbname):
    step = 'proxmox_pgsql_dropdb_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')        
        pgsql_server_version      = dictionary.get('pgsql_server_version')               
        
        package_postgresql_client = f"postgresql-client"
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        package_postgresql_client = f"postgresql-client-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False

        # Check if dba is up
        if not proxmox_pgsql_dba_up_lxc(dictionary):
           logger.error(f"postgresql failed to respond with {pgsql_dba_name}.", extra={'stepname': step})
           return False

        # Drop the specified database
        sql     = f"DROP DATABASE IF EXISTS {db_dbname};"
        command = ( f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} -d 'postgres' -c \"{sql}\" " )
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Verify deletion        
        if not proxmox_pgsql_database_up_lxc(dictionary, db_dbname):
           return False
        else:        
           return True
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_database_up_lxc(dictionary, db_dbname):
    step = 'proxmox_pgsql_database_up_lxc'

    try:

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_super_user',
            'pgsql_super_user_password',
            'pgsql_host',
            'pgsql_port',
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_server_version'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_super_user          = dictionary.get('pgsql_super_user')
        pgsql_super_user_password = dictionary.get('pgsql_super_user_password')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')        
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_port                = dictionary.get('pgsql_port')        
        pgsql_server_version      = dictionary.get('pgsql_server_version')            
        
        package_postgresql_client = f"postgresql-client"        
        package_postgresql_server = f"postgresql-{pgsql_server_version}"
        service                   = f"postgresql@{pgsql_server_version}-main"       
        
        # Decide if we connect locally or via VIP
        if proxmox_is_package_installed_lxc(dictionary, package_postgresql_server):
            pgsql_host = '127.0.0.1'
        else:
            pgsql_host = dictionary.get('pgsql_vip')    

        # Check if required packages are installed
        required_packages = [package_postgresql_client]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False
                
        # Check if db_dbname not empty
        if not db_dbname:
            logger.error("Failed db_dbname empty.", extra={'stepname': step})
            return False
            
        # Check if pgsql up
        if not proxmox_pgsql_up_lxc(dictionary):
           logger.error("postgresql failed to respond.", extra={'stepname': step})
           return False

        # Check if dba is up
        if not proxmox_pgsql_dba_up_lxc(dictionary):
           logger.error(f"postgresql failed to respond with {pgsql_dba_name}.", extra={'stepname': step})
           return False

        # Drop the specified database
        sql     = f"SELECT 1 FROM pg_database WHERE datname='{db_dbname}';"
        command = ( f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} -h {pgsql_host} -p {pgsql_port} -d postgres -c \"{sql}\" " )
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})
        
        return True
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_repmgr_remove_lxc(dictionary):
    step = 'proxmox_repmgr_remove_lxc'

    try:
        service = 'repmgrd'
        package = 'repmgr'

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        commands = [
            f"systemctl stop {service} || true",
            f"systemctl disable {service} || true",
            f"apt-get -y purge {package} || true",
            "rm -rf /etc/repmgr || true",
            "rm -rf /var/log/repmgr || true",

            "apt-get -y autoremove",
            "apt-get -y autoclean",
            
            "systemctl daemon-reload",        
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Failed to remove {package}:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"{package} removed successfully.", extra={'stepname': step})
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_repmgr_install_lxc(dictionary):
    step = 'proxmox_repmgr_install_lxc'
    
    # https://www.repmgr.org
    
    try:
        service = 'repmgrd'
        package = 'repmgr'

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Remove existing PostgreSQL installation
        if not proxmox_repmgr_remove_lxc(dictionary):
            logger.error(f"Failed to remove existing {service} installation.", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = ['postgresql']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        commands = [
            # Refresh package index – no confirmation prompt is ever needed here
            "apt-get -y update",

             # Apply available upgrades non-interactively
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",

             # Remove orphaned dependencies & clean cache
            "apt-get -y autoremove",
            "apt-get clean",

            # install package
            f"apt-get -y install {package}",
            
            "systemctl daemon-reload",
            
            # Fix /etc/repmgr           
            "mkdir -p /etc/repmgr",
            "chown -R postgres:postgres /etc/repmgr",
            
            # Fix Runtime
            "mkdir -p /run/repmgr",
            "chown postgres:postgres /run/repmgr",
            "chmod 0755 /run/repmgr",
            
            # Fix log
            "mkdir -p /var/log/repmgr",
            "chown -R postgres:postgres /var/log/repmgr",
            "chmod 0755 /var/log/repmgr",      

        ]
        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Failed to install {package}:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Tuning
        if not proxmox_repmgr_tuning_lxc(dictionary):
           return False

        # Check
        if not proxmox_repmgr_up_lxc(dictionary):
           return False

        # Status
        if not proxmox_service_status_lxc(dictionary, service):
           return False

        logger.info(f"{package} successfully installed.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_repmgr_tuning_lxc(dictionary):
    step = 'proxmox_repmgr_tuning_lxc'

    try:
        service = 'repmgrd'
        package = 'repmgr'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = [package, 'postgresql']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        # Validate required parameters
        required_keys = [
            'task_attributes',
            'repmgr_configs',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        
        # Get the container_id
        container_id = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False
        
        # Get the pgsql_node_id
        pgsql_node_id = dictionary['task_attributes'].get('pgsql_node_id', [])  
        if not pgsql_node_id:
            logger.error("No pgsql_node_id provided in the playbook.", extra={'stepname': step})
            return False

        # Get the IP address of the node
        success, container_ip = proxmox_get_ip_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current IP address for container {container_id}.", extra={'stepname': step})
           return False

        if not container_ip:
           logger.error(f"Unable to obtain current IP address for container {container_id}.", extra={'stepname': step})
           return False   

        # Get the name of the node
        success, container_name = proxmox_get_name_lxc(dictionary)
        if not success:
           logger.error(f"Failed to obtain current name for container {container_id}.", extra={'stepname': step})
           return False

        if not container_name:
           logger.error(f"Unable to obtain current name for container {container_id}.", extra={'stepname': step})
           return False   

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['repmgr_node_id']    = pgsql_node_id
        dictionary['repmgr_node_name']  = container_name
        dictionary['repmgr_node_ip']    = container_ip

        # Execute SQL files (repmgr DB setup)
        if not proxmox_pgsql_excute_sql_files_lxc(dictionary):
            logger.error("Failed to execute repmgr database setup SQL file(s).", extra={'stepname': step})
            return False

        # Check if 'repmgr' database exists 
        db_dbname = 'repmgr'
        if not proxmox_pgsql_database_up_lxc(dictionary, db_dbname):
           logger.error("Database 'repmgr' does not exist after setup.", extra={'stepname': step})
           return False                
  
        # Check connection to 'repmgr' database exists
        conninfo    = f"host={container_ip} user=repmgr dbname=repmgr connect_timeout=2"
        command     = f"su - postgres -c \"psql '{conninfo}' -c 'SELECT 1;'\""
        command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
        success, error, output = proxmox_command(dictionary, command_lxc, step)
        if not "1 row" in output:
           logger.error("Failed to connect with user=repmgr on dbname=repmgr.", extra={'stepname': step})
           return False        

        # upload .conf .service and follow.sh promote.sh required scripts
        files_to_upload = []
        for item in dictionary.get('repmgr_configs', []):
            if item.get('install'):
                local_path = item['local_conf']
                remote_path = item['remote_conf']
                files_to_upload.append((os.path.normpath(local_path), remote_path))

        if files_to_upload:
            if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
                logger.error("Failed to upload repmgr configuration files.", extra={'stepname': step})
                return False

        commands = [
            "chown -R postgres:postgres /etc/repmgr",
            "systemctl daemon-reload",
           f"systemctl enable {service}",
        ]

        for command in commands:
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error(f"Failed during {package} tuning:", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info(f"{package} tuning completed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_repmgr_up_lxc(dictionary):
    step = 'proxmox_repmgr_up_lxc'

    try: 
        service = 'repmgrd'
        package = 'repmgr'
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Check if required packages are installed
        required_packages = [package, 'postgresql']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False

        logger.info("Checking repmgr health...", extra={'stepname': step})
        
        # Basic checks  
        checks = [
            {
                'command':     f"systemctl status {service}",
                'success':      "active (running)",
                'error':       f"{service} service not running",
                'description': f"Check if {service} service is active"
            },
            {
                'command':     f"pg_isready -U repmgr -d repmgr",
                'success':      "accepting connections",
                'error':       f"{service} service not accepting connections",
                'description': f"Check if {service} service accepting connections"
            },            
            {
                'command':     f"repmgr node check --role=primary || repmgr node check --role=standby",
                'success':      "is connected",
                'error':       f"{service} service not connected",
                'description': f"Check if {service} service is connected"
            },           
        ]
        
        overall_success = True
        for check in checks:
            success, error, output = proxmox_command_for_lxc(dictionary, check['command'], step)

            # If a command fails but was allowed to be non-zero with no output, skip. Otherwise, handle error.
            if not success and check.get('allow_nonzero') and not output.strip():
                logger.info(f"Executed: {check['command']}", extra={'stepname': step})
                continue

            # If a specific string is expected in output and not found
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['error']}", extra={'stepname': step})
                logger.error(f"--> Error:   \n '{error}'", extra={'stepname': step})
                logger.error(f"--> Command: \n '{check['command']}'", extra={'stepname': step})
                logger.error(f"--> Output:  \n '{output}'", extra={'stepname': step})
                overall_success = False
                continue

            logger.info(f"Executed: {check['description']}", extra={'stepname': step})

        if overall_success:
            logger.info(f"'{service}' is up and running.", extra={'stepname': step})
            return True
        else:
            logger.warning("One or more health checks failed.", extra={'stepname': step})
            logger.info("Collecting debug information...", extra={'stepname': step})

            # Collect systemctl status for debugging
            command = f"systemctl status {service}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            logger.info(f"--> command :   '{command}'", extra={'stepname': step})
            logger.info(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.info(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_ha_install(dictionary):
    step = 'proxmox_pgsql_ha_install'

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_node01_container_id',
            'pgsql_node02_container_id',
            'pgsql_node01_ip',
            'pgsql_node02_ip',
            'pgsql_node01_name',
            'pgsql_node02_name',
            'pgsql_port',
            'pgsql_server_version',
            'pgsql_data_dir'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_node01_container_id = dictionary.get('pgsql_node01_container_id')
        pgsql_node02_container_id = dictionary.get('pgsql_node02_container_id') 
        pgsql_node01_ip           = dictionary.get('pgsql_node01_ip')
        pgsql_node02_ip           = dictionary.get('pgsql_node02_ip')        
        pgsql_node01_name         = dictionary.get('pgsql_node01_name')
        pgsql_node02_name         = dictionary.get('pgsql_node02_name')           
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_server_version      = dictionary.get('pgsql_server_version')
        pgsql_conf_path           = f"/etc/postgresql/{pgsql_server_version}/main/postgresql.conf"
        pgsql_data_dir            = dictionary.get('pgsql_data_dir')

        # Disable keepalived on both nodes to avoid interference during setup
        for container_id in [pgsql_node01_container_id, pgsql_node02_container_id]:
            for cmd in ['systemctl stop keepalived || true', 'systemctl disable keepalived || true']:
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(cmd)}"
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not success:
                    logger.error(f"Failed to run: {cmd} on container {container_id}", extra={'stepname': step})
                    logger.error(f"--> output: {output}", extra={'stepname': step})
                    logger.error(f"--> error : {error}", extra={'stepname': step})
                    return False
                logger.info(f"Executed: {cmd}", extra={'stepname': step})

        # loop on both node
        for container_id in [pgsql_node01_container_id, pgsql_node02_container_id]:

            # Check if PostgreSQL package is installed
            required_package = ['postgresql', 'repmgr']
            pkg_check_cmd    = "apt list --installed"
            command_lxc      = f"pct exec {container_id} -- bash -c {shlex.quote(pkg_check_cmd)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success or not any(pkg in output for pkg in required_package):
                logger.error(f"Required package '{required_package}' is not installed.", extra={'stepname': step})
                return False

            # Before starting PostgreSQL, ensure the archive directory exists
            archive_dir = f"/var/lib/postgresql/{pgsql_server_version}/main/archive"
            setup_archive_cmds = [
                f"mkdir -p {archive_dir}",
                f"chown postgres:postgres {archive_dir}",
                f"chmod 700 {archive_dir}"
            ]

            for cmd in setup_archive_cmds:
                cmd_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(cmd)}"
                success, error, output = proxmox_command(dictionary, cmd_lxc, step)
                if not success:
                    logger.error(f"Failed to prepare archive directory: {cmd}", extra={'stepname': step})
                    logger.error(f"--> output: {output}", extra={'stepname': step})
                    logger.error(f"--> error : {error}", extra={'stepname': step})
                    return False
                logger.info(f"Prepared archive dir with: {cmd}", extra={'stepname': step})

            # Configure PostgreSQL for Replication on both node
            commands = [        
            f"sed -i -e \"s|#wal_level.*|wal_level                   = replica |g\" {pgsql_conf_path}",
            f"sed -i -e \"s|#wal_log_hints.*|wal_log_hints                = on|g\" {pgsql_conf_path}",   
            f"sed -i -e \"s|#archive_mode.*|archive_mode                = on|g\" {pgsql_conf_path}",        
            f"sed -i -e \"s|#archive_command.*|archive_command              = 'cp %p /var/lib/postgresql/{pgsql_server_version}/main/archive/%f'|g\" {pgsql_conf_path}",        
            f"sed -i -e \"s|#max_wal_senders.*|max_wal_senders             = 10|g\" {pgsql_conf_path}",         
            f"sed -i -e \"s|#max_replication_slots.*|max_replication_slots       = 10|g\" {pgsql_conf_path}",   
            f"sed -i -e \"s|#wal_keep_size.*|wal_keep_size               = 64MB|g\" {pgsql_conf_path}",
            f"sed -i -e \"s|#hot_standby.*|hot_standby                                  = on|g\" {pgsql_conf_path}",
            f"sed -i -e \"s|#shared_preload_libraries.*|shared_preload_libraries           = 'repmgr'|g\" {pgsql_conf_path}",  
            ]           
            
            for command in commands:
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(command)}"
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not success:
                    logger.error("Failed to execute command:", extra={'stepname': step})
                    logger.error(f"--> command :   '{command_lxc}'", extra={'stepname': step})
                    logger.error(f"--> output  : \n'{output}'", extra={'stepname': step})
                    logger.error(f"--> error   : \n'{error}'", extra={'stepname': step})
                    return False
                else:
                    logger.info(f"Executed: {command_lxc}", extra={'stepname': step})


            # Restart PostgreSQL server on both node and check
            checks = [
                {
                    'command':     f"systemctl restart postgresql",
                    'success':      '',
                    'error':       f"Failed to restart postgresql on container id {container_id}",
                    'description': f"Restart postgresql on container id {container_id}",
                },
                {
                    'command':     f"systemctl status postgresql@{pgsql_server_version}-main",
                    'success':      'active (running)',
                    'error':        f"Postgresql on container id {container_id} service inactive",
                    'description':  f"Postgresql on container id {container_id} is up and running",
                },
                {
                    'command':     f"ss -tuln | grep {pgsql_port}",
                    'success':      'LISTEN',
                    'error':        f"Postgresql on container id {container_id} port not listening.",
                    'description':  f"Postgresql on container id {container_id} port listening.",
                },              
            ]

            for check in checks:
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(check['command'])}"
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not check['success'] in output:
                    logger.error(f"Check failed: {check['description']}", extra={'stepname': step})
                    logger.error(f"--> command: {command_lxc}", extra={'stepname': step})
                    logger.error(f"--> output : \n{output}", extra={'stepname': step})
                    logger.error(f"--> error  : \n{error}", extra={'stepname': step})
                    return False
                
                logger.info(f"{check['description']} succeeded", extra={'stepname': step})


        # Promote primary node (node01) and register it  --------------------------------------------------
        logger.info("Registering primary node...", extra={'stepname': step})
        
        command     = f"su - postgres -c \"PGPASSFILE='/var/lib/postgresql/.pgpass' repmgr -f '/etc/repmgr/repmgr.conf' primary register -S postgres \" "
        command_lxc = f"pct exec {pgsql_node01_container_id} -- bash -c {shlex.quote(command)}"
        success, error, output = proxmox_command(dictionary, command_lxc, step)
        if not "registered" not in output.lower():
            logger.error(f"Primary node registration failed on node {pgsql_node01_container_id}", extra={'stepname': step})
            logger.error(f"--> command: {command_lxc}", extra={'stepname': step})
            logger.error(f"--> output : {output}", extra={'stepname': step})
            logger.error(f"--> error  : {error}", extra={'stepname': step})
            return False

        # Verify cluster status
        command = f"su - postgres -c \"PGPASSFILE='/var/lib/postgresql/.pgpass' repmgr -f /etc/repmgr/repmgr.conf cluster show \" "
        command_lxc = f"pct exec {pgsql_node01_container_id} -- bash -c {shlex.quote(command)}"
        success, error, output = proxmox_command(dictionary, command_lxc, step)
        if not success or "* running" not in output or "primary" not in output:
            logger.error("Cluster check after primary registration failed.", extra={'stepname': step})
            logger.error(f"command: {command_lxc}, output: {output}, error: {error}", extra={'stepname': step})
            return False
        logger.info("Primary node operational and verified.", extra={'stepname': step})       


        # Prepare standby node (node02) for cloning      --------------------------------------------------
        logger.info("Preparing standby node for cloning...", extra={'stepname': step})

        standby_prep_commands = [
            # stop standby clone        
            f"systemctl stop postgresql@{pgsql_server_version}-main",
            
            # delete datadir
            f"rm -rf {pgsql_data_dir}/*",

            # clone
            f"su - postgres -c \"repmgr -h {pgsql_node01_ip} -U repmgr -d repmgr -f /etc/repmgr/repmgr.conf standby clone --force \" ",            
            
            # restart standby clone
            f"systemctl start postgresql@{pgsql_server_version}-main",

            # register as standby clone
            f"su - postgres -c \"repmgr -f /etc/repmgr/repmgr.conf standby register --force\" ",
        ]

        for cmd in standby_prep_commands:
            command_lxc = f"pct exec {pgsql_node02_container_id} -- bash -c {shlex.quote(cmd)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error(f"Standby preparation failed on node {pgsql_node02_container_id}", extra={'stepname': step})
                logger.error(f"--> command: {command_lxc}", extra={'stepname': step})
                logger.error(f"--> output : {output}", extra={'stepname': step})
                logger.error(f"--> error  : {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {cmd}", extra={'stepname': step})


        logger.info("Standby node registered successfully.", extra={'stepname': step})


        # loop on both node
        for container_id in [pgsql_node01_container_id, pgsql_node02_container_id]:

             # Restart repmgrd on both node and check
            checks = [
                {               
                    'command':     f"systemctl restart repmgrd",
                    'success':      '',
                    'error':       f"Failed to restart repmgrd on container id {container_id}",
                    'description': f"Restart repmgrd on container id {container_id}",
                },                
                {
                    'command':     f"systemctl status repmgrd",
                    'success':      'active (running)',
                    'error':        f"repmgrd on container id {container_id} service inactive",
                    'description':  f"repmgrd on container id {container_id} is up and running",
                },        
            ]

            for check in checks:
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(check['command'])}"
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not check['success'] in output:
                    logger.error(f"Check failed: {check['description']}", extra={'stepname': step})
                    logger.error(f"--> command: {command_lxc}", extra={'stepname': step})
                    logger.error(f"--> output : \n{output}", extra={'stepname': step})
                    logger.error(f"--> error  : \n{error}", extra={'stepname': step})
                    return False
                
                logger.info(f"{check['description']} succeeded", extra={'stepname': step})


        # Final check on primary node                    --------------------------------------------------
        standby_checks = [
            {
                'command':    f"systemctl status postgresql@{pgsql_server_version}-main",
                'success':     "active (running)",
                'error':      f"Standby PostgreSQL inactive on container id {pgsql_node02_container_id}",
                'description': "Standby PostgreSQL is running"
            },
            {
                'command':     f"ss -tuln | grep {pgsql_port}",
                'success':      "LISTEN",
                'error':       f"Standby PostgreSQL port {pgsql_port} not listening",
                'description':  "Standby PostgreSQL port is listening"
            },
            {
                'command':    f"systemctl status repmgrd",
                'success':     "active (running)",
                'error':       "repmgrd service inactive on standby node",
                'description': "repmgrd is running on standby node"
            },                
            {
                'command':     f"su - postgres -c \"PGPASSFILE='/var/lib/postgresql/.pgpass' repmgr -f /etc/repmgr/repmgr.conf cluster show\" ",
                'success':     f"{pgsql_node01_name} | primary | * running",
                'error':       f"{pgsql_node01_name} is not running as primary",
                'description': f"{pgsql_node01_name} is running as primary"
            },                
            {
                'command':     f"su - postgres -c \"PGPASSFILE='/var/lib/postgresql/.pgpass' repmgr -f /etc/repmgr/repmgr.conf cluster show\" ",
                'success':     f"{pgsql_node02_name} | standby |   running",
                'error':       f"{pgsql_node02_name} is not running as standby node",
                'description': f"{pgsql_node02_name} is running as standby node"
            }                          
            
        ]

        for check in standby_checks:
            command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(check['command'])}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if check['success'] not in output:
                logger.error(f"Health check failed: {check['description']}", extra={'stepname': step})
                logger.error(f"command: {command_lxc}, output: {output}, error: {error}", extra={'stepname': step})
                return False
            logger.info(f"{check['description']} passed.", extra={'stepname': step})


        # Re-enable keepalived on both nodes after successful HA setup
        for container_id in [pgsql_node01_container_id, pgsql_node02_container_id]:
            for cmd in ['systemctl enable keepalived || true', 'systemctl start keepalived || true']:
                command_lxc = f"pct exec {container_id} -- bash -c {shlex.quote(cmd)}"
                success, error, output = proxmox_command(dictionary, command_lxc, step)
                if not success:
                    logger.error(f"Failed to run: {cmd} on container {container_id}", extra={'stepname': step})
                    logger.error(f"--> output: {output}", extra={'stepname': step})
                    logger.error(f"--> error : {error}", extra={'stepname': step})
                    return False
                logger.info(f"Executed: {cmd}", extra={'stepname': step})

        return True
 
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_replication_up(dictionary):
    step = 'proxmox_pgsql_ha_replication_up'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_node01_ip',
            'pgsql_node02_ip',
            'nginx_node01_container_id'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_vip                 = dictionary.get('pgsql_vip')
        pgsql_node01_ip           = dictionary.get('pgsql_node01_ip')
        pgsql_node02_ip           = dictionary.get('pgsql_node02_ip')        
        pgsql_node01_container_id = dictionary.get('pgsql_node01_container_id')
        pgsql_node02_container_id = dictionary.get('pgsql_node02_container_id')
        nginx_node01_container_id = dictionary.get('nginx_node01_container_id')
        pgsql_port                = dictionary.get('pgsql_port', '5432')
        db_dbname                 = "dbtest"
        
        # -- Create DBtest on using pgsql_vip --
        queries_sql = [
           f"DROP DATABASE IF EXISTS {db_dbname};",
           f"CREATE DATABASE {db_dbname};",
           f"GRANT ALL PRIVILEGES ON DATABASE {db_dbname} TO {pgsql_dba_name};",
        ]
        for sql in queries_sql:
            command = (
               f"PGPASSFILE=/var/lib/postgresql/.pgpass "
               f"psql --no-password -U {pgsql_dba_name} -h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"{sql}\""
               )
            success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command :    '{command}'", extra={'stepname': step})
                logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # -- Verify DBtest exists on node01 using pgsql_vip --
        command = (
            f"PGPASSFILE=/var/lib/postgresql/.pgpass "
            f"psql --no-password -U {pgsql_dba_name} -h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\""
            )
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command :    '{command}'", extra={'stepname': step})
            logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})            
                        
        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found with IP {pgsql_vip}.", extra={'stepname': step})      
        else:
            logger.error(f"{db_dbname} not found with IP {pgsql_vip}.", extra={'stepname': step})
            return False 
        
        # -- Verify DBtest exists on node01 using pgsql_node01_ip --
        command = (
           f"PGPASSFILE=/var/lib/postgresql/.pgpass "
           f"psql --no-password -U {pgsql_dba_name} -h {pgsql_node01_ip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\""
           )
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})            
                        
        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found in node {pgsql_node01_ip}.", extra={'stepname': step})      
        else:
            logger.error(f"{db_dbname} not found in node {pgsql_node01_ip}.", extra={'stepname': step})
            return False 

        # -- Wait for replication (node01 -> node02) --
        time.sleep(15)        

        # -- Verify DBtest exists on node02 using pgsql_node02_ip --
        command = (
           f"PGPASSFILE=/var/lib/postgresql/.pgpass "
           f"psql --no-password -U {pgsql_dba_name} -h {pgsql_node02_ip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\""
           )
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})    
            
        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found on node {pgsql_node02_ip}.", extra={'stepname': step})
        else:
            logger.error(f"{db_dbname} not found on node {pgsql_node02_ip}.", extra={'stepname': step})
            return False 

        logger.info("Replication node01 -> node02 successfully checked.", extra={'stepname': step})
        return True

        # -- Drop DBtest using pgsql_vip --
        command = (
            f"PGPASSFILE=/var/lib/postgresql/.pgpass "
            f"psql --no-password -U {pgsql_dba_name} -h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"DROP DATABASE {db_dbname};\""
            )
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute drop command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step}) 

        # -- Verify DBtest exists using pgsql_vip --
        command = (
           f"PGPASSFILE=/var/lib/postgresql/.pgpass "
           f"psql --no-password -U {pgsql_dba_name} -h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\" "
           )
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})    

        if db_dbname in output:
            logger.error(f"{db_dbname} not found with IP {pgsql_vip}.Failover mismatch.", extra={'stepname': step})
            return False                  

        logger.info("Replication node01 -> node02 successfully checked.", extra={'stepname': step})

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_pgsql_ha_up(dictionary):
    step = 'proxmox_pgsql_ha_up'
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Validate required parameters
        required_keys = [
            'pgsql_dba_name',
            'pgsql_dba_password',
            'pgsql_vip',
            'pgsql_node01_ip',
            'pgsql_node02_ip',
            'nginx_node01_container_id'
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_dba_password        = dictionary.get('pgsql_dba_password')
        pgsql_vip                 = dictionary.get('pgsql_vip')
        pgsql_node01_ip           = dictionary.get('pgsql_node01_ip')
        pgsql_node02_ip           = dictionary.get('pgsql_node02_ip')        
        pgsql_node01_container_id = dictionary.get('pgsql_node01_container_id')
        pgsql_node02_container_id = dictionary.get('pgsql_node02_container_id')
        nginx_node01_container_id = dictionary.get('nginx_node01_container_id')
        pgsql_port                = dictionary.get('pgsql_port', '5432')
        db_dbname                 = "dbtest"
        
        # -- Create DBtest on using pgsql_vip --
        queries_sql = [
           f"DROP DATABASE IF EXISTS {db_dbname};",
           f"CREATE DATABASE {db_dbname};",
           f"GRANT ALL PRIVILEGES ON DATABASE {db_dbname} TO {pgsql_dba_name};",
        ]
        for sql in queries_sql:
            command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                       f"-h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"{sql}\"")
            success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command : '{command}'.", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
                logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
                return False
            else:
                logger.info(f"Executed: {command}", extra={'stepname': step})

        # -- Verify DBtest exists on node01 using pgsql_vip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})            
                        
        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found with IP {pgsql_vip}.", extra={'stepname': step})      
        else:
            logger.error(f"{db_dbname} not found with IP {pgsql_vip}.", extra={'stepname': step})
            return False 
        
        # -- Verify DBtest exists on node01 using pgsql_node01_ip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_node01_ip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})            
                        
        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found in node {pgsql_node01_ip}.", extra={'stepname': step})      
        else:
            logger.error(f"{db_dbname} not found in node {pgsql_node01_ip}.", extra={'stepname': step})
            return False 

        # -- Wait for replication (node01 -> node02) --
        time.sleep(30)        

        # -- Verify DBtest exists on node02 using pgsql_node02_ip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_node02_ip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})    
            
        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found on node {pgsql_node02_ip}.", extra={'stepname': step})
        else:
            logger.error(f"{db_dbname} not found on node {pgsql_node02_ip}.", extra={'stepname': step})
            return False 

        logger.info("Replication node01 -> node02 successfully checked.", extra={'stepname': step})
        return True











        # --  Stop pgsql_node01_container_id --
        command_stop = f"pct stop {pgsql_node01_container_id}"
        success, error, output = proxmox_command(dictionary, command_stop, step)
        if not success:
            logger.error("Failed to stop node01 container.", extra={'stepname': step})
            return False
        logger.info("Node01 container stopped successfully.", extra={'stepname': step})

        # -- Wait for Keepalived to switch node01 -> node02 --
        time.sleep(15)

        # -- Verify DBtest exists using pgsql_vip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})    

        if db_dbname in output:
            logger.info(f"Check   : {db_dbname} found with IP {pgsql_vip}.Replication up.", extra={'stepname': step})
        else:
            logger.error(f"{db_dbname} not found with IP {pgsql_vip}.Replication mismatch.", extra={'stepname': step})
            return False 

        # -- Drop DBtest using pgsql_vip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"DROP DATABASE {db_dbname};\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute drop command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step}) 

        # -- Verify DBtest exists using pgsql_vip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_vip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})    

        if db_dbname in output:
            logger.error(f"{db_dbname} not found with IP {pgsql_vip}.Failover mismatch.", extra={'stepname': step})
            return False        
        else:        
            logger.info(f"Check   : {db_dbname} found with IP {pgsql_vip}.HA up.", extra={'stepname': step})

        # --  restart pgsql_node01_container_id --
        command_stop = f"pct start {pgsql_node01_container_id}"
        success, error, output = proxmox_command(dictionary, command_stop, step)
        if not success:
            logger.error("Failed to stop node01 container.", extra={'stepname': step})
            return False
        logger.info("Node01 container stopped successfully.", extra={'stepname': step})

        # -- Wait for Keepalived to switch node01 -> node02 --
        time.sleep(30)  

        # -- Verify DBtest does not exist using pgsql_node01_ip --
        command = (f"PGPASSFILE='/var/lib/postgresql/.pgpass' psql -U {pgsql_dba_name} "
                   f"-h {pgsql_node01_ip} -p {pgsql_port} -d 'postgres' -c \"SELECT datname FROM pg_database;\"")
        success, error, output = proxmox_command_for_lxc_with_id(dictionary, command, nginx_node01_container_id, step)
        if not success:
            logger.error("Failed to execute verification command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        else:
            logger.info(f"Executed: {command}", extra={'stepname': step})    
            
        if db_dbname in output:
            logger.error(f"{db_dbname} not found with IP {pgsql_node01_ip}.Rewind mismatch.", extra={'stepname': step})
            return False        
        else:        
            logger.info(f"Check   : {db_dbname} found with IP {pgsql_vip}.Rewind up.", extra={'stepname': step})
            

        logger.info("Replication node01 -> node02 successfully checked.", extra={'stepname': step})

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_download_lxc(dictionary):
    step = 'proxmox_nextcloud_download_lxc'

    try:
        logger.info("Start nextcloud download...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'proxmox_archive',
            'nginx_webserver_html_path',
            'php_version',
            'pgsql_node01_container_id',   # only primary node
            'pgsql_vip',
            'pgsql_dba_name',
            'pgsql_port',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("No nextcloud_url provided in the playbook.", extra={'stepname': step})
            return False

        container_id               = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_node01_container_id  = dictionary.get('pgsql_node01_container_id') 
        if not pgsql_node01_container_id:
            logger.error("No pgsql_node01_container_id provided in the playbook.", extra={'stepname': step})
            return False

        proxmox_archive            = dictionary.get('proxmox_archive') 
        if not proxmox_archive:
            logger.error("No proxmox_archive provided in the playbook.", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("No php_version provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_vip                  = dictionary.get('pgsql_vip') 
        if not pgsql_vip:
            logger.error("No pgsql_vip provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_port                 = dictionary.get('pgsql_port') 
        if not pgsql_port:
            logger.error("No pgsql_port provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_dba_name             = dictionary.get('pgsql_dba_name') 
        if not pgsql_dba_name:
            logger.error("No pgsql_dba_name provided in the playbook.", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name          = match.group(1)
        nextcloud_db_name  = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        proxmox_archive           = dictionary.get('proxmox_archive')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_vip                 = dictionary.get('pgsql_vip')
        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_ssd}/log"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"
        
        # Optional unused param
        nextcloud_url_download    = dictionary.get('nextcloud_url_download')

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_db_name']        = site_name        

        # Check if required packages are installed
        php               = f"php{php_version}"
        php_fpm           = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm, 'postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False


        # ---------------------------------------------------------------------
        # Download process
        # ---------------------------------------------------------------------

        # -------------------------------------------------------------------
        # If nextcloud_html_root exists and is not empty, back it up
        # If it exists (whether empty or not), remove it (step 3).
        # If it doesn't exist, create it (step 2).
        # -------------------------------------------------------------------

        # Check if nextcloud_html_root is an existing directory
        command = f"test -d {nextcloud_html_root}"
        success, error, output = proxmox_command(dictionary, command, step)
        folder_exists = success  # If 'test -d' succeeded, the folder exists

        if folder_exists:
            # Check if it's non-empty
            command = f"ls -A {nextcloud_html_root} 2>/dev/null | wc -l"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to check if folder is empty.", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output: '{output}'", extra={'stepname': step})
                logger.error(f"--> error: '{error}'", extra={'stepname': step})
                return False

            try:
                file_count = int(output.strip())
            except ValueError:
                file_count = 0

            if file_count > 0:
                logger.info(f"{nextcloud_html_root} exists and is not empty. Starting backup...", extra={'stepname': step})
                
                # Call your existing backup function
                if not proxmox_nextcloud_backup_html_lxc(dictionary):
                    logger.error("nextcloud_backup_html(dictionary) failed.", extra={'stepname': step})
                    return False

            # Remove the old folder regardless of it being empty or not
            command = f"rm -rf {nextcloud_html_root}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to remove existing Nextcloud HTML folder before download.", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output: '{output}'", extra={'stepname': step})
                logger.error(f"--> error: '{error}'", extra={'stepname': step})
                return False
            logger.info(f"Removed old Nextcloud HTML folder: {nextcloud_html_root}", extra={'stepname': step})
        else:
            logger.info(f"{nextcloud_html_root} does not exist. Will create it fresh.", extra={'stepname': step})

        # (Re)create nextcloud_html_root
        command = f"mkdir -p {nextcloud_html_root}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to create nextcloud_html_root directory.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Created (fresh) Nextcloud HTML folder: {nextcloud_html_root}", extra={'stepname': step})

        # Also ensure log path exists
        command = f"mkdir -p {nextcloud_log_path}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to create Nextcloud log directory.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Ensured Nextcloud log directory: {nextcloud_log_path}", extra={'stepname': step})

        # -------------------------------------------------------------------
        # Download Nextcloud as defined in nextcloud_url_download
        # -------------------------------------------------------------------
        if not nextcloud_url_download:
            logger.error("No nextcloud_url_download provided in the playbook.", extra={'stepname': step})
            return False

        command = f"wget -O /tmp/nextcloud.zip {nextcloud_url_download}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to download Nextcloud.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info("Downloaded Nextcloud ZIP to /tmp/nextcloud.zip.", extra={'stepname': step})
            
        # -------------------------------------------------------------------
        # Check if the Nextcloud zip file exists after download
        # -------------------------------------------------------------------
        command = "if [ -f /tmp/nextcloud.zip ]; then echo 'NEXTCLOUD_ZIP_EXISTS'; else echo 'NEXTCLOUD_ZIP_NOT_FOUND'; fi"
        success, error, output = proxmox_command(dictionary, command, step)
        if 'NEXTCLOUD_ZIP_NOT_FOUND' in output:
            logger.error("Downloaded Nextcloud ZIP file is not found.", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output: '{output}'", extra={'stepname': step})
            logger.error(f"--> error: '{error}'", extra={'stepname': step})
            return False   
        logger.info("Verified Nextcloud ZIP exists in /tmp.", extra={'stepname': step})

        # -------------------------------------------------------------------
        # Extract Nextcloud in /tmp
        # -------------------------------------------------------------------
        command = "unzip -o /tmp/nextcloud.zip -d /tmp"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to unzip Nextcloud in /tmp.", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output: '{output}'", extra={'stepname': step})
            logger.error(f"--> error: '{error}'", extra={'stepname': step})
            return False
        logger.info("Unzipped Nextcloud in /tmp.", extra={'stepname': step})

        # -------------------------------------------------------------------
        # Check if /tmp/nextcloud/version.php exists
        # -------------------------------------------------------------------
        command = "if [ -f /tmp/nextcloud/version.php ]; then echo 'VERSION_FILE_EXISTS'; else echo 'VERSION_FILE_NOT_FOUND'; fi"
        success, error, output = proxmox_command(dictionary, command, step)
        if 'VERSION_FILE_NOT_FOUND' in output:
            logger.error("version.php not found in /tmp/nextcloud after unzip.", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output: '{output}'", extra={'stepname': step})
            logger.error(f"--> error: '{error}'", extra={'stepname': step})
            return False        
        logger.info("Nextcloud unzipped successfully in /tmp/nextcloud.", extra={'stepname': step})   

        # -------------------------------------------------------------------
        # Move the extracted files to the target directory
        # -------------------------------------------------------------------
        logger.info("Moving extracted Nextcloud files to the target directory...", extra={'stepname': step})
        command = f"mv /tmp/nextcloud/* {nextcloud_html_root}/"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to move Nextcloud files to the target directory.", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output: '{output}'", extra={'stepname': step})
            logger.error(f"--> error: '{error}'", extra={'stepname': step})
            return False
        logger.info(f"Nextcloud files moved to {nextcloud_html_root}.", extra={'stepname': step})

        # -------------------------------------------------------------------
        # Check that version.php was successfully moved
        # -------------------------------------------------------------------
        command = f"if [ -f {nextcloud_html_root}/version.php ]; then echo 'VERSION_FILE_EXISTS'; else echo 'VERSION_FILE_NOT_FOUND'; fi"
        success, error, output = proxmox_command(dictionary, command, step)
        if 'VERSION_FILE_NOT_FOUND' in output:
            logger.error("version.php file not found after moving files.", extra={'stepname': step})
            return False
        logger.info("version.php file found in the Nextcloud directory.", extra={'stepname': step})

        # -------------------------------------------------------------------
        # Extract version from version.php (optional)
        # -------------------------------------------------------------------
        version_file_path = f"{nextcloud_html_root}/version.php"
        command = rf"grep '\$OC_VersionString' {version_file_path}"
        success, error, output = proxmox_command(dictionary, command, step)
        if success and '$OC_VersionString' in output:
            # output typically has a line like: `$OC_VersionString = '25.0.0';`
            # We'll parse the right side of the '='
            version_line = output.strip()
            # Split on '=' and take the second part
            try:
                right_side = version_line.split("=", 1)[1].strip()
                # Example: "'25.0.0';"
                nextcloud_version = right_side.strip(';').strip(" '\"")
                logger.info(f"Nextcloud version: {nextcloud_version}.", extra={'stepname': step})
            except:
                logger.warning("Could not parse version from version.php line.", extra={'stepname': step})
        else:
            logger.error("Failed to grep version info from version.php.", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output: '{output}'", extra={'stepname': step})
            logger.error(f"--> error: '{error}'", extra={'stepname': step})
            return False

        # -------------------------------------------------------------------
        # Clean up installation files in /tmp
        # -------------------------------------------------------------------
        command = "rm -rf /tmp/nextcloud* /tmp/nextcloud.zip"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to remove temporary Nextcloud installation files in /tmp.", extra={'stepname': step})
            logger.error(f"--> command: '{command}'", extra={'stepname': step})
            logger.error(f"--> output: '{output}'", extra={'stepname': step})
            logger.error(f"--> error: '{error}'", extra={'stepname': step})
            return False
        logger.info(f"Cleaned up /tmp/nextcloud* files.", extra={'stepname': step})

        logger.info("Nextcloud download and setup completed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_backup_lxc(dictionary):
    step = 'proxmox_nextcloud_backup_html_lxc'
    
    try:
        logger.info("Start nextcloud backup html ...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'proxmox_archive',
            'nginx_webserver_html_path',
            'php_version',
            'pgsql_node01_container_id',   # only primary node
            'pgsql_vip',
            'pgsql_dba_name',
            'pgsql_port',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("No nextcloud_url provided in the playbook.", extra={'stepname': step})
            return False

        container_id               = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_node01_container_id  = dictionary.get('pgsql_node01_container_id') 
        if not pgsql_node01_container_id:
            logger.error("No pgsql_node01_container_id provided in the playbook.", extra={'stepname': step})
            return False

        proxmox_archive            = dictionary.get('proxmox_archive') 
        if not proxmox_archive:
            logger.error("No proxmox_archive provided in the playbook.", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("No php_version provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_vip                  = dictionary.get('pgsql_vip') 
        if not pgsql_vip:
            logger.error("No pgsql_vip provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_port                 = dictionary.get('pgsql_port') 
        if not pgsql_port:
            logger.error("No pgsql_port provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_dba_name             = dictionary.get('pgsql_dba_name') 
        if not pgsql_dba_name:
            logger.error("No pgsql_dba_name provided in the playbook.", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name          = match.group(1)
        nextcloud_db_name  = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        proxmox_archive           = dictionary.get('proxmox_archive')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_vip                 = dictionary.get('pgsql_vip')
        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_ssd}/log"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"
        
        # Optional unused param
        nextcloud_url_download    = dictionary.get('nextcloud_url_download')

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_db_name']        = site_name        

        # Check if required packages are installed
        php               = f"php{php_version}"
        php_fpm           = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm, 'postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False


        # ---------------------------------------------------------------------
        # Retore process for nextcloud_html_root
        # ---------------------------------------------------------------------

        # Ensure the backup directory exists or create it
        command = f"test -d {proxmox_archive}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            command = f"mkdir -p {proxmox_archive}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to create backup directory.", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> Output: \n {output}", extra={'stepname': step})
                logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
                return False
            logger.info(f"Created backup directory: {proxmox_archive}", extra={'stepname': step})

        # Verify nextcloud_html_root actually exists before zipping
        command = f"test -d {nextcloud_html_root}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error(f"HTML path does not exist: {nextcloud_html_root}", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"HTML path verified: {nextcloud_html_root}", extra={'stepname': step})

        # Generate backup name and zip entire folder
        timestamp             = datetime.datetime.now().strftime("%d%m%Y-%H%M")
        html_backup_filename  = f"nextcloud_html_backup_{site_name}_{timestamp}.zip"
        html_backup_filepath  = posixpath.join(proxmox_archive, html_backup_filename)

        # Note: -r = recursive, -q = quiet (optional), or keep it verbose
        command = f"zip -r {html_backup_filepath} {nextcloud_html_root}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to create zip archive of Nextcloud HTML folder.", extra={'stepname': step})
            logger.error(f"--> command :   '{command}'", extra={'stepname': step})
            logger.error(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Created archive: {html_backup_filepath}", extra={'stepname': step})

        # Validate that the newly created backup file actually exists
        command = f"test -f {html_backup_filepath}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Backup file not found right after creation.", extra={'stepname': step})
            logger.error(f"--> command :   '{command}'", extra={'stepname': step})
            logger.error(f"--> output  : \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error   : \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Validated backup file: {html_backup_filepath}", extra={'stepname': step})

        logger.info(f"Backup of {nextcloud_html_root} successfully executed.", extra={'stepname': step})
 
 
        # ---------------------------------------------------------------------
        # Retore process for extcloud_db_name
        # --------------------------------------------------------------------- 
        
        # Check if the database actually exists inside the container
        sql = f"SELECT 1 FROM pg_database WHERE datname='{nextcloud_db_name}';"
        command = (
            f"PGPASSFILE='/var/lib/postgresql/.pgpass' "
            f"psql -U '{pgsql_dba_name}' -h '{pgsql_vip}' -p '{pgsql_port}' "
            f"-d postgres -tAc \"{sql}\""
        )
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command : '{command}'.", extra={'stepname': step})
            logger.error(f"--> output  : '{output}'.", extra={'stepname': step})
            logger.error(f"--> error   : '{error}'.", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})     

        if output.strip() == "1":
            # Database exists, so do a pg_dump
            timestamp_db              = datetime.datetime.now().strftime("%d%m%Y-%H%M")
            db_backup_filename        = f"nextcloud_db_backup_{site_name}_{timestamp_db}.sql"
            
            # We'll write the .sql file into /tmp first
            db_backup_filepath_in_tmp = f"/tmp/{db_backup_filename}"

            # Then we'll move it to the same path as the host sees,
            # which is presumably the same 'proxmox_archive' path you used for HTML backup
            db_backup_filepath_final  = posixpath.join(proxmox_archive, db_backup_filename)

            # Dump the DB as the 'postgres' user into /tmp
            pg_dump_cmd = (
                f"su - postgres -c "
                f"'export PGPASSFILE=/var/lib/postgresql/.pgpass; "
                f"pg_dump {nextcloud_db_name}' | tee {db_backup_filepath_in_tmp} > /dev/null"
            )
            command_lxc = f"pct exec {pgsql_node01_container_id} -- bash -c {shlex.quote(pg_dump_cmd)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to create pg_dump of Nextcloud DB.", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'",           extra={'stepname': step})
                logger.error(f"--> error   : '{error}'",            extra={'stepname': step})
                return False
            logger.info(f"Created DB dump in LXC: {db_backup_filepath_in_tmp}", extra={'stepname': step})

            # Move that file to the final archive path *from inside the container*
            command     = f"mv {db_backup_filepath_in_tmp} {db_backup_filepath_final}"
            command_lxc = f"pct exec {pgsql_node01_container_id} -- bash -c {shlex.quote(command)}"
            success, error, output = proxmox_command(dictionary, command_lxc, step)
            if not success:
                logger.error("Failed to move DB dump file into archive path from inside container.", extra={'stepname': step})
                logger.error(f"--> command : '{command_lxc}'", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'",         extra={'stepname': step})
                logger.error(f"--> error   : '{error}'",          extra={'stepname': step})
                return False
            logger.info(f"DB dump moved to: {db_backup_filepath_final}", extra={'stepname': step})

            # Confirm the backup is visible on the Proxmox host
            command = f"test -f {db_backup_filepath_final}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("DB backup file not found right after mv.", extra={'stepname': step})
                logger.error(f"--> command:   {command}", extra={'stepname': step})
                logger.error(f"--> output  : '{output}'",     extra={'stepname': step})
                logger.error(f"--> error   : '{error}'",      extra={'stepname': step})
                return False
            logger.info(f"Validated DB backup file: {db_backup_filepath_final}", extra={'stepname': step})

            logger.info("PostgreSQL DB backup successfully executed via in-container mv.", extra={'stepname': step})
        else:
            logger.info("No Nextcloud DB found (or DB check command errored). Skipping PG backup...", extra={'stepname': step})


        logger.info(f"Backup of {nextcloud_html_root} successfully executed.", extra={'stepname': step})
        
        return True
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_restore_html_lxc(dictionary):
    step = 'proxmox_nextcloud_restore_html_lxc'
    
    try:
        logger.info("Start nextcloud restore html ...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'proxmox_archive',
            'nginx_webserver_html_path',
            'php_version',
            'pgsql_node01_container_id',   # only primary node
            'pgsql_vip',
            'pgsql_dba_name',
            'pgsql_port',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("No nextcloud_url provided in the playbook.", extra={'stepname': step})
            return False

        container_id               = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_node01_container_id  = dictionary.get('pgsql_node01_container_id') 
        if not pgsql_node01_container_id:
            logger.error("No pgsql_node01_container_id provided in the playbook.", extra={'stepname': step})
            return False

        proxmox_archive            = dictionary.get('proxmox_archive') 
        if not proxmox_archive:
            logger.error("No proxmox_archive provided in the playbook.", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("No php_version provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_vip                  = dictionary.get('pgsql_vip') 
        if not pgsql_vip:
            logger.error("No pgsql_vip provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_port                 = dictionary.get('pgsql_port') 
        if not pgsql_port:
            logger.error("No pgsql_port provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_dba_name             = dictionary.get('pgsql_dba_name') 
        if not pgsql_dba_name:
            logger.error("No pgsql_dba_name provided in the playbook.", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name          = match.group(1)
        nextcloud_db_name  = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        proxmox_archive           = dictionary.get('proxmox_archive')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        pgsql_dba_name            = dictionary.get('pgsql_dba_name')
        pgsql_port                = dictionary.get('pgsql_port')
        pgsql_vip                 = dictionary.get('pgsql_vip')
        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_ssd}/log"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"
        
        # Optional unused param
        nextcloud_url_download    = dictionary.get('nextcloud_url_download')

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_db_name']        = site_name        

        # Check if required packages are installed
        php               = f"php{php_version}"
        php_fpm           = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm, 'postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False


        # ---------------------------------------------------------------------
        # Retore process
        # ---------------------------------------------------------------------
        
        # Ensure archive directory exists
        command = f"test -d {proxmox_archive}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error(f"Backup directory does not exist: {proxmox_archive}", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False

        # Find the latest backup ZIP for this site_name
        # This command lists the ZIP files (sorted by modification time, newest first) and picks the first.
        command = (
            f"ls -t {posixpath.join(proxmox_archive, f'nextcloud_html_backup_{site_name}_*.zip')} 2>/dev/null "
            "| head -n 1"
        )
        success, error, output = proxmox_command(dictionary, command, step)
        if not success or not output.strip():
            logger.error("No Nextcloud HTML backup found to restore.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        last_backup_file = output.strip()

        logger.info(f"Latest backup file: {last_backup_file}", extra={'stepname': step})

        # Remove existing Nextcloud HTML folder before restore (optional: you could rename it instead)
        command = f"rm -rf {nextcloud_html_root}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to remove existing Nextcloud HTML folder before restore.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Removed old Nextcloud HTML folder: {nextcloud_html_root}", extra={'stepname': step})

        # Restore from ZIP. 
        #     The zip was created with 'zip -r <archive.zip> <nextcloud_html_root>',
        #     so it contains the folder named '{nextcloud_url}' inside.
        #     We extract to 'nginx_webserver_html_path' so the folder is re-created under that path.
        command = f"unzip -o {last_backup_file} -d {nginx_webserver_html_path}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to unzip the backup file.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Restored from {last_backup_file} into {nginx_webserver_html_path}", extra={'stepname': step})

        # Validate that nextcloud_html_root now exists after restore
        command = f"test -d {nextcloud_html_root}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("After restore, Nextcloud HTML folder not found.", extra={'stepname': step})
            logger.error(f"--> command:   {command}", extra={'stepname': step})
            logger.error(f"--> Output: \n {output}", extra={'stepname': step})
            logger.error(f"--> Error:  \n {error}", extra={'stepname': step})
            return False
        logger.info(f"Restore complete and folder verified: {nextcloud_html_root}", extra={'stepname': step})

        logger.info("Nextcloud HTML restore succeeded.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_create_db_lxc(dictionary):
    step = 'nextcloud_create_db'

    try:
        logger.info("Start nextcloud create DB...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'proxmox_archive',
            'nginx_webserver_html_path',
            'php_version',
            'pgsql_node01_container_id',   # only primary node
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("No nextcloud_url provided in the playbook.", extra={'stepname': step})
            return False

        container_id               = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_node01_container_id  = dictionary.get('pgsql_node01_container_id') 
        if not pgsql_node01_container_id:
            logger.error("No pgsql_node01_container_id provided in the playbook.", extra={'stepname': step})
            return False

        proxmox_archive            = dictionary.get('proxmox_archive') 
        if not proxmox_archive:
            logger.error("No proxmox_archive provided in the playbook.", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("No php_version provided in the playbook.", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name          = match.group(1)
        nextcloud_db_name  = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        proxmox_archive           = dictionary.get('proxmox_archive')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')

        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_ssd}/log"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"
        
        # Optional unused param
        nextcloud_url_download    = dictionary.get('nextcloud_url_download')

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_db_name']        = site_name        

        # Check if required packages are installed
        php               = f"php{php_version}"
        php_fpm           = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm, 'postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False


        # ---------------------------------------------------------------------
        # Create Database for Nextcloud
        # ---------------------------------------------------------------------
        return proxmox_pgsql_createdb_lxc(dictionary, nextcloud_db_name)

    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_disable_locking_lxc(dictionary):
    step = 'proxmox_nextcloud_disable_locking_lxc'

    try:
        logger.info("Start nextcloud disable locking...", extra={'stepname': step})    
    
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'proxmox_archive',
            'nginx_webserver_html_path',
            'php_version',
            'pgsql_node01_container_id',   # only primary node
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("No nextcloud_url provided in the playbook.", extra={'stepname': step})
            return False

        container_id               = dictionary['task_attributes'].get('container_id', [])  
        if not container_id:
            logger.error("No container_id provided in the playbook.", extra={'stepname': step})
            return False

        pgsql_node01_container_id  = dictionary.get('pgsql_node01_container_id') 
        if not pgsql_node01_container_id:
            logger.error("No pgsql_node01_container_id provided in the playbook.", extra={'stepname': step})
            return False

        proxmox_archive            = dictionary.get('proxmox_archive') 
        if not proxmox_archive:
            logger.error("No proxmox_archive provided in the playbook.", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("No php_version provided in the playbook.", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name          = match.group(1)
        nextcloud_db_name  = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        proxmox_archive           = dictionary.get('proxmox_archive')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')

        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_ssd}/log"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"
        
        # Optional unused param
        nextcloud_url_download    = dictionary.get('nextcloud_url_download')

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_db_name']        = site_name        

        # Check if required packages are installed
        php               = f"php{php_version}"
        php_fpm           = f"php{php_version}-fpm"
        required_packages = ['nginx', php, php_fpm, 'postgresql-client']
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.")
                return False
  
  
        # ---------------------------------------------------------------------
        # Disable locking
        # ---------------------------------------------------------------------
        query_sql = f"DELETE FROM {nextcloud_db_name}.oc_file_locks WHERE true;"
        return proxmox_pgsql_query_sql_lxc(dictionary, query_sql)

    except Exception as e:
        logger.error(f"Unexpected error: {e}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_cron_lxc(dictionary):
    step = "proxmox_nextcloud_cron_lxc"

    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        required_keys = (
            "proxmox_datastore_ssd",
            "proxmox_datastore_sata",
            "nginx_webserver_html_path",
            "nginx_webserver_user",
            "php_version",
            "redis_unixsocket",
        )
        for key in required_keys:
            val = dictionary.get(key)
            if not val:
                state = "Missing" if val is None else "Empty"
                logger.error(f"{state} parameter: {key}", extra={"stepname": step})
                return False

        task_attr      = dictionary.get("task_attributes", {})
        nextcloud_url  = task_attr.get("nextcloud_url")
        container_id   = task_attr.get("container_id")
        php_version    = dictionary["php_version"]
        web_user       = dictionary["nginx_webserver_user"]

        if not nextcloud_url or not container_id:
            logger.error("nextcloud_url or container_id missing", extra={"stepname": step})
            return False

        m = re.fullmatch(r"cloud\.([^.]+)\.(com|eu)", nextcloud_url)
        if not m:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={"stepname": step})
            return False
        site_name = m.group(1)

        # ------------------------------------------------------------------
        # Paths & dictionary enrichment
        # ------------------------------------------------------------------
        html_base           = dictionary["nginx_webserver_html_path"]
        data_base           = dictionary["proxmox_datastore_sata"]
        nextcloud_html_root = f"{html_base}/{nextcloud_url}"

        dictionary.update(
            nextcloud_url            = nextcloud_url,
            nextcloud_html_root      = nextcloud_html_root,
            nextcloud_documents_root = f"{data_base}/nc/{site_name}",
            nextcloud_log_path       = f"{data_base}/nc/{site_name}",
            nextcloud_db_name        = site_name,
        )

        # Validate required parameters
        required_keys = [
            "nginx",
            f"php{php_version}",
            f"php{php_version}-fpm",
            "postgresql-client",
            "cron",
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # ------------------------------------------------------------------
        # Build the /etc/cron.d file
        # ------------------------------------------------------------------
        cron_filename = f"nextcloud-{site_name}"  # no dots allowed for cron.d
        cron_file     = f"/etc/cron.d/{cron_filename}"
        cron_log      = "/var/log/nextcloud-cron.log"

        cron_entry = (
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            f"*/5 * * * * {web_user} /usr/bin/php -f "
            f"{nextcloud_html_root}/cron.php >> {cron_log} 2>&1\n"
        )

        commands = [
            f"rm -f {cron_file}",
            f"printf '{cron_entry}' > {cron_file}",
          
            f"chown root:root {cron_file}",
          
            f"chmod 0644 {cron_file}",
            f"touch {cron_log}",
            f"chown {web_user}:www-data {cron_log}",
            f"chmod 0644 {cron_log}",
            
            # make cron read the new file now
            "systemctl reload cron",    

            # ensure service active on every boot
            "systemctl enable --now cron",
            
            # manual run to update last‑run timestamp instantly
            f"runuser -u {web_user} -- /usr/bin/php -f {nextcloud_html_root}/cron.php || true",
            
            # switch Nextcloud to 'cron' mode (idempotent)
            f"runuser -u {web_user} -- php {nextcloud_html_root}/occ background:cron || true",
        ]
        for command in commands:  
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command :   '{command}'", extra={'stepname': step})
                logger.error(f"--> output  : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error   : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("Nextcloud cron configured successfully", extra={"stepname": step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_nextcloud_occ_lxc(dictionary):
    step = "proxmox_nextcloud_occ_apps_lxc"

    try:
        logger.info("Start nextcloud occ batch ...", extra={"stepname": step})

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'nginx_webserver_html_path',
            'php_version',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("nextcloud_url handle missing in dictionary", extra={'stepname': step})
            return False

        container_id               = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("php_version handle missing in dictionary", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name          = match.group(1)
        nextcloud_db_name  = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_sata}/nc/{site_name}"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"     

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_db_name']        = site_name        

        # Check if required packages are installed
        required_packages = [
            "nginx",
            f"php{php_version}",
            f"php{php_version}-fpm",
            "postgresql-client",
        ]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={"stepname": step})
                return False 


        # Get occ files from the playbook
        occ_files = dictionary['task_attributes'].get('vars', {}).get('nextcloud_occ_files', [])   
        if not occ_files:
            logger.error("no nextcloud_occ_files in the playbook.", extra={'stepname': step})
            return False  

        for occ_file in occ_files:
            if  occ_file.get('install'):
                if not occ_file.get('local_conf'):
                   logger.error(f"local_conf handle missing in playbook.", extra={'stepname': step})
                   return False  
                if not occ_file.get('remote_conf'):
                   logger.error(f"remote_conf handle missing in playbook.", extra={'stepname': step})               
                   return False  
                
                if not proxmox_nextcloud_occ_file_lxc(dictionary, occ_file):
                   logger.error(f"Nextcloud occ failed.", extra={'stepname': step})
                   return False                    
                logger.info(f"{occ_file} successfull executed.", extra={'stepname': step})            

        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ---------------------------------------------------------------------------
def proxmox_nextcloud_occ_file_lxc(dictionary, occ_file):
    step = "proxmox_nextcloud_occ_file_lxc"

    try:
        
        logger.info(f"Start occ batch {occ_file}..." , extra={"stepname": step})

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
           
         # Check required keys
        required_keys = [ 
            'proxmox_datastore_ssd',
            'proxmox_datastore_sata',
            'proxmox_archive',
            'nginx_webserver_html_path',
            'php_version',
        ]
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retrieve variables (playbook or dictionary)           
        nextcloud_url              = dictionary['task_attributes'].get('nextcloud_url')
        if not nextcloud_url:
            logger.error("nextcloud_url handle missing in dictionary", extra={'stepname': step})
            return False

        container_id               = container_id = dictionary['task_attributes'].get('container_id') 
        if not container_id:
            logger.error("container_id handle missing in dictionary", extra={'stepname': step})
            return False

        php_version                = dictionary.get('php_version') 
        if not php_version:
            logger.error("php_version handle missing in dictionary", extra={'stepname': step})
            return False

        # Validate nextcloud_url format
        match = re.match(r"cloud\.([^.]+)\.(com|eu)$", nextcloud_url)
        if not match:
            logger.error(f"Invalid nextcloud_url format: {nextcloud_url}", extra={'stepname': step})
            return False

        site_name                 = match.group(1)
        nextcloud_db_name         = site_name
        
        # Build relevant paths
        proxmox_datastore_ssd     = dictionary.get('proxmox_datastore_ssd')
        proxmox_datastore_sata    = dictionary.get('proxmox_datastore_sata')
        proxmox_archive           = dictionary.get('proxmox_archive')
        nginx_webserver_html_path = dictionary.get('nginx_webserver_html_path')
        nextcloud_documents_root  = f"{proxmox_datastore_sata}/nc/{site_name}"
        nextcloud_log_path        = f"{proxmox_datastore_sata}/nc/{site_name}"

        # Where the live HTML folder for Nextcloud is located
        nextcloud_html_root       = f"{nginx_webserver_html_path}/{nextcloud_url}"
        
        # Optional unused param
        nextcloud_url_download    = dictionary.get('nextcloud_url_download')

        # Store into the dictionary for Jinja2 substitution usage
        dictionary['nextcloud_url']            = nextcloud_url
        dictionary['nextcloud_html_root']      = nextcloud_html_root
        dictionary['nextcloud_documents_root'] = nextcloud_documents_root
        dictionary['nextcloud_log_path']       = nextcloud_log_path
        dictionary['nextcloud_prefix_for_log'] = site_name
        dictionary['nextcloud_db_name']        = site_name
        
        # Check if required packages are installed
        required_packages = [
            "nginx",
            f"php{php_version}",
            f"php{php_version}-fpm",
            "postgresql-client",
        ]
        for pkg in required_packages:
            if not proxmox_is_package_installed_lxc(dictionary, pkg):
                logger.error(f"Required package '{pkg}' is not installed.", extra={"stepname": step})
                return False 

        # Identify OCC scripts to upload according to the occ_files
        if not occ_file:
            logger.error("occ_files handle missing in function arguments", extra={'stepname': step})
            return False        

        files_to_upload = []
        local  = os.path.normpath(occ_file.get("local_conf"))
        remote = occ_file.get("remote_conf")
        if local and remote:
           files_to_upload.append((local, remote))

        if not files_to_upload:
            logger.error(f"{occ_file} not found in occ_files list", extra={"stepname": step})
            return False

        # Upload phase the occ_file
        if not proxmox_upload_files_windows_2_lxc(dictionary, files_to_upload, step):
            logger.error("File upload failed", extra={"stepname": step})
            return False

        # ------------------------------------------------------------------
        # Execution phase – run each uploaded script inside LXC 
        # ------------------------------------------------------------------
        overall_success = True
        for _local, remote_path in files_to_upload:
            logger.info(f"Executing OCC commands from {remote_path}", extra={"stepname": step})

            shell_one_liner = (
                "bash --noprofile --norc -o pipefail -c "
                + shlex.quote(
                    "GLOBAL=0; "
                    "grep -Ev '^(#|$)' "
                    + remote_path
                    + " | while IFS= read -r CMD; do "
                    "echo \">>> $CMD\"; "
                    "bash -o pipefail -c \"$CMD\"; RET=$?; "
                    "if [ $RET -gt 2 ]; then GLOBAL=$RET; fi; "
                    "done; "
                    "exit $GLOBAL"
                )
            )
            success, error, output = proxmox_command_for_lxc(dictionary, shell_one_liner, step)
            if not success:
                logger.error("OCC batch execution failed", extra={"stepname": step})
                logger.error(f"output:\n{output}", extra={"stepname": step})
                logger.error(f"error :{error}", extra={"stepname": step})
                overall_success = False
            logger.info(f"Batch {remote_path} executed OK", extra={"stepname": step})

        # ------------------------------------------------------------------
        # Clean up the uploaded files
        # ------------------------------------------------------------------
        for _, remote_path in files_to_upload:
            command = f"rm -f {remote_path}"
            success, error, output = proxmox_command_for_lxc(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : '{output}'", extra={'stepname': step})
                logger.error(f"--> error  : '{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})
    
        # Verify if Nextcloud is up and running
        command = f"php {nextcloud_html_root}/occ status"
        success, error, output = proxmox_command_for_lxc(dictionary, command, step)
        if not success or 'installed: true' not in output:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command: '{command}'", extra={'stepname': step})
                logger.error(f"--> output : '{output}'", extra={'stepname': step})
                logger.error(f"--> error  : '{error}'", extra={'stepname': step})
                return False
        logger.info(f"Executed: {command}", extra={'stepname': step})

        # Check if maintenance operations were successful
        if not overall_success:
            logger.error(f"Nextcloud maintenance failed.", extra={'stepname': step})
            return False
        else:
            logger.info(f"--> Nextcloud batch {occ_file} completed.", extra={'stepname': step})
            return True
                
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_stress(dictionary):
    step = "proxmox_stress"
    
    try:
        
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False      

        # Retreive values from dictionary
        required_keys = [
              'task_attributes',
        ]        
        for key in required_keys:
            value = dictionary.get(key)
            if value is None:
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False
            elif value == '':
                logger.error(f"Empty parameter: {key}", extra={'stepname': step})
                return False

        # Retreive values from playbook
        vars_section               = dictionary['task_attributes'].get('vars', {})
        required_vars              = (
            'cpu_target',
            'duration',
            'lxc_id_to_stop',
        )
        for key in required_vars:
            if key not in vars_section or vars_section[key] in (None, '', []):
                logger.error(f"Missing or empty parameter: {key}", extra={'stepname': step})
                return False

        cpu_target        = int(vars_section.get('cpu_target', 80))
        duration          = int(vars_section.get('duration', 30))   
        lxc_id_to_stop    = int(vars_section.get('lxc_id_to_stop'))
        
        logger.info("Starting safe alertmanager stress test: CPU and Memory burn via SSH", extra={"stepname": step})

        # ---------------------------------------------------------------------
        # CPU BURN
        # ---------------------------------------------------------------------        
        command = "nproc"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to get CPU count", extra={"stepname": step})
            return False

        try:
            cpu_total = int(output.strip())
        except Exception:
            logger.error(f"Invalid CPU count output: {output}", extra={"stepname": step})
            return False

        burn_cores = max(1, int(cpu_total * (cpu_target / 100)))

        command_cpu = f"for i in $(seq 1 {burn_cores}); do timeout {duration} bash -c 'while :; do :; done' & done; wait"
        success, error, output = proxmox_command(dictionary, command_cpu, step)
        if not success:
            logger.error("Failed to execute CPU burn.", extra={"stepname": step})
            return False
        logger.info(f"CPU burn launched on {burn_cores} cores.", extra={"stepname": step})

        # ---------------------------------------------------------------------
        # OPTIONAL LXC STOP & RESTART TEST
        # ---------------------------------------------------------------------
        if lxc_id_to_stop:
            logger.info(f"Stopping LXC container {lxc_id_to_stop}", extra={'stepname': step})
            command_stop  = f"pct stop {lxc_id_to_stop}"
            success, error, output = proxmox_command(dictionary, command_stop, step)
            if not success:
                logger.error(f"Failed to stop LXC {lxc_id_to_stop}.", extra={'stepname': step})
                logger.error(f"--> command: '{command_stop}'", extra={'stepname': step})
                logger.error(f"--> output: '{output}'", extra={'stepname': step})
                logger.error(f"--> error: '{error}'", extra={'stepname': step})
                return False
            logger.info(f"LXC container {lxc_id_to_stop} stopped successfully.", extra={'stepname': step})

            # wait before restart
            command_sleep = f"sleep {duration}"
            success, error, output = proxmox_command(dictionary, command_sleep, step)
            if not success:
                logger.error(f"Sleep before restart failed.", extra={'stepname': step})
                return False
            logger.info(f"Waited {duration} seconds before restart.", extra={'stepname': step})

            # restart container
            logger.info(f"Restarting LXC container {lxc_id_to_stop}", extra={'stepname': step})
            command_start = f"pct start {lxc_id_to_stop}"
            success, error, output = proxmox_command(dictionary, command_start, step)
            if not success:
                logger.error(f"Failed to restart LXC {lxc_id_to_stop}.", extra={'stepname': step})
                logger.error(f"--> command: '{command_start}'", extra={'stepname': step})
                logger.error(f"--> output: '{output}'", extra={'stepname': step})
                logger.error(f"--> error: '{error}'", extra={'stepname': step})
                return False
            logger.info(f"LXC container {lxc_id_to_stop} restarted successfully.", extra={'stepname': step})
 
        logger.info("Alertmanager safe stress test completed successfully.", extra={"stepname": step})
        return True
 
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_vulnerability(dictionary):
    step = "proxmox_vulnerability"  # match playbook

    try:
        logger.info("Starting Proxmox network pentest", extra={'stepname': step})

        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        # Extract vars from dictionary (task_attributes/vars)
        vars_section = (
            dictionary.get('task_attributes', {}).get('vars')
            or dictionary.get('vars')
            or {}
        )
        required_keys = ('exclude_ips',)
        for key in required_keys:
            if not vars_section.get(key):
                logger.error(f"Missing parameter: {key}", extra={'stepname': step})
                return False

        exclude_ips = set(vars_section['exclude_ips'])

        # Subnet detection (detect primary host subnet)
        command = "ip -o -4 addr show scope global | awk '{print $4}' | head -n1"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success or not output.strip():
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command :    '{command}'", extra={'stepname': step})
            logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})

        iface_raw = output.strip().split()
        if not iface_raw:
            logger.error("No global IPv4 address found.", extra={'stepname': step})
            return False

        try:
            iface = ipaddress.IPv4Interface(iface_raw[0])
            network = iface.network
        except (ValueError, IndexError) as e:
            logger.error(f"Invalid CIDR '{output.strip()}': {e}", extra={'stepname': step})
            return False

        host_ip = str(iface.ip)
        cidr = str(network)
        logger.info(f"Identified host subnet: {cidr}", extra={'stepname': step})

        # Host discovery (ICMP scan)
        command = f"nmap -sn -oG - {cidr}"
        success, error, output = proxmox_command(dictionary, command, step)
        if not success:
            logger.error("Failed to execute command:", extra={'stepname': step})
            logger.error(f"--> command :    '{command}'", extra={'stepname': step})
            logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
            logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
            return False
        logger.info(f"Executed: {command}", extra={'stepname': step})

        alive_hosts = []
        for line in output.splitlines():
            m = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                ip = m.group(1)
                if ip == host_ip or ip in exclude_ips:
                    logger.info(f"Excluded host: {ip}", extra={'stepname': step})
                    continue
                alive_hosts.append(ip)
        logger.info(f"Alive hosts discovered (filtered): {alive_hosts}", extra={'stepname': step})

        if not alive_hosts:
            logger.info("No live hosts – pentest finished", extra={'stepname': step})
            return True

        # TCP port scan on discovered hosts
        open_ports = {}
        total = len(alive_hosts)
        for idx, ip in enumerate(alive_hosts, 1):
            if ip == host_ip or ip in exclude_ips:
                logger.info(f"Excluded host (tcp scan): {ip}", extra={'stepname': step})
                continue
            logger.info(f"Scanning {ip} ({idx}/{total}) – top 100 ports", extra={'stepname': step})
            command = f"nmap -sS -Pn --top-ports 100 -T4 {ip}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command :    '{command}'", extra={'stepname': step})
                logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

            ports = []
            for line in output.splitlines():
                m = re.match(r"\s*(\d+)/tcp\s+open", line)
                if m:
                    ports.append(int(m.group(1)))
            open_ports[ip] = ports
            logger.info(f"Open ports for {ip}: {ports}", extra={'stepname': step})

        # Vulnerability scan with nmap scripts (SKIP if in exclude_ips)
        cve_re = re.compile(r"CVE-\d{4}-\d{4,7}")
        for ip, ports in open_ports.items():
            if ip == host_ip or ip in exclude_ips:
                logger.info(f"Excluded host (vuln scan): {ip}", extra={'stepname': step})
                continue
            if not ports:
                continue
            logger.info(f"Running vuln scan on {ip}", extra={'stepname': step})
            command = f"nmap -sV --script vuln {ip}"
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command :    '{command}'", extra={'stepname': step})
                logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

            cves = sorted(set(cve_re.findall(output)))
            logger.info(f"{ip}: CVEs found {cves if cves else 'none'}", extra={'stepname': step})

        logger.info("--> Basic Security Pentest completed", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
        
# ------------------------------------------------------------------------------------------
def proxmox_physical_remove(dictionary):
    step = 'proxmox_physical_remove'

    try:
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        logger.info("Removing physical layer tools and cleanup ...", extra={'stepname': step})

        # Try to find the custom collector dir from the playbook vars
        vars_section  = dictionary.get('task_attributes', {}).get('vars', {})
        collector_dir = vars_section.get('node_exporter_collector_dir', '/var/lib/node_exporter/textfile_collector')

        commands = [
            # Stop and disable tshark-capture.timer service if it exists
            "systemctl stop tshark-capture.service || true",

            "systemctl stop tshark-capture.timer || true",
            "systemctl disable tshark-capture.timer || true",
            "systemctl daemon-reload",

            # Remove scripts and systemd service/timer files
            "rm -f /usr/local/bin/parse_pcap.py",
            "rm -f /usr/local/bin/phy_demo.py",
            "rm -f /usr/local/bin/tshark-capture.py",
            "rm -f /etc/systemd/system/tshark-capture.timer",
            "rm -f /etc/systemd/system/tshark-capture.service",

            # Remove capture directories (both old and custom)
            "rm -rf /var/log/captures",
           f"rm -rf {collector_dir}/*",

            # Remove the python venv for pyshark (if present)
            "rm -rf /opt/pyshark",

            # Remove Wireshark/Tshark packages and group
            "apt-get -y purge tshark wireshark-common || true",
            "apt-get -y autoremove || true",
            "getent group wireshark && groupdel wireshark || true",

            # Remove permissions/capabilities from dumpcap (if it remains)
            "setcap -r /usr/bin/dumpcap || true",
            "chmod 755 /usr/bin/dumpcap || true",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to remove existing physical packages or configuration.", extra={'stepname': step})
                logger.error(f"--> command :    '{command}'", extra={'stepname': step})
                logger.error(f"--> output  :  \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error   :  \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("Physical layer tools and configuration removed successfully.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_physical_install(dictionary):
    step = 'proxmox_physical_install'
    try:
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False
            
        if not proxmox_physical_remove(dictionary):
            logger.error("Failed to remove proxmox_physical_install", extra={'stepname': step})
            return False           
            
        commands = [
            "apt-get -y update",
            "DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",
            "apt-get -y autoremove",
            "apt-get clean",

            # Preseed wireshark-common to avoid prompt
            "echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections",
            "DEBIAN_FRONTEND=noninteractive apt-get -y install tshark wireshark-common",

            "getent group wireshark || groupadd --system wireshark",
            "usermod -a -G wireshark root",
            "chmod 750 /usr/bin/dumpcap",
            "setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap",

            # Python venv (PyShark)
            "apt-get -y install python3 python3-venv",
            "python3 -m venv /opt/pyshark",
            "/opt/pyshark/bin/python -m ensurepip --upgrade",
            "/opt/pyshark/bin/pip install --quiet --no-cache-dir pyshark",
        ]

        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error("Failed to execute command:", extra={'stepname': step})
                logger.error(f"--> command:   '{command}'", extra={'stepname': step})
                logger.error(f"--> output : \n'{output}'", extra={'stepname': step})
                logger.error(f"--> error  : \n'{error}'", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        # Run tuning
        if not proxmox_physical_tuning(dictionary):
            return False

        logger.info("Physical layer tools successfully installed and configured.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False

# ------------------------------------------------------------------------------------------
def proxmox_physical_tuning(dictionary):
    step = 'proxmox_physical_tuning'
    try:
        # Validate SSH connection
        if not proxmox_is_ssh_connected(dictionary):
            logger.error("SSH client is not connected", extra={'stepname': step})
            logger.info(f"SSH client: {dictionary.get('ssh_client')}", extra={'stepname': step})
            return False

        service = 'tshark-capture.timer'

        # Create keys in the dictionary: Error if required variables are missing or empty
        vars_section = dictionary.get('task_attributes', {}).get('vars', {})
        required_keys = (
            'promfile_basename',
            'capture_duration',
            'interface',
        )
        for key in required_keys:
            value = vars_section.get(key)
            if value in (None, '', []):
                logger.error(f"Missing or empty parameter: {key}", extra={'stepname': step})
                return False
            dictionary[key] = value

        # Enable tshark-capture.timer and ensure collector dir exists
        node_exporter_textfile_dir = dictionary['node_exporter_textfile_dir']

        # Retrieve files_for_physic from playbook vars
        files_for_physic = vars_section.get('files_for_physic', [])
        if not files_for_physic:
            logger.error("No files_for_physic in the playbook.", extra={'stepname': step})
            return False

        # Prepare list of files to upload
        files_to_upload = []
        for item in files_for_physic:
            if item.get('install'):
                local_path = item.get('local_conf')
                remote_path = item.get('remote_conf')
                if local_path and remote_path:
                    files_to_upload.append((os.path.normpath(local_path), remote_path))

        # Upload config files if needed
        if files_to_upload:
            if not upload_files_windows_2_linux(dictionary, files_to_upload, step):
                logger.error("Failed to upload physical_files files.", extra={'stepname': step})
                return False

        commands = [
            f"mkdir -p {node_exporter_textfile_dir}",
            f"chmod 755 {node_exporter_textfile_dir}",      
        
            "chmod 755 /usr/local/bin/tshark-capture.py",
            "systemctl daemon-reload",
            f"systemctl restart {service}",
            f"systemctl enable {service}",
        ]
        for command in commands:
            success, error, output = proxmox_command(dictionary, command, step)
            if not success:
                logger.error(f"Failed: {command}", extra={'stepname': step})
                logger.error(f"--> error: {error}", extra={'stepname': step})
                return False
            logger.info(f"Executed: {command}", extra={'stepname': step})

        logger.info("Physical layer tuning completed.", extra={'stepname': step})
        return True

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False    

# ------------------------------------------------------------------------------------------
def setup(dictionary_raw):
    step = 'setup'

    logger.info("Setup started...", extra={'stepname': step})

    try:    
        # Create a global configuration that excludes the 'playbooks' key
        global_config = {k: v for k, v in dictionary_raw.items() if k not in ['playbooks']}
       
        # Retrieve only the list of playbooks from the dictionary_raw
        playbooks = dictionary_raw.get('playbooks', [])
        if not playbooks:
            logger.error("Unexpected error: Missing 'playbooks'.", extra={'stepname': step})
            return False

    except KeyError:
        logger.error("Unexpected error in parsing 'playbooks'.", extra={'stepname': step})
        return False
   
    failed_playbook = []

    for playbook in playbooks:
        
        # Merge the filtered global_config with the current playbook,
        # making sure to exclude any 'playbooks' key that might be in the playbook itself.
        dictionary = {**global_config, **{k: v for k, v in playbook.items() if k != 'playbooks'}}

        name = dictionary.get('name', '')
        # Check if the playbook should terminate the loop (e.g. name == 'exit')
        if name.lower() == "exit":
            logger.info("Playbook name is 'exit', exiting the loop.", extra={'stepname': step})
            break
        
        # Get the host_name
        host = dictionary.get('host')
        if not host:
            logger.error("Missing 'host' in dictionary.", extra={'stepname': step})
            continue
        
        # Initialize SSH-related variables for the current VM
        dictionary['ssh_client']    = None
        dictionary['ssh_connected'] = False
        dictionary['ssh_host']      = host
        dictionary['ssh_ip']        = None

        # Log the VM name
        logger.info("------------------------------------------------", extra={'stepname': step})
        logger.info(f"Setup started for host: {host}", extra={'stepname': step})
        
        # Process tasks one by one
        if 'tasks' in playbook and playbook['tasks']:
            task_failed_for_this_host = False  # Flag to detect critical failure

            for task in playbook['tasks']:
                if task_failed_for_this_host:
                    # Already failed on a previous task; skip the rest
                    break

                try:
                    task_name = task.get('name')
                    if not task_name:
                        logger.warning(f"Task name is missing for host '{host}'. Skipping this task.", extra={'stepname': step})
                        continue

                    # Store task-specific attributes in the buffer
                    dictionary['task_attributes'] = task.copy()

                    # Attempt to retrieve the function by name
                    func = globals().get(task_name)
                    if not callable(func):
                        logger.warning(f"Step function --------------------> {task_name} (not callable).", extra={'stepname': step})
                        continue

                    # We only have one function in steps, but let's keep the structure
                    steps = [(func, (dictionary,))]

                    # Execute the steps for the current task
                    for step_tuple in steps:
                        if not (isinstance(step_tuple, tuple) and len(step_tuple) == 2):
                            logger.warning(f"Invalid step_tuple format: {step_tuple}. Skipping step.", extra={'stepname': step})
                            continue

                        step_func, args = step_tuple
                        if not callable(step_func):
                            logger.warning(f"Step function {step_func} is not callable. Skipping step.", extra={'stepname': step})
                            continue

                        logger.info(f"Step function --------------------> {step_func.__name__} for host {host}.", extra={'stepname': step})

                        # Execute step and handle errors
                        task_ignore_errors = dictionary.get('task_attributes', {}).get('ignore_errors', 'no').lower()
                        result = step_func(*args)
                        if not result:
                            if task_ignore_errors == 'no':
                                logger.error(f"Critical failure in {step_func.__name__}", extra={'stepname': step})
                                failed_playbook.append(host)
                                task_failed_for_this_host = True
                                break  # Stop step execution, then break out of tasks
                            else:
                                logger.warning(f"Ignored failure in {step_func.__name__}", extra={'stepname': step})
                        else:
                            logger.info(f"Completed {step_func.__name__} successfully", extra={'stepname': step})

                except Exception as e:
                    logger.error(f"Error processing task '{task_name}' for host {host}: {e}", extra={'stepname': step})
                    failed_playbook.append(host)
                    task_failed_for_this_host = True
                    break  # Stop processing further tasks for this host

        # Close SSH connection for the current host
        try:
            if proxmox_is_ssh_connected(dictionary):
                logger.info("Step function --------------------> proxmox_ssh_close.", extra={'stepname': step})
                proxmox_ssh_close(dictionary)
        except Exception as e:
            logger.error(f"Failed to close SSH connection with host '{host}'. Exception: {e}", extra={'stepname': step})
            failed_playbook.append(host)

    # Report any failed hosts
    logger.info("------------------------------------------------", extra={'stepname': step})
    if failed_playbook:
        logger.error(f"Setup failed for the following hosts: {', '.join(failed_playbook)}", extra={'stepname': step})
        return False

    logger.info("Setup completed successfully for all hosts.", extra={'stepname': step})
    return True