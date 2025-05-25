# ------------------------------------------------------------------------------------------
# Written by    : Ambroise Pétin
# Date          : Q1.2025
# Title         : Infrastructure as code
# command       : py iac.py <playbook>.yaml
# ------------------------------------------------------------------------------------------
# iac.py
import os
import logging
import sys
from enum import Enum

# Import necessary modules
from modules.config import load_dictionary  # this will handle vault.yaml now
from modules.logging import LoggerSetup
from modules.setup import setup
from modules.end import end

# ------------------------------------------------------------------------------------------
class RC(Enum):
    success  = 0
    error    = 1
    warning  = 4
    flush    = 16
    critical = 99

# ------------------------------------------------------------------------------------------
def get_root_directory():
    base_directory = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
    drive_letter   = os.path.splitdrive(base_directory)[0]
    
    return f"{drive_letter}/", base_directory

# ------------------------------------------------------------------------------------------
def setup_logging():
    root_directory, base_directory = get_root_directory()
    log_directory                  = os.path.join(root_directory, 'log')
    logger_setup                   = LoggerSetup(log_directory)
    
    return LoggerSetup.get_logger(__name__)

# ------------------------------------------------------------------------------------------
def load_configurations(playbook, logger):
    step = 'load_configurations'
    
    root_directory, base_directory = get_root_directory()

    dictionary_file   = os.path.join(base_directory, 'dictionary', 'dictionary.yaml').replace('\\', '/')
    playbook_file     = os.path.join(base_directory, 'playbooks', playbook).replace('\\', '/')
    
    for file_path in [dictionary_file, playbook_file]:
        if not os.path.exists(file_path):
            logger.error(f"Configuration file '{file_path}' does not exist.", extra={'stepname': step})
            end(RC.critical)

    success, dictionary = load_dictionary(dictionary_file, playbook_file)
    if not success or dictionary is None:
        logger.error(f"Failed to load configuration from '{playbook_file}'.", extra={'stepname': step})
        return False, None
    
    return True, dictionary

# ------------------------------------------------------------------------------------------
def begin(playbook, logger):
    step = 'iac: Initialization'
    
    try:
        success, dictionary = load_configurations(playbook, logger)
        if not success:
           return False, None
        
        root_dir, base_dir = get_root_directory()
        dictionary_file    = os.path.join(base_dir, 'dictionary', 'dictionary.yaml').replace('\\', '/')
        playbook_file      = os.path.join(base_dir, 'playbooks', playbook).replace('\\', '/')

        job_name           = dictionary.get('job_name', 'N/A')
        version            = dictionary.get('version', 'N/A')
        writtenby          = dictionary.get('writtenby', 'N/A')
        debug              = dictionary.get('debug', False)
        
        logger.info("------------------------------------------------", extra={'stepname': step})
        logger.info(f"Job Name        : {job_name}", extra={'stepname': step})
        logger.info(f"Version         : {version}", extra={'stepname': step})
        logger.info(f"Author          : {writtenby}", extra={'stepname': step})
        logger.info(f"Debug Mode      : {'Enabled' if debug else 'Disabled'}", extra={'stepname': step})
        logger.info(f"Root Directory  : {root_dir}", extra={'stepname': step})
        logger.info(f"Dictionary File : {dictionary_file}", extra={'stepname': step})
        logger.info(f"Playbook File   : {playbook_file}", extra={'stepname': step})
        logger.info(f"Log Directory   : {os.path.join(root_dir, 'log')}", extra={'stepname': step})
        
        return True, dictionary
    
    except Exception as e:
           logger.error(f"Initialization error: {str(e)}", extra={'stepname': step})
           return False, None

# ------------------------------------------------------------------------------------------
def main(playbook):
    step = 'main'
    
    logger  = setup_logging()

    try:
        success, dictionary = begin(playbook, logger)
        if not success:
            logger.error("Initialization failed. Exiting.", extra={'stepname': step})
            return False
        
        logger.info("Starting setup ...", extra={'stepname': step})
        if not setup(dictionary):
            logger.error("Setup failed.", extra={'stepname': step})
            return False
        
        logger.info("All tasks completed successfully.", extra={'stepname': step})
        return True
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", extra={'stepname': step})
        return False
    
    finally:
        logger.info("Execution phase completed.", extra={'stepname': step})
        return True

# ------------------------------------------------------------------------------------------
if __name__ == "__main__":
    step = 'iac: start'
    
    logger = setup_logging()
    
    os.system('cls' if os.name == 'nt' else 'clear')
    logger.info("IaC process started.", extra={'stepname': step})
    
    if len(sys.argv) != 2:
        logger.error("Usage: python iac.py <playbook.yaml>", extra={'stepname': step})
        end(RC.critical)
    
    playbook = sys.argv[1]
    
    if not playbook.lower().endswith(('.yaml', '.yml')):
        logger.error("Playbook must be a YAML file.", extra={'stepname': step})
        end(RC.critical)

    if not main(playbook):
        end(RC.critical)
    else:
        end(RC.success)