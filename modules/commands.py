# ------------------------------------------------------------------------------------------
#    name: commands.py
#
#    execute some commands: 
#    windows_command(command, step)
#    powershell_command(command, step):
#
#    ssh : no
#
# ------------------------------------------------------------------------------------------
# moduels/commands.py

import subprocess
import logging

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------------------

def windows_command(command, step):

    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True
        )
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute {command} during {step}: {e.stderr}", extra={'stepname': step})
        return False, e.stderr.strip()
    except FileNotFoundError as fnf_error:
        logger.error(f"Executable not found: {fnf_error}", extra={'stepname': step})
        return False, str(fnf_error)
    except Exception as e:
        logger.error(f"An unexpected error occurred during execution of '{command}' in {step}: {e}", extra={'stepname': step})
        return False, str(e)

# ------------------------------------------------------------------------------------------
def powershell_command(command, step):

    try:
        completed_process = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            timeout=300  # Adjust timeout as needed
        )
        success = completed_process.returncode == 0
        error   = completed_process.stderr.strip()
        output  = completed_process.stdout.strip()
        
        if not success:
           logger.error(f"Failed to execute powedshell command.", extra={'stepname': step})
           logger.error(f"--> command: {command}", extra={'stepname': step})
           logger.error(f"--> error  : {error}", extra={'stepname': step})
           logger.error(f"--> output : {output}", extra={'stepname': step})  
           return False
                
        return success, error, output
    
    except subprocess.TimeoutExpired:
        logger.error(f"PowerShell command timed out: {command}", extra={'stepname': step})
        return False, "Command timed out.", ""
    
    except Exception as e:
        logger.error(f"Unexpected error executing PowerShell command '{command}': {e}", extra={'stepname': step})
        return False, str(e), ""