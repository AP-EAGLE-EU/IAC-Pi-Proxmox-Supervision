# ------------------------------------------------------------------------------------------
#    name: end.py
#
#    execute: 
#    end(rc=None)
#
#    ssh : no
#
# ------------------------------------------------------------------------------------------
import logging
import sys

from enum import Enum

# ------------------------------------------------------------------------------------------
class RC(Enum):
    success  = 0
    error    = 1
    warning  = 4
    flush    = 16
    critical = 99

# ------------------------------------------------------------------------------------------
def end(rc=None):
    # End the script with the appropriate return code.
    #
    # Args:
    #     rc (RC, optional): Return code indicating the status of the job. Defaults to None.
    #
    
    step = 'thank for using'
    logger = logging.getLogger(__name__)
    
    try:
        # Log based on the return code provided
        if rc is None:
            logger.info("Job ended successfully.", extra={'stepname': step})
        elif rc == RC.critical:
            logger.critical("Critical error encountered. Job exiting with RC.critical", extra={'stepname': step})
        elif rc == RC.error:
            logger.error("Error encountered. Job exiting with RC.error", extra={'stepname': step})
        elif rc == RC.flush:
            logger.error("Job flush. Exiting with RC.flush", extra={'stepname': step})
        elif rc == RC.warning:
            logger.warning("Warning encountered. Job exiting with RC.warning", extra={'stepname': step})
        else:
            logger.info("Job ended successfully.", extra={'stepname': step})

    except Exception as e:
        logger.error(f"An unexpected error occurred during job termination: {e}", extra={'stepname': step})

    finally:
        logger.info("------------------------------------------------", extra={'stepname': step})
        logger.info("Thank you for using this script! Have a great day!", extra={'stepname': step})

        # Use sys.exit() to terminate script with appropriate return code
        if isinstance(rc, RC):
            sys.exit(rc.value)
        else:
            sys.exit(0)