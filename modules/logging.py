# ------------------------------------------------------------------------------------------
#
#    name: logging.py
#
#    logging setup with a custom formatter for both console and file logging.
#    This will handle logging for different levels and include a 'stepname' attribute for contextual information.
#
#    ssh : no
#
# ------------------------------------------------------------------------------------------
import os
import logging
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------------------------------------------------------------------------
class ConsoleCustomFormatter(logging.Formatter):
    format_dict = {
        logging.DEBUG:    "[{color}DEBUG   {reset}] %(stepname)-20s | %(message)s",
        logging.INFO:     "[{color}OK      {reset}] %(stepname)-20s | %(message)s",
        logging.WARNING:  "[{color}WARNING {reset}] %(stepname)-20s | %(message)s",
        logging.ERROR:    "[{color}ERROR   {reset}] %(stepname)-20s | %(message)s",
        logging.CRITICAL: "[{color}CRITICAL{reset}] %(stepname)-20s | %(message)s",
    }

    def format(self, record):
        if not hasattr(record, 'stepname') or not record.stepname:
            record.stepname = 'N/A'
        else:
            record.stepname = record.stepname[:20]

        log_fmt = self.format_dict.get(record.levelno).format(
            color=Fore.CYAN   if record.levelno == logging.DEBUG   else
                  Fore.GREEN  if record.levelno == logging.INFO    else
                  Fore.YELLOW if record.levelno == logging.WARNING else
                  Fore.RED    if record.levelno == logging.ERROR   else
                  Fore.RED + Style.BRIGHT,
            reset=Style.RESET_ALL
        )
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# ------------------------------------------------------------------------------------------
class FileCustomFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, 'stepname') or not record.stepname:
            record.stepname = 'N/A'
        else:
            record.stepname = record.stepname[:15]

        datefmt   = '%Y-%m-%d %H:%M:%S'
        log_fmt   = '%(asctime)s - %(name)-25s - [%(levelname)-8s] - %(stepname)-20s - %(message)s'
        formatter = logging.Formatter(log_fmt, datefmt)
        return formatter.format(record)

# ------------------------------------------------------------------------------------------
class LoggerSetup:
    def __init__(self, log_directory, log_level=logging.INFO):
        self.log_directory = log_directory
        self.log_level     = log_level
        self.log_file_name = self.generate_log_file_name()
        self.check_log_directory()
        self.configure_logging()

    def generate_log_file_name(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Use sys.argv[0] to get the script name instead of __file__
        script_name   = os.path.basename(sys.argv[0]).replace('.py', '')
        log_file_name = os.path.join(self.log_directory, f"{script_name}_{timestamp}.log")
        return log_file_name

    def check_log_directory(self):
        if not os.path.exists(self.log_directory):
            try:
                os.makedirs(self.log_directory)
                # Since logging is not configured yet, print to stdout
                print(f"Created log directory: {self.log_directory}")
            except Exception as e:
                print(f"Failed to create the directory {self.log_directory}: {e}")
                raise

    def configure_logging(self):
        try:
            logger = logging.getLogger()
            logger.setLevel(self.log_level)

            # Remove existing handlers to prevent duplicate logs
            if logger.hasHandlers():
                logger.handlers.clear()

            # Console handler with custom formatter
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            console_formatter = ConsoleCustomFormatter()
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)

            # File handler with custom formatter and UTF-8 encoding
            file_handler = logging.FileHandler(self.log_file_name, mode='a', encoding='utf-8')
            file_handler.setLevel(self.log_level)
            file_formatter = FileCustomFormatter()
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

        except Exception as e:
            # Since logging may not be configured, print the error
            print(f"Failed to configure logging: {e}")
            raise

    @staticmethod
    def get_logger(name):
        return logging.getLogger(name)