# ------------------------------------------------------------------------------------------
#    name: config.py
#
# ------------------------------------------------------------------------------------------
# config.py
import os
import yaml
import logging
from jinja2 import Template

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------------------
def get_directories():
    """
    Extract root and base directories, removing 'modules' if present at the end
    (assuming this script is in a 'modules' subfolder).
    """
    base_directory = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
    folders_to_remove = ['modules']
    
    for folder in folders_to_remove:
        if base_directory.endswith(f'/{folder}'):
            base_directory = os.path.dirname(base_directory)
    root_directory = os.path.splitdrive(base_directory)[0]
    
    return root_directory, base_directory

# ------------------------------------------------------------------------------------------
def render_jinja_template(content, variables):
    """
    Recursively render a Python object (dict, list, str) that may contain Jinja2 templates.
    """
    if isinstance(content, dict):
        return {k: render_jinja_template(v, variables) for k, v in content.items()}
    elif isinstance(content, list):
        return [render_jinja_template(item, variables) for item in content]
    elif isinstance(content, str):
        return Template(content).render(variables)  # Jinja2 rendering
    return content

# ------------------------------------------------------------------------------------------
def multi_pass_render(data, passes):
    """
    Call render_jinja_template multiple times to allow for nested or repeated Jinja references.
    """
    rendered = data
    for _ in range(passes):
        rendered = render_jinja_template(rendered, rendered)
    return rendered

# ------------------------------------------------------------------------------------------
def load_dictionary(dictionary_file, playbook_file):
    """
    1) Loads 'dictionary_file' (config.yaml) and 'playbook_file' (playbook.yaml).
    2) Retrieves 'vault_file_path' from config.yaml => e.g. '{{ base_directory }}/vault/vault.yaml'.
    3) Substitutes '{{ base_directory }}' in 'vault_file_path' before opening vault.yaml.
    4) Merges config.yaml, vault.yaml, and playbook.yaml into a single dictionary.
    5) Runs multi-pass Jinja rendering on the final combined dictionary.
    6) Validates, then returns (success, dictionary).
    """
    step = 'load_dictionary'
    try:
        root_directory, base_directory = get_directories()

        # ---------------------------------------------------------------------
        # 1) Load config.yaml
        # ---------------------------------------------------------------------
        if not os.path.exists(dictionary_file):
            logger.error(f"Not found: {dictionary_file}", extra={'stepname': step})
            return False, None
        
        with open(dictionary_file, 'r', encoding='utf-8') as f:
            config_content = yaml.safe_load(f) or {}

        # ---------------------------------------------------------------------
        # 2) Retrieve vault_file_path from config.yaml (under global_config).
        #    Double-check that global_config exists before referencing it.
        # ---------------------------------------------------------------------
        global_conf     = config_content.get('global_config', {})
        vault_file_path = global_conf.get('vault_file_path')
        
        if vault_file_path:
            # (IMPORTANT) Substitute '{{ base_directory }}' in the path
            vault_file_path = vault_file_path.replace('{{ base_directory }}', base_directory).replace('\\', '/')
            
            # 3) Load vault.yaml if the file actually exists
            if not os.path.exists(vault_file_path):
                logger.error(f"Vault file not found: {vault_file_path}", extra={'stepname': step})
                return False, None
            
            with open(vault_file_path, 'r', encoding='utf-8') as vf:
                # (IMPORTANT) Use the correct file handle (vf) here
                vault_content = yaml.safe_load(vf) or {}
            
        else:
            # If vault_file_path is missing or empty, either fail or skip. 
            logger.error("No vault_file_path provided in the config.", extra={'stepname': step})
            return False, None

        # ---------------------------------------------------------------------
        # 4) Load playbook.yaml
        # ---------------------------------------------------------------------
        if not os.path.exists(playbook_file):
            logger.error(f"Not found: {playbook_file}", extra={'stepname': step})
            return False, None
        
        with open(playbook_file, 'r', encoding='utf-8') as f:
            playbook_content = yaml.safe_load(f) or {}

        # ---------------------------------------------------------------------
        # Merge all three YAML sources: vault, config, playbook
        # ---------------------------------------------------------------------
        dictionary = {
            'base_directory': base_directory,
            'root_directory': root_directory,
            **config_content,
            **vault_content,
            **playbook_content
        }

        # ---------------------------------------------------------------------
        # Flatten global_config into the top-level dictionary
        # (so that keys in 'global_config' appear at the root level)
        # ---------------------------------------------------------------------
        if 'global_config' in dictionary:
            global_config = dictionary.pop('global_config')
            dictionary.update(global_config)
        
        # If you store vault data under a 'vault_config' section,
        # you can flatten it here similarly:
        if 'vault_config' in dictionary:
            vault_config = dictionary.pop('vault_config')
            dictionary.update(vault_config)

        # ---------------------------------------------------------------------
        # 5) Perform multi-pass Jinja rendering on the entire dictionary
        #    We also want to specifically handle the 'playbooks' list 
        #    if it references variables in the dictionary.
        # ---------------------------------------------------------------------
        playbooks = dictionary.get('playbooks', [])
        
        for i, vm in enumerate(playbooks):
            merged_vm = {**dictionary, **vm}
            # Could do 2 or 3 passes depending on how nested your Jinja is
            rendered_vm = multi_pass_render(merged_vm, passes=3)
            
            # Keep only the keys from the original VM, so we don't inadvertently
            # inject every dictionary-level key into the VM item.
            final_vm = {}
            for key in vm.keys():
                final_vm[key] = rendered_vm.get(key, vm[key])
            playbooks[i] = final_vm
        
        dictionary['playbooks'] = playbooks

        # Final multi-pass for the entire dictionary if needed
        dictionary = multi_pass_render(dictionary, passes=3)

        # ---------------------------------------------------------------------
        # 6) Debug logging (optional)
        # ---------------------------------------------------------------------
        # Debug info
        if dictionary.get('debug'):
           logger.info(f"============================================================ Debug-begin", extra={'stepname': step})
           logger.info(f"Dictionary dump:\n{yaml.dump(dictionary,)}", extra={'stepname': step})
           logger.info(f"============================================================ Debug-end", extra={'stepname': step})

        # ---------------------------------------------------------------------
        # Validate
        # ---------------------------------------------------------------------
        if not validate_config(dictionary):
            logger.error("Validation failed.", extra={'stepname': step})
            return False, None

        return True, dictionary

    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file: {e}", extra={'stepname': step})
        return False, None
    except Exception as e:
        logger.error(f"Error in load_dictionary: {e}", extra={'stepname': step})
        return False, None

# ------------------------------------------------------------------------------------------
def validate_config(dictionary):
    """
    Example validations of certain keys or values in the final dictionary.
    """
    step = 'validate_config'
    success = True

    if 'substitution_value' in dictionary and dictionary['substitution_value'] != 'test':
        logger.error("substitution_value must be 'test'", extra={'stepname': step})
        success = False

    root_name = dictionary.get('root_name')
    if root_name != 'root':
        logger.error(f"root_name retrieval error '{root_name}'", extra={'stepname': step})
        success = False

    return success
