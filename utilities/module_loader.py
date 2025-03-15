import os
import importlib

def load_all_modules_from_directory(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            importlib.import_module(f'{directory}.{module_name}')
