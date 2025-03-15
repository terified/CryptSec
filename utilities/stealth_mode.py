import os
import shutil

def activate_stealth_mode():
    # Пример функции самоуничтожения данных
    paths_to_destroy = ["path/to/sensitive/data", "another/path/to/destroy"]
    for path in paths_to_destroy:
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
    print("Stealth mode activated. Sensitive data destroyed.")