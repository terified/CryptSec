import os
import platform

def clear_console():
    """Очистка консоли в зависимости от операционной системы."""
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def wait_for_enter():
    """Функция ожидания нажатия клавиши Enter."""
    input("Press Enter to continue...")