import os
import subprocess

def update_repository():
    os.system('git pull')

def clear_screen():
    os.system('clear')

def start_main():
    subprocess.run(['python', 'main.py'])

update_repository()

clear_screen()

start_main()