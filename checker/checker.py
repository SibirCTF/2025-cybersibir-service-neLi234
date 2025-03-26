#!/usr/bin/env python3
import mimesis
import random
import pickle
import os
from argparse import ArgumentParser
import re
import sqlite3


# put-get flag to service success
def service_up():
    print("[service is worked] - 101")
    exit(101)


# service is available (available tcp connect) but protocol wrong could not put/get flag
def service_corrupt():
    print("[service is corrupt] - 102")
    exit(102)


# waited time (for example: 5 sec) but service did not have time to reply
def service_mumble():
    print("[service is mumble] - 103")
    exit(103)


# service is not available (maybe blocked port or service is down)
def service_down():
    print("[service is down] - 104")
    exit(104)
    
def wtf():
    print("[wtf] - 105")
    exit(105)

def initialize_db():
    db = sqlite3.connect("NeuroLinks.db")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS checker (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            flag_id TEXT,
            flag TEXT,
            vuln INT,
            username TEXT,
            password TEXT,
            key TEXT,
            message TEXT
        )
        """
    )
    db.commit()
    return db

def generate_company():
    return f"{mimesis.Finance().company().replace(' ', '_').replace(',', '').replace('.', '')}_{random.randint(1, 1000000)}"

def generate_thought():
    return mimesis.Food().fruit()

def generate_concept():
    return f"{mimesis.Person().political_views()}={mimesis.Person().views_on()}"



import socket

class CheckSock:
    def __init__(self, host, port, timeout):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.socket.settimeout(timeout)
        
    def __enter__(self):
        self.s = self.socket.connect((self.host, self.port))
        self._recv()
        return self

    def __exit__(self, type, value, traceback):
        self.socket.close()

    def _send(self, message):
        self.socket.sendall((message + '\n').encode())
        
    def _recv(self):
        return self.socket.recv(1024).decode().strip()
    
    def register(self, username, password):
        self._send('1')  # Choose register
        self._recv()     # Username prompt
        self._send(username)
        self._recv()     # Password prompt
        self._send(password)
        return self._recv()
    def login(self, username, password):
        self._send('2')  # Choose login
        self._recv()     # Username prompt
        self._send(username)
        self._recv()     # Password prompt
        self._send(password)
        return self._recv()
    
    def add_message(self, message):
        self._send(f'add {message}')
        return self._recv()
    
    def get_message(self, message):
        self._send(f'get {message}')
        return self._recv()
    
    def get_all_messages(self):
        self._send('getall')
        response = self._recv()
        # Parse multiple messages if needed
        return response
    
    def internalize(self, message):
        self._send(f'internalize {message}')
        return self._recv()
    
    def eject(self, message):
        self._send(f'eject {message}')
        return self._recv()

class Client:
    def __init__(self, host='127.0.0.1', port=2020, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.db = initialize_db()
        
    def __enter__(self):
        self.db = initialize_db()
        return self

    def __exit__(self, type, value, traceback):
        self.db.close()
    
    def check(self):
        test_username = generate_company()
        test_password = mimesis.Person().password(length=14)
        with CheckSock(self.host, self.port, self.timeout) as s:
            reg_result = s.register(test_username, test_password)
            if not reg_result.startswith("Registration successful!"):
                service_corrupt()
        with CheckSock(self.host, self.port, self.timeout) as s:
            login_result = s.login(test_username, test_password)
            if not login_result.startswith("Login successful!"):
                service_corrupt()
            message = generate_thought()
            add_result = s.add_message(message)
            if not add_result.startswith("Added successfully"):
                service_corrupt()
            get_result = s.get_message(message)
            if message not in get_result:
                service_corrupt()
            getall_result = s.get_all_messages()
            if message not in getall_result:
                service_corrupt()
            concept = generate_concept()
            internalize_result = s.internalize(concept)
            if not (match:= re.match(r"Internalized: ([0-9a-fA-F]+)$", internalize_result)):
                service_corrupt()
            eject_result = s.eject(match[1])
            if f"Ejected: {concept}" != eject_result:
                service_corrupt()

    def put(self, flag_id: str, flag: str):
        cursor = self.db.execute('SELECT id FROM checker ORDER BY id DESC LIMIT 1;')
        db_response = cursor.fetchone()
        cursor.close()
        if not db_response or not db_response[0]:
            vuln = 0
        else:
            vuln = db_response[0] % 2
        print(db_response)
        print(vuln)
        if vuln == 0:
            username = generate_company()
            password = mimesis.Person().password(length=14)
            print(username, password)
            with CheckSock(self.host, self.port, self.timeout) as s:
                reg_result = s.register(username, password)
                if not reg_result.startswith("Registration successful!"):
                    service_corrupt()
            with CheckSock(self.host, self.port, self.timeout) as s:
                login_result = s.login(username, password)
                if not login_result.startswith("Login successful!"):
                    service_corrupt()
                add_result = s.add_message(flag)
                if not add_result.startswith("Added successfully"):
                    service_corrupt()            
            cursor = self.db.execute('INSERT INTO checker (host, flag_id, flag, username, password, vuln) VALUES (?, ?, ?, ?, ?, ?)', (self.host, flag_id, flag, username, password, vuln))
            self.db.commit()
            cursor.close()
        if vuln == 1:
            username = generate_company()
            password = mimesis.Person().password(length=14)
            with CheckSock(self.host, self.port, self.timeout) as s:
                reg_result = s.register(username, password)
                if not reg_result.startswith("Registration successful!"):
                    service_corrupt()
            with CheckSock(self.host, self.port, self.timeout) as s:
                login_result = s.login(username, password)
                if not login_result.startswith("Login successful!"):
                    service_corrupt()
                internalize_result = s.internalize(f"flag={flag}")
                if not (match:= re.match(r"Internalized: ([0-9a-fA-F]+)$", internalize_result)):
                    service_corrupt()
            cursor = self.db.execute('INSERT INTO checker (host, flag_id, flag, username, password, vuln, key) VALUES (?, ?, ?, ?, ?, ?, ?)', (self.host, flag_id, flag, username, password, vuln, match[1]))
            self.db.commit()
            cursor.close()
            
    
    def get(self, flag_id: str, flag: str):
        cursor = self.db.execute('SELECT username, password, vuln, key FROM checker WHERE flag=?', ([flag]))
        db_response = cursor.fetchone()
        cursor.close()
        if not db_response:
            wtf()
        username = db_response[0]
        password = db_response[1]
        vuln = db_response[2]
        key = db_response[3]
        if vuln == 0:
            with CheckSock(self.host, self.port, self.timeout) as s:
                login_result = s.login(username, password)
                if not login_result.startswith("Login successful!"):
                    service_corrupt()
                get_result = s.get_message(flag)
                print(get_result)
                if flag not in get_result:
                    service_corrupt()
        if vuln == 1:
            with CheckSock(self.host, self.port, self.timeout) as s:
                login_result = s.login(username, password)
                if not login_result.startswith("Login successful!"):
                    service_corrupt()
                eject_result = s.eject(key)
                if f"Ejected: flag={flag}" != eject_result:
                    service_corrupt()

def main():
    pargs = ArgumentParser()
    pargs.add_argument("host")
    pargs.add_argument("command", type=str)
    pargs.add_argument("f_id", nargs='?')
    pargs.add_argument("flag", nargs='?')
    args = pargs.parse_args()
    port = 2340
    with Client(host=args.host, port=port) as client:
        if args.command == "put":
            try:
                client.put(args.f_id, args.flag)
                client.check()
            except socket.timeout:
                service_down()
            except Exception as e:
                print(e)
                service_down()
        elif args.command == "check":
            try:
                client.get(args.f_id, args.flag)
                client.check()
            except socket.timeout:
                service_down()
            except Exception as e:
                print(e)
                service_down()
        else:
            pargs.error("Wrong command")
    service_up()

if __name__ == "__main__":
    main()