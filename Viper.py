import re
import requests
import sqlite3
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
import threading
import socket
import paramiko
from ping3 import ping
import itertools
import string
import time
import hashlib 
import shlex
import base64 
import select 
import struct 
from urllib.parse import quote_plus, unquote_plus, urlparse, parse_qs, urlencode
import subprocess 
import html
import random
import os

# --- NEW: Global state for TCP Listeners ---
# Stores active listener threads keyed by (host, port)
listener_threads: Dict[Tuple[str, int], threading.Thread] = {}
# Flags to signal threads to stop
stop_listener_flags: Dict[Tuple[str, int], bool] = {}

# ICMP constants (for UDP scan)
ICMP_ECHOREPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_SRC_QUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO = 8
ICMP_TIME_EXCEEDED = 11
ICMP_PARAMETERPROB = 12
ICMP_TIMESTAMP = 13
ICMP_TIMESTAMPREPLY = 14
ICMP_INFO_REQUEST = 15
ICMP_INFO_REPLY = 16
ICMP_ADDRESS = 17
ICMP_ADDRESSREPLY = 18

# --- NEW: Default User Agents ---
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

# --- NEW: Fuzzing Payloads ---
FUZZING_PAYLOADS = {
    "sql": ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--"],
    "xss": ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><script>alert(1)</script>"],
    "lfi": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "file:///etc/passwd"],
    "rce": ["$(id)", "$(cat /etc/passwd)", "|id", ";id;", "\"|id"],
    "nosql": ["[$ne]", '{"$ne": null}', '{"$gt": ""}'],
    "numeric": ["0", "-1", "99999", "3.14159", "0x100"],
    "special": ["!@#$%^&*()", "null", "undefined", "true", "false", " ", ""]
}

# --- NEW: Function to handle TCP client connections for tcp_listen ---
def handle_tcp_client(client_socket: socket.socket, addr: Tuple[str, int], listener_key: Tuple[str, int]):
    host, port = listener_key
    print(f"[TCP Listener {host}:{port}] Accepted connection from {addr[0]}:{addr[1]}")
    client_socket.settimeout(2.0)
    try:
        while True:
            if stop_listener_flags.get(listener_key):
                print(f"[TCP Listener {host}:{port}] Stop signal received for client {addr[0]}:{addr[1]}. Closing.")
                break
            try:
                data = client_socket.recv(1024)
                if not data:
                    print(f"[TCP Listener {host}:{port}] Connection closed by client {addr[0]}:{addr[1]}.")
                    break 
                decoded_data = data.decode('utf-8', errors='ignore')
                print(f"[TCP Listener {host}:{port}] Received from {addr[0]}:{addr[1]}: {decoded_data}")
            except socket.timeout:
                continue
            except ConnectionResetError:
                 print(f"[TCP Listener {host}:{port}] Connection reset by client {addr[0]}:{addr[1]}.")
                 break
            except Exception as e:
                 print(f"[TCP Listener {host}:{port}] Error receiving from {addr[0]}:{addr[1]}: {e}")
                 break
    finally:
        print(f"[TCP Listener {host}:{port}] Closing client connection {addr[0]}:{addr[1]}.")
        client_socket.close()

# --- NEW: Function to run the main TCP listener thread ---
def tcp_listener_thread(host: str, port: int, listener_key: Tuple[str, int]):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[TCP Listener {host}:{port}] Now listening...")
        server_socket.settimeout(1.0)
        
        while not stop_listener_flags.get(listener_key):
            try:
                client_sock, addr = server_socket.accept()
                client_handler = threading.Thread(target=handle_tcp_client, args=(client_sock, addr, listener_key), daemon=True)
                client_handler.start()
            except socket.timeout:
                continue 
            except Exception as e:
                 if not stop_listener_flags.get(listener_key):
                    print(f"[TCP Listener {host}:{port}] Error accepting connections: {e}")
                 break
                 
    except OSError as e:
        print(f"[TCP Listener {host}:{port}] OS Error starting listener: {e}")
    except Exception as e:
        print(f"[TCP Listener {host}:{port}] Failed to bind or listen: {e}")
    finally:
        print(f"[TCP Listener {host}:{port}] Shutting down listener socket.")
        server_socket.close()
        if listener_key in listener_threads:
            del listener_threads[listener_key]
        if listener_key in stop_listener_flags:
             del stop_listener_flags[listener_key]

# Simple handler for the server
class SimpleViperHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello from Viper Server!")

class ViperInterpreter:
    def __init__(self):
        self.variables: Dict[str, Any] = {}
        self.functions = {}
        self.server_thread: Optional[threading.Thread] = None
        self.httpd: Optional[HTTPServer] = None
        
    # --- Wordlist Generation Helper ---
    def _generate_wordlist(self, base_words: List[str], rules: str) -> List[str]:
        new_list = set(base_words)
        processed_words = set(base_words)

        if "+digits" in rules:
            max_digits = 1 
            match = re.search(r'\+digits(\d+)', rules)
            if match:
                max_digits = int(match.group(1))
            
            current_processed = list(processed_words)
            for word in current_processed:
                for i in range(1, max_digits + 1):
                    for num_tuple in itertools.product(string.digits, repeat=i):
                         num_str = "".join(num_tuple)
                         new_list.add(word + num_str)
            processed_words.update(new_list)
        
        if "+symbols" in rules:
            symbols_to_add = "!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?~`"
            current_processed = list(processed_words)
            for word in current_processed:
                for sym in symbols_to_add:
                    new_list.add(word + sym)
            processed_words.update(new_list)
            
        if "leet" in rules:
             leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l':'1'}
             temp_words = set()
             current_processed = list(processed_words)
             for word in current_processed:
                leet_word = word.lower()
                has_leet = False
                temp_leet_word = leet_word
                for char, replacement in leet_map.items():
                     if char in temp_leet_word:
                         temp_leet_word = temp_leet_word.replace(char, replacement)
                         has_leet = True
                if has_leet:
                    temp_words.add(temp_leet_word)
             new_list.update(temp_words)
             processed_words.update(new_list)
             
        return sorted(list(new_list))

    def execute(self, code: str) -> Any:
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        lines = code.strip().split('\n')
        last_result = None
        i = 0
        while i < len(lines):
            original_line = lines[i].strip()
            i += 1
            line = original_line
            if not line: continue

            assignment_target = None
            expression_on_right = None
            match = re.match(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:=\s*(.*)", line)
            if match:
                assignment_target = match.group(1).strip()
                expression_on_right = match.group(2).strip()
                line = expression_on_right

            command_handled_assignment = False

            if line.startswith('show '):
                expr = line[len('show '):].strip()
                try:
                    value = self.evaluate(expr)
                    print(value)
                    last_result = value
                except Exception as e:
                    print(f"Error evaluating for show: {e}")
                    last_result = None
                
            elif line.startswith('get '):
                url_expr = line[len('get '):].strip()
                result = None
                try:
                    url = self.evaluate(url_expr)
                    response = requests.get(str(url)); response.raise_for_status()
                    try: result = response.json()
                    except json.JSONDecodeError: result = response.text
                except Exception as e: print(f"Error during GET: {e}"); result = None
                last_result = result
                if assignment_target: self.variables[assignment_target] = result; command_handled_assignment = True

            elif line.startswith('post '):
                parts = line[len('post '):].strip().split(',', 1)
                result = None
                if len(parts) == 2:
                    url_expr, data_expr = parts[0].strip(), parts[1].strip()
                    try:
                        url = self.evaluate(url_expr); data = self.evaluate(data_expr)
                        response = requests.post(str(url), json=data if isinstance(data, (dict, list)) else {'data': data}); response.raise_for_status()
                        try: result = response.json()
                        except json.JSONDecodeError: result = response.text
                    except Exception as e: print(f"Error during POST: {e}"); result = None
                    last_result = result
                    if assignment_target: self.variables[assignment_target] = result; command_handled_assignment = True
                else: print("Error: 'post' needs URL, data"); last_result = None
            
            elif line.startswith('generate_wordlist '):
                 parts = line[len('generate_wordlist '):].strip().split(' ', 2)
                 if len(parts) == 3:
                     base_list_var, rules_expr, output_var = parts
                     try:
                         if base_list_var not in self.variables or not isinstance(self.variables[base_list_var], list):
                              print(f"Error: Base wordlist '{base_list_var}' must be a valid list variable.")
                              last_result = None
                         else:
                              base_words = [str(w) for w in self.variables[base_list_var]]
                              rules = str(self.evaluate(rules_expr))
                              output_var_name = output_var.strip()
                              if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", output_var_name):
                                  print(f"Error: Invalid variable name for output: '{output_var_name}'")
                                  last_result = None
                              else:
                                  generated_list = self._generate_wordlist(base_words, rules)
                                  self.variables[output_var_name] = generated_list
                                  print(f"Generated {len(generated_list)} words into variable '{output_var_name}'.")
                                  last_result = len(generated_list)
                     except Exception as e:
                          print(f"Error generating wordlist: {e}")
                          last_result = None
                 else:
                     print("Error: 'generate_wordlist' requires base_list_variable, rules_string, output_variable.")
                     last_result = None

            elif line.startswith('serve on '):
                 port_expr = line[len('serve on '):].strip()
                 try:
                     port = int(self.evaluate(port_expr))
                     if self.server_thread and self.server_thread.is_alive(): print(f"HTTP Server already running.")
                     else:
                         self.httpd = HTTPServer(("", port), SimpleViperHandler)
                         self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True); self.server_thread.start()
                         print(f"Serving HTTP on port {port}..."); last_result = f"Serving on port {port}"
                 except Exception as e: print(f"Error starting HTTP server: {e}"); last_result = None
            elif line.startswith('stop server'):
                 if self.httpd: print("Stopping HTTP server..."); self.httpd.shutdown(); self.server_thread.join(); self.httpd = None; self.server_thread = None; print("HTTP Server stopped."); last_result = "Server stopped"
                 else: print("HTTP Server not running."); last_result = "Server not running"

            elif line.startswith('tcp_send '):
                parts = line[len('tcp_send '):].strip().split(' ', 2)
                if len(parts) == 3:
                    host_expr, port_expr, data_expr = parts
                    try:
                        host = str(self.evaluate(host_expr)); port = int(self.evaluate(port_expr)); data = self.evaluate(data_expr)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((host, port)); s.sendall(str(data).encode('utf-8'))
                        print(f"TCP data sent to {host}:{port}"); last_result = True
                    except Exception as e: print(f"Error sending TCP data: {e}"); last_result = False
                else: print("Error: 'tcp_send' requires host, port, data."); last_result = None
            
            elif line.startswith('udp_send '):
                 parts = line[len('udp_send '):].strip().split(' ', 2)
                 if len(parts) == 3:
                     host_expr, port_expr, data_expr = parts
                     try:
                         host = str(self.evaluate(host_expr)); port = int(self.evaluate(port_expr)); data = self.evaluate(data_expr)
                         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                             s.sendto(str(data).encode('utf-8'), (host, port))
                         print(f"UDP data sent to {host}:{port}"); last_result = True
                     except Exception as e: print(f"Error sending UDP data: {e}"); last_result = False
                 else: print("Error: 'udp_send' requires host, port, data."); last_result = None

            elif line.startswith('vip '):
                parts = shlex.split(line, posix=False)
                if len(parts) < 2: 
                    print("Error: 'vip' requires at least a host."); last_result = None
                else:
                    host_expr = parts[1]
                    ping_args = {'unit': 'ms'}
                    arg_parse_error = False
                    for part in parts[2:]:
                         try:
                             if part.startswith("timeout="): ping_args['timeout'] = int(self.evaluate(part[len("timeout="):].strip()))
                             elif part.startswith("size="): ping_args['size'] = int(self.evaluate(part[len("size="):].strip()))
                             elif part.startswith("interval="): ping_args['interval'] = float(self.evaluate(part[len("interval="):].strip()))
                             elif part.startswith("count="): ping_args['count'] = int(self.evaluate(part[len("count="):].strip()))
                             else: print(f"Warning: Unknown argument ignored in vip: {part}")
                         except Exception as e: print(f"Error parsing argument '{part}' for vip: {e}"); arg_parse_error = True; break
                    if not arg_parse_error:
                        try:
                            host = str(self.evaluate(host_expr))
                            print(f"Pinging {host} with options: {ping_args}...")
                            count = ping_args.get('count', 1)
                            if count > 1:
                                print("--- Verbose Ping Output --- (Result will be None)")
                                ping3.verbose_ping(host, **ping_args)
                                print("--- End Verbose Ping ---")
                                last_result = None
                            else:
                                delay = ping3.ping(host, **ping_args)
                                if delay is not None: print(f"Ping Reply from {host}: time={delay:.2f} ms"); last_result = delay
                                else: print(f"Ping to {host} timed out or failed."); last_result = None
                            if assignment_target: self.variables[assignment_target] = last_result; command_handled_assignment = True
                        except PermissionError: print(f"Error: Ping requires administrator/root privileges."); last_result = None
                        except Exception as e: print(f"Error during ping: {e}"); last_result = None
                            
            elif line.startswith('scan_ports '):
                parts = line[len('scan_ports '):].strip().split()
                if 1 <= len(parts) <= 3:
                     host_expr = parts[0]
                     start_port_expr = parts[1] if len(parts) > 1 else '1'
                     end_port_expr = parts[2] if len(parts) > 2 else '1024'
                     try:
                         host = str(self.evaluate(host_expr))
                         start_port = int(self.evaluate(start_port_expr)); end_port = int(self.evaluate(end_port_expr))
                         if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                             print("Error: Invalid port range (1-65535, start <= end)."); last_result = None
                         else:
                             open_ports = []
                             print(f"Scanning ports {start_port}-{end_port} on {host}...")
                             for port in range(start_port, end_port + 1):
                                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(0.2)
                                 result = sock.connect_ex((host, port))
                                 if result == 0:
                                     service_name = "unknown"
                                     try: service_name = socket.getservbyport(port, "tcp")
                                     except OSError: pass 
                                     print(f"  Port {port}: Open ({service_name})")
                                     open_ports.append(port)
                                 sock.close()
                             print(f"Scan finished. Found {len(open_ports)} open port(s).")
                             last_result = open_ports
                             if assignment_target: self.variables[assignment_target] = open_ports; command_handled_assignment = True
                     except socket.gaierror: print(f"Error: Hostname {host_expr} could not be resolved."); last_result = None
                     except ValueError: print("Error: Invalid port number specified."); last_result = None
                     except Exception as e: print(f"Error scanning ports: {e}"); last_result = None
                else: print("Error: 'scan_ports' requires host [start_port] [end_port]"); last_result = None
                     
            elif line.startswith('tcp_listen '):
                 parts = line[len('tcp_listen '):].strip().split()
                 if len(parts) == 2:
                     host_expr, port_expr = parts
                     try:
                         host = str(self.evaluate(host_expr)); port = int(self.evaluate(port_expr))
                         listener_key = (host, port)
                         if listener_key in listener_threads and listener_threads[listener_key].is_alive():
                             print(f"TCP Listener already running on {host}:{port}"); last_result = False
                         elif not (1 <= port <= 65535):
                              print(f"Error: Invalid port number {port}. Must be 1-65535."); last_result = None
                         else:
                             stop_listener_flags[listener_key] = False
                             thread = threading.Thread(target=tcp_listener_thread, args=(host, port, listener_key), daemon=True)
                             listener_threads[listener_key] = thread; thread.start(); time.sleep(0.1)
                             if thread.is_alive():
                                 last_result = True; print(f"TCP Listener started successfully in background for {host}:{port}.")
                             else: 
                                 last_result = False; print(f"TCP Listener failed to start properly for {host}:{port}. Check for errors above.")
                                 if listener_key in listener_threads: del listener_threads[listener_key]
                                 if listener_key in stop_listener_flags: del stop_listener_flags[listener_key]
                     except ValueError: print(f"Error: Invalid port number specified: {port_expr}"); last_result = None
                     except Exception as e: print(f"Error starting TCP listener: {e}"); last_result = None
                 else: print("Error: 'tcp_listen' requires host port"); last_result = None

            elif line.startswith('stop_listeners'):
                 count = 0
                 keys_to_stop = list(listener_threads.keys())
                 if not keys_to_stop: print("No active TCP listeners found to stop."); last_result = 0
                 else:
                      print(f"Sending stop signal to {len(keys_to_stop)} TCP listener(s)...")
                      for key in keys_to_stop:
                          if listener_threads.get(key) and listener_threads[key].is_alive(): stop_listener_flags[key] = True; count += 1
                          else:
                               if key in listener_threads: del listener_threads[key]
                               if key in stop_listener_flags: del stop_listener_flags[key]
                      print(f"Stop signal sent to {count} active listener(s). They will shut down shortly.")
                      last_result = count

            elif line.startswith('dns_lookup '):
                 host_expr = line[len('dns_lookup '):].strip()
                 if not host_expr: print("Error: 'dns_lookup' requires a hostname."); last_result = None
                 else:
                     try:
                         hostname = str(self.evaluate(host_expr)); ip_address = socket.gethostbyname(hostname)
                         print(f"DNS lookup for {hostname}: {ip_address}"); last_result = ip_address
                         if assignment_target: self.variables[assignment_target] = ip_address; command_handled_assignment = True
                     except socket.gaierror: print(f"Error: Could not resolve hostname: {hostname}"); last_result = None
                     except Exception as e: print(f"Error during DNS lookup: {e}"); last_result = None

            elif line.startswith('ssh_bruteforce '):
                 print("WARNING: SSH bruteforcing requires explicit permission.")
                 parts = line[len('ssh_bruteforce '):].strip().split(' ', 3)
                 if len(parts) == 4:
                     host_expr, port_expr, user_expr, wordlist_path_expr = parts
                     ssh = None
                     try:
                         host = str(self.evaluate(host_expr)); port = int(self.evaluate(port_expr)); username = str(self.evaluate(user_expr)); wordlist_path = str(self.evaluate(wordlist_path_expr))
                         found_password = None
                         try:
                             with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                                 ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                 password_count = 0
                                 for password in f:
                                     password = password.strip()
                                     if not password: continue
                                     password_count += 1
                                     if password_count % 50 == 0: print(f"Trying password #{password_count}...")
                                     try: ssh.connect(host, port=port, username=username, password=password, timeout=5); print(f"\nSUCCESS: Password found for {username}@{host}: {password}"); found_password = password; ssh.close(); ssh = None; break
                                     except paramiko.AuthenticationException: continue
                                     except paramiko.SSHException as sshEx: print(f"\nSSH connection error: {sshEx}"); break
                                     except socket.timeout: print(f"\nConnection timed out for password attempt."); continue 
                                     except Exception as e: print(f"\nError during SSH connection attempt: {e}"); break
                                 if ssh: ssh.close()
                                 if not found_password: print(f"Bruteforce attempt finished after {password_count} passwords. No password found.")
                                 last_result = found_password
                         except FileNotFoundError: print(f"Error: Wordlist file not found: {wordlist_path}"); last_result = None
                         except Exception as e: print(f"Error reading wordlist file '{wordlist_path}': {e}"); last_result = None
                     except ValueError: print(f"Error: Invalid port number specified: {port_expr}"); last_result = None
                     except Exception as e: print(f"Error setting up SSH bruteforce: {e}"); last_result = None
                     finally: 
                          if ssh: 
                              try: ssh.close()
                              except: pass
                 else: print("Error: 'ssh_bruteforce' requires host, port, user, wordlist_filepath."); last_result = None

            elif line.startswith('ssh_exec '):
                 print("WARNING: Executing commands via SSH requires authorization.")
                 parts = line[len('ssh_exec '):].strip().split(' ', 4)
                 if len(parts) == 5:
                      host_expr, port_expr, user_expr, pass_expr, command_expr = parts
                      ssh = None
                      try:
                          host = str(self.evaluate(host_expr)); port = int(self.evaluate(port_expr)); user = str(self.evaluate(user_expr))
                          password = str(self.evaluate(pass_expr)); command = str(self.evaluate(command_expr))
                          if not command: print("Error: SSH command cannot be empty."); last_result = None
                          else:
                              ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                              print(f"Connecting to {user}@{host}:{port}...")
                              ssh.connect(host, port=port, username=user, password=password, timeout=15)
                              print(f"Executing command: '{command}'")
                              stdin, stdout, stderr = ssh.exec_command(command)
                              output = stdout.read().decode('utf-8', errors='ignore').strip()
                              error = stderr.read().decode('utf-8', errors='ignore').strip()
                              exit_status = stdout.channel.recv_exit_status()
                              ssh.close(); ssh = None
                              print("--- SSH Command Result ---"); print(f"Exit Status: {exit_status}")
                              if output: print(f"Output:\n{output}")
                              if error: print(f"Error Output:\n{error}")
                              print("-------------------------")
                              result_data = {"exit_status": exit_status, "output": output, "error": error}
                              last_result = result_data
                              if assignment_target: self.variables[assignment_target] = result_data; command_handled_assignment = True
                      except paramiko.AuthenticationException: print(f"SSH Authentication failed for {user}@{host}:{port}."); last_result = None
                      except paramiko.SSHException as sshEx: print(f"SSH connection error to {host}:{port}: {sshEx}"); last_result = None
                      except socket.timeout: print(f"SSH connection to {host}:{port} timed out."); last_result = None
                      except ValueError: print(f"Error: Invalid port number specified: {port_expr}"); last_result = None
                      except Exception as e: print(f"Error during SSH execution: {e}"); last_result = None
                      finally: 
                           if ssh: 
                               try: ssh.close()
                               except: pass
                 else: print("Error: 'ssh_exec' requires host, port, user, password, command_string."); last_result = None

            elif line.startswith('httpv '):
                parts = shlex.split(line, posix=False) 
                if len(parts) < 3: 
                    print("Error: 'httpv' requires at least a method and URL."); last_result = None
                else:
                    method = parts[1].upper()
                    if method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
                         print(f"Error: Invalid HTTP method '{method}'."); last_result = None
                    else:
                        url_expr = parts[2]
                        data_arg = None; headers_arg = None; proxy_arg = None 
                        for part in parts[3:]:
                            if part.startswith("data="): data_arg = part[len("data="):]
                            elif part.startswith("headers="): headers_arg = part[len("headers="):]
                            elif part.startswith("proxy="): proxy_arg = part[len("proxy="):]
                            else: print(f"Warning: Unknown argument ignored in httpv: {part}")
                        if not url_expr: 
                            print(f"Error: Missing URL for httpv {method}."); last_result = None
                        else:
                             start_time = time.time()
                             request_params = {"timeout": 15}
                             proxies_dict = None 
                             error_occurred = False
                             try:
                                 url = str(self.evaluate(url_expr))
                                 if not url.startswith(('http://', 'https://')):
                                     print(f"Warning: URL scheme missing, assuming https:// for {url}")
                                     url = 'https://' + url
                                 if data_arg:
                                     if data_arg in self.variables: request_params['json'] = self.variables[data_arg] 
                                     else: print(f"Error: Data variable '{data_arg}' not found."); error_occurred = True
                                 if headers_arg and not error_occurred:
                                      if headers_arg in self.variables:
                                          headers_val = self.variables[headers_arg]
                                          if isinstance(headers_val, dict): request_params['headers'] = headers_val
                                          else: print(f"Error: Headers variable '{headers_arg}' must be a dictionary."); error_occurred = True
                                      else: print(f"Error: Headers variable '{headers_arg}' not found."); error_occurred = True
                                 if proxy_arg and not error_occurred:
                                     if proxy_arg in self.variables:
                                         proxy_str = str(self.variables[proxy_arg])
                                         if proxy_str.startswith(('http://', 'https://')):
                                             proxies_dict = {'http': proxy_str, 'https': proxy_str}
                                             print(f"Using proxy: {proxy_str}")
                                         else: print(f"Error: Proxy variable '{proxy_arg}' must be a valid proxy URL string."); error_occurred = True
                                     else: print(f"Error: Proxy variable '{proxy_arg}' not found."); error_occurred = True
                                 if not error_occurred:
                                     print(f"HTTPV Request: {method} {url}")
                                     if 'json' in request_params: print(f"  with data: {request_params['json']}")
                                     if 'headers' in request_params: print(f"  with headers: {request_params['headers']}")
                                     if proxies_dict: print(f"  via proxy: {proxies_dict['http']}")
                                     response = requests.request(method, url, proxies=proxies_dict, **request_params)
                                     end_time = time.time(); duration = end_time - start_time
                                     print(f"HTTPV Response Status: {response.status_code} ({response.reason})"); print(f"HTTPV Request Duration: {duration:.3f} seconds")
                                     try: result_content = response.json()
                                     except json.JSONDecodeError: result_content = response.text
                                     result_data = { "status_code": response.status_code, "reason": response.reason, "headers": dict(response.headers), "content": result_content, "duration_sec": duration, "url": url, "method": method }
                                     last_result = result_data
                                     if assignment_target: self.variables[assignment_target] = result_data; command_handled_assignment = True
                             except requests.exceptions.Timeout: print(f"Error: HTTPV request ({method} {url_expr}) timed out."); last_result = None
                             except requests.exceptions.ConnectionError: print(f"Error: HTTPV connection failed ({method} {url_expr})."); last_result = None
                             except requests.exceptions.RequestException as e: print(f"Error: HTTPV request failed ({method} {url_expr}): {e}"); last_result = None
                             except Exception as e: print(f"Error processing httpv command: {e}"); last_result = None
            
            elif line.startswith('md5 '):
                data_expr = line[len('md5 '):].strip()
                if not data_expr: print("Error: 'md5' requires data."); last_result = None
                else:
                     try:
                         data_to_hash = str(self.evaluate(data_expr))
                         hash_obj = hashlib.md5(data_to_hash.encode('utf-8')); hex_digest = hash_obj.hexdigest()
                         print(f"MD5(\"{data_to_hash}\"): {hex_digest}"); last_result = hex_digest
                         if assignment_target: self.variables[assignment_target] = hex_digest; command_handled_assignment = True
                     except Exception as e: print(f"Error calculating MD5: {e}"); last_result = None
            
            elif line.startswith('sha256 '):
                 data_expr = line[len('sha256 '):].strip()
                 if not data_expr: print("Error: 'sha256' requires data."); last_result = None
                 else:
                      try:
                          data_to_hash = str(self.evaluate(data_expr))
                          hash_obj = hashlib.sha256(data_to_hash.encode('utf-8')); hex_digest = hash_obj.hexdigest()
                          print(f"SHA256(\"{data_to_hash}\"): {hex_digest}"); last_result = hex_digest
                          if assignment_target: self.variables[assignment_target] = hex_digest; command_handled_assignment = True
                      except Exception as e: print(f"Error calculating SHA256: {e}"); last_result = None
                          
            elif line.startswith('fetch_proxies '):
                 parts = line[len('fetch_proxies '):].strip().split(' ', 1)
                 if len(parts) == 2:
                      url_expr, output_var = parts
                      output_var_name = output_var.strip()
                      if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", output_var_name):
                           print(f"Error: Invalid output variable name '{output_var_name}'"); last_result = None
                      else:
                           try:
                               url = str(self.evaluate(url_expr))
                               print(f"Fetching proxies from: {url}")
                               response = requests.get(url, timeout=15); response.raise_for_status()
                               proxy_text = response.text
                               proxies = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", proxy_text)
                               if proxies:
                                   self.variables[output_var_name] = proxies
                                   print(f"Fetched {len(proxies)} proxies into variable '{output_var_name}'."); last_result = proxies
                               else:
                                    print(f"No proxies found in the response from {url}."); self.variables[output_var_name] = []; last_result = []
                           except requests.exceptions.RequestException as e: print(f"Error fetching proxies from {url_expr}: {e}"); last_result = None
                           except Exception as e: print(f"Error processing fetch_proxies: {e}"); last_result = None
                 else: print("Error: 'fetch_proxies' requires url and output_variable."); last_result = None
            
            elif line.startswith('read_file '):
                path_expr = line[len('read_file '):].strip()
                if not path_expr: print("Error: 'read_file' requires a filepath."); last_result = None
                else:
                     try:
                         file_path = str(self.evaluate(path_expr))
                         with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
                         print(f"Read {len(content)} characters from '{file_path}'."); last_result = content
                         if assignment_target: self.variables[assignment_target] = content; command_handled_assignment = True
                     except FileNotFoundError: print(f"Error: File not found: '{file_path}'"); last_result = None
                     except Exception as e: print(f"Error reading file '{file_path}': {e}"); last_result = None
                         
            elif line.startswith('get_banner '):
                parts = line[len('get_banner '):].strip().split()
                if 2 <= len(parts) <= 3:
                     host_expr = parts[0]; port_expr = parts[1]
                     timeout_expr = parts[2] if len(parts) == 3 else '5'
                     try:
                         host = str(self.evaluate(host_expr)); port = int(self.evaluate(port_expr)); timeout = float(self.evaluate(timeout_expr))
                         banner = ""
                         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                             s.settimeout(timeout); print(f"Connecting to {host}:{port} for banner..."); s.connect((host, port)); print("Connection successful, receiving banner...")
                             data = s.recv(2048); banner = data.decode('utf-8', errors='ignore').strip()
                             print(f"Received Banner ({len(banner)} chars):\n---\n{banner}\n---"); last_result = banner
                             if assignment_target: self.variables[assignment_target] = banner; command_handled_assignment = True
                     except socket.timeout: print(f"Error: Timeout connecting/receiving banner from {host}:{port} after {timeout}s."); last_result = None
                     except ConnectionRefusedError: print(f"Error: Connection refused by {host}:{port}."); last_result = None
                     except ValueError: print(f"Error: Invalid port or timeout specified."); last_result = None
                     except Exception as e: print(f"Error getting banner from {host}:{port}: {e}"); last_result = None
                else: print("Error: 'get_banner' requires host, port, [optional_timeout]"); last_result = None
                     
            elif line.startswith('base64_encode '):
                 data_expr = line[len('base64_encode '):].strip()
                 if not data_expr: print("Error: 'base64_encode' requires data string."); last_result = None
                 else:
                     try:
                          data_to_encode = str(self.evaluate(data_expr))
                          encoded_bytes = base64.b64encode(data_to_encode.encode('utf-8')); encoded_string = encoded_bytes.decode('utf-8')
                          print(f"Base64 Encoded: {encoded_string}"); last_result = encoded_string
                          if assignment_target: self.variables[assignment_target] = encoded_string; command_handled_assignment = True
                     except Exception as e: print(f"Error during Base64 encoding: {e}"); last_result = None
                          
            elif line.startswith('base64_decode '):
                 data_expr = line[len('base64_decode '):].strip()
                 if not data_expr: print("Error: 'base64_decode' requires Base64 string."); last_result = None
                 else:
                      try:
                           b64_string = str(self.evaluate(data_expr))
                           missing_padding = len(b64_string) % 4
                           if missing_padding: b64_string += '=' * (4 - missing_padding)
                           decoded_bytes = base64.b64decode(b64_string); decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
                           print(f"Base64 Decoded: {decoded_string}"); last_result = decoded_string
                           if assignment_target: self.variables[assignment_target] = decoded_string; command_handled_assignment = True
                      except base64.binascii.Error as e: print(f"Error decoding Base64: Invalid input - {e}"); last_result = None
                      except Exception as e: print(f"Error during Base64 decoding: {e}"); last_result = None
            
            elif line.startswith('write_file '):
                parts = line[len('write_file '):].strip().split(' ', 1)
                if len(parts) == 2:
                    path_expr, data_expr = parts
                    try:
                        file_path = str(self.evaluate(path_expr)); data_to_write = str(self.evaluate(data_expr))
                        with open(file_path, 'w', encoding='utf-8') as f: f.write(data_to_write)
                        print(f"Wrote {len(data_to_write)} characters to '{file_path}'."); last_result = True
                    except Exception as e: print(f"Error writing to file '{path_expr}': {e}"); last_result = False
                else: print("Error: 'write_file' requires filepath and data."); last_result = None
                    
            elif line.startswith('append_file '):
                parts = line[len('append_file '):].strip().split(' ', 1)
                if len(parts) == 2:
                     path_expr, data_expr = parts
                     try:
                         file_path = str(self.evaluate(path_expr)); data_to_append = str(self.evaluate(data_expr))
                         with open(file_path, 'a', encoding='utf-8') as f: f.write(data_to_append)
                         print(f"Appended {len(data_to_append)} characters to '{file_path}'."); last_result = True
                     except Exception as e: print(f"Error appending to file '{path_expr}': {e}"); last_result = False
                else: print("Error: 'append_file' requires filepath and data."); last_result = None

            elif line.startswith('find_comments '):
                 target_expr = line[len('find_comments '):].strip()
                 if not target_expr: print("Error: 'find_comments' requires URL or HTML string variable."); last_result = None
                 else:
                      html_content = ""; last_result = None
                      try:
                           target = self.evaluate(target_expr)
                           if isinstance(target, str):
                               if target.startswith(('http://', 'https://')): 
                                   print(f"Fetching content from URL: {target}")
                                   response = requests.get(target, timeout=10); response.raise_for_status(); html_content = response.text
                               else: html_content = target
                           else: print("Error: Input for find_comments must be a URL string or HTML string variable."); continue
                           comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL); comments = [c.strip() for c in comments]
                           print(f"Found {len(comments)} HTML comments."); last_result = comments
                           if assignment_target: self.variables[assignment_target] = comments; command_handled_assignment = True
                      except requests.exceptions.RequestException as e: print(f"Error fetching URL for find_comments: {e}")
                      except Exception as e: print(f"Error finding comments: {e}")
                           
            elif line.startswith('extract_links '):
                 target_expr = line[len('extract_links '):].strip()
                 if not target_expr: print("Error: 'extract_links' requires URL or HTML string variable."); last_result = None
                 else:
                      html_content = ""; base_url = ""; last_result = None
                      try:
                           target = self.evaluate(target_expr)
                           if isinstance(target, str):
                               if target.startswith(('http://', 'https://')): 
                                   print(f"Fetching content from URL: {target}")
                                   response = requests.get(target, timeout=10); response.raise_for_status(); html_content = response.text; base_url = target
                               else: html_content = target
                           else: print("Error: Input for extract_links must be a URL string or HTML string variable."); continue
                           links = re.findall(r'<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>', html_content, re.IGNORECASE)
                           print(f"Extracted {len(links)} links."); last_result = links
                           if assignment_target: self.variables[assignment_target] = links; command_handled_assignment = True
                      except requests.exceptions.RequestException as e: print(f"Error fetching URL for extract_links: {e}")
                      except Exception as e: print(f"Error extracting links: {e}")
                           
            elif line.startswith('check_header '):
                 parts = line[len('check_header '):].strip().split(' ', 1)
                 if len(parts) == 2:
                      url_expr, header_name_expr = parts
                      try:
                           url = str(self.evaluate(url_expr)); header_name = str(self.evaluate(header_name_expr)).lower()
                           if not url.startswith(('http://', 'https://')): print(f"Warning: Assuming https:// for {url}"); url = 'https://' + url
                           print(f"Checking header '{header_name}' for {url}...")
                           response = requests.head(url, timeout=10, allow_redirects=True); response.raise_for_status()
                           header_value = None
                           for key, value in response.headers.items():
                                if key.lower() == header_name: header_value = value; break
                           if header_value: print(f"Header '{header_name}': {header_value}"); last_result = header_value
                           else: print(f"Header '{header_name}' not found."); last_result = None
                           if assignment_target: self.variables[assignment_target] = last_result; command_handled_assignment = True
                      except requests.exceptions.RequestException as e: print(f"Error checking header for {url_expr}: {e}"); last_result = None
                      except Exception as e: print(f"Error processing check_header: {e}"); last_result = None
                 else: print("Error: 'check_header' requires url and header_name."); last_result = None

            elif line.startswith('url_encode '):
                 data_expr = line[len('url_encode '):].strip()
                 if not data_expr: print("Error: 'url_encode' requires data string."); last_result = None
                 else:
                     try:
                          data_to_encode = str(self.evaluate(data_expr)); encoded_string = quote_plus(data_to_encode)
                          print(f"URL Encoded: {encoded_string}"); last_result = encoded_string
                          if assignment_target: self.variables[assignment_target] = encoded_string; command_handled_assignment = True
                     except Exception as e: print(f"Error during URL encoding: {e}"); last_result = None
                          
            elif line.startswith('url_decode '):
                 data_expr = line[len('url_decode '):].strip()
                 if not data_expr: print("Error: 'url_decode' requires URL encoded string."); last_result = None
                 else:
                      try:
                           encoded_data = str(self.evaluate(data_expr)); decoded_string = unquote_plus(encoded_data)
                           print(f"URL Decoded: {decoded_string}"); last_result = decoded_string
                           if assignment_target: self.variables[assignment_target] = decoded_string; command_handled_assignment = True
                      except Exception as e: print(f"Error during URL decoding: {e}"); last_result = None
                           
            elif line.startswith('ntp_info '):
                 host_expr = line[len('ntp_info '):].strip()
                 if not host_expr: print("Error: 'ntp_info' requires a host."); last_result = None
                 else:
                      try:
                          host = str(self.evaluate(host_expr)); port = 123
                          client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); client.settimeout(3.0)
                          data = b'\x1b' + 47 * b'\0' 
                          print(f"Sending NTP request to {host}:{port}...")
                          client.sendto(data, (host, port)); response_data, server_addr = client.recvfrom(1024); client.close()
                          if response_data:
                               unpacked = struct.unpack("!B B B b 11I", response_data); li_vn_mode = unpacked[0]; stratum = unpacked[1]
                               NTP_DELTA = 2208988800; tx_timestamp_secs = unpacked[10] - NTP_DELTA; tx_time = time.ctime(tx_timestamp_secs)
                               info = {"server": server_addr[0], "stratum": stratum, "transmit_time_unix": tx_timestamp_secs, "transmit_time_utc": tx_time}
                               print(f"NTP Response from {info['server']}: Stratum={info['stratum']}, Time={info['transmit_time_utc']}"); last_result = info
                               if assignment_target: self.variables[assignment_target] = info; command_handled_assignment = True
                          else: print("NTP query failed: No response data."); last_result = None
                      except socket.gaierror: print(f"Error: Could not resolve NTP host: {host_expr}"); last_result = None
                      except socket.timeout: print(f"Error: NTP query to {host_expr} timed out."); last_result = None
                      except Exception as e: print(f"Error during NTP query: {e}"); last_result = None
                           
            elif line.startswith('run_cmd '):
                 print("!!! SECURITY WARNING !!!\nExecuting arbitrary system commands is EXTREMELY DANGEROUS.\nEnsure command string is trusted. Use with caution!\n")
                 cmd_expr = line[len('run_cmd '):].strip()
                 if not cmd_expr: print("Error: 'run_cmd' requires a command string."); last_result = None
                 else:
                     try:
                         command_to_run = str(self.evaluate(cmd_expr)); print(f"Executing system command: {command_to_run}")
                         process = subprocess.run(command_to_run, shell=True, capture_output=True, text=True, timeout=30)
                         output = process.stdout.strip(); error = process.stderr.strip(); return_code = process.returncode
                         print(f"Command Return Code: {return_code}")
                         if output: print(f"Command Output:\n{output}")
                         if error: print(f"Command Error Output:\n{error}")
                         result_data = {"return_code": return_code, "output": output, "error": error}
                         last_result = result_data
                         if assignment_target: self.variables[assignment_target] = result_data; command_handled_assignment = True
                     except subprocess.TimeoutExpired: print(f"Error: Command '{command_to_run}' timed out."); last_result = None
                     except Exception as e: print(f"Error executing system command: {e}"); last_result = None
                         
            elif line.startswith('simple_listener '):
                 port_expr = line[len('simple_listener '):].strip()
                 if not port_expr: print("Error: 'simple_listener' requires a port."); last_result = None
                 else:
                     listener_socket = None
                     try:
                         port = int(self.evaluate(port_expr))
                         if not (1 <= port <= 65535): print(f"Error: Invalid port number {port}. Must be 1-65535."); last_result = None
                         else:
                             host = "0.0.0.0"; listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                             listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener_socket.bind((host, port))
                             listener_socket.listen(1); print(f"[Simple Listener] Waiting for connection on {host}:{port}...")
                             client_socket, addr = listener_socket.accept(); print(f"[Simple Listener] Connection received from {addr[0]}:{addr[1]}")
                             listener_socket.close(); listener_socket = None 
                             received_all_data = ""; client_socket.settimeout(5.0)
                             try:
                                 while True:
                                      data = client_socket.recv(1024); 
                                      if not data: break
                                      decoded = data.decode('utf-8', errors='ignore')
                                      print(f"[Simple Listener] Received: {decoded}", end='')
                                      received_all_data += decoded
                             except socket.timeout: print("\n[Simple Listener] Timeout waiting for more data.")
                             except Exception as recv_e: print(f"\n[Simple Listener] Error receiving data: {recv_e}")
                             finally:
                                 print("\n[Simple Listener] Closing client connection."); client_socket.close(); last_result = received_all_data
                                 if assignment_target: self.variables[assignment_target] = received_all_data; command_handled_assignment = True
                     except ValueError: print(f"Error: Invalid port number specified: {port_expr}"); last_result = None
                     except Exception as e: print(f"Error starting simple listener: {e}"); last_result = None
                     finally:
                          if listener_socket: 
                              try: listener_socket.close()
                              except: pass
            
            elif line.startswith('shell'):
                print("\n!!! SECURITY WARNING !!!")
                print("Entering interactive shell mode. Use 'exit' to return to Viper.")
                print("This is a direct system shell - use with extreme caution!\n")
                
                shell_cmd = "cmd.exe" if os.name == "nt" else "/bin/bash"
                try:
                    subprocess.run(shell_cmd, shell=True)
                except Exception as e:
                    print(f"Error launching shell: {e}")
                print("\nReturned to Viper interpreter.")
                last_result = None

            elif line.startswith('set_user_agent '):
                agent_expr = line[len('set_user_agent '):].strip()
                if not agent_expr:
                    print("Error: 'set_user_agent' requires a user agent string or 'random'.")
                    last_result = None
                else:
                    try:
                        if agent_expr.lower() == 'random':
                            agent = random.choice(DEFAULT_USER_AGENTS)
                        else:
                            agent = str(self.evaluate(agent_expr))
                        self.variables['current_user_agent'] = agent
                        print(f"User Agent set to: {agent}")
                        last_result = agent
                    except Exception as e:
                        print(f"Error setting user agent: {e}")
                        last_result = None

            elif line.startswith('fuzz_params '):
                parts = line[len('fuzz_params '):].strip().split(' ', 2)
                if len(parts) < 2:
                    print("Error: 'fuzz_params' requires URL and payload_type (sql/xss/lfi/rce/nosql/numeric/special)")
                    last_result = None
                else:
                    url_expr = parts[0]
                    payload_type = parts[1].lower()
                    target_param = parts[2] if len(parts) > 2 else None
                    
                    try:
                        url = str(self.evaluate(url_expr))
                        if payload_type not in FUZZING_PAYLOADS:
                            print(f"Error: Unknown payload type. Available types: {', '.join(FUZZING_PAYLOADS.keys())}")
                            last_result = None
                            continue

                        parsed_url = urlparse(url)
                        params = parse_qs(parsed_url.query)
                        results = []

                        if not params:
                            print("No parameters found in URL to fuzz.")
                            last_result = None
                            continue

                        print(f"\nFuzzing parameters in {url}")
                        print(f"Using {payload_type} payloads")
                        
                        for param in params:
                            if target_param and param != target_param:
                                continue
                                
                            print(f"\nFuzzing parameter: {param}")
                            for payload in FUZZING_PAYLOADS[payload_type]:
                                new_params = params.copy()
                                new_params[param] = [payload]
                                
                                # Reconstruct URL with new parameters
                                new_query = urlencode(new_params, doseq=True)
                                fuzz_url = parsed_url._replace(query=new_query).geturl()
                                
                                try:
                                    headers = {}
                                    if 'current_user_agent' in self.variables:
                                        headers['User-Agent'] = self.variables['current_user_agent']
                                    
                                    print(f"\nTrying: {param} = {payload}")
                                    response = requests.get(fuzz_url, headers=headers, timeout=10)
                                    
                                    result = {
                                        "parameter": param,
                                        "payload": payload,
                                        "status_code": response.status_code,
                                        "response_length": len(response.text),
                                        "url": fuzz_url
                                    }
                                    
                                    print(f"Status: {response.status_code}, Length: {len(response.text)}")
                                    results.append(result)
                                    
                                except Exception as e:
                                    print(f"Error testing payload: {e}")
                                    continue
                                    
                        print("\nFuzzing completed!")
                        last_result = results
                        if assignment_target:
                            self.variables[assignment_target] = results
                            command_handled_assignment = True
                            
                    except Exception as e:
                        print(f"Error during parameter fuzzing: {e}")
                        last_result = None

            elif assignment_target is not None and not command_handled_assignment:
                 try:
                     value_to_assign = self.evaluate(expression_on_right)
                     self.variables[assignment_target] = value_to_assign
                     last_result = value_to_assign
                     # print(f"Assigned: {assignment_target} = {value_to_assign}") # Verbose assignment log
                 except Exception as e:
                      print(f"Error assigning value to '{assignment_target}' from expression '{expression_on_right}': {e}")
                      last_result = None

            elif assignment_target is None:
                 known_prefixes = (
                     'show', 'get', 'post', 'generate_wordlist', 'serve', 'stop', 
                     'tcp_send', 'udp_send', 'vip', 'scan_ports_udp', 'ssh_bruteforce', 
                     'dns_lookup', 'scan_ports', 'tcp_listen', 'stop_listeners', 
                     'ssh_exec', 'httpv', 'md5', 'sha256', 'fetch_proxies', 
                     'read_file', 'get_banner', 'base64_encode', 'base64_decode', 
                     'url_encode', 'url_decode', 'ntp_info', 'run_cmd', 'simple_listener',
                     'shell', 'set_user_agent', 'fuzz_params'
                 ) 
                 is_known_prefix = False
                 for prefix in known_prefixes:
                     if original_line.startswith(prefix) and not original_line.startswith(prefix + ' '):
                         print(f"Error: Missing space or arguments after '{prefix}'? Input: {original_line}")
                         is_known_prefix = True; break
                 if not is_known_prefix:
                     try:
                         value = self.evaluate(original_line, allow_operations=False)
                         last_result = value
                     except ValueError as e:
                         print(f"Error: Unknown command or variable: {original_line}")
                         last_result = None
                     except Exception as e:
                         print(f"Error processing line: {original_line} -> {e}")
                         last_result = None

        return last_result

    def evaluate(self, expr: str, allow_operations=True) -> Any:
        expr = expr.strip()
        
        len_match = re.match(r"^\s*len\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*$", expr)
        if len_match:
            var_name = len_match.group(1).strip()
            if var_name in self.variables:
                target = self.variables[var_name]
                if isinstance(target, (str, list, dict)): 
                    try: return len(target)
                    except Exception as e: raise ValueError(f"Error calling len() on '{var_name}': {e}")
                else: raise TypeError(f"Variable '{var_name}' type {type(target).__name__} has no len().")
            else: raise NameError(f"Variable '{var_name}' in len() not defined.")
                
        access_match = re.match(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\[(.+)\]\s*$", expr)
        if access_match:
             var_name = access_match.group(1).strip()
             key_expr = access_match.group(2).strip()
             if var_name in self.variables:
                 container = self.variables[var_name]
                 try:
                     key_or_index = self.evaluate(key_expr, allow_operations=True)
                     if isinstance(container, dict):
                         if key_or_index in container: return container[key_or_index]
                         else: raise KeyError(f"Key '{key_or_index}' not in dict '{var_name}'")
                     elif isinstance(container, list):
                         if isinstance(key_or_index, int):
                             if 0 <= key_or_index < len(container): return container[key_or_index]
                             else: raise IndexError(f"Index {key_or_index} out of bounds for list '{var_name}' (size {len(container)})")
                         else: raise TypeError(f"List index for '{var_name}' must be int, not {type(key_or_index).__name__}")
                     else: raise TypeError(f"Variable '{var_name}' not a list/dict for [] access.")
                 except Exception as e: raise ValueError(f"Error accessing '{var_name}': {e}")
             else: raise NameError(f"Variable '{var_name}' not defined for [] access.")
        
        if expr.startswith('"') and expr.endswith('"'): return expr[1:-1]
        if expr.startswith("'") and expr.endswith("'"): return expr[1:-1]
        if expr == 'true': return True
        if expr == 'false': return False
        if expr == 'null': return None
        try: return float(expr) if '.' in expr else int(expr)
        except ValueError: pass 

        if expr.startswith('[') and expr.endswith(']'):
            content = expr[1:-1].strip()
            if not content: return []
            items = [] 
            try:
                for item_expr in content.split(','):
                    items.append(self.evaluate(item_expr.strip(), allow_operations=False))
                return items
            except Exception as e:
                 raise ValueError(f"Error parsing list literal items in '{expr}': {e}")

        if expr.startswith('{') and expr.endswith('}'):
             content = expr[1:-1].strip()
             if not content: return {}
             result_dict = {} 
             try: return json.loads(expr)
             except json.JSONDecodeError:
                 try: 
                     for pair in content.split(','):
                         key_val = pair.split(':', 1)
                         if len(key_val) == 2: 
                             key = self.evaluate(key_val[0].strip(), allow_operations=False)
                             value = self.evaluate(key_val[1].strip(), allow_operations=False)
                             result_dict[key] = value
                     return result_dict
                 except Exception as e:
                      raise ValueError(f"Error parsing dict literal items in '{expr}': {e}")
        
        if expr in self.variables: return self.variables[expr]

        if allow_operations and '+' in expr: 
            parts = expr.split('+', 1)
            if len(parts) == 2:
                try:
                    left = self.evaluate(parts[0].strip(), allow_operations=False) 
                    right = self.evaluate(parts[1].strip(), allow_operations=True)
                    if isinstance(left, str) or isinstance(right, str):
                        return str(left) + str(right)
                    elif isinstance(left, list) and isinstance(right, list):
                        return left + right
                    else:
                        raise TypeError(f"Operator '+' not supported for types {type(left).__name__} and {type(right).__name__}")
                except ValueError as e:
                    raise ValueError(f"Cannot evaluate operands for '+' in '{expr}': {e}")
                except Exception as e:
                     raise ValueError(f"Error during concatenation in '{expr}': {e}")

        raise ValueError(f"Cannot evaluate expression or unknown variable: {expr}")

def run_viper_code(code: str):
    interpreter = ViperInterpreter()
    try:
        result = interpreter.execute(code)
        if listener_threads:
             print(f"\nNote: {len(listener_threads)} TCP listener(s) may still be running in the background.")
             print("Use 'stop_listeners' in another script or terminate this process to stop them.")
        if interpreter.server_thread and interpreter.server_thread.is_alive():
             print("\nNote: HTTP server may still be running in the background.")
    except Exception as e:
        print(f"Runtime Error: {e}")

if __name__ == "__main__":
    import sys
    import os 
    import time

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if file_path.endswith(".viper"):
            try:
                with open(file_path, 'r') as f: viper_code = f.read()
                run_viper_code(viper_code)
            except FileNotFoundError: print(f"Error: File not found: {file_path}")
            except Exception as e: print(f"Error running file {file_path}: {e}")
        else: print("Usage: python Viper.py [your_program.viper]")
    else:
        example_code = f"""
        # Viper Example: More Utilities
        
        show "--- URL Encoding/Decoding ---"
        url_part := "test path?param=value with spaces"
        show "Original URL part: " + url_part
        encoded_url := url_encode url_part
        show "URL Encoded: " + encoded_url
        decoded_url := url_decode encoded_url
        show "URL Decoded: " + decoded_url
        
        show "\n--- NTP Info --- (Querying time server)"
        ntp_server := "pool.ntp.org"
        ntp_data := ntp_info ntp_server
        show "NTP Result: " + ntp_data
        
        show "\n--- Simple Listener Example ---"
        # simple_listener 4444
        show "(Simple Listener example commented out - runs in foreground, blocking)"
        
        show "\n--- System Command Example (Use with EXTREME caution!) ---"
        # For Windows:
        # dir_cmd := "dir C:\\Users"
        # For Linux/macOS:
        # dir_cmd := "ls -la /tmp"
        # show "(Executing system command - Example commented out for safety)"
        # cmd_output := run_cmd dir_cmd
        # show "Command output captured: " + cmd_output["output"]
        show "(Run Command example commented out for safety)"
        
        show "\n--- HTTPV with Proxy (Example) ---"
        # Ensure you have a proxy running, e.g., Burp at 127.0.0.1:8080
        my_proxy := "http://127.0.0.1:8080"
        # show "(Attempting HTTPV GET via proxy: " + my_proxy + ")"
        # proxy_test_result := httpv GET "https://httpbin.org/ip" proxy=my_proxy
        # show "Proxy Test Result (should show proxy IP): " + proxy_test_result["content"]
        show "(HTTPV Proxy example commented out)"
        
        show "\n(Previous command examples omitted)"
        """
        
        print("--- Running Default Example ---")
        run_viper_code(example_code)
        print("\n--- Example Finished ---")
        
        try: 
            if os.path.exists("viper_test_output.txt"): 
                os.remove("viper_test_output.txt")
                print("(Python: Cleaned up viper_test_output.txt)")
        except OSError as e:
             print(f"Python Error cleaning up test file: {e}")
             
        time.sleep(0.5) 
