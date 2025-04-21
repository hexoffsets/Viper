# Viper Programming Language

A simple, Python-based scripting language focused on **Networking** and **Database** operations.

## Installation

1. Make sure you have Python 3.7+ installed
2. Install dependencies:
```bash
# Install requests, paramiko, ping3, cryptography
pip install -r requirements.txt
```
*Notes: `ping3` might require admin privileges. `paramiko` and `cryptography` might need system build tools.*

## Language Features

### Comments
```viper
# This is a comment
```

### Variables
Variables are declared using `:=`
```viper
name := "John"
age := 25
pi := 3.14
is_active := true
```

### Data Types
- **Strings**: `"Hello"` or `'Hello'`
- **Numbers**: Integers (`10`) and Floats (`3.14`)
- **Booleans**: `true`, `false`
- **Null**: `null`
- **Lists**: `[1, "apple", true]`
- **Dictionaries**: `{"key": "value", "count": 10}`

### Output
Use `show` to print values:
```viper
show "Hello, World!"
name := "Viper"
show "Welcome to " + name
my_list := [1, 2, 3]
show my_list
```

### Wordlist Generation
Generate wordlists based on a list of base words and simple rules.
```viper
# Base words
words := ["admin", "pass", "test"]

# Rules:
# +digitsN : Append N digits (0-9) (e.g., +digits2 appends 00-99)
# +symbols : Append common symbols (!@#$...)
# leet     : Apply basic leet substitutions (a=4, e=3, etc.)
# (More rules can be added)
rules := "+digits2+symbols+leet"

# Generate list
generate_wordlist words rules expanded_list

show "Generated wordlist size: " + len(expanded_list)
# show expanded_list # Display the list (can be large)
```

### Hashing Functions
Calculate common cryptographic hashes.
```viper
data_to_hash := "ViperLang"

md5_hash := md5 data_to_hash
show "MD5: " + md5_hash

sha256_hash := sha256 data_to_hash
show "SHA256: " + sha256_hash
```

### Fetch Proxies
Fetch a list of proxies from a URL (expects one IP:PORT per line or space-separated).
```viper
proxy_api := "https://api.proxyscrape.com/?request=displayproxies&proxytype=http&timeout=5000&country=all"

fetch_proxies proxy_api my_proxies

show "Fetched proxy count: " + len(my_proxies)
# show "First proxy: " + my_proxies[0] # (Needs if/else check)
```

### File I/O
Read from or write/append to files.
```viper
file_path := "results.log"
data_line := "Scan result: Port 80 open\n"

# Write (overwrites file if exists)
write_file file_path "Scan started...\n"

# Append
append_file file_path data_line

# Read
content := read_file file_path
show content
```

### Web Requests (HTTP)
- **get**: Simple HTTP GET.
- **post**: Simple HTTP POST.
- **httpv**: Enhanced HTTP request.
  - Syntax: `httpv <METHOD> <url> [data=<data_var>] [headers=<headers_var>] [proxy=<proxy_str_var>]`
  - Supports GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH.
  - Data variable should hold dictionary/list for JSON.
  - Headers variable should hold a dictionary.
  - Proxy variable should hold a proxy URL string (e.g., "http://127.0.0.1:8080").

```viper
# HTTPV GET
httpv_resp_get := httpv GET "https://httpbin.org/get"

# HTTPV POST with data and headers
post_payload := {"id": 42}
headers_dict := {"User-Agent": "Viper Client"}
post_resp := httpv POST "https://httpbin.org/post" data=post_payload headers=headers_dict

# HTTPV GET via proxy
proxy_url := "http://127.0.0.1:8080" # Assuming proxy running here
# proxy_resp := httpv GET "https://httpbin.org/ip" proxy=proxy_url
```

### Web Content Utilities
Extract information from HTML content (fetched from URL or provided as string variable).
```viper
target := "http://example.com"

# Find HTML Comments
comments := find_comments target
show "Comments Found: " + comments

# Extract Links (href attributes from <a> tags)
links := extract_links target
show "Links Found: " + links

# Check Specific HTTP Header
server_header := check_header target "Server"
show "Server Header: " + server_header
```

### Banner Grabbing
Connect to a host/port and attempt to read the initial banner/data.
```viper
# Grab banner from common SSH port (if running on localhost)
# banner := get_banner "localhost" 22 2 # 2 second timeout
# show "SSH Banner: " + banner

# Grab banner from HTTP port
# http_banner := get_banner "example.com" 80
# show "HTTP Banner: " + http_banner
```

### Encoding / Decoding
**Base64:**
```viper
encoded_str := base64_encode "Test String"
decoded_str := base64_decode encoded_str
```
**URL Encoding:**
```viper
url_part := "query param with spaces & symbols?="
encoded_url := url_encode url_part
show encoded_url
decoded_url := url_decode encoded_url
show decoded_url
```

### Other Protocol Interaction (NTP)
Query an NTP time server.
```viper
ntp_server := "pool.ntp.org"
ntp_result := ntp_info ntp_server
show "NTP Server Time: " + ntp_result["transmit_time_utc"]
```

### System Command Execution
Execute commands directly on the underlying operating system.
**!!! WARNING: EXTREMELY DANGEROUS. USE WITH UTMOST CAUTION !!!**
```viper
# Example (Linux/macOS - uncomment ONLY if you understand the risk)
# cmd_res := run_cmd "ls -la /tmp"

# Example (Windows - uncomment ONLY if you understand the risk)
# cmd_res := run_cmd "dir C:\\Users"

# show cmd_res["output"]
```

### Basic Networking (HTTP Server)
Start a simple HTTP server.
```viper
# Start server on port 8080
serve on 8080
show "Server running on http://localhost:8080"

# Stop the server (if running)
stop server
```

### Low-Level Networking (TCP/UDP Send)
Send raw data over TCP or UDP sockets.
```viper
# Send data via TCP to host 127.0.0.1 on port 9999
tcp_send "127.0.0.1" 9999 "Some TCP Data"

# Send data via UDP to host 127.0.0.1 on port 9999
udp_send "127.0.0.1" 9999 "Some UDP Data"
```

### Custom Ping (ICMP - vip)
Send an ICMP echo request with configurable options.
```viper
# Simple ping (like before)
latency := vip "google.com"

# Ping with options (keyword args)
# count=N : Number of packets to send (returns None if count > 1)
# interval=S : Wait S seconds between sending packets (default 1)
# timeout=S : Seconds to wait for each reply (default 4)
# size=B : Bytes of payload data to send (default 56)
vip "google.com" count=4 interval=0.5 size=100 timeout=2
```
*Note: Running `vip` often requires administrator/root privileges.* 

### Port Scanning
Scan a range of TCP or UDP ports on a target host.

**TCP Scan:** (Reliable connect scan)
```viper
open_tcp := scan_ports "localhost" 1 1024
show "Open TCP ports (1-1024): " + open_tcp
```

**UDP Scan:** (Less reliable, uses ICMP port unreachable)
```viper
# Scan common UDP ports (e.g., 53 DNS, 161 SNMP)
# open_udp := scan_ports_udp "localhost" 50 200 0.5 # 0.5s timeout/port
# show "Open/Filtered UDP ports (50-200): " + open_udp
```
*Note: UDP scanning is less reliable than TCP scanning and often requires administrator/root privileges.* 

### TCP Listener
Start a background TCP listener on a specified host and port to receive data.
```viper
# Listen on all interfaces (0.0.0.0) on port 12345
tcp_listen "0.0.0.0" 12345
show "TCP listener started on port 12345..."
# Received data will be printed to the console.

# Stop all running listeners
stop_listeners
```

### DNS Lookup
Perform a DNS A-record lookup for a hostname.
```viper
ip_addr := dns_lookup "google.com"
show "Google IP: " + ip_addr
```

### SSH Operations
Interact with SSH servers (use responsibly and with authorization).

**SSH Bruteforce (from file):**
Attempts to find an SSH password by reading potential passwords line-by-line from a specified file.
```viper
# Create a wordlist file (e.g., 'mypasswords.txt') containing one password per line.
# Example file contents:
# password123
# secret
# admin

wordlist_file := "mypasswords.txt"
target_host := "192.168.1.100"

# Run the bruteforce attempt using the file
found := ssh_bruteforce target_host 22 "root" wordlist_file

show "Found password: " + found
```

**SSH Execute Command:**
Execute a single command on a remote SSH server.
```viper
ssh_host := "192.168.1.100"
ssh_user := "admin"
ssh_pass := "secret_password"
ssh_cmd := "uname -a"

# Execute command and store result (dictionary with output, error, status)
cmd_result := ssh_exec ssh_host 22 ssh_user ssh_pass ssh_cmd

show "SSH Command Result:"
show cmd_result
# Access parts: show cmd_result["output"]
```

### TCP Listeners
- **`tcp_listen <host> <port>`**: Starts a background listener for multiple connections.
- **`stop_listeners`**: Stops all background `tcp_listen` instances.
- **`simple_listener <port>`**: Starts a *foreground* listener for a *single* connection. Blocks until connection received and closed.
```viper
# Background listener (use stop_listeners later)
# tcp_listen "0.0.0.0" 12345

# Simple foreground listener (script waits here)
# received := simple_listener 4444
# show "Simple listener received: " + received
```

## Example Program

```viper
# Viper Example: File I/O & Web Utils

show "--- File I/O Example ---"
file := "viper_test_output.txt"
data1 := "First line for test file.\n"
data2 := "Second line to append."
write_file file data1
append_file file data2
content := read_file file
show "Content read from " + file + ":\n" + content
# File should be cleaned up manually or via Python after script finishes

show "\n--- Web Utils Example ---"
test_url := "http://example.com" # Use http for simpler banner/comments
show "Analyzing " + test_url

show "Finding comments..."
comments := find_comments test_url
show "Found Comments: " + comments

show "Extracting links..."
links := extract_links test_url
show "Extracted Links: " + links

show "Checking Server header..."
server_header := check_header test_url "Server"
show "Server Header: " + server_header

show "\n(Previous command examples omitted)"
```

## Running Viper Programs

Save your code in a `.viper` file (e.g., `