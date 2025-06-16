import socket
import sys
import time
import re

# Configurations
DEFAULT_TIMEOUT = 1.0  # Default timeout in seconds
ALLOWED_TARGETS = ['127.0.0.1', 'localhost', 'scanme.nmap.org']  # Allowed targets for scanning
# Function to validate target
def validate_target(target):
    # Check if the target is in the allowed list or a valid IP address
    if target.lower() not in ALLOWED_TARGETS:
        print(f"[-] Error: Target '{target}' is not allowed.")
        print(f'[!] Allowed targets are: {'127.0.0.1, localhost, scanme.nmap.org'}')
        sys.exit(1)
    return target

def parse_ports(port_input):
    # Parse ports from a comma-separated string or a range
    ports_colleciton = set()
    #print(f"[DEBUG] Parsing ports from input: {port_input}")
    port_parts = port_input.split(',')
    #print(f"[DEBUG] port_parts after split: {port_parts}")

    for part in port_parts:
        part = part.strip()  # Remove any leading/trailing whitespace
        #print(f"[DEBUG] Processing part: {part}")
        if '-' in part:  # Handle range
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    print(f"Error: Port range {start}-{end} is out of valid range (1-65535).")
                    sys.exit(1)
                ports_colleciton.update(range(start, end + 1))
                #print(f"[DEBUG] Added port range {start}-{end} to ports_collection. Current: {ports_colleciton}")
            except ValueError:
                print(f"Error: Invalid port range '{part}'.")
                sys.exit(1)
        else:  # Handle single port
            try:
                port = int(part)
                if not (1 <= port <= 65535):
                    print(f"Error: Port {port} is out of valid range (1-65535).")
                    sys.exit(1)
                ports_colleciton.add(port)
                #print(f"[DEBUG] Added port {port} to ports_collection. Current: {ports_colleciton}")
            except ValueError:
                print(f"Error: Invalid port '{part}'.")
                sys.exit(1)
        #print(f"[DEBUB] Final ports_collection: {ports_colleciton}")        
    return sorted(list(ports_colleciton))  # Return sorted list of unique ports

def scan_port(target_host, port, timeout=DEFAULT_TIMEOUT):
    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout) # Set the timeout for the socket

            result = sock.connect_ex((target_host, port)) # Connect to the target and port
            if result == 0: # 0 means the port is open
                return True
            else:
                return False # Non-zero result means the port is closed or filtered

    except socket.gaierror:
        print(f"Error: Invalid target '{target_host}'. Please check the hostname or IP address.")
        sys.exit(1)        
    except socket.error as e:
        print(f"Error connecting to {target_host}:{port} - {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while scanning {target_host}:{port} - {e}")
        return False

def main():
    target_host_input = input("Enter the target host (default:127.0.0.1, scanme.nmap.org): ").strip()
    ports_input = input("Enter the ports to scan (e.g., 22,80,443 or 1-1000): ").strip()

    # Validate and set the target host
    target_host = validate_target(target_host_input)

    # Parse and validate the ports
    ports_to_scan = parse_ports(ports_input)
    if not ports_to_scan:
        print("Error: No valid ports provided for scanning. Exiting.")
        sys.exit(1)

    print(f"Starting port scan on {target_host} for {len(ports_to_scan)} ports...")
    print(f"Ports to scan: {', '.join(map(str, ports_to_scan))}")   

    # Scan each port and report the results
    open_ports = []
    closed_ports_count = 0

    for port in ports_to_scan:
        status = scan_port(target_host, port)
        if status:
            open_ports.append(port)
            print(f"[+] Port {port} is open on {target_host}.")
        else:
            closed_ports_count += 1
            print(f"[-] Port {port} is closed.")

#     Summary of the scan results
    print("\n--- Scan Results---")
    if open_ports:
        print(f"[+] Open ports: {sorted(open_ports)}")
    else:
        print(f"[-] No open ports found in range.")

    print(f"[*] Total ports scanned: {len(ports_to_scan)}")
    print(f"[*] Open ports count: {len(open_ports)}")    
    print(f"[*] Closed/Filtered ports count: {closed_ports_count}")
    
    print("[*] Port scan finished.")

if __name__ == "__main__":
    main()
            