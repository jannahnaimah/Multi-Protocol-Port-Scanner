import socket
import threading
import queue
import sys
import time

def tcp_scan(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            if res == 0:
                banner = grab_banner(s, host, port)
                return (port, 'open', banner)
            else:
                return (port, 'closed', None)
    except Exception as e:
        return (port, 'error', str(e))

def grab_banner(sock, host, port):
    try:
        common_probes = {
            21: b'QUIT\r\n',                      # FTP
            22: b'\r\n',                          # SSH
            25: b'HELO probe\r\n',                # SMTP
            80: b'GET / HTTP/1.0\r\n\r\n',        # HTTP
            110: b'\r\n',                         # POP3
            143: b'\r\n',                         # IMAP
            443: b'GET / HTTP/1.0\r\n\r\n',       # HTTPS (often needs SSL handshake)
            3389: b'\r\n',                        # RDP
        }
        probe = common_probes.get(port, b'\r\n')
        try:
            sock.sendall(probe)
            data = sock.recv(512)
            return data.decode(errors='ignore').strip()
        except Exception:
            return None
    except Exception:
        return None

def udp_scan(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # Basic probe: send zero byte; many UDP services respond differently
            try:
                s.sendto(b'', (host, port))
                data, _ = s.recvfrom(512)
                return (port, 'open/response', data.decode(errors='ignore').strip())
            except socket.timeout:
                # Timeout could mean port is open|filtered (no response)
                return (port, 'open|filtered', None)
            except Exception as e:
                return (port, 'closed|error', str(e))
    except Exception as e:
        return (port, 'error', str(e))

def threaded_scan(host, ports, protocol='tcp', timeout=1, threads=50):
    results = []
    q = queue.Queue()
    for port in ports:
        q.put(port)

    def worker():
        while True:
            try:
                port = q.get_nowait()
            except queue.Empty:
                break
            if protocol == 'tcp':
                res = tcp_scan(host, port, timeout)
            else:
                res = udp_scan(host, port, timeout)
            results.append(res)
            q.task_done()

    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker)
        t.start()
        thread_list.append(t)
    q.join()
    for t in thread_list:
        t.join()
    return sorted(results, key=lambda x: x[0])

def parse_ports(portstr):
    ports = set()
    for part in portstr.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Protocol Port Scanner (Enhanced Nmap-lite)")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports (e.g. 22,80,443 or 1-100)")
    parser.add_argument("--udp", action="store_true", help="Scan UDP ports instead of TCP")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of scan threads")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    args = parser.parse_args()

    host = args.host
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)

    ports = parse_ports(args.ports)
    proto = 'udp' if args.udp else 'tcp'

    print(f"[+] Scanning {host} ({ip}) on ports: {args.ports} using {proto.upper()} protocol")

    start_time = time.time()
    results = threaded_scan(ip, ports, protocol=proto, timeout=args.timeout, threads=args.threads)
    scan_duration = time.time() - start_time

    for port, status, banner in results:
        if status.startswith('open'):
            print(f"[{proto.upper()}] Port {port:5}: OPEN", end="")
            if banner:
                banner_summary = banner.replace('\n', '\\n').strip()
                print(f" | Banner: {banner_summary[:80]}")
            else:
                print()
        elif status == 'closed':
            pass  # Don't print closed ports
        elif status.endswith('error'):
            print(f"[{proto.upper()}] Port {port:5}: ERROR: {banner}")
        else:
            print(f"[{proto.upper()}] Port {port:5}: {status}")

    print(f"[+] Scan completed in {scan_duration:.2f} seconds.")

if __name__ == "__main__":
    main()
