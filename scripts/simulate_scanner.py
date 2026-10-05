from simulate_local import send

if __name__ == "__main__":
    for path in ("/robots.txt", "/wp-admin", "/.git/config", "/api/v1/users", "/admin"):
        status, _ = send(path, user_agent="nmap/7.95 HoneyBot local demo")
        print(f"GET {path}: HTTP {status}")
