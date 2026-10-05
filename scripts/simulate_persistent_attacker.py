from simulate_local import send

if __name__ == "__main__":
    sequence = (("/", "GET", None), ("/login", "POST", {"username": "demo", "password": "fake"}),
                ("/admin", "GET", None), ("/ssh/login", "POST", {"username": "analyst", "password": "fake"}),
                ("/ssh/session", "POST", {"command": "whoami"}), ("/credentials.txt", "GET", None))
    for path, method, data in sequence:
        status, _ = send(path, method=method, data=data)
        print(f"{method} {path}: HTTP {status}")
