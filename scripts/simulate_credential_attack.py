from simulate_local import send

if __name__ == "__main__":
    for path in ("/credentials.txt", "/api_keys.txt", "/database_backup.sql"):
        status, _ = send(path)
        print(f"GET synthetic decoy {path}: HTTP {status}")
