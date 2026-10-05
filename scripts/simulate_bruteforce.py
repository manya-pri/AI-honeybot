from simulate_local import send

if __name__ == "__main__":
    for attempt in range(1, 6):
        status, _ = send("/login", method="POST", data={"username": f"demo{attempt}", "password": "fake"})
        print(f"synthetic login attempt {attempt}: HTTP {status}")
