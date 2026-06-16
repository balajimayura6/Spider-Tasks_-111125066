import os
import stat
import datetime

LOG_FILE = "vault_sweep.log"
def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

def scan_scripts(root):
    for dirpath, _, files in os.walk(root):
        for file in files:
            if file.endswith(".sh"):
                filepath = os.path.join(dirpath, file)
                check_script(filepath)

def check_script(filepath):
    reasons = []
    with open(filepath, "r", errors="ignore") as f:
        content = f.read()

    if "rm -rf /" in content or "mkfs" in content or "shutdown" in content or "reboot" in content:
        reasons.append("Destructive command")

    if "curl" in content and "| sh" in content:
        reasons.append("Suspicious curl pipe")
    if "wget" in content and "| sh" in content:
        reasons.append("Suspicious wget pipe")
    st = os.stat(filepath)
    if bool(st.st_mode & stat.S_IWOTH): 
        reasons.append("World writable (777/o+w)")

    if reasons:
        for reason in reasons:
            log(f"[WARN] {filepath} _ Reason: {reason}")
        fix_permissions(filepath)

def fix_permissions(filepath):
    choice = input(f"Fix permissions for {filepath}? (yes/no): ").strip().lower()
    if choice == "yes":
        st = os.stat(filepath)
        new_mode = st.st_mode & ~stat.S_IWOTH  # remove world write
        os.chmod(filepath, new_mode)
        log(f"[FIX] {filepath} removed world write permission")

def scan_env_files(root):
    for dirpath, _, files in os.walk(root):
        for file in files:
            if file.startswith(".env"):
                filepath = os.path.join(dirpath, file)
                sanitize_env(filepath)

def sanitize_env(filepath):
    valid = []
    invalid = []
    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            invalid.append(line)
            continue

        key, value = line.split("=", 1)
        if not key.isupper() and not key.startswith("_"):
            invalid.append(line)
            continue
        if " " in key or "-" in key:
            invalid.append(line)
            continue
        if key in ["PASSWORD", "SECRET", "TOKEN", "PATH"]:
            invalid.append(line)
            continue
        if '"' in value or "export" in line:
            invalid.append(line)
            continue

        valid.append(f"{key}={value}")

    sanitized_path = filepath + ".sanitized"
    with open(sanitized_path, "w") as f:
        f.write("\n".join(valid))

    log(f"[INFO] {filepath} Valid: {len(valid)}, Invalid: {len(invalid)}")
    if invalid:
        log(f"[SKIP] {filepath} Rejected: {', '.join(invalid)}")

def main(root):

    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    open(LOG_FILE, "w").close()
    os.chmod(LOG_FILE, 0o600)

    scan_scripts(root)
    scan_env_files(root)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python vault_sweep.py <directory>")
    else:
        main(sys.argv[1])
