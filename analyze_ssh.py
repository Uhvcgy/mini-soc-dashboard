import re
import sqlite3
from collections import Counter
from datetime import datetime

LOG_FILE = "auth.log"
DB_FILE = "soc_alerts.db"
THRESHOLD = 5

# 1. إعداد قاعدة البيانات وإنشاء الجدول
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            attempt_count INTEGER,
            targeted_users TEXT,
            attack_type TEXT
        )
    ''')
    conn.commit()
    return conn

# 2. تحليل السجلات
pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ip_counter = Counter()
ip_users = {}  # لحفظ أسماء المستخدمين لكل IP

with open(LOG_FILE, "r", errors="ignore") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            user, ip = match.groups()
            ip_counter[ip] += 1
            if ip not in ip_users:
                ip_users[ip] = set()
            ip_users[ip].add(user)

# 3. حفظ التنبيهات في قاعدة البيانات
conn = init_db()
cursor = conn.cursor()
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
alerts_saved = 0

for ip, count in ip_counter.items():
    if count > THRESHOLD:
        users_str = ", ".join(ip_users[ip])
        cursor.execute('''
            INSERT INTO alerts (timestamp, ip_address, attempt_count, targeted_users, attack_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (now, ip, count, users_str, "SSH Brute Force"))
        alerts_saved += 1
        print(f"[+] Saved alert for {ip} ({count} attempts) targeting: {users_str}")

conn.commit()
conn.close()

if alerts_saved == 0:
    print("[-] System secure. No alerts saved.")
else:
    print(f"[*] Done! {alerts_saved} alert(s) stored in '{DB_FILE}'.")
    
