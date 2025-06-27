# linux-audit-report
A lightweight Linux enumeration script generating detailed TXT and HTML reports.

## 📖 About

`linux-audit-report` is a powerful yet lightweight bash script designed to automate the enumeration of Linux systems for security auditing and privilege escalation discovery. Inspired by well-known tools like [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and [LinEnum](https://github.com/rebootuser/LinEnum), this script focuses on **clarity of output**, **useful defaults**, and **clean HTML reporting**.

It was built and refined with the help of **ChatGPT** to automate and optimize common post-exploitation and audit checks, without overwhelming the user with unnecessary data.

---

## ✨ Features

- 🔎 Collects detailed system info for local privilege escalation
- 📁 Categorized output with clear subheadings
- 📝 Generates both human-readable `.txt` and interactive `.html` reports
- 🧠 Includes many checks: System info, User info, SUID files, SSH keys, exposed credentials, service misconfigs, API keys, and more
- 💡 Inspired by real-world use of LinPEAS and LinEnum — but cleaner and faster

## 📦 Output Format

- `system_enumeration.txt` – Raw output in plain text format
- `system_report.html` – Expandable HTML report with search & filtering support

---

## 🚀 Usage

```bash
$ git clone ...
$ cd ... 
$ chmod +x enumeration_script.sh
$ chmod +x run_report.py
$ python3 run_report.py    
