#!/bin/bash

# Output file
OUTPUT="system_enumeration.txt"
> "$OUTPUT" # clear the file

# Helper functions
print_header() {
    echo -e "\n===== $1 =====" >> "$OUTPUT"
}

print_subheader() {
    echo -e "\n-- $1 --" >> "$OUTPUT"
}

run_and_log() {
    eval "$1" >> "$OUTPUT" 2>/dev/null
}

log_protection_check() {
    label=$1
    result=$2
    printf "%-35s %s\n" "$label" "$result" >> "$OUTPUT"
}

# ========== SECTION: SYSTEM INFO ==========
print_header "System Information"

print_subheader "System Version"
run_and_log "cat /proc/version"

print_subheader "Sudo Version"
run_and_log "sudo -V | grep 'Sudo ver'"

print_subheader "Environment Variables"
run_and_log "env | grep -v 'LS_COLORS'"

print_subheader "PATH"
run_and_log "echo \$PATH"

print_subheader "Kernel Info (Full)"
run_and_log "uname -a"

print_subheader "Release Info"
run_and_log "cat /etc/*-release"

print_subheader "Kernel Modules with Weak Permissions"
{
    result=$(find /lib/modules -type f -name '*.ko' -ls 2>/dev/null | grep -Ev 'root\s+root')
    if [ -n "$result" ]; then
        echo "$result"
    else
        echo "⚠️ No weakly permissioned kernel modules found."
    fi
} >> "$OUTPUT"

# ========== SECTION: PROTECTION MECHANISMS ==========
print_header "System Protection Mechanisms"
print_subheader "Protection Mechanism Checks"

# AppArmor
if command -v aa-status >/dev/null 2>&1; then
    aa-status | grep -q "enabled" && val="Yes" || val="No"
elif command -v apparmor_status >/dev/null 2>&1; then
    apparmor_status | grep -q "enabled" && val="Yes" || val="No"
elif ls -d /etc/apparmor* >/dev/null 2>&1; then
    val="Yes"
else
    val="No"
fi
log_protection_check "AppArmor enabled?" "$val"

# AppArmor profile
profile=$(cat /proc/self/attr/current 2>/dev/null)
[[ "$profile" == "unconfined" || -z "$profile" ]] && val="No" || val="Yes"
log_protection_check "AppArmor profile in use?" "$val"

# LinuxONE
uname -a | grep -q "s390x" && val="Yes" || val="No"
log_protection_check "LinuxONE (s390x)?" "$val"

# Grsecurity
if uname -r | grep -q "\-grsec" || grep -q "grsecurity" /etc/sysctl.conf 2>/dev/null; then
    val="Yes"
else
    val="No"
fi
log_protection_check "Grsecurity present?" "$val"

# PaX
(command -v paxctl-ng >/dev/null 2>&1 || command -v paxctl >/dev/null 2>&1) && val="Yes" || val="No"
log_protection_check "PaX tools present?" "$val"

# ExecShield
grep -q "exec-shield=1" /etc/sysctl.conf 2>/dev/null && val="Yes" || val="No"
log_protection_check "ExecShield enabled?" "$val"

# SELinux
sestatus 2>/dev/null | grep -q "enabled" && val="Yes" || val="No"
log_protection_check "SELinux enabled?" "$val"

# Seccomp
seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')
[[ "$seccomp" != "0" ]] && val="Yes" || val="No"
log_protection_check "Seccomp enabled?" "$val"

# User namespaces
[ -s /proc/self/uid_map ] && val="Yes" || val="No"
log_protection_check "User namespaces enabled?" "$val"

# Cgroup2
grep -q cgroup2 /proc/filesystems 2>/dev/null && val="Yes" || val="No"
log_protection_check "Cgroup2 enabled?" "$val"

# ASLR
aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
case "$aslr" in
    0) val="No" ;;
    1|2) val="Yes" ;;
    *) val="Unknown" ;;
esac
log_protection_check "ASLR enabled?" "$val"

# Virtualization
if command -v systemd-detect-virt >/dev/null 2>&1; then
    systemd-detect-virt --quiet && val="Yes" || val="No"
else
    grep -q hypervisor /proc/cpuinfo && val="Yes" || val="No"
fi
log_protection_check "Running in virtual machine?" "$val"

# Done
echo -e "\nReport written to: $OUTPUT"

# ========== SECTION: USER INFORMATION ==========
print_header "User Information"

print_subheader "Current User Identity"
run_and_log 'id || (whoami && groups)'

# ========== SECTION: User Histoy files ==========
print_header "Histroy Files"
print_subheader "User History Files"
usrhist=$(ls -la ~/.*_history 2>/dev/null)
if [ "$usrhist" ]; then
    echo -e "[-] Current user's history files:\n$usrhist" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$export" ] && [ "$usrhist" ]; then
    mkdir -p "$format/history_files/" 2>/dev/null
    for i in $(echo "$usrhist" | awk '{print $NF}'); do
        cp --parents "$i" "$format/history_files/" 2>/dev/null
    done
fi

print_subheader "Root History File Accessibility"
roothist=$(ls -la /root/.*_history 2>/dev/null)
if [ "$roothist" ]; then
    echo -e "[+] Root's history files are accessible!\n$roothist" >> "$OUTPUT"
    else
    	echo "⚠️ No accessible root history files found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$export" ] && [ "$roothist" ]; then
    mkdir -p "$format/history_files/" 2>/dev/null
    echo "$roothist" | awk '{print $NF}' | xargs -I{} cp {} "$format/history_files/" 2>/dev/null
fi

print_subheader "Home .bash_history Files (Accessible)"
checkbashhist=$(find /home -name .bash_history -print -exec cat {} \; 2>/dev/null)
if [ "$checkbashhist" ]; then
    echo -e "[-] Location and contents (if accessible) of .bash_history file(s):\n$checkbashhist" >> "$OUTPUT"
    else
    	echo "⚠️ No accessible .bash_history files found in /home." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for creds in .bash_history"
found=false

# Use associative array to avoid duplicate history file paths
declare -A checked_files

for hfile in /home/*/.*_history /root/.*_history ~/.bash_history ~/.zsh_history ~/.history ~/.histfile ~/.zhistory; do
    [ -f "$hfile" ] || continue

    real_path=$(realpath "$hfile" 2>/dev/null)
    [ -n "$real_path" ] || continue
    if [[ -n "${checked_files[$real_path]}" ]]; then
        continue
    fi
    checked_files[$real_path]=1

    matches=$(grep -Eai '\s(-p\s+|/p:|--pass(word)?=|password=|pass=|pw=|--pw=|--password\s+|--secret=|--token=)[^[:space:]]+' "$real_path" 2>/dev/null)

    if [ -n "$matches" ]; then
        echo "🛑 Potential credentials found in: $real_path" >> "$OUTPUT"
        echo "$matches" >> "$OUTPUT"
        found=true
    fi
done

if [ "$found" = false ]; then
    echo "⚠️ No credentials found in history files." >> "$OUTPUT"
fi

# ========== SECTION: User SUDO PERMISSIONS ==========
print_header "SUDO Permissions"
print_subheader "Output of 'sudo -l'"
{
    sudo -l 2>/dev/null || echo "Cannot run 'sudo -l' (no passwordless sudo or not in sudoers)"
} >> "$OUTPUT"

print_subheader "Contents of /etc/sudoers (if readable)"
{
    [ -r /etc/sudoers ] && cat /etc/sudoers || echo "/etc/sudoers is not readable"
} >> "$OUTPUT"

print_subheader "Contents of /etc/sudoers.d/ (if accessible)"
{
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] && echo -e "\n>>> $f" && cat "$f"
        done
    else
        echo "/etc/sudoers.d/ not accessible or doesn't exist"
    fi
} >> "$OUTPUT"

print_subheader "Can we sudo without a password?"
{
    sudo -n true 2>/dev/null && echo "Yes – passwordless sudo is allowed" || echo "No – passwordless sudo is not allowed"
} >> "$OUTPUT"

print_subheader "Other Users who have used SUDO"
{
    echo "[+] From /var/log/auth.log or /var/log/secure:"
    grep -i 'sudo:' /var/log/auth.log /var/log/secure 2>/dev/null | awk '{print $1, $2, $3, $6}' | sort | uniq -c | sort -nr || echo "  No sudo log entries found or access denied."

    echo -e "\n[+] From .sudo_as_admin_successful files:"
    cut -d: -f1,6 /etc/passwd | while IFS=: read -r user home; do
        [ -f "$home/.sudo_as_admin_successful" ] && echo "  $user"
    done
} >> "$OUTPUT"

print_subheader "ptrace_scope and SDUO TOKENS"
{
    ptrace_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
    if [ "$ptrace_scope" ] && [ "$ptrace_scope" -eq 0 ]; then
        echo "ptrace protection is DISABLED (0) – sudo tokens could be abused"

        if command -v gdb >/dev/null 2>&1; then
            echo "gdb is available in PATH – could be used to attach to processes"
        fi

        if [ -f "$HOME/.sudo_as_admin_successful" ]; then
            echo "Current user has .sudo_as_admin_successful – has likely used sudo"
        fi

        echo "Checking for other interactive shell sessions for current user:"
        ps -eo pid,command -u "$(id -u)" | grep -Ev "^ *$$|grep|ps" | grep -E '(bash|zsh|sh|dash|ksh|tcsh|ash)$' || echo "No other interactive shells found"
    else
        echo "ptrace protection is ENABLED ($ptrace_scope) – less risk of token abuse"
    fi
} >> "$OUTPUT"


print_subheader "Users with UID 0"
{
    awk -F: '($3 == 0) {print $1 " (UID 0)"}' /etc/passwd || echo "Failed to read /etc/passwd"
} >> "$OUTPUT"


print_subheader "Users with a valid login shell"
{
    awk -F: '($7 !~ /(nologin|false)$/) {print $1 " => " $7}' /etc/passwd || echo "Failed to parse /etc/passwd"
} >> "$OUTPUT"

print_subheader "CURRENTLY LOGGED-IN USERS"
{
    (w || who || finger || users) 2>/dev/null || echo "No session tools available or no users logged in"
} >> "$OUTPUT"

print_subheader "Is /etc/shadow readable by non-root users?"
{
    if [ -f /etc/shadow ]; then
        find /etc/shadow ! -user root -o ! -perm 600 -ls 2>/dev/null || echo "/etc/shadow is properly owned and permissioned (root:root 600)"
    else
        echo "/etc/shadow not found"
    fi
} >> "$OUTPUT"

print_subheader "Non-standard password fields in /etc/group"
{
    grep -v "^[^:]*:[x]" /etc/group && echo "Found entries in /etc/group with non-standard password fields" || echo "No password found"
} >> "$OUTPUT"


print_subheader "Check readable sensitive files in home directories"
{
    found=false
    SENSITIVE_FILES=".bash_history .netrc .git-credentials .ssh/config .aws/credentials .gnupg/* .docker/config.json"

    while IFS=: read -r USER _ _ _ _ DIR SHELL; do
        for FILE in $SENSITIVE_FILES; do
            FILE_PATH="$DIR/$FILE"
            if [ -f "$FILE_PATH" ] && [ -r "$FILE_PATH" ]; then
                echo "$FILE_PATH is readable and belongs to user $USER"
                found=true
            fi
        done
    done < /etc/passwd

    if [ "$found" = false ]; then
        echo "⚠️ No readable sensitive files found in home directories."
    fi
} >> "$OUTPUT"

print_subheader "Checking if sensitive files are writable"
{
	found=false
    CRITICAL_PATHS="/etc/apache2/apache2.conf /etc/apache2/httpd.conf /etc/bash.bashrc /etc/bash_completion /etc/bash_completion.d/* /etc/environment /etc/environment.d/* /etc/hosts.allow /etc/hosts.deny /etc/httpd/conf/httpd.conf /etc/httpd/httpd.conf /etc/incron.conf /etc/incron.d/* /etc/logrotate.d/* /etc/modprobe.d/* /etc/pam.d/* /etc/passwd /etc/php*/fpm/pool.d/* /etc/php/*/fpm/pool.d/* /etc/profile /etc/profile.d/* /etc/rc*.d/* /etc/rsyslog.d/* /etc/shadow /etc/skel/* /etc/sudoers /etc/sudoers.d/* /etc/supervisor/conf.d/* /etc/supervisor/supervisord.conf /etc/sysctl.conf /etc/sysctl.d/* /etc/uwsgi/apps-enabled/* /root/.ssh/authorized_keys"

    for path in $CRITICAL_PATHS; do
        for item in $path; do
            [ -e "$item" ] || continue
            if [ -w "$item" ]; then
                echo "Writable: $item"
                found=true
            fi
        done
    done

    if [ "$found" = false ]; then
        echo "⚠️ No writable sensitive files found."
    fi
} >> "$OUTPUT"

print_subheader "Checking if specified sensitive directories are writable"
{
    SENSITIVE_DIRS="/etc/bash_completion.d /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/environment.d /etc/logrotate.d /etc/modprobe.d /etc/pam.d /etc/profile.d /etc/rsyslog.d /etc/sudoers.d /etc/sysctl.d /root"

    for dir in $SENSITIVE_DIRS; do
        if [ -d "$dir" ]; then
            if [ -w "$dir" ]; then
                echo "Writable: $dir"
            fi
        else
            echo "Not found: $dir"
        fi
    done
} >> "$OUTPUT"

# ========== SECTION: PROCESSES ==========
print_header "Running Processes"
print_subheader "List of running processes (full details, sorted by user)"
{
    ps aux --sort=user || echo "Failed to list processes"
} >> "$OUTPUT"


print_subheader "Processes running as root with writable binary or script"
{
    found=false
    find /proc/*/exe -type l 2>/dev/null | while read -r exe; do
        PID=$(echo "$exe" | cut -d/ -f3)
        CMD=$(ps -p "$PID" -o cmd= 2>/dev/null)
        if [ -n "$CMD" ] && [ -w "$exe" ]; then
            echo "$CMD (PID: $PID) is using a writable executable: $exe"
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo "⚠️ No writable root-owned binaries found."
    fi
} >> "$OUTPUT"


print_subheader "Processes with environment variables including suspicious paths"
{
    found=false
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
        ENV_FILE="/proc/$pid/environ"
        [ -r "$ENV_FILE" ] || continue
        if tr '\0' '\n' < "$ENV_FILE" 2>/dev/null | grep -qE '(^|\s)PATH=.*(:|^)(\.|/tmp|/var/tmp)(:|$)'; then
            echo "Suspicious PATH found in PID $pid"
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo "⚠️ No suspicious PATHs found in environment variables."
    fi
} >> "$OUTPUT"

print_subheader "Processes with possible credentials in memory (root needed)"
{
    if [ "$(id -u)" -ne 0 ]; then
        echo "⚠️ This check requires root privileges. Skipping."
    else
        for pid in $(ls /proc | grep -E '^[0-9]+$'); do
            cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
            maps="/proc/$pid/maps"
            mem="/proc/$pid/mem"

            # If both maps and mem are readable
            if [ -r "$maps" ] && [ -r "$mem" ]; then
                grep -aEi 'password=|passwd|token=|secret=|apikey=|access_key=|authorization=|login=' /proc/$pid/environ 2>/dev/null | \
                grep -q . && echo "⚠️ PID $pid ($cmdline) may have credentials in its environment"
            fi
        done
    fi
} >> "$OUTPUT"


print_subheader "Checking if running binaries are writable (can we alter them?)"
{
    found=false
    for pid in $(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf "%f\n" 2>/dev/null); do
        exe_path="/proc/$pid/exe"
        [ -L "$exe_path" ] || continue

        exe_target=$(readlink -f "$exe_path" 2>/dev/null)
        [ -z "$exe_target" ] || [ ! -e "$exe_target" ] && continue

        if [ -w "$exe_target" ]; then
            cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
            echo "⚠️ Writable binary: $exe_target (PID: $pid, CMD: ${cmdline:-[unknown]})"
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo "⚠️ No writable binaries found among running processes."
    fi
} >> "$OUTPUT"


print_header "Cron Jobs"
print_subheader "List all cron jobs"

cronjobs=$(ls -la /etc/cron* 2>/dev/null)

if [ -n "$cronjobs" ]; then
    echo -e "🕒 System-wide cron jobs found:\n$cronjobs" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No cron jobs found in /etc/cron*" >> "$OUTPUT"
fi

print_subheader "Check for world-writable cron jobs"

cronjobwwperms=$(find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;)

if [ -n "$cronjobwwperms" ]; then
    echo -e "⚠️ World-writable cron job files found. Contents below:\n$cronjobwwperms" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "✅ No world-writable cron jobs detected." >> "$OUTPUT"
fi

print_subheader "Check for crontab and anacron configuration"

# 1. Check contents of /etc/crontab
crontabvalue=$(cat /etc/crontab 2>/dev/null)
if [ -n "$crontabvalue" ]; then
    echo -e "📄 Contents of /etc/crontab:\n$crontabvalue" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No /etc/crontab file found." >> "$OUTPUT"
fi

# 2. Check contents of /var/spool/cron/crontabs (user crontabs)
crontabvar=$(ls -la /var/spool/cron/crontabs 2>/dev/null)
if [ -n "$crontabvar" ]; then
    echo -e "📁 User crontab files in /var/spool/cron/crontabs:\n$crontabvar" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No user crontabs found in /var/spool/cron/crontabs." >> "$OUTPUT"
fi

# 3. Check /etc/anacrontab and its permissions
anacronjobs=$(ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null)
if [ -n "$anacronjobs" ]; then
    echo -e "📄 Anacron configuration and permissions (/etc/anacrontab):\n$anacronjobs" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No /etc/anacrontab file found." >> "$OUTPUT"
fi

# 4. Check job execution history in /var/spool/anacron
anacrontab=$(ls -la /var/spool/anacron 2>/dev/null)
if [ -n "$anacrontab" ]; then
    echo -e "📅 Anacron job execution history (/var/spool/anacron):\n$anacrontab" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No records found in /var/spool/anacron." >> "$OUTPUT"
fi


print_header "Network"
print_subheader "Device interfaces"

# 1. Check /etc/networks (legacy network definitions)
networksfile=$(cat /etc/networks 2>/dev/null)
if [ -n "$networksfile" ]; then
    echo -e "📄 Contents of /etc/networks:\n$networksfile" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No /etc/networks file found or it's empty." >> "$OUTPUT"
fi

# 2. Check network interfaces (ifconfig or ip or fallback to /proc)
if command -v ifconfig &>/dev/null; then
    netinterfaces=$(ifconfig 2>/dev/null)
    echo -e "🔧 Network interfaces (via ifconfig):\n$netinterfaces" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
elif command -v ip &>/dev/null; then
    netinterfaces=$(ip a 2>/dev/null)
    echo -e "🔧 Network interfaces (via ip a):\n$netinterfaces" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    procnetdev=$(cat /proc/net/dev 2>/dev/null)
    fibtrie=$(cat /proc/net/fib_trie 2>/dev/null)
    fibtrie6=$(cat /proc/net/fib_trie6 2>/dev/null)

    if [ -n "$procnetdev" ] || [ -n "$fibtrie" ] || [ -n "$fibtrie6" ]; then
        echo "⚠️ Neither ifconfig nor ip command found. Showing /proc-based network info." >> "$OUTPUT"
        echo -e "\n📄 /proc/net/dev:\n$procnetdev" >> "$OUTPUT"
        echo -e "\n📄 /proc/net/fib_trie:\n$fibtrie" >> "$OUTPUT"
        echo -e "\n📄 /proc/net/fib_trie6:\n$fibtrie6" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    else
        echo "⚠️ No network information could be collected." >> "$OUTPUT"
    fi
fi

print_subheader "Hostname, DNS and ARP"

# Enable extra checks by default
EXTRA_CHECKS=true

# 1. Hostname, hosts, and resolv.conf
hostdnsinfo=$(cat /etc/hostname /etc/hosts /etc/resolv.conf 2>/dev/null | grep -v "^#" | grep -Ev "\W+\#|^#")
if [ -n "$hostdnsinfo" ]; then
    echo -e "🌐 Hostname, hosts file, and DNS resolver info:\n$hostdnsinfo" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ Could not read hostname or DNS configuration files." >> "$OUTPUT"
fi

# 2. DNS domain name
dnsdomain=$(dnsdomainname 2>/dev/null)
if [ -n "$dnsdomain" ]; then
    echo -e "📛 DNS domain name: $dnsdomain" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 3. Network routes and neighbors (always enabled now)
if [ "$EXTRA_CHECKS" ]; then
    echo -e "🌐 Network routes and neighbor devices:\n" >> "$OUTPUT"

    if [ "$MACPEAS" ]; then
        routes=$(netstat -rn 2>/dev/null)
    else
        routes=$( (route || ip n || cat /proc/net/route) 2>/dev/null )
    fi

    if [ -n "$routes" ]; then
        echo -e "📌 Routing table:\n$routes" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    else
        echo "⚠️ No routing table found." >> "$OUTPUT"
    fi

    neighbors=$( (arp -e || arp -a || cat /proc/net/arp) 2>/dev/null )
    if [ -n "$neighbors" ]; then
        echo -e "📡 ARP/neighbor table:\n$neighbors" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    else
        echo "⚠️ No ARP or neighbor information found." >> "$OUTPUT"
    fi
fi


print_subheader "Actice TCP Ports"

# 1. Try netstat with process info
tcpservs=$(netstat -ntpl 2>/dev/null)
if [ -n "$tcpservs" ]; then
    echo -e "🔌 Listening TCP ports and processes (via netstat):\n$tcpservs" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 2. Fallback to ss if netstat fails or is unavailable
if [ -z "$tcpservs" ]; then
    tcpservsip=$(ss -t -l -n -p 2>/dev/null)
    if [ -n "$tcpservsip" ]; then
        echo -e "🔌 Listening TCP ports and processes (via ss):\n$tcpservsip" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    else
        echo "⚠️ No listening TCP ports found or tools unavailable." >> "$OUTPUT"
    fi
fi

print_subheader "Active UDP Ports"

# 1. Try netstat with process info
udpservs=$(netstat -nupl 2>/dev/null)
if [ -n "$udpservs" ]; then
    echo -e "📡 Listening UDP ports and processes (via netstat):\n$udpservs" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 2. Fallback to ss if netstat fails or is unavailable
if [ -z "$udpservs" ]; then
    udpservsip=$(ss -u -l -n -p 2>/dev/null)
    if [ -n "$udpservsip" ]; then
        echo -e "📡 Listening UDP ports and processes (via ss):\n$udpservsip" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    else
        echo "⚠️ No listening UDP ports found or tools unavailable." >> "$OUTPUT"
    fi
fi

print_header "Firewall rules"
print_subheader "Checking firewall rules"

# 1. iptables rules
iptables_rules=$(iptables -L -n -v 2>/dev/null)
if [ -n "$iptables_rules" ]; then
    echo -e "🔥 iptables rules:\n$iptables_rules" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No iptables rules found or iptables not installed." >> "$OUTPUT"
fi

# 2. nftables rules
nft_rules=$(nft list ruleset 2>/dev/null)
if [ -n "$nft_rules" ]; then
    echo -e "🔥 nftables rules:\n$nft_rules" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No nftables rules found or nft not available." >> "$OUTPUT"
fi

# 3. UFW (Uncomplicated Firewall)
if command -v ufw &>/dev/null; then
    ufw_status=$(ufw status verbose 2>/dev/null)
    echo -e "🔥 UFW status:\n$ufw_status" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 4. firewalld (dynamic firewall used by RedHat-based distros)
if command -v firewall-cmd &>/dev/null; then
    firewall_status=$(firewall-cmd --state 2>/dev/null)
    if [ "$firewall_status" = "running" ]; then
        firewall_config=$(firewall-cmd --list-all --zone=public 2>/dev/null)
        echo -e "🔥 firewalld is running:\n$firewall_config" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    else
        echo "⚠️ firewalld is installed but not running." >> "$OUTPUT"
    fi
fi

# 5. Custom firewall-related scripts in if-up.d
if [ -d /etc/network/if-up.d ]; then
    custom_fw_scripts=$(ls -la /etc/network/if-up.d 2>/dev/null | grep -v "^total")
    if [ -n "$custom_fw_scripts" ]; then
        echo -e "📜 Custom network-up firewall scripts (/etc/network/if-up.d):\n$custom_fw_scripts" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    fi
fi

# 6. Optional: Check outbound policies using iptables
outbound_rules=$(iptables -L OUTPUT -n -v 2>/dev/null)
if [ -n "$outbound_rules" ]; then
    echo -e "🌍 Outbound connection rules (iptables OUTPUT chain):\n$outbound_rules" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi


print_header "Software"
print_subheader "Installed software on host (could be used for priv esc)"

USEFUL_SOFTWARE="
authbind awk base64 bash busybox cat chattr chgrp chmod chown
cp cpio crontab curl cut dash dd df dmesg dmsetup
docker doas echo ed env expand expect find flock fmt fold gawk
gcloud gcc g++ gcore gdb gh git grep groups gzip head
hostname iconv id ifconfig ip iptables jq journalctl kill less
ln login lsof lua lxc make more mount mv nano nc
nc.traditional ncat net netcat netstat newgrp nmap nohup nsenter
openssl parted passwd perl php ping pip pip3 podman powercat
ps pstree pwsh python python2 python2.6 python2.7 python3 python3.6 python3.7
readlink reboot red ruby runc rvi rview rsync run-parts
scp screen sed setfacl sh sha1sum sha256sum sleep socat sort
ssh ss ssmtp stat strace strings su sudo systemctl tac tail tar tee telnet
time timeout tmux top touch tr uname unshare unzip vi vim watch wc wget which whoami write xargs xxd xz yes zip
"

found_software=""

for bin in $USEFUL_SOFTWARE; do
    bin_path=$(command -v "$bin" 2>/dev/null)
    if [ -n "$bin_path" ]; then
        found_software+="$bin: $bin_path\n"
    fi
done

if [ -n "$found_software" ]; then
    echo -e "The following software was found:\n$found_software" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ None of the known escalation tools were found." >> "$OUTPUT"
fi

print_subheader "Check for installed compilers"

# 1. Search with dpkg or yum
compilers=""
if command -v dpkg &>/dev/null; then
    compilers=$(dpkg --list 2>/dev/null | grep -i "compiler" | grep -vi "decompiler\|lib")
elif command -v yum &>/dev/null; then
    compilers=$(yum list installed 'gcc*' 2>/dev/null | grep -i gcc)
fi

# 2. Check for installed binaries directly
for bin in gcc g++ clang cc c++ go rustc tcc zig; do
    bin_path=$(command -v "$bin" 2>/dev/null)
    if [ -n "$bin_path" ]; then
        compilers+="$bin: $bin_path\n"
    fi
done

# 3. Output
if [ -n "$compilers" ]; then
    echo -e "🛠️ Installed compilers found:\n$compilers" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No compilers found on the system." >> "$OUTPUT"
fi

print_subheader "Check for TMUX sessions and socket permissions"
# 1. Capture tmux session info
tmuxdefsess=$(tmux ls 2>/dev/null)
tmuxnondefsess=$(ps auxwww | grep "tmux " | grep -v grep)
tmuxsess2=$(find /tmp -type d -path "/tmp/tmux-*" 2>/dev/null)
tmux_othersess=$(find /tmp -type d -regex "/tmp/tmux-[0-9]+" ! -user "$USER" 2>/dev/null)

# 2. Check if anything was found
if [ -n "$tmuxdefsess" ] || [ -n "$tmuxnondefsess" ] || [ -n "$tmuxsess2" ] || [ -n "$tmux_othersess" ] || [ "$DEBUG" ]; then
    print_2title "Searching tmux sessions"
    print_info "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions"

    echo -e "🖥️ tmux version:\n$(tmux -V 2>/dev/null)" >> "$OUTPUT"

    echo -e "\n🔍 tmux sessions found:" >> "$OUTPUT"
    printf "$tmuxdefsess\n$tmuxnondefsess\n$tmuxsess2\n$tmux_othersess" \
        | sed -${E} "s,.*,${SED_RED}," \
        | sed -${E} "s,no server running on.*,${C}[32m&${C}[0m," >> "$OUTPUT"

    # 3. Check for other users' writable sockets
    writables=$(find /tmp -type s -path "/tmp/tmux*" -not -user "$USER" '(' '(' -perm -o=w ')' -or '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null)
    if [ -n "$writables" ]; then
        echo -e "\n⚠️ Writable tmux sockets owned by other users:" >> "$OUTPUT"
        echo "$writables" | while read -r f; do
            echo "Other user tmux socket is writable: $f" | sed "s,$f,${SED_RED_YELLOW}," >> "$OUTPUT"
        done
    fi

    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No active tmux sessions or sockets found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for pkexec/Polkit local authorization configuration"

# Search in /etc/polkit-1/localauthority.conf.d/
pkexec_policy=$(cat /etc/polkit-1/localauthority.conf.d/* 2>/dev/null \
    | grep -v "^#" \
    | grep -Ev "\W+\#|^#")

if [ -n "$pkexec_policy" ]; then
    echo -e "🛂 pkexec policy settings from /etc/polkit-1/localauthority.conf.d/:\n$pkexec_policy" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No readable pkexec policy files found in /etc/polkit-1/localauthority.conf.d/" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_header "Web Files"
print_subheader "Check for web-accessible files (limited output)"

# 1. /var/www/
web1=$(ls -alhR /var/www/ 2>/dev/null | head)
if [ -n "$web1" ]; then
    echo -e "🌐 /var/www/:\n$web1" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 2. /srv/www/htdocs/
web2=$(ls -alhR /srv/www/htdocs/ 2>/dev/null | head)
if [ -n "$web2" ]; then
    echo -e "🌐 /srv/www/htdocs/:\n$web2" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 3. /usr/local/www/apache22/data/
web3=$(ls -alhR /usr/local/www/apache22/data/ 2>/dev/null | head)
if [ -n "$web3" ]; then
    echo -e "🌐 /usr/local/www/apache22/data/:\n$web3" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 4. /opt/lampp/htdocs/
web4=$(ls -alhR /opt/lampp/htdocs/ 2>/dev/null | head)
if [ -n "$web4" ]; then
    echo -e "🌐 /opt/lampp/htdocs/:\n$web4" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi


print_subheader "Check for Apache and Nginx configuration files"
# 1. Apache version
apache_version=$(apache2 -v 2>/dev/null || httpd -v 2>/dev/null)
if [ -n "$apache_version" ]; then
    echo -e "🌐 Apache version:\n$apache_version" >> "$OUTPUT"
else
    echo "⚠️ Apache not installed or not in PATH." >> "$OUTPUT"
fi

# 2. Nginx version
nginx_version=$(nginx -v 2>&1)
if echo "$nginx_version" | grep -qi "version"; then
    echo -e "\n🌐 Nginx version:\n$nginx_version" >> "$OUTPUT"
else
    echo -e "\n⚠️ Nginx not installed or not in PATH." >> "$OUTPUT"
fi

# 3. Apache php handler grep
if [ -d "/etc/apache2" ] && [ -r "/etc/apache2" ]; then
    apache_php_handlers=$(grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null | head -n 70)
    if [ -n "$apache_php_handlers" ]; then
        echo -e "\n🔍 Detected Apache PHP handler mappings (/etc/apache2):\n$apache_php_handlers" >> "$OUTPUT"
    fi
fi

# 4. Nginx modules
if [ -d "/usr/share/nginx/modules" ] && [ -r "/usr/share/nginx/modules" ]; then
    print_3title "Nginx modules"
    nginx_modules=$(ls /usr/share/nginx/modules 2>/dev/null | sed -${E} "s,$NGINX_KNOWN_MODULES,${SED_GREEN},g")
    if [ -n "$nginx_modules" ]; then
        echo -e "📦 Nginx modules in /usr/share/nginx/modules:\n$nginx_modules" >> "$OUTPUT"
    fi
fi

echo -e "\n" >> "$OUTPUT"


print_subheader "Apache configuration, users, modules, and .htpasswd"

# 1. What account is Apache running under
apacheusr=$(grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null | awk '{sub(/.*\export /,"")}1')
if [ -n "$apacheusr" ]; then
    echo -e "👤 Apache user configuration from /etc/apache2/envvars:\n$apacheusr" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 2. Export apache envvars if requested
if [ "$export" ] && [ -n "$apacheusr" ]; then
    mkdir -p "$format/etc-export/apache2/" 2>/dev/null
    cp /etc/apache2/envvars "$format/etc-export/apache2/envvars" 2>/dev/null
fi

# 3. Installed Apache modules
apachemodules=$(apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null)
if [ -n "$apachemodules" ]; then
    echo -e "🧩 Installed Apache modules:\n$apachemodules" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 4. htpasswd files
htpasswd=$(find / -name .htpasswd -print -exec cat {} \; 2>/dev/null)
if [ -n "$htpasswd" ]; then
    echo -e "🔐 .htpasswd file(s) found (may contain credentials):\n$htpasswd" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# 5. Check Apache home directories (only if thorough mode is enabled)
if [ "$thorough" = "1" ]; then
    apachehomedirs=$(ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null)
    if [ -n "$apachehomedirs" ]; then
        echo -e "📁 Apache home directory contents (thorough mode):\n$apachehomedirs" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    fi
fi


print_subheader "Analyzing WordPress Files"

# 1. Find wp-config.php files from PSTORAGE_WORDPRESS
wpconfigs=$(printf "%s" "$PSTORAGE_WORDPRESS" | grep -E "wp-config\.php$")
found_wp=false

if [ -z "$wpconfigs" ]; then
    if [ "$DEBUG" ]; then
        echo_not_found "wp-config.php"
    fi
else
    found_wp=true
    echo -e "🔍 Found wp-config.php file(s):" >> "$OUTPUT"
fi

# 2. Process each wp-config.php
printf "%s" "$wpconfigs" | while read -r f; do
    # Show file metadata
    meta=$(ls -ld "$f" 2>/dev/null | sed -${E} "s,wp-config\.php$,${SED_RED},")
    if [ -n "$meta" ]; then
        echo -e "\n📄 $f metadata:\n$meta" >> "$OUTPUT"
    fi

    # Extract DB credentials
    dbcreds=$(cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "PASSWORD|USER|NAME|HOST" | sed -${E} "s,PASSWORD|USER|NAME|HOST,${SED_RED},g" | head -n 70)
    if [ -n "$dbcreds" ]; then
        echo -e "🔐 Extracted DB config lines:\n$dbcreds" >> "$OUTPUT"
    fi
done

# 3. Not found fallback message
if [ "$found_wp" = false ]; then
    echo "⚠️ No WordPress wp-config.php files were found." >> "$OUTPUT"
fi

echo -e "\n" >> "$OUTPUT"

print_subheader "Analyzing Apache Tomcat"

TOMCAT_DIRS="/opt/tomcat /usr/share/tomcat /usr/share/tomcat7 /usr/share/tomcat9 /usr/local/tomcat /var/lib/tomcat /var/lib/tomcat9"
found_tomcat=false

for dir in $TOMCAT_DIRS; do
    if [ -d "$dir" ]; then
        found_tomcat=true
        echo -e "📁 Tomcat directory found: $dir" >> "$OUTPUT"

        # 1. tomcat-users.xml
        if [ -f "$dir/conf/tomcat-users.xml" ]; then
            echo -e "\n🔐 Contents of tomcat-users.xml (credentials):" >> "$OUTPUT"
            grep -Ei "user|role" "$dir/conf/tomcat-users.xml" 2>/dev/null >> "$OUTPUT"
        fi

        # 2. Deployed webapps
        if [ -d "$dir/webapps" ]; then
            echo -e "\n🌐 Deployed web applications in $dir/webapps:" >> "$OUTPUT"
            ls -lh "$dir/webapps" 2>/dev/null >> "$OUTPUT"
        fi

        # 3. Configuration files
        if [ -d "$dir/conf" ]; then
            echo -e "\n⚙️ Tomcat configuration files in $dir/conf:" >> "$OUTPUT"
            ls -lh "$dir/conf" 2>/dev/null >> "$OUTPUT"
        fi

        echo -e "\n" >> "$OUTPUT"
    fi
done

# Message if nothing found
if [ "$found_tomcat" = false ]; then
    echo "⚠️ No Tomcat installation or configuration files found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi


print_header "Configuration Files"
print_subheader "Check for PAM Authentication Files"

pam_dirs=$(printf "%s" "$PSTORAGE_PAM_AUTH" | grep -E "pam\.d$")
if [ -z "$pam_dirs" ]; then
    echo "⚠️ No PAM directories (pam.d) found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo -e "🔐 PAM configuration directories found:\n" >> "$OUTPUT"
    found_pam=false
    printf "%s" "$pam_dirs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        found_pam=true

        find "$f" -name "sshd" 2>/dev/null | while read -r sshdfile; do
            ls -ld "$sshdfile" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 sshd PAM file contents ($sshdfile):" >> "$OUTPUT"
            cat "$sshdfile" 2>/dev/null | grep -Ev "^#|^@|^$" >> "$OUTPUT"
        done

        echo -e "\n" >> "$OUTPUT"
    done

    if [ "$found_pam" = false ]; then
        echo "⚠️ PAM directory was found, but no sshd files detected." >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    fi
fi

print_subheader "Check for LDAP configuration and database files"

ldap_dirs=$(printf "%s" "$PSTORAGE_LDAP" | grep -E "ldap$")
if [ -z "$ldap_dirs" ]; then
    echo "⚠️ No LDAP directories found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo -e "📁 LDAP directories found:\n" >> "$OUTPUT"
    found_ldap=false
    printf "%s" "$ldap_dirs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        found_ldap=true

        find "$f" -name "*.bdb" 2>/dev/null | while read -r bdbfile; do
            ls -ld "$bdbfile" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 LDAP .bdb file contents ($bdbfile):" >> "$OUTPUT"
            cat "$bdbfile" 2>/dev/null \
                | grep -i -a -o "description.*" \
                | sort | uniq >> "$OUTPUT"
        done

        echo -e "\n" >> "$OUTPUT"
    done

    if [ "$found_ldap" = false ]; then
        echo "⚠️ LDAP path exists, but no .bdb files found." >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    fi
fi

print_subheader "Check for Keyring, Keystore, and Credential Files"

# Keyrings (directory)
keyring_dirs=$(printf "%s" "$PSTORAGE_KEYRING" | grep -E "keyrings$")
if [ -z "$keyring_dirs" ]; then
    echo "⚠️ No keyring directories found." >> "$OUTPUT"
else
    echo -e "🔐 Keyring directories found:\n" >> "$OUTPUT"
    printf "%s" "$keyring_dirs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
fi
echo -e "\n" >> "$OUTPUT"

# .keyring files
keyring_files=$(printf "%s" "$PSTORAGE_KEYRING" | grep -E "\.keyring$")
if [ -z "$keyring_files" ]; then
    echo "⚠️ No .keyring files found." >> "$OUTPUT"
else
    echo -e "🔑 .keyring files found:\n" >> "$OUTPUT"
    printf "%s" "$keyring_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
fi
echo -e "\n" >> "$OUTPUT"

# .keystore files
keystore_files=$(printf "%s" "$PSTORAGE_KEYRING" | grep -E "\.keystore$")
if [ -z "$keystore_files" ]; then
    echo "⚠️ No .keystore files found." >> "$OUTPUT"
else
    echo -e "🗝️ .keystore files found:\n" >> "$OUTPUT"
    printf "%s" "$keystore_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
fi
echo -e "\n" >> "$OUTPUT"

# .jks files
jks_files=$(printf "%s" "$PSTORAGE_KEYRING" | grep -E "\.jks$")
if [ -z "$jks_files" ]; then
    echo "⚠️ No .jks files found." >> "$OUTPUT"
else
    echo -e "🔐 .jks files found:\n" >> "$OUTPUT"
    printf "%s" "$jks_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
fi
echo -e "\n" >> "$OUTPUT"

print_subheader "Check for FTP Configuration Files"

ftp_found=false

# vsftpd.conf
vsftpd_confs=$(printf "%s" "$PSTORAGE_FTP" | grep -E "vsftpd\.conf$")
if [ -z "$vsftpd_confs" ]; then
    echo "⚠️ No vsftpd.conf files found." >> "$OUTPUT"
else
    ftp_found=true
    echo -e "🔧 vsftpd.conf files found:\n" >> "$OUTPUT"
    printf "%s" "$vsftpd_confs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Relevant settings from $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null \
            | grep -E "anonymous_enable|anon_upload_enable|anon_mkdir_write_enable|anon_root|chown_uploads|chown_username|local_enable|no_anon_password|write_enable" \
            | grep -Ev "^$" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# Generic function for other config types
check_ftp_filetype() {
    pattern="$1"
    label="$2"

    matches=$(printf "%s" "$PSTORAGE_FTP" | grep -E "$pattern")
    if [ -z "$matches" ]; then
        echo "⚠️ No $label files found." >> "$OUTPUT"
    else
        ftp_found=true
        echo -e "📄 $label files found:\n" >> "$OUTPUT"
        printf "%s" "$matches" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        done
    fi
    echo -e "\n" >> "$OUTPUT"
}

# Run checks on known FTP-related files
check_ftp_filetype "\.ftpconfig$" ".ftpconfig"
check_ftp_filetype "ffftp\.ini$" "ffftp.ini"
check_ftp_filetype "ftp\.ini$" "ftp.ini"
check_ftp_filetype "ftp\.config$" "ftp.config"
check_ftp_filetype "sites\.ini$" "sites.ini"
check_ftp_filetype "wcx_ftp\.ini$" "wcx_ftp.ini"
check_ftp_filetype "winscp\.ini$" "winscp.ini"
check_ftp_filetype "ws_ftp\.ini$" "ws_ftp.ini"

# Final message if nothing found at all
if [ "$ftp_found" = false ]; then
    echo "⚠️ No FTP configuration files of interest were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Cloud-Init Configuration Files"

cloud_init_found=false

cloud_cfg_files=$(printf "%s" "$PSTORAGE_CLOUD_INIT" | grep -E "cloud\.cfg$")
if [ -z "$cloud_cfg_files" ]; then
    echo "⚠️ No cloud.cfg files found." >> "$OUTPUT"
else
    cloud_init_found=true
    echo -e "☁️ cloud.cfg files found:\n" >> "$OUTPUT"
    printf "%s" "$cloud_cfg_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sensitive or configuration entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null \
            | grep -E "consumer_key|token_key|token_secret|metadata_url|password:|passwd:|PRIVATE KEY|encrypted_data_bag_secret|_proxy" \
            | grep -Ev "^#|^\s*#" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$cloud_init_found" = false ]; then
    echo "⚠️ No cloud-init credentials or config artifacts were discovered." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Git Credentials Files"

git_creds_found=false

git_cred_files=$(printf "%s" "$PSTORAGE_GIT" | grep -E "\.git-credentials$")
if [ -z "$git_cred_files" ]; then
    echo "⚠️ No .git-credentials files found." >> "$OUTPUT"
else
    git_creds_found=true
    echo -e "🔐 .git-credentials files found:\n" >> "$OUTPUT"
    printf "%s" "$git_cred_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^$" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$git_creds_found" = false ]; then
    echo "⚠️ No Git credential files with sensitive content were discovered." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi


print_subheader "Check for GitHub Configuration and Credential Files"

github_found=false

# .github directory
github_dirs=$(printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.github$")
if [ -z "$github_dirs" ]; then
    echo "⚠️ No .github directories found." >> "$OUTPUT"
else
    github_found=true
    echo -e "📁 .github directories found:\n" >> "$OUTPUT"
    printf "%s" "$github_dirs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# .gitconfig file
gitconfig_files=$(printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.gitconfig$")
if [ -z "$gitconfig_files" ]; then
    echo "⚠️ No .gitconfig files found." >> "$OUTPUT"
else
    github_found=true
    echo -e "⚙️ .gitconfig files found:\n" >> "$OUTPUT"
    printf "%s" "$gitconfig_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^$" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# .git-credentials file
gitcred_files=$(printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.git-credentials$")
if [ -z "$gitcred_files" ]; then
    echo "⚠️ No .git-credentials files found." >> "$OUTPUT"
else
    github_found=true
    echo -e "🔐 .git-credentials files found:\n" >> "$OUTPUT"
    printf "%s" "$gitcred_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# .git directories
git_dirs=$(printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.git$")
if [ -z "$git_dirs" ]; then
    echo "⚠️ No .git directories found." >> "$OUTPUT"
else
    github_found=true
    echo -e "📂 .git directories found:\n" >> "$OUTPUT"
    printf "%s" "$git_dirs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# Additional scan for version control directories using find
vcs_dirs=$(find / $lse_find_opts \( -name ".git" -o -name ".svn" \) -print 2>/dev/null)
if [ -n "$vcs_dirs" ]; then
    github_found=true
    echo -e "🔎 Version control directories found on system:\n$vcs_dirs" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ No .git or .svn directories found using filesystem scan." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# Final fallback message
if [ "$github_found" = false ]; then
    echo "⚠️ No GitHub-related configuration, credential files, or repositories were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi


print_subheader "Check for Moodle Configuration Files"

moodle_found=false

moodle_configs=$(printf "%s" "$PSTORAGE_MOODLE" | grep -E "config\.php$")
if [ -z "$moodle_configs" ]; then
    echo "⚠️ No Moodle config.php files found." >> "$OUTPUT"
else
    moodle_found=true
    echo -e "📄 Moodle config.php files found:\n" >> "$OUTPUT"
    printf "%s" "$moodle_configs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Extracted database settings from $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null \
            | grep -E "dbtype|dbhost|dbuser|dbpass|dbport" \
            | grep -Ev "^$" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$moodle_found" = false ]; then
    echo "⚠️ No Moodle configuration files with sensitive content were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Rsync Configuration and Secrets Files"

rsync_found=false

# rsyncd.conf
rsync_conf_files=$(printf "%s" "$PSTORAGE_RSYNC" | grep -E "rsyncd\.conf$")
if [ -z "$rsync_conf_files" ]; then
    echo "⚠️ No rsyncd.conf files found." >> "$OUTPUT"
else
    rsync_found=true
    echo -e "⚙️ rsyncd.conf files found:\n" >> "$OUTPUT"
    printf "%s" "$rsync_conf_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null \
            | grep -Ev "^#|^\s*#" \
            | grep -Ei "secrets|auth.*users" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# rsyncd.secrets
rsync_secrets_files=$(printf "%s" "$PSTORAGE_RSYNC" | grep -E "rsyncd\.secrets$")
if [ -z "$rsync_secrets_files" ]; then
    echo "⚠️ No rsyncd.secrets files found." >> "$OUTPUT"
else
    rsync_found=true
    echo -e "🔐 rsyncd.secrets files found:\n" >> "$OUTPUT"
    printf "%s" "$rsync_secrets_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^$" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$rsync_found" = false ]; then
    echo "⚠️ No rsync configuration or secrets files with sensitive data were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for RPCD Configuration Files"

rpcd_found=false

rpcd_files=$(printf "%s" "$PSTORAGE_RPCD" | grep -E "rpcd$")
if [ -z "$rpcd_files" ]; then
    echo "⚠️ No rpcd files found." >> "$OUTPUT"
else
    rpcd_found=true
    echo -e "⚙️ rpcd configuration files found:\n" >> "$OUTPUT"
    printf "%s" "$rpcd_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null \
            | grep -Ev "^$" \
            | grep -Ei "username.+|password.+" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$rpcd_found" = false ]; then
    echo "⚠️ No rpcd configuration files with sensitive content were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Bitcoin Configuration Files"

btc_found=false
btc_files=$(printf "%s" "$PSTORAGE_BITCOIN" | grep -E "bitcoin\.conf$")

if [ -z "$btc_files" ]; then
    echo "⚠️ No bitcoin.conf files found." >> "$OUTPUT"
else
    btc_found=true
    echo -e "💰 bitcoin.conf files found:\n" >> "$OUTPUT"
    printf "%s" "$btc_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^#" | grep -Ei "user=|password=|auth=" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Hostapd Configuration Files"

hostapd_found=false
hostapd_files=$(printf "%s" "$PSTORAGE_HOSTAPD" | grep -E "hostapd\.conf$")

if [ -z "$hostapd_files" ]; then
    echo "⚠️ No hostapd.conf files found." >> "$OUTPUT"
else
    hostapd_found=true
    echo -e "📡 hostapd.conf files found:\n" >> "$OUTPUT"
    printf "%s" "$hostapd_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^#" | grep -Ei "passphrase" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for NFS Exports and Mounts"

nfs_found=false

# Check currently connected NFS mounts
nfsmounts=$(cat /proc/mounts 2>/dev/null | grep nfs)
if [ -n "$nfsmounts" ]; then
    nfs_found=true
    echo -e "📥 Connected NFS mounts:\n$nfsmounts" >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# Look for /etc/exports files
nfs_exports=$(printf "%s" "$PSTORAGE_NFS_EXPORTS" | grep -E "exports$")
if [ -z "$nfs_exports" ]; then
    echo "⚠️ No NFS exports files found." >> "$OUTPUT"
else
    nfs_found=true
    echo -e "📂 NFS exports files found:\n" >> "$OUTPUT"
    printf "%s" "$nfs_exports" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Export options in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null \
            | grep -Ev "^#" \
            | grep -Ei "insecure|rw|nohide|no_root_squash|no_all_squash" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$nfs_found" = false ]; then
    echo "⚠️ No NFS configuration or mounts found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for VNC Configuration and Credential Files"

vnc_found=false

# .vnc directories
vnc_dirs=$(printf "%s" "$PSTORAGE_VNC" | grep -E "\.vnc$")
if [ -z "$vnc_dirs" ]; then
    echo "⚠️ No .vnc directories found." >> "$OUTPUT"
else
    vnc_found=true
    echo -e "📁 .vnc directories:\n" >> "$OUTPUT"
    printf "%s" "$vnc_dirs" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        find "$f" -name "passwd" 2>/dev/null | while read -r ff; do
            echo -e "\n🔐 VNC password file: $ff" >> "$OUTPUT"
            ls -ld "$ff" 2>/dev/null >> "$OUTPUT"
        done
    done
    echo -e "\n" >> "$OUTPUT"
fi

# VNC config files (vnc*.conf)
vnc_conf=$(printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.c.*nf.*$")
if [ -z "$vnc_conf" ]; then
    echo "⚠️ No vnc*.conf files found." >> "$OUTPUT"
else
    vnc_found=true
    echo -e "⚙️ VNC configuration (.conf) files:\n" >> "$OUTPUT"
    printf "%s" "$vnc_conf" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n📄 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^#" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# VNC .ini files
vnc_ini=$(printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.ini$")
if [ -z "$vnc_ini" ]; then
    echo "⚠️ No vnc*.ini files found." >> "$OUTPUT"
else
    vnc_found=true
    echo -e "📑 VNC .ini files:\n" >> "$OUTPUT"
    printf "%s" "$vnc_ini" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# VNC .txt files
vnc_txt=$(printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.txt$")
if [ -z "$vnc_txt" ]; then
    echo "⚠️ No vnc*.txt files found." >> "$OUTPUT"
else
    vnc_found=true
    echo -e "📝 VNC .txt files:\n" >> "$OUTPUT"
    printf "%s" "$vnc_txt" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n📄 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# VNC .xml files
vnc_xml=$(printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.xml$")
if [ -z "$vnc_xml" ]; then
    echo "⚠️ No vnc*.xml files found." >> "$OUTPUT"
else
    vnc_found=true
    echo -e "🧾 VNC .xml files:\n" >> "$OUTPUT"
    printf "%s" "$vnc_xml" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n📄 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$vnc_found" = false ]; then
    echo "⚠️ No VNC-related configuration or credential files were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Terraform Configuration and State Files"

terraform_found=false

# .tfstate files (may contain secrets)
tfstate_files=$(printf "%s" "$PSTORAGE_TERRAFORM" | grep -E "\.tfstate$")
if [ -z "$tfstate_files" ]; then
    echo "⚠️ No .tfstate files found." >> "$OUTPUT"
else
    terraform_found=true
    echo -e "🗂️ Terraform state files (.tfstate):\n" >> "$OUTPUT"
    printf "%s" "$tfstate_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔐 Sensitive entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ei "secret" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# .tf files (Terraform configuration)
tf_files=$(printf "%s" "$PSTORAGE_TERRAFORM" | grep -E "\.tf$")
if [ -z "$tf_files" ]; then
    echo "⚠️ No .tf files found." >> "$OUTPUT"
else
    terraform_found=true
    echo -e "📄 Terraform configuration files (.tf):\n" >> "$OUTPUT"
    printf "%s" "$tf_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$terraform_found" = false ]; then
    echo "⚠️ No Terraform files or secrets were found." >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Check for Anaconda Kickstart Files"

anaconda_found=false

anaconda_files=$(printf "%s" "$PSTORAGE_ANACONDA_KS" | grep -E "anaconda-ks\.cfg$")

if [ -z "$anaconda_files" ]; then
    echo "⚠️ No anaconda-ks.cfg files found." >> "$OUTPUT"
else
    anaconda_found=true
    echo -e "📄 anaconda-ks.cfg files:\n" >> "$OUTPUT"
    printf "%s" "$anaconda_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 root password entry in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ei "rootpw" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Analyzing OpenVPN Configuration Files (.ovpn)"

ovpn_files=$(find / -type f -iname "*.ovpn" 2>/dev/null)

if [ -z "$ovpn_files" ]; then
    echo "[!] No OpenVPN configuration (.ovpn) files found."
else
    echo "[+] Found .ovpn files:"
    echo "$ovpn_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null
        cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "auth-user-pass.+" || true
        echo ""
    done
fi

print_subheader "Analyzing Elasticsearch Configuration Files"

es_found=false

# Try to get Elasticsearch version
es_version=$(curl -s -X GET '127.0.0.1:9200' | grep number | cut -d ':' -f 2 | tr -d '", ')
if [ -n "$es_version" ]; then
    echo "📦 Elasticsearch version: $es_version" >> "$OUTPUT"
else
    echo "⚠️ Could not retrieve Elasticsearch version from localhost:9200" >> "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# Find elasticsearch.yml or elasticsearch.yaml
es_files=$(find / -type f -iname "elasticsearch.y*ml" 2>/dev/null)

if [ -z "$es_files" ]; then
    echo "⚠️ No Elasticsearch configuration files (elasticsearch.yml) found." >> "$OUTPUT"
else
    es_found=true
    echo "📄 Elasticsearch configuration files found:" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "$es_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Interesting settings in $f:" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "path.data|path.logs|cluster.name|node.name|network.host|discovery.zen.ping.unicast.hosts" | grep -Ev "^\s*#" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    done
fi

echo "" >> "$OUTPUT"

print_subheader "Analyzing OpenVPN Configuration Files (.ovpn)"

ovpn_found=false

ovpn_files=$(find / -type f -iname "*.ovpn" 2>/dev/null)

if [ -z "$ovpn_files" ]; then
    echo "⚠️ No OpenVPN .ovpn files found." >> "$OUTPUT"
else
    ovpn_found=true
    echo -e "📄 OpenVPN .ovpn files:" >> "$OUTPUT"
    echo "$ovpn_files" | while read -r f; do
        {
            ls -ld "$f" 2>/dev/null
            echo "🔍 Entries in $f containing auth-user-pass:"
            cat "$f" 2>/dev/null | grep -E "auth-user-pass.+"
        } >> "$OUTPUT"
    done
    echo "" >> "$OUTPUT"
fi

print_subheader "Analyzing FileZilla Configuration Files"

filezilla_dirs=$(find / -type d -iname "filezilla" 2>/dev/null)
filezilla_xml=$(find / -type f -iname "filezilla.xml" 2>/dev/null)
recentservers_xml=$(find / -type f -iname "recentservers.xml" 2>/dev/null)

if [ -z "$filezilla_dirs" ] && [ -z "$filezilla_xml" ] && [ -z "$recentservers_xml" ]; then
    echo "⚠️ No FileZilla configuration files found." >> "$OUTPUT"
else
    if [ -n "$filezilla_dirs" ]; then
        echo -e "📂 FileZilla configuration directories:\n" >> "$OUTPUT"
        echo "$filezilla_dirs" | while read -r dir; do
            ls -ld "$dir" 2>/dev/null >> "$OUTPUT"
            find "$dir" -name "sitemanager.xml" 2>/dev/null | while read -r sm; do
                ls -ld "$sm" >> "$OUTPUT"
                echo "🔍 Entries in $sm (host/user/pass info):" >> "$OUTPUT"
                cat "$sm" 2>/dev/null | grep -Ei "Host|Port|Protocol|User|Pass" >> "$OUTPUT"
            done
        done
    fi

    if [ -n "$filezilla_xml" ]; then
        echo -e "\n📄 Found filezilla.xml files:" >> "$OUTPUT"
        echo "$filezilla_xml" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        done
    fi

    if [ -n "$recentservers_xml" ]; then
        echo -e "\n📄 Found recentservers.xml files:" >> "$OUTPUT"
        echo "$recentservers_xml" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        done
    fi

    echo "" >> "$OUTPUT"
fi

print_subheader "Analyzing Atlantis Database Files"

atlantis_db_files=$(find / -type f -iname "atlantis.db" 2>/dev/null)

if [ -z "$atlantis_db_files" ]; then
    echo "⚠️ No atlantis.db files found." >> "$OUTPUT"
else
    echo -e "📄 Found atlantis.db files:\n" >> "$OUTPUT"
    echo "$atlantis_db_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Matching entries in $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -IE "CloneURL|Username" >> "$OUTPUT"
    done
    echo "" >> "$OUTPUT"
fi

print_subheader "Analyzing Firefox Profile Files"

firefox_files=$(find / -type d \( -name ".mozilla" -o -name "Firefox" \) 2>/dev/null)

if [ -z "$firefox_files" ]; then
    echo "⚠️ No Firefox profile directories (.mozilla or Firefox) found." >> "$OUTPUT"
else
    echo -e "📄 Found Firefox-related directories:\n" >> "$OUTPUT"
    echo "$firefox_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sample entries in $f:\n" >> "$OUTPUT"
        find "$f" -type f -name "*logins.json*" -o -name "*key*.db" -o -name "*places.sqlite" 2>/dev/null | while read -r ff; do
            ls -l "$ff" 2>/dev/null >> "$OUTPUT"
        done
    done
    echo "" >> "$OUTPUT"
fi

print_subheader "Analyzing Google Chrome Profile Files"

chrome_files=$(find / -type d \( -name "google-chrome" -o -name "Chrome" \) 2>/dev/null)

if [ -z "$chrome_files" ]; then
    echo "⚠️ No Chrome profile directories (google-chrome or Chrome) found." >> "$OUTPUT"
else
    echo -e "📄 Found Chrome-related directories:\n" >> "$OUTPUT"
    echo "$chrome_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sample entries in $f:\n" >> "$OUTPUT"
        find "$f" -type f \( -name "Login Data" -o -name "Web Data" -o -name "History" -o -name "Bookmarks" -o -name "*.ldb" -o -name "*.log" \) 2>/dev/null | while read -r ff; do
            ls -l "$ff" 2>/dev/null >> "$OUTPUT"
        done
    done
    echo "" >> "$OUTPUT"
fi

print_subheader "Analyzing Safari Files"

safari_found=false

safari_files=$(find / -type d -name "Safari" 2>/dev/null)

if [ -z "$safari_files" ]; then
    echo "⚠️ No Safari directories found." >> "$OUTPUT"
else
    safari_found=true
    echo -e "📁 Safari directories found:\n" >> "$OUTPUT"
    echo "$safari_files" >> "$OUTPUT"
    echo -e "\n🔍 Inspecting contents of Safari directories:\n" >> "$OUTPUT"
    echo "$safari_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n📄 Content in $f:\n" >> "$OUTPUT"
        find "$f" -type f 2>/dev/null | while read -r ff; do
            ls -l "$ff" 2>/dev/null >> "$OUTPUT"
            cat "$ff" 2>/dev/null | grep -IEv "^$" >> "$OUTPUT"
            echo -e "\n" >> "$OUTPUT"
        done
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Analyzing Opera Browser Files"

opera_found=false

opera_dirs=$(find / -type d -name "com.operasoftware.Opera" 2>/dev/null)

if [ -z "$opera_dirs" ]; then
    echo "⚠️ No Opera directories (com.operasoftware.Opera) found." >> "$OUTPUT"
else
    opera_found=true
    echo -e "📁 Opera directories found:\n" >> "$OUTPUT"
    echo "$opera_dirs" >> "$OUTPUT"
    echo -e "\n🔍 Inspecting contents of Opera directories:\n" >> "$OUTPUT"
    echo "$opera_dirs" | while read -r dir; do
        ls -ld "$dir" 2>/dev/null >> "$OUTPUT"
        echo -e "\n📄 Content in $dir:\n" >> "$OUTPUT"
        find "$dir" -type f 2>/dev/null | while read -r file; do
            ls -l "$file" 2>/dev/null >> "$OUTPUT"
            cat "$file" 2>/dev/null | grep -IEv "^$" >> "$OUTPUT"
            echo -e "\n" >> "$OUTPUT"
        done
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Analyzing Shodan API Key Files"

shodan_files=$(find / -type f -name "api_key" 2>/dev/null)

if [ -z "$shodan_files" ]; then
    echo "⚠️ No Shodan API key files (api_key) found." >> "$OUTPUT"
else
    echo -e "🔑 Found Shodan API key files:\n" >> "$OUTPUT"
    echo "$shodan_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n📄 Contents of $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -IEv "^$" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    done
fi

print_subheader "Analyzing Zabbix Configuration Files"

zabbix_server_files=$(find / -type f -name "zabbix_server.conf" 2>/dev/null)
zabbix_agent_files=$(find / -type f -name "zabbix_agentd.conf" 2>/dev/null)
zabbix_psk_dirs=$(find / -type d -name "zabbix" 2>/dev/null)

if [ -z "$zabbix_server_files" ]; then
    echo "⚠️ No zabbix_server.conf files found." >> "$OUTPUT"
else
    echo -e "📄 zabbix_server.conf files:\n" >> "$OUTPUT"
    echo "$zabbix_server_files" | while read -r f; do
        ls -ld "$f" >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries in $f:\n" >> "$OUTPUT"
        grep -Ev "^#|^$" "$f" | grep -E "DBName|DBUser|DBPassword" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    done
fi

if [ -z "$zabbix_agent_files" ]; then
    echo "⚠️ No zabbix_agentd.conf files found." >> "$OUTPUT"
else
    echo -e "📄 zabbix_agentd.conf files:\n" >> "$OUTPUT"
    echo "$zabbix_agent_files" | while read -r f; do
        ls -ld "$f" >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries in $f:\n" >> "$OUTPUT"
        grep -Ev "^#|^$" "$f" | grep -E "TLSPSKFile|psk" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    done
fi

if [ -z "$zabbix_psk_dirs" ]; then
    echo "⚠️ No 'zabbix' directories found." >> "$OUTPUT"
else
    echo -e "📁 zabbix directories (searching for .psk files):\n" >> "$OUTPUT"
    echo "$zabbix_psk_dirs" | while read -r dir; do
        ls -ld "$dir" >> "$OUTPUT"
        find "$dir" -type f -name "*.psk" 2>/dev/null | while read -r psk; do
            echo -e "\n🔐 Found PSK file: $psk\n" >> "$OUTPUT"
            ls -ld "$psk" >> "$OUTPUT"
            cat "$psk" 2>/dev/null | grep -Ev "^$" >> "$OUTPUT"
        done
        echo -e "\n" >> "$OUTPUT"
    done
fi

print_header "Database"
print_subheader "Analyzing MariaDB Configuration Files"

mariadb_found=false

# --- From PSTORAGE_MARIADB
if [ -n "$PSTORAGE_MARIADB" ]; then
    mariadb_cnf_files=$(printf "%s" "$PSTORAGE_MARIADB" | grep -E "mariadb\.cnf$")
    debian_cnf_files=$(printf "%s" "$PSTORAGE_MARIADB" | grep -E "debian\.cnf$")

    if [ -n "$mariadb_cnf_files" ]; then
        mariadb_found=true
        echo -e "📄 Found mariadb.cnf files from PSTORAGE:\n" >> "$OUTPUT"
        echo "$mariadb_cnf_files" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 Sensitive entries from $f:\n" >> "$OUTPUT"
            grep -IEv "^$|^#" "$f" 2>/dev/null | grep -Ei "user.*|password.*|admin_address.*|debug.*|sql_warnings.*|secure_file_priv.*" >> "$OUTPUT"
        done
        echo -e "\n" >> "$OUTPUT"
    fi

    if [ -n "$debian_cnf_files" ]; then
        mariadb_found=true
        echo -e "📄 Found debian.cnf files from PSTORAGE:\n" >> "$OUTPUT"
        echo "$debian_cnf_files" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 Sensitive entries from $f:\n" >> "$OUTPUT"
            grep -IEv "^$|^#" "$f" 2>/dev/null | grep -Ei "user.*|password.*|admin_address.*|debug.*|sql_warnings.*|secure_file_priv.*" >> "$OUTPUT"
        done
        echo -e "\n" >> "$OUTPUT"
    fi
fi

# --- From file system search (redundant check in case PSTORAGE misses)
fs_mariadb_files=$(find / -type f \( -iname "mariadb.cnf" -o -iname "debian.cnf" \) 2>/dev/null)

if [ -n "$fs_mariadb_files" ]; then
    mariadb_found=true
    echo -e "📂 Additional MariaDB config files from file system scan:\n" >> "$OUTPUT"
    echo "$fs_mariadb_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Sensitive entries from $f:\n" >> "$OUTPUT"
        grep -IEv "^$|^#" "$f" 2>/dev/null | grep -Ei "user.*|password.*|admin_address.*|debug.*|sql_warnings.*|secure_file_priv.*" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

if [ "$mariadb_found" = false ]; then
    echo "⚠️ No MariaDB configuration files (mariadb.cnf or debian.cnf) found." >> "$OUTPUT"
fi

print_subheader "Analyzing PostgreSQL Configuration Files"

postgres_found=false

# --- From PSTORAGE_POSTGRES
if [ -n "$PSTORAGE_POSTGRES" ]; then
    pgpass_files=$(printf "%s" "$PSTORAGE_POSTGRES" | grep -E "\.pgpass$")
    conf_files=$(printf "%s" "$PSTORAGE_POSTGRES" | grep -E "postgresql\.conf$")
    hba_files=$(printf "%s" "$PSTORAGE_POSTGRES" | grep -E "pg_hba\.conf$")

    if [ -n "$pgpass_files" ]; then
        postgres_found=true
        echo -e "🔐 Found .pgpass credential files:\n" >> "$OUTPUT"
        echo "$pgpass_files" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 Contents of $f:\n" >> "$OUTPUT"
            cat "$f" 2>/dev/null | grep -Ev "^$|^\s*#" >> "$OUTPUT"
        done
        echo -e "\n" >> "$OUTPUT"
    fi

    if [ -n "$conf_files" ]; then
        postgres_found=true
        echo -e "📄 Found postgresql.conf files:\n" >> "$OUTPUT"
        echo "$conf_files" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 Filtered content from $f:\n" >> "$OUTPUT"
            grep -Ei "listen_addresses|port|max_connections|password_encryption|ssl" "$f" 2>/dev/null | grep -Ev "^$|^\s*#" >> "$OUTPUT"
        done
        echo -e "\n" >> "$OUTPUT"
    fi

    if [ -n "$hba_files" ]; then
        postgres_found=true
        echo -e "📘 Found pg_hba.conf access control files:\n" >> "$OUTPUT"
        echo "$hba_files" | while read -r f; do
            ls -ld "$f" 2>/dev/null >> "$OUTPUT"
            echo -e "\n🔍 Entries in $f:\n" >> "$OUTPUT"
            grep -Ev "^$|^\s*#" "$f" 2>/dev/null >> "$OUTPUT"
        done
        echo -e "\n" >> "$OUTPUT"
    fi
fi

# --- Redundant scan via find
fs_pg_files=$(find / -type f \( -name ".pgpass" -o -name "postgresql.conf" -o -name "pg_hba.conf" \) 2>/dev/null)

if [ -n "$fs_pg_files" ]; then
    postgres_found=true
    echo -e "🗂️ Additional PostgreSQL config files found via filesystem scan:\n" >> "$OUTPUT"
    echo "$fs_pg_files" | while read -r f; do
        ls -ld "$f" 2>/dev/null >> "$OUTPUT"
        echo -e "\n🔍 Content from $f:\n" >> "$OUTPUT"
        cat "$f" 2>/dev/null | grep -Ev "^$|^\s*#" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

# --- Fallback message
if [ "$postgres_found" = false ]; then
    echo "⚠️ No PostgreSQL configuration or credential files found." >> "$OUTPUT"
fi


print_subheader "Searching Tables Inside Readable Database Files (.db/.sql/.sqlite)"

db_found=false
FILECMD="$(command -v file 2>/dev/null || echo -n '')"

db_files=$(find / -type f \( -iname "*.db" -o -iname "*.sql" -o -iname "*.sqlite" -o -iname "*.sqlite3" \) 2>/dev/null | head -n 100)

if [ -z "$db_files" ]; then
    echo "⚠️ No .db/.sql/.sqlite/.sqlite3 files found." >> "$OUTPUT"
else
    db_found=true
    echo -e "🗂️ Found database files (limit 100):\n" >> "$OUTPUT"
    echo "$db_files" | while read -r f; do
        if [ "$FILECMD" ]; then
            file_info=$(file "$f" 2>/dev/null)
            echo "📄 $file_info" | sed -${E} "s,\.db|\.sql|\.sqlite|\.sqlite3,${SED_RED},g" >> "$OUTPUT"
        else
            echo "📄 $f" | sed -${E} "s,\.db|\.sql|\.sqlite|\.sqlite3,${SED_RED},g" >> "$OUTPUT"
        fi
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_header "SUID/SGID/Capabilities"
# SUID Check - Combined Version with Limited Deep Inspection
print_subheader "Analyzing SUID Binaries"
echo "ℹ️ Note: For detailed analysis of specific SUID binaries, you can manually run 'ldd' or 'readelf' on them."

allsuid=$(find / -perm -4000 -type f ! -path "/dev/*" 2>/dev/null)

if [ -z "$allsuid" ]; then
    echo "⚠️ No SUID binaries found." >> "$OUTPUT"
else
    echo -e "🔍 Found SUID binaries:
" >> "$OUTPUT"
    checked_count=0
    max_deep_checks=10

    echo "$allsuid" | while read -r s; do
        sname=$(basename "$s")
        ls -lah "$s" 2>/dev/null >> "$OUTPUT"

        if [ -O "$s" ]; then
            echo "🔝 Owned by current user: $s" >> "$OUTPUT"
        elif [ -w "$s" ]; then
            echo "🖍️ Writable SUID: $s" >> "$OUTPUT"
        fi

        if [ "$checked_count" -lt "$max_deep_checks" ]; then
            modifiable_path_found=false
            detailed_output=""

            if [ -x "$s" ] && command -v strings >/dev/null 2>&1; then
                strings "$s" 2>/dev/null | head -n 200 | sort -u | while read -r sline; do
                    sline_first=$(echo "$sline" | cut -d ' ' -f1)
                    if echo "$sline_first" | grep -q "/" && [ -f "$sline_first" ]; then
                        if [ -O "$sline_first" ] || [ -w "$sline_first" ]; then
                            echo "⚠️ Uses modifiable path: $sline_first (in $sname)" >> "$OUTPUT"
                            modifiable_path_found=true
                        fi
                    elif command -v "$sline_first" >/dev/null 2>&1; then
                        detailed_output+=$'\ud83d\udd27 Executes binary: '"$sline_first"' (via '"$sname"')\n'
                    fi
                done
            fi

            if [ "$modifiable_path_found" = true ]; then
                echo -e "$detailed_output" >> "$OUTPUT"
                if command -v strace >/dev/null 2>&1; then
                    echo "📱 strace output (short):" >> "$OUTPUT"
                    timeout 2 strace "$s" 2>&1 | grep -iE "open|access|no such file" | head -n 5 >> "$OUTPUT"
                fi
            fi

            checked_count=$((checked_count + 1))
        fi

        echo "" >> "$OUTPUT"
    done

    if [ "$export" ]; then
        mkdir -p "$format/suid-files" 2>/dev/null
        for i in $allsuid; do
            cp "$i" "$format/suid-files/" 2>/dev/null
        done
    fi

    if [ -n "$binarylist" ]; then
        echo -e "✨ Possibly interesting SUID binaries:
" >> "$OUTPUT"
        echo "$allsuid" | grep -w "$binarylist" | xargs -r ls -la 2>/dev/null >> "$OUTPUT"
    fi

    echo -e "🌍 World-writable SUID binaries:
" >> "$OUTPUT"
    find $allsuid -perm -4002 -type f -exec ls -la {} \; 2>/dev/null >> "$OUTPUT"

    echo -e "👑 Root-owned world-writable SUID binaries:
" >> "$OUTPUT"
    find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} \; 2>/dev/null >> "$OUTPUT"

    echo -e "\n" >> "$OUTPUT"
fi

# SGID Check - Combined Version with Limited Deep Inspection
print_subheader "Analyzing SGID Binaries"
echo "ℹ️ Note: For detailed analysis of specific SGID binaries, you can manually run 'ldd' or 'readelf' on them."

allsgid=$(find / -perm -2000 -type f ! -path "/dev/*" 2>/dev/null)

if [ -z "$allsgid" ]; then
    echo "⚠️ No SGID binaries found." >> "$OUTPUT"
else
    echo -e "🔍 Found SGID binaries:
" >> "$OUTPUT"
    checked_count=0
    max_deep_checks=10

    echo "$allsgid" | while read -r s; do
        sname=$(basename "$s")
        ls -lah "$s" 2>/dev/null >> "$OUTPUT"

        if [ -O "$s" ]; then
            echo "🔝 Owned by current user: $s" >> "$OUTPUT"
        elif [ -w "$s" ]; then
            echo "🖍️ Writable SGID: $s" >> "$OUTPUT"
        fi

        if [ "$checked_count" -lt "$max_deep_checks" ]; then
            modifiable_path_found=false
            detailed_output=""

            if [ -x "$s" ] && command -v strings >/dev/null 2>&1; then
                strings "$s" 2>/dev/null | head -n 200 | sort -u | while read -r sline; do
                    sline_first=$(echo "$sline" | cut -d ' ' -f1)
                    if echo "$sline_first" | grep -q "/" && [ -f "$sline_first" ]; then
                        if [ -O "$sline_first" ] || [ -w "$sline_first" ]; then
                            echo "⚠️ Uses modifiable path: $sline_first (in $sname)" >> "$OUTPUT"
                            modifiable_path_found=true
                        fi
                    elif command -v "$sline_first" >/dev/null 2>&1; then
                        detailed_output+=$'\ud83d\udd27 Executes binary: '"$sline_first"' (via '"$sname"')\n'
                    fi
                done
            fi

            if [ "$modifiable_path_found" = true ]; then
                echo -e "$detailed_output" >> "$OUTPUT"
                if command -v strace >/dev/null 2>&1; then
                    echo "📱 strace output (short):" >> "$OUTPUT"
                    timeout 2 strace "$s" 2>&1 | grep -iE "open|access|no such file" | head -n 5 >> "$OUTPUT"
                fi
            fi

            checked_count=$((checked_count + 1))
        fi

        echo "" >> "$OUTPUT"
    done

    if [ "$export" ]; then
        mkdir -p "$format/sgid-files" 2>/dev/null
        for i in $allsgid; do
            cp "$i" "$format/sgid-files/" 2>/dev/null
        done
    fi

    if [ -n "$binarylist" ]; then
        echo -e "✨ Possibly interesting SGID binaries:
" >> "$OUTPUT"
        echo "$allsgid" | grep -w "$binarylist" | xargs -r ls -la 2>/dev/null >> "$OUTPUT"
    fi

    echo -e "🌍 World-writable SGID binaries:
" >> "$OUTPUT"
    find $allsgid -perm -2002 -type f -exec ls -la {} \; 2>/dev/null >> "$OUTPUT"

    echo -e "👑 Root-owned world-writable SGID binaries:
" >> "$OUTPUT"
    find $allsgid -uid 0 -perm -2002 -type f -exec ls -la {} \; 2>/dev/null >> "$OUTPUT"

    echo -e "\n" >> "$OUTPUT"
fi


print_subheader "Uncommon Setuid Binaries"

# Note: These are commonly expected setuid binaries; anything else is considered uncommon
common_suid_bins=(
  "/bin/mount"
  "/bin/su"
  "/bin/umount"
  "/usr/bin/passwd"
  "/usr/bin/chsh"
  "/usr/bin/gpasswd"
  "/usr/bin/sudo"
  "/usr/bin/newgrp"
  "/usr/bin/chfn"
  "/usr/bin/at"
  "/usr/bin/crontab"
  "/usr/bin/ssh-agent"
  "/usr/lib/openssh/ssh-keysign"
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
  "/usr/lib/policykit-1/polkit-agent-helper-1"
)

# Find all setuid files
all_suid_files=$(find / -perm -4000 -type f 2>/dev/null)

# Filter out the common setuid binaries
uncommon_suid_files="$all_suid_files"
for cs in "${common_suid_bins[@]}"; do
    uncommon_suid_files=$(printf "%s\n" "$uncommon_suid_files" | grep -v -x "$cs")
done

# Output result
if [ -z "$uncommon_suid_files" ]; then
    echo "⚠️ No uncommon setuid binaries found." >> "$OUTPUT"
else
    echo -e "🔎 Uncommon setuid binaries found:\n" >> "$OUTPUT"
    echo "$uncommon_suid_files" | while read -r f; do
        ls -l "$f" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
fi

print_subheader "Checking Files with ACLs (limit 70)"

acl_found=false

if command -v getfacl >/dev/null 2>&1; then
    if [ -z "$SEARCH_IN_FOLDER" ]; then
        acl_output=$(getfacl -t -s -R -p /bin /etc "$HOMESEARCH" /opt /sbin /usr /tmp /root 2>/dev/null | head -n 70)
    else
        acl_output=$(getfacl -t -s -R -p "$SEARCH_IN_FOLDER" 2>/dev/null | head -n 70)
    fi

    if [ -n "$acl_output" ]; then
        acl_found=true
        echo -e "📂 Files with ACLs found:\n" >> "$OUTPUT"
        echo "$acl_output" >> "$OUTPUT"
        echo -e "\n" >> "$OUTPUT"
    fi
else
    echo "⚠️ getfacl command not found. Cannot check ACLs." >> "$OUTPUT"
fi

if [ "$acl_found" = false ]; then
    echo "⚠️ No files with ACLs found." >> "$OUTPUT"
fi

print_subheader "Checking Capabilities and Related Files (limit 50)"

# Current process capabilities
if command -v capsh >/dev/null 2>&1; then
    echo -e "🔍 Current shell capabilities:\n" >> "$OUTPUT"
    grep Cap /proc/$$/status | while read -r cap_line; do
        cap_name=$(echo "$cap_line" | awk '{print $1}')
        cap_value=$(echo "$cap_line" | awk '{print $2}')
        decoded=$(capsh --decode=0x"$cap_value")
        echo "$cap_name $decoded" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"

    echo -e "👨‍👧 Parent process capabilities:\n" >> "$OUTPUT"
    grep Cap /proc/$PPID/status | while read -r cap_line; do
        cap_name=$(echo "$cap_line" | awk '{print $1}')
        cap_value=$(echo "$cap_line" | awk '{print $2}')
        decoded=$(capsh --decode=0x"$cap_value")
        echo "$cap_name $decoded" >> "$OUTPUT"
    done
    echo -e "\n" >> "$OUTPUT"
else
    echo "⚠️ 'capsh' command not found. Cannot decode capabilities." >> "$OUTPUT"
    grep Cap /proc/$$/status >> "$OUTPUT"
    grep Cap /proc/$PPID/status >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# Files with capabilities (limit 50)
echo -e "📄 Files with capabilities:\n" >> "$OUTPUT"
getcap -r / 2>/dev/null | head -n 50 | while read -r cb; do
    echo "$cb" >> "$OUTPUT"
    filepath=$(echo "$cb" | cut -d" " -f1)
    if [ -w "$filepath" ]; then
        echo "⚠️ $filepath is writable by current user" >> "$OUTPUT"
    fi
    # Note: Capability vulnerability pattern checks could be added here.
done

# Users with capability rules
if [ -f "/etc/security/capability.conf" ]; then
    echo -e "👥 Users with capabilities defined in /etc/security/capability.conf:\n" >> "$OUTPUT"
    grep -vE '^#|none|^$' /etc/security/capability.conf >> "$OUTPUT"
    echo -e "\n" >> "$OUTPUT"
fi

# Note for advanced analysis
echo -e "💡 If you want more details about a capability-enabled binary, use tools like \"ldd\" or \"readelf\" manually.\n" >> "$OUTPUT"


print_header "Backup Files"

print_subheader "Backup Folder Files (Limit 70)"

# Check readable files inside temp and backup folders
echo "🔍 Scanning for readable files in /tmp, /var/tmp, /private/tmp and known backup folders..." >> "$OUTPUT"

filstmpback=$(find /tmp /var/tmp /private/tmp /private/var/at/tmp /private/var/tmp $backup_folders_row \
  -type f 2>/dev/null | grep -Ev "dpkg\.statoverride\.|dpkg\.status\.|apt\.extended_states\.|dpkg\.diversions\." | head -n 70)

if [ -n "$filstmpback" ]; then
  echo "📁 Readable files found:" >> "$OUTPUT"
  echo "$filstmpback" | while read -r f; do
    if [ -r "$f" ]; then
      ls -l "$f" 2>/dev/null >> "$OUTPUT"
    fi
  done
  echo "" >> "$OUTPUT"
else
  echo "ℹ️ No readable files found in target directories." >> "$OUTPUT"
fi

# Optional: List contents of known backup folders
if [ -n "$PSTORAGE_BACKUPS" ] || [ "$DEBUG" ]; then
  echo "📦 Known backup directories:" >> "$OUTPUT"
  echo "$PSTORAGE_BACKUPS" | while read -r b; do
    ls -ld "$b" 2>/dev/null >> "$OUTPUT"
    ls -l "$b" 2>/dev/null >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  done
fi

echo "" >> "$OUTPUT"

print_subheader "Backup File Investigation (limit 100)"

echo "📦 Searching for backup-related files in $ROOT_FOLDER..." >> "$OUTPUT"

# First method: pattern-based from ROOT_FOLDER
find "$ROOT_FOLDER" -type f \
  \( -iname "*backup*" -o -iname "*.bak" -o -iname "*.bak.*" -o -iname "*.bck" -o -iname "*.bck.*" -o -iname "*.bk" -o -iname "*.bk.*" -o -iname "*.old" -o -iname "*.old.*" \) \
  ! -path "/proc/*" 2>/dev/null | while read -r b; do
    if [ -r "$b" ]; then
      ls -l "$b" 2>/dev/null | grep -Ev "$notBackup" | grep -Ev "$notExtensions"
    fi
done | head -n 70 >> "$OUTPUT"

# Second method: regex-based backup archive search across entire system
echo "📦 Scanning system for compressed backup archives..." >> "$OUTPUT"

find / \
  \( -path /usr/lib -o -path /usr/share \) -prune -o \
  -regextype egrep \
  -iregex '.*(backup|dump|cop(y|ies)|bak|bkp)[^/]*\.(sql|tgz|tar|zip)?\.?(gz|xz|bzip2|bz2|lz|7z)?$' \
  -readable -type f -exec ls -al {} \; 2>/dev/null | head -n 30 >> "$OUTPUT"

echo "" >> "$OUTPUT"

print_subheader "Analyzing Backup Manager Files (limit 70)"

# Search for known backup manager config files
mapfile -t backup_manager_files < <(printf "%s\n" "$PSTORAGE_BACKUP_MANAGER" | grep -E "(storage\.php$|database\.php$)" | head -n 70)

if [ "${#backup_manager_files[@]}" -eq 0 ]; then
  echo "⚠️ No backup manager files like storage.php or database.php found." >> "$OUTPUT"
else
  for f in "${backup_manager_files[@]}"; do
    echo "📄 File: $f" >> "$OUTPUT"
    ls -ld "$f" 2>/dev/null >> "$OUTPUT"

    # Show potentially sensitive lines
    cat "$f" 2>/dev/null | grep -Ei "'pass'|'password'|'user'|'database'|'host'" | grep -vE "^\s*$" >> "$OUTPUT"

    echo "" >> "$OUTPUT"
  done
fi

print_subheader "Modified Interesting Files in the Last 5 Minutes (limit 100)"

modified_files=$(find "$ROOT_FOLDER" -type f -mmin -5 \
  ! -path "/proc/*" \
  ! -path "/sys/*" \
  ! -path "/run/*" \
  ! -path "/dev/*" \
  ! -path "/var/lib/*" \
  ! -path "/private/var/*" \
  2>/dev/null | grep -v "/linpeas" | head -n 100)

if [ -n "$modified_files" ]; then
  echo "📄 Files modified in the last 5 minutes:" >> "$OUTPUT"
  echo "$modified_files" >> "$OUTPUT"
else
  echo "✅ No interesting files modified in the last 5 minutes." >> "$OUTPUT"
fi

echo "" >> "$OUTPUT"

print_subheader "Hidden Files Check"

echo "📁 Searching for hidden files in '/' and '$ROOT_FOLDER' (limit 70 each)..." >> "$OUTPUT"

# 1. Global scan: hidden files under /
echo "📂 Hidden files found under '/' (limit 70):" >> "$OUTPUT"
find / -type f -name ".*" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -n 70 | while read -r f; do
  ls -l "$f" 2>/dev/null >> "$OUTPUT"
done
echo "" >> "$OUTPUT"

# 2. Targeted scan: filtered hidden files under $ROOT_FOLDER
echo "📂 Suspicious hidden files in '$ROOT_FOLDER' (limit 70):" >> "$OUTPUT"
find "$ROOT_FOLDER" -type f -iname ".*" \
  ! -path "/sys/*" ! -path "/System/*" ! -path "/private/var/*" 2>/dev/null | \
  grep -Ev "$INT_HIDDEN_FILES" | \
  grep -Ev "_history$|\.gitignore|\.npmignore|\.listing|\.ignore|\.uuid|\.depend|\.placeholder|\.gitkeep|\.keep|\.keepme|\.travis.yml" | \
  head -n 70 | while read -r f; do
    ls -l "$f" 2>/dev/null >> "$OUTPUT"
done
echo "" >> "$OUTPUT"


print_header "Containers"
print_subheader "Docker & LXC Container Checks"

# Detect if we are inside a Docker container
{
  echo "🔍 Checking for Docker container environment..."
  docker_container=$(grep -i docker /proc/self/cgroup 2>/dev/null)
  docker_env_file=$(find / -name "*dockerenv*" 2>/dev/null | xargs -r ls -la 2>/dev/null)

  if [ -n "$docker_container" ] || [ -n "$docker_env_file" ]; then
    echo "📦 This system appears to be running inside a Docker container:"
    echo "$docker_container"
    echo "$docker_env_file"
  fi

  # Check if Docker is installed (Docker host)
  docker_host_info=$(docker --version 2>/dev/null; docker ps -a 2>/dev/null)
  if [ -n "$docker_host_info" ]; then
    echo "🖥️ Docker is installed and running on this host:"
    echo "$docker_host_info"
  fi

  # Check if user is in docker group
  docker_group=$(id | grep -i docker 2>/dev/null)
  if [ -n "$docker_group" ]; then
    echo "👥 User is part of the 'docker' group (potential escalation vector):"
    echo "$docker_group"
  fi

  # Look for docker-compose.yml files
  compose_files=$(find / -name "docker-compose.yml" 2>/dev/null | xargs -r ls -l 2>/dev/null)
  if [ -n "$compose_files" ]; then
    echo "📄 docker-compose.yml file(s) found:"
    echo "$compose_files"
  fi

  echo ""
} >> "$OUTPUT"

# LXC / LXD Checks
{
  echo "🔍 Checking for LXC/LXD environment..."

  lxc_container=$(grep -qa container=lxc /proc/1/environ 2>/dev/null && echo "container=lxc detected")
  if [ -n "$lxc_container" ]; then
    echo "📦 This system appears to be running inside an LXC container:"
    echo "$lxc_container"
  fi

  lxd_group=$(id | grep -i lxd 2>/dev/null)
  if [ -n "$lxd_group" ]; then
    echo "👥 User is part of the 'lxd' group (potential escalation vector):"
    echo "$lxd_group"
  fi

  echo ""
} >> "$OUTPUT"

print_header "Passwords/Keys/Private Keys"

print_subheader "🔐 Searching for Passwords in Logs (limit 70)"

# Search log folders for likely password mentions
if [ -z "$SEARCH_IN_FOLDER" ]; then
  log_hits=$(find /var/log/ /var/logs/ /private/var/log -type f -exec grep -R -H -i "pwd\|passw" {} \; 2>/dev/null | \
             grep -vE "File does not exist:|modules-config/config-set-passwords|config-set-passwords already ran|script not found or unable to stat:|\"GET /.*\" 404" | \
             sed '/^.\{150\}./d' | sort -u | head -n 70)
  if [ -n "$log_hits" ]; then
    echo "📄 Potential password-related entries found in logs:" >> "$OUTPUT"
    echo "$log_hits" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  fi
fi

print_subheader "🔐 Searching for Password Variables in Common Folders (limit 140)"

# Search for common password variable patterns
if [ -z "$SEARCH_IN_FOLDER" ]; then
  folders="$HOMESEARCH /var/www $backup_folders_row /tmp /etc /mnt /private"
else
  folders="$SEARCH_IN_FOLDER"
fi

pwd_grep_pattern="($pwd_in_variables1|$pwd_in_variables2|$pwd_in_variables3|$pwd_in_variables4|$pwd_in_variables5|$pwd_in_variables6|$pwd_in_variables7|$pwd_in_variables8|$pwd_in_variables9|$pwd_in_variables10|$pwd_in_variables11).*[=:].+"

timeout 150 find $folders -type f -exec grep -HnRiIE "$pwd_grep_pattern" {} \; 2>/dev/null | \
  grep -vE "^#" | grep -iv "linpeas" | sed '/^.\{150\}./d' | sort -u | head -n 140 >> "$OUTPUT"

echo "" >> "$OUTPUT"

print_subheader "🔐 Searching for Passwords in Config Files"

# Look for secrets inside config files
if [ -z "$SEARCH_IN_FOLDER" ]; then
  conf_paths="$HOMESEARCH /var/www/ /usr/local/www/ /etc /opt /tmp /private /Applications /mnt"
else
  conf_paths="$SEARCH_IN_FOLDER"
fi

config_files=$(timeout 150 find $conf_paths -type f \( -name "*.conf" -o -name "*.cnf" -o -name "*.config" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" \) 2>/dev/null)

for f in $config_files; do
  if grep -qEi 'passwd.*|creden.*|^kind:\W?Secret|\Wenv:|\Wsecret:|\WsecretName:|^kind:\W?EncryptionConfiguration|\-\-encryption\-provider\-config' "$f" 2>/dev/null; then
    echo "📁 Suspicious config file: $f" >> "$OUTPUT"
    grep -HnEi 'passwd.*|creden.*|^kind:\W?Secret|\Wenv:|\Wsecret:|\WsecretName:|^kind:\W?EncryptionConfiguration|\-\-encryption\-provider\-config' "$f" 2>/dev/null >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  fi
done

print_subheader "🔐 Password Policy from /etc/login.defs"

# Extract relevant password policy configuration
logindefs=$(grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null)

if [ -n "$logindefs" ]; then
  echo "📄 Found password and storage policy details in /etc/login.defs:" >> "$OUTPUT"
  echo "$logindefs" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

print_subheader "Checking for .password-store Directory"

echo "🔍 Searching for readable .password-store directories..." >> "$OUTPUT"

mapfile -t pass_store_dirs < <(
  find / $lse_find_opts -name ".password-store" -readable -type d -print 2>/dev/null
)

if [ "${#pass_store_dirs[@]}" -gt 0 ]; then
  echo "🔐 Found .password-store directories:" >> "$OUTPUT"
  for dir in "${pass_store_dirs[@]}"; do
    ls -ld "$dir" 2>/dev/null >> "$OUTPUT"
  done
  echo "" >> "$OUTPUT"
else
  echo "ℹ️ No readable .password-store directories found." >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

print_subheader "Analyzing KeePass Files"

echo "🔍 Searching for KeePass-related files..." >> "$OUTPUT"

# Passive search using find (matches *.kdbx, case-insensitive)
mapfile -t keepass_found < <(
  find / $lse_find_opts -regextype egrep -iregex ".*\.kdbx?" -readable -type f -print 2>/dev/null | head -n 70
)

# Combine with additional known KeePass config files if provided
keepass_patterns=("*.kdbx" "KeePass.config*" "KeePass.ini" "KeePass.enforced*")
for pattern in "${keepass_patterns[@]}"; do
  mapfile -t matches < <(printf "%s\n" "$PSTORAGE_KEEPASS" | grep -E "$pattern")
  keepass_found+=("${matches[@]}")
done

# Deduplicate entries
IFS=$'\n' read -rd '' -a keepass_found <<<"$(printf '%s\n' "${keepass_found[@]}" | sort -u)"

if [ "${#keepass_found[@]}" -gt 0 ]; then
  echo "🧩 KeePass files found (limit 70):" >> "$OUTPUT"
  for f in "${keepass_found[@]:0:70}"; do
    ls -ld "$f" 2>/dev/null >> "$OUTPUT"
  done
  echo "" >> "$OUTPUT"
else
  echo "ℹ️ No KeePass-related files found." >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

print_subheader "Kerberos Configuration and Ticket Analysis"

# Auto-discover Kerberos-related files
PSTORAGE_KERBEROS=$(find / -type f \( \
    -name "*.keytab" -o \
    -name "*.ccache" -o \
    -name "*.k5login" -o \
    -name "*.krb5.conf" -o \
    -name "kadm5.acl" -o \
    -name "sssd.conf" -o \
    -name "*.secrets.mkey" -o \
    -name "secrets.ldb" \
  \) -readable 2>/dev/null)

# Detect presence of Kerberos tooling
kadmin_path=$(command -v kadmin 2>/dev/null)
klist_path=$(command -v klist 2>/dev/null)
kinit_path=$(command -v kinit 2>/dev/null)

if [ -n "$kadmin_path" ] || [ -n "$klist_path" ] || [ -n "$kinit_path" ] || [ -n "$PSTORAGE_KERBEROS" ]; then
  echo "🔍 Kerberos tools or related files detected:" >> "$OUTPUT"

  [ -n "$kadmin_path" ] && echo "kadmin: $kadmin_path" >> "$OUTPUT"
  [ -n "$klist_path" ] && echo "klist: $klist_path" >> "$OUTPUT"
  [ -n "$kinit_path" ] && echo "kinit: $kinit_path" >> "$OUTPUT"
  echo "" >> "$OUTPUT"

  # Show Kerberos-related environment variables
  (env || printenv) 2>/dev/null | grep -E "^KRB5" >> "$OUTPUT"
  echo "" >> "$OUTPUT"

  # Check ptrace protection level
  ptrace_val=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
  if [ "$ptrace_val" = "0" ]; then
    echo "ptrace protection is DISABLED (can inspect memory for tickets)" >> "$OUTPUT"
  elif [ -n "$ptrace_val" ]; then
    echo "ptrace protection is ENABLED (value = $ptrace_val)" >> "$OUTPUT"
  fi
  echo "" >> "$OUTPUT"

  # Analyze discovered Kerberos-related files
  printf "%s\n" "$PSTORAGE_KERBEROS" | while read -r f; do
    [ ! -r "$f" ] && continue
    case "$f" in
      *.k5login)
        echo "Found .k5login: $f" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        ;;
      *keytab)
        echo "Found keytab file: $f" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        klist -k "$f" 2>/dev/null >> "$OUTPUT"
        ;;
      *krb5.conf)
        echo "Found krb5.conf: $f" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        ;;
      *kadm5.acl)
        echo "Found kadm5.acl: $f" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        ;;
      *sssd.conf)
        echo "Found sssd.conf: $f" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        ;;
      *secrets.ldb)
        echo "Found secrets.ldb: $f (SSSDKCMExtractor may help)" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        ;;
      *.secrets.mkey)
        echo "Found secrets.mkey: $f (used with SSSDKCMExtractor)" >> "$OUTPUT"
        ls -l "$f" 2>/dev/null >> "$OUTPUT"
        ;;
    esac
    echo "" >> "$OUTPUT"
  done

  # Search default ticket and credential paths
  echo "Scanning default ticket/keytab paths..." >> "$OUTPUT"
  ls -l /tmp/krb5cc* /var/lib/sss/db/ccache_* /etc/opt/quest/vas/host.keytab 2>/dev/null >> "$OUTPUT"
  echo "" >> "$OUTPUT"

  # List active Kerberos tickets
  echo "Listing currently cached Kerberos tickets:" >> "$OUTPUT"
  klist 2>/dev/null >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

print_subheader "SSH and SSL Credential & Configuration Check"
echo "📌 NOTE: This scan may return a large number of private/public key files, including test, example, or development keys." >> "$OUTPUT"
echo "👉 You should manually review and filter the results to identify sensitive keys or misconfigurations relevant to production or real users." >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Locate relevant SSH configuration and control files
sshconfig=$(ls /etc/ssh/ssh_config 2>/dev/null)
hostsdenied=$(ls /etc/hosts.denied 2>/dev/null)
hostsallow=$(ls /etc/hosts.allow 2>/dev/null)

# Search for SSH agent sockets (writable or interesting)
writable_agents=$(find /tmp /etc /home -type s \( -name "agent.*" -o -name "*gpg-agent*" \) 2>/dev/null)

# Search for SSH key/config files (in known user home directories)
echo "🔐 Scanning user home directories for SSH keys:" >> "$OUTPUT"
for uhome in /root /home/*; do
  if [ -d "$uhome/.ssh" ]; then
    find "$uhome/.ssh" -type f -name "id_*" -o -name "*.pub" -o -name "authorized_keys" -o -name "known_hosts" 2>/dev/null | while read -r f; do
      ls -ld "$f" 2>/dev/null >> "$OUTPUT"
    done
  fi
  echo "" >> "$OUTPUT"
done

# Check SSH daemon configuration for potentially dangerous options
echo "⚙️ Reviewing SSH daemon configuration (/etc/ssh/sshd_config):" >> "$OUTPUT"
grep -E "PermitRootLogin|ChallengeResponseAuthentication|PasswordAuthentication|UsePAM|PermitEmptyPasswords|PubkeyAuthentication|ListenAddress|Port|AllowAgentForwarding|ForwardAgent|AuthorizedKeysFiles" /etc/ssh/sshd_config 2>/dev/null | grep -v "#" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Search for private SSH/SSL key files by name only (optimized)
echo "🔑 Scanning for likely private SSH/SSL key files (locations only):" >> "$OUTPUT"
find /etc /root /mnt /home -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" \) -readable 2>/dev/null | while read -r key; do
  echo "$key" >> "$OUTPUT"
done

echo "" >> "$OUTPUT"

# Certificates (already discovered by PSTORAGE if populated)
if [ -n "$certsb4_grep" ] || [ -n "$PSTORAGE_CERTSBIN" ]; then
  echo "📜 Certificate files found:" >> "$OUTPUT"
  printf "%s\n" "$certsb4_grep" "$PSTORAGE_CERTSBIN" | head -n 20 >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

# Client certs
if [ "$PSTORAGE_CERTSCLIENT" ]; then
  echo "📎 Client certificates:" >> "$OUTPUT"
  printf "%s\n" "$PSTORAGE_CERTSCLIENT" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

# SSH Agent and GPG cached keys
if [ "$PSTORAGE_SSH_AGENTS" ]; then
  echo "📎 SSH Agent files found:" >> "$OUTPUT"
  printf "%s\n" "$PSTORAGE_SSH_AGENTS" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

if ssh-add -l 2>/dev/null | grep -qv 'no identities'; then
  echo "🗝️ SSH agent identities available:" >> "$OUTPUT"
  ssh-add -l >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

if gpg-connect-agent "keyinfo --list" /bye 2>/dev/null | grep -q "D - - 1"; then
  echo "🔐 GPG keys cached in gpg-agent:" >> "$OUTPUT"
  gpg-connect-agent "keyinfo --list" /bye >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

if [ "$writable_agents" ]; then
  echo "✏️ Writable SSH/GPG agent sockets found:" >> "$OUTPUT"
  printf "%s\n" "$writable_agents" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

if [ "$PSTORAGE_SSH_CONFIG" ]; then
  echo "🧩 User SSH config files:" >> "$OUTPUT"
  printf "%s\n" "$PSTORAGE_SSH_CONFIG" | while read -r f; do
    ls "$f" 2>/dev/null >> "$OUTPUT"
  done
  echo "" >> "$OUTPUT"
fi

# Hosts allow/deny checks
if [ "$hostsdenied" ]; then
  echo "🚫 /etc/hosts.denied rules:" >> "$OUTPUT"
  cat "$hostsdenied" 2>/dev/null | grep -v "^#" | grep -Ev "^\s*$" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

if [ "$hostsallow" ]; then
  echo "✅ /etc/hosts.allow rules:" >> "$OUTPUT"
  cat "$hostsallow" 2>/dev/null | grep -v "^#" | grep -Ev "^\s*$" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

# SSH client config
if [ "$sshconfig" ]; then
  echo "🔍 /etc/ssh/ssh_config entries:" >> "$OUTPUT"
  grep -v "^#" "$sshconfig" 2>/dev/null | grep -Ev "^\s*$" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

print_subheader "PGP / GPG Credential and Configuration Check"

# Check for gpg/netpgp tools
{
  echo "🔑 Checking for GPG/PGP tools:" 
  if command -v gpg >/dev/null 2>&1; then
    echo "✔️ gpg found: $(command -v gpg)"
    gpg --list-keys 2>/dev/null | head -n 20
  else
    echo "❌ gpg not found"
  fi

  if command -v netpgpkeys >/dev/null 2>&1; then
    echo "✔️ netpgpkeys found: $(command -v netpgpkeys)"
    netpgpkeys --list-keys 2>/dev/null | head -n 20
  else
    echo "❌ netpgpkeys not found"
  fi

  if command -v netpgp >/dev/null 2>&1; then
    echo "✔️ netpgp found: $(command -v netpgp)"
  else
    echo "❌ netpgp not found"
  fi
} >> "$OUTPUT"

# Search for .gpg, .pgp, and .gnupg files (limit results)
echo -e "\n📦 Searching for PGP/GPG-related files (limit 70):" >> "$OUTPUT"
find / -type f \( -iname "*.gpg" -o -iname "*.pgp" \) -readable -not -path "/proc/*" 2>/dev/null | head -n 70 | while read -r f; do
  ls -ld "$f" 2>/dev/null >> "$OUTPUT"
done

# Also include .gnupg directories
find / -type d -iname ".gnupg" -readable -not -path "/proc/*" 2>/dev/null | head -n 10 | while read -r d; do
  echo "📂 Found GnuPG config directory: $d" >> "$OUTPUT"
  ls -ld "$d" 2>/dev/null >> "$OUTPUT"
done

echo "" >> "$OUTPUT"

print_subheader "API Key Detection"

if [ "$REGEXES" ] && [ "$TIMEOUT" ]; then
  # Add commonly used API key regexes
  search_for_regex "Generic API Key (hex/64)" "[A-Za-z0-9_]{32,64}"
  search_for_regex "Google API Key" "AIza[0-9A-Za-z\-_]{35}"
  search_for_regex "AWS Access Key ID" "AKIA[0-9A-Z]{16}"
  search_for_regex "AWS Secret Access Key" "([a-zA-Z0-9/+=]{40})"
  search_for_regex "Slack Token" "xox[baprs]-([0-9a-zA-Z]{10,48})?"
  search_for_regex "Stripe API Key" "sk_live_[0-9a-zA-Z]{24}"
  search_for_regex "GitHub Token" "gh[pousr]_[A-Za-z0-9_]{36,255}"
  search_for_regex "Heroku API Key" "[hH]eroku[a-zA-Z0-9]{32}"
  search_for_regex "Twilio API Key" "SK[0-9a-fA-F]{32}"
  search_for_regex "Mailgun API Key" "key-[0-9a-zA-Z]{32}"

  # Extended: Add hundreds more regexes
  search_for_regex "Adobe Client Id (Oauth Web)" "(adobe[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]" 1
  search_for_regex "Abode Client Secret" "(p8e-)[a-z0-9]{32}" 1
  search_for_regex "Age Secret Key" "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"
  search_for_regex "Airtable API Key" "[\"']?air[-_]?table[-_]?api[-_]?key[\"']?[=:][\"']?.+[\"']"
  search_for_regex "Alchemi API Key" "(alchemi[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-zA-Z0-9-]{32})['\"]" 1
  search_for_regex "Alibaba Access Key ID" "(LTAI)[a-z0-9]{20}" 1
  search_for_regex "Alibaba Secret Key" "(alibaba[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]" 1
  search_for_regex "AWS Client ID" "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
  search_for_regex "AWS MWS Key" "amzn\.mws\.[0-9a-f\-]{36}"
  search_for_regex "AWS Secret Key" "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]"
  search_for_regex "AWS AppSync GraphQL Key" "da2-[a-z0-9]{26}"
  search_for_regex "Facebook Access Token" "EAACEdEose0cBA[0-9A-Za-z]+"
  search_for_regex "Github OAuth Access Token" "gho_[0-9a-zA-Z]{36}"
  search_for_regex "Gitlab Personal Access Token" "glpat-[0-9a-zA-Z\-]{20}"
  search_for_regex "Google Cloud Platform API Key" "(google|gcp|youtube|drive|yt)(.{0,20})?['\"]AIza[0-9a-z_\-]{35}['\"]"
  search_for_regex "JSON Web Token" "(ey[0-9a-z]{30,34}\.ey[0-9a-z/_\-]{30,}\.[0-9a-zA-Z/_\-]{10,}={0,2})"
  search_for_regex "Private Keys" "\-\-\-\-\-BEGIN (RSA |OPENSSH |PGP )?PRIVATE KEY\-\-\-\-\-"

  echo ''
fi

# Additional passive AWS key presence scan (non-regex based)
print_subheader "Passive AWS Key Search in /home Directory"
echo "📌 NOTE: This passive scan searches for known AWS credential keywords in user home directories." >> "$OUTPUT"
echo "🔍 May catch hardcoded keys in config or code, requires manual validation." >> "$OUTPUT"
echo "" >> "$OUTPUT"

awskeyfiles=$(grep -rli "aws_secret_access_key" /home 2>/dev/null)
if [ -n "$awskeyfiles" ]; then
  echo "⚠️ AWS key references found in the following files:" >> "$OUTPUT"
  echo "$awskeyfiles" >> "$OUTPUT"
  echo '' >> "$OUTPUT"
fi


print_header "Other Interesting Findings"

print_subheader "Shell Scripts (.sh) Found in PATH"
echo "" >> "$OUTPUT"

echo "$PATH" | tr ":" "\n" | while read -r d; do
  [ -d "$d" ] || continue
  find "$d" -type f \( -name "*.sh" -o -name "*.sh.*" \) 2>/dev/null | while read -r f; do
    if [ -O "$f" ]; then
      echo "🔴 Owned by current user: $f" >> "$OUTPUT"
    elif [ -w "$f" ]; then
      echo "🟡 Writable by current user: $f" >> "$OUTPUT"
    else
      echo "🟢 Found: $f" >> "$OUTPUT"
    fi
  done
done
echo "" >> "$OUTPUT"

print_subheader "Unexpected Files or Directories in / (root)"
echo "" >> "$OUTPUT"

if [ "$MACPEAS" ]; then
  unexpected_root=$(find "$ROOT_FOLDER" -maxdepth 1 | grep -Ev "$commonrootdirsMacG")
else
  unexpected_root=$(find "$ROOT_FOLDER" -maxdepth 1 | grep -Ev "$commonrootdirsG")
fi

if [ -n "$unexpected_root" ]; then
  echo "$unexpected_root" | while read -r entry; do
    echo "🔴 Unexpected: $entry" >> "$OUTPUT"
  done
else
  echo "✅ No unexpected files or directories in / detected." >> "$OUTPUT"
fi

echo "" >> "$OUTPUT"

print_subheader "Mailboxes in /var/mail"
echo "" >> "$OUTPUT"

readmail=$(ls -la /var/mail 2>/dev/null)
if [ -n "$readmail" ]; then
  echo "📬 Mail directory contents:" >> "$OUTPUT"
  echo "$readmail" >> "$OUTPUT"
else
  echo "✅ No accessible mailboxes found in /var/mail." >> "$OUTPUT"
fi

echo "" >> "$OUTPUT"
