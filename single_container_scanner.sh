#!/bin/bash
# 单容器安全扫描脚本
# 用于对单个容器执行详细的安全检查
# 可通过nsenter注入执行或直接在容器内执行

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 扫描结果统计
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0

# 清理标记
NEED_CLEANUP=false

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $1" >> /tmp/container_scan_detail.log
}
log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> /tmp/container_scan_detail.log
}
log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> /tmp/container_scan_detail.log
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}
log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> /tmp/container_scan_detail.log
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}
log_cmd() {
    echo -e "${CYAN}[CMD]${NC} $1"
    echo "[CMD] $1" >> /tmp/container_scan_detail.log
}
log_result() {
    echo -e "  ${CYAN}→ 结果:${NC} $1"
    echo "  → 结果: $1" >> /tmp/container_scan_detail.log
}
log_detail() {
    echo -e "    ${CYAN}$1${NC}"
    echo "    $1" >> /tmp/container_scan_detail.log
}

# ==================== 主扫描函数 ====================
main_scan() {
    echo "=========================================="
    echo "单容器安全扫描"
    echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
    # 使用多种方式获取主机名
    local hostname_val=""
    if command -v hostname >/dev/null 2>&1; then
        hostname_val=$(hostname 2>/dev/null)
    elif [ -f /etc/hostname ]; then
        hostname_val=$(cat /etc/hostname 2>/dev/null)
    else
        hostname_val=$(uname -n 2>/dev/null)
    fi
    echo "主机名: $hostname_val"
    echo "=========================================="

    # ==================== 1. 系统信息收集 ====================
    echo ""
    echo "--- 1. 系统信息收集 ---"
    log_cmd "uname -a"
    log_result "$(uname -a)"

    log_cmd "cat /etc/os-release"
    if [ -f /etc/os-release ]; then
        cat /etc/os-release 2>/dev/null | head -5 | while read line; do
            log_detail "$line"
        done
    else
        log_detail "/etc/os-release 不存在"
    fi

    # ==================== 2. 包管理器检测与工具安装 ====================
    echo ""
    echo "--- 2. 包管理器检测与工具安装 ---"

    log_cmd "检测包管理器并安装工具"
    if command -v apt >/dev/null 2>&1; then
        log_result "检测到 apt 包管理器"
        log_cmd "apt update && apt install -y net-tools findutils procps jq nmap openssl"
        apt update -qq && apt install -y -qq net-tools findutils procps jq nmap openssl 2>/dev/null
        NEED_CLEANUP=true
    elif command -v yum >/dev/null 2>&1; then
        log_result "检测到 yum 包管理器"
        log_cmd "yum install -y net-tools findutils procps-ng jq nmap openssl"
        yum install -y -q net-tools findutils procps-ng jq nmap openssl 2>/dev/null
        NEED_CLEANUP=true
    elif command -v apk >/dev/null 2>&1; then
        log_result "检测到 apk 包管理器"
        log_cmd "apk add --no-cache net-tools findutils procps jq nmap openssl"
        apk add --no-cache net-tools findutils procps jq nmap openssl 2>/dev/null
        NEED_CLEANUP=true
    else
        log_warning "未知包管理器，无法安装工具"
    fi

    # 安装jq(如果不存在)
    if ! command -v jq &>/dev/null; then
        log_info "安装 jq 工具..."
        local arch=$(uname -m)
        local jq_url="https://gitee.com/opensourceway/sec_efficiency_tool/releases/download/1.0.0/jq-linux-amd64"

        if [[ "$arch" == "aarch64" || "$arch" == arm* ]]; then
            jq_url="https://gitee.com/opensourceway/sec_efficiency_tool/releases/download/1.0.0/jq-linux-arm64"
        fi

        curl -sL "$jq_url" -o /tmp/jq && chmod +x /tmp/jq && mv /tmp/jq /usr/bin/jq
        log_success "jq 安装完成: $(jq --version 2>/dev/null || echo 'unknown')"
    else
        log_success "jq 已安装: $(jq --version 2>/dev/null || echo 'installed')"
    fi

    # ==================== 3. umask检查 ====================
    echo ""
    echo "--- 3. umask 安全检查 ---"
    log_cmd "umask"
    local UMASK_VAL=$(umask)
    log_result "当前 umask: $UMASK_VAL"

    if [ "$UMASK_VAL" != "0027" ]; then
        log_warning "非标准 umask 设置: $UMASK_VAL"
        log_detail "建议: 设置 umask 为 0027 以限制默认文件权限"
        log_detail "影响: 当前创建的文件可能对其他用户可读"
    else
        log_success "umask 设置正确: $UMASK_VAL"
    fi

    # ==================== 4. 挂载目录检查 ====================
    echo ""
    echo "--- 4. 挂载目录检查 ---"
    log_cmd "df -h"
    df -h

    # 忽略的挂载点
    local EXCLUDES=("/" "/dev" "/sys/fs/cgroup" "/etc/hosts" "/dev/shm" "/proc/acpi" "/proc/scsi" "/sys/firmware")

    # 获取挂载点列表
    local MOUNTS=$(df -h | awk 'NR>1 {print $6}' | sort -u)

    log_info "检查挂载目录安全性..."
    for mount in $MOUNTS; do
        local skip=false
        for exclude in "${EXCLUDES[@]}"; do
            if [[ "$mount" == "$exclude" ]]; then
                skip=true
                break
            fi
        done

        if ! $skip; then
            # 检查目录是否非空
            if [ -d "$mount" ] && [ "$(ls -A "$mount" 2>/dev/null)" ]; then
                log_warning "挂载目录非空: $mount"
                ls -la "$mount" 2>/dev/null | head -5 | while read line; do
                    log_detail "$line"
                done
            fi

            # 检查是否挂载k8s token
            if [ "$mount" = "/run/secrets/kubernetes.io/serviceaccount" ]; then
                log_error "检测到挂载 Kubernetes ServiceAccount Token: $mount"
                log_detail "风险: 可能导致集群权限泄露"
            fi
        fi
    done

    # ==================== 5. 敏感文件与权限检查 ====================
    echo ""
    echo "--- 5. 敏感文件与权限检查 ---"

    local SCAN_PATHS=("/opt" "/opt/app" "/home" "/etc/nginx/cert" "/etc/nginx" "/var/log" "/var/www" "/app" "/data")
    local IGNORE_PATHS=("/opt" "/home" "/var/log")

    for path in "${SCAN_PATHS[@]}"; do
        if [ ! -d "$path" ]; then
            continue
        fi

        log_info "扫描路径: $path"
        log_cmd "ls -la $path"
        ls -la "$path" 2>/dev/null | head -10 | while read line; do
            log_detail "$line"
        done

        # 检查敏感文件
        log_cmd "find $path -type f \\( -name '*.key' -o -name '*.pem' -o -name '*application.yml' -o -name '*application.yaml' \\)"
        find "$path" -type f \( -name '*.key' -o -name '*.pem' -o -name '*application.yml' -o -name '*application.yaml' \) 2>/dev/null | head -10 | while read file; do
            if [ -n "$file" ]; then
                log_warning "检测到敏感文件: $file"
                local perms=$(ls -la "$file" 2>/dev/null | awk '{print $1, $3, $4}')
                log_detail "权限: $perms"
            fi
        done

        # 检查其他用户可写的文件
        log_cmd "find $path -type f -perm /007"
        find "$path" -type f -perm /007 2>/dev/null | head -10 | while read file; do
            if [ -n "$file" ]; then
                # 检查是否在忽略列表
                local skip_file=false
                for ignore in "${IGNORE_PATHS[@]}"; do
                    if [[ "$file" == "$ignore"* ]]; then
                        skip_file=true
                        break
                    fi
                done

                if ! $skip_file; then
                    log_warning "其他用户可写文件: $file"
                    local perms=$(ls -la "$file" 2>/dev/null | awk '{print $1, $3, $4}')
                    log_detail "权限: $perms"
                fi
            fi
        done
    done

    # ==================== 6. History配置检查 ====================
    echo ""
    echo "--- 6. History 配置检查 ---"
    log_cmd "检查 /etc/bashrc /etc/profile /root/.bashrc"

    local files="/etc/bashrc /etc/profile /root/.bashrc"
    local found_history_disable=false

    for f in $files; do
        if [ -f "$f" ]; then
            log_detail "检查文件: $f"
            if grep -q 'set +o history' "$f" 2>/dev/null; then
                log_success "发现 'set +o history' 在 $f，历史功能已禁用"
                found_history_disable=true
            fi
            if grep -q 'HISTSIZE=0' "$f" 2>/dev/null; then
                log_success "发现 'HISTSIZE=0' 在 $f，历史记录已禁用"
                found_history_disable=true
            fi
        fi
    done

    if [ "$found_history_disable" = false ]; then
        log_warning "未发现历史记录禁用配置"
        log_detail "建议: 添加 'set +o history' 或 'HISTSIZE=0' 以禁用历史记录"
    fi

    # ==================== 7. 进程安全检查 ====================
    echo ""
    echo "--- 7. 进程安全检查 ---"
    log_cmd "ps -eo pid,ppid,user,comm --sort=pid | head -n 50"

    local TOP_OUT=$(ps -eo pid,ppid,user,comm --sort=pid | head -n 50)
    echo "$TOP_OUT"

    echo "$TOP_OUT" | tail -n +2 | while read -r pid ppid user cmd; do
        # 检查PID为1的进程
        if [[ "$pid" == "1" ]]; then
            if [[ "$user" == "root" ]]; then
                log_warning "PID 1 (init进程) 以 root 用户运行"
            else
                log_success "PID 1 以非root用户运行: $user"
            fi
        fi

        # 检查PPID为1的进程
        if [[ "$ppid" == "1" ]] && [[ "$pid" != "1" ]]; then
            if [[ "$user" == "root" ]]; then
                log_warning "进程 $pid ($cmd) 父进程为init，以root运行"
            fi
        fi
    done

    # ==================== 8. 环境变量与敏感信息检查 ====================
    echo ""
    echo "--- 8. 环境变量与敏感信息检查 ---"
    log_cmd "env | grep -iE '(password|secret|token|key|api)'"

    # 检查环境变量中的敏感信息
    local env_output=$(env 2>/dev/null)
    local sensitive_patterns="password passwd secret api_key token private_key access_key secret_key credential auth"

    for pattern in $sensitive_patterns; do
        local found=$(echo "$env_output" | grep -i "$pattern" 2>/dev/null)
        if [ -n "$found" ]; then
            log_warning "环境变量中发现敏感关键字: $pattern"
            echo "$found" | while read line; do
                # 隐藏部分内容
                local masked=$(echo "$line" | sed 's/=.*/=***/')
                log_detail "$masked"
            done
        fi
    done

    # 使用gitleaks扫描
    log_info "使用 Gitleaks 扫描敏感信息..."
    local TMPDIR=$(mktemp -d)
    cd "$TMPDIR"

    # 下载并安装gitleaks
    local arch=$(uname -m)
    local GITLEAKS_URL="https://gitee.com/opensourceway/sec_efficiency_tool/releases/download/1.0.0/gitleaks_8.27.0_linux_x64.tar.gz"

    if [[ "$arch" == "aarch64" || "$arch" == arm* ]]; then
        GITLEAKS_URL="https://gitee.com/opensourceway/sec_efficiency_tool/releases/download/1.0.0/gitleaks_8.27.2_linux_arm64.tar.gz"
    fi

    log_cmd "curl -sL $GITLEAKS_URL"
    curl -sL "$GITLEAKS_URL" -o gitleaks.tar.gz 2>/dev/null
    tar -xzf gitleaks.tar.gz gitleaks 2>/dev/null
    chmod +x gitleaks 2>/dev/null

    if [ -x ./gitleaks ]; then
        # 扫描环境变量
        env > /tmp/env_check.txt
        log_cmd "./gitleaks dir /tmp/env_check.txt --report-format=json"
        ./gitleaks dir /tmp/env_check.txt --report-format=json --report-path=/tmp/gitleaks_env_report.json --no-git 2>/dev/null

        if [ -f /tmp/gitleaks_env_report.json ] && [ -s /tmp/gitleaks_env_report.json ]; then
            local leaks=$(cat /tmp/gitleaks_env_report.json | jq -r '.[] | .Description' 2>/dev/null)
            if [ -n "$leaks" ]; then
                log_warning "Gitleaks 发现敏感信息泄露:"
                echo "$leaks" | while read line; do
                    [ -n "$line" ] && log_detail "$line"
                done
            fi
        fi
    fi

    cd /
    rm -rf "$TMPDIR" /tmp/env_check.txt

    # ==================== 9. Sudo权限检查 ====================
    echo ""
    echo "--- 9. Sudo 权限检查 ---"
    log_cmd "which sudo"
    if which sudo >/dev/null 2>&1; then
        log_warning "sudo 已安装"

        # 检查sudoers配置
        log_cmd "cat /etc/sudoers | grep -vE '^#|^$'"
        if [ -f /etc/sudoers ]; then
            grep -vE '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | while read line; do
                log_detail "$line"
            done
        fi

        # 检查NOPASSWD配置
        log_cmd "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d"
        grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | while read line; do
            log_detail "$line"
        done

        # 检查sudo/wheel组成员
        log_cmd "getent group sudo wheel"
        getent group sudo wheel 2>/dev/null | while read line; do
            log_detail "$line"
        done
    else
        log_success "sudo 未安装"
    fi

    # ==================== 10. PATH安全性检查 ====================
    echo ""
    echo "--- 10. PATH 安全性检查 ---"
    log_cmd "echo \$PATH"
    log_result "$PATH"

    IFS=':' read -r -a path_dirs <<< "$PATH"

    for dir in "${path_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            log_detail "PATH目录不存在: $dir"
            continue
        fi

        # 检查目录中的可写文件
        find "$dir" -maxdepth 1 -type f -executable 2>/dev/null | while read file; do
            if [ -f "$file" ]; then
                local perms=$(stat -c "%A" "$file" 2>/dev/null)
                local owner=$(stat -c "%U" "$file" 2>/dev/null)

                # 检查其他用户写权限
                local other_writable=${perms:8:1}
                local group_writable=${perms:5:1}

                if [[ "$other_writable" == "w" ]]; then
                    log_error "文件对其他用户可写: $file"
                    log_detail "权限: $perms 所有者: $owner"
                elif [[ "$group_writable" == "w" ]]; then
                    log_warning "文件对组可写: $file"
                    log_detail "权限: $perms 所有者: $owner"
                fi
            fi
        done
    done

    log_success "PATH 检查完成"

    # ==================== 11. 网络端口与SSL检查 ====================
    echo ""
    echo "--- 11. 网络端口与 SSL 检查 ---"
    log_cmd "netstat -tunlp || ss -tunlp"

    local NETSTAT_OUTPUT=$(netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null)
    echo "$NETSTAT_OUTPUT"

    # 创建nmap扫描结果目录
    local NMAP_DIR="/tmp/nmap_scan_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$NMAP_DIR"
    log_info "Nmap扫描结果保存目录: $NMAP_DIR"

    # 收集需要扫描的SSL端口
    local SSL_PORTS=""

    echo "$NETSTAT_OUTPUT" | while read -r line; do
        # 跳过标题行
        if [[ "$line" == Proto* ]] || [[ "$line" == Active* ]] || [[ "$line" == Netid* ]]; then
            continue
        fi

        # 解析端口信息
        set -- $line
        local ADDR_PORT="${4:-}"
        local PID_FIELD="${7:-}"

        [ -z "$ADDR_PORT" ] && continue

        # 解析IP和端口
        local IP="${ADDR_PORT%:*}"
        local PORT="${ADDR_PORT##*:}"
        [ -z "$IP" ] && IP="0.0.0.0"

        log_info "检测端口: $IP:$PORT (进程: ${PID_FIELD:-unknown})"

        # 检查绑定地址
        if [[ "$IP" == "0.0.0.0" ]] || [[ "$IP" == "::" ]] || [[ "$IP" == "*" ]]; then
            log_warning "绑定到任意地址 (0.0.0.0/::)"
        else
            log_success "绑定到特定地址: $IP"
        fi

        # SSL探测 (仅对常见HTTPS端口)
        if [[ "$PORT" == "443" ]] || [[ "$PORT" == "8443" ]] || [[ "$PORT" == "9443" ]] || [[ "$PORT" == "8080" ]]; then
            log_cmd "timeout 3 openssl s_client -connect $IP:$PORT"

            local tmpfileSSL=$(mktemp)
            timeout 3 bash -c "echo | openssl s_client -connect $IP:$PORT" > "$tmpfileSSL" 2>/dev/null

            if grep -q "CONNECTED" "$tmpfileSSL"; then
                log_success "SSL 已启用"

                # 提取协议和加密套件
                grep "New," "$tmpfileSSL" | head -1 | while read ssl_line; do
                    log_detail "$ssl_line"
                done

                # 检查证书信息
                openssl x509 -noout -dates -subject < "$tmpfileSSL" 2>/dev/null | while read cert_line; do
                    log_detail "证书: $cert_line"
                done

                # 添加到SSL端口列表用于nmap扫描
                SSL_PORTS="$SSL_PORTS $PORT"
            else
                log_detail "未检测到SSL"
            fi
            rm -f "$tmpfileSSL"
        fi
    done

    # ==================== 11.1 Nmap SSL加密套件检查 ====================
    echo ""
    echo "--- 11.1 Nmap SSL 加密套件检查 ---"

    if command -v nmap >/dev/null 2>&1; then
        # 从netstat获取监听端口进行SSL扫描
        local LISTEN_IPS=$(echo "$NETSTAT_OUTPUT" | grep LISTEN | awk '{print $4}' | cut -d: -f1 | sort -u | head -5)
        local LISTEN_PORTS=$(echo "$NETSTAT_OUTPUT" | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -nu | head -10)

        for ip in $LISTEN_IPS; do
            [ -z "$ip" ] && ip="127.0.0.1"
            [ "$ip" = "0.0.0.0" ] && ip="127.0.0.1"
            [ "$ip" = "::" ] && ip="::1"

            for port in $LISTEN_PORTS; do
                [ -z "$port" ] && continue

                log_cmd "nmap --script ssl-enum-ciphers -p $port $ip" "扫描SSL加密套件"

                local nmap_ssl_file="$NMAP_DIR/ssl_ciphers_${ip}_${port}"
                nmap --script ssl-enum-ciphers -p "$port" "$ip" > "$nmap_ssl_file" 2>/dev/null

                if [ -f "$nmap_ssl_file" ] && [ -s "$nmap_ssl_file" ]; then
                    log_detail "结果已保存: $nmap_ssl_file"

                    # 分析加密套件安全性
                    if grep -qE "SSLv2|SSLv3|TLSv1.0|TLSv1.1" "$nmap_ssl_file"; then
                        log_error "发现不安全的SSL/TLS协议版本"
                        grep -E "SSLv2|SSLv3|TLSv1.0|TLSv1.1" "$nmap_ssl_file" | while read line; do
                            log_detail "$line"
                        done
                    fi

                    if grep -qE "RC2|RC4|DES|3DES|MD5|NULL|EXPORT|ANON|ADH|AECDH" "$nmap_ssl_file"; then
                        log_error "发现弱加密套件"
                        grep -E "RC2|RC4|DES|3DES|MD5|NULL|EXPORT|ANON|ADH|AECDH" "$nmap_ssl_file" | head -10 | while read line; do
                            log_detail "$line"
                        done
                    fi

                    if grep -q "compressors:\s*DEFLATE" "$nmap_ssl_file"; then
                        log_warning "启用了压缩(可能存在CRIME攻击风险)"
                    fi
                fi
            done
        done
    else
        log_warning "nmap 未安装，跳过SSL加密套件检查"
    fi

    # ==================== 12. Nmap端口扫描 ====================
    echo ""
    echo "--- 12. Nmap 端口深度扫描 ---"

    if command -v nmap >/dev/null 2>&1; then
        log_info "开始Nmap端口扫描(结果保存到 $NMAP_DIR)..."

        # 扫描目标
        local SCAN_TARGET="127.0.0.1"

        # 1. TCP指定端口扫描(21,23)
        echo ""
        log_cmd "nmap -sS -p 21,23 -A -v3 -n -oA $NMAP_DIR/tcp_2_ports --max-scan-delay 10 -Pn --reason $SCAN_TARGET"
        log_info "扫描TCP端口 21,23..."
        nmap -sS -p 21,23 -A -v3 -n -oA "$NMAP_DIR/tcp_2_ports" --max-scan-delay 10 -Pn --reason "$SCAN_TARGET" 2>/dev/null

        if [ -f "$NMAP_DIR/tcp_2_ports.nmap" ]; then
            log_success "TCP 21,23端口扫描完成"
            log_detail "结果文件: $NMAP_DIR/tcp_2_ports.nmap"

            # 显示关键发现
            if grep -qi "open" "$NMAP_DIR/tcp_2_ports.nmap"; then
                log_warning "发现开放端口:"
                grep -i "open" "$NMAP_DIR/tcp_2_ports.nmap" | head -5 | while read line; do
                    log_detail "$line"
                done
            fi
        fi

        # 2. TCP全端口扫描
        echo ""
        log_cmd "nmap -sS -p- -A -v3 -n -oA $NMAP_DIR/tcp -Pn --reason $SCAN_TARGET"
        log_info "扫描TCP全端口(可能需要较长时间)..."
        nmap -sS -p- -A -v3 -n -oA "$NMAP_DIR/tcp" -Pn --reason "$SCAN_TARGET" 2>/dev/null

        if [ -f "$NMAP_DIR/tcp.nmap" ]; then
            log_success "TCP全端口扫描完成"
            log_detail "结果文件: $NMAP_DIR/tcp.nmap"

            # 统计开放端口
            local open_ports=$(grep -c "open" "$NMAP_DIR/tcp.nmap" 2>/dev/null || echo "0")
            log_result "发现 $open_ports 个开放端口"

            if [ "$open_ports" -gt "0" ]; then
                grep "open" "$NMAP_DIR/tcp.nmap" | head -10 | while read line; do
                    log_detail "$line"
                done
            fi
        fi

        # 3. UDP全端口扫描
        echo ""
        log_cmd "nmap -sU -p- -A -v3 -n -oA $NMAP_DIR/udp --max-scan-delay 10 -Pn --reason $SCAN_TARGET"
        log_info "扫描UDP全端口(可能需要较长时间)..."
        nmap -sU -p- -A -v3 -n -oA "$NMAP_DIR/udp" --max-scan-delay 10 -Pn --reason "$SCAN_TARGET" 2>/dev/null

        if [ -f "$NMAP_DIR/udp.nmap" ]; then
            log_success "UDP全端口扫描完成"
            log_detail "结果文件: $NMAP_DIR/udp.nmap"

            # 统计开放端口
            local open_udp=$(grep -c "open\|open\|filtered" "$NMAP_DIR/udp.nmap" 2>/dev/null || echo "0")
            log_result "发现 $open_udp 个开放/过滤的UDP端口"
        fi

        # 汇总nmap扫描结果
        echo ""
        log_info "=== Nmap扫描结果汇总 ==="
        echo ""
        echo "扫描结果文件:"
        ls -la "$NMAP_DIR" 2>/dev/null | grep -E "\.nmap|\.xml|\.gnmap" | while read line; do
            log_detail "$line"
        done

        log_info "Nmap扫描结果目录: $NMAP_DIR"

    else
        log_warning "nmap 未安装，跳过端口深度扫描"
    fi

    # ==================== 13. 调试工具检查 ====================
    echo ""
    echo "--- 13. 调试工具检查 ---"
    log_cmd "find / -type f \\( -name 'tcpdump' -o -name 'gdb' -o -name 'strace' -o -name 'nc' -o -name 'nmap' -o -name 'wireshark' \\)"

    local DEBUG_TOOLS=$(find / -type f \( -name 'tcpdump' -o -name 'gdb' -o -name 'strace' -o -name 'nc' -o -name 'nmap' -o -name 'wireshark' -o -name 'netcat' \) 2>/dev/null | grep -v '/nmap/rpc\|/locale')

    if [ -n "$DEBUG_TOOLS" ]; then
        log_warning "检测到调试工具:"
        echo "$DEBUG_TOOLS" | while read tool; do
            [ -n "$tool" ] && log_detail "$tool"
        done
    else
        log_success "未发现调试工具"
    fi

    # ==================== 清理安装的工具 ====================
    echo ""
    echo "--- 清理临时安装的工具 ---"
    if [ "$NEED_CLEANUP" = true ]; then
        log_cmd "卸载临时安装的工具"
        if command -v apt >/dev/null 2>&1; then
            apt remove -y -qq net-tools findutils procps jq nmap openssl 2>/dev/null
        elif command -v yum >/dev/null 2>&1; then
            yum remove -y -q net-tools findutils procps-ng jq nmap openssl 2>/dev/null
        elif command -v apk >/dev/null 2>&1; then
            apk del --no-cache net-tools findutils procps jq nmap openssl 2>/dev/null
        fi
        log_success "临时工具已清理"
    else
        log_info "无需清理临时工具"
    fi

    # ==================== 扫描结果汇总 ====================
    echo ""
    echo "=========================================="
    echo "扫描结果汇总"
    echo "=========================================="
    echo -e "${RED}严重问题: $HIGH_ISSUES${NC}"
    echo -e "${YELLOW}中危问题: $MEDIUM_ISSUES${NC}"
    echo -e "${BLUE}总问题数: $TOTAL_ISSUES${NC}"
    echo ""
    echo "Nmap扫描结果: $NMAP_DIR"
    echo "扫描完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
}

# 执行主扫描
main_scan
