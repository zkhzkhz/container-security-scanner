#!/bin/bash
# 容器安全扫描工具 v2.3
# 基于安全规范要求的多项安全检查
# 默认只扫描容器环境，支持指定特定容器
# 支持Docker和crictl(containerd/CRI)两种容器运行时

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 扫描模式
SCAN_MODE="${SCAN_MODE:-container}"

# 指定扫描的容器名称
TARGET_CONTAINERS=""

# 容器运行时 (auto/docker/crictl)
CONTAINER_RUNTIME=""

# 输出目录
REPORT_DIR="/tmp/container_security_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# 报告文件
REPORT_FILE="$REPORT_DIR/security_report.md"

# 扫描结果统计
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# 容器列表(全局变量)
CONTAINERS=""

# 容器ID到名称的映射
declare -A CONTAINER_ID_TO_NAME
declare -A CONTAINER_NAME_TO_ID

# 显示帮助信息
show_help() {
    echo -e "${BLUE}容器安全扫描工具 v2.3${NC}"
    echo ""
    echo "用法: $0 [选项] [容器名称...]"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示帮助信息"
    echo "  -a, --all           扫描所有运行中的容器(默认)"
    echo "  -l, --list          列出所有运行中的容器"
    echo "  -r, --runtime       指定容器运行时: auto(默认)/docker/crictl"
    echo "  -m, --mode MODE     设置扫描模式: container(默认)/host/all"
    echo ""
    echo "示例:"
    echo "  $0                        # 扫描所有容器"
    echo "  $0 nginx mysql            # 仅扫描nginx和mysql容器"
    echo "  $0 -r crictl              # 使用crictl运行时扫描"
    echo "  $0 -l                     # 列出所有容器"
    exit 0
}

# 检测容器运行时
detect_runtime() {
    if [ -n "$CONTAINER_RUNTIME" ] && [ "$CONTAINER_RUNTIME" != "auto" ]; then
        return
    fi

    # 优先检测docker
    if command -v docker &>/dev/null && docker ps &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="docker"
        return
    fi

    # 检测crictl
    if command -v crictl &>/dev/null && crictl ps &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="crictl"
        return
    fi

    # 默认docker
    CONTAINER_RUNTIME="docker"
}

# 获取容器执行命令 (docker exec 或 nsenter)
container_exec() {
    local container="$1"
    shift
    local cmd="$@"

    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        docker exec "$container" sh -c "$cmd" 2>/dev/null
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        local container_id="${CONTAINER_NAME_TO_ID[$container]}"
        if [ -z "$container_id" ]; then
            container_id="$container"
        fi
        # 先尝试crictl exec
        if crictl exec "$container_id" sh -c "$cmd" 2>/dev/null; then
            return 0
        fi
        # 如果crictl exec失败，尝试nsenter
        local pid=$(crictl inspect "$container_id" 2>/dev/null | grep -o '"pid": [0-9]*' | head -1 | awk '{print $2}')
        if [ -n "$pid" ]; then
            nsenter -t "$pid" -- sh -c "$cmd" 2>/dev/null
        fi
    fi
}

# 获取容器inspect信息
container_inspect() {
    local container="$1"
    local format="$2"

    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        docker inspect "$container" --format "$format" 2>/dev/null
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        local container_id="${CONTAINER_NAME_TO_ID[$container]}"
        [ -z "$container_id" ] && container_id="$container"
        crictl inspect "$container_id" 2>/dev/null | jq -r "$format" 2>/dev/null || \
        echo ""
    fi
}

# 获取容器端口映射
container_port() {
    local container="$1"

    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        docker port "$container" 2>/dev/null
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        local container_id="${CONTAINER_NAME_TO_ID[$container]}"
        [ -z "$container_id" ] && container_id="$container"
        crictl inspect "$container_id" 2>/dev/null | jq -r '.status.portMappings // [] | .[] | "\(.containerPort)/\(.protocol) -> \(.hostIp):\(.hostPort)"' 2>/dev/null || \
        echo ""
    fi
}

# 列出所有运行中的容器
list_containers() {
    detect_runtime
    echo -e "${BLUE}运行中的容器列表 (运行时: $CONTAINER_RUNTIME):${NC}"

    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        crictl ps --format "table {{.Name}}\t{{.Image}}\t{{.Status}}" 2>/dev/null || \
        crictl ps 2>/dev/null | awk '{print $1"\t"$2"\t"$7}'
    fi
    exit 0
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -a|--all) TARGET_CONTAINERS=""; shift ;;
            -l|--list) list_containers ;;
            -r|--runtime)
                [ -n "$2" ] && CONTAINER_RUNTIME="$2" && shift 2 || { echo -e "${RED}错误: --runtime 需要参数${NC}"; exit 1; }
                ;;
            -m|--mode)
                [ -n "$2" ] && SCAN_MODE="$2" && shift 2 || { echo -e "${RED}错误: --mode 需要参数${NC}"; exit 1; }
                ;;
            -*)
                echo -e "${RED}未知选项: $1${NC}"; show_help ;;
            *)
                TARGET_CONTAINERS="${TARGET_CONTAINERS:+$TARGET_CONTAINERS }$1"
                shift
                ;;
        esac
    done
}

# 初始化容器列表
init_containers() {
    detect_runtime

    log_info "检测到容器运行时: $CONTAINER_RUNTIME"

    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        if [ -z "$TARGET_CONTAINERS" ]; then
            CONTAINERS=$(docker ps --format "{{.Names}}" 2>/dev/null)
        else
            for name in $TARGET_CONTAINERS; do
                if docker ps --format "{{.Names}}" 2>/dev/null | grep -qx "$name"; then
                    CONTAINERS="${CONTAINERS:+$CONTAINERS }$name"
                else
                    echo -e "${YELLOW}[警告] 容器 '$name' 不存在或未运行，已跳过${NC}"
                fi
            done
        fi
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        # 使用crictl获取容器列表
        local container_list=""
        if [ -z "$TARGET_CONTAINERS" ]; then
            container_list=$(crictl ps --format "{{.Name}}" 2>/dev/null || crictl ps 2>/dev/null | awk 'NR>1 {print $NF}')
        else
            container_list="$TARGET_CONTAINERS"
        fi

        for name in $container_list; do
            local container_id=$(crictl ps --name "$name" --format "{{.ID}}" 2>/dev/null | head -1)
            if [ -n "$container_id" ]; then
                CONTAINER_ID_TO_NAME["$container_id"]="$name"
                CONTAINER_NAME_TO_ID["$name"]="$container_id"
                CONTAINERS="${CONTAINERS:+$CONTAINERS }$name"
            else
                echo -e "${YELLOW}[警告] 容器 '$name' 不存在或未运行，已跳过${NC}"
            fi
        done
    fi

    if [ -z "$CONTAINERS" ]; then
        echo -e "${RED}错误: 没有找到要扫描的容器${NC}"
        echo -e "${YELLOW}提示: 使用 -r crictl 指定容器运行时${NC}"
        exit 1
    fi
}

# 初始化报告
init_report() {
    echo "# 容器安全扫描报告" > "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**扫描时间:** $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
    echo "**扫描容器:** $CONTAINERS" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
}

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; echo "- $1" >> "$REPORT_FILE"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; echo "  - ✅ $1" >> "$REPORT_FILE"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; echo "  - ⚠️ $1" >> "$REPORT_FILE"; MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1)); TOTAL_ISSUES=$((TOTAL_ISSUES + 1)); }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; echo "  - ❌ $1" >> "$REPORT_FILE"; HIGH_ISSUES=$((HIGH_ISSUES + 1)); TOTAL_ISSUES=$((TOTAL_ISSUES + 1)); }

# ==================== 1. 全零IP暴露检查 ====================
check_zero_ip_exposure() {
    echo "" >> "$REPORT_FILE"
    echo "## 1. 全零IP暴露检查 (Nginx_2_2_6)" >> "$REPORT_FILE"
    log_info "开始检查容器内的 0.0.0.0 绑定..."

    for container in $CONTAINERS; do
        local ports=$(container_port "$container" 2>/dev/null)
        log_info "容器 [$container] 端口映射: ${ports:-无}"
        if echo "$ports" | grep -q "0.0.0.0"; then
            log_warning "容器 [$container] 绑定到 0.0.0.0"
            echo "  端口映射: $ports" >> "$REPORT_FILE"
        else
            log_success "容器 [$container] 未绑定到 0.0.0.0"
        fi
    done
}

# ==================== 2. SSL/TLS证书检查 ====================
check_ssl_certificates() {
    echo "" >> "$REPORT_FILE"
    echo "## 2. SSL/TLS证书检查" >> "$REPORT_FILE"
    log_info "开始检查容器内证书..."

    for container in $CONTAINERS; do
        local certs=$(container_exec "$container" "find /etc -name '*.pem' -o -name '*.crt' 2>/dev/null | head -5" 2>/dev/null || true)
        if [ -n "$certs" ]; then
            log_info "容器 [$container] 发现证书文件:"
            echo "$certs" | while read cert; do
                [ -n "$cert" ] && echo "    - $cert" >> "$REPORT_FILE"
            done
        else
            log_info "容器 [$container] 未发现证书文件"
        fi
    done
}

# ==================== 3. 加密套件检查 ====================
check_cipher_suites() {
    echo "" >> "$REPORT_FILE"
    echo "## 3. 加密套件检查 (Nginx_2_7_4)" >> "$REPORT_FILE"
    log_info "开始检查加密套件配置..."

    for container in $CONTAINERS; do
        local nginx_check=$(container_exec "$container" "which nginx 2>/dev/null" || true)
        if [ -n "$nginx_check" ]; then
            log_info "容器 [$container] 发现Nginx: $nginx_check"
            local ssl_ciphers=$(container_exec "$container" "nginx -T 2>/dev/null | grep -i ssl_ciphers" 2>/dev/null || true)
            if [ -n "$ssl_ciphers" ]; then
                log_info "容器 [$container] 加密套件配置:"
                echo "  \`\`\`" >> "$REPORT_FILE"
                echo "$ssl_ciphers" >> "$REPORT_FILE"
                echo "  \`\`\`" >> "$REPORT_FILE"
                local found_weak=false
                for weak in RC4 DES 3DES MD5 NULL EXPORT; do
                    if echo "$ssl_ciphers" | grep -qi "$weak"; then
                        log_error "容器 [$container] 发现弱加密套件: $weak"
                        found_weak=true
                    fi
                done
                [ "$found_weak" = false ] && log_success "容器 [$container] 未发现弱加密套件"
            else
                log_info "容器 [$container] 未配置ssl_ciphers"
            fi
        else
            log_info "容器 [$container] 未安装Nginx"
        fi
    done
}

# ==================== 4. 敏感信息检查 ====================
check_sensitive_info() {
    echo "" >> "$REPORT_FILE"
    echo "## 4. 敏感信息泄露检查" >> "$REPORT_FILE"
    log_info "开始检查容器内敏感信息..."

    local patterns="password passwd secret api_key token private_key access_key secret_key"

    for container in $CONTAINERS; do
        log_info "检查容器 [$container] 环境变量..."
        local env_output=$(container_exec "$container" "env 2>/dev/null" || true)
        local found_sensitive=false

        for pattern in $patterns; do
            local found=$(echo "$env_output" | grep -i "$pattern" || true)
            if [ -n "$found" ]; then
                log_warning "容器 [$container] 发现敏感环境变量: $pattern"
                echo "    匹配行: $(echo "$found" | cut -c1-50)..." >> "$REPORT_FILE"
                found_sensitive=true
            fi
        done

        [ "$found_sensitive" = false ] && log_success "容器 [$container] 未发现敏感环境变量"

        # SSH私钥检查
        log_info "检查容器 [$container] SSH私钥..."
        local keys=$(container_exec "$container" "find / -name 'id_rsa' 2>/dev/null | head -3" || true)
        if [ -n "$keys" ]; then
            log_warning "容器 [$container] 发现SSH私钥:"
            echo "$keys" | while read key; do
                [ -n "$key" ] && echo "    - $key" >> "$REPORT_FILE"
            done
        else
            log_success "容器 [$container] 未发现SSH私钥"
        fi
    done
}

# ==================== 5. Nginx安全规范专项检查(48项) ====================
check_nginx_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 5. Nginx安全规范专项检查 (48项)" >> "$REPORT_FILE"
    log_info "开始检查Nginx安全规范..."

    for container in $CONTAINERS; do
        local nginx_check=$(container_exec "$container" which nginx 2>/dev/null || true)
        if [ -n "$nginx_check" ]; then
            local config=$(container_exec "$container" sh -c "nginx -T 2>/dev/null" 2>/dev/null || true)
            echo "### 容器 [$container] Nginx配置检查" >> "$REPORT_FILE"

            # ========== 安装安全检查 ==========
            # 规范1: 删除缺省文件
            local default_files="/etc/nginx/conf.d/default.conf /usr/share/nginx/html/index.html"
            for f in $default_files; do
                container_exec "$container" test -f "$f" 2>/dev/null && log_warning "容器 [$container] 存在缺省文件: $f (规范1)"
            done

            # 规范2: 检查模块数量(简化)
            local module_count=$(container_exec "$container" nginx -V 2>&1 | grep -o "with-" | wc -l)
            log_info "容器 [$container] 编译模块数: $module_count (规范2)"

            # 规范3: 禁止webDAV
            if container_exec "$container" nginx -V 2>&1 | grep -qi "http_dav_module"; then
                log_error "容器 [$container] 安装了webDAV模块 (规范3)"
            else
                log_success "容器 [$container] 未安装webDAV模块 (规范3)"
            fi

            # ========== 网络绑定检查 ==========
            # 规范4: 绑定特定IP
            if echo "$config" | grep -E "listen\s+(\*:|\[::\]:|0\.0\.0\.0:)" > /dev/null 2>&1; then
                log_error "容器 [$container] 监听地址绑定到通配符 (规范4)"
            else
                log_success "容器 [$container] 监听地址已绑定特定IP (规范4)"
            fi

            # ========== 功能配置检查 ==========
            # 规范5: 禁用SSI
            if echo "$config" | grep -E "ssi\s+on" > /dev/null 2>&1; then
                log_error "容器 [$container] SSI功能已启用 (规范5)"
            else
                log_success "容器 [$container] SSI功能已禁用 (规范5)"
            fi

            # 规范17: 禁用不必要的HTTP方法
            if echo "$config" | grep -E "if\s*\(\$request_method\s*~\s*\".*(TRACE|OPTIONS)" > /dev/null 2>&1; then
                log_success "容器 [$container] 已限制不必要的HTTP方法 (规范17)"
            else
                log_error "容器 [$container] 未限制TRACE/OPTIONS方法 (规范17)"
            fi

            # ========== 账号安全检查 ==========
            # 规范6: 运行用户
            local nginx_user=$(echo "$config" | grep -E "^\s*user\s+" | head -1 | awk '{print $2}' | tr -d ';')
            if [ -z "$nginx_user" ] || [ "$nginx_user" == "root" ]; then
                log_error "容器 [$container] Nginx运行用户为root (规范6)"
            else
                log_success "容器 [$container] Nginx运行用户: $nginx_user (规范6)"

                # 规范7: 账号锁定状态
                local lock_status=$(container_exec "$container" passwd -S "$nginx_user" 2>/dev/null | awk '{print $2}')
                if [ "$lock_status" == "L" ] || [ "$lock_status" == "LK" ]; then
                    log_success "容器 [$container] 账号 $nginx_user 已锁定 (规范7)"
                else
                    log_warning "容器 [$container] 账号 $nginx_user 未锁定 (规范7)"
                fi

                # 规范8: 禁止登录shell
                local shell=$(container_exec "$container" getent passwd "$nginx_user" 2>/dev/null | cut -d: -f7)
                if [ "$shell" == "/sbin/nologin" ] || [ "$shell" == "/bin/false" ] || [ -z "$shell" ]; then
                    log_success "容器 [$container] 账号 $nginx_user 禁止登录shell (规范8)"
                else
                    log_error "容器 [$container] 账号 $nginx_user 可登录shell (规范8)"
                fi
            fi

            # ========== 文件权限检查 ==========
            # 规范9: Nginx目录权限
            local nginx_dir=$(container_exec "$container" nginx -V 2>&1 | grep -o "prefix=[^ ]*" | cut -d= -f2 | tr -d ' ')
            [ -z "$nginx_dir" ] && nginx_dir="/etc/nginx"
            local dir_perm=$(container_exec "$container" stat -c "%a" "$nginx_dir" 2>/dev/null || echo "755")
            if [ "$dir_perm" -le "550" ]; then
                log_success "容器 [$container] Nginx目录权限: $dir_perm (规范9)"
            else
                log_error "容器 [$container] Nginx目录权限过宽: $dir_perm (规范9)"
            fi

            # 规范10: 配置文件权限
            local conf_perm=$(container_exec "$container" stat -c "%a" /etc/nginx/nginx.conf 2>/dev/null || echo "644")
            if [ "$conf_perm" -le "640" ]; then
                log_success "容器 [$container] 配置文件权限: $conf_perm (规范10)"
            else
                log_error "容器 [$container] 配置文件权限过宽: $conf_perm (规范10)"
            fi

            # 规范11: 日志文件权限
            local log_dir="/var/log/nginx"
            local log_issue=false
            for logfile in access.log error.log; do
                local log_perm=$(container_exec "$container" stat -c "%a" "$log_dir/$logfile" 2>/dev/null || echo "644")
                if [ "$log_perm" -gt "640" ]; then
                    log_error "容器 [$container] 日志文件权限过宽: $logfile ($log_perm) (规范11)"
                    log_issue=true
                fi
            done
            [ "$log_issue" = false ] && log_success "容器 [$container] 日志文件权限安全 (规范11)"

            # 规范13: PID文件权限
            local pid_file=$(echo "$config" | grep -E "^\s*pid\s+" | awk '{print $2}' | tr -d ';')
            [ -z "$pid_file" ] && pid_file="/var/run/nginx.pid"
            local pid_perm=$(container_exec "$container" stat -c "%a" "$pid_file" 2>/dev/null || echo "644")
            if [ "$pid_perm" -le "640" ]; then
                log_success "容器 [$container] PID文件权限: $pid_perm (规范13)"
            else
                log_warning "容器 [$container] PID文件权限: $pid_perm (规范13)"
            fi

            # ========== 安全漏洞防护检查 ==========
            # 规范15: alias配置安全
            if echo "$config" | grep -E "alias\s+[^;]*[^/];" > /dev/null 2>&1; then
                log_error "容器 [$container] alias配置可能存在路径遍历风险 (规范15)"
            else
                log_success "容器 [$container] alias配置安全 (规范15)"
            fi

            # 规范16: try_files安全
            if echo "$config" | grep -E "try_files\s+.*\.\." > /dev/null 2>&1; then
                log_warning "容器 [$container] try_files可能存在跨目录风险 (规范16)"
            else
                log_success "容器 [$container] try_files配置安全 (规范16)"
            fi

            # 规范31: 禁止重定向到监听端口
            if echo "$config" | grep -E "return\s+3[0-9]{2}\s+https?://\$host" > /dev/null 2>&1; then
                log_warning "容器 [$container] 存在重定向配置，请确认安全性 (规范31)"
            else
                log_success "容器 [$container] 重定向配置安全 (规范31)"
            fi

            # 规范44: CRLF注入防护
            if echo "$config" | grep -E 'rewrite.*\$uri|return.*\$uri' > /dev/null 2>&1; then
                log_error "容器 [$container] 使用\$uri可能导致CRLF注入 (规范44)"
            else
                log_success "容器 [$container] CRLF注入防护安全 (规范44)"
            fi

            # ========== SSL/TLS安全检查 ==========
            local ssl_enabled=$(echo "$config" | grep -E "listen\s+.*ssl|listen\s+.*443" | head -1)

            if [ -n "$ssl_enabled" ]; then
                # 规范21: 启用SSL
                log_success "容器 [$container] 已启用SSL功能 (规范21)"

                # 规范22: TLS协议版本
                if echo "$config" | grep -E "ssl_protocols" > /dev/null 2>&1; then
                    if echo "$config" | grep -E "ssl_protocols.*SSLv2|ssl_protocols.*SSLv3|ssl_protocols.*TLSv1[^\.]" > /dev/null 2>&1; then
                        log_error "容器 [$container] 使用不安全的TLS协议 (规范22)"
                    else
                        log_success "容器 [$container] TLS协议版本安全 (规范22)"
                    fi
                else
                    log_warning "容器 [$container] 未显式配置ssl_protocols (规范22)"
                fi

                # 规范23: 加密套件
                if echo "$config" | grep -E "ssl_ciphers" > /dev/null 2>&1; then
                    if echo "$config" | grep -iE "ssl_ciphers.*(RC4|DES|3DES|MD5|NULL|EXPORT|ANON)" > /dev/null 2>&1; then
                        log_error "容器 [$container] 使用不安全的加密套件 (规范23)"
                    else
                        log_success "容器 [$container] 加密套件配置安全 (规范23)"
                    fi
                fi

                # 规范24: DHE参数(3072位)
                if echo "$config" | grep -E "ssl_dhparam" > /dev/null 2>&1; then
                    log_success "容器 [$container] 已配置DHE参数 (规范24)"
                else
                    log_warning "容器 [$container] 未配置ssl_dhparam (规范24)"
                fi

                # 规范25: 超时时间
                if echo "$config" | grep -E "ssl_session_timeout" > /dev/null 2>&1; then
                    log_success "容器 [$container] 已配置SSL会话超时 (规范25)"
                else
                    log_warning "容器 [$container] 未配置ssl_session_timeout (规范25)"
                fi

                # 规范26: SSL会话缓存
                if echo "$config" | grep -E "ssl_session_cache" > /dev/null 2>&1; then
                    log_success "容器 [$container] 已配置SSL会话缓存 (规范26)"
                else
                    log_warning "容器 [$container] 未配置ssl_session_cache (规范26)"
                fi

                # 规范27: OCSP
                if echo "$config" | grep -E "ssl_stapling\s+on" > /dev/null 2>&1; then
                    log_success "容器 [$container] 已启用OCSP (规范27)"
                else
                    log_warning "容器 [$container] 未启用ssl_stapling (规范27)"
                fi

                # 规范41: 禁用会话恢复
                if echo "$config" | grep -E "ssl_session_tickets\s+off" > /dev/null 2>&1; then
                    log_success "容器 [$container] 已禁用SSL会话tickets (规范41)"
                else
                    log_warning "容器 [$container] 未禁用ssl_session_tickets (规范41)"
                fi
            else
                log_warning "容器 [$container] 未检测到SSL配置 (规范21)"
            fi

            # ========== 请求限制检查 ==========
            # 规范28: 网络超时
            local timeout_ok=true
            for setting in client_body_timeout client_header_timeout keepalive_timeout send_timeout; do
                if ! echo "$config" | grep -E "$setting" > /dev/null 2>&1; then
                    timeout_ok=false
                fi
            done
            [ "$timeout_ok" = true ] && log_success "容器 [$container] 已配置网络超时 (规范28)" || log_warning "容器 [$container] 网络超时配置不完整 (规范28)"

            # 规范30: 请求体大小限制
            if echo "$config" | grep -E "client_max_body_size" > /dev/null 2>&1; then
                log_success "容器 [$container] 已限制请求体大小 (规范30)"
            else
                log_error "容器 [$container] 未配置client_max_body_size (规范30)"
            fi

            # 规范35: 定制错误页面
            if echo "$config" | grep -E "error_page" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置自定义错误页面 (规范35)"
            else
                log_warning "容器 [$container] 未配置自定义错误页面 (规范35)"
            fi

            # ========== 信息隐藏检查 ==========
            # 规范37: 隐藏X-Powered-By
            if echo "$config" | grep -E "proxy_hide_header\s+X-Powered-By|fastcgi_hide_header\s+X-Powered-By" > /dev/null 2>&1; then
                log_success "容器 [$container] 已隐藏X-Powered-By头 (规范37)"
            else
                log_warning "容器 [$container] 未配置隐藏X-Powered-By (规范37)"
            fi

            # 规范38: 隐藏版本信息
            if echo "$config" | grep -E "server_tokens\s+off" > /dev/null 2>&1; then
                log_success "容器 [$container] server_tokens 已关闭 (规范38)"
            else
                log_error "容器 [$container] server_tokens 未关闭 (规范38)"
            fi

            # 规范39: 禁用目录列表
            if echo "$config" | grep -E "autoindex\s+on" > /dev/null 2>&1; then
                log_error "容器 [$container] 启用了目录列表 (规范39)"
            else
                log_success "容器 [$container] 未启用目录列表 (规范39)"
            fi

            # ========== 日志审计检查 ==========
            # 规范42: 开启日志
            if echo "$config" | grep -E "access_log" | grep -v "off" > /dev/null 2>&1; then
                log_success "容器 [$container] 已开启访问日志 (规范42)"
            else
                log_error "容器 [$container] 未开启访问日志 (规范42)"
            fi
            if echo "$config" | grep -E "error_log" | grep -v "off" > /dev/null 2>&1; then
                log_success "容器 [$container] 已开启错误日志 (规范42)"
            else
                log_error "容器 [$container] 未开启错误日志 (规范42)"
            fi

            # 规范43: 日志详细记录
            local log_format=$(echo "$config" | grep -E "log_format" | head -1)
            if [ -n "$log_format" ]; then
                log_success "容器 [$container] 已配置log_format (规范43)"
            else
                log_warning "容器 [$container] 未配置log_format (规范43)"
            fi

            # ========== HTTP安全头检查 ==========
            # 规范45: 安全响应头
            for header in X-Frame-Options X-Content-Type-Options X-XSS-Protection Strict-Transport-Security Content-Security-Policy; do
                if echo "$config" | grep -qi "add_header\s+$header" > /dev/null 2>&1; then
                    log_success "容器 [$container] 已配置 $header (规范45)"
                else
                    log_error "容器 [$container] 未配置 $header (规范45)"
                fi
            done

            # ========== 建议项检查 ==========
            # 规范14: Dump目录权限(建议)
            # 规范18: 独立环境运行(需人工确认)
            log_info "容器 [$container] 请确认不同实例在独立环境运行 (规范18)"

            # 规范19: 限制访问IP(建议)
            if echo "$config" | grep -E "allow\s+[0-9]+\.|deny\s+all" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置IP访问限制 (规范19)"
            else
                log_warning "容器 [$container] 未配置IP访问限制 (规范19-建议)"
            fi

            # 规范20: 防盗链(建议)
            if echo "$config" | grep -E "valid_referers" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置防盗链 (规范20)"
            else
                log_warning "容器 [$container] 未配置防盗链 (规范20-建议)"
            fi

            # 规范29: 连接数限制(建议)
            if echo "$config" | grep -E "limit_conn" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置连接数限制 (规范29)"
            else
                log_warning "容器 [$container] 未配置连接数限制 (规范29-建议)"
            fi

            # 规范32: 并发数限制(建议)
            if echo "$config" | grep -E "worker_connections" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置worker_connections (规范32)"
            else
                log_warning "容器 [$container] 未配置worker_connections (规范32-建议)"
            fi

            # 规范33: 速率限制(建议)
            if echo "$config" | grep -E "limit_req" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置请求速率限制 (规范33)"
            else
                log_warning "容器 [$container] 未配置请求速率限制 (规范33-建议)"
            fi

            # 规范34: 请求体存储(建议)
            if echo "$config" | grep -E "client_body_in_file_only\s+on" > /dev/null 2>&1; then
                log_warning "容器 [$container] 开启了请求体存储到文件 (规范34-建议)"
            else
                log_success "容器 [$container] 未开启请求体存储到文件 (规范34)"
            fi

            # 规范36: 隐藏文件服务(建议)
            if echo "$config" | grep -E "location\s+~\s*/\." > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置拒绝隐藏文件访问 (规范36)"
            else
                log_warning "容器 [$container] 未配置拒绝隐藏文件访问 (规范36-建议)"
            fi

            # 规范40: Referer配置(建议)
            if echo "$config" | grep -E "valid_referers\s+none\s+blocked" > /dev/null 2>&1; then
                log_success "容器 [$container] 已配置Referer策略 (规范40)"
            else
                log_warning "容器 [$容器] 未配置Referer策略 (规范40-建议)"
            fi

            # 规范46: CSRF防护(建议)
            # 规范47: 响应头覆盖防护(建议)
            # 规范48: URL仿冒防护(建议)
            log_info "容器 [$container] 请人工确认CSRF/响应头覆盖/URL仿冒防护 (规范46-48)"
        fi
    done
}

# ==================== 6. 端口扫描 ====================
check_ports() {
    echo "" >> "$REPORT_FILE"
    echo "## 6. 端口暴露检查" >> "$REPORT_FILE"
    log_info "开始扫描容器端口..."

    for container in $CONTAINERS; do
        local ports=$(container_port "$container" 2>/dev/null || true)
        if [ -n "$ports" ]; then
            log_info "容器 [$container] 端口映射:"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$ports" >> "$REPORT_FILE"
            echo "  \`\`\`" >> "$REPORT_FILE"
        else
            log_info "容器 [$container] 无端口映射或无法获取"
        fi
    done
}

# ==================== 7. 容器安全基线检查 ====================
check_container_baseline() {
    echo "" >> "$REPORT_FILE"
    echo "## 7. 容器安全基线检查" >> "$REPORT_FILE"
    log_info "开始容器安全基线检查..."

    for container in $CONTAINERS; do
        echo "### 容器 [$container]" >> "$REPORT_FILE"

        # 运行用户
        local user=$(container_exec "$container" "whoami 2>/dev/null" || echo "unknown")
        log_info "容器 [$container] 运行用户: $user"
        [ "$user" == "root" ] && log_warning "容器 [$container] 以root用户运行 (D_IAM_48_1)" || log_success "容器 [$container] 以非root用户($user)运行"

        # 特权模式 - 需要从宿主机检查
        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local priv=$(docker inspect "$container" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo "false")
        elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
            local container_id="${CONTAINER_NAME_TO_ID[$container]}"
            [ -z "$container_id" ] && container_id="$container"
            local priv=$(crictl inspect "$container_id" 2>/dev/null | grep -o '"privileged": [^,]*' | head -1 | awk '{print $2}' || echo "false")
        fi
        [ "$priv" == "true" ] && log_error "容器 [$container] 运行在特权模式" || log_success "容器 [$container] 未运行在特权模式"

        # 资源限制 - 需要从宿主机检查
        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local mem=$(docker inspect "$container" --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
            local cpu=$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}' 2>/dev/null || echo "0")
            local net=$(docker inspect "$container" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || echo "default")
            local ro=$(docker inspect "$container" --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null || echo "false")
        elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
            local container_id="${CONTAINER_NAME_TO_ID[$container]}"
            [ -z "$container_id" ] && container_id="$container"
            local inspect_json=$(crictl inspect "$container_id" 2>/dev/null)
            local mem=$(echo "$inspect_json" | grep -o '"memory": [^,]*' | head -1 | awk -F'[ :]' '{print $3}' | tr -d ',' || echo "0")
            local cpu=$(echo "$inspect_json" | grep -o '"cpu_quota": [^,]*' | head -1 | awk -F'[ :]' '{print $3}' | tr -d ',' || echo "0")
            local net=$(echo "$inspect_json" | grep -o '"network_mode": "[^"]*"' | head -1 | cut -d'"' -f4 || echo "default")
            local ro=$(echo "$inspect_json" | grep -o '"readonly_rootfs": [^,]*' | head -1 | awk '{print $2}' || echo "false")
        fi

        log_info "容器 [$container] 内存限制: ${mem:-0} bytes"
        [ "$mem" == "0" ] && log_warning "容器 [$container] 未设置内存限制" || log_success "容器 [$container] 已设置内存限制"

        log_info "容器 [$container] CPU限制: ${cpu:-0}"
        [ "$cpu" == "0" ] && log_warning "容器 [$container] 未设置CPU限制" || log_success "容器 [$container] 已设置CPU限制"

        log_info "容器 [$container] 网络模式: ${net:-default}"
        [ "$net" == "host" ] && log_error "容器 [$container] 使用host网络模式" || log_success "容器 [$container] 网络模式: $net"

        [ "$ro" == "true" ] && log_success "容器 [$container] 根文件系统为只读" || log_warning "容器 [$container] 根文件系统可写"
    done
}

# ==================== 8. 镜像安全检查 ====================
check_image_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 8. 镜像安全检查" >> "$REPORT_FILE"
    log_info "开始检查镜像安全..."

    for container in $CONTAINERS; do
        local image=$(container_inspect "$container" --format '{{.Config.Image}}' 2>/dev/null || true)
        echo "$image" | grep -qE ":latest$|:$" && log_warning "容器 [$container] 使用latest标签镜像: $image"
    done
}

# ==================== 9. MD5密码安全检查 ====================
check_md5_password_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 9. MD5密码安全检查 (D_CAS_2_4)" >> "$REPORT_FILE"
    log_info "开始检查MD5密码..."

    for container in $CONTAINERS; do
        local md5=$(container_exec "$container" "grep -E '\\\$1\\\$' /etc/shadow 2>/dev/null" || true)
        if [ -n "$md5" ]; then
            log_error "容器 [$container] 使用MD5加密密码"
            echo "  发现行数: $(echo "$md5" | wc -l)" >> "$REPORT_FILE"
        else
            log_success "容器 [$container] 未使用MD5加密密码"
        fi
    done
}

# ==================== 10. 安全工具残留检查 ====================
check_residual_tools() {
    echo "" >> "$REPORT_FILE"
    echo "## 10. 安全残留工具检查 (D_SCS_5_4)" >> "$REPORT_FILE"
    log_info "开始检查容器内安全工具..."

    local tools="gcc g++ make nmap netcat tcpdump gdb john hydra curl wget"

    for container in $CONTAINERS; do
        log_info "检查容器 [$container] 安全工具..."
        local found_tools=""
        for tool in $tools; do
            local tool_path=$(container_exec "$container" "which $tool 2>/dev/null" || true)
            if [ -n "$tool_path" ]; then
                found_tools="$found_tools $tool($tool_path)"
            fi
        done
        if [ -n "$found_tools" ]; then
            log_warning "容器 [$container] 包含安全工具:$found_tools"
        else
            log_success "容器 [$container] 未发现高危安全工具"
        fi
    done
}

# ==================== 11. 安装调试工具扫描 ====================
check_debug_tools() {
    echo "" >> "$REPORT_FILE"
    echo "## 11. 安装调试工具扫描" >> "$REPORT_FILE"
    log_info "开始检查容器内调试工具..."

    for container in $CONTAINERS; do
        log_info "扫描容器 [$container] 调试工具..."
        local debug_tools=$(container_exec "$container" "find / -type f \( -name 'tcpdump' -o -name 'gdb' -o -name 'strace' -o -name 'nmap' -o -name 'wireshark' -o -name 'gcc' -o -name 'g++' -o -name 'make' -o -name 'cmake' -o -name 'perf' \) 2>/dev/null | head -20" || true)

        if [ -n "$debug_tools" ]; then
            local count=$(echo "$debug_tools" | wc -l)
            log_warning "容器 [$container] 发现 $count 个调试工具"
            echo "  发现的工具:" >> "$REPORT_FILE"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$debug_tools" >> "$REPORT_FILE"
            echo "  \`\`\`" >> "$REPORT_FILE"
        else
            log_success "容器 [$container] 未发现调试工具"
        fi
    done
}

# ==================== 12. 用户权限检查 ====================
check_user_permissions() {
    echo "" >> "$REPORT_FILE"
    echo "## 12. 用户权限检查" >> "$REPORT_FILE"
    log_info "开始检查容器内用户权限..."

    for container in $CONTAINERS; do
        # UID为0的账户
        local uid0=$(container_exec "$container" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd 2>/dev/null" || true)
        if [ -n "$uid0" ] && [ "$uid0" != "root" ]; then
            log_warning "容器 [$container] 发现多个UID为0账户: $uid0"
        else
            log_success "容器 [$container] 仅root账户UID为0"
        fi

        # 口令期限
        local maxdays=$(container_exec "$container" "grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print \$2}'" || true)
        if [ -n "$maxdays" ]; then
            log_info "容器 [$container] 口令期限: $maxdays 天"
            [ "$maxdays" -gt "90" ] 2>/dev/null && log_warning "容器 [$container] 口令期限过长: $maxdays 天" || log_success "容器 [$container] 口令期限符合规范"
        else
            log_info "容器 [$container] 无法获取口令期限配置"
        fi
    done
}

# ==================== 13. 文件权限检查 ====================
check_file_permissions() {
    echo "" >> "$REPORT_FILE"
    echo "## 13. 文件权限检查" >> "$REPORT_FILE"
    log_info "开始检查容器内文件权限..."

    for container in $CONTAINERS; do
        # 敏感文件权限
        local shadow_perm=$(container_exec "$container" "stat -c '%a' /etc/shadow 2>/dev/null" || true)
        if [ -n "$shadow_perm" ]; then
            log_info "容器 [$container] /etc/shadow 权限: $shadow_perm"
            [ "$shadow_perm" -le "640" ] 2>/dev/null && log_success "容器 [$container] shadow文件权限安全" || log_warning "容器 [$container] shadow文件权限过宽"
        else
            log_info "容器 [$container] 无法获取shadow权限"
        fi

        # passwd文件权限
        local passwd_perm=$(container_exec "$container" "stat -c '%a' /etc/passwd 2>/dev/null" || true)
        if [ -n "$passwd_perm" ]; then
            log_info "容器 [$container] /etc/passwd 权限: $passwd_perm"
        fi

        # 无属主文件
        local noowner=$(container_exec "$container" "find /etc -nouser -o -nogroup 2>/dev/null | head -3" || true)
        if [ -n "$noowner" ]; then
            log_warning "容器 [$container] 发现无属主文件"
        else
            log_success "容器 [$container] 未发现无属主文件"
        fi
    done
}
        # 敏感文件权限
        local shadow_perm=$(container_exec "$container" stat -c "%a" /etc/shadow 2>/dev/null || true)
        log_info "容器 [$container] /etc/shadow 权限: $shadow_perm"

        # 无属主文件
        local noowner=$(container_exec "$container" find /etc -nouser -o -nogroup 2>/dev/null | head -3 || true)
        [ -n "$noowner" ] && log_warning "容器 [$container] 发现无属主文件"
    done
}

# ==================== 14. 暴力破解防护检查 ====================
check_brute_force_protection() {
    echo "" >> "$REPORT_FILE"
    echo "## 14. 暴力破解防护检查 (D_SCS_2_10)" >> "$REPORT_FILE"
    log_info "开始检查容器内暴力破解防护..."

    for container in $CONTAINERS; do
        local fail2ban=$(container_exec "$container" "which fail2ban-server 2>/dev/null" || true)
        if [ -n "$fail2ban" ]; then
            log_success "容器 [$container] 已安装fail2ban: $fail2ban"
        else
            log_warning "容器 [$container] 未安装fail2ban"
        fi
    done
}

# ==================== 15. 不安全函数检查 ====================
check_unsafe_functions() {
    echo "" >> "$REPORT_FILE"
    echo "## 15. 不安全函数检查 (RL_13_1_2_1)" >> "$REPORT_FILE"
    log_info "开始检查代码中不安全函数..."

    local unsafe_funcs="strcpy strcat sprintf gets scanf"

    for container in $CONTAINERS; do
        log_info "扫描容器 [$container] C代码文件..."
        local cfiles=$(container_exec "$container" "find /app /home /root -name '*.c' 2>/dev/null | head -10" || true)
        if [ -z "$cfiles" ]; then
            log_info "容器 [$container] 未发现C代码文件"
            continue
        fi

        local found_unsafe=false
        for file in $cfiles; do
            for func in $unsafe_funcs; do
                local match=$(container_exec "$container" "grep -l '$func' '$file' 2>/dev/null" || true)
                if [ -n "$match" ]; then
                    log_warning "容器 [$container] 发现不安全函数 $func: $file"
                    found_unsafe=true
                fi
            done
        done
        [ "$found_unsafe" = false ] && log_success "容器 [$container] 未发现不安全函数"
    done
}

# ==================== 生成报告摘要 ====================
generate_summary() {
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "## 扫描摘要" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "| 严重级别 | 数量 |" >> "$REPORT_FILE"
    echo "|---------|------|" >> "$REPORT_FILE"
    echo "| 🚨 严重 | $CRITICAL_ISSUES |" >> "$REPORT_FILE"
    echo "| ❌ 高危 | $HIGH_ISSUES |" >> "$REPORT_FILE"
    echo "| ⚠️ 中危 | $MEDIUM_ISSUES |" >> "$REPORT_FILE"
    echo "| **总计** | **$TOTAL_ISSUES** |" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**报告保存位置:** \`$REPORT_DIR\`" >> "$REPORT_FILE"

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}          扫描完成${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${RED}🚨 严重: $CRITICAL_ISSUES${NC}"
    echo -e "${RED}❌ 高危: $HIGH_ISSUES${NC}"
    echo -e "${YELLOW}⚠️  中危: $MEDIUM_ISSUES${NC}"
    echo -e "${BLUE}总计: $TOTAL_ISSUES${NC}"
    echo ""
    echo -e "报告已保存至: ${GREEN}$REPORT_DIR${NC}"
}

# ==================== 主函数 ====================
main() {
    parse_args "$@"

    echo -e "${BLUE}"
    echo "========================================"
    echo "    容器安全扫描工具 v2.3"
    echo "========================================"
    echo -e "${NC}"

    init_containers

    echo -e "${BLUE}目标容器:${NC}"
    for c in $CONTAINERS; do
        echo -e "  - ${GREEN}$c${NC}"
    done
    echo ""

    init_report

    check_zero_ip_exposure
    check_ssl_certificates
    check_cipher_suites
    check_sensitive_info
    check_nginx_security
    check_ports
    check_container_baseline
    check_image_security
    check_md5_password_security
    check_residual_tools
    check_debug_tools
    check_user_permissions
    check_file_permissions
    check_brute_force_protection
    check_unsafe_functions

    generate_summary
}

main "$@"
