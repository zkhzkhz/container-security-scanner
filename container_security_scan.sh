#!/bin/bash
# 容器安全扫描工具 v2.2
# 基于安全规范要求的多项安全检查
# 默认只扫描容器环境，支持指定特定容器

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

# 显示帮助信息
show_help() {
    echo -e "${BLUE}容器安全扫描工具 v2.2${NC}"
    echo ""
    echo "用法: $0 [选项] [容器名称...]"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示帮助信息"
    echo "  -a, --all           扫描所有运行中的容器(默认)"
    echo "  -l, --list          列出所有运行中的容器"
    echo "  -m, --mode MODE     设置扫描模式: container(默认)/host/all"
    echo ""
    echo "示例:"
    echo "  $0                        # 扫描所有容器"
    echo "  $0 nginx mysql            # 仅扫描nginx和mysql容器"
    echo "  $0 haproxy                # 仅扫描haproxy容器"
    echo "  $0 -l                     # 列出所有容器"
    exit 0
}

# 列出所有运行中的容器
list_containers() {
    echo -e "${BLUE}运行中的容器列表:${NC}"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null
    exit 0
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -a|--all) TARGET_CONTAINERS=""; shift ;;
            -l|--list) list_containers ;;
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

    if [ -z "$CONTAINERS" ]; then
        echo -e "${RED}错误: 没有找到要扫描的容器${NC}"
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
        local ports=$(docker port "$container" 2>/dev/null | grep "0.0.0.0" || true)
        if [ -n "$ports" ]; then
            log_warning "容器 [$container] 绑定到 0.0.0.0"
            echo "  端口映射: $ports" >> "$REPORT_FILE"
        fi
    done
}

# ==================== 2. SSL/TLS证书检查 ====================
check_ssl_certificates() {
    echo "" >> "$REPORT_FILE"
    echo "## 2. SSL/TLS证书检查" >> "$REPORT_FILE"
    log_info "开始检查容器内证书..."

    for container in $CONTAINERS; do
        local certs=$(docker exec "$container" find /etc -name "*.pem" -o -name "*.crt" 2>/dev/null | head -5 || true)
        if [ -n "$certs" ]; then
            log_info "容器 [$container] 发现证书文件"
        fi
    done
}

# ==================== 3. 加密套件检查 ====================
check_cipher_suites() {
    echo "" >> "$REPORT_FILE"
    echo "## 3. 加密套件检查 (Nginx_2_7_4)" >> "$REPORT_FILE"
    log_info "开始检查加密套件配置..."

    for container in $CONTAINERS; do
        local nginx_check=$(docker exec "$container" which nginx 2>/dev/null || true)
        if [ -n "$nginx_check" ]; then
            local ssl_ciphers=$(docker exec "$container" sh -c "nginx -T 2>/dev/null | grep -i ssl_ciphers" 2>/dev/null || true)
            if [ -n "$ssl_ciphers" ]; then
                for weak in RC4 DES 3DES MD5; do
                    echo "$ssl_ciphers" | grep -qi "$weak" && log_error "容器 [$container] 发现弱加密套件: $weak"
                done
            fi
        fi
    done
}

# ==================== 4. 敏感信息检查 ====================
check_sensitive_info() {
    echo "" >> "$REPORT_FILE"
    echo "## 4. 敏感信息泄露检查" >> "$REPORT_FILE"
    log_info "开始检查容器内敏感信息..."

    local patterns="password passwd secret api_key token private_key"

    for container in $CONTAINERS; do
        for pattern in $patterns; do
            local found=$(docker exec "$container" env 2>/dev/null | grep -i "$pattern" || true)
            [ -n "$found" ] && log_warning "容器 [$container] 发现敏感环境变量: $pattern"
        done

        # SSH私钥检查
        local keys=$(docker exec "$container" find / -name "id_rsa" 2>/dev/null | head -3 || true)
        [ -n "$keys" ] && log_warning "容器 [$container] 发现SSH私钥"
    done
}

# ==================== 5. Nginx安全规范专项检查(48项) ====================
check_nginx_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 5. Nginx安全规范专项检查 (48项)" >> "$REPORT_FILE"
    log_info "开始检查Nginx安全规范..."

    for container in $CONTAINERS; do
        local nginx_check=$(docker exec "$container" which nginx 2>/dev/null || true)
        if [ -n "$nginx_check" ]; then
            local config=$(docker exec "$container" sh -c "nginx -T 2>/dev/null" 2>/dev/null || true)
            echo "### 容器 [$container] Nginx配置检查" >> "$REPORT_FILE"

            # ========== 安装安全检查 ==========
            # 规范1: 删除缺省文件
            local default_files="/etc/nginx/conf.d/default.conf /usr/share/nginx/html/index.html"
            for f in $default_files; do
                docker exec "$container" test -f "$f" 2>/dev/null && log_warning "容器 [$container] 存在缺省文件: $f (规范1)"
            done

            # 规范2: 检查模块数量(简化)
            local module_count=$(docker exec "$container" nginx -V 2>&1 | grep -o "with-" | wc -l)
            log_info "容器 [$container] 编译模块数: $module_count (规范2)"

            # 规范3: 禁止webDAV
            if docker exec "$container" nginx -V 2>&1 | grep -qi "http_dav_module"; then
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
                local lock_status=$(docker exec "$container" passwd -S "$nginx_user" 2>/dev/null | awk '{print $2}')
                if [ "$lock_status" == "L" ] || [ "$lock_status" == "LK" ]; then
                    log_success "容器 [$container] 账号 $nginx_user 已锁定 (规范7)"
                else
                    log_warning "容器 [$container] 账号 $nginx_user 未锁定 (规范7)"
                fi

                # 规范8: 禁止登录shell
                local shell=$(docker exec "$container" getent passwd "$nginx_user" 2>/dev/null | cut -d: -f7)
                if [ "$shell" == "/sbin/nologin" ] || [ "$shell" == "/bin/false" ] || [ -z "$shell" ]; then
                    log_success "容器 [$container] 账号 $nginx_user 禁止登录shell (规范8)"
                else
                    log_error "容器 [$container] 账号 $nginx_user 可登录shell (规范8)"
                fi
            fi

            # ========== 文件权限检查 ==========
            # 规范9: Nginx目录权限
            local nginx_dir=$(docker exec "$container" nginx -V 2>&1 | grep -o "prefix=[^ ]*" | cut -d= -f2 | tr -d ' ')
            [ -z "$nginx_dir" ] && nginx_dir="/etc/nginx"
            local dir_perm=$(docker exec "$container" stat -c "%a" "$nginx_dir" 2>/dev/null || echo "755")
            if [ "$dir_perm" -le "550" ]; then
                log_success "容器 [$container] Nginx目录权限: $dir_perm (规范9)"
            else
                log_error "容器 [$container] Nginx目录权限过宽: $dir_perm (规范9)"
            fi

            # 规范10: 配置文件权限
            local conf_perm=$(docker exec "$container" stat -c "%a" /etc/nginx/nginx.conf 2>/dev/null || echo "644")
            if [ "$conf_perm" -le "640" ]; then
                log_success "容器 [$container] 配置文件权限: $conf_perm (规范10)"
            else
                log_error "容器 [$container] 配置文件权限过宽: $conf_perm (规范10)"
            fi

            # 规范11: 日志文件权限
            local log_dir="/var/log/nginx"
            local log_issue=false
            for logfile in access.log error.log; do
                local log_perm=$(docker exec "$container" stat -c "%a" "$log_dir/$logfile" 2>/dev/null || echo "644")
                if [ "$log_perm" -gt "640" ]; then
                    log_error "容器 [$container] 日志文件权限过宽: $logfile ($log_perm) (规范11)"
                    log_issue=true
                fi
            done
            [ "$log_issue" = false ] && log_success "容器 [$container] 日志文件权限安全 (规范11)"

            # 规范13: PID文件权限
            local pid_file=$(echo "$config" | grep -E "^\s*pid\s+" | awk '{print $2}' | tr -d ';')
            [ -z "$pid_file" ] && pid_file="/var/run/nginx.pid"
            local pid_perm=$(docker exec "$container" stat -c "%a" "$pid_file" 2>/dev/null || echo "644")
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

    echo "### 容器端口映射" >> "$REPORT_FILE"
    for container in $CONTAINERS; do
        local ports=$(docker port "$container" 2>/dev/null || true)
        echo "容器 [$container]:" >> "$REPORT_FILE"
        echo "$ports" >> "$REPORT_FILE"
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
        local user=$(docker exec "$container" whoami 2>/dev/null || echo "unknown")
        [ "$user" == "root" ] && log_warning "容器 [$container] 以root用户运行 (D_IAM_48_1)" || log_success "容器 [$container] 以非root用户运行"

        # 特权模式
        local priv=$(docker inspect "$container" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo "false")
        [ "$priv" == "true" ] && log_error "容器 [$container] 运行在特权模式" || log_success "容器 [$container] 未运行在特权模式"

        # 资源限制
        local mem=$(docker inspect "$container" --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
        [ "$mem" == "0" ] && log_warning "容器 [$container] 未设置内存限制" || log_success "容器 [$container] 已设置内存限制"

        local cpu=$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}' 2>/dev/null || echo "0")
        [ "$cpu" == "0" ] && log_warning "容器 [$container] 未设置CPU限制" || log_success "容器 [$container] 已设置CPU限制"

        # 网络模式
        local net=$(docker inspect "$container" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || echo "default")
        [ "$net" == "host" ] && log_error "容器 [$container] 使用host网络模式" || log_info "容器 [$container] 网络模式: $net"

        # 只读根文件系统
        local ro=$(docker inspect "$container" --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null || echo "false")
        [ "$ro" == "true" ] && log_success "容器 [$container] 根文件系统为只读" || log_warning "容器 [$container] 根文件系统可写"
    done
}

# ==================== 8. 镜像安全检查 ====================
check_image_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 8. 镜像安全检查" >> "$REPORT_FILE"
    log_info "开始检查镜像安全..."

    for container in $CONTAINERS; do
        local image=$(docker inspect "$container" --format '{{.Config.Image}}' 2>/dev/null || true)
        echo "$image" | grep -qE ":latest$|:$" && log_warning "容器 [$container] 使用latest标签镜像: $image"
    done
}

# ==================== 9. MD5密码安全检查 ====================
check_md5_password_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 9. MD5密码安全检查 (D_CAS_2_4)" >> "$REPORT_FILE"
    log_info "开始检查MD5密码..."

    for container in $CONTAINERS; do
        local md5=$(docker exec "$container" grep -E '\$1\$' /etc/shadow 2>/dev/null || true)
        [ -n "$md5" ] && log_error "容器 [$container] 使用MD5加密密码" || log_success "容器 [$container] 未使用MD5加密密码"
    done
}

# ==================== 10. 安全工具残留检查 ====================
check_residual_tools() {
    echo "" >> "$REPORT_FILE"
    echo "## 10. 安全残留工具检查 (D_SCS_5_4)" >> "$REPORT_FILE"
    log_info "开始检查容器内安全工具..."

    local tools="gcc g++ make nmap netcat tcpdump gdb john hydra"

    for container in $CONTAINERS; do
        local found=0
        for tool in $tools; do
            if docker exec "$container" which "$tool" 2>/dev/null; then
                log_warning "容器 [$container] 包含安全工具: $tool"
                found=1
            fi
        done
        [ $found -eq 0 ] && log_success "容器 [$container] 未发现高危安全工具"
    done
}

# ==================== 11. 安装调试工具扫描 ====================
check_debug_tools() {
    echo "" >> "$REPORT_FILE"
    echo "## 11. 安装调试工具扫描" >> "$REPORT_FILE"
    log_info "开始检查容器内调试工具..."

    for container in $CONTAINERS; do
        local debug_tools=$(docker exec "$container" sh -c "find / -name 'tcpdump' -o -name 'sniffer' -o -name 'nmap' -o -name 'wireshark' -o -name 'netcat' -o -name 'gdb' -o -name 'strace' -o -name 'readelf' -o -name 'ethereal' -o -name 'cpp' -o -name 'gcc' -o -name 'dexdump' -o -name 'mirror' -o -name 'jdk' -o -name 'javac' -o -name 'go' -o -name 'dlv' -o -name 'ld' -o -name 'lex' -o -name 'rpcgen' -o -name 'php' -o -name 'binutils' -o -name 'flex' -o -name 'glibc' -o -name 'aplay' -o -name 'ar' -o -name 'arecord' -o -name 'atop' -o -name 'cmake' -o -name 'Dev-cpp' -o -name 'iftop' -o -name 'jsoncpp' -o -name 'make' -o -name 'mcpp' -o -name 'nc' -o -name 'ncat' -o -name 'nload' -o -name 'objdump' -o -name 'perf' -o -name 'rpm-build' -o -name 'vnstat' -o -name 'vnstatsvg' -o -name 'telnetd' -o -name 'libtool' -o -name 'sdk' -o -name 'npm' -o -name 'npx' -o -name 'node-inspector' -o -name 'corepack' -o -name 'pdb.py' -o -name 'bdb.py' -o -name 'trace.py' -o -name 'tracemalloc.py' -o -name 'timeit.py' 2>/dev/null | sort" 2>/dev/null || true)

        if [ -n "$debug_tools" ]; then
            log_warning "容器 [$container] 发现调试工具"
            echo "  发现的工具:" >> "$REPORT_FILE"
            echo "\`\`\`" >> "$REPORT_FILE"
            echo "$debug_tools" >> "$REPORT_FILE"
            echo "\`\`\`" >> "$REPORT_FILE"
        else
            log_success "容器 [$container] 未发现调试工具"
        fi
    done
}

# ==================== 11. 用户权限检查 ====================
check_user_permissions() {
    echo "" >> "$REPORT_FILE"
    echo "## 11. 用户权限检查" >> "$REPORT_FILE"
    log_info "开始检查容器内用户权限..."

    for container in $CONTAINERS; do
        # UID为0的账户
        local uid0=$(docker exec "$container" awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null || true)
        [ "$uid0" != "root" ] && [ -n "$uid0" ] && log_warning "容器 [$container] 发现多个UID为0账户: $uid0"

        # 口令期限
        local maxdays=$(docker exec "$container" grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || true)
        [ "$maxdays" -gt "90" ] 2>/dev/null && log_warning "容器 [$container] 口令期限过长: $maxdays 天"
    done
}

# ==================== 12. 文件权限检查 ====================
check_file_permissions() {
    echo "" >> "$REPORT_FILE"
    echo "## 12. 文件权限检查" >> "$REPORT_FILE"
    log_info "开始检查容器内文件权限..."

    for container in $CONTAINERS; do
        # 敏感文件权限
        local shadow_perm=$(docker exec "$container" stat -c "%a" /etc/shadow 2>/dev/null || true)
        log_info "容器 [$container] /etc/shadow 权限: $shadow_perm"

        # 无属主文件
        local noowner=$(docker exec "$container" find /etc -nouser -o -nogroup 2>/dev/null | head -3 || true)
        [ -n "$noowner" ] && log_warning "容器 [$container] 发现无属主文件"
    done
}

# ==================== 13. 暴力破解防护检查 ====================
check_brute_force_protection() {
    echo "" >> "$REPORT_FILE"
    echo "## 13. 暴力破解防护检查 (D_SCS_2_10)" >> "$REPORT_FILE"
    log_info "开始检查容器内暴力破解防护..."

    for container in $CONTAINERS; do
        docker exec "$container" which fail2ban-server 2>/dev/null && log_success "容器 [$container] 已安装fail2ban" || log_warning "容器 [$container] 未安装fail2ban"
    done
}

# ==================== 14. 不安全函数检查 ====================
check_unsafe_functions() {
    echo "" >> "$REPORT_FILE"
    echo "## 14. 不安全函数检查 (RL_13_1_2_1)" >> "$REPORT_FILE"
    log_info "开始检查代码中不安全函数..."

    local unsafe_funcs="strcpy strcat sprintf gets scanf"

    for container in $CONTAINERS; do
        local cfiles=$(docker exec "$container" find /app /home /root -name "*.c" 2>/dev/null | head -10 || true)
        for file in $cfiles; do
            for func in $unsafe_funcs; do
                docker exec "$container" grep -l "$func" "$file" 2>/dev/null && log_warning "容器 [$container] 发现不安全函数 $func: $file"
            done
        done
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
    echo "    容器安全扫描工具 v2.2"
    echo "========================================"
    echo -e "${NC}"

    init_containers

    echo -e "${BLUE}目标容器:${NC}"
    for c in $CONTAINERS; do
        local img=$(docker inspect "$c" --format '{{.Config.Image}}' 2>/dev/null || echo "?")
        echo -e "  - ${GREEN}$c${NC} ($img)"
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
