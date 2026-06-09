#!/bin/bash
# Nginx安全规范专项扫描工具 v1.0
# 基于Nginx安全规范48项检查点
# 支持扫描宿主机Nginx配置

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认配置
NGINX_CONF_PATH="/etc/nginx/nginx.conf"
NGINX_DIR="/etc/nginx"
NGINX_BIN="/usr/sbin/nginx"
SCAN_TYPE="host"  # host 或 config

# 指定扫描的配置文件路径
TARGET_CONFIG=""

# 输出目录
REPORT_DIR="/tmp/nginx_security_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# 报告文件
REPORT_FILE="$REPORT_DIR/nginx_security_report.md"

# 扫描结果统计
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0
PASSED_CHECKS=0

# 显示帮助信息
show_help() {
    echo -e "${BLUE}Nginx安全规范专项扫描工具 v1.0${NC}"
    echo ""
    echo "用法: $0 [选项] [配置文件路径]"
    echo ""
    echo "选项:"
    echo "  -h, --help              显示帮助信息"
    echo "  -c, --config PATH       指定Nginx配置文件路径"
    echo "  -d, --dir PATH          指定Nginx配置目录"
    echo "  --critical              只显示高优先级(必须项)检查"
    echo ""
    echo "示例:"
    echo "  $0                        # 扫描默认位置 /etc/nginx"
    echo "  $0 -c /path/to/nginx.conf # 扫描指定配置文件"
    echo "  $0 -d /usr/local/nginx/conf"
    exit 0
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -c|--config)
                [ -n "$2" ] && TARGET_CONFIG="$2" && shift 2 || { echo -e "${RED}错误: --config 需要参数${NC}"; exit 1; }
                ;;
            -d|--dir)
                [ -n "$2" ] && NGINX_DIR="$2" && NGINX_CONF_PATH="$2/nginx.conf" && shift 2 || { echo -e "${RED}错误: --dir 需要参数${NC}"; exit 1; }
                ;;
            *)
                TARGET_CONFIG="$1"
                shift
                ;;
        esac
    done
}

# 初始化报告
init_report() {
    echo "# Nginx安全规范专项扫描报告" > "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**扫描时间:** $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
    echo "**配置路径:** $NGINX_CONF_PATH" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
}

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; echo "- $1" >> "$REPORT_FILE"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; echo "  - ✅ $1" >> "$REPORT_FILE"; PASSED_CHECKS=$((PASSED_CHECKS + 1)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; echo "  - ⚠️ $1 (建议)" >> "$REPORT_FILE"; LOW_ISSUES=$((LOW_ISSUES + 1)); TOTAL_ISSUES=$((TOTAL_ISSUES + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; echo "  - ❌ $1" >> "$REPORT_FILE"; HIGH_ISSUES=$((HIGH_ISSUES + 1)); TOTAL_ISSUES=$((TOTAL_ISSUES + 1)); }

# 获取Nginx配置内容(包括include的文件)
get_nginx_config() {
    if [ -f "$NGINX_CONF_PATH" ]; then
        if command -v nginx &> /dev/null; then
            nginx -T -c "$NGINX_CONF_PATH" 2>/dev/null
        else
            cat "$NGINX_CONF_PATH" 2>/dev/null
            # 简单处理include
            grep -E "^\s*include" "$NGINX_CONF_PATH" 2>/dev/null | while read line; do
                inc_file=$(echo "$line" | sed 's/.*include\s*//;s/;//;s/\s*$//')
                if [ -f "$inc_file" ]; then
                    cat "$inc_file" 2>/dev/null
                fi
            done
        fi
    fi
}

# ==================== 1. 安装安全检查 ====================
check_installation_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 1. 安装安全检查" >> "$REPORT_FILE"
    log_info "开始检查Nginx安装安全..."

    # 检查1: 删除安装过程文件
    log_info "检查安装过程文件..."
    local default_files="/etc/nginx/default.d /etc/nginx/conf.d/default.conf /usr/share/nginx/html/index.html"
    for f in $default_files; do
        if [ -e "$f" ]; then
            log_fail "发现缺省文件: $f (规范1)"
        fi
    done

    # 检查2: 最小化安装模块
    log_info "检查安装模块..."
    if command -v nginx &> /dev/null; then
        local modules=$(nginx -V 2>&1 | grep -o "with-[^[:space:]]*" | wc -l)
        log_info "已安装模块数量: $modules"
    fi

    # 检查3: 禁止webDAV
    if command -v nginx &> /dev/null; then
        if nginx -V 2>&1 | grep -qi "http_dav_module"; then
            log_fail "安装了webDAV模块 (规范3)"
        else
            log_pass "未安装webDAV模块 (规范3)"
        fi
    fi
}

# ==================== 2. 网络绑定检查 ====================
check_network_binding() {
    echo "" >> "$REPORT_FILE"
    echo "## 2. 网络绑定检查" >> "$REPORT_FILE"
    log_info "开始检查网络绑定配置..."

    local config=$(get_nginx_config)

    # 检查4: 绑定特定IP
    if echo "$config" | grep -E "listen\s+(\*:|\[::\]:|0\.0\.0\.0:)" > /dev/null 2>&1; then
        log_fail "监听地址绑定到通配符(0.0.0.0或::)，应绑定特定IP (规范4)"
    else
        log_pass "监听地址已绑定特定IP (规范4)"
    fi
}

# ==================== 3. 功能配置检查 ====================
check_functionality() {
    echo "" >> "$REPORT_FILE"
    echo "## 3. 功能配置检查" >> "$REPORT_FILE"
    log_info "开始检查功能配置..."

    local config=$(get_nginx_config)

    # 检查5: 禁用SSI
    if echo "$config" | grep -E "ssi\s+on" > /dev/null 2>&1; then
        log_fail "SSI功能已启用，应禁用 (规范5)"
    else
        log_pass "SSI功能已禁用 (规范5)"
    fi

    # 检查17: 禁用不必要的HTTP方法
    if echo "$config" | grep -E "if\s*\(\$request_method\s*~\s*\".*(TRACE|OPTIONS)" > /dev/null 2>&1; then
        log_pass "已限制不必要的HTTP方法 (规范17)"
    else
        log_fail "未限制TRACE/OPTIONS等不必要的HTTP方法 (规范17)"
    fi
}

# ==================== 4. 账号安全检查 ====================
check_account_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 4. 账号安全检查" >> "$REPORT_FILE"
    log_info "开始检查账号安全..."

    local config=$(get_nginx_config)

    # 检查6: 运行账号
    local user=$(echo "$config" | grep -E "^\s*user\s+" | head -1 | awk '{print $2}' | tr -d ';')
    if [ -z "$user" ] || [ "$user" == "root" ] || [ "$user" == "nobody" ]; then
        log_fail "运行用户为root或nobody，应使用非特权账号 (规范6)"
    else
        log_pass "运行用户: $user (规范6)"

        # 检查7: 账号锁定状态
        if id "$user" &>/dev/null; then
            local lock_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
            if [ "$lock_status" == "L" ] || [ "$lock_status" == "LK" ]; then
                log_pass "账号 $user 已锁定 (规范7)"
            else
                log_warn "账号 $user 未锁定 (规范7)"
            fi
        fi

        # 检查8: 禁止登录shell
        local shell=$(getent passwd "$user" 2>/dev/null | cut -d: -f7)
        if [ "$shell" == "/sbin/nologin" ] || [ "$shell" == "/bin/false" ] || [ -z "$shell" ]; then
            log_pass "账号 $user 禁止登录shell (规范8)"
        else
            log_fail "账号 $user 可登录shell: $shell (规范8)"
        fi
    fi
}

# ==================== 5. 文件权限检查 ====================
check_file_permissions() {
    echo "" >> "$REPORT_FILE"
    echo "## 5. 文件权限检查" >> "$REPORT_FILE"
    log_info "开始检查文件权限..."

    # 检查9: Nginx目录权限
    if [ -d "$NGINX_DIR" ]; then
        local dir_perm=$(stat -c "%a" "$NGINX_DIR" 2>/dev/null)
        if [ "$dir_perm" -le "550" ]; then
            log_pass "Nginx目录权限: $dir_perm (规范9)"
        else
            log_fail "Nginx目录权限过宽: $dir_perm，应为550 (规范9)"
        fi
    fi

    # 检查10: 配置文件权限
    if [ -f "$NGINX_CONF_PATH" ]; then
        local conf_perm=$(stat -c "%a" "$NGINX_CONF_PATH" 2>/dev/null)
        if [ "$conf_perm" -le "640" ]; then
            log_pass "配置文件权限: $conf_perm (规范10)"
        else
            log_fail "配置文件权限过宽: $conf_perm，应不超过640 (规范10)"
        fi
    fi

    # 检查11: 日志文件权限
    local log_dir="/var/log/nginx"
    if [ -d "$log_dir" ]; then
        local found_issue=false
        for logfile in "$log_dir"/*.log; do
            if [ -f "$logfile" ]; then
                local log_perm=$(stat -c "%a" "$logfile" 2>/dev/null)
                if [ "$log_perm" -gt "640" ]; then
                    log_fail "日志文件权限过宽: $logfile ($log_perm) (规范11)"
                    found_issue=true
                fi
            fi
        done
        [ "$found_issue" = false ] && log_pass "日志文件权限符合规范 (规范11)"
    fi

    # 检查13: PID文件权限
    local pid_file=$(get_nginx_config | grep -E "^\s*pid\s+" | awk '{print $2}' | tr -d ';')
    [ -z "$pid_file" ] && pid_file="/var/run/nginx.pid"
    if [ -f "$pid_file" ]; then
        local pid_perm=$(stat -c "%a" "$pid_file" 2>/dev/null)
        if [ "$pid_perm" -le "640" ]; then
            log_pass "PID文件权限: $pid_perm (规范13)"
        else
            log_fail "PID文件权限过宽: $pid_perm (规范13)"
        fi
    fi
}

# ==================== 6. 安全漏洞防护检查 ====================
check_security_vulnerabilities() {
    echo "" >> "$REPORT_FILE"
    echo "## 6. 安全漏洞防护检查" >> "$REPORT_FILE"
    log_info "开始检查安全漏洞防护..."

    local config=$(get_nginx_config)

    # 检查15: alias配置安全
    if echo "$config" | grep -E "alias\s+[^;]*[^/];" > /dev/null 2>&1; then
        log_fail "alias配置可能存在路径遍历风险(末尾无/) (规范15)"
    else
        log_pass "alias配置安全 (规范15)"
    fi

    # 检查31: 禁止重定向到监听端口
    if echo "$config" | grep -E "return\s+3[0-9]{2}\s+https?://\$host" > /dev/null 2>&1; then
        log_warn "存在重定向配置，请确认不重定向到监听端口 (规范31)"
    fi

    # 检查44: CRLF注入防护
    if echo "$config" | grep -E '\$uri|\$document_uri' > /dev/null 2>&1; then
        if echo "$config" | grep -E 'rewrite.*\$uri|return.*\$uri' > /dev/null 2>&1; then
            log_fail "使用\$uri可能导致CRLF注入，应使用\$request_uri (规范44)"
        fi
    fi
}

# ==================== 7. SSL/TLS安全检查 ====================
check_ssl_tls() {
    echo "" >> "$REPORT_FILE"
    echo "## 7. SSL/TLS安全检查" >> "$REPORT_FILE"
    log_info "开始检查SSL/TLS配置..."

    local config=$(get_nginx_config)

    # 检查是否启用SSL
    local ssl_enabled=$(echo "$config" | grep -E "listen\s+.*ssl|listen\s+.*443" | head -1)

    if [ -n "$ssl_enabled" ]; then
        # 检查21: 启用SSL
        log_pass "已启用SSL功能 (规范21)"

        # 检查22: TLS协议版本
        if echo "$config" | grep -E "ssl_protocols" > /dev/null 2>&1; then
            local protocols=$(echo "$config" | grep -E "ssl_protocols" | head -1)
            if echo "$protocols" | grep -E "SSLv2|SSLv3|TLSv1[^\.]" > /dev/null 2>&1; then
                log_fail "使用不安全的TLS协议(SSLv2/SSLv3/TLSv1.0) (规范22)"
            else
                log_pass "TLS协议版本安全 (规范22)"
            fi
        else
            log_warn "未显式配置ssl_protocols (规范22)"
        fi

        # 检查23: 加密套件
        if echo "$config" | grep -E "ssl_ciphers" > /dev/null 2>&1; then
            local ciphers=$(echo "$config" | grep -E "ssl_ciphers" | head -1)
            if echo "$ciphers" | grep -iE "RC4|DES|3DES|MD5|NULL|EXPORT|ANON" > /dev/null 2>&1; then
                log_fail "使用不安全的加密套件 (规范23)"
            else
                log_pass "加密套件配置安全 (规范23)"
            fi
        fi

        # 检查25: 超时时间
        if echo "$config" | grep -E "ssl_session_timeout" > /dev/null 2>&1; then
            log_pass "已配置SSL会话超时 (规范25)"
        else
            log_warn "未配置ssl_session_timeout (规范25)"
        fi

        # 检查26: SSL会话缓存
        if echo "$config" | grep -E "ssl_session_cache" > /dev/null 2>&1; then
            log_pass "已配置SSL会话缓存 (规范26)"
        else
            log_warn "未配置ssl_session_cache (规范26)"
        fi

        # 检查41: 禁用会话恢复
        if echo "$config" | grep -E "ssl_session_tickets\s+off" > /dev/null 2>&1; then
            log_pass "已禁用SSL会话tickets (规范41)"
        else
            log_warn "未禁用ssl_session_tickets (规范41)"
        fi
    else
        log_warn "未检测到SSL配置 (规范21)"
    fi
}

# ==================== 8. 请求限制检查 ====================
check_request_limits() {
    echo "" >> "$REPORT_FILE"
    echo "## 8. 请求限制检查" >> "$REPORT_FILE"
    log_info "开始检查请求限制配置..."

    local config=$(get_nginx_config)

    # 检查28: 网络超时
    local timeout_settings="client_body_timeout client_header_timeout keepalive_timeout send_timeout"
    for setting in $timeout_settings; do
        if echo "$config" | grep -E "$setting" > /dev/null 2>&1; then
            log_pass "已配置 $setting (规范28)"
        else
            log_warn "未配置 $setting (规范28)"
        fi
    done

    # 检查30: 请求体大小限制
    if echo "$config" | grep -E "client_max_body_size" > /dev/null 2>&1; then
        log_pass "已限制请求体大小 (规范30)"
    else
        log_warn "未配置client_max_body_size (规范30)"
    fi
}

# ==================== 9. 信息隐藏检查 ====================
check_info_hiding() {
    echo "" >> "$REPORT_FILE"
    echo "## 9. 信息隐藏检查" >> "$REPORT_FILE"
    log_info "开始检查信息隐藏配置..."

    local config=$(get_nginx_config)

    # 检查38: 隐藏版本信息
    if echo "$config" | grep -E "server_tokens\s+off" > /dev/null 2>&1; then
        log_pass "已隐藏版本信息 (规范38)"
    else
        log_fail "未隐藏版本信息，应设置server_tokens off (规范38)"
    fi

    # 检查37: 隐藏X-Powered-By
    if echo "$config" | grep -E "proxy_hide_header\s+X-Powered-By|fastcgi_hide_header\s+X-Powered-By" > /dev/null 2>&1; then
        log_pass "已隐藏X-Powered-By头 (规范37)"
    else
        log_warn "未配置隐藏X-Powered-By头 (规范37)"
    fi

    # 检查39: 禁用目录列表
    if echo "$config" | grep -E "autoindex\s+on" > /dev/null 2>&1; then
        log_fail "启用了目录列表功能，应禁用 (规范39)"
    else
        log_pass "未启用目录列表功能 (规范39)"
    fi

    # 检查35: 定制错误页面
    if echo "$config" | grep -E "error_page" > /dev/null 2>&1; then
        log_pass "已配置自定义错误页面 (规范35)"
    else
        log_warn "未配置自定义错误页面 (规范35)"
    fi
}

# ==================== 10. 日志审计检查 ====================
check_logging() {
    echo "" >> "$REPORT_FILE"
    echo "## 10. 日志审计检查" >> "$REPORT_FILE"
    log_info "开始检查日志配置..."

    local config=$(get_nginx_config)

    # 检查42: 开启日志
    local access_log=$(echo "$config" | grep -E "access_log" | grep -v "off" | head -1)
    local error_log=$(echo "$config" | grep -E "error_log" | grep -v "off" | head -1)

    if [ -n "$access_log" ]; then
        log_pass "已开启访问日志 (规范42)"
    else
        log_fail "未开启访问日志 (规范42)"
    fi

    if [ -n "$error_log" ]; then
        log_pass "已开启错误日志 (规范42)"
    else
        log_fail "未开启错误日志 (规范42)"
    fi
}

# ==================== 11. HTTP安全头检查 ====================
check_security_headers() {
    echo "" >> "$REPORT_FILE"
    echo "## 11. HTTP安全响应头检查" >> "$REPORT_FILE"
    log_info "开始检查HTTP安全响应头..."

    local config=$(get_nginx_config)

    # 检查45: 安全响应头
    local headers="X-Frame-Options X-Content-Type-Options X-XSS-Protection Strict-Transport-Security Content-Security-Policy"

    for header in $headers; do
        if echo "$config" | grep -E "add_header\s+$header" > /dev/null 2>&1; then
            log_pass "已配置 $header (规范45)"
        else
            log_fail "未配置安全响应头 $header (规范45)"
        fi
    done
}

# ==================== 12. 建议项检查 ====================
check_recommendations() {
    echo "" >> "$REPORT_FILE"
    echo "## 12. 建议项检查 (低优先级)" >> "$REPORT_FILE"
    log_info "开始检查建议项..."

    local config=$(get_nginx_config)

    # 检查19: 限制访问IP
    if echo "$config" | grep -E "allow\s+[0-9]+\.|deny\s+all" > /dev/null 2>&1; then
        log_pass "已配置IP访问限制 (规范19)"
    else
        log_warn "未配置IP访问限制 (规范19)"
    fi

    # 检查29: 连接数限制
    if echo "$config" | grep -E "limit_conn" > /dev/null 2>&1; then
        log_pass "已配置连接数限制 (规范29)"
    else
        log_warn "未配置连接数限制 (规范29)"
    fi

    # 检查32: 并发数限制
    if echo "$config" | grep -E "worker_connections" > /dev/null 2>&1; then
        log_pass "已配置worker_connections (规范32)"
    else
        log_warn "未配置worker_connections (规范32)"
    fi

    # 检查33: 速率限制
    if echo "$config" | grep -E "limit_req" > /dev/null 2>&1; then
        log_pass "已配置请求速率限制 (规范33)"
    else
        log_warn "未配置请求速率限制 (规范33)"
    fi

    # 检查36: 禁用隐藏文件服务
    if echo "$config" | grep -E "location\s+~\s*/\." > /dev/null 2>&1; then
        log_pass "已配置拒绝隐藏文件访问 (规范36)"
    else
        log_warn "未配置拒绝隐藏文件访问 (规范36)"
    fi

    # 检查40: Referer配置
    if echo "$config" | grep -E "valid_referers\s+none\s+blocked" > /dev/null 2>&1; then
        log_pass "已配置Referer策略 (规范40)"
    else
        log_warn "未配置Referer策略 (规范40)"
    fi
}

# ==================== 生成报告摘要 ====================
generate_summary() {
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "## 扫描摘要" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "| 级别 | 数量 |" >> "$REPORT_FILE"
    echo "|------|------|" >> "$REPORT_FILE"
    echo "| 🚨 高危(必须项) | $HIGH_ISSUES |" >> "$REPORT_FILE"
    echo "| ⚠️ 建议(建议项) | $LOW_ISSUES |" >> "$REPORT_FILE"
    echo "| ✅ 通过 | $PASSED_CHECKS |" >> "$REPORT_FILE"
    echo "| **问题总计** | **$TOTAL_ISSUES** |" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**报告保存位置:** \`$REPORT_DIR\`" >> "$REPORT_FILE"

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}     Nginx安全规范专项扫描完成${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${RED}🚨 高危(必须项): $HIGH_ISSUES${NC}"
    echo -e "${YELLOW}⚠️ 建议(建议项): $LOW_ISSUES${NC}"
    echo -e "${GREEN}✅ 通过: $PASSED_CHECKS${NC}"
    echo ""
    echo -e "报告已保存至: ${GREEN}$REPORT_DIR${NC}"
}

# ==================== 主函数 ====================
main() {
    parse_args "$@"

    # 如果指定了配置文件
    if [ -n "$TARGET_CONFIG" ]; then
        NGINX_CONF_PATH="$TARGET_CONFIG"
        NGINX_DIR=$(dirname "$TARGET_CONFIG")
    fi

    echo -e "${BLUE}"
    echo "========================================"
    echo "    Nginx安全规范专项扫描工具 v1.0"
    echo "========================================"
    echo -e "${NC}"

    # 检查配置文件是否存在
    if [ ! -f "$NGINX_CONF_PATH" ]; then
        echo -e "${YELLOW}警告: 配置文件不存在: $NGINX_CONF_PATH${NC}"
        echo -e "${YELLOW}请使用 -c 指定配置文件路径${NC}"
        exit 1
    fi

    echo -e "${BLUE}配置文件:${NC} ${GREEN}$NGINX_CONF_PATH${NC}"
    echo ""

    init_report

    check_installation_security
    check_network_binding
    check_functionality
    check_account_security
    check_file_permissions
    check_security_vulnerabilities
    check_ssl_tls
    check_request_limits
    check_info_hiding
    check_logging
    check_security_headers
    check_recommendations

    generate_summary
}

main "$@"
