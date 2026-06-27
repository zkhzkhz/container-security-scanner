#!/bin/bash
# Web应用安全扫描工具
# 对指定域名进行安全扫描
# 包括SSL/TLS检查、端口扫描、安全头检查、漏洞探测等

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 配置
TARGET_DOMAIN=""
TARGET_URL=""
OUTPUT_DIR=""
PORTS="80,443,8080,8443,3000,5000,8000,9000"

# 扫描结果统计
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0

# 显示帮助
show_help() {
    echo -e "${BLUE}Web应用安全扫描工具 v1.0${NC}"
    echo ""
    echo "用法: $0 [选项] <域名>"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示帮助信息"
    echo "  -d, --domain DOMAIN 指定扫描域名"
    echo "  -p, --ports PORTS   指定扫描端口(默认: 80,443,8080,8443)"
    echo "  -o, --output DIR    指定输出目录"
    echo "  --skip-nmap         跳过nmap扫描"
    echo "  --skip-ssl          跳过SSL检查"
    echo "  --skip-headers      跳过安全头检查"
    echo ""
    echo "示例:"
    echo "  $0 example.com                    # 扫描指定域名"
    echo "  $0 -d example.com -p 80,443       # 指定端口扫描"
    echo "  $0 https://example.com            # 指定HTTPS"
    echo ""
    echo "扫描模块:"
    echo "  1.  DNS解析检查"
    echo "  2.  SSL/TLS证书检查"
    echo "  3.  SSL加密套件检查"
    echo "  4.  HTTP安全头检查"
    echo "  5.  端口扫描(Nmap)"
    echo "  6.  Web技术识别"
    echo "  7.  敏感路径扫描"
    echo "  8.  漏洞探测"
    exit 0
}

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[INFO] $1" >> "$REPORT_FILE"
}
log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[PASS] $1" >> "$REPORT_FILE"
}
log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[WARN] $1" >> "$REPORT_FILE"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}
log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[FAIL] $1" >> "$REPORT_FILE"
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}
log_cmd() {
    echo -e "${CYAN}[CMD]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[CMD] $1" >> "$REPORT_FILE"
}
log_result() {
    local result="$1"
    local len=${#result}
    if [ $len -gt 100 ]; then
        echo -e "  ${CYAN}→ 结果:${NC} ${result:0:100}..."
    else
        echo -e "  ${CYAN}→ 结果:${NC} $result"
    fi
    [ -n "$REPORT_FILE" ] && echo "  → 结果: $result" >> "$REPORT_FILE"
}
log_detail() {
    echo -e "    ${CYAN}$1${NC}"
    [ -n "$REPORT_FILE" ] && echo "    $1" >> "$REPORT_FILE"
}

# 解析参数
SKIP_NMAP=false
SKIP_SSL=false
SKIP_HEADERS=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -d|--domain)
                [ -n "$2" ] && TARGET_DOMAIN="$2" && shift 2 || { echo -e "${RED}错误: --domain 需要参数${NC}"; exit 1; }
                ;;
            -p|--ports)
                [ -n "$2" ] && PORTS="$2" && shift 2 || { echo -e "${RED}错误: --ports 需要参数${NC}"; exit 1; }
                ;;
            -o|--output)
                [ -n "$2" ] && OUTPUT_DIR="$2" && shift 2 || { echo -e "${RED}错误: --output 需要参数${NC}"; exit 1; }
                ;;
            --skip-nmap) SKIP_NMAP=true; shift ;;
            --skip-ssl) SKIP_SSL=true; shift ;;
            --skip-headers) SKIP_HEADERS=true; shift ;;
            http*://*)
                TARGET_URL="$1"
                TARGET_DOMAIN=$(echo "$1" | sed -E 's|https?://([^/:]+).*|\1|')
                shift
                ;;
            -*)
                echo -e "${RED}未知选项: $1${NC}"; show_help ;;
            *)
                TARGET_DOMAIN="$1"
                shift
                ;;
        esac
    done

    if [ -z "$TARGET_DOMAIN" ]; then
        echo -e "${RED}错误: 请指定扫描域名${NC}"
        show_help
    fi

    # 设置默认URL
    [ -z "$TARGET_URL" ] && TARGET_URL="https://$TARGET_DOMAIN"

    # 设置输出目录
    [ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="/tmp/web_scan_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"

    REPORT_FILE="$OUTPUT_DIR/scan_report.md"
}

# 检查依赖工具
check_dependencies() {
    log_info "检查依赖工具..."

    local tools="curl openssl nmap dig"
    for tool in $tools; do
        if ! command -v $tool &>/dev/null; then
            log_warning "未安装 $tool，尝试安装..."
            if command -v apt &>/dev/null; then
                apt install -y $tool 2>/dev/null
            elif command -v yum &>/dev/null; then
                yum install -y $tool 2>/dev/null
            fi
        fi
    done
}

# ==================== 1. DNS解析检查 ====================
check_dns() {
    echo ""
    echo "--- 1. DNS解析检查 ---"

    log_cmd "dig +short $TARGET_DOMAIN"
    local dns_result=$(dig +short "$TARGET_DOMAIN" 2>/dev/null | head -5)

    if [ -n "$dns_result" ]; then
        log_success "DNS解析成功"
        echo "$dns_result" | while read ip; do
            [ -n "$ip" ] && log_detail "IP: $ip"
        done

        # 检查是否使用CDN
        local cname=$(dig +short CNAME "$TARGET_DOMAIN" 2>/dev/null | head -1)
        if [ -n "$cname" ]; then
            log_info "CNAME: $cname"
            if echo "$cname" | grep -qiE "cloudflare|akamai|cloudfront|fastly|cdn"; then
                log_detail "检测到CDN: $cname"
            fi
        fi
    else
        log_error "DNS解析失败"
        return 1
    fi
}

# ==================== 2. SSL/TLS证书检查 ====================
check_ssl_certificate() {
    echo ""
    echo "--- 2. SSL/TLS证书检查 ---"

    if [ "$SKIP_SSL" = true ]; then
        log_info "跳过SSL检查"
        return
    fi

    # 获取证书信息
    log_cmd "echo | openssl s_client -connect $TARGET_DOMAIN:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer"

    local cert_info=$(echo | openssl s_client -connect "$TARGET_DOMAIN:443" -servername "$TARGET_DOMAIN" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)

    if [ -n "$cert_info" ]; then
        log_success "SSL证书获取成功"

        # 解析证书信息
        local subject=$(echo "$cert_info" | grep "subject=" | sed 's/subject=//')
        local issuer=$(echo "$cert_info" | grep "issuer=" | sed 's/issuer=//')
        local not_before=$(echo "$cert_info" | grep "notBefore=" | sed 's/notBefore=//')
        local not_after=$(echo "$cert_info" | grep "notAfter=" | sed 's/notAfter=//')

        log_detail "主体: $subject"
        log_detail "颁发者: $issuer"
        log_detail "有效期: $not_before 至 $not_after"

        # 检查证书是否过期
        local end_date=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo "0")
        local now=$(date +%s)

        if [ "$end_date" != "0" ]; then
            if [ "$end_date" -lt "$now" ]; then
                log_error "证书已过期!"
            elif [ "$((end_date - now))" -lt "2592000" ]; then
                log_warning "证书即将过期(30天内)"
            else
                local days_left=$(( (end_date - now) / 86400 ))
                log_success "证书有效期剩余 $days_left 天"
            fi
        fi

        # 检查证书链
        echo ""
        log_cmd "echo | openssl s_client -connect $TARGET_DOMAIN:443 -servername $TARGET_DOMAIN 2>/dev/null | grep -E 'Verify return|depth|s:|i:'"
        local verify=$(echo | openssl s_client -connect "$TARGET_DOMAIN:443" -servername "$TARGET_DOMAIN" 2>/dev/null | grep "Verify return")
        log_result "$verify"

        if echo "$verify" | grep -q "error"; then
            log_error "证书验证失败"
        else
            log_success "证书验证通过"
        fi
    else
        log_warning "无法获取SSL证书(可能未启用HTTPS)"
    fi
}

# ==================== 3. SSL加密套件检查 ====================
check_ssl_ciphers() {
    echo ""
    echo "--- 3. SSL加密套件检查 ---"

    if [ "$SKIP_SSL" = true ]; then
        log_info "跳过SSL加密套件检查"
        return
    fi

    if ! command -v nmap &>/dev/null; then
        log_warning "nmap未安装，跳过加密套件检查"
        return
    fi

    log_cmd "nmap --script ssl-enum-ciphers -p 443 $TARGET_DOMAIN"

    local nmap_output="$OUTPUT_DIR/ssl_ciphers.txt"
    nmap --script ssl-enum-ciphers -p 443 "$TARGET_DOMAIN" > "$nmap_output" 2>/dev/null

    if [ -f "$nmap_output" ] && [ -s "$nmap_output" ]; then
        log_success "SSL加密套件扫描完成"
        log_detail "结果文件: $nmap_output"

        # 检查不安全协议
        if grep -qE "SSLv2|SSLv3|TLSv1.0|TLSv1.1" "$nmap_output"; then
            log_error "发现不安全的SSL/TLS协议版本"
            grep -E "SSLv2|SSLv3|TLSv1.0|TLSv1.1" "$nmap_output" | while read line; do
                log_detail "$line"
            done
        else
            log_success "SSL/TLS协议版本安全"
        fi

        # 检查弱加密套件
        if grep -qE "RC4|DES|3DES|MD5|NULL|EXPORT|ANON|ADH|AECDH" "$nmap_output"; then
            log_error "发现弱加密套件"
            grep -E "RC4|DES|3DES|MD5|NULL|EXPORT|ANON|ADH|AECDH" "$nmap_output" | head -10 | while read line; do
                log_detail "$line"
            done
        else
            log_success "未发现弱加密套件"
        fi
    fi
}

# ==================== 4. HTTP安全头检查 ====================
check_security_headers() {
    echo ""
    echo "--- 4. HTTP安全头检查 ---"

    if [ "$SKIP_HEADERS" = true ]; then
        log_info "跳过安全头检查"
        return
    fi

    # 获取HTTP响应头
    log_cmd "curl -sI $TARGET_URL"
    local headers=$(curl -sI -m 10 "$TARGET_URL" 2>/dev/null)

    if [ -z "$headers" ]; then
        log_warning "无法获取HTTP响应头"
        return
    fi

    # 显示响应头
    echo "$headers" | head -20 | while read line; do
        [ -n "$line" ] && log_detail "$line"
    done

    # 检查安全响应头
    echo ""
    log_info "=== 安全响应头检查 ==="

    # Strict-Transport-Security
    if echo "$headers" | grep -qi "Strict-Transport-Security"; then
        local hsts=$(echo "$headers" | grep -i "Strict-Transport-Security" | head -1)
        log_success "HSTS 已配置"
        log_detail "$hsts"
    else
        log_warning "未配置 HSTS (Strict-Transport-Security)"
        log_detail "风险: 可能遭受SSL剥离攻击"
    fi

    # X-Frame-Options
    if echo "$headers" | grep -qi "X-Frame-Options"; then
        local xfo=$(echo "$headers" | grep -i "X-Frame-Options" | head -1)
        log_success "X-Frame-Options 已配置"
        log_detail "$xfo"
    else
        log_warning "未配置 X-Frame-Options"
        log_detail "风险: 可能遭受点击劫持攻击"
    fi

    # X-Content-Type-Options
    if echo "$headers" | grep -qi "X-Content-Type-Options"; then
        local xcto=$(echo "$headers" | grep -i "X-Content-Type-Options" | head -1)
        log_success "X-Content-Type-Options 已配置"
        log_detail "$xcto"
    else
        log_warning "未配置 X-Content-Type-Options"
        log_detail "风险: 可能遭受MIME类型嗅探攻击"
    fi

    # X-XSS-Protection
    if echo "$headers" | grep -qi "X-XSS-Protection"; then
        local xss=$(echo "$headers" | grep -i "X-XSS-Protection" | head -1)
        log_success "X-XSS-Protection 已配置"
        log_detail "$xss"
    else
        log_warning "未配置 X-XSS-Protection"
    fi

    # Content-Security-Policy
    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        local csp=$(echo "$headers" | grep -i "Content-Security-Policy" | head -1)
        log_success "CSP 已配置"
        log_detail "$csp"
    else
        log_warning "未配置 Content-Security-Policy"
        log_detail "风险: 可能遭受XSS等注入攻击"
    fi

    # Referrer-Policy
    if echo "$headers" | grep -qi "Referrer-Policy"; then
        local ref=$(echo "$headers" | grep -i "Referrer-Policy" | head -1)
        log_success "Referrer-Policy 已配置"
        log_detail "$ref"
    else
        log_info "未配置 Referrer-Policy"
    fi

    # Permissions-Policy
    if echo "$headers" | grep -qi "Permissions-Policy"; then
        local perm=$(echo "$headers" | grep -i "Permissions-Policy" | head -1)
        log_success "Permissions-Policy 已配置"
        log_detail "$perm"
    else
        log_info "未配置 Permissions-Policy"
    fi

    # 检查不安全头
    echo ""
    log_info "=== 敏感信息泄露检查 ==="

    # Server头
    if echo "$headers" | grep -qi "Server:"; then
        local server=$(echo "$headers" | grep -i "Server:" | head -1)
        log_warning "Server头暴露: $server"
        log_detail "建议: 隐藏或修改Server头"
    fi

    # X-Powered-By
    if echo "$headers" | grep -qi "X-Powered-By"; then
        local xpb=$(echo "$headers" | grep -i "X-Powered-By" | head -1)
        log_warning "X-Powered-By暴露: $xpb"
        log_detail "建议: 隐藏X-Powered-By头"
    fi

    # Set-Cookie检查
    if echo "$headers" | grep -qi "Set-Cookie"; then
        local cookies=$(echo "$headers" | grep -i "Set-Cookie")
        echo "$cookies" | while read cookie; do
            if ! echo "$cookie" | grep -qi "Secure"; then
                log_warning "Cookie未设置Secure标志: $cookie"
            fi
            if ! echo "$cookie" | grep -qi "HttpOnly"; then
                log_warning "Cookie未设置HttpOnly标志: $cookie"
            fi
        done
    fi
}

# ==================== 5. 端口扫描 ====================
check_ports() {
    echo ""
    echo "--- 5. 端口扫描 ---"

    if [ "$SKIP_NMAP" = true ]; then
        log_info "跳过Nmap端口扫描"
        return
    fi

    if ! command -v nmap &>/dev/null; then
        log_warning "nmap未安装，跳过端口扫描"
        return
    fi

    log_info "扫描端口: $PORTS"

    # 快速端口扫描
    log_cmd "nmap -sS -Pn -p $PORTS -oA $OUTPUT_DIR/ports $TARGET_DOMAIN"
    nmap -sS -Pn -p "$PORTS" -oA "$OUTPUT_DIR/ports" "$TARGET_DOMAIN" 2>/dev/null

    if [ -f "$OUTPUT_DIR/ports.nmap" ]; then
        log_success "端口扫描完成"
        log_detail "结果文件: $OUTPUT_DIR/ports.nmap"

        # 显示开放端口
        grep "open" "$OUTPUT_DIR/ports.nmap" | while read line; do
            log_detail "$line"
        done
    fi
}

# ==================== 6. Web技术识别 ====================
check_web_technology() {
    echo ""
    echo "--- 6. Web技术识别 ---"

    # 获取首页内容
    log_cmd "curl -sL -m 10 $TARGET_URL | head -100"
    local page_content=$(curl -sL -m 10 "$TARGET_URL" 2>/dev/null | head -100)

    if [ -n "$page_content" ]; then
        # 检测Web服务器
        if echo "$page_content" | grep -qi "nginx"; then
            log_info "检测到: Nginx"
        elif echo "$page_content" | grep -qi "apache"; then
            log_info "检测到: Apache"
        elif echo "$page_content" | grep -qi "iis"; then
            log_info "检测到: IIS"
        fi

        # 检测框架
        if echo "$page_content" | grep -qi "react"; then
            log_info "检测到: React"
        fi
        if echo "$page_content" | grep -qi "vue"; then
            log_info "检测到: Vue.js"
        fi
        if echo "$page_content" | grep -qi "angular"; then
            log_info "检测到: Angular"
        fi
        if echo "$page_content" | grep -qi "jquery"; then
            log_info "检测到: jQuery"
        fi

        # 检测CMS
        if echo "$page_content" | grep -qi "wordpress"; then
            log_info "检测到: WordPress"
        fi
        if echo "$page_content" | grep -qi "drupal"; then
            log_info "检测到: Drupal"
        fi

        # 保存首页
        echo "$page_content" > "$OUTPUT_DIR/index.html" 2>/dev/null
        log_detail "首页已保存: $OUTPUT_DIR/index.html"
    fi
}

# ==================== 7. 敏感路径扫描 ====================
check_sensitive_paths() {
    echo ""
    echo "--- 7. 敏感路径扫描 ---"

    local sensitive_paths=(
        "/.git/config"
        "/.env"
        "/.htaccess"
        "/.htpasswd"
        "/web.config"
        "/phpinfo.php"
        "/info.php"
        "/admin"
        "/administrator"
        "/wp-admin"
        "/wp-login.php"
        "/backup"
        "/backup.sql"
        "/dump.sql"
        "/database.sql"
        "/.svn/entries"
        "/robots.txt"
        "/sitemap.xml"
        "/.DS_Store"
        "/server-status"
        "/server-info"
        "/actuator"
        "/actuator/health"
        "/swagger-ui.html"
        "/api-docs"
        "/graphql"
        "/.well-known/security.txt"
    )

    log_info "扫描敏感路径..."

    local found_paths=""
    for path in "${sensitive_paths[@]}"; do
        local url="$TARGET_URL$path"
        local response=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null)

        if [ "$response" = "200" ] || [ "$response" = "403" ]; then
            log_warning "发现敏感路径: $path (HTTP $response)"
            found_paths="$found_paths $path"

            # 特殊处理robots.txt
            if [ "$path" = "/robots.txt" ]; then
                local robots=$(curl -s -m 5 "$url" 2>/dev/null)
                if [ -n "$robots" ]; then
                    log_detail "robots.txt内容:"
                    echo "$robots" | head -10 | while read line; do
                        log_detail "  $line"
                    done
                fi
            fi
        fi
    done

    if [ -z "$found_paths" ]; then
        log_success "未发现敏感路径"
    fi
}

# ==================== 8. 漏洞探测 ====================
check_vulnerabilities() {
    echo ""
    echo "--- 8. 基础漏洞探测 ---"

    # 检查HTTPS重定向
    log_info "检查HTTPS重定向..."
    local http_response=$(curl -sI -m 5 "http://$TARGET_DOMAIN" 2>/dev/null | head -1)
    if echo "$http_response" | grep -q "301\|302"; then
        local location=$(curl -sI -m 5 "http://$TARGET_DOMAIN" 2>/dev/null | grep -i "Location:" | head -1)
        if echo "$location" | grep -q "https"; then
            log_success "HTTP正确重定向到HTTPS"
        else
            log_warning "HTTP重定向但未指向HTTPS"
        fi
    else
        log_warning "HTTP未重定向到HTTPS"
    fi

    # 检查点击劫持
    log_info "检查点击劫持防护..."
    local headers=$(curl -sI -m 5 "$TARGET_URL" 2>/dev/null)
    if echo "$headers" | grep -qi "X-Frame-Options\|Content-Security-Policy.*frame-ancestors"; then
        log_success "已配置点击劫持防护"
    else
        log_warning "未配置点击劫持防护"
    fi

    # 检查Cookie安全
    log_info "检查Cookie安全属性..."
    local cookies=$(curl -sI -m 5 "$TARGET_URL" 2>/dev/null | grep -i "Set-Cookie")
    if [ -n "$cookies" ]; then
        local cookie_issues=0
        echo "$cookies" | while read cookie; do
            if ! echo "$cookie" | grep -qi "Secure"; then
                log_warning "Cookie缺少Secure属性"
                cookie_issues=$((cookie_issues + 1))
            fi
            if ! echo "$cookie" | grep -qi "HttpOnly"; then
                log_warning "Cookie缺少HttpOnly属性"
                cookie_issues=$((cookie_issues + 1))
            fi
        done
    fi

    # 检查开放重定向
    log_info "检查开放重定向..."
    local test_url="$TARGET_URL?url=http://evil.com&redirect=http://evil.com&next=http://evil.com"
    local redirect_test=$(curl -sI -m 5 "$test_url" 2>/dev/null | grep -i "Location:" | head -1)
    if echo "$redirect_test" | grep -q "evil.com"; then
        log_error "可能存在开放重定向漏洞"
    else
        log_success "未发现开放重定向漏洞"
    fi
}

# ==================== 生成报告 ====================
generate_report() {
    echo ""
    echo "=========================================="
    echo "扫描报告摘要"
    echo "=========================================="
    echo -e "${RED}严重问题: $HIGH_ISSUES${NC}"
    echo -e "${YELLOW}中危问题: $MEDIUM_ISSUES${NC}"
    echo -e "${BLUE}总问题数: $TOTAL_ISSUES${NC}"
    echo ""
    echo "扫描结果目录: $OUTPUT_DIR"
    echo ""
    echo "生成的文件:"
    ls -la "$OUTPUT_DIR" 2>/dev/null | grep -v "^total\|^d" | while read line; do
        echo "  $line"
    done
    echo "=========================================="

    # 写入报告文件
    {
        echo "# Web安全扫描报告"
        echo ""
        echo "**扫描域名:** $TARGET_DOMAIN"
        echo "**扫描时间:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "---"
        echo ""
        echo "## 扫描结果统计"
        echo ""
        echo "| 级别 | 数量 |"
        echo "|------|------|"
        echo "| 高危 | $HIGH_ISSUES |"
        echo "| 中危 | $MEDIUM_ISSUES |"
        echo "| 总计 | $TOTAL_ISSUES |"
        echo ""
        echo "---"
        echo ""
        echo "## 扫描模块"
        echo ""
        echo "1. DNS解析检查"
        echo "2. SSL/TLS证书检查"
        echo "3. SSL加密套件检查"
        echo "4. HTTP安全头检查"
        echo "5. 端口扫描"
        echo "6. Web技术识别"
        echo "7. 敏感路径扫描"
        echo "8. 漏洞探测"
        echo ""
        echo "**报告文件:** $REPORT_FILE"
    } > "$REPORT_FILE"
}

# 主函数
main() {
    parse_args "$@"

    echo -e "${BLUE}"
    echo "=========================================="
    echo "    Web应用安全扫描工具 v1.0"
    echo "=========================================="
    echo -e "${NC}"

    echo -e "${GREEN}目标域名:${NC} $TARGET_DOMAIN"
    echo -e "${GREEN}目标URL:${NC}  $TARGET_URL"
    echo -e "${GREEN}输出目录:${NC} $OUTPUT_DIR"
    echo ""

    check_dependencies

    check_dns
    check_ssl_certificate
    check_ssl_ciphers
    check_security_headers
    check_ports
    check_web_technology
    check_sensitive_paths
    check_vulnerabilities

    generate_report
}

main "$@"
