#!/bin/bash
# 代码仓库安全扫描工具 v1.0
# 支持DOS检测、ReDoS检测、代码检查、不安全算法排查、Web安全规范、Trivy漏洞扫描、Gitleaks敏感信息扫描

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认配置
REPO_PATH=""
SKIP_TRIVY=false
SKIP_GITLEAKS=false
SKIP_SEMGREP=false

# 输出目录
REPORT_DIR="/tmp/repo_security_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# 报告文件
REPORT_FILE="$REPORT_DIR/security_report.md"

# 扫描结果统计
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# 显示帮助信息
show_help() {
    echo -e "${BLUE}代码仓库安全扫描工具 v1.0${NC}"
    echo ""
    echo "用法: $0 [选项] <仓库路径>"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示帮助信息"
    echo "  -r, --repo PATH     指定代码仓库路径"
    echo "  --skip-trivy        跳过trivy漏洞扫描"
    echo "  --skip-gitleaks     跳过gitleaks敏感信息扫描"
    echo "  --skip-semgrep      跳过semgrep代码检查"
    echo ""
    echo "示例:"
    echo "  $0 /path/to/repo                  # 扫描指定仓库"
    echo "  $0 -r /path/to/repo --skip-trivy  # 跳过trivy扫描"
    exit 0
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -r|--repo)
                [ -n "$2" ] && REPO_PATH="$2" && shift 2 || { echo -e "${RED}错误: --repo 需要参数${NC}"; exit 1; }
                ;;
            --skip-trivy) SKIP_TRIVY=true; shift ;;
            --skip-gitleaks) SKIP_GITLEAKS=true; shift ;;
            --skip-semgrep) SKIP_SEMGREP=true; shift ;;
            -*)
                echo -e "${RED}未知选项: $1${NC}"; show_help ;;
            *)
                REPO_PATH="$1"
                shift
                ;;
        esac
    done

    if [ -z "$REPO_PATH" ]; then
        echo -e "${RED}错误: 请指定代码仓库路径${NC}"
        show_help
    fi

    if [ ! -d "$REPO_PATH" ]; then
        echo -e "${RED}错误: 目录不存在: $REPO_PATH${NC}"
        exit 1
    fi
}

# 初始化报告
init_report() {
    echo "# 代码仓库安全扫描报告" > "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**扫描时间:** $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
    echo "**扫描路径:** $REPO_PATH" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
}

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; echo "- $1" >> "$REPORT_FILE"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; echo "  - ✅ $1" >> "$REPORT_FILE"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; echo "  - ⚠️ $1" >> "$REPORT_FILE"; MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1)); TOTAL_ISSUES=$((TOTAL_ISSUES + 1)); }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; echo "  - ❌ $1" >> "$REPORT_FILE"; HIGH_ISSUES=$((HIGH_ISSUES + 1)); TOTAL_ISSUES=$((TOTAL_ISSUES + 1)); }

# ==================== 工具安装检查 ====================
check_and_install_tools() {
    echo "" >> "$REPORT_FILE"
    echo "## 0. 工具检查与安装" >> "$REPORT_FILE"
    log_info "检查所需工具..."

    local tools_to_install=()

    # 检查trivy
    if [ "$SKIP_TRIVY" = false ]; then
        if ! command -v trivy &> /dev/null; then
            log_info "trivy 未安装，正在安装..."
            curl -sf https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.50.0 2>/dev/null
            if command -v trivy &> /dev/null; then
                log_success "trivy 安装成功"
            else
                log_warning "trivy 安装失败，跳过trivy扫描"
                SKIP_TRIVY=true
            fi
        else
            log_success "trivy 已安装: $(trivy --version 2>/dev/null | head -1)"
        fi
    fi

    # 检查gitleaks
    if [ "$SKIP_GITLEAKS" = false ]; then
        if ! command -v gitleaks &> /dev/null; then
            log_info "gitleaks 未安装，正在安装..."
            local gitleaks_url="https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz"
            curl -sSfL "$gitleaks_url" | tar -xz -C /usr/local/bin gitleaks 2>/dev/null
            if command -v gitleaks &> /dev/null; then
                log_success "gitleaks 安装成功"
            else
                log_warning "gitleaks 安装失败，跳过gitleaks扫描"
                SKIP_GITLEAKS=true
            fi
        else
            log_success "gitleaks 已安装: $(gitleaks version 2>/dev/null)"
        fi
    fi

    # 检查semgrep
    if [ "$SKIP_SEMGREP" = false ]; then
        if ! command -v semgrep &> /dev/null; then
            log_info "semgrep 未安装，正在安装..."
            pip install semgrep -q 2>/dev/null
            if command -v semgrep &> /dev/null; then
                log_success "semgrep 安装成功"
            else
                log_warning "semgrep 安装失败，跳过semgrep扫描"
                SKIP_SEMGREP=true
            fi
        else
            log_success "semgrep 已安装: $(semgrep --version 2>/dev/null | head -1)"
        fi
    fi
}

# ==================== 1. DOS检测 ====================
check_dos_vulnerabilities() {
    echo "" >> "$REPORT_FILE"
    echo "## 1. DOS漏洞检测" >> "$REPORT_FILE"
    log_info "开始检测DOS漏洞..."

    cd "$REPO_PATH" || return

    # Python - 检测无限循环和大文件读取
    local py_dos=$(grep -rn --include="*.py" -E "(while\s+True|while\s+1:|read\(\s*\)|readlines\(\s*\))" . 2>/dev/null | head -20 || true)
    if [ -n "$py_dos" ]; then
        log_warning "发现潜在的DOS风险代码 (Python)"
        echo "  发现位置:" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$py_dos" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    else
        log_success "未发现明显的DOS风险代码"
    fi

    # JavaScript - 检测无限循环和未限制解析
    local js_dos=$(grep -rn --include="*.js" --include="*.ts" -E "(while\s*\(true\)|while\s*\(1\)|JSON\.parse\([^)]*\)|\.readFile\([^,]+,\s*[^)]+\))" . 2>/dev/null | head -20 || true)
    if [ -n "$js_dos" ]; then
        log_warning "发现潜在的DOS风险代码 (JavaScript)"
        echo "  发现位置:" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$js_dos" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    fi

    # Go - 检测无限循环
    local go_dos=$(grep -rn --include="*.go" -E "for\s*\{\s*\}" . 2>/dev/null | head -20 || true)
    if [ -n "$go_dos" ]; then
        log_warning "发现潜在的无限循环 (Go)"
    fi
}

# ==================== 2. ReDoS检测 ====================
check_redos_vulnerabilities() {
    echo "" >> "$REPORT_FILE"
    echo "## 2. ReDoS漏洞检测" >> "$REPORT_FILE"
    log_info "开始检测ReDoS漏洞..."

    cd "$REPO_PATH" || return

    # 检测危险的正则表达式模式
    local redos_patterns='\)\s*\+\s*\)|\*\s*\.\s*\*|\(\.\*\)\+|\[[^\]]*\]\+\s*\+|\?\s*\+\s*\?'

    # Python正则
    local py_redos=$(grep -rn --include="*.py" -E "(re\.(compile|match|search|findall)\s*\(|RegExp\s*\()" . 2>/dev/null | grep -E "$redos_patterns" | head -20 || true)
    if [ -n "$py_redos" ]; then
        log_error "发现潜在的ReDoS漏洞 (Python)"
        echo "  危险正则表达式:" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$py_redos" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    fi

    # JavaScript正则
    local js_redos=$(grep -rn --include="*.js" --include="*.ts" -E "new\s+RegExp|/.+/" . 2>/dev/null | grep -E '(\)\+|\*\.\*|\+\+|\?\+)' | head -20 || true)
    if [ -n "$js_redos" ]; then
        log_error "发现潜在的ReDoS漏洞 (JavaScript)"
        echo "  危险正则表达式:" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$js_redos" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    fi

    if [ -z "$py_redos" ] && [ -z "$js_redos" ]; then
        log_success "未发现明显的ReDoS漏洞"
    fi
}

# ==================== 3. 代码检查 (Semgrep) ====================
check_code_quality() {
    echo "" >> "$REPORT_FILE"
    echo "## 3. 代码质量检查 (Semgrep)" >> "$REPORT_FILE"

    if [ "$SKIP_SEMGREP" = true ]; then
        log_info "跳过semgrep扫描"
        return
    fi

    log_info "开始Semgrep代码检查..."

    cd "$REPO_PATH" || return

    local semgrep_output="$REPORT_DIR/semgrep_report.json"

    if semgrep --config p/security-audit --config p/secrets --json --output "$semgrep_output" . 2>/dev/null; then
        local findings=$(cat "$semgrep_output" 2>/dev/null | grep -o '"results":\[' 2>/dev/null || true)

        if [ -n "$findings" ]; then
            local count=$(cat "$semgrep_output" 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data.get('results', [])))" 2>/dev/null || echo "0")

            if [ "$count" -gt 0 ]; then
                log_warning "Semgrep发现 $count 个问题"
                echo "  详细报告: \`$semgrep_output\`" >> "$REPORT_FILE"
            else
                log_success "Semgrep未发现问题"
            fi
        else
            log_success "Semgrep未发现问题"
        fi
    else
        log_warning "Semgrep扫描失败"
    fi
}

# ==================== 4. 不安全算法排查 ====================
check_insecure_algorithms() {
    echo "" >> "$REPORT_FILE"
    echo "## 4. 不安全算法排查" >> "$REPORT_FILE"
    log_info "开始检测不安全加密算法..."

    cd "$REPO_PATH" || return

    local insecure_found=false

    # Python不安全算法
    local py_weak=$(grep -rn --include="*.py" -iE "(hashlib\.(md5|sha1)|MD5|SHA1|DES|RC4|Blowfish|ECB|from\s+Crypto\.Cipher\s+import\s+DES|from\s+Crypto\.Cipher\s+import\s+ARC4)" . 2>/dev/null | head -20 || true)
    if [ -n "$py_weak" ]; then
        log_error "发现不安全算法使用 (Python)"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$py_weak" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        insecure_found=true
    fi

    # JavaScript不安全算法
    local js_weak=$(grep -rn --include="*.js" --include="*.ts" -iE "(createHash\s*\(\s*['\"]md5['\"]|createHash\s*\(\s*['\"]sha1['\"]|createCipher\s*\(\s*['\"]des|createCipheriv\s*\(\s*['\"]des|MD5|SHA1|RC4)" . 2>/dev/null | head -20 || true)
    if [ -n "$js_weak" ]; then
        log_error "发现不安全算法使用 (JavaScript)"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$js_weak" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        insecure_found=true
    fi

    # Go不安全算法
    local go_weak=$(grep -rn --include="*.go" -iE "(md5\.New|sha1\.New|des\.NewCipher|crypto/md5|crypto/sha1)" . 2>/dev/null | head -20 || true)
    if [ -n "$go_weak" ]; then
        log_error "发现不安全算法使用 (Go)"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$go_weak" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        insecure_found=true
    fi

    # Java不安全算法
    local java_weak=$(grep -rn --include="*.java" -iE "(MessageDigest\.getInstance\s*\(\s*['\"]MD5|MessageDigest\.getInstance\s*\(\s*['\"]SHA-1|Cipher\.getInstance\s*\(\s*['\"]DES|Cipher\.getInstance\s*\(\s*['\"]RC4)" . 2>/dev/null | head -20 || true)
    if [ -n "$java_weak" ]; then
        log_error "发现不安全算法使用 (Java)"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$java_weak" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        insecure_found=true
    fi

    if [ "$insecure_found" = false ]; then
        log_success "未发现不安全加密算法"
    fi
}

# ==================== 5. Web应用安全规范 ====================
check_web_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 5. Web应用安全检查" >> "$REPORT_FILE"
    log_info "开始检测Web应用安全问题..."

    cd "$REPO_PATH" || return

    # SQL注入检测
    log_info "检测SQL注入..."
    local sql_injection=$(grep -rn --include="*.py" --include="*.php" --include="*.java" --include="*.js" -iE "(\+.*SELECT|\+.*INSERT|\+.*UPDATE|\+.*DELETE|execute\s*\(|exec\s*\(|query\s*\(.+\s*\+|f\".*SELECT|f'.*SELECT|String\.format.*SELECT)" . 2>/dev/null | head -20 || true)
    if [ -n "$sql_injection" ]; then
        log_error "发现潜在SQL注入风险"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$sql_injection" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    else
        log_success "未发现明显SQL注入风险"
    fi

    # XSS检测
    log_info "检测XSS漏洞..."
    local xss=$(grep -rn --include="*.py" --include="*.php" --include="*.js" -iE "(innerHTML\s*=|document\.write\(|Response\.write\(|echo\s*<|print\s*<|render_template_string|safe_filter|mark_safe)" . 2>/dev/null | head -20 || true)
    if [ -n "$xss" ]; then
        log_warning "发现潜在XSS风险"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$xss" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    else
        log_success "未发现明显XSS风险"
    fi

    # 命令注入检测
    log_info "检测命令注入..."
    local cmd_injection=$(grep -rn --include="*.py" --include="*.php" --include="*.go" --include="*.java" -iE "(os\.system|subprocess\.call|subprocess\.Popen|exec\(|eval\(|shell_exec|Runtime\.getRuntime\(\)|exec\.Command)" . 2>/dev/null | head -20 || true)
    if [ -n "$cmd_injection" ]; then
        log_error "发现潜在命令注入风险"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$cmd_injection" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    else
        log_success "未发现明显命令注入风险"
    fi

    # 路径遍历检测
    log_info "检测路径遍历..."
    local path_traversal=$(grep -rn --include="*.py" --include="*.php" --include="*.java" -iE "(open\s*\(.+\+|readFile\s*\(.+\+|fopen\s*\(.+\+|File\s*\(.+\+|\.read\(.+request|\.read\(.+input)" . 2>/dev/null | head -20 || true)
    if [ -n "$path_traversal" ]; then
        log_warning "发现潜在路径遍历风险"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$path_traversal" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    else
        log_success "未发现明显路径遍历风险"
    fi
}

# ==================== 6. Trivy漏洞扫描 ====================
check_trivy_scan() {
    echo "" >> "$REPORT_FILE"
    echo "## 6. Trivy漏洞扫描" >> "$REPORT_FILE"

    if [ "$SKIP_TRIVY" = true ]; then
        log_info "跳过trivy扫描"
        return
    fi

    log_info "开始Trivy漏洞扫描..."

    cd "$REPO_PATH" || return

    local trivy_output="$REPORT_DIR/trivy_report.json"

    if trivy fs --format json --output "$trivy_output" --quiet . 2>/dev/null; then
        local vuln_count=$(cat "$trivy_output" 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); results=data.get('Results',[]); print(sum(len(r.get('Vulnerabilities',[])) for r in results))" 2>/dev/null || echo "0")

        if [ "$vuln_count" -gt 0 ]; then
            log_warning "Trivy发现 $vuln_count 个漏洞"
            echo "  详细报告: \`$trivy_output\`" >> "$REPORT_FILE"

            # 显示高危漏洞摘要
            local critical=$(cat "$trivy_output" 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); results=data.get('Results',[]); print(sum(1 for r in results for v in r.get('Vulnerabilities',[]) if v.get('Severity','')=='CRITICAL'))" 2>/dev/null || echo "0")
            local high=$(cat "$trivy_output" 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); results=data.get('Results',[]); print(sum(1 for r in results for v in r.get('Vulnerabilities',[]) if v.get('Severity','')=='HIGH'))" 2>/dev/null || echo "0")

            echo "  - 严重: $critical" >> "$REPORT_FILE"
            echo "  - 高危: $high" >> "$REPORT_FILE"
        else
            log_success "Trivy未发现漏洞"
        fi
    else
        log_warning "Trivy扫描失败"
    fi
}

# ==================== 7. Gitleaks敏感信息扫描 ====================
check_gitleaks_scan() {
    echo "" >> "$REPORT_FILE"
    echo "## 7. Gitleaks敏感信息扫描" >> "$REPORT_FILE"

    if [ "$SKIP_GITLEAKS" = true ]; then
        log_info "跳过gitleaks扫描"
        return
    fi

    log_info "开始Gitleaks敏感信息扫描..."

    cd "$REPO_PATH" || return

    local gitleaks_output="$REPORT_DIR/gitleaks_report.json"

    if gitleaks detect --source . --report-path "$gitleaks_output" --report-format json --no-git -q 2>/dev/null; then
        log_success "Gitleaks未发现敏感信息泄露"
    else
        if [ -f "$gitleaks_output" ]; then
            local leak_count=$(cat "$gitleaks_output" 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

            if [ "$leak_count" -gt 0 ]; then
                log_error "Gitleaks发现 $leak_count 个敏感信息泄露"
                echo "  详细报告: \`$gitleaks_output\`" >> "$REPORT_FILE"
            else
                log_success "Gitleaks未发现敏感信息泄露"
            fi
        else
            log_warning "Gitleaks扫描异常"
        fi
    fi
}

# ==================== 8. Nginx安全规范专项检查(48项) ====================
check_nginx_security_spec() {
    echo "" >> "$REPORT_FILE"
    echo "## 8. Nginx安全规范专项检查 (48项)" >> "$REPORT_FILE"
    log_info "开始检查Nginx安全规范..."

    cd "$REPO_PATH" || return

    # 查找所有nginx配置文件
    local nginx_files=$(find . -type f \( -name "*.conf" -o -name "nginx.conf" \) 2>/dev/null | head -20)

    if [ -z "$nginx_files" ]; then
        log_info "未发现Nginx配置文件"
        return
    fi

    for conf_file in $nginx_files; do
        echo "### 配置文件: $conf_file" >> "$REPORT_FILE"
        local config=$(cat "$conf_file" 2>/dev/null || true)

        if [ -z "$config" ]; then
            continue
        fi

        # 规范1: 缺省文件检查
        if echo "$conf_file" | grep -qE "default\.conf|default\.conf$"; then
            log_warning "发现缺省配置文件: $conf_file (规范1)"
        fi

        # 规范4: 绑定特定IP
        if echo "$config" | grep -E "listen\s+(\*:|\[::\]:|0\.0\.0\.0:)" > /dev/null 2>&1; then
            log_error "$conf_file: 监听地址绑定到通配符 (规范4)"
        else
            log_success "$conf_file: 监听地址已绑定特定IP (规范4)"
        fi

        # 规范5: 禁用SSI
        if echo "$config" | grep -E "ssi\s+on" > /dev/null 2>&1; then
            log_error "$conf_file: SSI功能已启用 (规范5)"
        else
            log_success "$conf_file: SSI功能已禁用 (规范5)"
        fi

        # 规范6: 运行用户
        local nginx_user=$(echo "$config" | grep -E "^\s*user\s+" | head -1 | awk '{print $2}' | tr -d ';')
        if [ -n "$nginx_user" ] && [ "$nginx_user" != "root" ]; then
            log_success "$conf_file: 运行用户 $nginx_user (规范6)"
        else
            log_error "$conf_file: 运行用户为root或未配置 (规范6)"
        fi

        # 规范15: alias配置安全
        if echo "$config" | grep -E "alias\s+[^;]*[^/];" > /dev/null 2>&1; then
            log_error "$conf_file: alias配置可能存在路径遍历风险 (规范15)"
        else
            log_success "$conf_file: alias配置安全 (规范15)"
        fi

        # 规范17: 禁用不必要的HTTP方法
        if echo "$config" | grep -E "if\s*\(\$request_method\s*~\s*\".*(TRACE|OPTIONS)" > /dev/null 2>&1; then
            log_success "$conf_file: 已限制不必要的HTTP方法 (规范17)"
        else
            log_error "$conf_file: 未限制TRACE/OPTIONS方法 (规范17)"
        fi

        # SSL/TLS检查
        if echo "$config" | grep -E "listen\s+.*ssl|listen\s+.*443" > /dev/null 2>&1; then
            # 规范21: 启用SSL
            log_success "$conf_file: 已启用SSL功能 (规范21)"

            # 规范22: TLS协议版本
            if echo "$config" | grep -E "ssl_protocols.*SSLv2|ssl_protocols.*SSLv3|ssl_protocols.*TLSv1[^\.]" > /dev/null 2>&1; then
                log_error "$conf_file: 使用不安全的TLS协议 (规范22)"
            else
                log_success "$conf_file: TLS协议版本安全 (规范22)"
            fi

            # 规范23: 加密套件
            if echo "$config" | grep -iE "ssl_ciphers.*(RC4|DES|3DES|MD5|NULL)" > /dev/null 2>&1; then
                log_error "$conf_file: 使用不安全的加密套件 (规范23)"
            else
                log_success "$conf_file: 加密套件配置安全 (规范23)"
            fi

            # 规范25-26: SSL会话配置
            echo "$config" | grep -E "ssl_session_timeout" > /dev/null 2>&1 && log_success "$conf_file: 已配置SSL会话超时 (规范25)" || log_warning "$conf_file: 未配置ssl_session_timeout (规范25)"
            echo "$config" | grep -E "ssl_session_cache" > /dev/null 2>&1 && log_success "$conf_file: 已配置SSL会话缓存 (规范26)" || log_warning "$conf_file: 未配置ssl_session_cache (规范26)"
            echo "$config" | grep -E "ssl_session_tickets\s+off" > /dev/null 2>&1 && log_success "$conf_file: 已禁用SSL会话tickets (规范41)" || log_warning "$conf_file: 未禁用ssl_session_tickets (规范41)"
        fi

        # 规范28: 网络超时
        local timeout_ok=true
        for setting in client_body_timeout client_header_timeout keepalive_timeout send_timeout; do
            echo "$config" | grep -E "$setting" > /dev/null 2>&1 || timeout_ok=false
        done
        [ "$timeout_ok" = true ] && log_success "$conf_file: 已配置网络超时 (规范28)" || log_warning "$conf_file: 网络超时配置不完整 (规范28)"

        # 规范30: 请求体大小限制
        echo "$config" | grep -E "client_max_body_size" > /dev/null 2>&1 && log_success "$conf_file: 已限制请求体大小 (规范30)" || log_error "$conf_file: 未配置client_max_body_size (规范30)"

        # 规范38: 隐藏版本信息
        echo "$config" | grep -E "server_tokens\s+off" > /dev/null 2>&1 && log_success "$conf_file: server_tokens 已关闭 (规范38)" || log_error "$conf_file: server_tokens 未关闭 (规范38)"

        # 规范39: 禁用目录列表
        echo "$config" | grep -E "autoindex\s+on" > /dev/null 2>&1 && log_error "$conf_file: 启用了目录列表 (规范39)" || log_success "$conf_file: 未启用目录列表 (规范39)"

        # 规范42: 日志配置
        echo "$config" | grep -E "access_log" | grep -v "off" > /dev/null 2>&1 && log_success "$conf_file: 已开启访问日志 (规范42)" || log_error "$conf_file: 未开启访问日志 (规范42)"
        echo "$config" | grep -E "error_log" | grep -v "off" > /dev/null 2>&1 && log_success "$conf_file: 已开启错误日志 (规范42)" || log_error "$conf_file: 未开启错误日志 (规范42)"

        # 规范44: CRLF注入防护
        if echo "$config" | grep -E 'rewrite.*\$uri|return.*\$uri' > /dev/null 2>&1; then
            log_error "$conf_file: 使用\$uri可能导致CRLF注入 (规范44)"
        else
            log_success "$conf_file: CRLF注入防护安全 (规范44)"
        fi

        # 规范45: 安全响应头
        for header in X-Frame-Options X-Content-Type-Options X-XSS-Protection Strict-Transport-Security Content-Security-Policy; do
            echo "$config" | grep -qi "add_header\s+$header" > /dev/null 2>&1 && log_success "$conf_file: 已配置 $header (规范45)" || log_error "$conf_file: 未配置 $header (规范45)"
        done

        # 建议项检查
        # 规范19: 限制访问IP
        echo "$config" | grep -E "allow\s+[0-9]+\.|deny\s+all" > /dev/null 2>&1 && log_success "$conf_file: 已配置IP访问限制 (规范19)" || log_warning "$conf_file: 未配置IP访问限制 (规范19-建议)"

        # 规范29: 连接数限制
        echo "$config" | grep -E "limit_conn" > /dev/null 2>&1 && log_success "$conf_file: 已配置连接数限制 (规范29)" || log_warning "$conf_file: 未配置连接数限制 (规范29-建议)"

        # 规范33: 速率限制
        echo "$config" | grep -E "limit_req" > /dev/null 2>&1 && log_success "$conf_file: 已配置请求速率限制 (规范33)" || log_warning "$conf_file: 未配置请求速率限制 (规范33-建议)"

        # 规范36: 隐藏文件服务
        echo "$config" | grep -E "location\s+~\s*/\." > /dev/null 2>&1 && log_success "$conf_file: 已配置拒绝隐藏文件访问 (规范36)" || log_warning "$conf_file: 未配置拒绝隐藏文件访问 (规范36-建议)"
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
    echo "    代码仓库安全扫描工具 v1.0"
    echo "========================================"
    echo -e "${NC}"

    echo -e "${BLUE}目标仓库:${NC} ${GREEN}$REPO_PATH${NC}"
    echo ""

    init_report

    check_and_install_tools
    check_dos_vulnerabilities
    check_redos_vulnerabilities
    check_code_quality
    check_insecure_algorithms
    check_web_security
    check_trivy_scan
    check_gitleaks_scan
    check_nginx_security_spec

    generate_summary
}

main "$@"
