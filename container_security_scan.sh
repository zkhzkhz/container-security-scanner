#!/bin/bash
# 容器安全扫描工具 v2.4
# 基于安全规范要求的多项安全检查
# 默认只扫描容器环境，支持指定特定容器
# 支持Docker和crictl(containerd/CRI)两种容器运行时
# 详细输出每个检查项的执行命令、原始结果和分析结论

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 扫描模式
SCAN_MODE="${SCAN_MODE:-container}"

# 指定扫描的容器名称
TARGET_CONTAINERS=""

# 容器运行时 (auto/docker/crictl)
CONTAINER_RUNTIME=""
# 是否安装工具
INSTALL_TOOLS=true

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
    echo -e "${BLUE}容器安全扫描工具 v2.4${NC}"
    echo ""
    echo "用法: $0 [选项] [容器名称...]"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示帮助信息"
    echo "  -a, --all           扫描所有运行中的容器(默认)"
    echo "  -l, --list          列出所有运行中的容器"
    echo "  -r, --runtime       指定容器运行时: auto(默认)/docker/crictl"
    echo "  -m, --mode MODE     设置扫描模式: container(默认)/host/all"
    echo "  --skip-install      跳过容器内工具安装"
    echo ""
    echo "扫描模块:"
    echo "  1.  全零IP暴露检查"
    echo "  2.  SSL/TLS证书检查"
    echo "  3.  加密套件检查"
    echo "  4.  敏感信息泄露检查"
    echo "  5.  Nginx安全规范专项检查(48项)"
    echo "  6.  端口暴露检查"
    echo "  7.  容器安全基线检查"
    echo "  8.  镜像安全检查"
    echo "  9.  MD5密码安全检查"
    echo "  10. 安全工具残留检查"
    echo "  11. 调试工具扫描"
    echo "  12. 用户权限检查"
    echo "  13. 文件权限检查"
    echo "  14. 暴力破解防护检查"
    echo "  15. 不安全函数检查"
    echo ""
    echo "示例:"
    echo "  $0                        # 扫描所有容器"
    echo "  $0 nginx mysql            # 仅扫描nginx和mysql容器"
    echo "  $0 -r crictl              # 使用crictl运行时扫描"
    echo "  $0 -l                     # 列出所有容器"
    echo "  $0 --skip-install         # 跳过工具安装"
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

# 在容器内安装必要工具
install_container_tools() {
    local container="$1"

    log_info "检查容器 [$container] 必要工具..."

    # 检测包管理器并安装工具
    local pkg_manager=""
    local install_cmd=""

    # 检测apt (Debian/Ubuntu)
    if container_exec "$container" "which apt-get 2>/dev/null" >/dev/null 2>&1; then
        pkg_manager="apt"
        install_cmd="apt-get update -qq && apt-get install -y -qq coreutils findutils grep gawk"
    # 检测yum (CentOS/RHEL)
    elif container_exec "$container" "which yum 2>/dev/null" >/dev/null 2>&1; then
        pkg_manager="yum"
        install_cmd="yum install -y -q coreutils findutils grep gawk"
    # 检测apk (Alpine)
    elif container_exec "$container" "which apk 2>/dev/null" >/dev/null 2>&1; then
        pkg_manager="apk"
        install_cmd="apk add --no-cache coreutils findutils grep gawk"
    # 检测dnf (Fedora)
    elif container_exec "$container" "which dnf 2>/dev/null" >/dev/null 2>&1; then
        pkg_manager="dnf"
        install_cmd="dnf install -y -q coreutils findutils grep gawk"
    fi

    # 检查必要工具是否存在
    local tools_missing=false
    for tool in find stat grep awk; do
        if ! container_exec "$container" "which $tool 2>/dev/null" >/dev/null 2>&1; then
            tools_missing=true
            break
        fi
    done

    if [ "$tools_missing" = true ] && [ -n "$pkg_manager" ]; then
        log_info "容器 [$container] 缺少必要工具，尝试临时安装 ($pkg_manager)..."
        container_exec "$container" "$install_cmd" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_success "容器 [$container] 工具安装成功"
        else
            log_warning "容器 [$container] 工具安装失败，部分检查可能不完整"
        fi
    else
        log_success "容器 [$container] 必要工具已存在"
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
            --skip-install) INSTALL_TOOLS=false; shift ;;
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

# 详细日志函数 - 显示执行的命令和结果
log_cmd() {
    local desc="$1"
    local cmd="$2"
    echo -e "${BLUE}[CMD]${NC} $desc"
    echo "  执行命令: \`$cmd\`" >> "$REPORT_FILE"
}
log_result() {
    local result="$1"
    local len=${#result}
    if [ $len -gt 100 ]; then
        echo -e "  ${CYAN}→ 结果:${NC} ${result:0:100}..."
    else
        echo -e "  ${CYAN}→ 结果:${NC} $result"
    fi
    echo "  结果: $result" >> "$REPORT_FILE"
}
log_detail() {
    echo -e "    ${CYAN}$1${NC}"
    echo "    $1" >> "$REPORT_FILE"
}

# ==================== 1. 全零IP暴露检查 ====================
check_zero_ip_exposure() {
    echo "" >> "$REPORT_FILE"
    echo "## 1. 全零IP暴露检查 (Nginx_2_2_6)" >> "$REPORT_FILE"
    log_info "开始检查容器内的 0.0.0.0 绑定..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # ===== 外部端口映射检查 =====
        log_info "=== 外部端口映射检查 ==="
        local cmd="docker port $container 2>/dev/null || crictl port $container 2>/dev/null"
        log_cmd "查询容器端口映射" "$cmd"

        local ports=$(container_port "$container" 2>/dev/null)
        local port_result="${ports:-无端口映射}"

        echo -e "  ${CYAN}→ 原始结果:${NC}"
        echo "  \`\`\`" >> "$REPORT_FILE"
        echo "$port_result" | while read line; do
            [ -n "$line" ] && echo -e "    ${CYAN}$line${NC}" && echo "    $line" >> "$REPORT_FILE"
        done
        echo "  \`\`\`" >> "$REPORT_FILE"

        # 分析外部端口映射
        if echo "$ports" | grep -q "0.0.0.0"; then
            local bind_ports=$(echo "$ports" | grep "0.0.0.0" | awk '{print $1}' | tr '\n' ' ')
            log_error "容器 [$container] 外部端口绑定到 0.0.0.0"
            log_detail "暴露端口: $bind_ports"
            log_detail "风险说明: 0.0.0.0绑定允许任意IP访问"
        else
            log_success "容器 [$container] 外部端口映射安全"
        fi

        # ===== 容器内部监听端口检查 =====
        echo ""
        log_info "=== 容器内部监听端口检查 ==="
        log_cmd "netstat -tunlp 2>/dev/null || ss -tunlp" "获取容器内部监听端口"

        local listen_ports=$(container_exec "$container" "netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null" || true)

        if [ -n "$listen_ports" ]; then
            echo -e "  ${CYAN}→ 容器内部监听端口:${NC}"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$listen_ports" >> "$REPORT_FILE"
            echo "  \`\`\`" >> "$REPORT_FILE"

            # 检查监听地址
            echo "$listen_ports" | grep -E "0\.0\.0\.0:|:::" | while read line; do
                local addr=$(echo "$line" | awk '{print $4}')
                local pid=$(echo "$line" | awk '{print $7}')
                if [[ "$addr" == 0.0.0.0* ]] || [[ "$addr" == ::* ]]; then
                    log_warning "容器内部监听 0.0.0.0: $addr (进程: $pid)"
                    log_detail "说明: 这是容器内部监听，K8s环境下正常行为"
                fi
            done
        else
            log_info "容器 [$container] 无法获取内部监听端口"
        fi
    done
}

# ==================== 2. SSL/TLS证书检查 ====================
check_ssl_certificates() {
    echo "" >> "$REPORT_FILE"
    echo "## 2. SSL/TLS证书检查" >> "$REPORT_FILE"
    log_info "开始检查容器内证书..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # 查找证书文件
        local cmd="find /etc /usr /opt -name '*.pem' -o -name '*.crt' -o -name '*.key' 2>/dev/null"
        log_cmd "查找证书文件" "$cmd"

        local certs=$(container_exec "$container" "find /etc /usr /opt -name '*.pem' -o -name '*.crt' 2>/dev/null | head -10" 2>/dev/null || true)

        if [ -n "$certs" ]; then
            local cert_count=$(echo "$certs" | wc -l)
            log_info "容器 [$container] 发现 $cert_count 个证书文件:"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$certs" | while read cert; do
                if [ -n "$cert" ]; then
                    echo -e "    ${CYAN}$cert${NC}"
                    echo "    $cert" >> "$REPORT_FILE"

                    # 检查证书详情
                    local cert_info=$(container_exec "$container" "openssl x509 -in '$cert' -noout -dates -subject 2>/dev/null" || true)
                    if [ -n "$cert_info" ]; then
                        echo -e "      ${CYAN}证书信息:${NC}"
                        echo "$cert_info" | while read line; do
                            echo -e "        ${CYAN}$line${NC}"
                            echo "        $line" >> "$REPORT_FILE"
                        done

                        # 检查证书是否过期
                        local end_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
                        if [ -n "$end_date" ]; then
                            local expire_epoch=$(date -d "$end_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$end_date" +%s 2>/dev/null || echo "0")
                            local now_epoch=$(date +%s)
                            if [ "$expire_epoch" != "0" ] && [ "$expire_epoch" -lt "$now_epoch" ]; then
                                log_error "证书已过期: $cert"
                                log_detail "过期时间: $end_date"
                            elif [ "$expire_epoch" != "0" ] && [ "$((expire_epoch - now_epoch))" -lt "2592000" ]; then
                                log_warning "证书即将过期(30天内): $cert"
                                log_detail "过期时间: $end_date"
                            else
                                log_success "证书有效期正常: $cert"
                            fi
                        fi
                    fi
                fi
            done
            echo "  \`\`\`" >> "$REPORT_FILE"
        else
            log_info "容器 [$container] 未发现证书文件"
            log_detail "可能不涉及HTTPS服务或证书挂载在其他位置"
        fi
    done
}

# ==================== 3. 加密套件检查 ====================
check_cipher_suites() {
    echo "" >> "$REPORT_FILE"
    echo "## 3. 加密套件检查 (Nginx_2_7_4)" >> "$REPORT_FILE"
    log_info "开始检查加密套件配置..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # 多种方式检测Nginx
        log_cmd "which nginx || find / -name nginx -type f 2>/dev/null | head -3" "检查Nginx安装"
        local nginx_check=$(container_exec "$container" "which nginx 2>/dev/null || find /usr /etc /opt -name 'nginx' -type f 2>/dev/null | head -1" || true)

        # 如果which找不到，尝试通过进程检测
        if [ -z "$nginx_check" ]; then
            local nginx_proc=$(container_exec "$container" "ps aux 2>/dev/null | grep -E '[n]ginx' | head -1" || true)
            if [ -n "$nginx_proc" ]; then
                log_info "容器 [$container] 通过进程检测到Nginx运行中"
                log_detail "$nginx_proc"
                nginx_check="running"
            fi
        fi

        # 尝试直接执行nginx命令检测
        if [ -z "$nginx_check" ]; then
            local nginx_test=$(container_exec "$container" "nginx -v 2>&1" || true)
            if echo "$nginx_test" | grep -qi "nginx version"; then
                log_info "容器 [$container] 检测到Nginx: $nginx_test"
                nginx_check="detected"
            fi
        fi

        if [ -n "$nginx_check" ]; then
            log_info "容器 [$container] 发现Nginx: $nginx_check"

            # 获取Nginx版本
            log_cmd "nginx -v" "获取Nginx版本"
            local nginx_ver=$(container_exec "$container" "nginx -v 2>&1" || true)
            log_result "$nginx_ver"

            # 获取Nginx配置中的SSL加密套件
            log_cmd "nginx -T 2>/dev/null | grep -iE 'ssl_(cipher|protocol|prefer)'" "获取SSL配置"
            local ssl_config=$(container_exec "$container" "nginx -T 2>/dev/null | grep -iE 'ssl_(cipher|protocol|prefer)'" 2>/dev/null || true)

            if [ -n "$ssl_config" ]; then
                echo -e "  ${CYAN}→ SSL配置:${NC}"
                echo "  \`\`\`nginx" >> "$REPORT_FILE"
                echo "$ssl_config" | while read line; do
                    [ -n "$line" ] && echo -e "    ${CYAN}$line${NC}" && echo "    $line" >> "$REPORT_FILE"
                done
                echo "  \`\`\`" >> "$REPORT_FILE"

                # 分析加密套件安全性
                local found_weak=false
                local weak_ciphers=""

                for weak in RC4 DES 3DES MD5 NULL EXPORT aNULL SHA; do
                    if echo "$ssl_config" | grep -qi "$weak"; then
                        found_weak=true
                        weak_ciphers="$weak_ciphers $weak"
                    fi
                done

                if [ "$found_weak" = true ]; then
                    log_error "容器 [$container] 发现弱加密套件"
                    log_detail "弱算法: $weak_ciphers"
                    log_detail "建议: 使用 ECDHE+AESGCM 加密套件，禁用弱算法"
                else
                    log_success "容器 [$container] 未发现弱加密套件"
                fi

                # 检查SSL协议版本
                if echo "$ssl_config" | grep -qi "SSLv3\|TLSv1\|TLSv1.1"; then
                    log_warning "容器 [$container] 启用了不安全的SSL/TLS协议版本"
                    log_detail "建议: 仅启用 TLSv1.2 和 TLSv1.3"
                fi
            else
                log_info "容器 [$container] 未找到SSL配置"
                log_detail "可能未配置HTTPS或配置文件位置不同"
            fi
        else
            log_info "容器 [$container] 未安装Nginx，跳过检查"
        fi
    done
}

# ==================== 4. 敏感信息检查 ====================
check_sensitive_info() {
    echo "" >> "$REPORT_FILE"
    echo "## 4. 敏感信息泄露检查" >> "$REPORT_FILE"
    log_info "开始检查容器内敏感信息..."

    local patterns="password passwd secret api_key token private_key access_key secret_key credential auth_key"

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # 检查环境变量
        log_cmd "env" "获取容器环境变量"
        local env_output=$(container_exec "$container" "env 2>/dev/null" || true)

        echo -e "  ${CYAN}→ 环境变量数量: $(echo "$env_output" | wc -l)${NC}"

        local found_sensitive=false
        for pattern in $patterns; do
            local found=$(echo "$env_output" | grep -i "$pattern" || true)
            if [ -n "$found" ]; then
                log_warning "容器 [$container] 发现敏感环境变量关键字: $pattern"
                echo "  \`\`\`" >> "$REPORT_FILE"
                echo "$found" | while read line; do
                    # 隐藏敏感值
                    local masked=$(echo "$line" | sed 's/=.*/=***(已隐藏)***/g')
                    echo -e "    ${CYAN}$masked${NC}"
                    echo "    $masked" >> "$REPORT_FILE"
                done
                echo "  \`\`\`" >> "$REPORT_FILE"
                log_detail "风险: 敏感信息可能通过环境变量泄露"
                found_sensitive=true
            fi
        done

        [ "$found_sensitive" = false ] && log_success "容器 [$container] 未发现敏感环境变量"

        # SSH私钥检查
        echo ""
        log_cmd "find / -name 'id_rsa' -o -name 'id_dsa' -o -name '*.pem' -o -name '*.key'" "查找SSH私钥和证书文件"
        local keys=$(container_exec "$container" "find / \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ed25519' \) -type f 2>/dev/null | head -10" || true)

        if [ -n "$keys" ]; then
            log_warning "容器 [$container] 发现SSH私钥:"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$keys" | while read key; do
                if [ -n "$key" ]; then
                    echo -e "    ${CYAN}$key${NC}"
                    echo "    $key" >> "$REPORT_FILE"
                    # 检查私钥权限
                    local key_perm=$(container_exec "$container" "stat -c '%a %U:%G' '$key' 2>/dev/null" || true)
                    if [ -n "$key_perm" ]; then
                        log_detail "权限: $key_perm"
                        if [[ "$key_perm" == 6* ]] || [[ "$key_perm" == 77* ]]; then
                            log_error "私钥权限过宽，可能被其他用户读取"
                        fi
                    fi
                fi
            done
            echo "  \`\`\`" >> "$REPORT_FILE"
        else
            log_success "容器 [$container] 未发现SSH私钥"
        fi

        # 检查敏感配置文件
        echo ""
        log_cmd "find / -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.yaml' -o -name '*.yml'" "查找配置文件"
        local config_files=$(container_exec "$container" "find /opt /etc /app /home -type f \( -name 'application.yml' -o -name 'application.yaml' -o -name 'config.yml' -o -name 'settings.py' \) 2>/dev/null | head -10" || true)

        if [ -n "$config_files" ]; then
            log_info "容器 [$container] 发现敏感配置文件:"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$config_files" | while read cf; do
                [ -n "$cf" ] && echo -e "    ${CYAN}$cf${NC}" && echo "    $cf" >> "$REPORT_FILE"
            done
            echo "  \`\`\`" >> "$REPORT_FILE"
        fi
    done
}

# ==================== 5. Nginx安全规范专项检查(48项) ====================
check_nginx_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 5. Nginx安全规范专项检查 (48项)" >> "$REPORT_FILE"
    log_info "开始检查Nginx安全规范..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # 多种方式检测Nginx
        log_cmd "which nginx || find / -name nginx -type f 2>/dev/null" "检查Nginx安装"
        local nginx_check=$(container_exec "$container" "which nginx 2>/dev/null || find /usr /etc /opt -name 'nginx' -type f 2>/dev/null | head -1" || true)

        # 如果which找不到，尝试通过进程检测
        if [ -z "$nginx_check" ]; then
            local nginx_proc=$(container_exec "$container" "ps aux 2>/dev/null | grep -E '[n]ginx' | head -1" || true)
            if [ -n "$nginx_proc" ]; then
                log_info "容器 [$container] 通过进程检测到Nginx运行中"
                log_detail "$nginx_proc"
                nginx_check="running"
            fi
        fi

        # 尝试直接执行nginx命令检测
        if [ -z "$nginx_check" ]; then
            local nginx_test=$(container_exec "$container" "nginx -v 2>&1" || true)
            if echo "$nginx_test" | grep -qi "nginx version"; then
                log_info "容器 [$container] 检测到Nginx"
                nginx_check="detected"
            fi
        fi

        if [ -z "$nginx_check" ]; then
            log_info "容器 [$container] 未安装Nginx，跳过检查"
            continue
        fi

        log_info "容器 [$container] 发现Nginx: $nginx_check"

        # 获取Nginx版本
        log_cmd "nginx -v" "获取Nginx版本"
        local nginx_version=$(container_exec "$container" "nginx -v 2>&1" || true)
        log_result "$nginx_version"

        # 获取完整配置
        log_cmd "nginx -T" "获取Nginx完整配置"
        local config=$(container_exec "$container" sh -c "nginx -T 2>/dev/null" 2>/dev/null || true)
        local config_lines=$(echo "$config" | wc -l)
        log_result "配置行数: $config_lines"

        # 显示关键配置片段
        echo "  \`\`\`nginx" >> "$REPORT_FILE"
        echo "# 关键配置片段:" >> "$REPORT_FILE"
        echo "$config" | grep -E "^\s*(server\s*\{|listen\s+|server_name\s+|ssl_|location\s+)" | head -30 | while read line; do
            echo "  $line" >> "$REPORT_FILE"
        done
        echo "  \`\`\`" >> "$REPORT_FILE"

        # ========== 安装安全检查 ==========
        echo ""
        log_info "=== 安装安全检查 ==="

        # 规范1: 删除缺省文件
        log_cmd "test -f /etc/nginx/conf.d/default.conf" "检查缺省配置文件"
        local default_files="/etc/nginx/conf.d/default.conf /usr/share/nginx/html/index.html"
        for f in $default_files; do
            if container_exec "$container" test -f "$f" 2>/dev/null; then
                log_warning "容器 [$container] 存在缺省文件: $f (规范1)"
                log_detail "风险: 缺省文件可能泄露服务器信息"
            fi
        done

        # 规范2: 检查模块数量
        log_cmd "nginx -V 2>&1 | grep -o 'with-' | wc -l" "检查编译模块数"
        local module_count=$(container_exec "$container" nginx -V 2>&1 | grep -o "with-" | wc -l)
        log_info "容器 [$container] 编译模块数: $module_count (规范2)"
        log_detail "建议: 仅启用必要的模块，减少攻击面"

        # 规范3: 禁止webDAV
        log_cmd "nginx -V 2>&1 | grep -i 'http_dav_module'" "检查webDAV模块"
        if container_exec "$container" nginx -V 2>&1 | grep -qi "http_dav_module"; then
            log_error "容器 [$container] 安装了webDAV模块 (规范3)"
            log_detail "风险: webDAV模块可能被滥用进行文件上传攻击"
        else
            log_success "容器 [$container] 未安装webDAV模块 (规范3)"
        fi

        # ========== 网络绑定检查 ==========
        echo ""
        log_info "=== 网络绑定检查 ==="

        # 规范4: 绑定特定IP
        log_cmd "grep -E 'listen\\s+(\\*:|\\[::\\]:|0\\.0\\.0\\.0:)' nginx.conf" "检查监听地址"
        local listen_all=$(echo "$config" | grep -E "listen\s+(\*:|\[::\]:|0\.0\.0\.0:)" 2>/dev/null || true)
        if [ -n "$listen_all" ]; then
            log_error "容器 [$container] 监听地址绑定到通配符 (规范4)"
            echo "$listen_all" | while read line; do
                log_detail "发现: $line"
            done
            log_detail "风险: 绑定0.0.0.0可能暴露服务到所有网络接口"
        else
            log_success "容器 [$container] 监听地址已绑定特定IP (规范4)"
        fi

        # ========== 功能配置检查 ==========
        echo ""
        log_info "=== 功能配置检查 ==="

        # 规范5: 禁用SSI
        log_cmd "grep -E 'ssi\\s+on' nginx.conf" "检查SSI功能"
        if echo "$config" | grep -E "ssi\s+on" > /dev/null 2>&1; then
            log_error "容器 [$container] SSI功能已启用 (规范5)"
            log_detail "风险: SSI可能被利用执行服务器端命令"
        else
            log_success "容器 [$container] SSI功能已禁用 (规范5)"
        fi

        # 规范17: 禁用不必要的HTTP方法
        log_cmd "grep -E 'request_method.*TRACE|OPTIONS' nginx.conf" "检查HTTP方法限制"
        if echo "$config" | grep -E "if\s*\(\$request_method\s*~\s*\".*(TRACE|OPTIONS)" > /dev/null 2>&1; then
            log_success "容器 [$container] 已限制不必要的HTTP方法 (规范17)"
        else
            log_error "容器 [$container] 未限制TRACE/OPTIONS方法 (规范17)"
            log_detail "风险: TRACE方法可能导致XST跨站跟踪攻击"
            log_detail "建议: 添加 if (\$request_method ~ ^(TRACE|OPTIONS)) { return 405; }"
        fi

        # ========== 账号安全检查 ==========
        echo ""
        log_info "=== 账号安全检查 ==="

        # 规范6: 运行用户
        log_cmd "grep -E '^\\s*user\\s+' nginx.conf" "检查Nginx运行用户"
        local nginx_user=$(echo "$config" | grep -E "^\s*user\s+" | head -1 | awk '{print $2}' | tr -d ';')
        log_result "Nginx运行用户: ${nginx_user:-未配置(默认nobody)}"

        if [ -z "$nginx_user" ] || [ "$nginx_user" == "root" ]; then
            log_error "容器 [$container] Nginx运行用户为root (规范6)"
            log_detail "风险: 以root运行nginx可能导致权限提升攻击"
        else
            log_success "容器 [$container] Nginx运行用户: $nginx_user (规范6)"

            # 规范7: 账号锁定状态
            log_cmd "passwd -S $nginx_user" "检查账号锁定状态"
            local lock_status=$(container_exec "$container" passwd -S "$nginx_user" 2>/dev/null | awk '{print $2}')
            if [ "$lock_status" == "L" ] || [ "$lock_status" == "LK" ]; then
                log_success "容器 [$container] 账号 $nginx_user 已锁定 (规范7)"
            else
                log_warning "容器 [$container] 账号 $nginx_user 未锁定 (规范7)"
                log_detail "建议: 执行 passwd -l $nginx_user 锁定账号"
            fi

            # 规范8: 禁止登录shell
            log_cmd "getent passwd $nginx_user" "检查登录shell"
            local shell=$(container_exec "$container" getent passwd "$nginx_user" 2>/dev/null | cut -d: -f7)
            log_result "登录shell: $shell"
            if [ "$shell" == "/sbin/nologin" ] || [ "$shell" == "/bin/false" ] || [ -z "$shell" ]; then
                log_success "容器 [$container] 账号 $nginx_user 禁止登录shell (规范8)"
            else
                log_error "容器 [$container] 账号 $nginx_user 可登录shell: $shell (规范8)"
                log_detail "建议: 修改 /etc/passwd 将shell改为 /sbin/nologin"
            fi
        fi

        # ========== 文件权限检查 ==========
        echo ""
        log_info "=== 文件权限检查 ==="

        # 规范9: Nginx目录权限
        log_cmd "stat -c '%a' /etc/nginx" "检查Nginx目录权限"
        local nginx_dir=$(container_exec "$container" nginx -V 2>&1 | grep -o "prefix=[^ ]*" | cut -d= -f2 | tr -d ' ')
        [ -z "$nginx_dir" ] && nginx_dir="/etc/nginx"
        local dir_perm=$(container_exec "$container" stat -c "%a" "$nginx_dir" 2>/dev/null || echo "755")
        log_result "Nginx目录($nginx_dir)权限: $dir_perm"
        if [ "$dir_perm" -le "550" ] 2>/dev/null; then
            log_success "容器 [$container] Nginx目录权限安全 (规范9)"
        else
            log_error "容器 [$container] Nginx目录权限过宽: $dir_perm (规范9)"
            log_detail "建议: chmod 550 $nginx_dir"
        fi

        # 规范10: 配置文件权限
        log_cmd "stat -c '%a' /etc/nginx/nginx.conf" "检查配置文件权限"
        local conf_perm=$(container_exec "$container" stat -c "%a" /etc/nginx/nginx.conf 2>/dev/null || echo "644")
        log_result "nginx.conf权限: $conf_perm"
        if [ "$conf_perm" -le "640" ] 2>/dev/null; then
            log_success "容器 [$container] 配置文件权限安全 (规范10)"
        else
            log_error "容器 [$container] 配置文件权限过宽: $conf_perm (规范10)"
            log_detail "建议: chmod 640 /etc/nginx/nginx.conf"
        fi

        # 规范11: 日志文件权限
        log_cmd "stat -c '%a' /var/log/nginx/*.log" "检查日志文件权限"
        local log_dir="/var/log/nginx"
        local log_issue=false
        for logfile in access.log error.log; do
            local log_perm=$(container_exec "$container" stat -c "%a" "$log_dir/$logfile" 2>/dev/null || echo "644")
            if [ "$log_perm" -gt "640" ] 2>/dev/null; then
                log_error "容器 [$container] 日志文件权限过宽: $logfile ($log_perm) (规范11)"
                log_issue=true
            fi
        done
        [ "$log_issue" = false ] && log_success "容器 [$container] 日志文件权限安全 (规范11)"

        # ========== SSL/TLS安全检查 ==========
        echo ""
        log_info "=== SSL/TLS安全检查 ==="

        local ssl_enabled=$(echo "$config" | grep -E "listen\s+.*ssl|listen\s+.*443" | head -1)

        if [ -n "$ssl_enabled" ]; then
            log_success "容器 [$container] 已启用SSL功能 (规范21)"
            log_detail "SSL配置: $ssl_enabled"

            # 规范22: TLS协议版本
            log_cmd "grep -E 'ssl_protocols' nginx.conf" "检查TLS协议版本"
            local ssl_proto=$(echo "$config" | grep -E "ssl_protocols" | head -1)
            if [ -n "$ssl_proto" ]; then
                log_result "$ssl_proto"
                if echo "$ssl_proto" | grep -E "SSLv2|SSLv3|TLSv1[^\.]" > /dev/null 2>&1; then
                    log_error "容器 [$container] 使用不安全的TLS协议 (规范22)"
                    log_detail "风险: SSLv2/v3和TLSv1.0存在已知漏洞"
                else
                    log_success "容器 [$container] TLS协议版本安全 (规范22)"
                fi
            else
                log_warning "容器 [$container] 未显式配置ssl_protocols (规范22)"
                log_detail "建议: 添加 ssl_protocols TLSv1.2 TLSv1.3;"
            fi

            # 规范23: 加密套件
            log_cmd "grep -E 'ssl_ciphers' nginx.conf" "检查加密套件"
            local ssl_ciphers=$(echo "$config" | grep -E "ssl_ciphers" | head -1)
            if [ -n "$ssl_ciphers" ]; then
                log_result "已配置加密套件"
                if echo "$ssl_ciphers" | grep -iE "RC4|DES|3DES|MD5|NULL|EXPORT|ANON" > /dev/null 2>&1; then
                    log_error "容器 [$container] 使用不安全的加密套件 (规范23)"
                    log_detail "风险: 弱加密算法可能被破解"
                else
                    log_success "容器 [$container] 加密套件配置安全 (规范23)"
                fi
            else
                log_warning "容器 [$container] 未配置ssl_ciphers (规范23)"
            fi

            # 规范24-27: 其他SSL配置
            echo "$config" | grep -E "ssl_dhparam|ssl_session_timeout|ssl_session_cache|ssl_stapling" | while read line; do
                log_detail "$line"
            done
        else
            log_info "容器 [$container] 未启用SSL功能"
        fi

        # ========== 安全头配置检查 ==========
        echo ""
        log_info "=== 安全头配置检查 ==="

        # 检查安全响应头
        local security_headers="X-Frame-Options X-Content-Type-Options X-XSS-Protection Strict-Transport-Security Content-Security-Policy"

        for header in $security_headers; do
            log_cmd "grep -i 'add_header.*$header' nginx.conf" "检查 $header"
            if echo "$config" | grep -i "add_header.*$header" > /dev/null 2>&1; then
                local header_value=$(echo "$config" | grep -i "add_header.*$header" | head -1)
                log_success "容器 [$container] 已配置 $header"
                log_detail "$header_value"
            else
                log_warning "容器 [$container] 未配置 $header"
            fi
        done

        log_info "容器 [$container] Nginx安全规范检查完成"
    done
}

# ==================== 6. 端口扫描 ====================
check_ports() {
    echo "" >> "$REPORT_FILE"
    echo "## 6. 端口暴露检查" >> "$REPORT_FILE"
    log_info "开始扫描容器端口..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # ===== 外部端口映射 =====
        log_info "=== 外部端口映射 ==="
        log_cmd "docker port $container 或 crictl port $container" "获取端口映射"

        local ports=$(container_port "$container" 2>/dev/null || true)

        if [ -n "$ports" ]; then
            echo -e "  ${CYAN}→ 端口映射结果:${NC}"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$ports" | while read line; do
                [ -n "$line" ] && echo -e "    ${CYAN}$line${NC}" && echo "    $line" >> "$REPORT_FILE"

                # 分析绑定地址
                local bind_ip=$(echo "$line" | awk -F: '{print $1}')
                local bind_port=$(echo "$line" | awk -F: '{print $2}')

                if [[ "$bind_ip" == "0.0.0.0" ]] || [[ "$bind_ip" == "::" ]]; then
                    log_warning "端口 $bind_port 绑定到所有接口 ($bind_ip)"
                    log_detail "风险: 暴露到所有网络接口，可能被外部访问"
                fi
            done
            echo "  \`\`\`" >> "$REPORT_FILE"

            # 统计端口数量
            local port_count=$(echo "$ports" | grep -c ":" 2>/dev/null || echo "0")
            log_result "共 $port_count 个端口映射"

            # 检查高危端口
            local high_risk_ports="22 23 3389 5900 5901 6379 27017 9200 5672"
            for hr_port in $high_risk_ports; do
                if echo "$ports" | grep -q ":$hr_port"; then
                    log_warning "发现高危端口暴露: $hr_port"
                    log_detail "风险: 端口 $hr_port 可能被攻击者利用"
                fi
            done
        else
            log_info "容器 [$container] 无外部端口映射"
        fi

        # ===== 容器内部监听端口 =====
        echo ""
        log_info "=== 容器内部监听端口 ==="
        log_cmd "netstat -tunlp 2>/dev/null || ss -tunlp" "获取容器内部监听端口"

        local listen_ports=$(container_exec "$container" "netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null" || true)

        if [ -n "$listen_ports" ]; then
            echo -e "  ${CYAN}→ 容器内部监听:${NC}"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$listen_ports" >> "$REPORT_FILE"
            echo "  \`\`\`" >> "$REPORT_FILE"

            # 分析监听地址
            echo "$listen_ports" | grep -E "LISTEN" | while read line; do
                local addr=$(echo "$line" | awk '{print $4}')
                local pid_prog=$(echo "$line" | awk '{print $7}')

                if [[ "$addr" == 0.0.0.0* ]]; then
                    local port_num=$(echo "$addr" | cut -d: -f2)
                    log_info "监听 0.0.0.0:$port_num (进程: $pid_prog) - K8s环境正常"
                elif [[ "$addr" == 127.0.0.1* ]] || [[ "$addr" == ::1* ]]; then
                    local port_num=$(echo "$addr" | cut -d: -f2)
                    log_success "仅监听本地: $port_num"
                fi
            done
        else
            log_info "容器 [$container] 无法获取内部监听端口"
        fi
    done
}

# ==================== 7. 容器安全基线检查 ====================
check_container_baseline() {
    echo "" >> "$REPORT_FILE"
    echo "## 7. 容器安全基线检查" >> "$REPORT_FILE"
    log_info "开始容器安全基线检查..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # ===== 运行用户检查 =====
        log_cmd "whoami" "检查容器运行用户"
        local user=$(container_exec "$container" "whoami 2>/dev/null" || echo "unknown")
        log_result "当前用户: $user"

        if [ "$user" == "root" ]; then
            log_warning "容器 [$container] 以root用户运行 (D_IAM_48_1)"
            log_detail "风险: 以root运行可能导致容器逃逸风险"
            log_detail "建议: 在Dockerfile中使用USER指令指定非root用户"
        else
            log_success "容器 [$container] 以非root用户($user)运行"

            # 显示用户详细信息
            log_cmd "id" "获取用户ID信息"
            local user_info=$(container_exec "$container" "id 2>/dev/null" || true)
            [ -n "$user_info" ] && log_detail "$user_info"
        fi

        # ===== 特权模式检查 =====
        echo ""
        log_cmd "docker inspect --format '{{.HostConfig.Privileged}}'" "检查特权模式"

        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local priv=$(docker inspect "$container" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo "false")
        elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
            local container_id="${CONTAINER_NAME_TO_ID[$container]}"
            [ -z "$container_id" ] && container_id="$container"
            local priv=$(crictl inspect "$container_id" 2>/dev/null | grep -o '"privileged": [^,]*' | head -1 | awk '{print $2}' || echo "false")
        fi

        log_result "特权模式: $priv"
        if [ "$priv" == "true" ]; then
            log_error "容器 [$container] 运行在特权模式"
            log_detail "风险: 特权容器拥有宿主机所有能力，可能导致容器逃逸"
            log_detail "建议: 移除--privileged参数，仅添加必要的capabilities"
        else
            log_success "容器 [$container] 未运行在特权模式"
        fi

        # ===== 资源限制检查 =====
        echo ""
        log_cmd "docker inspect --format 'Memory/CpuQuota/NetworkMode/ReadonlyRootfs'" "检查资源限制"

        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local mem=$(docker inspect "$container" --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
            local cpu=$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}' 2>/dev/null || echo "0")
            local cpu_period=$(docker inspect "$container" --format '{{.HostConfig.CpuPeriod}}' 2>/dev/null || echo "0")
            local net=$(docker inspect "$container" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || echo "default")
            local ro=$(docker inspect "$container" --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null || echo "false")
            local pid_limit=$(docker inspect "$container" --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || echo "0")
        elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
            local container_id="${CONTAINER_NAME_TO_ID[$container]}"
            [ -z "$container_id" ] && container_id="$container"
            local inspect_json=$(crictl inspect "$container_id" 2>/dev/null)
            local mem=$(echo "$inspect_json" | grep -o '"memory": [^,]*' | head -1 | awk -F'[ :]' '{print $3}' | tr -d ',' || echo "0")
            local cpu=$(echo "$inspect_json" | grep -o '"cpu_quota": [^,]*' | head -1 | awk -F'[ :]' '{print $3}' | tr -d ',' || echo "0")
            local cpu_period=$(echo "$inspect_json" | grep -o '"cpu_period": [^,]*' | head -1 | awk -F'[ :]' '{print $3}' | tr -d ',' || echo "0")
            local net=$(echo "$inspect_json" | grep -o '"network_mode": "[^"]*"' | head -1 | cut -d'"' -f4 || echo "default")
            local ro=$(echo "$inspect_json" | grep -o '"readonly_rootfs": [^,]*' | head -1 | awk '{print $2}' || echo "false")
            local pid_limit="0"
        fi

        # 内存限制
        if [ "$mem" == "0" ] || [ -z "$mem" ]; then
            log_warning "容器 [$container] 未设置内存限制"
            log_detail "风险: 可能导致资源耗尽攻击"
            log_detail "建议: 使用 --memory 参数限制内存使用"
        else
            local mem_mb=$((mem / 1024 / 1024))
            log_success "容器 [$container] 内存限制: ${mem_mb}MB"
        fi

        # CPU限制
        if [ "$cpu" == "0" ] || [ -z "$cpu" ]; then
            log_warning "容器 [$container] 未设置CPU限制"
            log_detail "风险: 可能占用过多CPU资源"
        else
            local cpu_cores=$(echo "scale=2; $cpu / 100000" | bc 2>/dev/null || echo "$cpu")
            log_success "容器 [$container] CPU限制: quota=$cpu, period=${cpu_period:-100000}"
        fi

        # 网络模式
        log_result "网络模式: $net"
        if [ "$net" == "host" ]; then
            log_error "容器 [$container] 使用host网络模式"
            log_detail "风险: 容器可以直接访问宿主机网络，端口无隔离"
            log_detail "建议: 使用bridge或自定义网络"
        else
            log_success "容器 [$container] 网络模式安全: $net"
        fi

        # 只读根文件系统
        log_result "只读根文件系统: $ro"
        if [ "$ro" == "true" ]; then
            log_success "容器 [$container] 根文件系统为只读"
        else
            log_warning "容器 [$container] 根文件系统可写"
            log_detail "建议: 使用 --read-only 参数保护根文件系统"
        fi

        # PID限制
        if [ "$pid_limit" != "0" ] && [ -n "$pid_limit" ]; then
            log_success "容器 [$container] PID限制: $pid_limit"
        else
            log_warning "容器 [$container] 未设置PID限制"
        fi

        # ===== Capabilities检查 =====
        echo ""
        log_cmd "docker inspect --format '{{.HostConfig.CapAdd}}'" "检查Linux Capabilities"

        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local cap_add=$(docker inspect "$container" --format '{{.HostConfig.CapAdd}}' 2>/dev/null || true)
            local cap_drop=$(docker inspect "$container" --format '{{.HostConfig.CapDrop}}' 2>/dev/null || true)
        fi

        if [ -n "$cap_add" ] && [ "$cap_add" != "[]" ]; then
            log_warning "容器 [$container] 添加了额外Capabilities: $cap_add"
            log_detail "风险: 额外的capabilities可能被利用进行攻击"

            # 检查危险capabilities
            local dangerous_caps="SYS_ADMIN NET_ADMIN SYS_PTRACE SYS_MODULE DAC_READ_SEARCH"
            for cap in $dangerous_caps; do
                if echo "$cap_add" | grep -qi "$cap"; then
                    log_error "发现危险Capability: $cap"
                fi
            done
        else
            log_success "容器 [$container] 未添加额外Capabilities"
        fi

        if [ -n "$cap_drop" ] && [ "$cap_drop" != "[]" ]; then
            log_success "容器 [$container] 已丢弃Capabilities: $cap_drop"
        fi
    done
}

# ==================== 8. 镜像安全检查 ====================
check_image_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 8. 镜像安全检查" >> "$REPORT_FILE"
    log_info "开始检查镜像安全..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        log_cmd "docker inspect --format '{{.Config.Image}}'" "获取镜像信息"
        local image=$(container_inspect "$container" --format '{{.Config.Image}}' 2>/dev/null || true)
        log_result "镜像: $image"

        # 检查镜像标签
        if echo "$image" | grep -qE ":latest$|:$"; then
            log_warning "容器 [$container] 使用latest标签镜像"
            log_detail "风险: latest标签可能指向不同版本，难以追踪漏洞"
            log_detail "建议: 使用明确的版本标签如 nginx:1.24"
        else
            log_success "容器 [$container] 使用明确版本标签"
        fi

        # 获取镜像创建时间
        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local image_id=$(docker inspect "$container" --format '{{.Image}}' 2>/dev/null || true)
            local created=$(docker inspect "$image_id" --format '{{.Created}}' 2>/dev/null || true)
            log_detail "镜像创建时间: $created"
        fi

        # 检查镜像大小
        if [ "$CONTAINER_RUNTIME" = "docker" ]; then
            local image_size=$(docker inspect "$container" --format '{{.Size}}' 2>/dev/null || echo "0")
            if [ "$image_size" != "0" ]; then
                local size_mb=$((image_size / 1024 / 1024))
                log_detail "镜像大小: ${size_mb}MB"

                if [ "$size_mb" -gt "500" ]; then
                    log_warning "镜像较大 (${size_mb}MB)，可能包含不必要的软件"
                fi
            fi
        fi
    done
}

# ==================== 9. MD5密码安全检查 ====================
check_md5_password_security() {
    echo "" >> "$REPORT_FILE"
    echo "## 9. MD5密码安全检查 (D_CAS_2_4)" >> "$REPORT_FILE"
    log_info "开始检查MD5密码..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        log_cmd "grep -E '\\\$1\\\$' /etc/shadow" "检查MD5加密密码"
        local md5=$(container_exec "$container" "grep -E '\\\$1\\\$' /etc/shadow 2>/dev/null" || true)

        if [ -n "$md5" ]; then
            local md5_count=$(echo "$md5" | wc -l)
            log_error "容器 [$container] 使用MD5加密密码"
            log_result "发现 $md5_count 个MD5加密的密码"

            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$md5" | while read line; do
                # 隐藏密码哈希
                local masked=$(echo "$line" | sed 's/\$1\$[^:]*:/**MD5_HASH**:/')
                log_detail "$masked"
                echo "    $masked" >> "$REPORT_FILE"
            done
            echo "  \`\`\`" >> "$REPORT_FILE"

            log_detail "风险: MD5加密已被破解，建议使用SHA-512"
            log_detail "建议: 修改 /etc/login.defs 中的 ENCRYPT_METHOD 为 SHA512"
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

    local tools="gcc g++ make nmap netcat tcpdump gdb john hydra curl wget nc"

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        log_info "检查容器 [$container] 安全工具..."

        local found_tools=""
        local tool_details=""

        for tool in $tools; do
            log_cmd "which $tool" "检查工具 $tool"
            local tool_path=$(container_exec "$container" "which $tool 2>/dev/null" || true)

            if [ -n "$tool_path" ]; then
                found_tools="$found_tools $tool"
                log_result "发现: $tool ($tool_path)"

                # 获取工具版本信息
                local version=$(container_exec "$container" "$tool --version 2>/dev/null | head -1" || true)
                [ -n "$version" ] && log_detail "版本: $version"
                tool_details="$tool_details\n  - $tool: $tool_path"
            fi
        done

        if [ -n "$found_tools" ]; then
            log_warning "容器 [$container] 包含安全工具:$found_tools"
            log_detail "风险: 安全工具可能被攻击者利用"
            log_detail "建议: 在生产镜像中移除这些工具"
            echo -e "$tool_details" >> "$REPORT_FILE"
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
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        log_cmd "find / -type f \\( -name 'tcpdump' -o -name 'gdb' -o -name 'strace' ... \\)" "扫描调试工具"

        local debug_tools=$(container_exec "$container" "find / -type f \( -name 'tcpdump' -o -name 'gdb' -o -name 'strace' -o -name 'nmap' -o -name 'wireshark' -o -name 'gcc' -o -name 'g++' -o -name 'make' -o -name 'cmake' -o -name 'perf' -o -name 'objdump' -o -name 'readelf' \) 2>/dev/null | head -30" || true)

        if [ -n "$debug_tools" ]; then
            local count=$(echo "$debug_tools" | wc -l)
            log_warning "容器 [$container] 发现 $count 个调试工具"

            echo -e "  ${CYAN}→ 发现的工具:${NC}"
            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$debug_tools" | while read tool; do
                if [ -n "$tool" ]; then
                    echo -e "    ${CYAN}$tool${NC}"
                    echo "    $tool" >> "$REPORT_FILE"

                    # 检查工具权限
                    local perms=$(container_exec "$container" "stat -c '%a %U:%G' '$tool' 2>/dev/null" || true)
                    [ -n "$perms" ] && log_detail "权限: $perms"
                fi
            done
            echo "  \`\`\`" >> "$REPORT_FILE"

            log_detail "风险: 调试工具可能被用于逆向分析或漏洞利用"
            log_detail "建议: 移除开发工具或使用最小化镜像"
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
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # ===== UID为0的账户检查 =====
        log_cmd "awk -F: '\$3 == 0 {print \$1}' /etc/passwd" "检查UID为0的账户"
        local uid0=$(container_exec "$container" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd 2>/dev/null" || true)
        log_result "UID=0账户: ${uid0:-root}"

        if [ -n "$uid0" ] && [ "$uid0" != "root" ]; then
            log_error "容器 [$container] 发现多个UID为0账户: $uid0"
            log_detail "风险: 多个UID为0的账户可能导致权限管理混乱"
        else
            log_success "容器 [$container] 仅root账户UID为0"
        fi

        # ===== 口令期限检查 =====
        echo ""
        log_cmd "grep '^PASS_MAX_DAYS' /etc/login.defs" "检查口令期限配置"
        local maxdays=$(container_exec "$container" "grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print \$2}'" || true)

        if [ -n "$maxdays" ]; then
            log_result "口令最大有效期: $maxdays 天"

            if [ "$maxdays" -gt "90" ] 2>/dev/null; then
                log_warning "容器 [$container] 口令期限过长: $maxdays 天"
                log_detail "建议: 设置 PASS_MAX_DAYS <= 90"
            else
                log_success "容器 [$container] 口令期限符合规范"
            fi
        else
            log_info "容器 [$container] 无法获取口令期限配置(可能无login.defs)"
        fi

        # ===== 空密码账户检查 =====
        echo ""
        log_cmd "awk -F: '\$2 == \"\" {print \$1}' /etc/shadow" "检查空密码账户"
        local empty_pass=$(container_exec "$container" "awk -F: '\$2 == \"\" {print \$1}' /etc/shadow 2>/dev/null" || true)

        if [ -n "$empty_pass" ]; then
            log_error "容器 [$container] 发现空密码账户: $empty_pass"
            log_detail "风险: 空密码账户可被无密码登录"
        else
            log_success "容器 [$container] 未发现空密码账户"
        fi

        # ===== sudo权限检查 =====
        echo ""
        log_cmd "which sudo && cat /etc/sudoers" "检查sudo配置"
        local sudo_installed=$(container_exec "$container" "which sudo 2>/dev/null" || true)

        if [ -n "$sudo_installed" ]; then
            log_warning "容器 [$container] 安装了sudo"

            # 检查NOPASSWD配置
            local nopasswd=$(container_exec "$container" "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null" || true)
            if [ -n "$nopasswd" ]; then
                log_error "容器 [$container] 存在NOPASSWD配置"
                log_detail "$nopasswd"
            fi
        else
            log_success "容器 [$container] 未安装sudo"
        fi
    done
}

# ==================== 13. 文件权限检查 ====================
check_file_permissions() {
    echo "" >> "$REPORT_FILE"
    echo "## 13. 文件权限检查" >> "$REPORT_FILE"
    log_info "开始检查容器内文件权限..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        # ===== 敏感文件权限检查 =====
        log_info "=== 敏感文件权限检查 ==="

        # /etc/shadow 权限
        log_cmd "stat -c '%a %U:%G' /etc/shadow" "检查shadow文件权限"
        local shadow_perm=$(container_exec "$container" "stat -c '%a %U:%G' /etc/shadow 2>/dev/null" || true)

        if [ -n "$shadow_perm" ]; then
            log_result "/etc/shadow: $shadow_perm"
            local perm_num=$(echo "$shadow_perm" | awk '{print $1}')

            if [ "$perm_num" -le "640" ] 2>/dev/null; then
                log_success "容器 [$container] shadow文件权限安全"
            else
                log_warning "容器 [$container] shadow文件权限过宽: $perm_num"
                log_detail "建议: chmod 640 /etc/shadow"
            fi
        else
            log_info "容器 [$container] 无法获取shadow权限(可能不存在)"
        fi

        # /etc/passwd 权限
        log_cmd "stat -c '%a %U:%G' /etc/passwd" "检查passwd文件权限"
        local passwd_perm=$(container_exec "$container" "stat -c '%a %U:%G' /etc/passwd 2>/dev/null" || true)

        if [ -n "$passwd_perm" ]; then
            log_result "/etc/passwd: $passwd_perm"
        fi

        # /etc/gshadow 权限
        log_cmd "stat -c '%a %U:%G' /etc/gshadow" "检查gshadow文件权限"
        local gshadow_perm=$(container_exec "$container" "stat -c '%a %U:%G' /etc/gshadow 2>/dev/null" || true)

        if [ -n "$gshadow_perm" ]; then
            log_result "/etc/gshadow: $gshadow_perm"
        fi

        # ===== SUID/SGID文件检查 =====
        echo ""
        log_info "=== SUID/SGID文件检查 ==="
        log_cmd "find / -perm -4000 -o -perm -2000 2>/dev/null | head -20" "查找SUID/SGID文件"

        local suid_files=$(container_exec "$container" "find / -perm -4000 -type f 2>/dev/null | head -20" || true)

        if [ -n "$suid_files" ]; then
            local suid_count=$(echo "$suid_files" | wc -l)
            log_warning "容器 [$container] 发现 $suid_count 个SUID文件"

            echo "  \`\`\`" >> "$REPORT_FILE"
            echo "$suid_files" | while read file; do
                if [ -n "$file" ]; then
                    echo -e "    ${CYAN}$file${NC}"
                    echo "    $file" >> "$REPORT_FILE"

                    # 检查是否为常见的SUID程序
                    local basename=$(basename "$file")
                    local common_suid="sudo passwd su mount umount ping newgrp chsh chfn"
                    if ! echo "$common_suid" | grep -qw "$basename"; then
                        log_detail "非标准SUID程序: $basename"
                    fi
                fi
            done
            echo "  \`\`\`" >> "$REPORT_FILE"

            log_detail "风险: SUID程序可能被用于权限提升"
        else
            log_success "容器 [$container] 未发现SUID文件"
        fi

        # ===== 无属主文件检查 =====
        echo ""
        log_info "=== 无属主文件检查 ==="
        log_cmd "find / -nouser -o -nogroup 2>/dev/null | head -10" "查找无属主文件"

        local noowner=$(container_exec "$container" "find /etc /opt /app -nouser -o -nogroup 2>/dev/null | head -10" || true)

        if [ -n "$noowner" ]; then
            log_warning "容器 [$container] 发现无属主文件:"
            echo "$noowner" | while read file; do
                [ -n "$file" ] && log_detail "$file"
            done
            log_detail "风险: 无属主文件可能被攻击者利用"
        else
            log_success "容器 [$container] 未发现无属主文件"
        fi

        # ===== 可写文件检查 =====
        echo ""
        log_cmd "find /etc -type f -perm /002 2>/dev/null | head -10" "查找其他用户可写文件"
        local writable=$(container_exec "$container" "find /etc -type f -perm /002 2>/dev/null | head -10" || true)

        if [ -n "$writable" ]; then
            log_warning "容器 [$container] /etc目录下发现其他用户可写文件:"
            echo "$writable" | while read file; do
                [ -n "$file" ] && log_detail "$file"
            done
        else
            log_success "容器 [$container] /etc目录下文件权限安全"
        fi
    done
}

# ==================== 14. 暴力破解防护检查 ====================
check_brute_force_protection() {
    echo "" >> "$REPORT_FILE"
    echo "## 14. 暴力破解防护检查 (D_SCS_2_10)" >> "$REPORT_FILE"
    log_info "开始检查容器内暴力破解防护..."

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        log_cmd "which fail2ban-server" "检查fail2ban安装"
        local fail2ban=$(container_exec "$container" "which fail2ban-server 2>/dev/null" || true)

        if [ -n "$fail2ban" ]; then
            log_success "容器 [$container] 已安装fail2ban: $fail2ban"

            # 检查fail2ban状态
            log_cmd "fail2ban-client status" "检查fail2ban状态"
            local f2b_status=$(container_exec "$container" "fail2ban-client status 2>/dev/null" || true)
            if [ -n "$f2b_status" ]; then
                log_result "fail2ban状态: 运行中"
                log_detail "$f2b_status"
            fi
        else
            log_warning "容器 [$container] 未安装fail2ban"
            log_detail "注意: 容器环境通常不需要fail2ban"
            log_detail "建议: 如果暴露SSH服务，考虑安装fail2ban"
        fi

        # 检查登录失败锁定策略
        echo ""
        log_cmd "grep 'auth required' /etc/pam.d/* 2>/dev/null | grep deny" "检查PAM锁定策略"
        local pam_lock=$(container_exec "$container" "grep -r 'auth required' /etc/pam.d/ 2>/dev/null | grep -E 'deny|lock'" || true)

        if [ -n "$pam_lock" ]; then
            log_success "容器 [$container] 配置了登录失败锁定策略"
            log_detail "$pam_lock"
        else
            log_info "容器 [$container] 未配置登录失败锁定策略"
        fi
    done
}

# ==================== 15. 不安全函数检查 ====================
check_unsafe_functions() {
    echo "" >> "$REPORT_FILE"
    echo "## 15. 不安全函数检查 (RL_13_1_2_1)" >> "$REPORT_FILE"
    log_info "开始检查代码中不安全函数..."

    local unsafe_funcs="strcpy strcat sprintf gets scanf sscanf vsprintf strtok"

    for container in $CONTAINERS; do
        echo "" >> "$REPORT_FILE"
        echo "### 容器: $container" >> "$REPORT_FILE"

        log_cmd "find /app /home /root -name '*.c' -o -name '*.cpp' 2>/dev/null" "查找C/C++代码文件"
        local cfiles=$(container_exec "$container" "find /app /home /root -type f \( -name '*.c' -o -name '*.cpp' \) 2>/dev/null | head -20" || true)

        if [ -z "$cfiles" ]; then
            log_info "容器 [$container] 未发现C/C++代码文件"
            continue
        fi

        local file_count=$(echo "$cfiles" | wc -l)
        log_result "发现 $file_count 个C/C++文件"

        local found_unsafe=false
        local unsafe_count=0

        for file in $cfiles; do
            for func in $unsafe_funcs; do
                log_cmd "grep -l '$func' $file" "检查函数 $func"
                local match=$(container_exec "$container" "grep -l '$func' '$file' 2>/dev/null" || true)

                if [ -n "$match" ]; then
                    log_warning "容器 [$container] 发现不安全函数 $func: $file"
                    found_unsafe=true
                    unsafe_count=$((unsafe_count + 1))

                    # 显示使用位置
                    local usage=$(container_exec "$container" "grep -n '$func' '$file' 2>/dev/null | head -3" || true)
                    [ -n "$usage" ] && log_detail "$usage"
                fi
            done
        done

        if [ "$found_unsafe" = false ]; then
            log_success "容器 [$container] 未发现不安全函数"
        else
            log_warning "容器 [$container] 共发现 $unsafe_count 处不安全函数调用"
            log_detail "风险: 不安全函数可能导致缓冲区溢出"
            log_detail "建议: 使用安全的替代函数如strncpy、snprintf"
        fi
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
    echo "    容器安全扫描工具 v2.4"
    echo "========================================"
    echo -e "${NC}"

    init_containers

    echo -e "${BLUE}目标容器:${NC}"
    for c in $CONTAINERS; do
        echo -e "  - ${GREEN}$c${NC}"
    done
    echo ""

    init_report

    # 为每个容器安装必要工具
    if [ "$INSTALL_TOOLS" = true ]; then
        for container in $CONTAINERS; do
            install_container_tools "$container"
        done
    else
        log_info "跳过容器内工具安装"
    fi

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
