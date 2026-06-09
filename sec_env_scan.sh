#!/bin/bash
# 容器环境安全扫描入口脚本
# 用于遍历所有容器并执行安全扫描
# 支持Docker和crictl(containerd/CRI)两种容器运行时

set -o pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 配置
LOG_FILE="/root/sec_scanner_result_$(hostname).txt"
TARGET_CONTAINER=""
CONTAINER_RUNTIME=""

# 白名单命名空间
NAMESPACE_WHITELIST="hss istio-system monitoring kube-system merlin"
# 白名单Pod名称前缀
POD_WHITELIST="vault super-scanner"

# 显示帮助
show_help() {
    echo -e "${BLUE}容器环境安全扫描工具${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help              显示帮助信息"
    echo "  -c, --container NAME    指定要扫描的容器名称"
    echo "  -r, --runtime RUNTIME   指定容器运行时: docker/crictl (默认自动检测)"
    echo "  -a, --all               扫描所有容器(默认)"
    echo "  -l, --list              列出所有容器"
    echo ""
    echo "示例:"
    echo "  $0                      # 扫描所有容器"
    echo "  $0 -c nginx             # 仅扫描nginx容器"
    echo "  $0 -r crictl            # 使用crictl运行时"
    exit 0
}

# 检测容器运行时
detect_runtime() {
    if [ -n "$CONTAINER_RUNTIME" ]; then
        return
    fi

    if command -v docker &>/dev/null && docker ps &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="docker"
    elif command -v crictl &>/dev/null && crictl ps &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="crictl"
    else
        echo -e "${RED}错误: 未检测到可用的容器运行时${NC}"
        exit 1
    fi
}

# 列出容器
list_containers() {
    detect_runtime
    echo -e "${BLUE}容器列表 (${CONTAINER_RUNTIME}):${NC}"
    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        crictl ps --format "table {{.Name}}\t{{.Image}}\t{{.Status}}" 2>/dev/null || \
        crictl ps 2>/dev/null
    fi
    exit 0
}

# 解析参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -c|--container)
                [ -n "$2" ] && TARGET_CONTAINER="$2" && shift 2 || { echo -e "${RED}错误: --container 需要参数${NC}"; exit 1; }
                ;;
            -r|--runtime)
                [ -n "$2" ] && CONTAINER_RUNTIME="$2" && shift 2 || { echo -e "${RED}错误: --runtime 需要参数${NC}"; exit 1; }
                ;;
            -a|--all) TARGET_CONTAINER=""; shift ;;
            -l|--list) list_containers ;;
            *) echo -e "${RED}未知选项: $1${NC}"; show_help ;;
        esac
    done
}

# 安装jq工具
install_jq() {
    if ! command -v jq &>/dev/null; then
        echo -e "${YELLOW}[INFO]${NC} 安装 jq 工具..."
        local arch=$(uname -m)
        local jq_url="https://gitee.com/opensourceway/sec_efficiency_tool/releases/download/1.0.0/jq-linux-amd64"

        if [[ "$arch" == "aarch64" || "$arch" == arm* ]]; then
            jq_url="https://gitee.com/opensourceway/sec_efficiency_tool/releases/download/1.0.0/jq-linux-arm64"
        fi

        curl -sL "$jq_url" -o /tmp/jq && chmod +x /tmp/jq && mv /tmp/jq /usr/bin/jq
        echo -e "${GREEN}[OK]${NC} jq 安装完成"
    fi
}

# 检查是否在白名单中
is_whitelisted() {
    local namespace="$1"
    local pod_name="$2"

    # 检查命名空间白名单
    for ns in $NAMESPACE_WHITELIST; do
        if [ "$namespace" == "$ns" ] || [[ "$namespace" == ${ns}* ]]; then
            return 0
        fi
    done

    # 检查Pod名称白名单
    for pod in $POD_WHITELIST; do
        if [[ "$pod_name" == ${pod}* ]]; then
            return 0
        fi
    done

    return 1
}

# 扫描单个容器(Docker模式)
scan_docker_container() {
    local container="$1"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}扫描容器: $container${NC}"
    echo -e "${BLUE}========================================${NC}"

    # 获取容器信息
    echo -e "${CYAN}[CMD]${NC} docker inspect $container"
    local inspect=$(docker inspect "$container" 2>/dev/null)
    local pid=$(echo "$inspect" | jq -r '.[0].State.Pid // empty')
    local image=$(echo "$inspect" | jq -r '.[0].Config.Image // "unknown"')
    local status=$(echo "$inspect" | jq -r '.[0].State.Status // "unknown"')

    echo -e "  ${CYAN}→ 镜像:${NC} $image"
    echo -e "  ${CYAN}→ 状态:${NC} $status"
    echo -e "  ${CYAN}→ PID:${NC} $pid"

    # 创建宿主机结果目录
    local HOST_RESULT_DIR="/root/sec_scan_results/${container}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$HOST_RESULT_DIR"

    # 记录到日志
    {
        echo ""
        echo "========================================"
        echo "容器: $container"
        echo "镜像: $image"
        echo "状态: $status"
        echo "PID: $pid"
        echo "结果目录: $HOST_RESULT_DIR"
        echo "========================================"
    } | tee -a "$LOG_FILE"

    if [ -z "$pid" ] || [ "$pid" == "0" ]; then
        echo -e "${YELLOW}[WARN]${NC} 容器PID无效，跳过" | tee -a "$LOG_FILE"
        return
    fi

    if [ ! -d "/proc/$pid/root" ]; then
        echo -e "${YELLOW}[WARN]${NC} 容器rootfs不存在，跳过" | tee -a "$LOG_FILE"
        return
    fi

    # 执行单容器扫描
    local scanner_script="$(dirname "$0")/single_container_scanner.sh"
    if [ -f "$scanner_script" ]; then
        echo -e "${CYAN}[CMD]${NC} nsenter -t $pid -n -m -u -i -p -- bash -i $scanner_script"
        nsenter -t "$pid" -n -m -u -i -p -- bash -ic "$(cat "$scanner_script")" 2>&1 | tee -a "$LOG_FILE"

        # 复制容器内的nmap扫描结果到宿主机
        echo -e "${CYAN}[CMD]${NC} 复制nmap扫描结果到宿主机"
        local container_nmap_dir=$(nsenter -t "$pid" -n -m -u -i -p -- bash -c "ls -d /tmp/nmap_scan_* 2>/dev/null | head -1" 2>/dev/null || true)
        if [ -n "$container_nmap_dir" ]; then
            echo -e "${GREEN}[INFO]${NC} 发现容器内nmap结果: $container_nmap_dir"
            # 通过/proc复制文件
            cp -r "/proc/$pid/root${container_nmap_dir}" "$HOST_RESULT_DIR/nmap_results" 2>/dev/null || \
            nsenter -t "$pid" -n -m -u -i -p -- tar -czf - -C "$(dirname $container_nmap_dir)" "$(basename $container_nmap_dir)" 2>/dev/null | tar -xzf - -C "$HOST_RESULT_DIR" 2>/dev/null

            if [ -d "$HOST_RESULT_DIR/nmap_results" ] || [ -d "$HOST_RESULT_DIR/$(basename $container_nmap_dir)" ]; then
                echo -e "${GREEN}[OK]${NC} nmap结果已保存到: $HOST_RESULT_DIR"
            fi
        fi
    else
        echo -e "${RED}[ERROR]${NC} 找不到扫描脚本: $scanner_script"
    fi

    echo -e "${GREEN}[OK]${NC} 容器扫描完成: $container" | tee -a "$LOG_FILE"
}

# 扫描单个容器(crictl模式)
scan_crictl_container() {
    local container_id="$1"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}扫描容器: $container_id${NC}"
    echo -e "${BLUE}========================================${NC}"

    # 获取容器信息
    echo -e "${CYAN}[CMD]${NC} crictl inspect $container_id"
    local inspect=$(crictl inspect "$container_id" 2>/dev/null)

    local pid=$(echo "$inspect" | jq -r '.info.pid // empty')
    local pod_name=$(echo "$inspect" | jq -r '.status.labels["io.kubernetes.pod.name"] // "unknown"')
    local pod_namespace=$(echo "$inspect" | jq -r '.status.labels["io.kubernetes.pod.namespace"] // "unknown"')
    local container_name=$(echo "$inspect" | jq -r '.status.metadata.name // "unknown"')
    local image=$(echo "$inspect" | jq -r '.status.image.image // "unknown"')

    echo -e "  ${CYAN}→ Pod:${NC} $pod_namespace/$pod_name"
    echo -e "  ${CYAN}→ 容器名:${NC} $container_name"
    echo -e "  ${CYAN}→ 镜像:${NC} $image"
    echo -e "  ${CYAN}→ PID:${NC} $pid"

    # 检查白名单
    if is_whitelisted "$pod_namespace" "$pod_name"; then
        echo -e "${YELLOW}[SKIP]${NC} 白名单容器，跳过" | tee -a "$LOG_FILE"
        return
    fi

    # 创建宿主机结果目录
    local HOST_RESULT_DIR="/root/sec_scan_results/${pod_namespace}_${pod_name}_${container_name}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$HOST_RESULT_DIR"

    # 记录到日志
    {
        echo ""
        echo "========================================"
        echo "Pod: $pod_namespace/$pod_name"
        echo "容器: $container_name ($container_id)"
        echo "镜像: $image"
        echo "PID: $pid"
        echo "结果目录: $HOST_RESULT_DIR"
        echo "========================================"
    } | tee -a "$LOG_FILE"

    if [ -z "$pid" ] || [ "$pid" == "0" ]; then
        echo -e "${YELLOW}[WARN]${NC} 容器PID无效，跳过" | tee -a "$LOG_FILE"
        return
    fi

    if [ ! -d "/proc/$pid/root" ]; then
        echo -e "${YELLOW}[WARN]${NC} 容器rootfs不存在，跳过" | tee -a "$LOG_FILE"
        return
    fi

    # 执行单容器扫描
    local scanner_script="$(dirname "$0")/single_container_scanner.sh"
    if [ -f "$scanner_script" ]; then
        echo -e "${CYAN}[CMD]${NC} nsenter -t $pid -n -m -u -i -p -- bash -i $scanner_script"
        nsenter -t "$pid" -n -m -u -i -p -- bash -ic "$(cat "$scanner_script")" 2>&1 | tee -a "$LOG_FILE"

        # 复制容器内的nmap扫描结果到宿主机
        echo -e "${CYAN}[CMD]${NC} 复制nmap扫描结果到宿主机"
        local container_nmap_dir=$(nsenter -t "$pid" -n -m -u -i -p -- bash -c "ls -d /tmp/nmap_scan_* 2>/dev/null | head -1" 2>/dev/null || true)
        if [ -n "$container_nmap_dir" ]; then
            echo -e "${GREEN}[INFO]${NC} 发现容器内nmap结果: $container_nmap_dir"
            # 通过/proc复制文件
            cp -r "/proc/$pid/root${container_nmap_dir}" "$HOST_RESULT_DIR/nmap_results" 2>/dev/null || \
            nsenter -t "$pid" -n -m -u -i -p -- tar -czf - -C "$(dirname $container_nmap_dir)" "$(basename $container_nmap_dir)" 2>/dev/null | tar -xzf - -C "$HOST_RESULT_DIR" 2>/dev/null

            if [ -d "$HOST_RESULT_DIR/nmap_results" ] || [ -d "$HOST_RESULT_DIR/$(basename $container_nmap_dir)" ]; then
                echo -e "${GREEN}[OK]${NC} nmap结果已保存到: $HOST_RESULT_DIR"
                # 列出保存的文件
                ls -la "$HOST_RESULT_DIR" 2>/dev/null | tee -a "$LOG_FILE"
            fi
        fi
    else
        echo -e "${RED}[ERROR]${NC} 找不到扫描脚本: $scanner_script"
    fi

    echo -e "${GREEN}[OK]${NC} 容器扫描完成: $pod_namespace/$pod_name/$container_name" | tee -a "$LOG_FILE"
}

# 主函数
main() {
    parse_args "$@"

    # 初始化日志文件
    rm -f "$LOG_FILE"
    echo -e "${BLUE}📦 容器环境安全扫描工具${NC}" | tee "$LOG_FILE"
    echo -e "${BLUE}扫描时间: $(date '+%Y-%m-%d %H:%M:%S')${NC}" | tee -a "$LOG_FILE"

    # 检测运行时
    detect_runtime
    echo -e "${CYAN}[INFO]${NC} 检测到容器运行时: $CONTAINER_RUNTIME" | tee -a "$LOG_FILE"

    # 安装依赖
    install_jq

    # 扫描容器
    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        if [ -n "$TARGET_CONTAINER" ]; then
            scan_docker_container "$TARGET_CONTAINER"
        else
            local containers=$(docker ps --format "{{.Names}}")
            for container in $containers; do
                scan_docker_container "$container"
            done
        fi
    elif [ "$CONTAINER_RUNTIME" = "crictl" ]; then
        if [ -n "$TARGET_CONTAINER" ]; then
            scan_crictl_container "$TARGET_CONTAINER"
        else
            local container_ids=$(crictl ps -q)
            for container_id in $container_ids; do
                scan_crictl_container "$container_id"
            done
        fi
    fi

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}扫描完成${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "日志文件: ${CYAN}$LOG_FILE${NC}"
}

main "$@"
