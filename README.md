# 容器环境安全扫描工具 v2.4

## 项目简介

本工具用于对宿主机下的容器环境进行全面安全扫描，基于行业标准安全规范，自动化检测潜在的安全风险。

**v2.4 更新内容:**
- 详细输出每个检查项的执行命令、原始结果和分析结论
- 新增 `sec_env_scan.sh` 容器环境批量扫描入口脚本
- 新增 `single_container_scanner.sh` 单容器深度扫描脚本
- 支持指定容器名称进行扫描
- 支持 Docker 和 crictl(containerd) 两种容器运行时
- 支持 `--skip-install` 参数跳过容器内工具安装
- Nginx 48项安全规范完整检查
- 增强的报告格式，包含风险说明和修复建议

## 工具列表

| 脚本 | 功能 | 用法 |
|------|------|------|
| `container_security_scan.sh` | 容器安全扫描(详细版) | `./container_security_scan.sh [容器名...]` |
| `sec_env_scan.sh` | 容器环境批量扫描入口 | `./sec_env_scan.sh [-c 容器名]` |
| `single_container_scanner.sh` | 单容器深度扫描 | 通过nsenter注入执行 |
| `repo_security_scan.sh` | 代码仓库安全扫描 | `./repo_security_scan.sh <仓库路径>` |
| `nginx_security_scan.sh` | Nginx安全规范专项扫描 | `./nginx_security_scan.sh -c <配置文件>` |

## 支持的容器运行时

| 运行时 | 命令 | 支持状态 |
|--------|------|----------|
| Docker | `docker ps` | ✅ 完全支持 |
| containerd/CRI | `crictl ps` | ✅ 支持(使用nsenter) |

## 支持的扫描规范

本工具实现了以下安全规范要求:

| 规范编号 | 规范名称 |
|---------|---------|
| RL_13_1_2_1 | 除编程规范许可的场景外，禁止使用不安全函数 |
| D_IAM_12_5 | 代码口令硬编码 |
| Nginx_2_7_5 | 使用安全椭圆曲线 |
| Nginx_2_2_10 | 隐藏X-Powered-By |
| D_CAS_1_4 | 禁止使用Base64编码的方式实现数据加密目的 |
| D_CAS_25_1 | 禁止sslv2/v3/tls1 |
| Nginx_2_7_4 | 使用安全加密套件 |
| D_IAM_36_1 | 登录登出记录日志 |
| D_IAM_49_1 | root执行文件权限 |
| Nginx_2_3_2 | Nginx配置文件权限 |
| Other_1_2 | 环境变量敏感数据 |
| D_IAM_62_1 | 证书私钥加密存储 |
| D_IAM_42_3 | 用户umask>=027 |
| D_IAM_54_2 | ecc证书秘钥长256 |
| D_CAS_2_4 | MD5用于密码安全 |
| D_IAM_3_1 | uid为0的账户 |
| Other_1_1 | 进程参数敏感数据 |
| D_IAM_53_2 | 证书签名禁用sha1 |
| D_IAM_16_1 | 口令使用期限 |
| D_IAM_54_1 | rsa证书秘钥长3072 |
| D_CAS_2_6 | dh/ecdh秘钥长度 |
| Nginx_2_6_1 | 正确设置安全响应头 |
| D_IAM_37_5 | 禁止sudo用通配符 |
| D_IAM_27_2 | root远程登录 |
| public_ip_check | 公网ip硬编码地址扫描 |
| Nginx_2_2_6 | 绑定特定IP地址 |
| Nginx_2_1_3 | 隐藏版本信息 |
| Nginx_2_2_4 | 禁止开启列表功能 |
| Nginx_2_2_9 | 配置网络超时时间 |
| D_IAM_17_3 | 日志口令明文打印 |
| D_IAM_45_1 | MyBatis配置文件SQL注入检查 |
| Nginx_2_7_1 | 启用SSL功能 |
| D_SMS_16_1 | 会话超时时间设置 |
| Nginx_2_1_2 | 运行Nginx用户非root |
| Nginx_2_3_3 | 日志文件权限 |
| D_KMS_5_1 | 代码秘钥硬编码 |
| Nginx_2_4_1 | 禁用SSI功能 |
| D_CAS_8_1 | 禁止ssl/tls包含rc4 |
| Nginx_2_2_8 | 限制http请求的消息 |
| D_IAM_44_1 | 无属主文件 |
| D_IAM_9_1 | 密码复杂度 |
| Nginx_2_7_3 | 使用安全TLS协议 |
| D_CAS_2_2 | des/3des弱加密算法 |
| D_SCS_2_10 | 防爆力默认开启 |
| D_CAS_2_5 | rsa/dsa密钥长度 |
| D_IAM_42_1 | 敏感数据文件权限 |
| Nginx_2_2_5 | 禁止重定向监听端口 |
| D_LUS_5_2 | 关机重启记录日志 |
| D_IAM_46_1 | 应用账号禁止登录 |
| D_IAM_10_1 | ssh空密码登录 |
| D_SCS_3_1 | 通配监听端口 |
| D_IAM_48_1 | 低权限运行进程 |
| D_IAM_55_1 | 证书应设置合理的有效期 |
| Nginx_2_3_1 | Nginx根目录权限 |
| D_IDS_1_1 | 安全传输通道 |
| Nginx_2_5_1 | 开启Nginx日志功能 |
| D_CAS_2_1 | blowfish/rc4弱加密 |
| D_IDS_2_4 | 敏感个人数据加密 |
| Other_1_5 | id_rsa登录秘钥 |
| Other_1_4 | db_history敏感数据 |
| Nginx_2_3_4 | Web应用目录权限 |
| D_IAM_14_1 | 配置口令明文存储 |
| Nginx_2_7_2 | 设置超时时间 |
| Nginx_2_2_1 | 禁用不必要http方法 |
| D_SCS_4_2 | 公网IP域名配置 |
| D_IAM_14_6 | 内存敏感信息扫描 |
| D_LUS_5_1 | 增删用户记录日志 |
| D_IAM_53_1 | 使用x.509 v3证书 |
| D_IAM_62_3 | 证书私钥访问权限 |
| D_IDS_2_2 | sessionid明文存储 |
| D_SCS_5_4 | 系统残留工具 |

## 扫描模块列表

### container_security_scan.sh (15个模块)

| 序号 | 模块名称 | 输出内容 |
|------|---------|---------|
| 1 | 全零IP暴露检查 | 端口映射详情、绑定地址分析、高危端口告警 |
| 2 | SSL/TLS证书检查 | 证书路径、有效期、过期告警 |
| 3 | 加密套件检查 | SSL配置、弱算法检测、协议版本分析 |
| 4 | 敏感信息泄露检查 | 环境变量扫描、SSH私钥检测、配置文件发现 |
| 5 | Nginx安全规范检查 | 48项规范逐项检查、配置详情、修复建议 |
| 6 | 端口暴露检查 | 端口映射列表、高危端口告警 |
| 7 | 容器安全基线检查 | 运行用户、特权模式、资源限制、Capabilities |
| 8 | 镜像安全检查 | 镜像标签、大小、创建时间 |
| 9 | MD5密码安全检查 | shadow文件分析、弱加密检测 |
| 10 | 安全工具残留检查 | 编译器、调试器、网络工具检测 |
| 11 | 调试工具扫描 | tcpdump、gdb、strace等调试工具 |
| 12 | 用户权限检查 | UID=0账户、空密码、sudo配置 |
| 13 | 文件权限检查 | shadow/passwd权限、SUID文件、无属主文件 |
| 14 | 暴力破解防护检查 | fail2ban安装、PAM锁定策略 |
| 15 | 不安全函数检查 | C/C++代码中危险函数检测 |

### single_container_scanner.sh (深度扫描)

| 序号 | 模块名称 | 功能说明 |
|------|---------|---------|
| 1 | 系统信息收集 | OS版本、内核信息 |
| 2 | 包管理器检测 | apt/yum/apk自动检测 |
| 3 | umask检查 | 默认权限配置检查 |
| 4 | 挂载目录检查 | 目录非空、K8s token检测 |
| 5 | 敏感文件检查 | 证书、配置文件权限 |
| 6 | History配置检查 | 历史记录禁用检测 |
| 7 | 进程安全检查 | PID 1、root进程检测 |
| 8 | 环境变量检查 | Gitleaks敏感信息扫描 |
| 9 | Sudo权限检查 | NOPASSWD配置检测 |
| 10 | PATH安全性检查 | 可写命令文件检测 |
| 11 | 网络端口检查 | SSL探测、加密套件分析 |
| 12 | 调试工具检查 | 编译器、调试器检测 |

## 使用方法

### 容器安全扫描 (详细版)

```bash
# 扫描所有运行中的容器
./container_security_scan.sh

# 扫描指定容器
./container_security_scan.sh nginx mysql

# 使用crictl运行时
./container_security_scan.sh -r crictl

# 跳过容器内工具安装
./container_security_scan.sh --skip-install

# 列出所有容器
./container_security_scan.sh -l

# 显示帮助
./container_security_scan.sh -h

# 扫描结果保存在 /tmp/container_security_scan_* 目录
# 报告格式: Markdown (security_report.md)
```

### 容器环境批量扫描

```bash
# 扫描所有容器
./sec_env_scan.sh

# 扫描指定容器
./sec_env_scan.sh -c nginx

# 使用crictl运行时
./sec_env_scan.sh -r crictl

# 结果保存: /root/sec_scanner_result_<hostname>.txt
```

### 代码仓库安全扫描

```bash
# 扫描指定代码仓库
./repo_security_scan.sh /path/to/repo

# 跳过trivy扫描
./repo_security_scan.sh /path/to/repo --skip-trivy

# 显示帮助
./repo_security_scan.sh -h

# 扫描结果保存在 /tmp/repo_security_scan_* 目录
```

### Nginx安全规范专项扫描

```bash
# 扫描指定Nginx配置文件
./nginx_security_scan.sh -c /path/to/nginx.conf

# 扫描指定Nginx配置目录
./nginx_security_scan.sh -d /etc/nginx

# 显示帮助
./nginx_security_scan.sh -h
```

## 输出报告格式

### 控制台输出示例

```
[CMD] docker port nginx
  → 结果:
    0.0.0.0:80->80/tcp
    0.0.0.0:443->443/tcp

[WARN] 容器 [nginx] 绑定到 0.0.0.0，存在外部暴露风险
    暴露端口: 80 443
    风险说明: 0.0.0.0绑定允许任意IP访问，应绑定到特定IP如127.0.0.1

[PASS] 容器 [nginx] 未发现弱加密套件
```

### Markdown报告示例

```markdown
## 1. 全零IP暴露检查 (Nginx_2_2_6)

### 容器: nginx

执行命令: `docker port nginx`

```
0.0.0.0:80->80/tcp
0.0.0.0:443->443/tcp
```

- ❌ 容器 [nginx] 绑定到 0.0.0.0
  - 风险: 0.0.0.0绑定允许任意IP访问
  - 建议: 绑定到特定IP地址
```

## 问题级别定义

| 级别 | 标识 | 说明 |
|------|------|------|
| 严重(Critical) | 🚨 | 需立即修复的高危问题 |
| 高危(High) | ❌ | 重要安全问题，如过期证书、弱加密套件、MD5密码 |
| 中危(Medium) | ⚠️ | 需关注的问题，如全零IP暴露、未配置资源限制 |
| 低危(Low) | 信息提示 | 建议改进的配置项 |

## 外部工具依赖

脚本会自动安装以下工具(如需要):

| 工具 | 用途 | 安装方式 |
|------|------|----------|
| trivy | 容器镜像漏洞扫描 | 官方安装脚本 |
| gitleaks | 敏感信息扫描 | GitHub下载二进制 |
| semgrep | 静态代码分析 | pip安装 |
| jq | JSON处理 | 包管理器/apt下载 |
| nmap | 端口扫描 | 包管理器 |

## 关键安全建议

### 密码安全
- 使用bcrypt、scrypt或Argon2替代MD5存储密码
- 禁止在代码中硬编码口令和密钥

### 加密安全
- 使用TLSv1.2或TLSv1.3，禁用SSLv2/v3/TLSv1.0/TLSv1.1
- RSA密钥长度不低于3072位，ECC密钥不低于256位
- 禁用RC4、DES、3DES、Blowfish等弱加密算法

### Nginx安全
- 运行用户设为非root
- 隐藏版本信息(server_tokens off)
- 配置安全响应头
- 禁用目录列表和SSI功能

### 容器安全
- 以非root用户运行容器
- 设置资源限制(memory, cpu)
- 使用只读根文件系统
- 禁用特权模式
- 使用自定义网络而非host网络

## 白名单配置

`sec_env_scan.sh` 支持以下白名单:

```bash
# 命名空间白名单
NAMESPACE_WHITELIST="hss istio-system monitoring kube-system merlin"

# Pod名称白名单
POD_WHITELIST="vault super-scanner"
```

## 后续扩展计划

- [ ] Kubernetes安全配置检查
- [ ] 容器逃逸风险检测
- [ ] 镜像签名验证
- [ ] 实时监控模式
- [ ] JSON详细报告输出
- [ ] 支持自定义扫描项
- [ ] Web报告界面

## License

Apache-2.0
