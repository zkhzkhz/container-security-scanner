# 容器环境安全扫描工具 v2.2

## 项目简介

本工具用于对宿主机下的容器环境进行全面安全扫描，基于行业标准安全规范，自动化检测潜在的安全风险。

## 工具列表

| 脚本 | 功能 | 用法 |
|------|------|------|
| `container_security_scan.sh` | 容器安全扫描 | `./container_security_scan.sh [容器名...]` |
| `repo_security_scan.sh` | 代码仓库安全扫描 | `./repo_security_scan.sh <仓库路径>` |
| `nginx_security_scan.sh` | Nginx安全规范专项扫描 | `./nginx_security_scan.sh -c <配置文件>` |

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

| 序号 | 模块名称 | 包含规范 |
|------|---------|---------|
| 1 | 全零IP暴露检查 | Nginx_2_2_6, D_SCS_3_1 |
| 2 | SSL/TLS证书检查 | D_IAM_55_1, D_IAM_53_1, D_IAM_53_2, D_IAM_62_1 |
| 3 | 加密套件检查 | Nginx_2_7_4, D_CAS_8_1, D_CAS_2_2, D_CAS_2_1, D_CAS_25_1, Nginx_2_7_3 |
| 4 | 敏感信息泄露检查 | Other_1_2, Other_1_1, Other_1_4, Other_1_5, D_IAM_17_3 |
| 5 | Nginx安全配置检查 | Nginx_2_1_2, Nginx_2_1_3, Nginx_2_2_1, Nginx_2_2_4, Nginx_2_2_8, Nginx_2_2_9, Nginx_2_2_10, Nginx_2_4_1, Nginx_2_6_1, Nginx_2_7_1, Nginx_2_7_2, Nginx_2_8_1 |
| 6 | 端口暴露检查 | D_SCS_3_1 |
| 7 | 容器安全基线检查 | D_IAM_48_1 |
| 8 | 镜像安全检查 | - |
| 9 | 网络安全检查 | D_IDS_1_1 |
| 10 | 日志与审计检查 | D_IAM_36_1, D_LUS_5_1, D_LUS_5_2 |
| 11 | MD5密码安全检查 | D_CAS_2_4 |
| 12 | 代码口令硬编码检查 | D_IAM_12_5, D_KMS_5_1 |
| 13 | 安全椭圆曲线检查 | Nginx_2_7_5 |
| 14 | Base64编码加密检查 | D_CAS_1_4 |
| 15 | 用户权限检查 | D_IAM_3_1, D_IAM_27_2, D_IAM_37_5, D_IAM_42_3, D_IAM_16_1, D_IAM_9_1, D_IAM_10_1, D_IAM_46_1 |
| 16 | 文件权限检查 | D_IAM_49_1, D_IAM_42_1, Nginx_2_3_1, Nginx_2_3_2, D_IAM_44_1 |
| 17 | 密钥长度检查 | D_IAM_54_1, D_IAM_54_2, D_CAS_2_5, D_CAS_2_6 |
| 18 | SSH配置检查 | D_CAS_26_1 |
| 19 | 不安全函数检查 | RL_13_1_2_1 |
| 20 | 公网IP硬编码检查 | public_ip_check, D_SCS_4_2 |
| 21 | 证书签名算法检查 | D_IAM_53_1, D_IAM_53_2, D_IAM_62_1 |
| 22 | 会话安全检查 | D_SMS_16_1, D_IDS_2_2 |
| 23 | 安全残留工具检查 | D_SCS_5_4 |
| 24 | MyBatis配置检查 | D_IAM_45_1 |
| 25 | 内存敏感信息扫描 | D_IAM_14_6 |
| 26 | 暴力破解防护检查 | D_SCS_2_10 |

## 使用方法

### 容器安全扫描

```bash
# 扫描所有运行中的容器
./container_security_scan.sh

# 扫描指定容器
./container_security_scan.sh nginx mysql

# 列出所有容器
./container_security_scan.sh -l

# 显示帮助
./container_security_scan.sh -h

# 扫描结果保存在 /tmp/container_security_scan_* 目录
# 报告格式: Markdown (security_report.md)
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

#### 代码仓库扫描模块

| 序号 | 模块名称 | 功能说明 |
|------|---------|---------|
| 1 | DOS漏洞检测 | 检测无限循环、大文件读取未限制等 |
| 2 | ReDoS漏洞检测 | 检测危险的正则表达式模式 |
| 3 | 代码质量检查 | 使用Semgrep进行静态分析 |
| 4 | 不安全算法排查 | 检测MD5/SHA1/DES/RC4等弱加密算法 |
| 5 | Web应用安全检查 | SQL注入、XSS、命令注入、路径遍历检测 |
| 6 | Trivy漏洞扫描 | 依赖漏洞和文件系统漏洞扫描 |
| 7 | Gitleaks敏感信息 | 检测API密钥、密码等敏感信息泄露 |

#### 外部工具依赖

脚本会自动安装以下工具:
- **trivy** - 容器镜像和文件系统漏洞扫描
- **gitleaks** - 敏感信息泄露扫描
- **semgrep** - 静态代码分析

### Nginx安全规范专项扫描

```bash
# 扫描指定Nginx配置文件
./nginx_security_scan.sh -c /path/to/nginx.conf

# 扫描指定Nginx配置目录
./nginx_security_scan.sh -d /etc/nginx

# 显示帮助
./nginx_security_scan.sh -h
```

#### Nginx规范检查项 (48项)

**必须项 (高优先级):**

| 分类 | 检查项 |
|------|--------|
| 安装安全 | 删除缺省文件、最小化安装、禁止webDAV |
| 网络绑定 | 绑定特定IP地址 |
| 功能配置 | 禁用SSI、禁用不必要的HTTP方法 |
| 账号安全 | 非特权账号运行、锁定账号、禁止登录shell |
| 文件权限 | 目录550、配置440、日志640、PID文件640 |
| 安全防护 | alias安全、try_files安全、CRLF注入防护 |
| SSL/TLS | 安全协议、安全加密套件、会话缓存、OCSP |
| 信息隐藏 | 隐藏版本、隐藏X-Powered-By、禁用目录列表 |
| 日志审计 | 开启访问日志、错误日志 |
| HTTP安全头 | X-Frame-Options、X-Content-Type-Options、HSTS等 |

**建议项 (低优先级):**

- IP访问限制、防盗链、连接数限制、速率限制
- 禁用隐藏文件服务、Referer策略配置等

## 输出报告

扫描完成后生成以下文件:
- `security_report.md` - Markdown格式的详细报告，包含问题级别标记和规范编号
- `security_report.json` - JSON格式报告(预留)

## 问题级别定义

| 级别 | 标识 | 说明 |
|------|------|------|
| 严重(Critical) | 🚨 | 需立即修复的高危问题 |
| 高危(High) | ❌ | 重要安全问题，如过期证书、弱加密套件、MD5密码 |
| 中危(Medium) | ⚠️ | 需关注的问题，如全零IP暴露、未配置资源限制 |
| 低危(Low) | 信息提示 | 建议改进的配置项 |

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

### 用户权限
- 禁止root远程SSH登录
- 配置密码复杂度和使用期限
- 设置合理的umask值(>=027)

## 后续扩展计划

- [ ] Kubernetes安全配置检查
- [ ] 容器逃逸风险检测
- [ ] 镜像签名验证
- [ ] 实时监控模式
- [ ] JSON详细报告输出
- [ ] 支持自定义扫描项