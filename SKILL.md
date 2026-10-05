---
name: ubuntu-server-hardening
description: 给 Ubuntu 服务器做 SSH + 防火墙 + fail2ban 三件套安全加固，带 10 分钟自动回滚安全网、改前备份、事后实测验证。当要在服务器上关 SSH 密码登录、限制 root 直登、启用 ufw、装 fail2ban，或要排查「fail2ban 装了却一条日志都抓不到」时使用。含两个会静默失效的坑（Ubuntu 的 SSH 单元名是 ssh.service 而非 sshd.service；jail 配置缺 [DEFAULT] 段头会直接启动失败）。
agent_created: true
---

# Ubuntu 服务器安全加固闭环（SSH + ufw + fail2ban）

## 适用场景
- 新纳管的服务器要做基线加固
- 审计发现 `PasswordAuthentication yes` / `PermitRootLogin yes` / `ufw inactive` / 无 fail2ban
- fail2ban 显示 running 但「Currently failed: 0」永远是 0 —— 很可能 journalmatch 错了（见坑一）

## 铁律：动手前先做这三件事

1. **确认密钥登录真的能用**——这是唯一能救命的东西。
   ```bash
   ssh -o BatchMode=yes -o ConnectTimeout=10 <别名> 'whoami'
   ```
   `BatchMode=yes` 会禁用一切交互式认证，能成功就说明纯公钥登录可用。
2. **确认 sudo 免密**：`sudo -n true`。**关掉密码登录后，sudo 若还要密码就无法自救。**
3. **确认目标用户有 authorized_keys**：
   ```bash
   sudo bash -c 'for h in /root /home/*; do [ -s $h/.ssh/authorized_keys ] && echo "$h: $(wc -l < $h/.ssh/authorized_keys)"; done'
   ```
   ⚠️ 常见误判：root 有密码但**没有** authorized_keys。此时设 `PermitRootLogin prohibit-password` 会彻底封掉 root 直登——这通常正是想要的，但必须知情。

---

## 执行流程

### 第 0 步：备份 + 挂自动回滚安全网

```bash
TS=$(date +%Y%m%d-%H%M%S); BK=/root/ops-hardening-bak-$TS; mkdir -p "$BK"
cp -a /etc/ssh/sshd_config "$BK/"; cp -a /etc/ssh/sshd_config.d "$BK/"; cp -a /etc/default/ufw "$BK/"

# 10 分钟后若没人取消，就自动回退（把配置删掉 + ufw 关掉）
systemd-run --on-active=10min --unit=ops-revert --collect /bin/bash -c \
  "rm -f /etc/ssh/sshd_config.d/99-ops-hardening.conf; systemctl reload ssh; ufw --force disable; date >> /root/ops-revert.log; echo AUTO-REVERT >> /root/ops-revert.log"
```
**验证全部通过后**再取消：
```bash
sudo systemctl stop ops-revert.timer; sudo systemctl reset-failed ops-revert.service
sudo cat /root/ops-revert.log   # 应为空 = 没触发过
```

### 第 1 步：SSH 加固（用 drop-in，别改主文件）

Ubuntu 22.04 的 `/etc/ssh/sshd_config` 第 12 行有 `Include /etc/ssh/sshd_config.d/*.conf`，
drop-in 优先级更高、可随时删掉回退。

```bash
cat > /etc/ssh/sshd_config.d/99-ops-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 4
EOF
sshd -t && systemctl reload ssh     # 用 reload，不用 restart；先 -t 校验
```
注意：`PermitRootLogin` 生效值显示为 `without-password`（等价于 `prohibit-password`）。

### 第 2 步：ufw（**先放行 22，再 enable**）

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp          # ← 必须在 enable 之前
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```
- 已建立的连接不会被切断（ufw 自带 ESTABLISHED,RELATED 规则），所以**不会**踢掉当前 SSH 会话。
- 开之前先 `ss -lntp` 看清有哪些对外端口，别漏放行。

### 第 3 步：fail2ban

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq fail2ban

cat > /etc/fail2ban/jail.d/ops-hardening.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1 <自己的出口IP>

[sshd]
enabled = true
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
EOF
systemctl enable --now fail2ban
sleep 4 && systemctl is-active fail2ban
```

---

## 🔴 坑一：Ubuntu 的 SSH 单元名是 `ssh.service`，不是 `sshd.service`

fail2ban 的 `[sshd]` jail 默认 `journalmatch` 是 `_SYSTEMD_UNIT=sshd.service`。
Ubuntu/Debian 上服务叫 `ssh.service` → **journalmatch 匹配不到任何日志，fail2ban 看着在跑、实际一个人都封不了**，而且不报错。

**必须显式覆盖**（如上配置里的 `journalmatch` 那行）。

**验证方法**（jail 状态里看 `Journal matches` 是不是你要的那个）：
```bash
sudo fail2ban-client status sshd        # 看 "Journal matches:" 行
sudo journalctl _SYSTEMD_UNIT=ssh.service -n 2 --no-pager   # 有输出 = 单元名对
sudo journalctl _SYSTEMD_UNIT=sshd.service -n 2 --no-pager  # "No entries" = 默认值错了
```
**再验证过滤器真能命中**（用真实日志跑正则，比等真实攻击快）：
```bash
sudo journalctl _SYSTEMD_UNIT=ssh.service --since "7 days ago" --no-pager > /tmp/j.txt
sudo fail2ban-regex /tmp/j.txt /etc/fail2ban/filter.d/sshd.conf | grep -A10 Results
sudo rm -f /tmp/j.txt   # 里面含 IP，用完就删
```
> `fail2ban-regex` 直接接 `systemd-journal[journalmatch=...]` 在 0.11.2 上会抛
> `TypeError: Filter.__init__() got an unexpected keyword argument 'journalmatch'` —— 别纠缠，落文件再跑。

## 🔴 坑二：jail 配置缺 `[DEFAULT]` 段头 → fail2ban 直接启动失败

用 `echo "bantime = 1h" > file` 然后 `cat >> file` 追加内容时，如果 `[DEFAULT]` 写在追加部分里，
就先写了一条没有段头的键 → 启动报：
```
ERROR Failed during configuration: File contains no section headers.
file: '/etc/fail2ban/jail.d/xxx.local', line: 1
```
**一定要用单个 heredoc 从 `[DEFAULT]` 开始写。**

## 坑三：`sudo cmd > /root/x.log` 的权限陷阱

```bash
sudo nohup bash script.sh > /root/log 2>&1 &     # ❌ 重定向由当前用户执行 -> Permission denied
sudo bash -c "nohup bash script.sh > /root/log 2>&1 &"   # ✅ 重定向在 root 里做
```

---

## 收尾验证清单（每条都要实测，不能只看配置）

```bash
# 1 配置生效
sudo /usr/sbin/sshd -T | grep -iE "^passwordauthentication|^permitrootlogin|^maxauthtries"
# 2 密码登录被拒（期望 Permission denied (publickey)）
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 <别名> 'echo BAD'
# 3 root 直登被拒
ssh -o BatchMode=yes root@<IP> 'echo BAD'
# 4 密钥登录仍正常
ssh -o BatchMode=yes <别名> 'echo OK'
# 5 防火墙
sudo ufw status verbose
# 6 fail2ban
sudo fail2ban-client status sshd
# 7 业务没被弄坏（换成该站真实探针）
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" -L https://<域名>/
```
全部通过后：
```bash
sudo systemctl stop ops-revert.timer; sudo systemctl reset-failed ops-revert.service
sudo rm -f /root/hardening.sh /tmp/hardening.sh   # 清理脚本
```

## 注意

- 别在同一个动作里顺手做 `apt upgrade`——内核/服务重启会引入与本次无关的变量；补丁另开一次。
- 加固不改变业务端口，但有安全组（云厂商）时 ufw 只是第二层，**云控制台安全组别忘同步核对**。
- 适用面不限发行版细节：原生 nginx 的 Ubuntu 主机（如 SaaS 单服务机，systemd 托管）与宝塔托管的主机都适用本流程；宝塔机会有面板自身的覆盖行为（面板可能重置 nginx 配置或自带防火墙界面），改动后要在面板内外双侧核对。
