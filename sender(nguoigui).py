import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import json
import base64
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1

HOST = 'localhost'
PORT = 23456

# ==================== PHẦN CỦA NGUYỄN VĂN PHÚC ====================
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def sign_data(private_key, data: bytes):
    return private_key.sign(
        data,
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
# ==================== END PHÚC ====================

# ==================== PHẦN CỦA TRẦN VĂN PHONG ====================
def encrypt_des(des_key, plaintext: bytes):
    iv = get_random_bytes(8)
    cipher = DES.new(des_key, DES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv, ciphertext
# ==================== END PHONG ====================

class SecureMessengerSender:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messenger - Người gửi")
        self.setup_ui()
        
        # Khởi tạo RSA
        self.sender_private_key, self.sender_public_key = generate_rsa_key_pair()
        self.des_key = None
        self.receiver_public_key = None
        self.socket = None

    def setup_ui(self):
        # ==================== PHẦN CỦA PHAN LƯU PHONG ====================
        # Frame kết nối
        conn_frame = tk.LabelFrame(self.root, text="Kết nối", padx=10, pady=10)
        conn_frame.pack(padx=10, pady=5, fill="x")
        
        tk.Button(conn_frame, text="Kết nối", command=self.connect).pack(side="left", padx=5)
        self.conn_status = tk.Label(conn_frame, text="❌ Chưa kết nối", fg="red")
        self.conn_status.pack(side="left", padx=10)
        
        # Frame tin nhắn
        msg_frame = tk.LabelFrame(self.root, text="Tin nhắn", padx=10, pady=10)
        msg_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.message_entry = scrolledtext.ScrolledText(msg_frame, height=10)
        self.message_entry.pack(fill="both", expand=True)
        
        tk.Button(msg_frame, text="Gửi tin nhắn", command=self.send_message).pack(pady=5)
        
        # Frame log
        log_frame = tk.LabelFrame(self.root, text="Nhật ký hoạt động", padx=10, pady=10)
        log_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, state="disabled")
        self.log_area.pack(fill="both", expand=True)
        # ==================== END PHONG ====================

    def log(self, message):
        self.log_area.config(state="normal")
        self.log_area.insert("end", message + "\n")
        self.log_area.config(state="disabled")
        self.log_area.see("end")

    def connect(self):
        try:
            # ==================== PHẦN CỦA LÊ HỒNG PHI ====================
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            self.socket.sendall(b"Hello!")
            
            if self.socket.recv(1024).decode() != "Ready!":
                raise ConnectionError("Handshake failed")
            
            self.log("🤝 Handshake thành công với người nhận")
            self.conn_status.config(text="✅ Đã kết nối", fg="green")
            
            # Nhận public key từ receiver
            receiver_pub_bytes = self.socket.recv(4096)
            self.receiver_public_key = serialization.load_pem_public_key(receiver_pub_bytes)
            
            # Trao đổi khóa DES
            self.des_key = get_random_bytes(8)
            encrypted_des_key = self.receiver_public_key.encrypt(
                self.des_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
            
            signed_info = sign_data(self.sender_private_key, b"sender_id")
            auth_packet = {
                "signed_info": base64.b64encode(signed_info).decode(),
                "encrypted_des_key": base64.b64encode(encrypted_des_key).decode()
            }
            self.socket.sendall(json.dumps(auth_packet).encode())
            
            # Gửi public key của sender
            self.socket.sendall(serialize_public_key(self.sender_public_key))
            self.log("🔑 Đã trao đổi khóa DES an toàn")
            # ==================== END PHI ====================
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Kết nối thất bại: {str(e)}")
            self.log(f"❌ Lỗi kết nối: {str(e)}")

    def send_message(self):
        if not self.socket:
            messagebox.showwarning("Cảnh báo", "Vui lòng kết nối trước khi gửi tin nhắn")
            return
            
        message = self.message_entry.get("1.0", "end-1c").strip()
        if not message:
            return
            
        try:
            # ==================== PHẦN CỦA TRẦN VĂN PHONG ====================
            iv, ciphertext = encrypt_des(self.des_key, message.encode())
            msg_hash = sha256(ciphertext).hexdigest()
            # ==================== END PHONG ====================
            
            # ==================== PHẦN CỦA NGUYỄN VĂN PHÚC ====================
            signature = sign_data(self.sender_private_key, ciphertext)
            # ==================== END PHÚC ====================
            
            payload = {
                "cipher": base64.b64encode(ciphertext).decode(),
                "iv": base64.b64encode(iv).decode(),
                "hash": msg_hash,
                "sig": base64.b64encode(signature).decode()
            }
            
            self.socket.sendall(json.dumps(payload).encode())
            self.log(f"✉️ Đã gửi tin nhắn bảo mật: {message}")
            self.message_entry.delete("1.0", "end")
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Gửi tin nhắn thất bại: {str(e)}")
            self.log(f"❌ Lỗi khi gửi: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessengerSender(root)
    root.mainloop()
