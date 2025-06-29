import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import json
import base64
from Crypto.Cipher import DES
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.exceptions import InvalidSignature

HOST = 'localhost'
PORT = 23456

# ==================== PHẦN CỦA NGUYỄN VĂN PHÚC ====================
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def verify_signature(public_key, signature: bytes, data: bytes):
    try:
        public_key.verify(
            signature,
            data,
            PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
# ==================== END PHÚC ====================

# ==================== PHẦN CỦA TRẦN VĂN PHONG ====================
def decrypt_des(des_key, iv, ciphertext: bytes):
    cipher = DES.new(des_key, DES.MODE_CFB, iv)
    return cipher.decrypt(ciphertext)
# ==================== END PHONG ====================

class SecureMessengerReceiver:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messenger - Người nhận")
        self.setup_ui()
        
        # Khởi tạo RSA
        self.receiver_private_key, self.receiver_public_key = generate_rsa_key_pair()
        self.des_key = None
        self.sender_public_key = None
        self.server_socket = None
        self.client_socket = None

    def setup_ui(self):
        # ==================== PHẦN CỦA PHAN LƯU PHONG ====================
        # Frame trạng thái
        status_frame = tk.LabelFrame(self.root, text="Trạng thái", padx=10, pady=10)
        status_frame.pack(padx=10, pady=5, fill="x")
        
        tk.Button(status_frame, text="Bắt đầu lắng nghe", command=self.start_server).pack(side="left", padx=5)
        self.status_label = tk.Label(status_frame, text="❌ Chưa kết nối", fg="red")
        self.status_label.pack(side="left", padx=10)
        
        # Frame tin nhắn
        msg_frame = tk.LabelFrame(self.root, text="Tin nhắn nhận được", padx=10, pady=10)
        msg_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.message_display = scrolledtext.ScrolledText(msg_frame, height=10, state="disabled")
        self.message_display.pack(fill="both", expand=True)
        
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

    def display_message(self, message):
        self.message_display.config(state="normal")
        self.message_display.insert("end", message + "\n")
        self.message_display.config(state="disabled")
        self.message_display.see("end")

    def start_server(self):
        try:
            # ==================== PHẦN CỦA LÊ HỒNG PHI ====================
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(1)
            
            self.status_label.config(text="🟡 Đang chờ kết nối...", fg="orange")
            self.log(f"🧭 Đang lắng nghe tại {HOST}:{PORT}...")
            
            # Chạy trong thread riêng để không block GUI
            import threading
            threading.Thread(target=self.accept_connection, daemon=True).start()
            # ==================== END PHI ====================
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Khởi động server thất bại: {str(e)}")
            self.log(f"❌ Lỗi khởi động server: {str(e)}")

    def accept_connection(self):
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.root.after(0, lambda: self.status_label.config(text=f"✅ Đã kết nối với {addr[0]}", fg="green"))
            self.root.after(0, lambda: self.log(f"🔗 Đã kết nối với {addr}"))
            
            # ==================== PHẦN CỦA LÊ HỒNG PHI ====================
            hello = self.client_socket.recv(1024).decode()
            if hello != "Hello!":
                raise ConnectionError("Handshake failed")
            
            self.client_socket.sendall(b"Ready!")
            self.root.after(0, lambda: self.log("🤝 Handshake thành công"))
            
            # Gửi public key RSA
            self.client_socket.sendall(serialize_public_key(self.receiver_public_key))
            
            # Nhận thông tin xác thực
            secure_data = self.client_socket.recv(4096)
            auth_packet = json.loads(secure_data.decode())
            encrypted_des_key = base64.b64decode(auth_packet["encrypted_des_key"])
            signed_info = base64.b64decode(auth_packet["signed_info"])
            
            # Nhận public key của sender
            sender_pub_bytes = self.client_socket.recv(4096)
            self.sender_public_key = serialization.load_pem_public_key(sender_pub_bytes)
            
            # ==================== PHẦN CỦA NGUYỄN VĂN PHÚC ====================
            if not verify_signature(self.sender_public_key, signed_info, b"sender_id"):
                raise ValueError("Chữ ký định danh không hợp lệ")
            
            self.des_key = self.receiver_private_key.decrypt(
                encrypted_des_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
            self.root.after(0, lambda: self.log("🔑 Đã nhận khóa DES an toàn"))
            # ==================== END PHÚC ====================
            
            # Bắt đầu lắng nghe tin nhắn
            self.receive_messages()
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Lỗi", f"Xử lý kết nối thất bại: {str(e)}"))
            self.root.after(0, lambda: self.log(f"❌ Lỗi kết nối: {str(e)}"))

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                    
                # ==================== PHẦN CỦA TRẦN VĂN PHONG & NGUYỄN VĂN PHÚC ====================
                payload = json.loads(data.decode())
                ciphertext = base64.b64decode(payload["cipher"])
                iv = base64.b64decode(payload["iv"])
                msg_hash = payload["hash"]
                signature = base64.b64decode(payload["sig"])
                
                # Kiểm tra hash
                if sha256(ciphertext).hexdigest() != msg_hash:
                    self.root.after(0, lambda: self.log("❌ Hash không khớp! Dữ liệu có thể bị sửa."))
                    continue
                
                # Xác thực chữ ký
                if not verify_signature(self.sender_public_key, signature, ciphertext):
                    self.root.after(0, lambda: self.log("❌ Chữ ký không hợp lệ!"))
                    continue
                
                # Giải mã
                plaintext = decrypt_des(self.des_key, iv, ciphertext)
                self.root.after(0, lambda: self.display_message(f"Người gửi: {plaintext.decode()}"))
                self.root.after(0, lambda: self.log(f"📩 Đã nhận tin nhắn bảo mật"))
                # ==================== END PHONG & PHÚC ====================
                
        except Exception as e:
            self.root.after(0, lambda: self.log(f"❌ Lỗi nhận tin nhắn: {str(e)}"))

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessengerReceiver(root)
    root.mainloop()
