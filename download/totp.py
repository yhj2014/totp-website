import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyotp
import qrcode
import cv2
from PIL import Image, ImageTk
import base64
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import threading
import webbrowser
import sys
import hashlib
import gettext
import platform

# === 多语言支持初始化 ===
LOCALE_DIR = 'locales'
os.makedirs(LOCALE_DIR, exist_ok=True)

# 初始化国际化
try:
    lang = gettext.translation('totp', localedir=LOCALE_DIR, languages=['zh_CN'])
    lang.install()
    _ = lang.gettext
except FileNotFoundError:
    _ = gettext.gettext

# === 主密码保护模块 ===
class AuthManager:
    def __init__(self):
        self.auth_file = "auth.enc"
        self.key_file = "secret.key"
        self.crypto_key = None
        self.cipher = None
        self.load_or_generate_key()
        
    def load_or_generate_key(self):
        """加载或生成加密密钥"""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                self.crypto_key = f.read()
        else:
            self.crypto_key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(self.crypto_key)
        self.cipher = Fernet(self.crypto_key)
    
    def encrypt_data(self, data):
        """加密数据"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """解密数据"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def hash_password(self, password):
        """PBKDF2密码哈希"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            self.crypto_key,
            100000
        ).hex()
    
    def set_master_password(self, password):
        """设置主密码"""
        hashed = self.hash_password(password)
        with open(self.auth_file, "w") as f:
            f.write(self.encrypt_data(hashed))
    
    def verify_password(self, password):
        """验证密码"""
        if not os.path.exists(self.auth_file):
            return True  # 首次使用无需验证
        
        with open(self.auth_file, "r") as f:
            stored_hash = self.decrypt_data(f.read())
        
        return self.hash_password(password) == stored_hash

# === 生物识别模块 ===
class BiometricAuth:
    @staticmethod
    def is_available():
        """检查生物识别是否可用"""
        if platform.system() == 'Android':
            try:
                from android.permissions import Permission, request_permissions
                from jnius import autoclass
                return True
            except ImportError:
                return False
        return False
    
    @staticmethod
    def authenticate(callback):
        """执行生物识别认证"""
        if platform.system() == 'Android':
            try:
                from jnius import autoclass
                Context = autoclass('android.content.Context')
                FingerprintManager = autoclass('android.hardware.fingerprint.FingerprintManager')
                
                context = autoclass('org.kivy.android.PythonActivity').mActivity
                fingerprint_manager = context.getSystemService(Context.FINGERPRINT_SERVICE)
                
                if not fingerprint_manager.isHardwareDetected():
                    raise Exception(_("未检测到指纹硬件"))
                
                if not fingerprint_manager.hasEnrolledFingerprints():
                    raise Exception(_("未录入指纹"))
                
                # 简化版实现（实际需要实现AuthenticationCallback）
                callback(True, None)
            except Exception as e:
                callback(False, str(e))
        else:
            callback(False, _("非Android平台"))

# === 主应用类 ===
class TOTPApp:
    def __init__(self, root):
        self.root = root
        self.root.title(_("TOTP认证器"))
        self.root.geometry("400x600")
        
        # 初始化管理器
        self.auth_manager = AuthManager()
        self.accounts = {}
        self.cap = None
        self.scanning = False
        
        # 检查认证
        if os.path.exists(self.auth_manager.auth_file):
            self.show_auth_dialog()
        else:
            self.setup_ui()
    
    # === 认证相关方法 ===
    def show_auth_dialog(self):
        """显示认证对话框"""
        self.auth_dialog = tk.Toplevel(self.root)
        self.auth_dialog.title(_("身份验证"))
        self.auth_dialog.geometry("300x250")
        self.auth_dialog.resizable(False, False)
        self.center_window(self.auth_dialog)
        self.auth_dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        
        ttk.Label(self.auth_dialog, text=_("请输入主密码:")).pack(pady=(20, 5))
        self.password_entry = ttk.Entry(self.auth_dialog, show="*")
        self.password_entry.pack(pady=5, ipady=5)
        self.password_entry.focus()
        
        # 生物识别按钮
        if BiometricAuth.is_available():
            ttk.Button(
                self.auth_dialog, 
                text=_("使用指纹验证"), 
                command=self.use_biometric
            ).pack(pady=10)
        
        ttk.Button(
            self.auth_dialog, 
            text=_("验证"), 
            command=self.verify_master_password
        ).pack(pady=10)
        
        self.status_label = ttk.Label(self.auth_dialog, text="", foreground="red")
        self.status_label.pack()
    
    def use_biometric(self):
        """使用生物识别认证"""
        def callback(success, error=None):
            if success:
                self.auth_dialog.destroy()
                self.setup_ui()
            else:
                self.status_label.config(text=_("生物识别失败: ") + (error or _("未知错误")))
        
        BiometricAuth.authenticate(callback)
    
    def verify_master_password(self):
        """验证主密码"""
        password = self.password_entry.get()
        if not password:
            self.status_label.config(text=_("密码不能为空"))
            return
        
        if self.auth_manager.verify_password(password):
            self.auth_dialog.destroy()
            self.setup_ui()
        else:
            self.status_label.config(text=_("密码错误"))
    
    # === 主界面 ===
    def setup_ui(self):
        """初始化主界面"""
        self.create_menu()
        
        # 顶部按钮
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text=_("添加账户"), command=self.show_add_account_dialog).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text=_("扫描二维码"), command=self.start_scan).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text=_("在线解码"), command=self.open_online_decoder).grid(row=0, column=2, padx=5)
        
        # 账户列表
        self.tree = ttk.Treeview(self.root, columns=("issuer", "code"), show="headings")
        self.tree.heading("issuer", text=_("账户"))
        self.tree.heading("code", text=_("验证码"))
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 右键菜单
        self.create_context_menu()
        
        # 状态栏
        self.status_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self.status_var).pack(fill=tk.X, padx=10, pady=5)
        
        self.load_accounts()
        self.update_codes()
    
    def create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=_("设置主密码"), command=self.show_set_password_dialog)
        file_menu.add_command(label=_("切换语言"), command=self.show_language_dialog)
        file_menu.add_separator()
        file_menu.add_command(label=_("退出"), command=self.on_closing)
        menubar.add_cascade(label=_("文件"), menu=file_menu)
        
        self.root.config(menu=menubar)
    
    def create_context_menu(self):
        """创建右键菜单"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label=_("复制验证码"), command=self.copy_code)
        self.context_menu.add_command(label=_("删除账户"), command=self.delete_account)
        self.context_menu.add_command(label=_("显示密钥"), command=self.show_secret)
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    # === 账户管理 ===
    def show_add_account_dialog(self):
        """显示添加账户对话框"""
        self.add_dialog = tk.Toplevel(self.root)
        self.add_dialog.title(_("添加TOTP账户"))
        self.add_dialog.geometry("400x300")
        
        ttk.Label(self.add_dialog, text=_("账户名称:")).pack(pady=(10,0))
        self.issuer_entry = ttk.Entry(self.add_dialog)
        self.issuer_entry.pack(pady=5, padx=10, fill=tk.X)
        
        ttk.Label(self.add_dialog, text=_("密钥:")).pack()
        self.secret_entry = ttk.Entry(self.add_dialog)
        self.secret_entry.pack(pady=5, padx=10, fill=tk.X)
        
        ttk.Label(self.add_dialog, text=_("或从图片导入:")).pack()
        img_btn_frame = ttk.Frame(self.add_dialog)
        img_btn_frame.pack(pady=5)
        
        ttk.Button(img_btn_frame, text=_("选择图片"), command=self.import_from_image).pack(side=tk.LEFT, padx=5)
        
        btn_frame = ttk.Frame(self.add_dialog)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text=_("添加"), command=self.add_account).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text=_("取消"), command=self.add_dialog.destroy).pack(side=tk.LEFT, padx=10)
    
    def import_from_image(self):
        """从图片导入二维码"""
        file_path = filedialog.askopenfilename(filetypes=[(_("图片文件"), "*.png;*.jpg;*.jpeg")])
        if file_path:
            try:
                img = cv2.imread(file_path)
                detector = cv2.QRCodeDetector()
                data, _, _ = detector.detectAndDecode(img)
                
                if data:
                    self.process_otp_uri(data)
                else:
                    messagebox.showerror(_("错误"), _("未在图片中找到有效的二维码"))
            except Exception as e:
                messagebox.showerror(_("错误"), _("解析二维码时出错: {}").format(str(e)))
    
    def process_otp_uri(self, uri):
        """处理OTP URI"""
        try:
            if uri.startswith("otpauth://totp/"):
                parts = uri.split("?")
                path_part = parts[0]
                query_part = parts[1] if len(parts) > 1 else ""
                
                issuer_account = path_part[len("otpauth://totp/"):]
                issuer = issuer_account.split(":")[0] if ":" in issuer_account else issuer_account
                
                params = dict(param.split("=") for param in query_part.split("&"))
                secret = params.get("secret", "")
                
                if hasattr(self, 'add_dialog') and self.add_dialog.winfo_exists():
                    self.issuer_entry.delete(0, tk.END)
                    self.issuer_entry.insert(0, issuer)
                    self.secret_entry.delete(0, tk.END)
                    self.secret_entry.insert(0, secret)
                else:
                    self.add_account_from_data(issuer, secret)
                
                self.status_var.set(_("成功从二维码导入账户: {}").format(issuer))
            else:
                messagebox.showerror(_("错误"), _("不是有效的TOTP URI"))
        except Exception as e:
            messagebox.showerror(_("错误"), _("解析URI时出错: {}").format(str(e)))
    
    def add_account(self):
        """添加账户"""
        issuer = self.issuer_entry.get().strip()
        secret = self.secret_entry.get().strip()
        
        if not issuer or not secret:
            messagebox.showerror(_("错误"), _("账户名称和密钥不能为空"))
            return
        
        try:
            pyotp.TOTP(secret).now()
            self.add_account_from_data(issuer, secret)
            self.add_dialog.destroy()
        except Exception as e:
            messagebox.showerror(_("错误"), _("无效的密钥: {}").format(str(e)))
    
    def add_account_from_data(self, issuer, secret):
        """从数据添加账户"""
        if issuer in self.accounts:
            messagebox.showerror(_("错误"), _("该账户已存在"))
            return
        
        self.accounts[issuer] = {
            "secret": secret,
            "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.save_accounts()
        self.update_account_list()
        self.status_var.set(_("已添加账户: {}").format(issuer))
    
    # === 二维码扫描 ===
    def start_scan(self):
        """开始扫描"""
        if self.scanning:
            return
        
        self.scan_dialog = tk.Toplevel(self.root)
        self.scan_dialog.title(_("扫描二维码"))
        self.scan_dialog.geometry("400x400")
        
        self.video_frame = ttk.Label(self.scan_dialog)
        self.video_frame.pack(pady=10)
        
        ttk.Button(self.scan_dialog, text=_("停止扫描"), command=self.stop_scan).pack()
        
        self.cap = cv2.VideoCapture(0)
        self.scanning = True
        self.scan_qr_code()
    
    def scan_qr_code(self):
        """扫描二维码"""
        if not self.scanning:
            return
        
        ret, frame = self.cap.read()
        if ret:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            detector = cv2.QRCodeDetector()
            data, vertices, _ = detector.detectAndDecode(frame)
            
            if data:
                self.stop_scan()
                self.process_otp_uri(data)
                return
            
            img = Image.fromarray(frame)
            imgtk = ImageTk.PhotoImage(image=img)
            self.video_frame.imgtk = imgtk
            self.video_frame.configure(image=imgtk)
        
        self.video_frame.after(50, self.scan_qr_code)
    
    def stop_scan(self):
        """停止扫描"""
        if self.cap:
            self.cap.release()
            self.cap = None
        self.scanning = False
        if hasattr(self, 'scan_dialog') and self.scan_dialog.winfo_exists():
            self.scan_dialog.destroy()
    
    # === 其他功能 ===
    def show_set_password_dialog(self):
        """显示设置密码对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title(_("设置主密码"))
        dialog.geometry("300x200")
        self.center_window(dialog)
        
        ttk.Label(dialog, text=_("新密码:")).pack(pady=(10, 0))
        self.new_password_entry = ttk.Entry(dialog, show="*")
        self.new_password_entry.pack(pady=5, ipady=5)
        
        ttk.Label(dialog, text=_("确认密码:")).pack()
        self.confirm_password_entry = ttk.Entry(dialog, show="*")
        self.confirm_password_entry.pack(pady=5, ipady=5)
        
        ttk.Button(dialog, text=_("设置"), command=self.set_password).pack(pady=10)
        
        self.password_status = ttk.Label(dialog, text="", foreground="red")
        self.password_status.pack()
    
    def set_password(self):
        """设置密码"""
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not new_password:
            self.password_status.config(text=_("密码不能为空"))
            return
        
        if new_password != confirm_password:
            self.password_status.config(text=_("两次输入的密码不一致"))
            return
        
        self.auth_manager.set_master_password(new_password)
        self.password_status.config(text=_("主密码设置成功"), foreground="green")
    
    def show_language_dialog(self):
        """显示语言选择对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title(_("选择语言"))
        dialog.geometry("200x150")
        self.center_window(dialog)
        
        ttk.Label(dialog, text=_("请选择语言:")).pack(pady=10)
        
        ttk.Button(dialog, text="中文", command=lambda: self.change_language('zh_CN')).pack(pady=5)
        ttk.Button(dialog, text="English", command=lambda: self.change_language('en')).pack(pady=5)
    
    def change_language(self, lang_code):
        """切换语言"""
        try:
            global _
            lang = gettext.translation('totp', localedir=LOCALE_DIR, languages=[lang_code])
            lang.install()
            _ = lang.gettext
            
            # 重新加载界面
            for widget in self.root.winfo_children():
                widget.destroy()
            self.setup_ui()
        except Exception as e:
            messagebox.showerror(_("错误"), _("语言切换失败: {}").format(str(e)))
    
    def open_online_decoder(self):
        """打开在线解码器"""
        webbrowser.open("https://zxing.org/w/decode.jspx")
    
    def show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_code(self):
        """复制验证码"""
        item = self.tree.selection()[0]
        code = self.tree.item(item, "values")[1]
        self.root.clipboard_clear()
        self.root.clipboard_append(code)
        self.status_var.set(_("验证码已复制"))
    
    def delete_account(self):
        """删除账户"""
        item = self.tree.selection()[0]
        issuer = self.tree.item(item, "values")[0]
        
        if messagebox.askyesno(_("确认"), _("确定要删除账户 '{}' 吗?").format(issuer)):
            self.tree.delete(item)
            del self.accounts[issuer]
            self.save_accounts()
            self.status_var.set(_("已删除账户: {}").format(issuer))
    
    def show_secret(self):
        """显示密钥"""
        item = self.tree.selection()[0]
        issuer = self.tree.item(item, "values")[0]
        secret = self.accounts[issuer]["secret"]
        messagebox.showinfo(_("密钥"), _("账户: {}\n密钥: {}").format(issuer, secret))
    
    # === 数据持久化 ===
    def load_accounts(self):
        """加载账户"""
        data_file = "accounts.enc"
        if os.path.exists(data_file):
            try:
                with open(data_file, "r") as f:
                    encrypted_data = f.read()
                    decrypted_data = self.auth_manager.decrypt_data(encrypted_data)
                    self.accounts = json.loads(decrypted_data)
            except Exception as e:
                messagebox.showerror(_("错误"), _("加载账户数据时出错: {}").format(str(e)))
        
        self.update_account_list()
    
    def save_accounts(self):
        """保存账户"""
        try:
            data_file = "accounts.enc"
            json_data = json.dumps(self.accounts)
            encrypted_data = self.auth_manager.encrypt_data(json_data)
            
            with open(data_file, "w") as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror(_("错误"), _("保存账户数据时出错: {}").format(str(e)))
    
    # === 辅助方法 ===
    def update_account_list(self):
        """更新账户列表"""
        self.tree.delete(*self.tree.get_children())
        for issuer in sorted(self.accounts.keys()):
            secret = self.accounts[issuer]["secret"]
            totp = pyotp.TOTP(secret)
            code = totp.now()
            self.tree.insert("", tk.END, values=(issuer, code))
    
    def update_codes(self):
        """更新验证码"""
        for item in self.tree.get_children():
            issuer = self.tree.item(item, "values")[0]
            secret = self.accounts[issuer]["secret"]
            totp = pyotp.TOTP(secret)
            self.tree.item(item, values=(issuer, totp.now()))
        
        self.root.after(30000, self.update_codes)
    
    def center_window(self, window):
        """窗口居中"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
    
    def on_closing(self):
        """关闭应用"""
        self.stop_scan()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = TOTPApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
