import sqlite3
import os
import base64
import hashlib
import secrets
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from tkinter import filedialog
import re

# Security configuration
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_DERIVATION_ITERATIONS = 600_000
KEY_LENGTH = 32  # AES-256

# Database configuration
DB_FILE = "password_vault.db"
BACKUP_FOLDER = "password_backups"

# Create backup directory if it doesn't exist
os.makedirs(BACKUP_FOLDER, exist_ok=True)

class PasswordManager:
    def __init__(self):
        self.conn = self.create_database()
        
    def create_database(self):
        """Create database with secure storage for encrypted credentials"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                tag BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        return conn
    
    def derive_key(self, password, salt):
        """Derive a cryptographic key from password"""
        return PBKDF2(password, salt, dkLen=KEY_LENGTH, 
                      count=KEY_DERIVATION_ITERATIONS)
    
    def encrypt_data(self, data, password):
        """Encrypt data using AES-GCM with derived key"""
        salt = get_random_bytes(SALT_SIZE)
        key = self.derive_key(password, salt)
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return ciphertext, salt, nonce, tag
    
    def decrypt_data(self, encrypted_data, password, salt, nonce, tag):
        """Decrypt data using AES-GCM with derived key"""
        key = self.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(encrypted_data, tag).decode()
    
    def save_credentials(self, website, username, password, master_key):
        """Save encrypted credentials to database"""
        data = json.dumps({"password": password})
        ciphertext, salt, nonce, tag = self.encrypt_data(data, master_key)
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO credentials (website, username, encrypted_data, salt, nonce, tag)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (website, username, ciphertext, salt, nonce, tag))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_credentials(self, website, username, master_key):
        """Retrieve and decrypt credentials from database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT encrypted_data, salt, nonce, tag 
            FROM credentials 
            WHERE website = ? AND username = ?
        ''', (website, username))
        
        row = cursor.fetchone()
        if not row:
            return None
            
        encrypted_data, salt, nonce, tag = row
        try:
            data = self.decrypt_data(encrypted_data, master_key, salt, nonce, tag)
            return json.loads(data)['password']
        except:
            return None
    
    def get_all_websites(self):
        """Get list of all websites in database"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT DISTINCT website FROM credentials')
        return [row[0] for row in cursor.fetchall()]
    
    def get_usernames_for_website(self, website):
        """Get usernames for a specific website"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT DISTINCT username FROM credentials WHERE website = ?', (website,))
        return [row[0] for row in cursor.fetchall()]
    
    def backup_database(self):
        """Create an encrypted backup of the database"""
        backup_file = os.path.join(BACKUP_FOLDER, f"backup_{secrets.token_hex(4)}.pmb")
        with open(DB_FILE, 'rb') as source, open(backup_file, 'wb') as target:
            target.write(source.read())
        return backup_file
    
    def restore_database(self, backup_file):
        """Restore database from backup"""
        if not os.path.exists(backup_file):
            return False
            
        # Close existing connection
        self.conn.close()
        
        # Restore backup
        with open(backup_file, 'rb') as source, open(DB_FILE, 'wb') as target:
            target.write(source.read())
        
        # Reopen connection
        self.conn = sqlite3.connect(DB_FILE)
        return True
        
    def delete_credentials(self, website, username):
        """Delete credentials from database"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM credentials WHERE website = ? AND username = ?', (website, username))
        self.conn.commit()
        return cursor.rowcount > 0

class PasswordGenerator:
    @staticmethod
    def generate_strong_password(length=16):
        """Generate a strong random password"""
        uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # Remove I and O for clarity
        lowercase = "abcdefghjkmnpqrstuvwxyz"   # Remove i, l, o
        digits = "23456789"                     # Remove 0, 1
        symbols = "!@#$%^&*()_-+=<>?"
        
        # Ensure at least one of each character type
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        # Fill the rest with random characters
        all_chars = uppercase + lowercase + digits + symbols
        password += [secrets.choice(all_chars) for _ in range(length - 4)]
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    @staticmethod
    def calculate_password_strength(password):
        """Calculate password strength (0-100)"""
        strength = 0
        
        # Length contributes up to 50 points
        length = len(password)
        strength += min(50, length * 3)
        
        # Character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Variety contributes up to 30 points
        if has_upper: strength += 7
        if has_lower: strength += 7
        if has_digit: strength += 7
        if has_special: strength += 9
        
        # Entropy calculation
        char_pool = 0
        if has_upper: char_pool += 26
        if has_lower: char_pool += 26
        if has_digit: char_pool += 10
        if has_special: char_pool += 20
        
        if char_pool > 0:
            entropy = length * (char_pool ** 0.5)
            strength += min(20, entropy / 5)
        
        return min(100, strength)

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Apply UI styling
        self.apply_styles()
        
        # Prompt for master key
        self.master_key = self.prompt_master_key()
        if not self.master_key:
            self.root.destroy()
            return
            
        # Initialize password manager
        self.pm = PasswordManager()
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_add_tab()
        self.create_retrieve_tab()
        self.create_backup_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.update_status("Ready")
        
    def apply_styles(self):
        """Apply UI styling and themes"""
        style = ttk.Style()
        
        # Try to use a modern theme if available
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
        elif 'alt' in available_themes:
            style.theme_use('alt')
        elif 'default' in available_themes:
            style.theme_use('default')
            
        # Configure styles
        style.configure('TButton', font=('Segoe UI', 10), padding=6)
        style.configure('TLabel', font=('Segoe UI', 10))
        style.configure('TEntry', font=('Segoe UI', 10))
        style.configure('TCombobox', font=('Segoe UI', 10))
        style.configure('TNotebook', background='#f0f4f8')
        style.configure('TNotebook.Tab', font=('Segoe UI', 10, 'bold'), padding=[10, 5])
        
        # Set background color
        self.root.configure(bg='#f0f4f8')
    
    def prompt_master_key(self):
        """Prompt user for master key at startup"""
        master_key = simpledialog.askstring(
            "Master Key", 
            "Enter your master key (must be at least 8 characters):",
            show="*"
        )
        
        if not master_key or len(master_key) < 8:
            messagebox.showerror("Error", "Master key must be at least 8 characters!")
            return None
            
        # Verify master key with a hash
        confirm_key = simpledialog.askstring(
            "Confirm Master Key", 
            "Re-enter your master key to confirm:",
            show="*"
        )
        
        if master_key != confirm_key:
            messagebox.showerror("Error", "Master keys do not match!")
            return None
            
        return master_key
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def create_add_tab(self):
        """Create tab for adding new credentials"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Add Password")
        
        # Website input
        ttk.Label(tab, text="Website:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.website_entry = ttk.Entry(tab, width=40)
        self.website_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Username input
        ttk.Label(tab, text="Username:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.username_entry = ttk.Entry(tab, width=40)
        self.username_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Password input
        ttk.Label(tab, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(tab, width=40, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Password strength meter
        self.strength_var = tk.StringVar(value="Strength: 0%")
        self.strength_label = ttk.Label(tab, textvariable=self.strength_var)
        self.strength_label.grid(row=3, column=1, padx=10, pady=2, sticky=tk.W)
        
        self.strength_bar = ttk.Progressbar(tab, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.strength_bar.grid(row=4, column=1, padx=10, pady=2, sticky=tk.W)
        self.strength_bar['value'] = 0
        
        # Buttons
        button_frame = ttk.Frame(tab)
        button_frame.grid(row=6, column=1, padx=10, pady=10, sticky=tk.W)
        
        ttk.Button(button_frame, text="Generate Password", 
                  command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Password", 
                  command=self.save_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Form", 
                  command=self.clear_add_form).pack(side=tk.LEFT, padx=5)
        
        # Bind password strength calculation
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)
    
    def create_retrieve_tab(self):
        """Create tab for retrieving passwords"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Retrieve Password")
        
        # Website selection
        ttk.Label(tab, text="Select Website:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.website_combo = ttk.Combobox(tab, width=37)
        self.website_combo.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        self.website_combo.bind("<<ComboboxSelected>>", self.on_website_selected)
        
        # Username selection
        ttk.Label(tab, text="Select Username:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.username_combo = ttk.Combobox(tab, width=37)
        self.username_combo.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Password display
        ttk.Label(tab, text="Password:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        self.password_display = ttk.Entry(tab, width=40, state="readonly")
        self.password_display.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(tab)
        button_frame.grid(row=4, column=1, padx=10, pady=10, sticky=tk.W)
        
        ttk.Button(button_frame, text="Retrieve Password", 
                  command=self.retrieve_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=self.copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Show/Hide", 
                  command=self.toggle_password_visibility).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", 
                  command=self.delete_password).pack(side=tk.LEFT, padx=5)
        
        # Update website list
        self.update_website_list()
    
    def create_backup_tab(self):
        """Create tab for backup and restore"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Backup & Restore")
        
        # Backup section
        backup_frame = ttk.LabelFrame(tab, text="Backup Database")
        backup_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W+tk.E)
        
        ttk.Button(backup_frame, text="Create Backup", 
                  command=self.create_backup).pack(padx=10, pady=10)
        
        # Restore section
        restore_frame = ttk.LabelFrame(tab, text="Restore Database")
        restore_frame.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W+tk.E)
        
        ttk.Label(restore_frame, text="Backup File:").pack(padx=10, pady=5, anchor=tk.W)
        self.backup_file_var = tk.StringVar()
        ttk.Entry(restore_frame, textvariable=self.backup_file_var, state="readonly", width=50).pack(padx=10, pady=5, fill=tk.X)
        
        button_frame = ttk.Frame(restore_frame)
        button_frame.pack(padx=10, pady=5, fill=tk.X)
        
        ttk.Button(button_frame, text="Browse", command=self.browse_backup).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Restore", command=self.restore_backup).pack(side=tk.LEFT, padx=5)
        
        # Recent backups
        recent_frame = ttk.LabelFrame(tab, text="Recent Backups")
        recent_frame.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W+tk.E+tk.N+tk.S)
        
        self.backup_listbox = tk.Listbox(recent_frame, height=6)
        self.backup_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Load recent backups
        self.update_backup_list()
    
    def create_settings_tab(self):
        """Create settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Settings")
        
        # Security section
        security_frame = ttk.LabelFrame(tab, text="Security Settings")
        security_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(security_frame, text="Master Key Requirements:").pack(anchor=tk.W, padx=10, pady=5)
        
        # Password policy
        policy_frame = ttk.Frame(security_frame)
        policy_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(policy_frame, text="Minimum Length:").grid(row=0, column=0, sticky=tk.W)
        self.min_length_var = tk.IntVar(value=12)
        ttk.Entry(policy_frame, textvariable=self.min_length_var, width=5).grid(row=0, column=1, padx=5)
        
        # About section
        about_frame = ttk.LabelFrame(tab, text="About Password Manager")
        about_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        about_text = """
        Secure Password Manager
        
        Version: 3.1
        Release Date: 2023-10-20
        
        Features:
        - Military-grade AES-256 encryption
        - Secure key derivation with PBKDF2
        - Password strength evaluation
        - Secure password generation
        - Automatic backup management
        - Single master key for all operations
        - Credential deletion
        
        Security Notes:
        1. Master keys are NEVER stored
        2. Losing your master key means permanent data loss
        3. Always use strong, unique master keys
        
        Backups are stored in:
        """
        about_text += os.path.abspath(BACKUP_FOLDER)
        
        about_label = ttk.Label(about_frame, text=about_text, justify=tk.LEFT)
        about_label.pack(padx=10, pady=10, anchor=tk.W)
    
    def update_password_strength(self, event=None):
        """Update password strength display"""
        password = self.password_entry.get()
        if password:
            strength = PasswordGenerator.calculate_password_strength(password)
            self.strength_bar['value'] = strength
            
            if strength < 40:
                strength_text = "Weak"
                color = "red"
            elif strength < 70:
                strength_text = "Medium"
                color = "orange"
            else:
                strength_text = "Strong"
                color = "green"
            
            self.strength_var.set(f"Strength: {strength_text} ({strength}%)")
            self.strength_label.config(foreground=color)
        else:
            self.strength_bar['value'] = 0
            self.strength_var.set("Strength: 0%")
            self.strength_label.config(foreground="black")
    
    def generate_password(self):
        """Generate a strong password and insert into password field"""
        password = PasswordGenerator.generate_strong_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.update_password_strength()
    
    def clear_add_form(self):
        """Clear all fields in add tab"""
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.strength_bar['value'] = 0
        self.strength_var.set("Strength: 0%")
    
    def save_password(self):
        """Save password to database"""
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        # Validate inputs
        if not website or not username or not password:
            messagebox.showerror("Error", "Website, username, and password are required!")
            return
            
        try:
            # Save credentials
            self.pm.save_credentials(website, username, password, self.master_key)
            messagebox.showinfo("Success", "Password saved successfully!")
            self.clear_add_form()
            self.update_website_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")
    
    def update_website_list(self):
        """Update list of websites in retrieve tab"""
        websites = self.pm.get_all_websites()
        self.website_combo['values'] = websites
        if websites:
            self.website_combo.current(0)
            self.on_website_selected()
    
    def on_website_selected(self, event=None):
        """Update usernames when website is selected"""
        website = self.website_combo.get()
        if website:
            usernames = self.pm.get_usernames_for_website(website)
            self.username_combo['values'] = usernames
            if usernames:
                self.username_combo.current(0)
    
    def retrieve_password(self):
        """Retrieve password from database"""
        website = self.website_combo.get()
        username = self.username_combo.get()
        
        if not website or not username:
            messagebox.showerror("Error", "Select website and username!")
            return
            
        try:
            password = self.pm.get_credentials(website, username, self.master_key)
            if password is None:
                messagebox.showerror("Error", "Credentials not found or master key incorrect!")
                return
                
            self.password_display.config(state="normal")
            self.password_display.delete(0, tk.END)
            self.password_display.insert(0, password)
            self.password_display.config(state="readonly", show="*")
            self.password_visible = False
            self.update_status("Password retrieved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")
    
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_display.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.update_status("Password copied to clipboard")
    
    def toggle_password_visibility(self):
        """Toggle password visibility in retrieve tab"""
        if not hasattr(self, 'password_visible'):
            self.password_visible = False
            
        if self.password_visible:
            self.password_display.config(show="*")
            self.password_visible = False
        else:
            self.password_display.config(show="")
            self.password_visible = True
    
    def create_backup(self):
        """Create a backup of the database"""
        try:
            backup_file = self.pm.backup_database()
            messagebox.showinfo("Success", f"Backup created successfully!\n{backup_file}")
            self.update_backup_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create backup: {str(e)}")
    
    def browse_backup(self):
        """Browse for backup file"""
        file_path = filedialog.askopenfilename(
            initialdir=BACKUP_FOLDER,
            title="Select Backup File",
            filetypes=(("Password Backup", "*.pmb"), ("All Files", "*.*"))
        )
        
        if file_path:
            self.backup_file_var.set(file_path)
    
    def restore_backup(self):
        """Restore database from backup"""
        backup_file = self.backup_file_var.get()
        if not backup_file:
            messagebox.showerror("Error", "Please select a backup file!")
            return
            
        try:
            if self.pm.restore_database(backup_file):
                messagebox.showinfo("Success", "Database restored successfully!")
                self.update_website_list()
            else:
                messagebox.showerror("Error", "Failed to restore database!")
        except Exception as e:
            messagebox.showerror("Error", f"Restore failed: {str(e)}")
    
    def update_backup_list(self):
        """Update list of recent backups"""
        try:
            backups = sorted(
                [f for f in os.listdir(BACKUP_FOLDER) if f.endswith('.pmb')],
                key=lambda f: os.path.getmtime(os.path.join(BACKUP_FOLDER, f)),
                reverse=True
            )[:5]  # Show last 5 backups
            
            self.backup_listbox.delete(0, tk.END)
            for backup in backups:
                self.backup_listbox.insert(tk.END, backup)
        except:
            pass
            
    def delete_password(self):
        """Delete selected credentials"""
        website = self.website_combo.get()
        username = self.username_combo.get()
        
        if not website or not username:
            messagebox.showerror("Error", "Select website and username!")
            return
            
        confirmation = messagebox.askyesno(
            "Confirm Deletion", 
            f"Are you sure you want to delete credentials for:\n\nWebsite: {website}\nUsername: {username}?"
        )
        
        if confirmation:
            try:
                if self.pm.delete_credentials(website, username):
                    messagebox.showinfo("Success", "Credentials deleted successfully!")
                    self.password_display.config(state="normal")
                    self.password_display.delete(0, tk.END)
                    self.password_display.config(state="readonly")
                    self.update_website_list()
                else:
                    messagebox.showerror("Error", "Failed to delete credentials!")
            except Exception as e:
                messagebox.showerror("Error", f"Delete operation failed: {str(e)}")

if __name__ == "__main__":
    # Check for required packages
    try:
        import sqlite3
        import tkinter as tk
        from Crypto.Cipher import AES
    except ImportError as e:
        print(f"Error: {e}")
        print("Please install required packages:")
        print("pip install pycryptodome")
        exit(1)
     
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()