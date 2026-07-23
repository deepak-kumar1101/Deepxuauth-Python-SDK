import os
import sys
import json
import platform
import subprocess
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, Tuple

class UserData:
    def __init__(self, username: str = "", subscription: str = "", expiry: str = ""):
        self.username = username
        self.subscription = subscription
        self.expiry = expiry

class DXA:
    def __init__(self, name: str = "", secret: str = "", version: str = "1.0", ownerid: str = "", app_name: str = "", api_url: str = "https://deepxauth.pages.dev", **kwargs):
        self.app_name = (name or app_name or kwargs.get("appName", "")).strip()
        self.secret = (secret or ownerid or kwargs.get("appSecret", "")).strip()
        self.version = (version or kwargs.get("appVersion", "1.0")).strip()
        self.api_url = (api_url or kwargs.get("apiUrl", "https://deepxauth.pages.dev")).rstrip('/')
        
        self.is_initialized: bool = False
        self.is_logged_in: bool = False
        self.user: Optional[UserData] = None
        self.response_message: str = ""
        self.variables: Dict[str, str] = {}
        self.is_application_active: bool = False
        self.is_version_correct: bool = False
        self.server_version: str = ""

    @staticmethod
    def get_hwid() -> str:
        """Retrieves hardware ID (Windows SID or MachineGUID)."""
        if platform.system() == "Windows":
            try:
                output = subprocess.check_output("whoami /user", shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if "S-1-" in line:
                        for token in line.split():
                            if token.startswith("S-1-"):
                                return token.strip()
            except Exception:
                pass

            try:
                import winreg
                registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(registry, r"SOFTWARE\Microsoft\Cryptography")
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                if val:
                    return str(val).strip()
            except Exception:
                pass

        return f"{os.environ.get('COMPUTERNAME', 'PC')}_{os.environ.get('USERNAME', 'User')}"

    def init(self) -> bool:
        """Initializes the DXA SDK (version check, pause check, load app variables)."""
        if not self.app_name or not self.secret:
            self.response_message = "Init Error: AppName and Secret are required."
            return False

        try:
            # 1. Check if application is paused
            if self._check_if_paused():
                self.response_message = "Application is currently paused by administrator."
                self.is_application_active = False
                return False
            self.is_application_active = True

            # 2. Check version
            valid, server_ver = self._check_version()
            self.is_version_correct = valid
            self.server_version = server_ver
            if not valid:
                self.response_message = f"Version mismatch! Client: {self.version}, Server: {server_ver}"
                return False

            # 3. Load Application Variables
            self._load_app_variables()

            self.is_initialized = True
            self.response_message = "DXA SDK Initialized successfully!"
            return True
        except Exception as ex:
            self.response_message = f"Initialization failed: {str(ex)}"
            return False

    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[UserData]]:
        """Logs in a user with username and password."""
        self.response_message = ""
        if not self.is_initialized:
            if not self.init():
                return False, self.response_message, None

        username = username.strip()
        password = password.strip()
        if not username or not password:
            self.response_message = "Username and password cannot be empty."
            return False, self.response_message, None

        hwid = self.get_hwid()
        payload = {
            "username": username,
            "password": password,
            "secret": self.secret,
            "appName": self.app_name,
            "appVersion": self.version,
            "hwid": hwid
        }

        res = self._send_request("login", payload)
        if res.get("success"):
            self.is_logged_in = True
            self.user = UserData(
                username=res.get("username", username),
                subscription=res.get("subscription", "default"),
                expiry=res.get("expiry", "lifetime")
            )
            self.response_message = f"Login successful! Welcome, {self.user.username}"
            return True, self.response_message, self.user
        else:
            raw_msg = res.get("message", "Login failed")
            self.response_message = self._format_error(raw_msg, "login")
            return False, self.response_message, None

    def register(self, username: str, password: str, license_key: str) -> Tuple[bool, str]:
        """Registers a new user account with a license key."""
        self.response_message = ""
        if not self.is_initialized:
            if not self.init():
                return False, self.response_message

        username = username.strip()
        password = password.strip()
        license_key = license_key.strip()
        if not username or not password or not license_key:
            self.response_message = "Username, password, and license key are required."
            return False, self.response_message

        hwid = self.get_hwid()
        payload = {
            "username": username,
            "password": password,
            "licenseKey": license_key,
            "secret": self.secret,
            "appName": self.app_name,
            "appVersion": self.version,
            "hwid": hwid
        }

        res = self._send_request("register", payload)
        if res.get("success"):
            self.response_message = "Registration successful! You can now log in."
            return True, self.response_message
        else:
            raw_msg = res.get("message", "Registration failed")
            self.response_message = self._format_error(raw_msg, "register")
            return False, self.response_message

    def var(self, var_name: str) -> str:
        """Gets variable value from cached variables dictionary."""
        return self.variables.get(var_name, "VARIABLE_NOT_FOUND")

    def _check_if_paused(self) -> bool:
        res = self._send_request("isapplicationpaused", {"secret": self.secret, "appName": self.app_name})
        return res.get("success", False) and res.get("message") == "APPLICATION_PAUSED"

    def _check_version(self) -> Tuple[bool, str]:
        res = self._send_request("versioncheck", {"secret": self.secret, "appName": self.app_name, "appVersion": self.version})
        if res.get("success") and res.get("message") == "VERSION_OK":
            return True, self.version
        server_ver = res.get("serverVersion", "1.0")
        if res.get("message") == "VERSION_MISMATCH":
            return False, server_ver
        return True, self.version

    def _load_app_variables(self):
        res = self._send_request("getvariables", {"secret": self.secret, "appName": self.app_name})
        if res.get("success") and isinstance(res.get("variables"), dict):
            self.variables = res["variables"]

    def _send_request(self, endpoint: str, payload: dict) -> dict:
        url = f"{self.api_url}/{endpoint}"
        data_bytes = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json", "User-Agent": "DXA-Python-SDK/1.0"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8')
                return json.loads(body)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode('utf-8')
                return json.loads(body)
            except Exception:
                return {"success": False, "message": f"HTTP Error {e.code}"}
        except urllib.error.URLError as e:
            return {"success": False, "message": f"Network Error: {e.reason}"}
        except Exception as e:
            return {"success": False, "message": f"Request Error: {str(e)}"}

    def _format_error(self, msg: str, operation: str) -> str:
        u = msg.upper()
        if operation == "login":
            if "INVALID_CREDENTIALS" in u or "INVALID USERNAME" in u or "INVALID CREDENTIALS" in u:
                return "Invalid username or password."
            if "HWID_MISMATCH" in u or "HWID MISMATCH" in u:
                return "HWID mismatch! This account is bound to another PC."
            if "BANNED" in u or "SUSPENDED" in u:
                return "Your account has been banned or suspended."
            if "EXPIRED" in u:
                return "Your subscription has expired."
            if "APPLICATION_PAUSED" in u:
                return "Application is paused by administrator."
        elif operation == "register":
            if "INVALID OR USED LICENSE" in u or "INVALID_LICENSE" in u or "LICENSE_USED" in u:
                return "Invalid or already used license key."
            if "USERNAME TAKEN" in u or "USERNAME_TAKEN" in u:
                return "Username is already taken."
            if "EXPIRED" in u:
                return "License key has expired."
        return f"{operation.capitalize()} failed: {msg}"

# Compatibility aliases
keyauthapp = DXA
api = DXA
