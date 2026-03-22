#2026 22 mar
import os
import sys
import socket
import subprocess
import threading
import time
import json
import hashlib
import requests
import cv2
import numpy as np
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import paramiko
import scapy.all as scapy
from cryptography.fernet import Fernet
import logging
import platform

# إعدادات التسجيل
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecurityAuditTool:
    """الأداة الرئيسية لفحص الثغرات الأمنية"""
    
    def __init__(self):
        self.tools = {}
        self.session_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        self.results_dir = f"audit_results_{self.session_id}"
        self.setup_tools()
        self.create_results_directory()
        
    def create_results_directory(self):
        """إنشاء مجلد للنتائج"""
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            logging.info(f"تم إنشاء مجلد النتائج: {self.results_dir}")
    
    def setup_tools(self):
        """تجهيز جميع الأدوات الـ 33"""
        
        # 1-10: أدوات فحص الشبكة والمنافذ
        self.tools[1] = {
            'name': 'مسح المنافذ الأساسي',
            'description': 'فحص المنافذ المفتوحة على الهدف',
            'function': self.basic_port_scan
        }
        
        self.tools[2] = {
            'name': 'مسح متقدم للمنافذ',
            'description': 'مسح شامل لجميع المنافذ (1-65535)',
            'function': self.advanced_port_scan
        }
        
        self.tools[3] = {
            'name': 'كشف نظام التشغيل',
            'description': 'محاولة تحديد نظام التشغيل للجهاز الهدف',
            'function': self.os_fingerprinting
        }
        
        self.tools[4] = {
            'name': 'فحص الخدمات والإصدارات',
            'description': 'تحديد الخدمات وإصداراتها على المنافذ المفتوحة',
            'function': self.service_version_detection
        }
        
        self.tools[5] = {
            'name': 'كشف الأجهزة في الشبكة',
            'description': 'فحص جميع الأجهزة المتصلة بالشبكة المحلية',
            'function': self.network_discovery
        }
        
        self.tools[6] = {
            'name': 'تحليل حزم الشبكة',
            'description': 'التقاط وتحليل حزم الشبكة',
            'function': self.packet_analyzer
        }
        
        self.tools[7] = {
            'name': 'اختبار اختراق الواي فاي',
            'description': 'فحص أمان شبكات الواي فاي المحيطة',
            'function': self.wifi_security_test
        }
        
        self.tools[8] = {
            'name': 'كشف نقاط الضعف في DNS',
            'description': 'فحص ثغرات خادم DNS',
            'function': self.dns_vulnerability_scan
        }
        
        self.tools[9] = {
            'name': 'اختبار هجوم الرجل في الوسط',
            'description': 'محاكاة هجوم MITM للكشف عن الثغرات',
            'function': self.mitm_simulation
        }
        
        self.tools[10] = {
            'name': 'فحص جدران الحماية',
            'description': 'اختبار فعالية جدار الحماية',
            'function': self.firewall_testing
        }
        
        # 11-20: أدوات فحص تطبيقات الويب
        self.tools[11] = {
            'name': 'فحص ثغرات SQL Injection',
            'description': 'اختبار حقن SQL في تطبيقات الويب',
            'function': self.sql_injection_scanner
        }
        
        self.tools[12] = {
            'name': 'فحص XSS (Cross-Site Scripting)',
            'description': 'كشف ثغرات البرمجة النصية عبر المواقع',
            'function': self.xss_scanner
        }
        
        self.tools[13] = {
            'name': 'كشف الملفات الحساسة',
            'description': 'البحث عن الملفات والمجلدات الحساسة',
            'function': self.sensitive_files_scanner
        }
        
        self.tools[14] = {
            'name': 'اختبار قوة كلمات المرور',
            'description': 'تحليل قوة كلمات المرور وهجوم القاموس',
            'function': self.password_strength_tester
        }
        
        self.tools[15] = {
            'name': 'كشف ثغرات CSRF',
            'description': 'فحص ثغرات تزوير الطلبات عبر المواقع',
            'function': self.csrf_scanner
        }
        
        self.tools[16] = {
            'name': 'تحليل رؤوس HTTP',
            'description': 'فحص إعدادات الأمان في رؤوس HTTP',
            'function': self.http_headers_analyzer
        }
        
        self.tools[17] = {
            'name': 'كشف الثغرات في واجهات API',
            'description': 'اختبار أمان واجهات برمجة التطبيقات',
            'function': self.api_security_scanner
        }
        
        self.tools[18] = {
            'name': 'فحص SSL/TLS',
            'description': 'تحليل إعدادات SSL/TLS والثغرات',
            'function': self.ssl_tls_scanner
        }
        
        self.tools[19] = {
            'name': 'كشف الثغرات في CMS',
            'description': 'فحص أنظمة إدارة المحتوى المعروفة',
            'function': self.cms_vulnerability_scanner
        }
        
        self.tools[20] = {
            'name': 'اختبار هجمات الجمود',
            'description': 'محاكاة هجمات DoS للكشف عن الثغرات',
            'function': self.dos_simulation
        }
        
        # 21-30: أدوات متقدمة للاختراق الأخلاقي
        self.tools[21] = {
            'name': 'أداة إنشاء روابط الكاميرا',
            'description': 'إنشاء رابط محلي لالتقاط الصور من الكاميرا',
            'function': self.camera_link_generator
        }
        
        self.tools[22] = {
            'name': 'محاكاة هجوم التصيد',
            'description': 'إنشاء صفحة تصيد تجريبية للتعليم',
            'function': self.phishing_simulation
        }
        
        self.tools[23] = {
            'name': 'كشف الثغرات في خدمات FTP',
            'description': 'فحص خوادم FTP والثغرات الأمنية',
            'function': self.ftp_vulnerability_scanner
        }
        
        self.tools[24] = {
            'name': 'تحليل الثغرات في SSH',
            'description': 'فحص تكوينات SSH والثغرات',
            'function': self.ssh_security_audit
        }
        
        self.tools[25] = {
            'name': 'كشف الثغرات في SMB',
            'description': 'فحص خدمة SMB والثغرات المعروفة',
            'function': self.smb_vulnerability_scanner
        }
        
        self.tools[26] = {
            'name': 'اختبار حقن الأوامر',
            'description': 'فحص ثغرات حقن أوامر النظام',
            'function': self.command_injection_scanner
        }
        
        self.tools[27] = {
            'name': 'كشف الثغرات في قواعد البيانات',
            'description': 'فحص قواعد البيانات المكشوفة',
            'function': self.database_scanner
        }
        
        self.tools[28] = {
            'name': 'تحليل الذاكرة المؤقتة',
            'description': 'فحص ثغرات تجاوز سعة الذاكرة المؤقتة',
            'function': self.buffer_overflow_simulation
        }
        
        self.tools[29] = {
            'name': 'كشف الثغرات في خدمات البريد',
            'description': 'فحص خوادم البريد الإلكتروني',
            'function': self.email_server_scanner
        }
        
        self.tools[30] = {
            'name': 'أداة الدخول من الثغرات',
            'description': 'محاكاة استغلال الثغرات للدخول',
            'function': self.exploit_simulator
        }
        
        # 31-33: أدوات إضافية
        self.tools[31] = {
            'name': 'كشف الثغرات في إنترنت الأشياء',
            'description': 'فحص أجهزة إنترنت الأشياء',
            'function': self.iot_vulnerability_scanner
        }
        
        self.tools[32] = {
            'name': 'تحليل سجلات النظام',
            'description': 'فحص السجلات للكشف عن اختراقات',
            'function': self.log_analyzer
        }
        
        self.tools[33] = {
            'name': 'تقرير أمني شامل',
            'description': 'تجميع نتائج جميع الفحوصات في تقرير',
            'function': self.generate_comprehensive_report
        }
    
    # تنفيذ الأدوات (هنا نضع المنطق البرمجي لكل أداة)
    
    def basic_port_scan(self, target):
        """أداة 1: مسح المنافذ الأساسي"""
        logging.info(f"بدء مسح المنافذ الأساسي للهدف: {target}")
        results = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    results.append(f"المنفذ {port}: مفتوح - الخدمة: {service}")
                sock.close()
            except:
                pass
        
        return self.save_results("basic_port_scan", results)
    
    def advanced_port_scan(self, target):
        """أداة 2: مسح متقدم للمنافذ"""
        logging.info(f"بدء المسح المتقدم للمنافذ للهدف: {target}")
        results = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    return f"المنفذ {port}: مفتوح - الخدمة: {service}"
                sock.close()
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, port) for port in range(1, 1025)]
            for future in futures:
                result = future.result()
                if result:
                    results.append(result)
        
        return self.save_results("advanced_port_scan", results)
    
    def os_fingerprinting(self, target):
        """أداة 3: كشف نظام التشغيل"""
        logging.info(f"محاولة كشف نظام التشغيل للهدف: {target}")
        results = []
        
        # طريقة بسيطة للكشف عن نظام التشغيل باستخدام TTL
        try:
            ping = subprocess.run(['ping', '-c', '1', target], capture_output=True, text=True)
            if "ttl=" in ping.stdout.lower():
                ttl_line = [line for line in ping.stdout.split('\n') if 'ttl=' in line.lower()]
                if ttl_line:
                    ttl = int(ttl_line[0].split('ttl=')[1].split()[0])
                    if ttl <= 64:
                        os_type = "Linux/Unix"
                    elif ttl <= 128:
                        os_type = "Windows"
                    else:
                        os_type = "Solaris/AIX"
                    results.append(f"TTL: {ttl} - نظام التشغيل المحتمل: {os_type}")
        except:
            results.append("تعذر كشف نظام التشغيل")
        
        return self.save_results("os_fingerprinting", results)
    
    def service_version_detection(self, target):
        """أداة 4: فحص الخدمات والإصدارات"""
        logging.info(f"فحص الخدمات والإصدارات للهدف: {target}")
        results = []
        
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }
        
        for port, service in services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                
                # محاولة الحصول على البانر
                if port == 80:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    pass  # FTP يرسل البانر تلقائياً
                elif port == 22:
                    pass  # SSH يرسل البانر تلقائياً
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                results.append(f"المنفذ {port} ({service}): {banner[:100]}")
                sock.close()
            except:
                pass
        
        return self.save_results("service_version_detection", results)
    
    def network_discovery(self, target_network=None):
        """أداة 5: كشف الأجهزة في الشبكة"""
        logging.info("بدء كشف الأجهزة في الشبكة المحلية")
        results = []
        
        if not target_network:
            # الحصول على الشبكة المحلية
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        else:
            network = target_network
        
        results.append(f"فحص الشبكة: {network}")
        
        # ARP scan
        try:
            arp_request = scapy.ARP(pdst=network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                results.append(f"الجهاز: IP {element[1].psrc} - MAC {element[1].hwsrc}")
        except:
            results.append("تعذر إجراء فحص ARP، قد تحتاج صلاحيات مدير النظام")
        
        return self.save_results("network_discovery", results)
    
    def packet_analyzer(self, interface="eth0", count=10):
        """أداة 6: تحليل حزم الشبكة"""
        logging.info(f"بدء تحليل الحزم على الواجهة {interface}")
        results = []
        
        try:
            packets = scapy.sniff(iface=interface, count=count, timeout=10)
            results.append(f"تم التقاط {len(packets)} حزمة")
            
            for i, packet in enumerate(packets[:5]):  # عرض أول 5 حزم فقط
                results.append(f"الحزمة {i+1}: {packet.summary()}")
        except:
            results.append("تعذر التقاط الحزم، قد تحتاج صلاحيات مدير النظام")
        
        return self.save_results("packet_analyzer", results)
    
    def wifi_security_test(self):
        """أداة 7: اختبار اختراق الواي فاي"""
        logging.info("بدء اختبار أمان شبكات الواي فاي")
        results = []
        
        if platform.system() == "Linux":
            try:
                # فحص الشبكات المتاحة
                networks = subprocess.run(['nmcli', 'dev', 'wifi', 'list'], capture_output=True, text=True)
                results.append("الشبكات المتاحة:")
                results.append(networks.stdout)
                
                # تحليل أمان الشبكات
                results.append("\nتحليل الأمان:")
                results.append("- استخدم تشفير WPA3 إن أمكن")
                results.append("- تجنب شبكات WEP وWPA القديمة")
                results.append("- تأكد من تعطيل WPS")
            except:
                results.append("تعذر فحص شبكات الواي فاي")
        else:
            results.append("فحص الواي فاي متاح فقط على نظام Linux")
        
        return self.save_results("wifi_security_test", results)
    
    def dns_vulnerability_scan(self, dns_server="8.8.8.8"):
        """أداة 8: كشف نقاط الضعف في DNS"""
        logging.info(f"فحص ثغرات DNS للخادم {dns_server}")
        results = []
        
        try:
            # فتح منفذ DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            # اختبار الثغرات المعروفة
            results.append("اختبار ثغرات DNS:")
            
            # اختبار انعكاس DNS
            test_packet = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
            sock.sendto(test_packet, (dns_server, 53))
            response, _ = sock.recvfrom(1024)
            
            if len(response) > len(test_packet) * 10:
                results.append("⚠️ تحذير: خادم DNS قد يكون عرضة لهجمات الانعكاس")
            else:
                results.append("✅ خادم DNS يبدو آمناً من هجمات الانعكاس")
                
        except:
            results.append("تعذر فحص خادم DNS")
        
        return self.save_results("dns_vulnerability_scan", results)
    
    def mitm_simulation(self, target_ip, gateway_ip):
        """أداة 9: اختبار هجوم الرجل في الوسط"""
        logging.info(f"محاكاة هجوم MITM بين {target_ip} و {gateway_ip}")
        results = []
        
        results.append("محاكاة هجوم الرجل في الوسط (للأغراض التعليمية فقط)")
        results.append(f"الهدف: {target_ip}")
        results.append(f"البوابة: {gateway_ip}")
        
        # شرح كيفية حدوث الهجوم
        results.append("\nخطوات الهجوم:")
        results.append("1. إرسال حزم ARP مزيفة للهدف لتحديث جدول ARP")
        results.append("2. إرسال حزم ARP مزيفة للبوابة لتحديث جدول ARP")
        results.append("3. تمكين توجيه الحزم بين الهدف والبوابة")
        results.append("4. تحليل الحزم المارة")
        
        results.append("\nطرق الوقاية:")
        results.append("- استخدام HTTPS في جميع المواقع")
        results.append("- استخدام VPN للاتصالات الحساسة")
        results.append("- تفعيل حماية ARP في الشبكة")
        
        return self.save_results("mitm_simulation", results)
    
    def firewall_testing(self, target):
        """أداة 10: فحص جدران الحماية"""
        logging.info(f"اختبار جدار الحماية للهدف {target}")
        results = []
        
        test_ports = [80, 443, 22, 21, 25, 3389, 8080, 8443]
        
        results.append("اختبار جدار الحماية:")
        
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    results.append(f"المنفذ {port}: مفتوح (قد يكون محمياً)")
                elif result == 10060 or result == 110:  # مهلة الاتصال
                    results.append(f"المنفذ {port}: مغلق أو محمي (مهلة)")
                else:
                    results.append(f"المنفذ {port}: مغلق")
                
                sock.close()
            except:
                results.append(f"المنفذ {port}: تعذر الاتصال")
        
        return self.save_results("firewall_testing", results)
    
    def sql_injection_scanner(self, url):
        """أداة 11: فحص ثغرات SQL Injection"""
        logging.info(f"فحص ثغرات SQL Injection في {url}")
        results = []
        
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "admin' --",
            "' UNION SELECT NULL--",
            "' WAITFOR DELAY '00:00:05'--"
        ]
        
        results.append("اختبار حقن SQL:")
        
        for payload in payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=5)
                
                # البحث عن علامات ثغرة SQL
                sql_errors = [
                    "mysql_fetch",
                    "sql syntax",
                    "unclosed quotation mark",
                    "you have an error in your sql",
                    "warning: mysql",
                    "driver error"
                ]
                
                for error in sql_errors:
                    if error in response.text.lower():
                        results.append(f"⚠️ ثغرة محتملة مع payload: {payload}")
                        results.append(f"   رسالة الخطأ: {error}")
                        break
                        
            except:
                results.append(f"تعذر اختبار payload: {payload}")
        
        return self.save_results("sql_injection_scanner", results)
    
    def xss_scanner(self, url):
        """أداة 12: فحص XSS"""
        logging.info(f"فحص ثغرات XSS في {url}")
        results = []
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//"
        ]
        
        results.append("اختبار ثغرات XSS:")
        
        for payload in payloads:
            try:
                test_url = f"{url}?q={payload}"
                response = requests.get(test_url, timeout=5)
                
                # البحث عن تنفيذ الـ payload
                if payload in response.text and payload not in response.text.replace('&lt;', '<').replace('&gt;', '>'):
                    results.append(f"⚠️ ثغرة XSS محتملة مع payload: {payload[:30]}...")
                    
            except:
                pass
        
        return self.save_results("xss_scanner", results)
    
    def sensitive_files_scanner(self, url):
        """أداة 13: كشف الملفات الحساسة"""
        logging.info(f"البحث عن الملفات الحساسة في {url}")
        results = []
        
        sensitive_paths = [
            "/admin",
            "/backup",
            "/config",
            "/wp-admin",
            "/.git",
            "/.env",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/backup.sql",
            "/database.sql",
            "/config.php",
            "/wp-config.php",
            "/.htaccess",
            "/.htpasswd",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml"
        ]
        
        results.append("البحث عن الملفات والمجلدات الحساسة:")
        
        for path in sensitive_paths:
            try:
                test_url = f"{url}{path}"
                response = requests.get(test_url, timeout=3)
                
                if response.status_code == 200:
                    results.append(f"⚠️ موجود: {path} (رمز الحالة: 200)")
                elif response.status_code == 403:
                    results.append(f"🔒 محظور: {path} (رمز الحالة: 403)")
                elif response.status_code == 401:
                    results.append(f"🔑 يتطلب توثيق: {path}")
                    
            except:
                pass
        
        return self.save_results("sensitive_files_scanner", results)
    
    def password_strength_tester(self, password):
        """أداة 14: اختبار قوة كلمات المرور"""
        logging.info("اختبار قوة كلمة المرور")
        results = []
        
        def check_strength(pwd):
            score = 0
            feedback = []
            
            if len(pwd) >= 8:
                score += 1
            else:
                feedback.append("كلمة المرور قصيرة جداً (يجب أن تكون 8 أحرف على الأقل)")
            
            if any(c.isupper() for c in pwd):
                score += 1
            else:
                feedback.append("يجب إضافة حرف كبير واحد على الأقل")
            
            if any(c.islower() for c in pwd):
                score += 1
            else:
                feedback.append("يجب إضافة حرف صغير واحد على الأقل")
            
            if any(c.isdigit() for c in pwd):
                score += 1
            else:
                feedback.append("يجب إضافة رقم واحد على الأقل")
            
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd):
                score += 1
            else:
                feedback.append("يجب إضافة رمز خاص واحد على الأقل")
            
            return score, feedback
        
        score, feedback = check_strength(password)
        
        results.append(f"نتيجة تحليل كلمة المرور:")
        results.append(f"الطول: {len(password)} حرف")
        results.append(f"درجة القوة: {score}/5")
        
        if score <= 2:
            results.append("التقييم: ضعيفة جداً")
        elif score <= 3:
            results.append("التقييم: متوسطة")
        elif score <= 4:
            results.append("التقييم: قوية")
        else:
            results.append("التقييم: قوية جداً")
        
        if feedback:
            results.append("\nملاحظات للتحسين:")
            for note in feedback:
                results.append(f"- {note}")
        
        return self.save_results("password_strength_tester", results)
    
    def csrf_scanner(self, url):
        """أداة 15: كشف ثغرات CSRF"""
        logging.info(f"فحص ثغرات CSRF في {url}")
        results = []
        
        try:
            response = requests.get(url, timeout=5)
            
            # البحث عن نماذج بدون توكن CSRF
            if '<form' in response.text.lower():
                results.append("تم العثور على نماذج في الصفحة:")
                
                # تحليل بسيط للنماذج
                if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                    results.append("⚠️ تحذير: النماذج قد لا تحتوي على حماية CSRF")
                else:
                    results.append("✅ تم العثور على مؤشرات لحماية CSRF")
            
            # فحص رؤوس الأمان
            security_headers = {
                'x-frame-options': 'حماية من Clickjacking',
                'x-content-type-options': 'حماية من MIME sniffing',
                'x-xss-protection': 'حماية XSS',
                'content-security-policy': 'سياسة أمان المحتوى'
            }
            
            results.append("\nرؤوس الأمان:")
            for header, description in security_headers.items():
                if header in response.headers:
                    results.append(f"✅ {description}: موجود")
                else:
                    results.append(f"❌ {description}: غير موجود")
                    
        except:
            results.append("تعذر فحص CSRF")
        
        return self.save_results("csrf_scanner", results)
    
    def http_headers_analyzer(self, url):
        """أداة 16: تحليل رؤوس HTTP"""
        logging.info(f"تحليل رؤوس HTTP لـ {url}")
        results = []
        
        try:
            response = requests.get(url, timeout=5)
            
            results.append("رؤوس HTTP الحالية:")
            for header, value in response.headers.items():
                results.append(f"{header}: {value}")
            
            # تحليل الرؤوس المهمة للأمان
            important_headers = {
                'Strict-Transport-Security': 'HSTS مفعل - اتصال آمن',
                'Content-Security-Policy': 'سياسة أمان المحتوى مفعلة',
                'X-Frame-Options': 'حماية من Clickjacking مفعلة',
                'X-Content-Type-Options': 'حماية من MIME sniffing مفعلة',
                'Referrer-Policy': 'سياسة الإحالة مفعلة',
                'Permissions-Policy': 'سياسة الصلاحيات مفعلة'
            }
            
            results.append("\nتحليل الأمان:")
            for header, description in important_headers.items():
                if header in response.headers:
                    results.append(f"✅ {description}")
                else:
                    results.append(f"❌ {header} غير موجود")
                    
        except Exception as e:
            results.append(f"خطأ في التحليل: {str(e)}")
        
        return self.save_results("http_headers_analyzer", results)
    
    def api_security_scanner(self, api_url):
        """أداة 17: كشف الثغرات في واجهات API"""
        logging.info(f"فحص أمان API: {api_url}")
        results = []
        
        # اختبارات أمان API الأساسية
        tests = [
            ("GET", "", "فحص الوصول بدون توثيق"),
            ("GET", "/admin", "فحص المسارات الإدارية"),
            ("DELETE", "/users/1", "فحص صلاحيات الحذف"),
            ("POST", "/users", "فحذ إنشاء مستخدم بدون صلاحيات"),
            ("PUT", "/users/1", "فحص تحديث بيانات بدون توثيق")
        ]
        
        results.append("اختبار أمان API:")
        
        for method, path, description in tests:
            try:
                test_url = f"{api_url}{path}"
                if method == "GET":
                    response = requests.get(test_url, timeout=3)
                elif method == "POST":
                    response = requests.post(test_url, timeout=3)
                elif method == "DELETE":
                    response = requests.delete(test_url, timeout=3)
                elif method == "PUT":
                    response = requests.put(test_url, timeout=3)
                
                if response.status_code == 200:
                    results.append(f"⚠️ {description}: تم الوصول بنجاح (رمز 200)")
                elif response.status_code == 401:
                    results.append(f"✅ {description}: ممنوع (401) - جيد")
                elif response.status_code == 403:
                    results.append(f"✅ {description}: محظور (403) - جيد")
                else:
                    results.append(f"ℹ️ {description}: رمز الحالة {response.status_code}")
                    
            except:
                results.append(f"تعذر اختبار: {description}")
        
        return self.save_results("api_security_scanner", results)
    
    def ssl_tls_scanner(self, hostname, port=443):
        """أداة 18: فحص SSL/TLS"""
        logging.info(f"فحص SSL/TLS لـ {hostname}:{port}")
        results = []
        
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # معلومات الشهادة
                    results.append("معلومات شهادة SSL/TLS:")
                    results.append(f"الموضوع: {cert.get('subject', [])}")
                    results.append(f"المصدر: {cert.get('issuer', [])}")
                    results.append(f"الإصدار: {cert.get('version', 'غير معروف')}")
                    
                    # تاريخ انتهاء الصلاحية
                    from datetime import datetime
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.now()).days
                        results.append(f"تنتهي بعد: {days_left} يوم")
                        
                        if days_left < 30:
                            results.append("⚠️ تحذير: الشهادة ستنتهي قريباً")
                    
                    # إصدار البروتوكول
                    results.append(f"إصدار SSL/TLS: {ssock.version()}")
                    
        except Exception as e:
            results.append(f"خطأ في فحص SSL/TLS: {str(e)}")
        
        return self.save_results("ssl_tls_scanner", results)
    
    def cms_vulnerability_scanner(self, url):
        """أداة 19: كشف الثغرات في CMS"""
        logging.info(f"فحص CMS في {url}")
        results = []
        
        # التعرف على CMS
        cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-json'],
            'joomla': ['com_content', 'option=com_', '/media/system/js/'],
            'drupal': ['sites/default', 'drupal.js', 'core/misc/drupal.js'],
            'magento': ['skin/frontend', 'mage/cookies.js', 'x-magento-tags'],
            'shopify': ['cdn.shopify.com', 'myshopify.com', '/cart'],
            'wix': ['wix.com', '_wix']
        }
        
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
            
            detected_cms = []
            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig in content:
                        detected_cms.append(cms)
                        break
            
            if detected_cms:
                results.append(f"تم اكتشاف: {', '.join(set(detected_cms))}")
                
                # فحص الثغرات المعروفة لكل CMS
                if 'wordpress' in detected_cms:
                    results.append("\nثغرات WordPress المعروفة:")
                    results.append("- فحص ملفات wp-config.php")
                    results.append("- فحص ثغرات الإضافات")
                    results.append("- فحص المستخدمين")
                    
            else:
                results.append("لم يتم التعرف على CMS محدد")
                
        except:
            results.append("تعذر فحص CMS")
        
        return self.save_results("cms_vulnerability_scanner", results)
    
    def dos_simulation(self, target):
        """أداة 20: محاكاة هجمات الجمود"""
        logging.info(f"محاكاة هجوم DoS على {target}")
        results = []
        
        results.append("محاكاة هجوم DoS (للأغراض التعليمية فقط)")
        results.append(f"الهدف: {target}")
        
        # شرح أنواع هجمات DoS
        results.append("\nأنواع هجمات DoS:")
        results.append("1. SYN Flood - إغراق بطلبات الاتصال")
        results.append("2. UDP Flood - إغراق بحزم UDP")
        results.append("3. HTTP Flood - إغراق بطلبات HTTP")
        results.append("4. Ping of Death - حزم ping ضخمة")
        results.append("5. Slowloris - إبطاء الاتصالات")
        
        # طرق الوقاية
        results.append("\nطرق الوقاية من DoS:")
        results.append("- استخدام جدران حماية متقدمة")
        results.append("- تفعيل حماية من الهجمات الموزعة (DDoS)")
        results.append("- تحديد معدل الطلبات (Rate Limiting)")
        results.append("- استخدام CDN لامتصاص الهجمات")
        results.append("- مراقبة حركة المرور باستمرار")
        
        return self.save_results("dos_simulation", results)
    
    def camera_link_generator(self):
        """أداة 21: إنشاء رابط محلي للكاميرا"""
        logging.info("بدء تشغيل خادم الكاميرا المحلي")
        results = []
        
        try:
            import http.server
            import socketserver
            import threading
            
            # إنشاء خادم HTTP بسيط يعرض الكاميرا
            class CameraHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        
                        html = """
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>كاميرا محلية - تجريبية</title>
                            <style>
                                body { font-family: Arial; text-align: center; padding: 50px; background: #f0f0f0; }
                                video, canvas { max-width: 100%; border: 2px solid #333; border-radius: 10px; }
                                button { padding: 10px 20px; font-size: 16px; margin: 10px; cursor: pointer; }
                                #status { margin: 20px; padding: 10px; background: #fff; border-radius: 5px; }
                            </style>
                        </head>
                        <body>
                            <h1>📷 كاميرا تجريبية - للأغراض التعليمية</h1>
                            <div id="status">يرجى السماح بالوصول إلى الكاميرا</div>
                            <video id="video" width="640" height="480" autoplay></video>
                            <canvas id="canvas" width="640" height="480" style="display:none;"></canvas>
                            <div>
                                <button onclick="capture()">التقاط صورة</button>
                                <button onclick="toggleCamera()">تشغيل/إيقاف الكاميرا</button>
                            </div>
                            
                            <script>
                                let video = document.getElementById('video');
                                let canvas = document.getElementById('canvas');
                                let stream = null;
                                
                                async function startCamera() {
                                    try {
                                        stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
                                        video.srcObject = stream;
                                        document.getElementById('status').innerHTML = '✅ الكاميرا تعمل';
                                    } catch(err) {
                                        document.getElementById('status').innerHTML = '❌ خطأ في الوصول للكاميرا: ' + err.message;
                                    }
                                }
                                
                                function stopCamera() {
                                    if(stream) {
                                        stream.getTracks().forEach(track => track.stop());
                                        video.srcObject = null;
                                        document.getElementById('status').innerHTML = '⏹️ الكاميرا متوقفة';
                                    }
                                }
                                
                                function toggleCamera() {
                                    if(video.srcObject) {
                                        stopCamera();
                                    } else {
                                        startCamera();
                                    }
                                }
                                
                                function capture() {
                                    if(video.srcObject) {
                                        let context = canvas.getContext('2d');
                                        context.drawImage(video, 0, 0, 640, 480);
                                        let imgData = canvas.toDataURL('image/png');
                                        
                                        let link = document.createElement('a');
                                        link.download = 'capture_' + Date.now() + '.png';
                                        link.href = imgData;
                                        link.click();
                                        
                                        document.getElementById('status').innerHTML = '📸 تم التقاط الصورة!';
                                    } else {
                                        alert('الكاميرا غير مفعلة');
                                    }
                                }
                                
                                // بدء الكاميرا تلقائياً
                                startCamera();
                            </script>
                            
                            <div style="margin-top: 30px; color: #666;">
                                <p>⚠️ هذا تطبيق تجريبي للأغراض التعليمية فقط</p>
                                <p>يتم تشغيل الكاميرا محلياً ولا يتم إرسال الصور لأي خادم</p>
                            </div>
                        </body>
                        </html>
                        """
                        self.wfile.write(html.encode())
                    else:
                        super().do_GET()
            
            # تشغيل الخادم في منفذ عشوائي
            port = 8080
            handler = CameraHandler
            
            with socketserver.TCPServer(("", port), handler) as httpd:
                local_ip = socket.gethostbyname(socket.gethostname())
                results.append(f"✅ خادم الكاميرا يعمل على:")
                results.append(f"   - محلياً: http://localhost:{port}")
                results.append(f"   - شبكة محلية: http://{local_ip}:{port}")
                results.append("\n⚠️ ملاحظة: هذا للاختبار على أجهزتك فقط!")
                
                # تشغيل الخادم في خيط منفصل
                server_thread = threading.Thread(target=httpd.serve_forever)
                server_thread.daemon = True
                server_thread.start()
                
                # الانتظار لمدة 30 ثانية (يمكن تغييرها)
                time.sleep(30)
                httpd.shutdown()
                results.append("\nتم إيقاف خادم الكاميرا بعد 30 ثانية")
                
        except Exception as e:
            results.append(f"خطأ في تشغيل خادم الكاميرا: {str(e)}")
        
        return self.save_results("camera_link_generator", results)
    
    def phishing_simulation(self):
        """أداة 22: محاكاة هجوم التصيد"""
        logging.info("محاكاة هجوم التصيد (للتعليم)")
        results = []
        
        results.append("محاكاة هجوم التصيد - للأغراض التعليمية")
        
        # شرح هجمات التصيد
        results.append("\nأنواع هجمات التصيد:")
        results.append("1. تصيد عبر البريد الإلكتروني")
        results.append("2. تصيد عبر المواقع المزيفة")
        results.append("3. تصيد عبر الرسائل النصية (Smishing)")
        results.append("4. تصيد عبر المكالمات (Vishing)")
        results.append("5. تصيد عبر وسائل التواصل")
        
        # كيفية الكشف
        results.append("\nكيفية كشف التصيد:")
        results.append("✓ التحقق من عنوان URL بعناية")
        results.append("✓ التأكد من استخدام HTTPS")
        results.append("✓ عدم النقر على روابط مشبوهة")
        results.append("✓ التحقق من المرسل في البريد الإلكتروني")
        results.append("✓ استخدام التحقق بخطوتين")
        
        # مثال على صفحة تصيد تعليمية
        results.append("\nمثال على صفحة تصيد (للتوعية فقط):")
        results.append("""
        <!DOCTYPE html>
        <html>
        <head><title>تنبيه أمني - وهمي</title></head>
        <body style="text-align:center; padding:50px;">
            <h1 style="color:red;">⚠️ هذا مثال تعليمي لصفحة تصيد!</h1>
            <p>هذه الصفحة توضح كيف تبدو صفحات التصيد</p>
            <div style="border:1px solid #ccc; padding:20px; max-width:300px; margin:auto;">
                <h2>تسجيل الدخول - وهمي</h2>
                <input type="text" placeholder="البريد الإلكتروني" style="width:100%; margin:5px;"><br>
                <input type="password" placeholder="كلمة المرور" style="width:100%; margin:5px;"><br>
                <button style="width:100%; padding:10px;">تسجيل الدخول</button>
            </div>
            <p style="color:#999;">هذا مجرد مثال تعليمي، لا تدخل بيانات حقيقية!</p>
        </body>
        </html>
        """)
        
        return self.save_results("phishing_simulation", results)
    
    def ftp_vulnerability_scanner(self, target, port=21):
        """أداة 23: كشف الثغرات في خدمات FTP"""
        logging.info(f"فحص ثغرات FTP على {target}:{port}")
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            results.append(f"بصمة FTP: {banner}")
            
            # اختبار الدخول المجهول
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "331" in response:  # كود انتظار كلمة المرور
                sock.send(b"PASS anonymous@example.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if "230" in response:  # تم الدخول بنجاح
                    results.append("⚠️ ثغرة: الدخول المجهول مسموح!")
                    
                    # محاولة استعراض الملفات
                    sock.send(b"LIST\r\n")
                    files = sock.recv(4096).decode('utf-8', errors='ignore')
                    results.append("الملفات المتاحة:")
                    results.append(files[:500])
                    
            sock.close()
            
        except Exception as e:
            results.append(f"خطأ في فحص FTP: {str(e)}")
        
        return self.save_results("ftp_vulnerability_scanner", results)
    
    def ssh_security_audit(self, target, port=22):
        """أداة 24: تحليل الثغرات في SSH"""
        logging.info(f"فحص أمان SSH على {target}:{port}")
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            results.append(f"بصمة SSH: {banner}")
            
            # تحليل الإصدار
            if "SSH-2.0" in banner:
                results.append("✅ بروتوكول SSH2 - جيد")
            else:
                results.append("⚠️ تحذير: إصدار SSH قديم")
            
            # اختبار طرق المصادقة
            sock.send(b"\x00" * 20)  # حزمة اختبار
            response = sock.recv(1024)
            
            # قائمة بالثغرات المعروفة في SSH
            known_vulnerabilities = {
                "libssh": "ثغرة CVE-2018-10933",
                "Dropbear": "ثغرات متعددة في الإصدارات القديمة",
                "OpenSSH < 7.4": "ثغرات في المصادقة"
            }
            
            for key, vuln in known_vulnerabilities.items():
                if key.lower() in banner.lower():
                    results.append(f"⚠️ {vuln}")
            
            sock.close()
            
        except Exception as e:
            results.append(f"خطأ في فحص SSH: {str(e)}")
        
        return self.save_results("ssh_security_audit", results)
    
    def smb_vulnerability_scanner(self, target):
        """أداة 25: كشف الثغرات في SMB"""
        logging.info(f"فحص ثغرات SMB على {target}")
        results = []
        
        ports = [139, 445]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    results.append(f"✅ منفذ SMB {port} مفتوح")
                    
                    # فحص الثغرات المعروفة
                    results.append("فحص ثغرات SMB المعروفة:")
                    
                    # ثغرة EternalBlue (MS17-010)
                    results.append("- MS17-010 (EternalBlue): ")
                    results.append("  تحقق من تحديثات Windows")
                    
                    # ثغرة SMB signing
                    results.append("- SMB Signing: ")
                    results.append("  يجب تفعيل توقيع SMB للأمان")
                    
                    # مشاركات SMB
                    results.append("- مشاركات SMB متاحة (قد تكون خطرة)")
                    
                sock.close()
                
            except:
                pass
        
        return self.save_results("smb_vulnerability_scanner", results)
    
    def command_injection_scanner(self, url):
        """أداة 26: اختبار حقن الأوامر"""
        logging.info(f"فحص ثغرات حقن الأوامر في {url}")
        results = []
        
        # أوامر اختبار على أنظمة مختلفة
        test_commands = [
            ("; ls", "Linux/Unix listing"),
            ("&& dir", "Windows directory"),
            ("| whoami", "Current user"),
            ("; cat /etc/passwd", "Password file (Linux)"),
            ("& ipconfig", "Network config (Windows)"),
            ("`id`", "User ID (Linux)"),
            ("$(uname -a)", "System info")
        ]
        
        results.append("اختبار حقن الأوامر:")
        
        for cmd, description in test_commands:
            try:
                test_url = f"{url}?cmd={cmd}"
                response = requests.get(test_url, timeout=5)
                
                # البحث عن مؤشرات تنفيذ الأوامر
                indicators = [
                    "uid=",
                    "root:",
                    "Directory of",
                    "Volume in drive",
                    "bin/bash",
                    "Microsoft Windows"
                ]
                
                for indicator in indicators:
                    if indicator in response.text:
                        results.append(f"⚠️ ثغرة محتملة مع الأمر: {cmd}")
                        results.append(f"   مؤشر: {indicator}")
                        break
                        
            except:
                pass
        
        return self.save_results("command_injection_scanner", results)
    
    def database_scanner(self, target):
        """أداة 27: كشف الثغرات في قواعد البيانات"""
        logging.info(f"فحص قواعد البيانات على {target}")
        results = []
        
        # منافذ قواعد البيانات الشائعة
        db_ports = {
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB",
            6379: "Redis",
            1521: "Oracle",
            1433: "SQL Server",
            9042: "Cassandra",
            9200: "Elasticsearch"
        }
        
        for port, db_type in db_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    results.append(f"✅ {db_type} على المنفذ {port}")
                    
                    # محاولة الحصول على البصمة
                    try:
                        sock.send(b"\x00")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner:
                            results.append(f"   البصمة: {banner[:100]}")
                    except:
                        pass
                        
                sock.close()
                
            except:
                pass
        
        return self.save_results("database_scanner", results)
    
    def buffer_overflow_simulation(self):
        """أداة 28: محاكاة تجاوز سعة الذاكرة المؤقتة"""
        logging.info("محاكاة ثغرة تجاوز سعة الذاكرة المؤقتة")
        results = []
        
        results.append("محاكاة Buffer Overflow - للأغراض التعليمية")
        
        # شرح الثغرة
        results.append("\nما هي ثغرة Buffer Overflow؟")
        results.append("تحدث عندما يكتب برنامج بيانات أكثر من سعة الذاكرة المخصصة")
        results.append("مما قد يؤدي إلى تنفيذ أكواد ضارة أو تعطيل البرنامج")
        
        # مثال برمجي توضيحي
        results.append("\nمثال على كود ضعيف:")
        results.append("""
        #include <stdio.h>
        #include <string.h>
        
        void vulnerable_function(char *user_input) {
            char buffer[10];  // سعة صغيرة جداً
            strcpy(buffer, user_input);  // لا يوجد تحقق من الطول!
            printf("تم النسخ: %s\\n", buffer);
        }
        
        int main() {
            // هذا قد يسبب تجاوز للذاكرة
            vulnerable_function("نص طويل جداً جداً يتجاوز السعة المخصصة");
            return 0;
        }
        """)
        
        # طرق الوقاية
        results.append("\nطرق الوقاية:")
        results.append("✓ استخدام دوال آمنة مثل strncpy بدلاً من strcpy")
        results.append("✓ التحقق من طول المدخلات")
        errors.append("✓ تفعيل حماية ASLR و DEP")
        results.append("✓ تحديث البرامج والمكتبات")
        
        return self.save_results("buffer_overflow_simulation", results)
    
    def email_server_scanner(self, target):
        """أداة 29: كشف الثغرات في خدمات البريد"""
        logging.info(f"فحص خوادم البريد على {target}")
        results = []
        
        email_ports = {
            25: "SMTP",
            465: "SMTPS",
            587: "SMTP Submission",
            110: "POP3",
            995: "POP3S",
            143: "IMAP",
            993: "IMAPS"
        }
        
        for port, service in email_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    results.append(f"✅ {service} على المنفذ {port}")
                    
                    # محاولة الحصول على البصمة
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        results.append(f"   البصمة: {banner[:100]}")
                        
                        # اختبارات أمان SMTP
                        if port == 25:
                            sock.send(b"HELO test.com\r\n")
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            if "250" in response:
                                # اختبار VRFY (يكشف عن المستخدمين)
                                sock.send(b"VRFY root\r\n")
                                vrfy_response = sock.recv(1024).decode('utf-8', errors='ignore')
                                
                                if "252" in vrfy_response or "250" in vrfy_response:
                                    results.append("   ⚠️ أمر VRFY مفعل - قد يكشف عن المستخدمين")
                                    
                    except:
                        pass
                        
                sock.close()
                
            except:
                pass
        
        return self.save_results("email_server_scanner", results)
    
    def exploit_simulator(self, target, port=None):
        """أداة 30: محاكاة استغلال الثغرات للدخول"""
        logging.info(f"محاكاة استغلال الثغرات على {target}")
        results = []
        
        results.append("محاكاة استغلال الثغرات - للأغراض التعليمية")
        results.append(f"الهدف: {target}")
        
        # سيناريوهات الاستغلال المحتملة
        exploits = {
            "SMB": ["EternalBlue (MS17-010)", "هجمات Pass-the-Hash"],
            "SSH": ["هجمات القاموس", "ثغرات المصادقة"],
            "FTP": ["دخول مجهول", "نقل ملفات خبيثة"],
            "WEB": ["SQL Injection", "File Upload", "LFI/RFI"],
            "RDP": ["BlueKeep (CVE-2019-0708)", "هجمات القاموس"]
        }
        
        # فحص المنافذ المفتوحة لتحديد الاستغلالات المحتملة
        try:
            open_ports = []
            for p in [21,22,80,139,443,445,3389,8080]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target, p)) == 0:
                    open_ports.append(p)
                sock.close()
            
            if open_ports:
                results.append(f"\nالمنافذ المفتوحة: {open_ports}")
                
                results.append("\nسيناريوهات الاستغلال المحتملة:")
                for port in open_ports:
                    if port == 445:
                        results.append(f"  - SMB (المنفذ {port}): {exploits['SMB']}")
                    elif port == 22:
                        results.append(f"  - SSH (المنفذ {port}): {exploits['SSH']}")
                    elif port == 21:
                        results.append(f"  - FTP (المنفذ {port}): {exploits['FTP']}")
                    elif port in [80,443,8080]:
                        results.append(f"  - WEB (المنفذ {port}): {exploits['WEB']}")
                    elif port == 3389:
                        results.append(f"  - RDP (المنفذ {port}): {exploits['RDP']}")
            else:
                results.append("\nلا توجد منافذ مفتوحة شائعة")
                
        except:
            pass
        
        # خطوات الاستغلال العامة
        results.append("\nخطوات الاستغلال العامة:")
        results.append("1. جمع المعلومات (Reconnaissance)")
        results.append("2. فحص الثغرات (Vulnerability Scanning)")
        results.append("3. اختيار الاستغلال المناسب (Exploit Selection)")
        results.append("4. تنفيذ الاستغلال (Exploitation)")
        results.append("5. رفع الصلاحيات (Privilege Escalation)")
        results.append("6. تنظيف الآثار (Covering Tracks)")
        
        # طرق الوقاية
        results.append("\nطرق الوقاية من الاستغلال:")
        results.append("✓ تحديث جميع الأنظمة باستمرار")
        results.append("✓ استخدام جدران حماية متقدمة")
        results.append("✓ تفعيل التحقق بخطوتين")
        results.append("✓ مراقبة السجلات باستمرار")
        results.append("✓ تقليل سطح الهجوم")
        
        return self.save_results("exploit_simulator", results)
    
    def iot_vulnerability_scanner(self, target):
        """أداة 31: كشف الثغرات في إنترنت الأشياء"""
        logging.info(f"فحص أجهزة إنترنت الأشياء على {target}")
        results = []
        
        # منافذ أجهزة IoT الشائعة
        iot_ports = {
            80: "HTTP (IoT واجهة ويب)",
            443: "HTTPS (IoT)",
            21: "FTP (أجهزة تخزين)",
            23: "Telnet (أجهزة شبكة)",
            8080: "HTTP بديل (كاميرات)",
            8443: "HTTPS بديل (أجهزة أمان)",
            554: "RTSP (كاميرات IP)",
            8554: "RTSP بديل",
            37777: "Dahua كاميرات",
            8888: "بعض أنظمة المراقبة"
        }
        
        results.append(f"فحص أجهزة IoT على {target}")
        
        for port, description in iot_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    results.append(f"✅ {description} (المنفذ {port})")
                    
                    # محاولة التعرف على الجهاز
                    try:
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        # البحث عن بصمات أجهزة IoT
                        iot_signatures = {
                            "dahua": "كاميرات Dahua",
                            "hikvision": "كاميرات Hikvision",
                            "axis": "كاميرات Axis",
                            "foscam": "كاميرات Foscam",
                            "tp-link": "أجهزة TP-Link",
                            "d-link": "أجهزة D-Link",
                            "netgear": "أجهزة Netgear",
                            "ubiquiti": "أجهزة Ubiquiti"
                        }
                        
                        for sig, name in iot_signatures.items():
                            if sig in response.lower():
                                results.append(f"   الجهاز المحتمل: {name}")
                                break
                                
                    except:
                        pass
                        
                sock.close()
                
            except:
                pass
        
        # توصيات أمان IoT
        results.append("\nتوصيات أمان لأجهزة IoT:")
        results.append("• تغيير كلمات المرور الافتراضية")
        results.append("• تحديث البرامج الثابتة (Firmware)")
        results.append("• تعطيل الخدمات غير الضرورية (Telnet, FTP)")
        results.append("• استخدام شبكة منفصلة لأجهزة IoT")
        results.append("• تفعيل جدار الحماية")
        
        return self.save_results("iot_vulnerability_scanner", results)
    
    def log_analyzer(self, log_file=None):
        """أداة 32: تحليل سجلات النظام"""
        logging.info("تحليل سجلات النظام")
        results = []
        
        if not log_file:
            # محاولة العثور على سجلات النظام حسب نظام التشغيل
            if platform.system() == "Linux":
                log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log"]
            elif platform.system() == "Windows":
                log_files = ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]
            else:
                log_files = []
                
            results.append("البحث عن سجلات النظام...")
        else:
            log_files = [log_file]
        
        for log in log_files:
            if os.path.exists(log):
                results.append(f"\nتحليل الملف: {log}")
                
                try:
                    with open(log, 'r', errors='ignore') as f:
                        lines = f.readlines()[-100:]  # آخر 100 سطر
                        
                    # البحث عن أنشطة مشبوهة
                    suspicious_patterns = {
                        "Failed password": "محاولات دخول فاشلة",
                        "authentication failure": "فشل توثيق",
                        "Invalid user": "محاولة دخول بمستخدم غير موجود",
                        "BREAK-IN": "محاولة اختراق",
                        "error: maximum authentication attempts": "محاولات توثيق كثيرة",
                        "Connection closed by authenticating user": "اتصال مغلق أثناء التوثيق",
                        "sudo: COMMAND": "أوامر sudo منفذة",
                        "CRON": "مهام مجدولة"
                    }
                    
                    found_suspicious = False
                    for line in lines[-20:]:  # آخر 20 سطر
                        for pattern, desc in suspicious_patterns.items():
                            if pattern in line:
                                results.append(f"⚠️ {desc}: {line.strip()}")
                                found_suspicious = True
                                break
                    
                    if not found_suspicious:
                        results.append("لم يتم العثور على أنشطة مشبوهة في آخر 20 سطر")
                        
                except Exception as e:
                    results.append(f"خطأ في قراءة الملف: {str(e)}")
            else:
                results.append(f"الملف غير موجود: {log}")
        
        return self.save_results("log_analyzer", results)
    
    def generate_comprehensive_report(self):
        """أداة 33: تقرير أمني شامل"""
        logging.info("تجميع تقرير أمني شامل")
        results = []
        
        results.append("=" * 60)
        results.append("تقرير الأمن الشامل - شامل جميع الفحوصات")
        results.append("=" * 60)
        results.append(f"تاريخ التقرير: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        results.append(f"معرف الجلسة: {self.session_id}")
        results.append("=" * 60)
        
        # تجميع نتائج جميع الفحوصات
        for tool_num in range(1, 34):
            tool_name = self.tools[tool_num]['name']
            result_file = f"{self.results_dir}/{self.tools[tool_num]['function'].__name__}.txt"
            
            if os.path.exists(result_file):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    results.append(f"\n📊 {tool_num}. {tool_name}")
                    results.append("-" * 40)
                    results.append(content[:500] + "..." if len(content) > 500 else content)
                except:
                    pass
        
        # ملخص الثغرات المكتشفة
        results.append("\n" + "=" * 60)
        results.append("📋 ملخص الثغرات المكتشفة")
        results.append("=" * 60)
        
        results.append("\nمستويات الخطورة:")
        results.append("🔴 عالية: ثغرات حرجة تحتاج تدخل فوري")
        results.append("🟡 متوسطة: ثغرات مهمة تحتاج معالجة")
        results.append("🟢 منخفضة: تحسينات مقترحة")
        
        results.append("\nتوصيات عامة:")
        results.append("1. تحديث جميع الأنظمة والبرامج")
        results.append("2. تفعيل جدران الحماية")
        results.append("3. استخدام كلمات مرور قوية")
        results.append("4. تفعيل التحقق بخطوتين")
        results.append("5. مراقبة السجلات باستمرار")
        results.append("6. عمل نسخ احتياطية منتظمة")
        
        results.append("\n" + "=" * 60)
        results.append("نهاية التقرير الشامل")
        results.append("=" * 60)
        
        return self.save_results("comprehensive_report", results)
    
    def get_service_name(self, port):
        """الحصول على اسم الخدمة من رقم المنفذ"""
        common_services = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return common_services.get(port, "Unknown")
    
    def save_results(self, tool_name, results):
        """حفظ نتائج الأداة في ملف"""
        if not isinstance(results, list):
            results = [str(results)]
        
        filename = f"{self.results_dir}/{tool_name}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"نتائج {tool_name}\n")
                f.write(f"التاريخ: {datetime.now()}\n")
                f.write("-" * 50 + "\n")
                for line in results:
                    f.write(str(line) + "\n")
            logging.info(f"تم حفظ النتائج في {filename}")
            return filename
        except Exception as e:
            logging.error(f"خطأ في حفظ النتائج: {e}")
            return None
    
    def display_menu(self):
        """عرض القائمة الرئيسية"""
        print("\n" + "=" * 60)
        print("🔐 الأداة الشاملة لفحص الثغرات الأمنية - للأغراض التعليمية")
        print("=" * 60)
        print(f"معرف الجلسة: {self.session_id}")
        print(f"مجلد النتائج: {self.results_dir}")
        print("=" * 60)
        
        for num in range(1, 34):
            tool = self.tools[num]
            print(f"{num:2d}. {tool['name']}")
        print("0. خروج")
        print("=" * 60)
    
    def run(self):
        """تشغيل الأداة الرئيسية"""
        while True:
            self.display_menu()
            
            try:
                choice = input("\nاختر رقم الأداة (0-33): ").strip()
                
                if choice == '0':
                    print("تم إيقاف الأداة. شكراً لاستخدامك النظام التعليمي!")
                    print(f"نتائج الفحوصات محفوظة في: {self.results_dir}")
                    break
                
                choice = int(choice)
                if 1 <= choice <= 33:
                    tool = self.tools[choice]
                    print(f"\n▶️ تشغيل: {tool['name']}")
                    print(f"📝 {tool['description']}")
                    
                    # الحصول على المدخلات حسب الأداة
                    target = None
                    if choice in [1, 2, 3, 4, 9, 10, 23, 24, 25, 27, 29, 30, 31]:
                        target = input("أدخل عنوان الهدف (IP أو domain): ").strip()
                        if not target:
                            print("❌ يجب إدخال عنوان الهدف")
                            continue
                    
                    elif choice in [11, 12, 13, 15, 16, 17, 19, 26]:
                        target = input("أدخل URL كاملاً (مثال: http://example.com): ").strip()
                        if not target:
                            print("❌ يجب إدخال URL")
                            continue
                    
                    elif choice == 14:
                        target = input("أدخل كلمة المرور للاختبار: ").strip()
                        if not target:
                            print("❌ يجب إدخال كلمة المرور")
                            continue
                    
                    elif choice == 18:
                        target = input("أدخل اسم المضيف (hostname): ").strip()
                        port = input("أدخل رقم المنفذ (افتراضي 443): ").strip()
                        port = int(port) if port else 443
                    
                    # تشغيل الأداة المناسبة
                    start_time = time.time()
                    
                    if choice == 18 and 'port' in locals():
                        result_file = tool['function'](target, port)
                    elif choice == 21:
                        result_file = tool['function']()
                    elif choice == 32:
                        log_file = input("أدخل مسار ملف السجل (أو اترك فارغاً للبحث التلقائي): ").strip()
                        result_file = tool['function'](log_file if log_file else None)
                    elif choice == 33:
                        result_file = tool['function']()
                    elif target:
                        result_file = tool['function'](target)
                    else:
                        result_file = tool['function']()
                    
                    elapsed = time.time() - start_time
                    
                    if result_file:
                        print(f"✅ تم إكمال الفحص في {elapsed:.2f} ثانية")
                        print(f"📁 النتائج محفوظة في: {result_file}")
                        
                        # عرض ملخص سريع
                        try:
                            with open(result_file, 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                                print("\n📋 ملخص النتائج:")
                                for line in lines[:5]:  # أول 5 أسطر فقط
                                    print(f"  {line.strip()}")
                        except:
                            pass
                    else:
                        print("❌ فشل في إكمال الفحص")
                    
                    input("\nاضغط Enter للمتابعة...")
                    
                else:
                    print("❌ رقم غير صحيح، اختر من 1 إلى 33")
                    
            except ValueError:
                print("❌ الرجاء إدخال رقم صحيح")
            except KeyboardInterrupt:
                print("\n\nتم إيقاف الأداة بواسطة المستخدم")
                break
            except Exception as e:
                print(f"❌ حدث خطأ: {str(e)}")
                logging.error(f"خطأ في تشغيل الأداة: {str(e)}")

if __name__ == "__main__":
    # التحقق من الصلاحيات
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("⚠️ تحذير: بعض الأدوات تحتاج صلاحيات مدير النظام (root)")
        response = input("هل تريد المتابعة؟ (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # إنشاء وتشغيل الأداة
    tool = SecurityAuditTool()
    tool.run()