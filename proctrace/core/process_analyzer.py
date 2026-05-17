"""
进程分析核心模块
Process Analysis Core Module
"""

import psutil
import os
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ProcessInfo:
    """进程信息数据结构"""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    create_time: float
    username: str
    status: str
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    connections: List[Dict]
    threads: int
    parent_pid: Optional[int]
    children_count: int
    
    # 安全分析字段
    file_hash: str = ""
    is_signed: bool = False
    threat_score: int = 0
    risk_level: str = "unknown"
    suspicious_indicators: List[str] = None
    
    def __post_init__(self):
        if self.suspicious_indicators is None:
            self.suspicious_indicators = []


class ProcessAnalyzer:
    """进程分析器"""
    
    # 可疑进程名称模式
    SUSPICIOUS_PATTERNS = [
        "miner", "mining", "xmr", "monero", "bitcoin",
        "trojan", "backdoor", "keylogger", "stealer",
        "crypt", "ransom", "exploit", "payload",
        "nc.exe", "ncat", "nmap", "metasploit",
        "mimikatz", "mimilib", "procdump", "pwdump"
    ]
    
    # 可疑路径模式
    SUSPICIOUS_PATHS = [
        r"\temp\", r"\tmp\", r"\windows\temp\",
        r"\appdata\local\temp\", r"/tmp/", r"/var/tmp/",
        r"\users\public\", r"/dev/shm/"
    ]
    
    # 系统关键进程列表
    SYSTEM_PROCESSES = [
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        "kernel", "init", "systemd", "sshd", "cron"
    ]
    
    def __init__(self):
        self.analysis_results: List[ProcessInfo] = []
        
    def get_all_processes(self) -> List[ProcessInfo]:
        """获取所有进程信息"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 
                                          'create_time', 'username', 'status',
                                          'cpu_percent', 'memory_percent', 
                                          'memory_info', 'num_threads', 'ppid']):
            try:
                pinfo = ProcessInfo(
                    pid=proc.info['pid'],
                    name=proc.info['name'] or "unknown",
                    exe=proc.info['exe'] or "",
                    cmdline=proc.info['cmdline'] or [],
                    create_time=proc.info['create_time'] or 0,
                    username=proc.info['username'] or "unknown",
                    status=proc.info['status'] or "unknown",
                    cpu_percent=proc.info['cpu_percent'] or 0.0,
                    memory_percent=proc.info['memory_percent'] or 0.0,
                    memory_rss=proc.info['memory_info'].rss if proc.info['memory_info'] else 0,
                    connections=self._get_connections(proc),
                    threads=proc.info['num_threads'] or 0,
                    parent_pid=proc.info['ppid'],
                    children_count=len(proc.children())
                )
                
                # 执行安全分析
                self._analyze_security(pinfo)
                processes.append(pinfo)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        self.analysis_results = processes
        return processes
    
    def _get_connections(self, proc: psutil.Process) -> List[Dict]:
        """获取进程网络连接信息"""
        connections = []
        try:
            for conn in proc.connections(kind='inet'):
                conn_info = {
                    'status': conn.status,
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'type': 'TCP' if conn.type == 1 else 'UDP'
                }
                connections.append(conn_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return connections
    
    def _analyze_security(self, pinfo: ProcessInfo):
        """执行安全分析"""
        score = 0
        indicators = []
        
        # 1. 检查可疑进程名称
        name_lower = pinfo.name.lower()
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in name_lower:
                score += 30
                indicators.append(f"可疑进程名称匹配: {pattern}")
        
        # 2. 检查可疑路径
        exe_lower = pinfo.exe.lower() if pinfo.exe else ""
        for path in self.SUSPICIOUS_PATHS:
            if path.lower() in exe_lower:
                score += 20
                indicators.append(f"可疑执行路径: {path}")
        
        # 3. 检查无父进程（可能是孤儿进程）
        if pinfo.parent_pid == 0 or pinfo.parent_pid == 1:
            if pinfo.name.lower() not in self.SYSTEM_PROCESSES:
                score += 15
                indicators.append("无父进程或父进程为init")
        
        # 4. 检查网络连接
        external_connections = [c for c in pinfo.connections if c.get('remote_addr')]
        if len(external_connections) > 5:
            score += 10
            indicators.append(f"大量外部网络连接: {len(external_connections)}")
        
        # 5. 检查高资源使用
        if pinfo.cpu_percent > 50:
            score += 10
            indicators.append(f"高CPU使用率: {pinfo.cpu_percent:.1f}%")
        
        if pinfo.memory_percent > 20:
            score += 10
            indicators.append(f"高内存使用率: {pinfo.memory_percent:.1f}%")
        
        # 6. 检查命令行参数
        cmdline_str = ' '.join(pinfo.cmdline).lower()
        suspicious_args = ['-enc', '-encodedcommand', '-nop', '-windowstyle hidden',
                          'downloadstring', 'invoke-expression', 'iex', 'bitsadmin',
                          'certutil', 'regsvr32', 'mshta']
        for arg in suspicious_args:
            if arg in cmdline_str:
                score += 25
                indicators.append(f"可疑命令行参数: {arg}")
        
        # 7. 计算文件哈希（如果可访问）
        if pinfo.exe and os.path.exists(pinfo.exe):
            try:
                pinfo.file_hash = self._calculate_file_hash(pinfo.exe)
            except:
                pass
        
        # 设置风险等级
        if score >= 60:
            pinfo.risk_level = "high"
        elif score >= 30:
            pinfo.risk_level = "medium"
        elif score > 0:
            pinfo.risk_level = "low"
        else:
            pinfo.risk_level = "safe"
        
        pinfo.threat_score = min(score, 100)
        pinfo.suspicious_indicators = indicators
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """计算文件SHA256哈希"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """获取可疑进程列表"""
        return [p for p in self.analysis_results if p.threat_score > 0]
    
    def get_high_risk_processes(self) -> List[ProcessInfo]:
        """获取高风险进程"""
        return [p for p in self.analysis_results if p.risk_level == "high"]
    
    def get_process_tree(self, pid: int) -> Dict:
        """获取进程树"""
        try:
            proc = psutil.Process(pid)
            tree = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe() if hasattr(proc, 'exe') else '',
                'children': []
            }
            
            for child in proc.children(recursive=True):
                try:
                    tree['children'].append({
                        'pid': child.pid,
                        'name': child.name(),
                        'exe': child.exe() if hasattr(child, 'exe') else ''
                    })
                except:
                    pass
            
            # 获取父进程链
            tree['ancestors'] = []
            current = proc
            while current.parent():
                try:
                    parent = current.parent()
                    tree['ancestors'].insert(0, {
                        'pid': parent.pid,
                        'name': parent.name(),
                        'exe': parent.exe() if hasattr(parent, 'exe') else ''
                    })
                    current = parent
                except:
                    break
            
            return tree
        except psutil.NoSuchProcess:
            return {}
    
    def generate_report(self, output_format: str = "json") -> str:
        """生成分析报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_processes': len(self.analysis_results),
                'suspicious_count': len(self.get_suspicious_processes()),
                'high_risk_count': len(self.get_high_risk_processes())
            },
            'suspicious_processes': [asdict(p) for p in self.get_suspicious_processes()],
            'high_risk_processes': [asdict(p) for p in self.get_high_risk_processes()]
        }
        
        if output_format == "json":
            return json.dumps(report, indent=2, default=str)
        
        return json.dumps(report, default=str)
