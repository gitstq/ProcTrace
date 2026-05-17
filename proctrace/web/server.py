"""
Web可视化服务器
Web Visualization Server
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime
from ..core.process_analyzer import ProcessAnalyzer


def create_app():
    """创建Flask应用"""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    CORS(app)
    
    analyzer = ProcessAnalyzer()
    
    @app.route('/')
    def index():
        """主页"""
        return render_template('index.html')
    
    @app.route('/api/processes')
    def get_processes():
        """获取所有进程"""
        processes = analyzer.get_all_processes()
        return jsonify({
            'total': len(processes),
            'processes': [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'exe': p.exe,
                    'username': p.username,
                    'status': p.status,
                    'cpu_percent': round(p.cpu_percent, 2),
                    'memory_percent': round(p.memory_percent, 2),
                    'threat_score': p.threat_score,
                    'risk_level': p.risk_level,
                    'suspicious_indicators': p.suspicious_indicators
                }
                for p in processes
            ]
        })
    
    @app.route('/api/suspicious')
    def get_suspicious():
        """获取可疑进程"""
        analyzer.get_all_processes()  # 确保数据已加载
        suspicious = analyzer.get_suspicious_processes()
        return jsonify({
            'count': len(suspicious),
            'processes': [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'exe': p.exe,
                    'cmdline': p.cmdline,
                    'username': p.username,
                    'cpu_percent': round(p.cpu_percent, 2),
                    'memory_percent': round(p.memory_percent, 2),
                    'threat_score': p.threat_score,
                    'risk_level': p.risk_level,
                    'suspicious_indicators': p.suspicious_indicators,
                    'connections': p.connections,
                    'file_hash': p.file_hash
                }
                for p in suspicious
            ]
        })
    
    @app.route('/api/process/<int:pid>')
    def get_process_detail(pid):
        """获取进程详情"""
        analyzer.get_all_processes()
        process = next((p for p in analyzer.analysis_results if p.pid == pid), None)
        if process:
            return jsonify({
                'pid': process.pid,
                'name': process.name,
                'exe': process.exe,
                'cmdline': process.cmdline,
                'username': process.username,
                'status': process.status,
                'create_time': process.create_time,
                'cpu_percent': round(process.cpu_percent, 2),
                'memory_percent': round(process.memory_percent, 2),
                'memory_rss': process.memory_rss,
                'threads': process.threads,
                'parent_pid': process.parent_pid,
                'children_count': process.children_count,
                'connections': process.connections,
                'file_hash': process.file_hash,
                'threat_score': process.threat_score,
                'risk_level': process.risk_level,
                'suspicious_indicators': process.suspicious_indicators
            })
        return jsonify({'error': 'Process not found'}), 404
    
    @app.route('/api/process/<int:pid>/tree')
    def get_process_tree(pid):
        """获取进程树"""
        tree = analyzer.get_process_tree(pid)
        return jsonify(tree)
    
    @app.route('/api/stats')
    def get_stats():
        """获取统计信息"""
        processes = analyzer.get_all_processes()
        suspicious = analyzer.get_suspicious_processes()
        high_risk = analyzer.get_high_risk_processes()
        
        # 风险分布
        risk_distribution = {'safe': 0, 'low': 0, 'medium': 0, 'high': 0, 'unknown': 0}
        for p in processes:
            risk_distribution[p.risk_level] = risk_distribution.get(p.risk_level, 0) + 1
        
        # 按用户统计
        user_stats = {}
        for p in processes:
            user_stats[p.username] = user_stats.get(p.username, 0) + 1
        
        # 资源使用Top10
        top_cpu = sorted(processes, key=lambda x: x.cpu_percent, reverse=True)[:10]
        top_memory = sorted(processes, key=lambda x: x.memory_percent, reverse=True)[:10]
        
        return jsonify({
            'total_processes': len(processes),
            'suspicious_count': len(suspicious),
            'high_risk_count': len(high_risk),
            'risk_distribution': risk_distribution,
            'user_stats': user_stats,
            'top_cpu': [{'pid': p.pid, 'name': p.name, 'cpu': round(p.cpu_percent, 2)} for p in top_cpu],
            'top_memory': [{'pid': p.pid, 'name': p.name, 'memory': round(p.memory_percent, 2)} for p in top_memory],
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/report')
    def generate_report():
        """生成完整报告"""
        analyzer.get_all_processes()
        report_data = analyzer.generate_report()
        return jsonify(json.loads(report_data))
    
    return app


def run_server(host='127.0.0.1', port=5000, debug=False):
    """运行Web服务器"""
    app = create_app()
    app.run(host=host, port=port, debug=debug)
