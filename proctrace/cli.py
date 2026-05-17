"""
命令行接口
Command Line Interface
"""

import argparse
import sys
import json
from datetime import datetime
from .core.process_analyzer import ProcessAnalyzer
from .web.server import run_server


def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog='proctrace',
        description='🔍 ProcTrace - 进程追踪与安全分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  proctrace scan                    # 扫描所有进程
  proctrace scan --suspicious       # 仅显示可疑进程
  proctrace scan --high-risk        # 仅显示高风险进程
  proctrace web                     # 启动Web可视化界面
  proctrace web --port 8080         # 指定端口启动Web服务
  proctrace report --output json    # 生成JSON格式报告
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # scan 命令
    scan_parser = subparsers.add_parser('scan', help='扫描进程')
    scan_parser.add_argument('--suspicious', '-s', action='store_true',
                            help='仅显示可疑进程')
    scan_parser.add_argument('--high-risk', '-r', action='store_true',
                            help='仅显示高风险进程')
    scan_parser.add_argument('--json', '-j', action='store_true',
                            help='以JSON格式输出')
    scan_parser.add_argument('--pid', '-p', type=int,
                            help='查看指定PID的进程详情')
    
    # web 命令
    web_parser = subparsers.add_parser('web', help='启动Web可视化服务')
    web_parser.add_argument('--host', default='127.0.0.1',
                           help='绑定地址 (默认: 127.0.0.1)')
    web_parser.add_argument('--port', '-p', type=int, default=5000,
                           help='监听端口 (默认: 5000)')
    web_parser.add_argument('--debug', action='store_true',
                           help='启用调试模式')
    
    # report 命令
    report_parser = subparsers.add_parser('report', help='生成分析报告')
    report_parser.add_argument('--output', '-o', choices=['json', 'text'], default='text',
                              help='输出格式 (默认: text)')
    report_parser.add_argument('--file', '-f', help='保存到文件')
    
    # version
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0.0')
    
    return parser


def format_process_info(process, detailed=False):
    """格式化进程信息输出"""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"🔹 进程: {process.name} (PID: {process.pid})")
    lines.append(f"{'='*60}")
    lines.append(f"   可执行文件: {process.exe or 'N/A'}")
    lines.append(f"   命令行: {' '.join(process.cmdline) if process.cmdline else 'N/A'}")
    lines.append(f"   用户: {process.username}")
    lines.append(f"   状态: {process.status}")
    lines.append(f"   启动时间: {datetime.fromtimestamp(process.create_time).strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"   CPU使用率: {process.cpu_percent:.1f}%")
    lines.append(f"   内存使用率: {process.memory_percent:.1f}%")
    lines.append(f"   线程数: {process.threads}")
    lines.append(f"   父进程PID: {process.parent_pid or 'N/A'}")
    lines.append(f"   子进程数: {process.children_count}")
    
    if process.file_hash:
        lines.append(f"   文件哈希: {process.file_hash[:16]}...")
    
    # 安全分析结果
    lines.append(f"\n   🛡️ 安全分析:")
    risk_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'safe': '🟢', 'unknown': '⚪'}
    lines.append(f"      风险等级: {risk_emoji.get(process.risk_level, '⚪')} {process.risk_level.upper()}")
    lines.append(f"      威胁评分: {process.threat_score}/100")
    
    if process.suspicious_indicators:
        lines.append(f"      可疑指标:")
        for indicator in process.suspicious_indicators:
            lines.append(f"         ⚠️  {indicator}")
    
    if detailed and process.connections:
        lines.append(f"\n   🌐 网络连接:")
        for conn in process.connections[:5]:
            lines.append(f"      {conn['type']} {conn['local_addr']} -> {conn['remote_addr']} [{conn['status']}]")
        if len(process.connections) > 5:
            lines.append(f"      ... 还有 {len(process.connections) - 5} 个连接")
    
    return '\n'.join(lines)


def cmd_scan(args):
    """执行扫描命令"""
    analyzer = ProcessAnalyzer()
    
    if args.pid:
        # 查看指定进程
        processes = analyzer.get_all_processes()
        process = next((p for p in processes if p.pid == args.pid), None)
        if process:
            if args.json:
                print(json.dumps(process.__dict__, indent=2, default=str))
            else:
                print(format_process_info(process, detailed=True))
                
                # 显示进程树
                tree = analyzer.get_process_tree(args.pid)
                if tree:
                    print(f"\n   🌳 进程树:")
                    if tree.get('ancestors'):
                        for ancestor in tree['ancestors']:
                            print(f"      {ancestor['name']} (PID: {ancestor['pid']})")
                        print(f"      {'│' * len(tree['ancestors'])}")
                    print(f"      📌 {tree['name']} (PID: {tree['pid']}) [当前]")
                    for child in tree.get('children', []):
                        print(f"      ├─ {child['name']} (PID: {child['pid']})")
        else:
            print(f"❌ 未找到PID为 {args.pid} 的进程")
            return 1
    else:
        # 扫描所有进程
        processes = analyzer.get_all_processes()
        
        if args.high_risk:
            processes = analyzer.get_high_risk_processes()
            title = "🔴 高风险进程"
        elif args.suspicious:
            processes = analyzer.get_suspicious_processes()
            title = "⚠️ 可疑进程"
        else:
            title = "📋 所有进程"
        
        if args.json:
            print(json.dumps([p.__dict__ for p in processes], indent=2, default=str))
        else:
            print(f"\n{'='*60}")
            print(f"{title}")
            print(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}")
            
            if not processes:
                print("\n✅ 未发现匹配的进程")
            else:
                for process in processes:
                    print(format_process_info(process))
            
            # 统计信息
            all_processes = analyzer.analysis_results
            suspicious = analyzer.get_suspicious_processes()
            high_risk = analyzer.get_high_risk_processes()
            
            print(f"\n{'='*60}")
            print("📊 统计摘要")
            print(f"{'='*60}")
            print(f"   总进程数: {len(all_processes)}")
            print(f"   可疑进程: {len(suspicious)}")
            print(f"   高风险进程: {len(high_risk)}")
    
    return 0


def cmd_web(args):
    """执行Web命令"""
    print(f"🚀 启动 ProcTrace Web 服务...")
    print(f"   地址: http://{args.host}:{args.port}")
    print(f"   按 Ctrl+C 停止服务\n")
    
    try:
        run_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n👋 服务已停止")
    
    return 0


def cmd_report(args):
    """执行报告命令"""
    analyzer = ProcessAnalyzer()
    analyzer.get_all_processes()
    
    if args.output == 'json':
        report = analyzer.generate_report('json')
        if args.file:
            with open(args.file, 'w') as f:
                f.write(report)
            print(f"✅ 报告已保存至: {args.file}")
        else:
            print(report)
    else:
        # 文本格式报告
        suspicious = analyzer.get_suspicious_processes()
        high_risk = analyzer.get_high_risk_processes()
        
        lines = []
        lines.append("="*70)
        lines.append("                     ProcTrace 安全分析报告")
        lines.append("="*70)
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"总进程数: {len(analyzer.analysis_results)}")
        lines.append(f"可疑进程: {len(suspicious)}")
        lines.append(f"高风险进程: {len(high_risk)}")
        lines.append("="*70)
        
        if high_risk:
            lines.append("\n🔴 高风险进程列表:")
            lines.append("-"*70)
            for p in high_risk:
                lines.append(f"  • {p.name} (PID: {p.pid}) - 评分: {p.threat_score}")
                for indicator in p.suspicious_indicators:
                    lines.append(f"    - {indicator}")
        
        if suspicious and not high_risk:
            lines.append("\n⚠️ 可疑进程列表:")
            lines.append("-"*70)
            for p in suspicious:
                lines.append(f"  • {p.name} (PID: {p.pid}) - 评分: {p.threat_score}")
        
        if not suspicious:
            lines.append("\n✅ 未发现可疑进程，系统状态良好！")
        
        lines.append("\n" + "="*70)
        lines.append("报告结束")
        lines.append("="*70)
        
        report_text = '\n'.join(lines)
        
        if args.file:
            with open(args.file, 'w') as f:
                f.write(report_text)
            print(f"✅ 报告已保存至: {args.file}")
        else:
            print(report_text)
    
    return 0


def main():
    """主入口"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        if args.command == 'scan':
            return cmd_scan(args)
        elif args.command == 'web':
            return cmd_web(args)
        elif args.command == 'report':
            return cmd_report(args)
        else:
            parser.print_help()
            return 0
    except Exception as e:
        print(f"❌ 错误: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
