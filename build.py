"""
构建脚本 - 生成跨平台可执行文件
Build Script - Generate Cross-Platform Executables
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path


def clean_build():
    """清理构建目录"""
    dirs_to_clean = ['build', 'dist', '__pycache__', '.pytest_cache']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"✓ 已清理: {dir_name}")
    
    # 清理Python缓存
    for root, dirs, files in os.walk('.'):
        for d in dirs:
            if d == '__pycache__':
                shutil.rmtree(os.path.join(root, d))
        for f in files:
            if f.endswith('.pyc'):
                os.remove(os.path.join(root, f))


def build_executable():
    """构建可执行文件"""
    system = platform.system()
    
    print(f"🔨 开始构建 ProcTrace ({system})...")
    
    # 基础命令
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",  # 单文件
        "--name", "proctrace",
        "--clean",
        "--noconfirm",
    ]
    
    # 添加数据文件
    cmd.extend([
        "--add-data", f"proctrace/web/templates{os.pathsep}proctrace/web/templates",
    ])
    
    # Windows特殊处理
    if system == "Windows":
        cmd.extend(["--console", "--icon", "NONE"])
    else:
        cmd.append("--console")
    
    # 隐藏导入
    cmd.extend([
        "--hidden-import", "psutil",
        "--hidden-import", "flask",
        "--hidden-import", "flask_cors",
    ])
    
    # 入口文件
    cmd.append("proctrace/cli.py")
    
    print(f"   执行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    
    if result.returncode == 0:
        print("✅ 构建成功!")
        
        # 显示输出文件
        dist_path = Path("dist")
        if system == "Windows":
            exe_path = dist_path / "proctrace.exe"
        else:
            exe_path = dist_path / "proctrace"
        
        if exe_path.exists():
            size = exe_path.stat().st_size / (1024 * 1024)  # MB
            print(f"   输出文件: {exe_path}")
            print(f"   文件大小: {size:.2f} MB")
    else:
        print("❌ 构建失败")
        return False
    
    return True


def create_package():
    """创建分发包"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    dist_dir = Path("dist")
    package_name = f"proctrace-v1.0.0-{system}-{machine}"
    package_dir = dist_dir / package_name
    
    # 创建包目录
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir(parents=True)
    
    # 复制可执行文件
    if system == "windows":
        exe_file = dist_dir / "proctrace.exe"
        shutil.copy(exe_file, package_dir / "proctrace.exe")
    else:
        exe_file = dist_dir / "proctrace"
        shutil.copy(exe_file, package_dir / "proctrace")
        # 添加执行权限
        os.chmod(package_dir / "proctrace", 0o755)
    
    # 复制文档
    shutil.copy("README.md", package_dir / "README.md")
    shutil.copy("LICENSE", package_dir / "LICENSE")
    
    # 创建压缩包
    shutil.make_archive(str(dist_dir / package_name), 'zip', package_dir)
    
    print(f"✅ 分发包已创建: {package_name}.zip")
    
    return package_dir


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ProcTrace 构建工具')
    parser.add_argument('--clean', action='store_true', help='仅清理构建目录')
    parser.add_argument('--no-package', action='store_true', help='不创建分发包')
    args = parser.parse_args()
    
    if args.clean:
        clean_build()
        return
    
    # 完整构建流程
    clean_build()
    
    if build_executable():
        if not args.no_package:
            create_package()
        print("\n🎉 构建完成!")
    else:
        print("\n❌ 构建失败")
        sys.exit(1)


if __name__ == "__main__":
    main()
