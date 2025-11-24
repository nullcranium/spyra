#!/usr/bin/env python3
import sys
import subprocess
import shutil
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
import frida
import time

console = Console()

def check_dependencies():
    missing = []
    
    if not shutil.which('apktool'):
        missing.append('apktool')
    if not shutil.which('npx'):
        missing.append('npx (Node.js)')
    
    try:
        import frida
    except ImportError:
        missing.append('frida (pip install frida==17.2.17)')

    if missing:
        console.print("[red]✗ Missing dependencies:[/red]")
        for dep in missing:
            console.print(f"  • {dep}")
        console.print("\n[yellow]Install missing dependencies and try again[/yellow]")
        return False
    
    console.print("[green]✓ All dependencies installed[/green]")
    return True

def check_frida_server():
    try:
        device = frida.get_usb_device(timeout=3)
        console.print(f"[green]✓ Frida server connected: {device.name}[/green]")
        return device
    except frida.TimedOutError:
        console.print("[red]✗ No USB device found[/red]")
        return None
    except frida.ServerNotRunningError:
        console.print("[red]✗ Frida server not running on device[/red]")
        return None
    except Exception as e:
        console.print(f"[red]✗ Frida connection error: {e}[/red]")
        return None

def decompile_apk(apk_path):
    apk_file = Path(apk_path)
    output_dir = Path('data') / f"{apk_file.stem}_decompiled"
    
    if output_dir.exists():
        console.print(f"[yellow]Removing old decompiled data...[/yellow]")
        shutil.rmtree(output_dir)
    
    output_dir.parent.mkdir(exist_ok=True)
    console.print(f"[cyan]Decompiling {apk_file.name}..[/cyan]")
    
    cmd = ['apktool', 'd', '-f', str(apk_file), '-o', str(output_dir), '-q']
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        console.print(f"[red]✗ Decompilation failed: {result.stderr}[/red]")
        return None
    
    console.print(f"[green]✓ Decompiled to {output_dir}[/green]")
    return output_dir

def detect_frameworks(decompiled_dir):
    sys.path.insert(0, str(Path(__file__).parent / 'src'))
    from framework_detector import FrameworkDetector, HookGenerator
    import xml.etree.ElementTree as ET
    
    console.print("[cyan]Detecting frameworks..[/cyan]")
    
    detector = FrameworkDetector(decompiled_dir)
    frameworks = detector.detect_all()
    
    if not frameworks:
        console.print("[yellow]No frameworks detected.[/yellow]")
        return None, None
    
    # show detected frameworks
    table = Table(title="Detected Frameworks", show_header=True)
    table.add_column("Framework", style="cyan")
    table.add_column("Confidence", style="green")
    
    for fw in frameworks:
        confidence_bar = "█" * int(fw.confidence * 10)
        table.add_row(fw.name, f"{confidence_bar} {fw.confidence:.0%}")
    
    console.print(table)
    
    # extract package name
    manifest = decompiled_dir / 'AndroidManifest.xml'
    package_name = None
    if manifest.exists():
        try:
            tree = ET.parse(manifest)
            package_name = tree.getroot().get('package')
            console.print(f"[cyan]Package: {package_name}[/cyan]")
        except:
            pass
    
    console.print("[cyan]Generating hooks..[/cyan]")
    generator = HookGenerator(frameworks)
    script = generator.generate_hooks()
    
    hooks_dir = Path('src/hooks')
    hooks_dir.mkdir(parents=True, exist_ok=True)
    
    ts_file = hooks_dir / 'generated_hooks.ts'
    ts_file.write_text(script)
    
    console.print(f"[green]✓ Generated {ts_file.name}[/green]")
    
    return ts_file, package_name

def compile_hooks(ts_file):
    js_file = ts_file.with_suffix('.js')
    
    cmd = ['npx', 'frida-compile', str(ts_file), '-o', str(js_file)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        console.print(f"[red]✗ Compilation failed: {result.stderr}[/red]")
        return None
    
    console.print(f"[green]✓ Compiled to {js_file.name}[/green]")
    return js_file

def run_frida_script(device, package_name, js_file):
    try:
        pid = device.spawn([package_name])
        session = device.attach(pid)
        
        with open(js_file) as f:
            script_code = f.read()
        
        script = session.create_script(script_code)
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message.get('payload', {})
                msg_type = payload.get('type', 'unknown')
                
                if msg_type == 'network':
                    action = payload.get('action', '')
                    url = payload.get('url', '')
                    method = payload.get('method', '')
                    console.print(f"[blue][NETWORK][/blue] {method} {url}")
                
                elif msg_type == 'crypto':
                    action = payload.get('action', '')
                    algo = payload.get('transformation') or payload.get('algorithm', '')
                    console.print(f"[yellow][CRYPTO][/yellow] {algo}")
                
                elif msg_type == 'file':
                    path = payload.get('path', '')
                    action = payload.get('action', '')
                    console.print(f"[green][FILE][/green] {action}: {path}")
                
                elif msg_type == 'system':
                    value = payload.get('value', '')
                    console.print(f"[red][SYSTEM][/red] Device ID: {value}")
            
            elif message['type'] == 'error':
                console.print(f"[red][ERROR][/red] {message}")
        
        script.on('message', on_message)
        script.load()
        
        device.resume(pid)
        
        console.print("[green]✓ Frida script loaded successfully.[/green]")
        console.print("[yellow]Monitoring app activity... (Press Ctrl+C to stop)[/yellow]\n")
        
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            session.detach()
            console.print("[green]✓ Session ended[/green]")
    
    except frida.ProcessNotFoundError:
        console.print(f"[red]✗ App not found: {package_name}[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")

def main():
    console.print(Panel.fit(
        "[bold cyan]APK Malware Analysis Automation[/bold cyan]\n"
        "[dim]Framework Detection + API Monitoring[/dim]",
        border_style="cyan"
    ))
    
    if len(sys.argv) < 2:
        console.print("\n[yellow]Usage:[/yellow] python3 main.py <apk_file>")
        console.print("[dim]Example: python3 main.py app.apk[/dim]\n")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    if not Path(apk_path).exists():
        console.print(f"[red]✗ APK file not found: {apk_path}[/red]")
        sys.exit(1)
    
    console.print("\n[bold][+] Checking dependencies[/bold]")
    if not check_dependencies():
        sys.exit(1)
    
    console.print("\n[bold][+] Checking Frida server[/bold]")
    device = check_frida_server()
    if not device:
        sys.exit(1)
    
    console.print("\n[bold][+] Decompiling APK[/bold]")
    decompiled_dir = decompile_apk(apk_path)
    if not decompiled_dir:
        sys.exit(1)
    
    console.print("\n[bold][+] Detecting frameworks[/bold]")
    ts_file, package_name = detect_frameworks(decompiled_dir)
    if not ts_file:
        sys.exit(1)
    
    if not package_name:
        console.print("[yellow]Package name not found in manifest[/yellow]")
        package_name = input("Enter package name manually: ").strip()
        if not package_name:
            console.print("[red]✗ Package name required[/red]")
            sys.exit(1)
    
    console.print("\n[bold][+] Compiling hooks[/bold]")
    js_file = compile_hooks(ts_file)
    if not js_file:
        sys.exit(1)
    
    console.print("\n[bold][+] Running Frida script[/bold]")
    run_frida_script(device, package_name, js_file)

if __name__ == '__main__':
    main()
