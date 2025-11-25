#!/usr/bin/env python3
import sys
import subprocess
import shutil
import json
import frida
import time
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from datetime import datetime
from rich.console import Console
from urllib.parse import urlparse
from rich.progress import Progress, SpinnerColumn, TextColumn


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
    script, is_typescript = generator.generate_hooks()
    
    hooks_dir = Path('src/hooks')
    hooks_dir.mkdir(parents=True, exist_ok=True)
    if is_typescript:
        script_file = hooks_dir / 'generated_hooks.ts'
    else:
        script_file = hooks_dir / 'generated_hooks.js'
    
    script_file.write_text(script)
    console.print(f"[green]✓ Generated {script_file.name}[/green]")
    
    return script_file, package_name

def compile_hooks(script_file):
    if script_file.suffix == '.js':
        console.print(f"[green]✓ Using {script_file.name} (no compilation needed)[/green]")
        return script_file
    js_file = script_file.with_suffix('.js')
    
    cmd = ['npx', 'frida-compile', str(script_file), '-o', str(js_file)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        console.print(f"[red]✗ Compilation failed: {result.stderr}[/red]")
        return None
    
    console.print(f"[green]✓ Compiled to {js_file.name}[/green]")
    return js_file

def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ''

def save_sequences(package_name, api_seq, net_seq, start_time):
    output_dir = Path('output') / package_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    end_time = time.time()
    duration = end_time - start_time if start_time else 0
    
    start_iso = datetime.fromtimestamp(start_time).isoformat() if start_time else None
    end_iso = datetime.fromtimestamp(end_time).isoformat()
    
    api_data = {
        "metadata": {
            "package_name": package_name,
            "capture_start": start_iso,
            "capture_end": end_iso,
            "duration_seconds": round(duration, 3),
            "total_calls": len(api_seq)
        },
        "sequence": api_seq
    }
    
    api_file = output_dir / f"{package_name}_api_sequence.json"
    with open(api_file, 'w') as f:
        json.dump(api_data, f, indent=2, default=str)    
    console.print(f"[green]✓ Saved API sequence: {api_file}[/green]")

    unique_domains = list(set(
        extract_domain(e.get('url', '')) 
        for e in net_seq if e.get('url')
    ))
    unique_domains = [d for d in unique_domains if d]  # rmv empty strings
    
    net_data = {
        "metadata": {
            "package_name": package_name,
            "capture_start": start_iso,
            "capture_end": end_iso,
            "duration_seconds": round(duration, 3),
            "total_requests": len(net_seq),
            "unique_domains": unique_domains
        },
        "sequence": net_seq
    }
    
    net_file = output_dir / f"{package_name}_network_sequence.json"
    with open(net_file, 'w') as f:
        json.dump(net_data, f, indent=2, default=str)
    console.print(f"[green]✓ Saved network sequence: {net_file}[/green]")

def run_frida_script(device, package_name, js_file):
    api_sequence = []
    network_sequence = []
    start_time = None
    api_seq_num = 0
    net_seq_num = 0
    
    try:
        pid = device.spawn([package_name])
        session = device.attach(pid)
        
        with open(js_file) as f:
            script_code = f.read()
        
        script = session.create_script(script_code)
        
        def on_message(message, data):
            nonlocal start_time, api_seq_num, net_seq_num
            if message['type'] == 'send':
                payload = message.get('payload', {})
                msg_type = payload.get('type', 'unknown')
                if start_time is None:
                    start_time = time.time()
                current_time = time.time()
                
                event = {
                    'timestamp': current_time,
                    'relative_time': round(current_time - start_time, 3),
                    **payload
                }
                # categorize and add to seqs
                if msg_type in ['network', 'http', 'https', 'okhttp', 'socket']:
                    net_seq_num += 1
                    event['seq'] = net_seq_num
                    network_sequence.append(event)
                else:
                    api_seq_num += 1
                    event['seq'] = api_seq_num
                    api_sequence.append(event)
                
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
                elif msg_type == 'native':
                    func = payload.get('func', '')
                    path = payload.get('path', '')
                    if path:
                        console.print(f"[magenta][NATIVE][/magenta] {func}(\"{path}\")")
                elif msg_type == 'ssl':
                    func = payload.get('func', '')
                    console.print(f"[cyan][SSL][/cyan] {func}")
            elif message['type'] == 'error':
                console.print(f"[red][ERROR][/red] {message}")
        
        script.on('message', on_message)
        script.load()
        
        device.resume(pid)
        
        console.print("[green]✓ Frida script loaded successfully.[/green]")
        console.print("[yellow]Monitoring app activity.. (Press Ctrl+C to stop)[/yellow]\n")
        
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            save_sequences(package_name, api_sequence, network_sequence, start_time)
            session.detach()
            console.print("\n[green]✓ Session ended[/green]")
    
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
    script_file, package_name = detect_frameworks(decompiled_dir)
    if not script_file:
        sys.exit(1)
    
    if not package_name:
        console.print("[yellow]Package name not found in manifest[/yellow]")
        package_name = input("Enter package name manually: ").strip()
        if not package_name:
            console.print("[red]✗ Package name required[/red]")
            sys.exit(1)
    
    console.print("\n[bold][+] Compiling hooks[/bold]")
    js_file = compile_hooks(script_file)
    if not js_file:
        sys.exit(1)
    
    console.print("\n[bold][+] Running Frida script[/bold]")
    run_frida_script(device, package_name, js_file)

if __name__ == '__main__':
    main()
