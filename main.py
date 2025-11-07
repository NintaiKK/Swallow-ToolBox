import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import os
import sys
from datetime import datetime
import psutil

class SwallowToolBox:
    def __init__(self, root):
        self.root = root
        self.root.title("Swallow ToolBox")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        # Configurar estilo
        self.setup_styles()
        
        # Criar interface
        self.create_widgets()
        
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabel', background='#2b2b2b', foreground='white')
        self.style.configure('TButton', background='#404040', foreground='white')
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        self.style.configure('Section.TLabelframe', background='#2b2b2b', foreground='white')
        self.style.configure('Section.TLabelframe.Label', background='#2b2b2b', foreground='white')
        
    def create_widgets(self):
        # Frame principal com scroll
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Canvas e Scrollbar
        canvas = tk.Canvas(main_frame, bg='#2b2b2b', highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Título
        title_label = ttk.Label(self.scrollable_frame, text="🛠️ Swallow ToolBox - Ferramentas de TI Completas", style='Title.TLabel')
        title_label.pack(pady=10)
        
        # Criar seções de ferramentas
        self.create_network_section()
        self.create_system_section()
        self.create_security_section()
        self.create_disk_section()
        self.create_web_section()
        self.create_automation_section()
        self.create_monitoring_section()
        
        # Área de output
        self.create_output_section()
        
        # Controles
        self.create_control_section()
    
    def create_network_section(self):
        """Seção de Ferramentas de Rede"""
        section = ttk.LabelFrame(self.scrollable_frame, text="🔍 Diagnóstico de Rede", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("Ping 8.8.8.8", "ping 8.8.8.8 -n 10"),
            ("Ping Contínuo", "ping 8.8.8.8 -t"),
            ("Traceroute", "tracert 8.8.8.8"),
            ("DNS Lookup", "nslookup google.com"),
            ("Port Scanner", "netstat -an"),
            ("Network Interfaces", "ipconfig /all"),
            ("ARP Table", "arp -a"),
            ("Route Table", "route print"),
            ("Network Statistics", "netstat -s"),
            ("Multi Host Ping", self.run_multi_ping),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_system_section(self):
        """Seção de Monitoramento do Sistema"""
        section = ttk.LabelFrame(self.scrollable_frame, text="🖥️ Monitoramento do Sistema", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("Process Manager", "tasklist"),
            ("Service Status", "sc query"),
            ("Event Viewer", "wevtutil qe System /c:10"),
            ("Disk Usage", "wmic logicaldisk get size,freespace,caption"),
            ("System Info", "systeminfo"),
            ("Hardware Info", "wmic computersystem list brief"),
            ("User Sessions", "query session"),
            ("Shared Resources", "net share"),
            ("System Health Report", self.generate_system_health_report),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_security_section(self):
        """Seção de Segurança"""
        section = ttk.LabelFrame(self.scrollable_frame, text="🔒 Segurança", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("Firewall Status", "netsh advfirewall show allprofiles"),
            ("Windows Defender", "Get-MpComputerStatus"),
            ("Open Ports", "netstat -ab"),
            ("Password Policy", "net accounts"),
            ("Scan Suspicious Processes", self.scan_suspicious_processes),
            ("Security Audit", self.run_security_audit),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_disk_section(self):
        """Seção de Gerenciamento de Disco"""
        section = ttk.LabelFrame(self.scrollable_frame, text="💾 Gerenciamento de Disco", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("Disk Check", "chkdsk /scan"),
            ("Defrag Analysis", "defrag /a C:"),
            ("Disk Cleanup", "cleanmgr /sageset:1"),
            ("Partition Info", "echo list volume | diskpart"),
            ("S.M.A.R.T. Status", "wmic diskdrive get status"),
            ("File System Info", "fsutil fsinfo statistics C:"),
            ("Disk Space Analyzer", self.analyze_disk_space),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_web_section(self):
        """Seção de Ferramentas Web"""
        section = ttk.LabelFrame(self.scrollable_frame, text="🌐 Ferramentas Web", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("HTTP Headers", "curl -I https://google.com"),
            ("Website Ping", "ping -n 5 www.google.com"),
            ("SSL Check", "openssl s_client -connect google.com:443 < nul"),
            ("Network Speed Test", self.run_speed_test),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_automation_section(self):
        """Seção de Scripts Automatizados"""
        section = ttk.LabelFrame(self.scrollable_frame, text="⚡ Scripts Automatizados", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("Backup Configurações", self.backup_system_config),
            ("Otimizar Sistema", self.optimize_system),
            ("Limpeza Completa", self.system_cleanup),
            ("Daily Report", self.generate_daily_report),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_monitoring_section(self):
        """Seção de Monitoramento em Tempo Real"""
        section = ttk.LabelFrame(self.scrollable_frame, text="📊 Monitoramento em Tempo Real", style='Section.TLabelframe')
        section.pack(fill=tk.X, padx=10, pady=5)
        
        tools = [
            ("Live System Monitor", self.start_live_monitor),
            ("Network Monitor", self.start_network_monitor),
            ("Process Monitor", self.start_process_monitor),
            ("Performance Dashboard", self.show_performance_dashboard),
        ]
        
        self.create_tool_buttons(section, tools)
    
    def create_tool_buttons(self, parent, tools):
        """Cria botões para uma seção de ferramentas"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, padx=5, pady=5)
        
        row_frame = None
        for i, (name, command) in enumerate(tools):
            if i % 4 == 0:
                row_frame = ttk.Frame(frame)
                row_frame.pack(fill=tk.X, pady=2)
            
            if callable(command):
                btn = ttk.Button(row_frame, text=name, command=command)
            else:
                btn = ttk.Button(row_frame, text=name, command=lambda cmd=command: self.run_command(cmd))
            
            btn.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
    
    def create_output_section(self):
        """Cria a área de output"""
        output_frame = ttk.LabelFrame(self.scrollable_frame, text="📋 Output", style='Section.TLabelframe')
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, 
            height=15,
            bg='#1e1e1e',
            fg='#00ff00',
            insertbackground='white',
            font=('Consolas', 9)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_control_section(self):
        """Cria a seção de controles"""
        control_frame = ttk.Frame(self.scrollable_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(control_frame, text="🧹 Clear Output", 
                  command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="💾 Save Log", 
                  command=self.save_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="➕ Custom Tool", 
                  command=self.add_custom_tool).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="❌ Exit", 
                  command=self.root.quit).pack(side=tk.RIGHT, padx=5)
    
    # ========== MÉTODOS DE EXECUÇÃO ==========
    
    def run_command(self, command):
        """Executa um comando em thread separada"""
        def thread_target():
            self.output_text.insert(tk.END, f"\n>>> Executando: {command}\n")
            self.output_text.insert(tk.END, "="*50 + "\n")
            self.output_text.see(tk.END)
            
            try:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                for line in process.stdout:
                    self.output_text.insert(tk.END, line)
                    self.output_text.see(tk.END)
                    self.root.update()
                
                process.wait()
                self.output_text.insert(tk.END, f"\n>>> Comando finalizado (código: {process.returncode})\n")
                
            except Exception as e:
                self.output_text.insert(tk.END, f"\n>>> ERRO: {str(e)}\n")
            
            self.output_text.see(tk.END)
        
        threading.Thread(target=thread_target, daemon=True).start()
    
    # ========== FERRAMENTAS PERSONALIZADAS ==========
    
    def run_multi_ping(self):
        """Ping para múltiplos hosts"""
        hosts = ["8.8.8.8", "google.com", "1.1.1.1", "localhost"]
        for host in hosts:
            self.run_command(f"ping {host} -n 2")
    
    def generate_system_health_report(self):
        """Gera relatório de saúde do sistema"""
        report_commands = [
            "echo ===== SYSTEM HEALTH REPORT =====",
            "echo Data: %date% Hora: %time%",
            "systeminfo | findstr /C:\"Total Physical Memory\" /C:\"Available Physical Memory\"",
            "wmic cpu get loadpercentage | findstr -v LoadPercentage",
            "wmic logicaldisk get size,freespace,caption",
            "netstat -an | find /C \"ESTABLISHED\""
        ]
        
        for cmd in report_commands:
            self.run_command(cmd)
    
    def scan_suspicious_processes(self):
        """Escaneia processos suspeitos"""
        suspicious_keywords = ['crypt', 'miner', 'bitcoin', 'monero', 'backdoor', 'keylogger']
        self.output_text.insert(tk.END, "\n>>> Escaneando processos suspeitos...\n")
        
        try:
            processes = subprocess.check_output("tasklist", shell=True, text=True)
            found = False
            
            for keyword in suspicious_keywords:
                if keyword in processes.lower():
                    self.output_text.insert(tk.END, f"ALERTA: Possível processo suspeito encontrado - {keyword}\n")
                    found = True
            
            if not found:
                self.output_text.insert(tk.END, "✓ Nenhum processo suspeito encontrado\n")
                
        except Exception as e:
            self.output_text.insert(tk.END, f"Erro no scan: {str(e)}\n")
    
    def run_security_audit(self):
        """Executa auditoria de segurança básica"""
        audit_commands = [
            "netsh advfirewall show allprofiles",
            "net accounts",
            "whoami /priv",
            "net localgroup administrators"
        ]
        
        for cmd in audit_commands:
            self.run_command(cmd)
    
    def analyze_disk_space(self):
        """Analisa uso de espaço em disco"""
        self.run_command("wmic logicaldisk get size,freespace,caption,drivetype")
        self.run_command("for %i in (C D E F) do @if exist %i:\\ (@echo Drive %i: & dir %i:\\ /a/s | find \"File(s)\"))")
    
    def run_speed_test(self):
        """Teste de velocidade de rede simplificado"""
        self.output_text.insert(tk.END, "\n>>> Testando velocidade de rede...\n")
        import time
        start_time = time.time()
        
        try:
            result = subprocess.run("ping 8.8.8.8 -n 4", shell=True, capture_output=True, text=True)
            end_time = time.time()
            
            if "tempo=" in result.stdout:
                times = [float(line.split("tempo=")[1].split("ms")[0]) 
                        for line in result.stdout.split("\n") if "tempo=" in line]
                avg_time = sum(times) / len(times) if times else 0
                
                self.output_text.insert(tk.END, f"Latência média: {avg_time:.2f} ms\n")
                self.output_text.insert(tk.END, f"Tempo total: {end_time - start_time:.2f} segundos\n")
            else:
                self.output_text.insert(tk.END, "Não foi possível medir a latência\n")
                
        except Exception as e:
            self.output_text.insert(tk.END, f"Erro no teste: {str(e)}\n")
    
    def backup_system_config(self):
        """Backup de configurações do sistema"""
        backup_dir = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.run_command(f"mkdir {backup_dir}")
        
        backup_commands = [
            f"ipconfig /all > {backup_dir}\\network_config.txt",
            f"systeminfo > {backup_dir}\\system_info.txt",
            f"tasklist > {backup_dir}\\process_list.txt",
            f"netstat -an > {backup_dir}\\network_connections.txt"
        ]
        
        for cmd in backup_commands:
            self.run_command(cmd)
        
        self.output_text.insert(tk.END, f"\n✓ Backup salvo em: {backup_dir}\n")
    
    def optimize_system(self):
        """Otimizações básicas do sistema"""
        optimize_commands = [
            "ipconfig /flushdns",
            "ipconfig /release && ipconfig /renew",
            "netsh winsock reset catalog",
            "netsh int ip reset reset.log"
        ]
        
        for cmd in optimize_commands:
            self.run_command(cmd)
    
    def system_cleanup(self):
        """Limpeza do sistema"""
        cleanup_commands = [
            "cleanmgr /sagerun:1",
            "ipconfig /flushdns",
            "del /q /f /s %temp%\\*.*",
            "del /q /f /s C:\\Windows\\Temp\\*.*"
        ]
        
        for cmd in cleanup_commands:
            self.run_command(cmd)
    
    def generate_daily_report(self):
        """Gera relatório diário"""
        report_commands = [
            "echo ===== RELATÓRIO DIÁRIO =====",
            f"echo Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "systeminfo | findstr /B /C:\"Host Name\" /C:\"OS Name\" /C:\"OS Version\"",
            "wmic logicaldisk get caption,size,freespace | findstr /V \"Caption\"",
            "netstat -an | find /C \"ESTABLISHED\""
        ]
        
        for cmd in report_commands:
            self.run_command(cmd)
    
    def start_live_monitor(self):
        """Inicia monitoramento em tempo real"""
        def monitor_thread():
            while hasattr(self, 'monitoring') and self.monitoring:
                try:
                    cpu = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory().percent
                    disk = psutil.disk_usage('/').percent
                    
                    self.output_text.insert(tk.END, 
                        f"\rCPU: {cpu:5.1f}% | Memória: {memory:5.1f}% | Disco: {disk:5.1f}% | {datetime.now().strftime('%H:%M:%S')}")
                    self.root.update()
                    
                except Exception as e:
                    self.output_text.insert(tk.END, f"\nErro no monitor: {str(e)}\n")
                    break
        
        self.monitoring = True
        self.output_text.insert(tk.END, "\n>>> Iniciando monitoramento em tempo real (Pressione Clear para parar)...\n")
        threading.Thread(target=monitor_thread, daemon=True).start()
    
    def start_network_monitor(self):
        """Monitoramento de rede"""
        self.run_command("netstat -e 1")
    
    def start_process_monitor(self):
        """Monitoramento de processos"""
        self.run_command("tasklist | sort")
    
    def show_performance_dashboard(self):
        """Mostra dashboard de performance"""
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            dashboard = f"""
📊 DASHBOARD DE PERFORMANCE
==============================
CPU Usage: {cpu}%
Memory: {memory.percent}% ({memory.used//1024//1024}MB / {memory.total//1024//1024}MB)
Disk: {disk.percent}% ({disk.used//1024//1024}MB / {disk.total//1024//1024}MB)
Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%d/%m/%Y %H:%M:%S')}
            """
            
            self.output_text.insert(tk.END, dashboard)
            
        except Exception as e:
            self.output_text.insert(tk.END, f"Erro no dashboard: {str(e)}\n")
    
    # ========== MÉTODOS UTILITÁRIOS ==========
    
    def add_custom_tool(self):
        """Adiciona ferramenta personalizada"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Adicionar Ferramenta Personalizada")
        dialog.geometry("400x300")
        dialog.configure(bg='#2b2b2b')
        
        ttk.Label(dialog, text="Nome da Ferramenta:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=40)
        name_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Comando:").pack(pady=5)
        command_text = scrolledtext.ScrolledText(dialog, height=8, width=50)
        command_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        def save_tool():
            name = name_entry.get()
            command = command_text.get("1.0", tk.END).strip()
            
            if name and command:
                # Criar botão dinamicamente na primeira seção
                network_section = self.scrollable_frame.winfo_children()[1]
                tools_frame = network_section.winfo_children()[0]
                
                # Encontrar último frame de linha
                last_row = tools_frame.winfo_children()[-1] if tools_frame.winfo_children() else None
                
                # Se a última linha está cheia (4 botões), criar nova linha
                if last_row and len(last_row.winfo_children()) >= 4:
                    last_row = ttk.Frame(tools_frame)
                    last_row.pack(fill=tk.X, pady=2)
                
                if not last_row:
                    last_row = ttk.Frame(tools_frame)
                    last_row.pack(fill=tk.X, pady=2)
                
                ttk.Button(last_row, text=name, 
                          command=lambda cmd=command: self.run_command(cmd)).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
                
                messagebox.showinfo("Sucesso", f"Ferramenta '{name}' adicionada!")
                dialog.destroy()
            else:
                messagebox.showwarning("Aviso", "Preencha nome e comando!")
        
        ttk.Button(dialog, text="Salvar", command=save_tool).pack(pady=10)
    
    def clear_output(self):
        """Limpa a área de output"""
        self.monitoring = False
        self.output_text.delete(1.0, tk.END)
    
    def save_log(self):
        """Salva o log em arquivo"""
        try:
            filename = f"swallow_toolbox_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.output_text.get(1.0, tk.END))
            
            messagebox.showinfo("Sucesso", f"Log salvo como: {filename}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar log: {str(e)}")

def main():
    try:
        import psutil
    except ImportError:
        print("Instalando psutil...")
        subprocess.call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
    
    root = tk.Tk()
    app = SwallowToolBox(root)
    root.mainloop()

if __name__ == "__main__":
    main()