#!/usr/bin/env python3
"""
Conan Exiles - Analisador de Rota v2
Melhorias: Grafico em tempo real, Historico de Jitter, Comparativo TIM vs VIVO,
           Botao Copiar IP, Lista de Servidores salvos, Notificacao Windows
Windows | Tkinter + Canvas | Python 3.8+
"""
import json
import socket
import statistics
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, simpledialog, ttk

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

PAYLOAD = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'
SERVERS_FILE = Path.home() / "Documents" / "ConanRotas" / "servers.json"
HISTORY_FILE = Path.home() / "Documents" / "ConanRotas" / "history.json"

# Thresholds de Jitter
JITTER_BOM      = 15.0
JITTER_ATENCAO  = 25.0

# Paleta
BG         = "#1e1e1e"
BG2        = "#252526"
BG3        = "#2d2d30"
FG         = "#d4d4d4"
FG2        = "#9cdcfe"
GREEN      = "#6daa45"
RED        = "#dd6974"
ORANGE     = "#fdab43"
YELLOW     = "#e8af34"
CYAN       = "#4f98a3"
BORDER     = "#3c3c3c"

# ─────────────────────────────────────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────────────────────────────────────

def ensure_dirs():
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Nao detectado"

def run_cmd(cmd, timeout=40):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (res.stdout or res.stderr or "Sem retorno.").strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except Exception as e:
        return f"[ERRO] {e}"

def notify_windows(title, msg):
    try:
        from ctypes import windll, wintypes, byref
    except ImportError:
        pass
    # Usa powershell como fallback nativo
    ps = (
        f"Add-Type -AssemblyName System.Windows.Forms;"
        f"$notify = New-Object System.Windows.Forms.NotifyIcon;"
        f"$notify.Icon = [System.Drawing.SystemIcons]::Information;"
        f"$notify.Visible = $true;"
        f"$notify.ShowBalloonTip(4000, '{title}', '{msg}', "
        f"[System.Windows.Forms.ToolTipIcon]::Info)"
    )
    subprocess.Popen(["powershell", "-Command", ps],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def jitter_color(val):
    if val is None:
        return FG
    if val < JITTER_BOM:
        return GREEN
    if val < JITTER_ATENCAO:
        return ORANGE
    return RED

def load_servers():
    ensure_dirs()
    if SERVERS_FILE.exists():
        try:
            return json.loads(SERVERS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return [{"name": "Furia de Derketo", "ip": "84.75.219.218", "port": 7700}]

def save_servers(data):
    ensure_dirs()
    SERVERS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

def load_history():
    ensure_dirs()
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []

def save_history(data):
    ensure_dirs()
    HISTORY_FILE.write_text(json.dumps(data[-50:], indent=2), encoding="utf-8")

# ─────────────────────────────────────────────────────────────────────────────
# FASES DE TESTE
# ─────────────────────────────────────────────────────────────────────────────

def phase_icmp(ip, log):
    log("[Fase 1] ICMP Ping...", CYAN)
    cmd = f"ping -n 10 {ip}" if sys.platform == "win32" else f"ping -c 10 {ip}"
    return run_cmd(cmd, timeout=20)

def phase_traceroute(ip, log):
    log("[Fase 2] Traceroute...", CYAN)
    cmd = f"tracert -h 20 -w 1000 {ip}" if sys.platform == "win32" else f"traceroute -n -w 2 -q 2 -m 20 {ip}"
    return run_cmd(cmd, timeout=45)

def phase_discover(ip, base_port, log):
    log("[Fase 3] Descoberta de Portas UDP...", CYAN)
    ports = [base_port, base_port + 1, base_port + 15, 27015]
    responding = []
    lines = []
    for p in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        try:
            t0 = time.time()
            sock.sendto(PAYLOAD, (ip, p))
            data, _ = sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            msg = f"[OK] Porta {p:<5} respondeu em {rtt:>6.1f}ms -> {len(data)} bytes"
            responding.append(p)
            log(msg, GREEN)
        except socket.timeout:
            msg = f"[--] Porta {p:<5} TIMEOUT"
            log(msg)
        except Exception as e:
            msg = f"[ER] Porta {p:<5} {e}"
            log(msg, RED)
        finally:
            sock.close()
        lines.append(msg)
    return responding, "\n".join(lines)

def phase_jitter(ip, port, count, log, on_packet=None, stop_event=None):
    log(f"[Fase 4] Stress Test na Porta {port} ({count} pacotes)...", CYAN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    latencies = []
    lost = 0

    for i in range(count):
        if stop_event and stop_event.is_set():
            break
        t0 = time.time()
        try:
            sock.sendto(PAYLOAD, (ip, port))
            sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            latencies.append(rtt)
            if on_packet:
                jitter_now = abs(latencies[-1] - latencies[-2]) if len(latencies) >= 2 else 0.0
                on_packet(i + 1, rtt, jitter_now, lost)
        except socket.timeout:
            lost += 1
            if on_packet:
                on_packet(i + 1, None, None, lost)
        time.sleep(0.1)

    sock.close()

    if not latencies:
        return None, "100% LOSS - Sem resposta.", "CRITICO"

    loss_pct  = (lost / count) * 100
    min_rtt   = min(latencies)
    avg_rtt   = statistics.mean(latencies)
    max_rtt   = max(latencies)
    jitter_l  = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
    avg_jitter= statistics.mean(jitter_l) if jitter_l else 0.0

    if loss_pct >= 2.0:
        diag = "RUIM - Packet Loss detectado!"; color = "RUIM"
    elif avg_jitter >= JITTER_ATENCAO:
        diag = "RUIM - Jitter alto (stuttering/teleporte)"; color = "RUIM"
    elif avg_jitter >= JITTER_BOM:
        diag = "ATENCAO - Jitter moderado"; color = "ATENCAO"
    else:
        diag = "BOM - Conexao estavel"; color = "BOM"

    stats = {
        "sent": count, "lost": lost, "loss_pct": loss_pct,
        "min": min_rtt, "avg": avg_rtt, "max": max_rtt, "jitter": avg_jitter,
        "diag": diag, "color": color
    }
    text = (
        f"Pacotes Enviados : {count}\n"
        f"Pacotes Perdidos : {lost} ({loss_pct:.1f}%)\n"
        f"Latencia Minima  : {min_rtt:.1f} ms\n"
        f"Latencia Media   : {avg_rtt:.1f} ms\n"
        f"Latencia Maxima  : {max_rtt:.1f} ms\n"
        f"Jitter Medio     : {avg_jitter:.1f} ms\n"
        f"\nDIAGNOSTICO: {diag}"
    )
    return stats, text, color

# ─────────────────────────────────────────────────────────────────────────────
# GRAFICO DE JITTER EM TEMPO REAL
# ─────────────────────────────────────────────────────────────────────────────

class JitterChart(tk.Canvas):
    MAX_POINTS = 100

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG3, highlightthickness=0, **kw)
        self.data_rtt    = []
        self.data_jitter = []
        self.bind("<Configure>", lambda e: self._redraw())

    def reset(self):
        self.data_rtt.clear()
        self.data_jitter.clear()
        self._redraw()

    def add_point(self, rtt, jitter):
        if rtt is None:
            rtt = 0
        if jitter is None:
            jitter = 0
        self.data_rtt.append(rtt)
        self.data_jitter.append(jitter)
        if len(self.data_rtt) > self.MAX_POINTS:
            self.data_rtt.pop(0)
            self.data_jitter.pop(0)
        self._redraw()

    def _redraw(self):
        self.delete("all")
        W = self.winfo_width()
        H = self.winfo_height()
        if W < 10 or H < 10:
            return

        pad = 30
        inner_w = W - pad * 2
        inner_h = H - pad * 2

        # Grade
        for i in range(5):
            y = pad + inner_h * i // 4
            self.create_line(pad, y, W - pad, y, fill=BORDER, dash=(2, 4))

        all_vals = self.data_rtt + self.data_jitter
        if not all_vals:
            self.create_text(W // 2, H // 2, text="Aguardando pacotes...", fill=FG2)
            return

        max_val = max(max(all_vals), 10)

        def to_xy(idx, val):
            n = max(len(self.data_rtt), 1)
            x = pad + idx * inner_w / max(n - 1, 1)
            y = pad + inner_h - (val / max_val) * inner_h
            return x, y

        # Linha RTT (azul)
        if len(self.data_rtt) >= 2:
            pts = [to_xy(i, v) for i, v in enumerate(self.data_rtt)]
            flat = [c for p in pts for c in p]
            self.create_line(*flat, fill=CYAN, width=1, smooth=True)

        # Linha Jitter (laranja)
        if len(self.data_jitter) >= 2:
            pts = [to_xy(i, v) for i, v in enumerate(self.data_jitter)]
            flat = [c for p in pts for c in p]
            self.create_line(*flat, fill=ORANGE, width=1, smooth=True)

        # Labels
        self.create_text(pad + 2, pad - 10, text=f"{max_val:.0f}ms", fill=FG2, anchor="w", font=("Consolas", 7))
        self.create_text(W - 5, H - 5, text="Pkt", fill=FG2, anchor="se", font=("Consolas", 7))
        self.create_text(pad + 10, H - 10, text="— RTT", fill=CYAN, anchor="sw", font=("Consolas", 7))
        self.create_text(pad + 60, H - 10, text="— Jitter", fill=ORANGE, anchor="sw", font=("Consolas", 7))

        # Ultimo valor
        if self.data_rtt:
            self.create_text(W - pad, pad, text=f"RTT {self.data_rtt[-1]:.0f}ms  Jitter {self.data_jitter[-1]:.0f}ms",
                             fill=FG, anchor="ne", font=("Consolas", 8))


# ─────────────────────────────────────────────────────────────────────────────
# JANELA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Conan Exiles - Analisador de Rota v2")
        self.root.configure(bg=BG)
        self.root.geometry("1050x760")
        self.running = False
        self.stop_event = threading.Event()
        self.servers = load_servers()
        self.history = load_history()
        self._build_ui()
        self._detect_ip()
        self._refresh_server_list()
        self._refresh_history()

    # ── Construcao da UI ─────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        # ─ Top Bar ─
        top = tk.Frame(self.root, bg=BG2, pady=8)
        top.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        top.columnconfigure(5, weight=1)

        tk.Label(top, text="IP Local:", bg=BG2, fg=FG2, font=("Consolas", 9)).grid(row=0, column=0, padx=(12, 4))
        self.var_local_ip = tk.StringVar(value="...")
        tk.Entry(top, textvariable=self.var_local_ip, width=16, state="readonly",
                 bg=BG3, fg=GREEN, relief="flat", font=("Consolas", 9)).grid(row=0, column=1, padx=(0, 2))
        tk.Button(top, text="Copiar", bg=BG3, fg=FG, relief="flat",
                  font=("Consolas", 8), command=self._copy_ip).grid(row=0, column=2, padx=(0, 20))

        tk.Label(top, text="IP Servidor:", bg=BG2, fg=FG2, font=("Consolas", 9)).grid(row=0, column=3, padx=(0, 4))
        self.var_server_ip = tk.StringVar(value="84.75.219.218")
        tk.Entry(top, textvariable=self.var_server_ip, width=16,
                 bg=BG3, fg=FG, relief="flat", font=("Consolas", 9)).grid(row=0, column=4, padx=(0, 8))

        tk.Label(top, text="Porta:", bg=BG2, fg=FG2, font=("Consolas", 9)).grid(row=0, column=5, sticky="e", padx=(0, 4))
        self.var_port = tk.StringVar(value="7700")
        tk.Entry(top, textvariable=self.var_port, width=7,
                 bg=BG3, fg=FG, relief="flat", font=("Consolas", 9)).grid(row=0, column=6, padx=(0, 8))

        tk.Label(top, text="Label:", bg=BG2, fg=FG2, font=("Consolas", 9)).grid(row=0, column=7, padx=(0, 4))
        self.var_label = tk.StringVar(value="TIM")
        tk.Entry(top, textvariable=self.var_label, width=7,
                 bg=BG3, fg=FG, relief="flat", font=("Consolas", 9)).grid(row=0, column=8, padx=(0, 8))

        self.btn_run = tk.Button(top, text="▶  INICIAR", command=self._start_test,
                                 bg=GREEN, fg="white", font=("Consolas", 9, "bold"),
                                 relief="flat", padx=12)
        self.btn_run.grid(row=0, column=9, padx=(0, 6))

        self.btn_stop = tk.Button(top, text="■  PARAR", command=self._stop_test,
                                  bg=RED, fg="white", font=("Consolas", 9, "bold"),
                                  relief="flat", padx=10, state="disabled")
        self.btn_stop.grid(row=0, column=10, padx=(0, 12))

        # ─ Progress ─
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
        self.root.rowconfigure(1, weight=0)

        # ─ Notebook principal ─
        nb = ttk.Notebook(self.root)
        nb.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        self.root.rowconfigure(2, weight=1)

        # Tab 1: Teste + Grafico
        tab_test = tk.Frame(nb, bg=BG)
        nb.add(tab_test, text="  Teste em Tempo Real  ")
        tab_test.rowconfigure(0, weight=3)
        tab_test.rowconfigure(1, weight=2)
        tab_test.columnconfigure(0, weight=1)

        self.txt_log = scrolledtext.ScrolledText(
            tab_test, font=("Consolas", 8), wrap="word",
            bg=BG, fg=FG, insertbackground=FG, relief="flat"
        )
        self.txt_log.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        for tag, color in [("GREEN", GREEN), ("RED", RED), ("ORANGE", ORANGE),
                           ("CYAN", CYAN), ("YELLOW", YELLOW), ("FG2", FG2)]:
            self.txt_log.tag_config(tag, foreground=color)
        self.txt_log.tag_config("BOLD", font=("Consolas", 8, "bold"))

        self.chart = JitterChart(tab_test, height=180)
        self.chart.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

        # Tab 2: Historico
        tab_hist = tk.Frame(nb, bg=BG)
        nb.add(tab_hist, text="  Historico de Jitter  ")
        tab_hist.columnconfigure(0, weight=1)
        tab_hist.rowconfigure(0, weight=1)

        cols = ("Data/Hora", "Label", "Servidor", "Jitter Medio", "Pico Max", "Loss%", "Diagnostico")
        self.tree_hist = ttk.Treeview(tab_hist, columns=cols, show="headings", height=20)
        for c in cols:
            self.tree_hist.heading(c, text=c)
            self.tree_hist.column(c, width=130, anchor="center")
        self.tree_hist.column("Diagnostico", width=260)
        scrolly = ttk.Scrollbar(tab_hist, orient="vertical", command=self.tree_hist.yview)
        self.tree_hist.configure(yscrollcommand=scrolly.set)
        self.tree_hist.grid(row=0, column=0, sticky="nsew")
        scrolly.grid(row=0, column=1, sticky="ns")

        btn_frame = tk.Frame(tab_hist, bg=BG)
        btn_frame.grid(row=1, column=0, sticky="ew", pady=4)
        tk.Button(btn_frame, text="Limpar Historico", bg=BG3, fg=RED, relief="flat",
                  font=("Consolas", 8), command=self._clear_history).pack(side="left", padx=8)

        # Tab 3: Servidores
        tab_srv = tk.Frame(nb, bg=BG)
        nb.add(tab_srv, text="  Servidores Salvos  ")
        tab_srv.columnconfigure(0, weight=1)
        tab_srv.rowconfigure(0, weight=1)

        cols_s = ("Nome", "IP", "Porta")
        self.tree_srv = ttk.Treeview(tab_srv, columns=cols_s, show="headings", height=15)
        for c in cols_s:
            self.tree_srv.heading(c, text=c)
        self.tree_srv.column("Nome", width=250)
        self.tree_srv.column("IP",   width=160, anchor="center")
        self.tree_srv.column("Porta",width=80,  anchor="center")
        self.tree_srv.bind("<Double-1>", self._load_server)
        self.tree_srv.grid(row=0, column=0, sticky="nsew")

        btn_srv = tk.Frame(tab_srv, bg=BG)
        btn_srv.grid(row=1, column=0, sticky="ew", pady=4)
        tk.Button(btn_srv, text="+ Adicionar Atual", bg=GREEN, fg="white", relief="flat",
                  font=("Consolas", 8), command=self._add_server).pack(side="left", padx=8)
        tk.Button(btn_srv, text="- Remover", bg=RED, fg="white", relief="flat",
                  font=("Consolas", 8), command=self._remove_server).pack(side="left", padx=4)
        tk.Label(btn_srv, text="Duplo clique para carregar servidor", bg=BG, fg=FG2,
                 font=("Consolas", 8)).pack(side="right", padx=12)

        # ─ Barra de Status ─
        self.lbl_status = tk.Label(self.root, text="Aguardando...",
                                   bg=BG2, fg=FG2, font=("Consolas", 9), anchor="w", padx=10)
        self.lbl_status.grid(row=3, column=0, sticky="ew")
        self.root.rowconfigure(3, weight=0)

    # ── Deteccao de IP ────────────────────────────────────────────────────────

    def _detect_ip(self):
        ip = get_local_ip()
        self.var_local_ip.set(ip)

    def _copy_ip(self):
        ip = self.var_local_ip.get()
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        self.lbl_status.config(text=f"IP {ip} copiado para a area de transferencia!", fg=GREEN)

    # ── Log ───────────────────────────────────────────────────────────────────

    def _log(self, msg, color=None):
        self.txt_log.configure(state="normal")
        tag = None
        if color == GREEN:   tag = "GREEN"
        elif color == RED:   tag = "RED"
        elif color == ORANGE:tag = "ORANGE"
        elif color == CYAN:  tag = "CYAN"
        elif color == YELLOW:tag = "YELLOW"
        elif color == FG2:   tag = "FG2"
        if tag:
            self.txt_log.insert("end", msg + "\n", tag)
        else:
            self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    # ── Teste ─────────────────────────────────────────────────────────────────

    def _start_test(self):
        if self.running:
            return
        ip    = self.var_server_ip.get().strip()
        port  = self.var_port.get().strip()
        label = self.var_label.get().strip().upper() or "TESTE"
        if not ip or not port:
            messagebox.showerror("Erro", "Preencha o IP e a Porta.")
            return
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Erro", "Porta invalida.")
            return

        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.chart.reset()
        self.stop_event.clear()
        self.running = True
        self.btn_run.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.progress.start(10)
        threading.Thread(target=self._run_test, args=(ip, port, label), daemon=True).start()

    def _stop_test(self):
        self.stop_event.set()
        self.lbl_status.config(text="Parando teste...", fg=ORANGE)

    def _run_test(self, ip, port, label):
        ensure_dirs()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        report = []

        def log(msg, color=None):
            self.root.after(0, self._log, msg, color)
            report.append(msg)

        def status(msg, color=FG2):
            self.root.after(0, self.lbl_status.config, {"text": msg, "fg": color})

        log("=" * 60, YELLOW)
        log(f"  ANALISADOR CONAN EXILES v2  |  {label}  |  {ip}:{port}", YELLOW)
        log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", YELLOW)
        log("=" * 60, YELLOW)

        status("Fase 1: ICMP Ping...", CYAN)
        r1 = phase_icmp(ip, log)
        log(r1)

        if self.stop_event.is_set():
            self._finish_test(report, ts, ip, port, label, None)
            return

        status("Fase 2: Traceroute...", CYAN)
        r2 = phase_traceroute(ip, log)
        log(r2)

        if self.stop_event.is_set():
            self._finish_test(report, ts, ip, port, label, None)
            return

        status("Fase 3: Descoberta de Portas...", CYAN)
        active_ports, r3 = phase_discover(ip, port, log)

        status("Fase 4: Stress Test (100 pacotes)...", CYAN)
        log("\n[Fase 4] Stress Test de Jitter...", CYAN)

        if not active_ports:
            log("FALHA: Nenhuma porta respondeu.", RED)
            self._finish_test(report, ts, ip, port, label, None)
            return

        test_port = active_ports[0]

        def on_packet(seq, rtt, jitter, lost):
            self.root.after(0, self.chart.add_point, rtt if rtt else 0, jitter if jitter else 0)

        stats, text, color = phase_jitter(ip, test_port, 100, log,
                                          on_packet=on_packet,
                                          stop_event=self.stop_event)
        log(text)
        self._finish_test(report, ts, ip, port, label, stats)

    def _finish_test(self, report, ts, ip, port, label, stats):
        ensure_dirs()
        outdir  = Path.home() / "Documents" / "ConanRotas"
        outpath = outdir / f"relatorio_{label}_{ip}_{ts}.txt"
        outpath.write_text("\n".join(report), encoding="utf-8")

        color_map = {"BOM": GREEN, "ATENCAO": ORANGE, "RUIM": RED, "CRITICO": RED}
        if stats:
            c = color_map.get(stats["color"], FG2)
            diag = stats["diag"]
            jitter_val = stats["jitter"]

            # Historico
            entry = {
                "ts": ts, "label": label, "ip": ip, "port": port,
                "jitter": round(jitter_val, 1), "max": round(stats["max"], 1),
                "loss_pct": round(stats["loss_pct"], 1), "diag": diag
            }
            self.history.append(entry)
            save_history(self.history)
            self.root.after(0, self._refresh_history)
            self.root.after(0, self.lbl_status.config,
                            {"text": f"Concluido: {diag}  |  Relatorio: {outpath.name}", "fg": c})

            # Notificacao Windows
            if stats["color"] in ("RUIM", "CRITICO"):
                notify_windows("Conan - Problema Detectado",
                               f"{label} | Jitter: {jitter_val:.1f}ms | {diag}")
        else:
            self.root.after(0, self.lbl_status.config,
                            {"text": "Teste cancelado ou sem resposta.", "fg": ORANGE})

        def _reset():
            self.progress.stop()
            self.btn_run.config(state="normal")
            self.btn_stop.config(state="disabled")
            self.running = False
        self.root.after(0, _reset)

    # ── Historico ─────────────────────────────────────────────────────────────

    def _refresh_history(self):
        for row in self.tree_hist.get_children():
            self.tree_hist.delete(row)
        color_tag = {"BOM": GREEN, "ATENCAO": ORANGE, "RUIM": RED, "CRITICO": RED}
        for e in reversed(self.history):
            tag = e.get("color") or ("RUIM" if e["jitter"] >= JITTER_ATENCAO else
                                     "ATENCAO" if e["jitter"] >= JITTER_BOM else "BOM")
            dt = e["ts"]
            dt_fmt = f"{dt[0:4]}-{dt[4:6]}-{dt[6:8]} {dt[9:11]}:{dt[11:13]}:{dt[13:15]}"
            values = (dt_fmt, e["label"], e["ip"],
                      f"{e['jitter']} ms", f"{e['max']} ms",
                      f"{e['loss_pct']}%", e["diag"])
            self.tree_hist.insert("", "end", values=values, tags=(tag,))
        for tag_name, col in [("BOM", GREEN), ("ATENCAO", ORANGE), ("RUIM", RED), ("CRITICO", RED)]:
            self.tree_hist.tag_configure(tag_name, foreground=col)

    def _clear_history(self):
        if messagebox.askyesno("Confirmar", "Limpar todo o historico?"):
            self.history.clear()
            save_history(self.history)
            self._refresh_history()

    # ── Servidores ────────────────────────────────────────────────────────────

    def _refresh_server_list(self):
        for row in self.tree_srv.get_children():
            self.tree_srv.delete(row)
        for s in self.servers:
            self.tree_srv.insert("", "end", values=(s["name"], s["ip"], s["port"]))

    def _add_server(self):
        ip   = self.var_server_ip.get().strip()
        port = self.var_port.get().strip()
        if not ip or not port:
            messagebox.showerror("Erro", "Preencha IP e Porta.")
            return
        name = simpledialog.askstring("Nome do Servidor", "Digite um nome para salvar:", initialvalue=ip)
        if not name:
            return
        self.servers.append({"name": name, "ip": ip, "port": int(port)})
        save_servers(self.servers)
        self._refresh_server_list()

    def _remove_server(self):
        sel = self.tree_srv.selection()
        if not sel:
            return
        idx = self.tree_srv.index(sel[0])
        del self.servers[idx]
        save_servers(self.servers)
        self._refresh_server_list()

    def _load_server(self, event=None):
        sel = self.tree_srv.selection()
        if not sel:
            return
        idx = self.tree_srv.index(sel[0])
        s   = self.servers[idx]
        self.var_server_ip.set(s["ip"])
        self.var_port.set(str(s["port"]))
        self.lbl_status.config(text=f"Servidor carregado: {s['name']} ({s['ip']}:{s['port']})", fg=GREEN)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TNotebook",        background=BG2, borderwidth=0)
    style.configure("TNotebook.Tab",    background=BG3, foreground=FG, padding=[10, 4])
    style.map("TNotebook.Tab",          background=[("selected", BG)], foreground=[("selected", YELLOW)])
    style.configure("Treeview",         background=BG2, foreground=FG, fieldbackground=BG2, rowheight=22)
    style.configure("Treeview.Heading", background=BG3, foreground=FG2)
    style.map("Treeview",               background=[("selected", CYAN)], foreground=[("selected", BG)])
    style.configure("TScrollbar",       background=BG3, troughcolor=BG)
    style.configure("Horizontal.TProgressbar", troughcolor=BG3, background=CYAN)
    App(root)
    root.mainloop()
