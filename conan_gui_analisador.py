#!/usr/bin/env python3
"""
Conan Exiles - Analisador de Rota com GUI
Windows | Tkinter | Python 3.8+
"""
import socket
import statistics
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import scrolledtext, ttk
import sys
import os

PAYLOAD = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'

# ─────────────────────────────────────────────────────────────────────────────
# LOGICA DE REDE
# ─────────────────────────────────────────────────────────────────────────────

def get_local_ip():
    """Descobre o IP local da maquina na LAN (DHCP ou estatico)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Nao detectado"

def run_cmd(cmd, timeout=30):
    """Executa um comando de sistema e retorna a saida como texto."""
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = res.stdout.strip()
        err = res.stderr.strip()
        return out or err or "Sem retorno."
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Demorou mais de {timeout}s."
    except Exception as e:
        return f"[ERRO] {str(e)}"

def phase_icmp(ip, log):
    log("[Fase 1] ICMP Ping...")
    cmd = f"ping -n 10 {ip}" if sys.platform == "win32" else f"ping -c 10 {ip}"
    result = run_cmd(cmd, timeout=20)
    log(result)
    return result

def phase_traceroute(ip, log):
    log("\n[Fase 2] Traceroute...")
    cmd = f"tracert -h 20 -w 1000 {ip}" if sys.platform == "win32" else f"traceroute -n -w 2 -q 2 -m 20 {ip}"
    result = run_cmd(cmd, timeout=40)
    log(result)
    return result

def phase_netcat(ip, base_port, log):
    log("\n[Fase 3] Descoberta UDP de Portas...")
    ports = [base_port, base_port + 1, base_port + 15, 27015]
    result_lines = []
    for p in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        try:
            start = time.time()
            sock.sendto(PAYLOAD, (ip, p))
            data, _ = sock.recvfrom(4096)
            rtt = (time.time() - start) * 1000
            msg = f"[OK] Porta {p:<5} respondeu em {rtt:>6.1f}ms -> {len(data)} bytes"
        except socket.timeout:
            msg = f"[--] Porta {p:<5} TIMEOUT"
        except Exception as e:
            msg = f"[ER] Porta {p:<5} {str(e)}"
        finally:
            sock.close()
        log(msg)
        result_lines.append(msg)
    return "\n".join(result_lines)

def discover_udp(ip, base_port):
    ports = [base_port, base_port + 1, base_port + 15, 27015]
    responding = []
    for p in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        try:
            sock.sendto(PAYLOAD, (ip, p))
            sock.recvfrom(4096)
            responding.append(p)
        except:
            pass
        finally:
            sock.close()
    return responding

def phase_jitter(ip, port, count, log):
    log(f"\n[Fase 4] Stress Test (Loss/Jitter) -> Porta {port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    latencies = []
    lost = 0

    for i in range(count):
        start = time.time()
        try:
            sock.sendto(PAYLOAD, (ip, port))
            sock.recvfrom(4096)
            latencies.append((time.time() - start) * 1000)
        except socket.timeout:
            lost += 1
        time.sleep(0.1)

        if (i + 1) % 20 == 0:
            log(f"   Progresso: {i+1}/{count} pacotes...")

    sock.close()

    if not latencies:
        result = "100% LOSS - Nenhuma resposta."
        log(result)
        return result, "CRITICO"

    loss_pct = (lost / count) * 100
    min_rtt = min(latencies)
    avg_rtt = statistics.mean(latencies)
    max_rtt = max(latencies)
    jitter_list = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
    avg_jitter = statistics.mean(jitter_list) if jitter_list else 0.0

    if loss_pct >= 2.0:
        diag = "RUIM - Packet Loss detectado!"
        color = "RUIM"
    elif avg_jitter >= 25.0:
        diag = "RUIM - Jitter alto (stuttering/teleporte no jogo)"
        color = "RUIM"
    elif avg_jitter >= 15.0:
        diag = "ATENCAO - Jitter moderado"
        color = "ATENCAO"
    else:
        diag = "BOM - Conexao estavel"
        color = "BOM"

    result = (
        f"\nPacotes Enviados  : {count}\n"
        f"Pacotes Perdidos  : {lost} ({loss_pct:.1f}%)\n"
        f"Latencia Minima   : {min_rtt:.1f} ms\n"
        f"Latencia Media    : {avg_rtt:.1f} ms\n"
        f"Latencia Maxima   : {max_rtt:.1f} ms\n"
        f"Jitter Medio      : {avg_jitter:.1f} ms\n"
        f"\nDIAGNOSTICO: {diag}"
    )
    log(result)
    return result, color


# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE GRAFICA
# ─────────────────────────────────────────────────────────────────────────────

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Conan Exiles - Analisador de Rota")
        self.root.resizable(True, True)
        self.running = False
        self._build_ui()
        self._detect_ip()

    def _build_ui(self):
        # ── Painel Superior: Inputs ──────────────────────────────────────────
        frame_top = tk.LabelFrame(self.root, text="Configuracao do Teste", padx=10, pady=8)
        frame_top.pack(fill="x", padx=10, pady=(10, 0))

        # IP Local (DHCP)
        tk.Label(frame_top, text="Seu IP Local (DHCP):").grid(row=0, column=0, sticky="w")
        self.var_local_ip = tk.StringVar(value="Detectando...")
        entry_local = tk.Entry(frame_top, textvariable=self.var_local_ip, width=20, state="readonly", relief="sunken")
        entry_local.grid(row=0, column=1, sticky="w", padx=(5, 20))

        tk.Label(frame_top, text="(use este IP para criar a regra no Omada)", fg="gray").grid(row=0, column=2, columnspan=3, sticky="w")

        # IP do Servidor
        tk.Label(frame_top, text="IP do Servidor do Jogo:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.var_server_ip = tk.StringVar(value="84.75.219.218")
        tk.Entry(frame_top, textvariable=self.var_server_ip, width=20).grid(row=1, column=1, sticky="w", padx=(5, 20), pady=(6, 0))

        # Porta
        tk.Label(frame_top, text="Porta (Game Port):").grid(row=1, column=2, sticky="w", pady=(6, 0))
        self.var_port = tk.StringVar(value="7700")
        tk.Entry(frame_top, textvariable=self.var_port, width=10).grid(row=1, column=3, sticky="w", padx=(5, 20), pady=(6, 0))

        # Label (TIM / VIVO)
        tk.Label(frame_top, text="Label (ex: TIM ou VIVO):").grid(row=1, column=4, sticky="w", pady=(6, 0))
        self.var_label = tk.StringVar(value="TIM")
        tk.Entry(frame_top, textvariable=self.var_label, width=10).grid(row=1, column=5, sticky="w", padx=(5, 0), pady=(6, 0))

        # Botoes
        frame_btn = tk.Frame(self.root)
        frame_btn.pack(fill="x", padx=10, pady=8)

        self.btn_run = tk.Button(frame_btn, text="▶  INICIAR TESTE", command=self._start_test,
                                 bg="#1e7e34", fg="white", font=("Consolas", 10, "bold"), width=20)
        self.btn_run.pack(side="left", padx=(0, 10))

        self.btn_clear = tk.Button(frame_btn, text="Limpar", command=self._clear, width=10)
        self.btn_clear.pack(side="left")

        # Status / Diagnostico
        self.lbl_status = tk.Label(frame_btn, text="Aguardando...", fg="gray", font=("Consolas", 10, "bold"))
        self.lbl_status.pack(side="right", padx=10)

        # ── Progress Bar ─────────────────────────────────────────────────────
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=(0, 4))

        # ── Log / Output ──────────────────────────────────────────────────────
        frame_log = tk.LabelFrame(self.root, text="Output do Teste", padx=5, pady=5)
        frame_log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.txt_log = scrolledtext.ScrolledText(frame_log, font=("Consolas", 9), wrap="word",
                                                 bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.txt_log.pack(fill="both", expand=True)

        self.txt_log.tag_config("BOM", foreground="#6daa45")
        self.txt_log.tag_config("RUIM", foreground="#dd6974")
        self.txt_log.tag_config("ATENCAO", foreground="#fdab43")
        self.txt_log.tag_config("INFO", foreground="#4f98a3")
        self.txt_log.tag_config("HEADER", foreground="#e8af34", font=("Consolas", 9, "bold"))

    def _detect_ip(self):
        ip = get_local_ip()
        self.var_local_ip.set(ip)

    def _log(self, msg, tag=None):
        self.txt_log.configure(state="normal")
        if tag:
            self.txt_log.insert("end", msg + "\n", tag)
        else:
            self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _clear(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.lbl_status.config(text="Aguardando...", fg="gray")

    def _start_test(self):
        if self.running:
            return
        ip = self.var_server_ip.get().strip()
        port_str = self.var_port.get().strip()
        label = self.var_label.get().strip().upper() or "TESTE"

        if not ip or not port_str:
            self._log("[ERRO] Preencha o IP e a Porta antes de iniciar.", "RUIM")
            return
        try:
            port = int(port_str)
        except ValueError:
            self._log("[ERRO] Porta invalida. Use apenas numeros.", "RUIM")
            return

        self.running = True
        self.btn_run.config(state="disabled")
        self.progress.start(10)
        threading.Thread(target=self._run_test, args=(ip, port, label), daemon=True).start()

    def _run_test(self, ip, port, label):
        report = []
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        def log(msg, tag=None):
            self.root.after(0, self._log, msg, tag)
            report.append(msg)

        log("=" * 55, "HEADER")
        log(f"  RELATORIO BRUTAL CONAN EXILES", "HEADER")
        log(f"  Operadora : {label}  |  Alvo: {ip}:{port}", "HEADER")
        log(f"  Data/Hora : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "HEADER")
        log("=" * 55, "HEADER")

        # Fase 1
        log("\n--- FASE 1: ICMP PING ---", "INFO")
        phase_icmp(ip, log)

        # Fase 2
        log("\n--- FASE 2: TRACEROUTE ---", "INFO")
        phase_traceroute(ip, log)

        # Fase 3
        log("\n--- FASE 3: DESCOBERTA UDP ---", "INFO")
        phase_netcat(ip, port, log)

        # Fase 4
        log("\n--- FASE 4: STRESS TEST ---", "INFO")
        active = discover_udp(ip, port)
        if active:
            test_port = active[0]
            log(f"Porta utilizada: {test_port}", "INFO")
            result_text, color = phase_jitter(ip, test_port, 100, log)

            diag_colors = {"BOM": "green", "RUIM": "red", "ATENCAO": "orange", "CRITICO": "red"}
            self.root.after(0, lambda: self.lbl_status.config(
                text=f"Resultado: {color}",
                fg=diag_colors.get(color, "gray")
            ))
        else:
            log("FALHA: Nenhuma porta respondeu.", "RUIM")
            color = "CRITICO"
            self.root.after(0, lambda: self.lbl_status.config(text="Resultado: FALHA", fg="red"))

        # Salva relatorio
        outdir = Path.home() / "Documents" / "ConanRotas"
        outdir.mkdir(parents=True, exist_ok=True)
        filename = outdir / f"relatorio_{label}_{ip}_{ts}.txt"
        filename.write_text("\n".join(report), encoding="utf-8")
        log(f"\nRelatorio salvo em: {filename}", "INFO")
        log("=" * 55, "HEADER")

        # Finaliza
        self.root.after(0, self.progress.stop)
        self.root.after(0, lambda: self.btn_run.config(state="normal"))
        self.running = False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("900x620")
    app = App(root)
    root.mainloop()
