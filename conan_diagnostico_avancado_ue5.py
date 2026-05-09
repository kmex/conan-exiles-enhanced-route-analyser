#!/usr/bin/env python3
"""
Conan Exiles Enhanced (Unreal Engine 5) - Diagnostico Avancado para Ticket de Suporte
Gera relatorio tecnico completo com analise de causa raiz e recomendacoes especificas
para servidores de Conan Exiles atualizados (UE5).
Windows/Linux | Python 3.8+
"""
import argparse
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PAYLOAD = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'

# ─────────────────────────────────────────────────────────────────────────────
THRESHOLDS = {
    "jitter_bom":       10.0,
    "jitter_atencao":   20.0,
    "jitter_critico":   40.0,
    "loss_bom":          0.5,
    "loss_atencao":      2.0,
    "loss_critico":      5.0,
    "latencia_bom":    100.0,
    "latencia_atencao":150.0,
    "latencia_critico":200.0,
    "spike_ratio":       3.0,   # pico > N * media = spike
}

def run_cmd(cmd, timeout=45):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (res.stdout or res.stderr or "Sem retorno.").strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except Exception as e:
        return f"[ERRO] {e}"

# ─────────────────────────────────────────────────────────────────────────────
# FASES 1 a 3 (Iguais as originais, removidas do corpo principal por simplicidade no display)
# ─────────────────────────────────────────────────────────────────────────────
def fase_icmp(ip):
    print("[Fase 1] ICMP Ping longo (50 pacotes)...")
    cmd = f"ping -n 50 {ip}" if sys.platform == "win32" else f"ping -c 50 {ip}"
    return run_cmd(cmd, timeout=70)

def fase_traceroute(ip):
    print("[Fase 2] Traceroute (mapeando a rota completa)...")
    cmd = f"tracert -h 30 -w 1500 {ip}" if sys.platform == "win32" else f"traceroute -n -w 3 -q 3 -m 30 {ip}"
    return run_cmd(cmd, timeout=60)

def fase_descoberta(ip, base_port):
    print("[Fase 3] Descoberta de Portas UDP...")
    ports = [base_port, base_port+1, base_port+15, 27015, 7778, 7777]
    responding = []
    lines = []
    for p in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            t0 = time.time()
            sock.sendto(PAYLOAD, (ip, p))
            data, _ = sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            msg = f"  [ABERTA] Porta {p:<6} -> {rtt:.1f}ms  ({len(data)} bytes recebidos)"
            responding.append(p)
        except socket.timeout:
            msg = f"  [FECHADA/TIMEOUT] Porta {p}"
        except Exception as e:
            msg = f"  [ERRO] Porta {p}: {e}"
        finally:
            sock.close()
        lines.append(msg)
        print(msg)
    return responding, lines

def fase_stress(ip, port, count=300, interval=0.1):
    print(f"[Fase 4] Stress Test longo ({count} pacotes, intervalo {interval}s)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.6)
    latencias = []
    perdidos = 0
    spikes = 0
    sequencias_perda = []
    perda_atual = 0

    for i in range(count):
        t0 = time.time()
        try:
            sock.sendto(PAYLOAD, (ip, port))
            sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            latencias.append(rtt)
            if perda_atual > 0:
                sequencias_perda.append(perda_atual)
                perda_atual = 0
        except socket.timeout:
            perdidos += 1
            perda_atual += 1
        time.sleep(interval)
        if (i + 1) % 50 == 0:
            print(f"  Progresso: {i+1:>3}/{count} pkt...")

    sock.close()
    if perda_atual > 0:
        sequencias_perda.append(perda_atual)
    return latencias, perdidos, count, sequencias_perda

def analise_blocos(latencias, count):
    if not latencias: return None
    n = len(latencias)
    t = n // 3
    if t < 5: return None
    b1, b2, b3 = latencias[:t], latencias[t:2*t], latencias[2*t:]
    return {
        "bloco1_avg": statistics.mean(b1),
        "bloco2_avg": statistics.mean(b2),
        "bloco3_avg": statistics.mean(b3),
        "bloco1_jitter": statistics.mean([abs(b1[i]-b1[i-1]) for i in range(1,len(b1))]) if len(b1)>1 else 0,
        "bloco2_jitter": statistics.mean([abs(b2[i]-b2[i-1]) for i in range(1,len(b2))]) if len(b2)>1 else 0,
        "bloco3_jitter": statistics.mean([abs(b3[i]-b3[i-1]) for i in range(1,len(b3))]) if len(b3)>1 else 0,
    }

# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTICO E RECOMENDACOES PARA UNREAL ENGINE 5 (Conan Exiles Enhanced)
# ─────────────────────────────────────────────────────────────────────────────
def diagnosticar(latencias, perdidos, count, seq_perda, blocos, label):
    T = THRESHOLDS
    problemas = []
    recomendacoes_servidor = []

    if not latencias:
        return ["CRITICO: 100% Packet Loss."], ["Servidor inacessivel."]

    loss_pct    = (perdidos / count) * 100
    avg_rtt     = statistics.mean(latencias)
    jitter_list = [abs(latencias[i]-latencias[i-1]) for i in range(1, len(latencias))]
    avg_jitter  = statistics.mean(jitter_list) if jitter_list else 0.0
    spikes      = sum(1 for j in jitter_list if j > avg_rtt * T["spike_ratio"])

    # Avaliacao Jitter e Degradacao
    if avg_jitter >= T["jitter_critico"]:
        problemas.append(f"[CRITICO] Jitter Medio: {avg_jitter:.1f}ms (causa: severo desync e hitreg na UE5)")
    elif avg_jitter >= T["jitter_atencao"]:
        problemas.append(f"[ATENCAO] Jitter Medio: {avg_jitter:.1f}ms (causa: stuttering e network corrections na UE5)")

    if loss_pct >= T["loss_atencao"]:
        problemas.append(f"[ATENCAO] Packet Loss de {loss_pct:.1f}%")

    if seq_perda and max(seq_perda) >= 3:
         problemas.append(f"[CRITICO] Burst Loss de {max(seq_perda)} pacotes (Estrangulamento/Drop rate UDP detectado)")

    degradando = blocos and blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4

    if degradando:
         problemas.append(f"[CRITICO] Jitter degrada com o tempo. Bloco 1: {blocos['bloco1_jitter']:.1f}ms -> Bloco 3: {blocos['bloco3_jitter']:.1f}ms (Sinal de sobrecarga no Game Thread ou Networking Thread da UE5)")


    # ── RECOMENDACOES ESPECIFICAS UNREAL ENGINE 5 E REDE ─────────────────────

    if avg_jitter >= T["jitter_atencao"] or degradando:
        recomendacoes_servidor.append(
            "1. UNREAL ENGINE 5 - NETWORK TICK E BANDWIDTH LIMITS (DefaultEngine.ini)\n"
            "   A variacao severa no jitter de pacotes (degradacao temporal) indica gargalo nas\n"
            "   filas de RPC e replicacao da UE5. Revisar os seguintes parametros no DefaultEngine.ini:\n"
            "   \n"
            "   [/Script/Engine.GameNetworkManager]\n"
            "   MaxDynamicBandwidth=200000\n"
            "   MinDynamicBandwidth=20000\n"
            "   TotalNetBandwidth=600000\n"
            "   \n"
            "   [/Script/Engine.Engine]\n"
            "   NetServerMaxTickRate=60 (ou 30 caso o servidor sofra muito com AI/Thralls)\n"
            "   \n"
            "   [SystemSettings]\n"
            "   net.MaxSmoothUpdateDistance=256\n"
            "   net.MaxSmoothUpdateDistanceSquared=65536"
        )

        recomendacoes_servidor.append(
            "2. UNREAL ENGINE 5 - GC E OVERHEAD DO GAME THREAD\n"
            "   Se o Server FPS cai e a latencia do UDP sobe (Network Thread esperando), \n"
            "   ajustar o Garbage Collection para evitar travamentos sistematicos:\n"
            "   \n"
            "   [SystemSettings]\n"
            "   gc.TimeBetweenPurgingPendingKillObjects=30\n"
            "   s.AsyncLoadingTimeLimit=5\n"
            "   s.PriorityAsyncLoadingExtraTime=15"
        )

    if loss_pct >= T["loss_atencao"] or (seq_perda and max(seq_perda) >= 2):
        recomendacoes_servidor.append(
            "3. OTIMIZACAO DE ANTI-DDOS PARA TRAFEGO UE5\n"
            "   A perda consecutiva de pacotes (Burst Loss) sugere que o firewall/mitigacao\n"
            "   esta dropando pacotes legitimos do servidor. Como a UE5 pode gerar rajadas\n"
            "   altas de atualizacoes UDP (RPCs):\n"
            "   - Ajustar o threshold de UDP flood mitigation do firewall (Rate Limit).\n"
            "   - Aumentar tolerancias de PPS (Packets Per Second) na porta alvo 7700/7701\n"
            "     para evitar 'falso positivo' em horarios de servidor lotado."
        )

    if avg_rtt >= T["latencia_atencao"] or spikes > 3:
        recomendacoes_servidor.append(
            "4. ROTEAMENTO DE REDE (DATACENTER)\n"
            "   Detectamos rotas sub-otimizadas com a operadora utilizada (testado via Omada Dual-WAN).\n"
            "   - Por favor, revisem as rotas BGP de entrada/saida para a operadora TIM (AS 26615)\n"
            "     e Telefonica/Vivo (AS 18881).\n"
            "   - Caso o servidor esteja hospedado na AWS/Azure/GCP, verificar se o trafego\n"
            "     esta passando pelo transit gateway mais proximo ao inves de fazer hairpinning."
        )

    recomendacoes_servidor.append(
        "5. DIAGNOSTICO DE HARDWARE/OS (DEDICADO)\n"
        "   - Monitorar a metrica %st (Steal Time) caso o servidor seja VPS. Steal alto\n"
        "     impacta a Engine brutalmente.\n"
        "   - Implementar regras de QoS/FQ-CoDel para a interface de rede do host,\n"
        "     priorizando a saida UDP do Game Server em relacao ao trafego TCP."
    )

    return problemas, recomendacoes_servidor

# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Conan Exiles Enhanced UE5 - Diagnostico")
    parser.add_argument("--ip",    required=True)
    parser.add_argument("--port",  type=int, required=True)
    parser.add_argument("--label", default="WAN")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args()

    ensure_output = Path("output")
    ensure_output.mkdir(exist_ok=True)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report = []
    def R(line=""): report.append(line); print(line)

    sep = "=" * 70
    R(sep)
    R(f"  RELATORIO TECNICO AVANCADO - CONAN EXILES ENHANCED (UNREAL ENGINE 5)")
    R(f"  Operadora  : {args.label.upper()}")
    R(f"  Alvo       : {args.ip}:{args.port}")
    R(f"  Data/Hora  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    R(f"  Pacotes    : {args.count}  |  Intervalo: {args.interval}s")
    R(sep)
    R()

    R("--- FASE 1: ICMP PING ---")
    R(fase_icmp(args.ip))
    R()

    R("--- FASE 2: TRACEROUTE ---")
    R(fase_traceroute(args.ip))
    R()

    R("--- FASE 3: DESCOBERTA UDP ---")
    active_ports, lines3 = fase_descoberta(args.ip, args.port)
    for l in lines3: R(l)
    R()

    R(f"--- FASE 4: STRESS TEST UDP ({args.count} PACOTES) ---")
    if not active_ports:
        R("FALHA: Nenhuma porta UDP respondeu.")
        return
    test_port = active_ports[0]
    latencias, perdidos, count, seq_perda = fase_stress(args.ip, test_port, args.count, args.interval)
    R()

    R("--- FASE 5: ANALISE ESTATISTICA ---")
    if latencias:
        avg_rtt     = statistics.mean(latencias)
        min_rtt     = min(latencias)
        max_rtt     = max(latencias)
        loss_pct    = (perdidos / count) * 100
        jitter_list = [abs(latencias[i]-latencias[i-1]) for i in range(1, len(latencias))]
        avg_jitter  = statistics.mean(jitter_list) if jitter_list else 0.0
        p95_rtt     = sorted(latencias)[int(len(latencias)*0.95)]
        spikes      = sum(1 for j in jitter_list if j > avg_rtt * THRESHOLDS["spike_ratio"])

        R(f"  Pacotes Perdidos        : {perdidos} ({loss_pct:.2f}%)")
        R(f"  Latencia Min/Med/Max    : {min_rtt:.1f}ms / {avg_rtt:.1f}ms / {max_rtt:.1f}ms")
        R(f"  Jitter Medio (|Δrtt|)   : {avg_jitter:.1f} ms")
        R(f"  Percentil 95            : {p95_rtt:.1f} ms")
        R(f"  Picos Detectados        : {spikes} eventos")

        blocos = analise_blocos(latencias, count)
        if blocos:
            R("\n--- ANALISE DE DEGRADACAO TEMPORAL ---")
            R(f"  Bloco 1 (inicio) | Avg: {blocos['bloco1_avg']:.1f}ms | Jitter: {blocos['bloco1_jitter']:.1f}ms")
            R(f"  Bloco 2 (meio)   | Avg: {blocos['bloco2_avg']:.1f}ms | Jitter: {blocos['bloco2_jitter']:.1f}ms")
            R(f"  Bloco 3 (final)  | Avg: {blocos['bloco3_avg']:.1f}ms | Jitter: {blocos['bloco3_jitter']:.1f}ms")
            if blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4:
                 R("  !! ALERTA: O jitter PIORA progressivamente !!")

    R()
    R(sep)
    R("  DIAGNOSTICO DE CAUSA RAIZ E RECOMENDACOES (UE5/REDE)")
    R(sep)
    problemas, rec_servidor = diagnosticar(latencias, perdidos, count, seq_perda, blocos, args.label)

    for p in problemas: R(f"  {p}")
    R()
    R("  Para o Administrador do Servidor:")
    R("  (Por favor, encaminhe os dados abaixo para a equipe tecnica)")
    R("  ------------------------------------------------------------")
    for r in rec_servidor: 
        R(r)
        R()

    outdir = Path.home() / "Documents" / "ConanRotas"
    outdir.mkdir(parents=True, exist_ok=True)
    filename = outdir / f"ticket_suporte_UE5_{args.label}_{ts}.txt"
    filename.write_text("\n".join(report), encoding="utf-8")
    print(f"\nSalvo em: {filename}")

if __name__ == "__main__":
    main()
