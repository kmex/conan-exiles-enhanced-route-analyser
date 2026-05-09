#!/usr/bin/env python3
"""
Conan Exiles Enhanced (Unreal Engine 5) - Diagnostico Avancado v3
Gera relatorio tecnico completo com analise de causa raiz e recomendacoes especificas
para administradores de servidores de Conan Exiles (UE5).

Diferencas principais da v3 em relacao a v2:
  - Modo de execucao: --mode quick/full (quick = teste mais rapido, full = completo)
  - Score de saude 0-100 com classificacao e RESUMO EXECUTIVO
  - Export adicional em JSON estruturado ao lado do .txt
  - Melhor organizacao das secoes e pequenos ajustes de mensagens

Windows/Linux | Python 3.8+
"""
import argparse
import json
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PAYLOAD      = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'
VERSION      = "3.0"

# ─────────────────────────────────────────────────────────────────────────────
THRESHOLDS = {
    "jitter_bom":      10.0,
    "jitter_atencao":  20.0,
    "jitter_critico":  40.0,
    "loss_bom":         0.5,
    "loss_atencao":     2.0,
    "loss_critico":     5.0,
    "latencia_bom":   100.0,
    "latencia_atencao":150.0,
    "latencia_critico":200.0,
    "spike_ratio":      3.0,   # pico > N * media = spike
    "mtu_minimo":    1400,     # MTU minimo aceitavel para UE5 sem fragmentacao
    "throttle_ratio":   4.0,   # se max_rtt > N * min_rtt = suspeita de throttling ISP
}

# ─────────────────────────────────────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=45):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (res.stdout or res.stderr or "Sem retorno.").strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except Exception as e:
        return f"[ERRO] {e}"

def ensure_output_dir():
    d = Path.home() / "Documents" / "ConanRotas"
    d.mkdir(parents=True, exist_ok=True)
    return d

def percentil(dados, p):
    if not dados:
        return 0.0
    s = sorted(dados)
    idx = int(len(s) * p / 100)
    return s[min(idx, len(s) - 1)]

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1 — ICMP PING LONGO
# ─────────────────────────────────────────────────────────────────────────────

def fase_icmp(ip):
    print("[Fase 1] ICMP Ping longo (50 pacotes)...")
    cmd = f"ping -n 50 {ip}" if sys.platform == "win32" else f"ping -c 50 {ip}"
    return run_cmd(cmd, timeout=70)

# ─────────────────────────────────────────────────────────────────────────────
# FASE 2 — TRACEROUTE
# ─────────────────────────────────────────────────────────────────────────────

def fase_traceroute(ip):
    print("[Fase 2] Traceroute (mapeando rota completa)...")
    cmd = (f"tracert -h 30 -w 1500 {ip}" if sys.platform == "win32"
           else f"traceroute -n -w 3 -q 3 -m 30 {ip}")
    return run_cmd(cmd, timeout=60)

# ─────────────────────────────────────────────────────────────────────────────
# FASE 3 — DESCOBERTA DE PORTAS UDP
# ─────────────────────────────────────────────────────────────────────────────

def fase_descoberta(ip, base_port):
    print("[Fase 3] Descoberta de Portas UDP...")
    ports      = [base_port, base_port + 1, base_port + 15, 27015, 7778, 7777]
    responding = []
    lines      = []
    for p in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            t0 = time.time()
            sock.sendto(PAYLOAD, (ip, p))
            data, _ = sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            msg = f"  [ABERTA]          Porta {p:<6} -> {rtt:.1f}ms ({len(data)} bytes recebidos)"
            responding.append(p)
        except socket.timeout:
            msg = f"  [FECHADA/TIMEOUT] Porta {p}"
        except Exception as e:
            msg = f"  [ERRO]            Porta {p}: {e}"
        finally:
            sock.close()
        lines.append(msg)
        print(msg)
    return responding, lines

# ─────────────────────────────────────────────────────────────────────────────
# FASE 4 — STRESS TEST PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def fase_stress(ip, port, count=300, interval=0.1):
    print(f"[Fase 4] Stress Test ({count} pacotes, intervalo {interval}s)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.6)
    latencias = []
    perdidos  = 0
    seq_perda = []
    perda_atual = 0

    for i in range(count):
        t0 = time.time()
        try:
            sock.sendto(PAYLOAD, (ip, port))
            sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            latencias.append(rtt)
            if perda_atual > 0:
                seq_perda.append(perda_atual)
                perda_atual = 0
        except socket.timeout:
            perdidos   += 1
            perda_atual += 1
        time.sleep(interval)
        if (i + 1) % 50 == 0:
            print(f"  Progresso: {i+1:>3}/{count} pkt...")

    sock.close()
    if perda_atual > 0:
        seq_perda.append(perda_atual)
    return latencias, perdidos, count, seq_perda

# ─────────────────────────────────────────────────────────────────────────────
# FASE 5 — MTU PATH DISCOVERY (detecta fragmentacao UDP)
# ─────────────────────────────────────────────────────────────────────────────

def fase_mtu(ip, port):
    print("[Fase 5] MTU Path Discovery (testando fragmentacao de pacotes UDP)...")
    resultados = {}
    tamanhos   = [64, 512, 1024, 1400, 1472, 1500]

    for tamanho in tamanhos:
        payload = bytes([0xFF, 0xFF, 0xFF, 0xFF]) + b'T' * max(1, tamanho - 4)
        sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        try:
            if sys.platform == "win32":
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAGMENT, 1)
            t0 = time.time()
            sock.sendto(payload, (ip, port))
            sock.recvfrom(4096)
            rtt = (time.time() - t0) * 1000
            resultados[tamanho] = ("OK", rtt)
            print(f"  [{tamanho:>4}B] OK    -> {rtt:.1f}ms")
        except socket.timeout:
            resultados[tamanho] = ("TIMEOUT", None)
            print(f"  [{tamanho:>4}B] TIMEOUT (possivel fragmentacao ou bloqueio)")
        except OSError as e:
            resultados[tamanho] = ("FRAG_BLOCKED", None)
            print(f"  [{tamanho:>4}B] BLOCKED (fragmentacao bloqueada pelo path): {e}")
        except Exception as e:
            resultados[tamanho] = ("ERRO", None)
            print(f"  [{tamanho:>4}B] ERRO: {e}")
        finally:
            sock.close()

    mtu_efetivo = max((t for t, (s, _) in resultados.items() if s == "OK"), default=0)
    print(f"  MTU Efetivo detectado: {mtu_efetivo} bytes")
    return resultados, mtu_efetivo

# ─────────────────────────────────────────────────────────────────────────────
# FASE 6 — PROBE DE CARGA SIMULADA (rajadas)
# ─────────────────────────────────────────────────────────────────────────────

def fase_burst_probe(ip, port, burst_size=20, num_bursts=5):
    print(f"[Fase 6] Probe de Carga Simulada ({num_bursts} rajadas de {burst_size} pacotes)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    resultados_burst = []

    for b in range(num_bursts):
        latencias_burst = []
        perdidos_burst  = 0
        for _ in range(burst_size):
            t0 = time.time()
            try:
                sock.sendto(PAYLOAD, (ip, port))
                sock.recvfrom(4096)
                latencias_burst.append((time.time() - t0) * 1000)
            except socket.timeout:
                perdidos_burst += 1
            time.sleep(0.01)

        avg_b   = statistics.mean(latencias_burst) if latencias_burst else None
        loss_b  = (perdidos_burst / burst_size) * 100
        resultados_burst.append((avg_b, loss_b))
        status  = "OK" if loss_b < 5 else "PERDA"
        avg_str = f"{avg_b:.1f}ms" if avg_b else "N/A"
        print(f"  Rajada {b+1}/{num_bursts}: avg={avg_str} loss={loss_b:.0f}%  [{status}]")
        time.sleep(1.0)

    sock.close()
    return resultados_burst

# ─────────────────────────────────────────────────────────────────────────────
# FASE 7 — DNS REVERSO E PORTAS TCP BASICAS
# ─────────────────────────────────────────────────────────────────────────────

def fase_dns_reverso(ip):
    print("[Fase 7] Resolucao DNS Reverso e informacoes do host...")
    resultados = {}

    try:
        rdns = socket.gethostbyaddr(ip)[0]
        resultados["rdns"] = rdns
        print(f"  rDNS:     {rdns}")
    except Exception:
        resultados["rdns"] = None
        print("  rDNS:     Nao configurado (sem registro PTR)")

    print("  WHOIS:    Consultando AS e provedor...")
    if sys.platform == "win32":
        whois_out = run_cmd(f"nslookup -type=TXT {ip}", timeout=10)
    else:
        whois_out = run_cmd(
            f"whois {ip} 2>/dev/null | grep -i 'netname\\|country\\|org\\|descr' | head -10",
            timeout=15,
        )
    resultados["whois"] = whois_out[:500] if whois_out else "Nao disponivel"

    for port_tcp in [80, 443, 22]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((ip, port_tcp))
            resultados[f"tcp_{port_tcp}"] = "ABERTA"
            print(f"  TCP {port_tcp}:  ABERTA (servico web/SSH presente no host)")
        except Exception:
            resultados[f"tcp_{port_tcp}"] = "FECHADA"
        finally:
            s.close()

    return resultados

# ─────────────────────────────────────────────────────────────────────────────
# FASE 8 — FINGERPRINT DO SERVIDOR (Source Engine)
# ─────────────────────────────────────────────────────────────────────────────

def fase_fingerprint(ip, port):
    print("[Fase 8] Fingerprint do Servidor (analise de resposta Source Engine)...")
    resultados = {}

    payloads_teste = {
        "A2S_INFO":   b'\xFF\xFF\xFF\xFFTSource Engine Query\x00',
        "A2S_PLAYER": b'\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF',
        "A2S_RULES":  b'\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF',
    }

    for nome, payload in payloads_teste.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            t0 = time.time()
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(8192)
            rtt  = (time.time() - t0) * 1000
            size = len(data)
            if nome == "A2S_INFO" and len(data) > 6:
                try:
                    info_str = data[6:].split(b'\x00')[0].decode("utf-8", errors="replace")
                    resultados["server_name"] = info_str
                    print(f"  Nome do servidor: {info_str}")
                except Exception:
                    resultados["server_name"] = "Nao decodificado"

            resultados[nome] = {"status": "OK", "rtt_ms": round(rtt, 1), "bytes": size}
            print(f"  {nome:<12}: OK   -> {rtt:.1f}ms, {size} bytes")
        except socket.timeout:
            resultados[nome] = {"status": "TIMEOUT"}
            print(f"  {nome:<12}: TIMEOUT")
        except Exception as e:
            resultados[nome] = {"status": f"ERRO: {e}"}
            print(f"  {nome:<12}: ERRO: {e}")
        finally:
            sock.close()

    return resultados

# ─────────────────────────────────────────────────────────────────────────────
# ANALISE DE BLOCOS TEMPORAIS (degradacao progressiva)
# ─────────────────────────────────────────────────────────────────────────────

def analise_blocos(latencias):
    if not latencias:
        return None
    n = len(latencias)
    t = n // 3
    if t < 5:
        return None
    b1, b2, b3 = latencias[:t], latencias[t:2*t], latencias[2*t:]

    def jm(lst):
        return statistics.mean([abs(lst[i] - lst[i - 1]) for i in range(1, len(lst))]) if len(lst) > 1 else 0

    return {
        "bloco1_avg":    statistics.mean(b1),
        "bloco2_avg":    statistics.mean(b2),
        "bloco3_avg":    statistics.mean(b3),
        "bloco1_jitter": jm(b1),
        "bloco2_jitter": jm(b2),
        "bloco3_jitter": jm(b3),
    }

# ─────────────────────────────────────────────────────────────────────────────
# SCORE DE SAUDE (0-100) E CAUSA PROVAVEL
# ─────────────────────────────────────────────────────────────────────────────

def calcular_score(latencias, perdidos, count, seq_perda, blocos, mtu_efetivo, burst_results):
    if not latencias:
        return 0, ["Sem dados de latencia."]
    T          = THRESHOLDS
    score      = 100
    penalidades = []

    loss_pct    = (perdidos / count) * 100
    avg_rtt     = statistics.mean(latencias)
    jitter_list = [abs(latencias[i] - latencias[i - 1]) for i in range(1, len(latencias))]
    avg_jitter  = statistics.mean(jitter_list) if jitter_list else 0.0
    p99         = percentil(latencias, 99)
    spikes      = sum(1 for j in jitter_list if j > avg_rtt * T["spike_ratio"])

    if loss_pct >= T["loss_critico"]:
        score -= 30; penalidades.append(f"Packet Loss CRITICO ({loss_pct:.1f}%): -30 pontos")
    elif loss_pct >= T["loss_atencao"]:
        score -= 15; penalidades.append(f"Packet Loss elevado ({loss_pct:.1f}%): -15 pontos")
    elif loss_pct > T["loss_bom"]:
        score -= 5;  penalidades.append(f"Packet Loss leve ({loss_pct:.1f}%): -5 pontos")

    if avg_jitter >= T["jitter_critico"]:
        score -= 25; penalidades.append(f"Jitter CRITICO ({avg_jitter:.1f}ms): -25 pontos")
    elif avg_jitter >= T["jitter_atencao"]:
        score -= 12; penalidades.append(f"Jitter alto ({avg_jitter:.1f}ms): -12 pontos")
    elif avg_jitter >= T["jitter_bom"]:
        score -= 5;  penalidades.append(f"Jitter moderado ({avg_jitter:.1f}ms): -5 pontos")

    if avg_rtt >= T["latencia_critico"]:
        score -= 15; penalidades.append(f"Latencia CRITICA ({avg_rtt:.1f}ms): -15 pontos")
    elif avg_rtt >= T["latencia_atencao"]:
        score -= 8;  penalidades.append(f"Latencia alta ({avg_rtt:.1f}ms): -8 pontos")

    if seq_perda and max(seq_perda) >= 5:
        score -= 20; penalidades.append(f"Burst Loss severo ({max(seq_perda)} pacotes seguidos): -20 pontos")
    elif seq_perda and max(seq_perda) >= 3:
        score -= 10; penalidades.append(f"Burst Loss moderado ({max(seq_perda)} pacotes seguidos): -10 pontos")

    if blocos and blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4:
        score -= 10; penalidades.append("Jitter degrada com o tempo (Memory Leak / CPU Bottleneck): -10 pontos")

    if mtu_efetivo < T["mtu_minimo"] and mtu_efetivo > 0:
        score -= 10; penalidades.append(f"MTU efetivo baixo ({mtu_efetivo}B < {T['mtu_minimo']}B): -10 pontos")

    if spikes > 10:
        score -= 10; penalidades.append(f"Muitos spikes de latencia ({spikes} eventos): -10 pontos")
    elif spikes > 4:
        score -= 5;  penalidades.append(f"Spikes de latencia ({spikes} eventos): -5 pontos")

    if p99 > avg_rtt * 5:
        score -= 5;  penalidades.append(f"P99 ({p99:.1f}ms) muito alto vs media ({avg_rtt:.1f}ms): -5 pontos")

    min_rtt = min(latencias)
    if min_rtt > 0 and max(latencias) > min_rtt * T["throttle_ratio"]:
        score -= 8;  penalidades.append(f"Suspeita de throttling UDP pelo ISP (max/min ratio: {max(latencias)/min_rtt:.1f}x): -8 pontos")

    if burst_results:
        burst_losses = [loss for _, loss in burst_results]
        avg_burst_loss = statistics.mean(burst_losses)
        if avg_burst_loss > 10:
            score -= 8; penalidades.append(f"Servidor nao suporta bem rajadas de trafego (loss em burst: {avg_burst_loss:.1f}%): -8 pontos")

    score = max(0, min(100, score))
    return score, penalidades

def score_label(score):
    if score >= 90:
        return "EXCELENTE"
    if score >= 75:
        return "BOM"
    if score >= 55:
        return "MODERADO"
    if score >= 35:
        return "RUIM"
    return "CRITICO"


def classificar_causa(latencias, perdidos, count, mtu_efetivo):
    if not latencias:
        return "Indefinida (sem dados)."
    T          = THRESHOLDS
    loss_pct   = (perdidos / count) * 100
    avg_rtt    = statistics.mean(latencias)
    min_rtt    = min(latencias)
    max_rtt    = max(latencias)
    jitter_lst = [abs(latencias[i] - latencias[i - 1]) for i in range(1, len(latencias))]
    avg_jitter = statistics.mean(jitter_lst) if jitter_lst else 0.0
    throttle_ratio = (max_rtt / min_rtt) if min_rtt > 0 else 0

    if avg_jitter >= T["jitter_atencao"] and throttle_ratio >= T["throttle_ratio"]:
        return (
            "Provavel gargalo no host do servidor ou mitigacao DDoS/datacenter "
            "(cliente e rota aparentam estar estaveis em comparacao ao UDP)."
        )
    if loss_pct >= T["loss_atencao"] and avg_jitter < T["jitter_critico"]:
        return "Provavel problema de rota/ISP (perda significativa de pacotes no caminho)."
    if mtu_efetivo and mtu_efetivo < T["mtu_minimo"]:
        return (
            "MTU efetivo abaixo do ideal, com alta probabilidade de fragmentacao de pacotes UDP "
            "afetando jitter e estabilidade."
        )
    return "Causa possivel mista (rota + carga do servidor)."

# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTICO COMPLETO + RECOMENDACOES
# ─────────────────────────────────────────────────────────────────────────────

def diagnosticar(latencias, perdidos, count, seq_perda, blocos, label,
                 mtu_efetivo, burst_results, dns_results, fp_results):
    T            = THRESHOLDS
    problemas    = []
    rec_servidor = []

    if not latencias:
        return ["CRITICO: 100% Packet Loss. Servidor inacessivel."], []

    loss_pct    = (perdidos / count) * 100
    avg_rtt     = statistics.mean(latencias)
    min_rtt     = min(latencias)
    max_rtt     = max(latencias)
    jitter_list = [abs(latencias[i] - latencias[i - 1]) for i in range(1, len(latencias))]
    avg_jitter  = statistics.mean(jitter_list) if jitter_list else 0.0
    p99         = percentil(latencias, 99)
    spikes      = sum(1 for j in jitter_list if j > avg_rtt * T["spike_ratio"])
    degradando  = blocos and blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4

    if avg_jitter >= T["jitter_critico"]:
        problemas.append(f"[CRITICO] Jitter Medio: {avg_jitter:.1f}ms | Severo desync e hitreg na UE5")
    elif avg_jitter >= T["jitter_atencao"]:
        problemas.append(f"[ATENCAO] Jitter Medio: {avg_jitter:.1f}ms | Stuttering e network corrections")

    if loss_pct >= T["loss_critico"]:
        problemas.append(f"[CRITICO] Packet Loss: {loss_pct:.1f}%")
    elif loss_pct >= T["loss_atencao"]:
        problemas.append(f"[ATENCAO] Packet Loss: {loss_pct:.1f}%")

    if seq_perda and max(seq_perda) >= 3:
        problemas.append(f"[CRITICO] Burst Loss: {max(seq_perda)} pacotes consecutivos | Anti-DDoS ou Rate Limit UDP")

    if degradando:
        problemas.append(
            f"[CRITICO] Jitter piora com o tempo: "
            f"Bloco1={blocos['bloco1_jitter']:.1f}ms -> Bloco3={blocos['bloco3_jitter']:.1f}ms "
            f"| Sinal de sobrecarga no Game Thread/GC da UE5"
        )

    if mtu_efetivo < T["mtu_minimo"] and mtu_efetivo > 0:
        problemas.append(
            f"[ATENCAO] MTU efetivo baixo ({mtu_efetivo}B) "
            f"| Pacotes UDP da UE5 serao fragmentados (causa de jitter e perda)"
        )

    if p99 > avg_rtt * 5:
        problemas.append(f"[ATENCAO] P99 ({p99:.1f}ms) muito alto | Outliers extremos afetando jogo")

    if min_rtt > 0 and max_rtt > min_rtt * T["throttle_ratio"]:
        problemas.append(
            f"[ATENCAO] Variacao extrema de latencia ({min_rtt:.1f}ms - {max_rtt:.1f}ms) "
            f"| Suspeita de throttling UDP pelo ISP"
        )

    if spikes > 4:
        problemas.append(f"[ATENCAO] {spikes} spikes de latencia detectados | Micro-freezes no servidor")

    if dns_results.get("rdns") is None:
        problemas.append("[INFO] Servidor sem rDNS (registro PTR) | Configura-lo melhora diagnosticos futuros")

    if burst_results:
        burst_losses = [loss for _, loss in burst_results]
        if statistics.mean(burst_losses) > 10:
            problemas.append(f"[ATENCAO] Servidor perde pacotes sob carga em rajada | Possivel limite de queue UDP")

    # Recomendas (mesmas ideias da v2, resumidas)
    if not problemas:
        rec_servidor.append("Servidor saudavel. Nenhuma acao imediata necessaria.")
        return problemas, rec_servidor

    rec_servidor.append(
        "REC-1  CONFIGURACAO DE REDE UE5 (DefaultEngine.ini)\n"
        "       [/Script/Engine.GameNetworkManager]\n"
        "       MaxDynamicBandwidth=200000\n"
        "       MinDynamicBandwidth=20000\n"
        "       TotalNetBandwidth=600000\n"
        "\n"
        "       [/Script/Engine.Engine]\n"
        "       NetServerMaxTickRate=60 ; (reduzir para 30 em casos extremos de carga de AI)\n"
        "\n"
        "       [SystemSettings]\n"
        "       net.MaxSmoothUpdateDistance=256\n"
        "       net.MaxSmoothUpdateDistanceSquared=65536\n"
        "       net.PktLag=0\n"
        "       net.PktLoss=0"
    )

    rec_servidor.append(
        "REC-2  GARBAGE COLLECTION E GAME THREAD (DefaultEngine.ini)\n"
        "       [SystemSettings]\n"
        "       gc.TimeBetweenPurgingPendingKillObjects=30\n"
        "       gc.AllowParallelGC=true\n"
        "       gc.MaxObjectsNotConsideredByGC=1000000\n"
        "       s.AsyncLoadingTimeLimit=5\n"
        "       s.PriorityAsyncLoadingExtraTime=15\n"
        "\n"
        "       [/Script/CoreUObject.GarbageCollectionSettings]\n"
        "       TimeBetweenPurgingPendingKillObjects=60"
    )

    rec_servidor.append(
        "REC-3  THRALLS E AI (Game.ini)\n"
        "       [/Script/ConanSandbox.ConanGameMode]\n"
        "       MaxThralls=100\n"
        "       MaxWildlife=300\n"
        "       MaxAIPathFinding=50\n"
        "       NPCRespawnMultiplier=0.5 ; reduzir respawn agressivo em servidores lotados"
    )

    if loss_pct >= T["loss_atencao"] or (seq_perda and max(seq_perda) >= 2):
        rec_servidor.append(
            "REC-4  FIREWALL / ANTI-DDOS\n"
            "       Ajustar rate-limit UDP para portas 7700/7701/7715/27015, criando excecao para o IP do servidor.\n"
            "       Testar modo 'Detection Only' na mitigacao DDoS para validar impacto sobre jitter."
        )

    if mtu_efetivo < T["mtu_minimo"] and mtu_efetivo > 0:
        rec_servidor.append(
            "REC-5  MTU / FRAGMENTACAO\n"
            f"       MTU efetivo detectado: {mtu_efetivo} bytes (ideal >= {T['mtu_minimo']}B).\n"
            "       Ajustar MTU da interface do host e, se necessario, limitar net.MaxPacketSize em ~1200B."
        )

    rec_servidor.append(
        "REC-6  MONITORAMENTO DE MEMORIA, CPU STEAL E SWAP\n"
        "       Monitorar 'free -m', 'top' (coluna %st) e uso de swap; swap > 0 ou %st alto prejudicam severamente a UE5."
    )

    rec_servidor.append(
        "REC-7  QOS E KERNEL (Linux)\n"
        "       Usar fq_codel ou prio+tc para priorizar UDP do servidor e aplicar sysctl de buffers (rmem/wmem, udp_mem, netdev_max_backlog)."
    )

    if dns_results.get("rdns") is None:
        rec_servidor.append(
            "REC-8  rDNS (Registro PTR)\n"
            "       Configurar reverse DNS para o IP do servidor, melhorando diagnósticos e evitando filtros heurísticos."
        )

    return problemas, rec_servidor

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Conan Exiles Enhanced UE5 - Diagnostico Avancado v{VERSION}"
    )
    parser.add_argument("--ip",       required=True,               help="IP do servidor")
    parser.add_argument("--port",     type=int, required=True,     help="Porta do servidor")
    parser.add_argument("--label",    default="WAN",               help="Nome da operadora/conexao")
    parser.add_argument("--count",    type=int,   default=300,     help="Pacotes no stress test")
    parser.add_argument("--interval", type=float, default=0.1,     help="Intervalo entre pacotes (s)")
    parser.add_argument("--skip-mtu", action="store_true",         help="Pular teste de MTU")
    parser.add_argument("--skip-dns", action="store_true",         help="Pular resolucao DNS")
    parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="full",
        help="Modo de teste: quick (mais rapido) ou full (completo)",
    )
    args = parser.parse_args()

    # Ajustes de modo
    if args.mode == "quick":
        if args.count > 150:
            args.count = 150
        args.skip_mtu = True
        args.skip_dns = True

    outdir = ensure_output_dir()
    ts     = datetime.now().strftime('%Y%m%d_%H%M%S')
    report = []

    def R(line=""):
        report.append(line)
        print(line)

    sep  = "=" * 70
    sep2 = "-" * 70

    R(sep)
    R(f"  RELATORIO TECNICO AVANCADO v{VERSION} - CONAN EXILES ENHANCED (UE5)")
    R(f"  Operadora  : {args.label.upper()}")
    R(f"  Alvo       : {args.ip}:{args.port}")
    R(f"  Data/Hora  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    R(f"  Pacotes    : {args.count} | Intervalo: {args.interval}s | Modo: {args.mode}")
    R(sep)
    R()

    # Fase 1
    R(sep2)
    R("FASE 1 — ICMP PING")
    R(sep2)
    icmp_out = fase_icmp(args.ip)
    R(icmp_out)
    R()

    # Fase 2
    R(sep2)
    R("FASE 2 — TRACEROUTE")
    R(sep2)
    trace_out = fase_traceroute(args.ip)
    R(trace_out)
    R()

    # Fase 3
    R(sep2)
    R("FASE 3 — DESCOBERTA DE PORTAS UDP")
    R(sep2)
    active_ports, lines3 = fase_descoberta(args.ip, args.port)
    for l in lines3:
        R(l)
    R()

    if not active_ports:
        R("FALHA CRITICA: Nenhuma porta UDP respondeu. Encerrando diagnostico.")
        filename_txt = outdir / f"ticket_UE5_{args.label}_{ts}.txt"
        filename_txt.write_text("\n".join(report), encoding="utf-8")
        print(f"\nRelatorio salvo em: {filename_txt}")
        return

    test_port = active_ports[0]

    # Fase 4
    R(sep2)
    R(f"FASE 4 — STRESS TEST UDP ({args.count} pacotes)")
    R(sep2)
    latencias, perdidos, count, seq_perda = fase_stress(
        args.ip, test_port, args.count, args.interval
    )
    R()

    # Fase 5
    R(sep2)
    R("FASE 5 — MTU PATH DISCOVERY")
    R(sep2)
    if args.skip_mtu:
        mtu_resultados, mtu_efetivo = {}, 0
        R("  [PULADO]")
    else:
        mtu_resultados, mtu_efetivo = fase_mtu(args.ip, test_port)
    R()

    # Fase 6
    R(sep2)
    R("FASE 6 — PROBE DE CARGA SIMULADA (BURST)")
    R(sep2)
    burst_results = fase_burst_probe(args.ip, test_port)
    R()

    # Fase 7
    R(sep2)
    R("FASE 7 — DNS REVERSO E PORTAS TCP")
    R(sep2)
    if args.skip_dns:
        dns_results = {}
        R("  [PULADO]")
    else:
        dns_results = fase_dns_reverso(args.ip)
        if dns_results.get("whois"):
            R(f"  WHOIS Info: {dns_results['whois'][:300]}")
    R()

    # Fase 8
    R(sep2)
    R("FASE 8 — FINGERPRINT DO SERVIDOR (Source Engine Query)")
    R(sep2)
    fp_results = fase_fingerprint(args.ip, test_port)
    R()

    # Fase 9 — Estatistica
    R(sep2)
    R("FASE 9 — ANALISE ESTATISTICA COMPLETA")
    R(sep2)

    blocos       = None
    resumo_stats = {}

    if latencias:
        avg_rtt    = statistics.mean(latencias)
        min_rtt    = min(latencias)
        max_rtt    = max(latencias)
        loss_pct   = (perdidos / count) * 100
        jitter_list= [abs(latencias[i] - latencias[i - 1]) for i in range(1, len(latencias))]
        avg_jitter = statistics.mean(jitter_list) if jitter_list else 0.0
        p50        = percentil(latencias, 50)
        p95        = percentil(latencias, 95)
        p99        = percentil(latencias, 99)
        spikes     = sum(1 for j in jitter_list if j > avg_rtt * THRESHOLDS["spike_ratio"])

        R(f"  Pacotes Enviados     : {count}")
        R(f"  Pacotes Perdidos     : {perdidos} ({loss_pct:.2f}%)")
        R(f"  Burst Loss (max seq) : {max(seq_perda) if seq_perda else 0} pacotes consecutivos")
        R(f"  Latencia Min/Med/Max : {min_rtt:.1f}ms / {avg_rtt:.1f}ms / {max_rtt:.1f}ms")
        R(f"  Jitter Medio (|Δrtt|): {avg_jitter:.1f} ms")
        R(f"  Percentil P50        : {p50:.1f} ms  (mediana)")
        R(f"  Percentil P95        : {p95:.1f} ms  (pior 5% das conexoes)")
        R(f"  Percentil P99        : {p99:.1f} ms  (pior 1% das conexoes)")
        R(f"  Spikes (> {THRESHOLDS['spike_ratio']}x media): {spikes} eventos")
        R(f"  MTU Efetivo          : {mtu_efetivo} bytes")

        throttle_ratio = 0.0
        if max_rtt > 0 and min_rtt > 0:
            throttle_ratio = max_rtt / min_rtt
            flag = "[SUSPEITA THROTTLING]" if throttle_ratio > THRESHOLDS["throttle_ratio"] else "[OK]"
            R(f"  Ratio Max/Min RTT    : {throttle_ratio:.1f}x {flag}")

        blocos = analise_blocos(latencias)
        if blocos:
            R()
            R("  Analise de Degradacao Temporal:")
            R(f"    Bloco 1 (inicio) | Avg: {blocos['bloco1_avg']:.1f}ms | Jitter: {blocos['bloco1_jitter']:.1f}ms")
            R(f"    Bloco 2 (meio)   | Avg: {blocos['bloco2_avg']:.1f}ms | Jitter: {blocos['bloco2_jitter']:.1f}ms")
            R(f"    Bloco 3 (final)  | Avg: {blocos['bloco3_avg']:.1f}ms | Jitter: {blocos['bloco3_jitter']:.1f}ms")
            if blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4:
                R("    !! ALERTA: Jitter PIORA progressivamente !!")
        else:
            blocos = None

        if burst_results:
            R()
            R("  Analise de Carga (Burst Probe):")
            for i, (avg_b, loss_b) in enumerate(burst_results, 1):
                avg_str = f"{avg_b:.1f}ms" if avg_b else "N/A"
                R(f"    Rajada {i}: avg={avg_str:<10} loss={loss_b:.0f}%")

        resumo_stats = {
            "avg_rtt": avg_rtt,
            "min_rtt": min_rtt,
            "max_rtt": max_rtt,
            "loss_pct": loss_pct,
            "avg_jitter": avg_jitter,
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "spikes": spikes,
            "mtu_efetivo": mtu_efetivo,
            "throttle_ratio": throttle_ratio,
        }
    else:
        R("  FALHA: Sem dados de latencia (100% loss).")

    # Score de saude
    R()
    R(sep)
    R("  SCORE DE SAUDE DO SERVIDOR")
    R(sep)
    score, penalidades = calcular_score(
        latencias, perdidos, count, seq_perda, blocos,
        mtu_efetivo, burst_results,
    )
    label_score   = score_label(score)
    causa_prob    = classificar_causa(latencias, perdidos, count, mtu_efetivo) if latencias else "Indefinida (sem dados)."

    R(f"  SCORE: {score}/100 — {label_score}")
    R(f"  CAUSA PROVAVEL: {causa_prob}")
    R()
    if penalidades:
        R("  Fatores de penalidade:")
        for p in penalidades:
            R(f"    - {p}")
    R()

    # Diagnostico + recomendacoes
    R(sep)
    R("  DIAGNOSTICO DE CAUSA RAIZ")
    R(sep)
    problemas, rec_servidor = diagnosticar(
        latencias, perdidos, count, seq_perda, blocos, args.label,
        mtu_efetivo, burst_results, dns_results, fp_results,
    )

    if problemas:
        for p in problemas:
            R(f"  {p}")
    else:
        R("  Nenhum problema critico detectado.")
    R()

    R(sep)
    R("  RECOMENDACOES TECNICAS PARA O ADMINISTRADOR DO SERVIDOR")
    R(sep)
    for rec in rec_servidor:
        R()
        R(rec)
    R()

    # Resumo executivo final (para colar em Discord / ticket)
    R(sep)
    R("  RESUMO EXECUTIVO")
    R(sep)
    if latencias:
        R(f"  Operadora : {args.label.upper()}")
        R(f"  Servidor  : {fp_results.get('server_name', 'Desconhecido')} ({args.ip}:{args.port})")
        R(f"  Score     : {score}/100 ({label_score})")
        R(f"  Ping base : ver Fase 1 (ICMP)")
        R(f"  UDP       : RTT medio {resumo_stats.get('avg_rtt', 0):.1f}ms, Jitter {resumo_stats.get('avg_jitter', 0):.1f}ms, Loss {resumo_stats.get('loss_pct', 0):.2f}%")
        R(f"  Comentario: {causa_prob}")
    else:
        R("  Sem dados suficientes para resumo executivo (100% perda).")
    R()
    R(sep)

    # Salvar relatorio .txt e JSON
    filename_txt  = outdir / f"ticket_UE5_{args.label}_{ts}.txt"
    filename_json = outdir / f"ticket_UE5_{args.label}_{ts}.json"
    filename_txt.write_text("\n".join(report), encoding="utf-8")

    payload_json = {
        "version": VERSION,
        "label": args.label,
        "ip": args.ip,
        "port": args.port,
        "mode": args.mode,
        "count": count,
        "interval": args.interval,
        "score": score,
        "score_label": label_score,
        "causa_provavel": causa_prob,
        "stats": resumo_stats,
        "problemas": problemas,
        "recomendacoes": rec_servidor,
    }
    try:
        filename_json.write_text(json.dumps(payload_json, indent=2), encoding="utf-8")
    except Exception:
        pass

    print(f"\nRelatorio salvo em: {filename_txt}")
    print(f"JSON salvo em:      {filename_json}")

if __name__ == "__main__":
    main()
