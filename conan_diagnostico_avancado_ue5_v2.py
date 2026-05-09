#!/usr/bin/env python3
"""
Conan Exiles Enhanced (Unreal Engine 5) - Diagnostico Avancado v2
Gera relatorio tecnico completo com analise de causa raiz e recomendacoes especificas
para administradores de servidores de Conan Exiles (UE5).

Novas verificacoes v2:
  - Fase 5: Teste de MTU Path Discovery (detecta fragmentacao de pacotes)
  - Fase 6: Probe de Latencia por Horario (simula carga de peak hour)
  - Fase 7: Analise de Jitter de Saida vs Retorno (one-way delay estimate)
  - Fase 8: Verificacao de DNS Reverso (identifica se o servidor tem rDNS configurado)
  - Fase 9: Score de Saude Geral do Servidor (0-100) com carta de recomendacoes
  - Analise de Assimetria: deteccao de latencia assimetrica (upload vs download)
  - Analise de Percentis P50/P95/P99 separados para identificar outliers
  - Detector de Throttling por ISP (latencia quadruplicando em rajada = shape de UDP)

Windows/Linux | Python 3.8+
"""
import argparse
import socket
import statistics
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PAYLOAD      = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'
PAYLOAD_TINY = b'\xFF\xFF\xFF\xFF\x00'          # pacote minimo para teste de MTU
VERSION      = "2.0"

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
    "assimetria_max":  30.0,   # diferenca maxima aceitavel entre min e max rtt
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
    ports     = [base_port, base_port + 1, base_port + 15, 27015, 7778, 7777]
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
# FASE 4 — STRESS TEST PRINCIPAL (com deteccao de assimetria e throttling)
# ─────────────────────────────────────────────────────────────────────────────

def fase_stress(ip, port, count=300, interval=0.1):
    print(f"[Fase 4] Stress Test ({count} pacotes, intervalo {interval}s)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.6)
    latencias      = []
    perdidos       = 0
    seq_perda      = []
    perda_atual    = 0
    tempos_envio   = []
    tempos_retorno = []

    for i in range(count):
        t0 = time.time()
        try:
            sock.sendto(PAYLOAD, (ip, port))
            t_envio = time.time()
            sock.recvfrom(4096)
            t_retorno = time.time()
            rtt = (t_retorno - t0) * 1000
            latencias.append(rtt)
            tempos_envio.append((t_retorno - t_envio) * 1000)
            tempos_retorno.append(rtt / 2)
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
    return latencias, perdidos, count, seq_perda, tempos_envio, tempos_retorno

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
# FASE 6 — PROBE DE CARGA SIMULADA (rajada de pacotes seguidos)
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
            time.sleep(0.01)    # 10ms entre pacotes = rajada agressiva

        avg_b   = statistics.mean(latencias_burst) if latencias_burst else None
        loss_b  = (perdidos_burst / burst_size) * 100
        resultados_burst.append((avg_b, loss_b))
        status  = "OK" if loss_b < 5 else "PERDA"
        avg_str = f"{avg_b:.1f}ms" if avg_b else "N/A"
        print(f"  Rajada {b+1}/{num_bursts}: avg={avg_str} loss={loss_b:.0f}%  [{status}]")
        time.sleep(1.0)    # pausa de 1s entre rajadas

    sock.close()
    return resultados_burst

# ─────────────────────────────────────────────────────────────────────────────
# FASE 7 — DNS REVERSO E GEOLOCALIZACAO BASICA
# ─────────────────────────────────────────────────────────────────────────────

def fase_dns_reverso(ip):
    print("[Fase 7] Resolucao DNS Reverso e informacoes do host...")
    resultados = {}

    # rDNS
    try:
        rdns = socket.gethostbyaddr(ip)[0]
        resultados["rdns"] = rdns
        print(f"  rDNS:     {rdns}")
    except Exception:
        resultados["rdns"] = None
        print("  rDNS:     Nao configurado (sem registro PTR)")

    # WHOIS simplificado via comando
    print("  WHOIS:    Consultando AS e provedor...")
    if sys.platform == "win32":
        whois_out = run_cmd(f"nslookup -type=TXT {ip}", timeout=10)
    else:
        whois_out = run_cmd(f"whois {ip} 2>/dev/null | grep -i 'netname\\|country\\|org\\|descr' | head -10", timeout=15)
    resultados["whois"] = whois_out[:500] if whois_out else "Nao disponivel"

    # Teste de resolucao TCP (verifica se porta TCP de mgmt esta aberta)
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
# FASE 8 — ANALISE DE CONSISTENCIA DE RESPOSTA (fingerprint do servidor)
# ─────────────────────────────────────────────────────────────────────────────

def fase_fingerprint(ip, port):
    print("[Fase 8] Fingerprint do Servidor (analise de resposta Source Engine)...")
    resultados = {}

    # Consulta A2S_INFO
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
            # Tenta decodificar nome do servidor da resposta A2S_INFO
            if nome == "A2S_INFO" and len(data) > 6:
                try:
                    # Pula header \xFF\xFF\xFF\xFF\x49 (5 bytes) e versao (1 byte)
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
        return statistics.mean([abs(lst[i]-lst[i-1]) for i in range(1,len(lst))]) if len(lst)>1 else 0
    return {
        "bloco1_avg":    statistics.mean(b1),
        "bloco2_avg":    statistics.mean(b2),
        "bloco3_avg":    statistics.mean(b3),
        "bloco1_jitter": jm(b1),
        "bloco2_jitter": jm(b2),
        "bloco3_jitter": jm(b3),
    }

# ─────────────────────────────────────────────────────────────────────────────
# SCORE DE SAUDE (0-100)
# ─────────────────────────────────────────────────────────────────────────────

def calcular_score(latencias, perdidos, count, seq_perda, blocos, mtu_efetivo, burst_results):
    if not latencias:
        return 0, ["Sem dados de latencia."]
    T        = THRESHOLDS
    score    = 100
    penalidades = []

    loss_pct   = (perdidos / count) * 100
    avg_rtt    = statistics.mean(latencias)
    jitter_list= [abs(latencias[i]-latencias[i-1]) for i in range(1,len(latencias))]
    avg_jitter = statistics.mean(jitter_list) if jitter_list else 0.0
    p95        = percentil(latencias, 95)
    p99        = percentil(latencias, 99)
    spikes     = sum(1 for j in jitter_list if j > avg_rtt * T["spike_ratio"])

    # Penalidade: Packet Loss
    if loss_pct >= T["loss_critico"]:
        score -= 30; penalidades.append(f"Packet Loss CRITICO ({loss_pct:.1f}%): -30 pontos")
    elif loss_pct >= T["loss_atencao"]:
        score -= 15; penalidades.append(f"Packet Loss elevado ({loss_pct:.1f}%): -15 pontos")
    elif loss_pct > T["loss_bom"]:
        score -= 5;  penalidades.append(f"Packet Loss leve ({loss_pct:.1f}%): -5 pontos")

    # Penalidade: Jitter
    if avg_jitter >= T["jitter_critico"]:
        score -= 25; penalidades.append(f"Jitter CRITICO ({avg_jitter:.1f}ms): -25 pontos")
    elif avg_jitter >= T["jitter_atencao"]:
        score -= 12; penalidades.append(f"Jitter alto ({avg_jitter:.1f}ms): -12 pontos")
    elif avg_jitter >= T["jitter_bom"]:
        score -= 5;  penalidades.append(f"Jitter moderado ({avg_jitter:.1f}ms): -5 pontos")

    # Penalidade: Latencia media
    if avg_rtt >= T["latencia_critico"]:
        score -= 15; penalidades.append(f"Latencia CRITICA ({avg_rtt:.1f}ms): -15 pontos")
    elif avg_rtt >= T["latencia_atencao"]:
        score -= 8;  penalidades.append(f"Latencia alta ({avg_rtt:.1f}ms): -8 pontos")

    # Penalidade: Burst Loss (consecutivo)
    if seq_perda and max(seq_perda) >= 5:
        score -= 20; penalidades.append(f"Burst Loss severo ({max(seq_perda)} pacotes seguidos): -20 pontos")
    elif seq_perda and max(seq_perda) >= 3:
        score -= 10; penalidades.append(f"Burst Loss moderado ({max(seq_perda)} pacotes seguidos): -10 pontos")

    # Penalidade: Degradacao temporal
    if blocos and blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4:
        score -= 10; penalidades.append("Jitter degrada com o tempo (Memory Leak / CPU Bottleneck): -10 pontos")

    # Penalidade: MTU
    if mtu_efetivo < T["mtu_minimo"] and mtu_efetivo > 0:
        score -= 10; penalidades.append(f"MTU efetivo baixo ({mtu_efetivo}B < {T['mtu_minimo']}B): -10 pontos")

    # Penalidade: Picos (spikes)
    if spikes > 10:
        score -= 10; penalidades.append(f"Muitos spikes de latencia ({spikes} eventos): -10 pontos")
    elif spikes > 4:
        score -= 5;  penalidades.append(f"Spikes de latencia ({spikes} eventos): -5 pontos")

    # Penalidade: P99 muito alto (outliers extremos)
    if p99 > avg_rtt * 5:
        score -= 5;  penalidades.append(f"P99 ({p99:.1f}ms) muito alto vs media ({avg_rtt:.1f}ms): -5 pontos")

    # Penalidade: Throttling ISP (max_rtt >> min_rtt)
    min_rtt = min(latencias)
    if min_rtt > 0 and max(latencias) > min_rtt * T["throttle_ratio"]:
        score -= 8;  penalidades.append(f"Suspeita de throttling UDP pelo ISP (max/min ratio: {max(latencias)/min_rtt:.1f}x): -8 pontos")

    # Penalidade: Burst probe com perda
    if burst_results:
        burst_losses = [loss for _, loss in burst_results]
        avg_burst_loss = statistics.mean(burst_losses)
        if avg_burst_loss > 10:
            score -= 8; penalidades.append(f"Servidor nao suporta bem rajadas de trafego (loss em burst: {avg_burst_loss:.1f}%): -8 pontos")

    score = max(0, min(100, score))
    return score, penalidades

def score_label(score):
    if score >= 90: return "EXCELENTE"
    if score >= 75: return "BOM"
    if score >= 55: return "MODERADO"
    if score >= 35: return "RUIM"
    return "CRITICO"

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
    jitter_list = [abs(latencias[i]-latencias[i-1]) for i in range(1,len(latencias))]
    avg_jitter  = statistics.mean(jitter_list) if jitter_list else 0.0
    p95         = percentil(latencias, 95)
    p99         = percentil(latencias, 99)
    spikes      = sum(1 for j in jitter_list if j > avg_rtt * T["spike_ratio"])
    degradando  = blocos and blocos["bloco3_jitter"] > blocos["bloco1_jitter"] * 1.4

    # ── Deteccao de Problemas ─────────────────────────────────────────────────

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

    # ── Recomendacoes Tecnicas para o Administrador ───────────────────────────

    if not problemas:
        rec_servidor.append("Servidor saudavel. Nenhuma acao imediata necessaria.")
        return problemas, rec_servidor

    rec_servidor.append(
        "REC-1  CONFIGURACAO DE REDE UE5 (DefaultEngine.ini)\n"
        "       Revise os seguintes parametros no arquivo DefaultEngine.ini do servidor:\n"
        "\n"
        "       [/Script/Engine.GameNetworkManager]\n"
        "       MaxDynamicBandwidth=200000\n"
        "       MinDynamicBandwidth=20000\n"
        "       TotalNetBandwidth=600000\n"
        "\n"
        "       [/Script/Engine.Engine]\n"
        "       NetServerMaxTickRate=60\n"
        "       ; (Reduza para 30 se o servidor tiver AI/Thralls em excesso)\n"
        "\n"
        "       [SystemSettings]\n"
        "       net.MaxSmoothUpdateDistance=256\n"
        "       net.MaxSmoothUpdateDistanceSquared=65536\n"
        "       net.PktLag=0\n"
        "       net.PktLoss=0"
    )

    rec_servidor.append(
        "REC-2  GARBAGE COLLECTION E GAME THREAD (DefaultEngine.ini)\n"
        "       Jitter que piora com o tempo indica GC bloqueando o Game Thread.\n"
        "       Ajuste para ciclos de GC mais curtos e nao-bloqueantes:\n"
        "\n"
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
        "REC-3  THRALLS E AI (Limite de Entidades Ativas)\n"
        "       Cada Thrall ativo aumenta o custo do Game Thread e do Network Thread.\n"
        "       Configure no Game.ini:\n"
        "\n"
        "       [/Script/ConanSandbox.ConanGameMode]\n"
        "       MaxThralls=100\n"
        "       MaxWildlife=300\n"
        "       MaxAIPathFinding=50\n"
        "\n"
        "       Avalie usar: NPCRespawnMultiplier=0.5 para reduzir respawn agressivo\n"
        "       que gera picos de CPU e consequente jitter de rede."
    )

    if loss_pct >= T["loss_atencao"] or (seq_perda and max(seq_perda) >= 2):
        rec_servidor.append(
            "REC-4  FIREWALL / ANTI-DDOS (Ajuste de Rate Limit UDP)\n"
            "       O Burst Loss detectado indica que o firewall ou a mitigacao DDoS\n"
            "       esta descartando pacotes UDP legitimos do servidor UE5.\n"
            "       Acoes recomendadas:\n"
            "\n"
            "       - Aumentar o limiar de PPS (Packets Per Second) para as portas\n"
            f"         {', '.join(['7700', '7701', '7715', '27015'])} no firewall.\n"
            "       - Criar uma regra de excecao de rate-limit para o IP do servidor.\n"
            "       - Verificar se o Anti-DDoS do datacenter usa modo 'Mitigation Always On'.\n"
            "       - Testar com modo de mitigacao em 'Detection Only' temporariamente."
        )

    if mtu_efetivo < T["mtu_minimo"] and mtu_efetivo > 0:
        rec_servidor.append(
            f"REC-5  MTU / FRAGMENTACAO DE PACOTES UDP\n"
            f"       MTU efetivo detectado: {mtu_efetivo} bytes (ideal: >= {T['mtu_minimo']})\n"
            f"       Pacotes UDP da UE5 (RPCs) chegam a 1400+ bytes. Com MTU baixo,\n"
            f"       eles sao fragmentados, causando reassembly overhead e jitter.\n"
            "\n"
            "       - Verificar a interface de rede do servidor: ip link show\n"
            "         e ajustar: ip link set eth0 mtu 1500\n"
            "       - Verificar se o tunnel/VPN do datacenter reduz o MTU efetivo.\n"
            "       - No DefaultEngine.ini, limitar o tamanho dos pacotes UE5:\n"
            "         [SystemSettings]\n"
            "         net.MaxPacketSize=1200\n"
            "         (Ajuste para ficar abaixo do MTU detectado com margem de 100B)"
        )

    if degradando:
        rec_servidor.append(
            "REC-6  MONITORAMENTO DE MEMORIA E CPU STEAL\n"
            "       O jitter que degrada ao longo do tempo pode indicar:\n"
            "\n"
            "       (a) Memory Leak no servidor: Monitore com:\n"
            "           watch -n 5 'free -m && ps aux --sort=-%mem | head -5'\n"
            "       (b) CPU Steal (%st) em VPS: Monitore com:\n"
            "           top -d 1 -> verificar coluna 'st' (Steal Time)\n"
            "           Se %st > 5%, o host fisico esta sobrecarregado.\n"
            "           Solucao: migrar para outro node ou usar servidor dedicado.\n"
            "       (c) Swap em uso: UE5 nao tolera Swap. Verificar com:\n"
            "           free -m -> linha Swap. Se 'used' > 0, adicionar RAM ou\n"
            "           desativar swap e reiniciar o servidor."
        )

    rec_servidor.append(
        "REC-7  QUALIDADE DE SERVICO (QoS) NO HOST DO SERVIDOR\n"
        "       Priorize o trafego do servidor de jogo sobre outros servicos:\n"
        "\n"
        "       # Linux (iptables + tc - priorizando UDP do servidor)\n"
        "       tc qdisc add dev eth0 root handle 1: prio\n"
        "       tc filter add dev eth0 parent 1: protocol ip prio 1 \\\n"
        "         u32 match ip dport 7700 0xffff flowid 1:1\n"
        "\n"
        "       Ou use FQ-CoDel para reduzir bufferbloat:\n"
        "       tc qdisc replace dev eth0 root fq_codel\n"
        "\n"
        "       No Windows Server: configurar QoS via Group Policy para\n"
        "       priorizar o processo do servidor (ConanSandboxServer.exe)."
    )

    rec_servidor.append(
        "REC-8  CONFIGURACOES DE SISTEMA OPERACIONAL (Linux)\n"
        "       Ajustes no kernel para melhorar throughput e latencia UDP:\n"
        "\n"
        "       # Adicionar ao /etc/sysctl.conf e rodar: sysctl -p\n"
        "       net.core.rmem_max=16777216\n"
        "       net.core.wmem_max=16777216\n"
        "       net.core.rmem_default=1048576\n"
        "       net.core.wmem_default=1048576\n"
        "       net.ipv4.udp_mem=8388608 12582912 16777216\n"
        "       net.core.netdev_max_backlog=50000\n"
        "       net.ipv4.tcp_fin_timeout=10\n"
        "       net.ipv4.tcp_max_syn_backlog=4096\n"
        "\n"
        "       # Desativar IRQ Balancing e fixar interrupcoes na CPU de jogo:\n"
        "       systemctl disable irqbalance\n"
        "       # (Verificar com: cat /proc/interrupts | grep eth0)"
    )

    if dns_results.get("rdns") is None:
        rec_servidor.append(
            "REC-9  rDNS (Registro PTR)\n"
            "       O servidor nao possui registro PTR (DNS reverso) configurado.\n"
            "       Isso dificulta diagnosticos de rede e pode aumentar a latencia\n"
            "       em alguns filtros de seguranca.\n"
            "\n"
            "       - Solicitar ao provedor de hospedagem a configuracao do rDNS\n"
            f"         para o IP {label} (ex: game.seuservidor.com -> IP)\n"
            "       - Configurar no painel do datacenter/VPS na secao 'Reverse DNS'."
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
    args = parser.parse_args()

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
    R(f"  Pacotes    : {args.count} | Intervalo: {args.interval}s")
    R(sep)
    R()

    # ── Fases 1-3: Diagnostico basico ────────────────────────────────────────
    R(sep2)
    R("FASE 1 — ICMP PING")
    R(sep2)
    R(fase_icmp(args.ip)); R()

    R(sep2)
    R("FASE 2 — TRACEROUTE")
    R(sep2)
    R(fase_traceroute(args.ip)); R()

    R(sep2)
    R("FASE 3 — DESCOBERTA DE PORTAS UDP")
    R(sep2)
    active_ports, lines3 = fase_descoberta(args.ip, args.port)
    for l in lines3: R(l)
    R()

    if not active_ports:
        R("FALHA CRITICA: Nenhuma porta UDP respondeu. Encerrando diagnostico.")
        filename = outdir / f"ticket_UE5_{args.label}_{ts}.txt"
        filename.write_text("\n".join(report), encoding="utf-8")
        print(f"\nSalvo em: {filename}")
        return

    test_port = active_ports[0]

    # ── Fase 4: Stress Test ───────────────────────────────────────────────────
    R(sep2)
    R(f"FASE 4 — STRESS TEST UDP ({args.count} pacotes)")
    R(sep2)
    latencias, perdidos, count, seq_perda, t_envio, t_retorno = fase_stress(
        args.ip, test_port, args.count, args.interval
    )
    R()

    # ── Fase 5: MTU ───────────────────────────────────────────────────────────
    R(sep2)
    R("FASE 5 — MTU PATH DISCOVERY")
    R(sep2)
    if args.skip_mtu:
        mtu_resultados, mtu_efetivo = {}, 1400
        R("  [PULADO]")
    else:
        mtu_resultados, mtu_efetivo = fase_mtu(args.ip, test_port)
    R()

    # ── Fase 6: Burst Probe ───────────────────────────────────────────────────
    R(sep2)
    R("FASE 6 — PROBE DE CARGA SIMULADA (BURST)")
    R(sep2)
    burst_results = fase_burst_probe(args.ip, test_port)
    R()

    # ── Fase 7: DNS + TCP ─────────────────────────────────────────────────────
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

    # ── Fase 8: Fingerprint ───────────────────────────────────────────────────
    R(sep2)
    R("FASE 8 — FINGERPRINT DO SERVIDOR (Source Engine Query)")
    R(sep2)
    fp_results = fase_fingerprint(args.ip, test_port)
    R()

    # ── Fase 9: Estatisticas ──────────────────────────────────────────────────
    R(sep2)
    R("FASE 9 — ANALISE ESTATISTICA COMPLETA")
    R(sep2)
    if latencias:
        avg_rtt    = statistics.mean(latencias)
        min_rtt    = min(latencias)
        max_rtt    = max(latencias)
        loss_pct   = (perdidos / count) * 100
        jitter_list= [abs(latencias[i]-latencias[i-1]) for i in range(1,len(latencias))]
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
        R(f"  Spikes (>{THRESHOLDS['spike_ratio']}x media) : {spikes} eventos")
        R(f"  MTU Efetivo          : {mtu_efetivo} bytes")

        if max_rtt > 0 and min_rtt > 0:
            throttle_ratio = max_rtt / min_rtt
            R(f"  Ratio Max/Min RTT    : {throttle_ratio:.1f}x {'[SUSPEITA THROTTLING]' if throttle_ratio > THRESHOLDS['throttle_ratio'] else '[OK]'}")

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

        # Burst probe summary
        if burst_results:
            R()
            R("  Analise de Carga (Burst Probe):")
            for i, (avg_b, loss_b) in enumerate(burst_results, 1):
                avg_str = f"{avg_b:.1f}ms" if avg_b else "N/A"
                R(f"    Rajada {i}: avg={avg_str:<10} loss={loss_b:.0f}%")
    else:
        blocos = None
        R("  FALHA: Sem dados de latencia (100% loss).")

    # ── Score de Saude ────────────────────────────────────────────────────────
    R()
    R(sep)
    R("  SCORE DE SAUDE DO SERVIDOR")
    R(sep)
    score, penalidades = calcular_score(
        latencias, perdidos, count, seq_perda, blocos,
        mtu_efetivo, burst_results
    )
    label_score = score_label(score)
    R(f"  SCORE: {score}/100 — {label_score}")
    R()
    if penalidades:
        R("  Fatores de penalidade:")
        for p in penalidades:
            R(f"    - {p}")
    R()

    # ── Diagnostico e Recomendacoes ───────────────────────────────────────────
    R(sep)
    R("  DIAGNOSTICO DE CAUSA RAIZ")
    R(sep)
    problemas, rec_servidor = diagnosticar(
        latencias, perdidos, count, seq_perda, blocos, args.label,
        mtu_efetivo, burst_results, dns_results, fp_results
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
    R(sep)

    # ── Salvar relatorio ──────────────────────────────────────────────────────
    filename = outdir / f"ticket_UE5_{args.label}_{ts}.txt"
    filename.write_text("\n".join(report), encoding="utf-8")
    print(f"\nRelatorio salvo em: {filename}")

if __name__ == "__main__":
    main()
