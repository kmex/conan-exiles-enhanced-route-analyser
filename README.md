# 🎮 Conan Exiles - Analisador de Rota (Dual-WAN)

Ferramenta de diagnóstico de rede focada para jogadores de **Conan Exiles** e administradores de servidores. Essencial para quem utiliza **roteadores com Dual-WAN** (ex: TP-Link Omada) e precisa descobrir qual provedor tem a melhor rota.

Este projeto contém ferramentas para análise em tempo real e um gerador de diagnóstico focado na **Unreal Engine 5 (Conan Exiles Enhanced)**.

---

## ✨ Funcionalidades

### 1. `conan_gui_v2.py` — Interface Gráfica para o Jogador
- Detecta seu **IP local (DHCP)** automaticamente para facilitar a criação de Policy Routing no Omada.
- **Gráfico em tempo real** de RTT (Ping) e Jitter.
- Histórico de testes em tabela com diagnóstico (BOM / ATENÇÃO / RUIM).
- Salva relatórios na pasta `Documentos\ConanRotas`.

### 2. `conan_diagnostico_avancado_ue5.py` — Gerador de Ticket para Suporte
- Script de terminal focado em **identificar problemas do lado do servidor**.
- **Análise de Degradação Temporal:** divide o teste em blocos para identificar se o Jitter piora com o tempo (sintoma de Game Thread sobrecarregada na UE5).
- **Detecção de Burst Loss:** identifica o descarte agressivo de pacotes UDP (geralmente causado por regras severas de Anti-DDoS).
- **Recomendações Prontas:** gera um arquivo `.txt` com instruções diretas para o administrador do servidor contendo parâmetros vitais da Unreal Engine 5 (ex: `MaxDynamicBandwidth`, `NetServerMaxTickRate`, `TimeBetweenPurgingPendingKillObjects`).

---

## 🚀 Como Executar no Windows

1. Baixe e instale o [Python 3.8+](https://www.python.org/downloads/) (marque a opção "Add Python to PATH" durante a instalação).
2. Baixe os arquivos deste repositório (Code > Download ZIP).
3. Abra o CMD ou PowerShell na pasta e execute:

Para abrir a interface gráfica:
```cmd
python conan_gui_v2.py
```

Para gerar um diagnóstico profundo de servidor:
```cmd
python conan_diagnostico_avancado_ue5.py --ip [IP_DO_SERVIDOR] --port 7700 --label [SUA_OPERADORA]
```
## 🔍 Diagnóstico Avançado para Conan Exiles Enhanced (UE5)
**Arquivo:** `conan_diagnostico_avancado_ue5.py`

Com a migração do Conan Exiles para a **Unreal Engine 5**, a forma como o servidor processa a rede e os eventos físicos mudou drasticamente. Jitter e perda de pacotes agora frequentemente não são culpa da sua internet, mas sim do **Game Thread** do servidor engasgando ou do **Anti-DDoS** do datacenter bloqueando o tráfego do jogo.

Este script foi desenhado para rodar via linha de comando (CLI) e gerar um **Dossiê Técnico** automatizado, pronto para ser enviado via Ticket de Suporte para os administradores do servidor.

### ⚙️ O que ele analisa?

1. **Análise de Degradação Temporal (Memory Leak / CPU Bottleneck)**
   O script divide o stress test em 3 blocos de tempo. Se o Jitter do Bloco 3 for >40% pior que o do Bloco 1, ele detecta que o problema piora progressivamente. Na UE5, isso geralmente indica falha no Garbage Collection ou acúmulo de processamento no Game Thread.
2. **Detecção de Burst Loss (Falso Positivo de Anti-DDoS)**
   Servidores UE5 mandam rajadas pesadas de pacotes UDP (RPCs). O script conta pacotes perdidos em sequência (Burst Loss). Perdas consecutivas geralmente significam que o Firewall/Mitigação DDoS do datacenter está cortando (rate-limiting) o tráfego legítimo do jogo.
3. **Percentis e Spikes (Picos)**
   Ao invés de mostrar apenas a "média", o script calcula o P95 (Percentil 95) e a quantidade de *Spikes* (quando um pacote demora 3x mais que a média), que são os responsáveis diretos pelos "teleportes" (rubberbanding) in-game.

### 📝 Recomendações Automáticas
Baseado nos resultados, o script imprime recomendações exatas para a equipe de TI do servidor, incluindo parâmetros do `DefaultEngine.ini` focados na UE5, como:
- Ajustes de `MaxDynamicBandwidth` e `TotalNetBandwidth`.
- Ajustes no Garbage Collection (`gc.TimeBetweenPurgingPendingKillObjects`).
- Alterações em `NetServerMaxTickRate`.
- Dicas de roteamento BGP e checagem de CPU Steal (`%st`) em máquinas virtuais.

### 🚀 Como utilizar

Abra o terminal (CMD ou PowerShell) na pasta do projeto e rode:

**Teste Rápido (300 pacotes / ~5 minutos)**
```cmd
python conan_diagnostico_avancado_ue5.py --ip IPCONANSERVER --port 7700 --label SUA_OPERADORA
```

**Teste de Estresse Pesado (Para horários de pico - 600 pacotes / ~10 minutos)**
```cmd
python conan_diagnostico_avancado_ue5.py --ip IPCONANSERVER --port 7700 --label SUA_OPERADORA --count 600 --interval 0.08
```

Ao finalizar, um arquivo `.txt` será gerado automaticamente na pasta `Documentos\ConanRotas\`. Basta anexar este arquivo no Discord ou sistema de tickets do seu servidor.
---

## 🔧 Uso com Roteador gerenciavel OMADA

1. Use o `conan_gui_v2.py` para testar sua Rota WAN1 vs WAN2.
2. Copie seu IP Local através do botão na interface.
3. No painel do Omada, vá em **Preferences > IP Group** e crie um grupo com o IP do servidor de Conan.
4. Vá em **Transmission > Routing > Policy Routing** e crie uma regra forçando o seu IP Local para a WAN vencedora em direção ao IP Group do Conan.
