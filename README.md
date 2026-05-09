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

---

## 🔧 Uso com Roteador gerenciavel OMADA

1. Use o `conan_gui_v2.py` para testar sua Rota WAN1 vs WAN2.
2. Copie seu IP Local através do botão na interface.
3. No painel do Omada, vá em **Preferences > IP Group** e crie um grupo com o IP do servidor de Conan.
4. Vá em **Transmission > Routing > Policy Routing** e crie uma regra forçando o seu IP Local para a WAN vencedora em direção ao IP Group do Conan.
