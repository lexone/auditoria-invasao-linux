# Manual de execução — Auditoria de Invasão Linux

## 1. Objetivo

Realizar uma varredura **defensiva, não destrutiva** e gerar evidências sobre possíveis acessos indevidos, mecanismos de persistência, privilégios, processos suspeitos e exposição de serviços em um Linux.

**Atenção:** o resultado é uma triagem de segurança. Não substitui EDR, monitoramento contínuo, auditoria de integridade independente nem perícia forense.

## 2. Antes de executar

1. Obtenha autorização para auditar o servidor.
2. Prefira executar em um período de menor demanda, especialmente com `--deep`.
3. Verifique se há espaço para os relatórios, que contêm dados sensíveis.
4. Entre por SSH ou console com uma conta autorizada que tenha `sudo`.
5. Copie o script de uma origem confiável e **inspecione-o antes de usar root**.

Identifique o ambiente:

```bash
cat /etc/os-release
id
command -v bash find awk grep ps stat journalctl ss
```

Os utilitários opcionais ausentes limitam a cobertura, mas nem todos impedem a execução.

## 3. Preparar o script

Com o repositório publicado:

```bash
git clone https://github.com/lexone/auditoria-invasao-linux.git
cd auditoria-invasao-linux
bash -n auditoria_invasao_linux.sh
```

Sem Git: transfira `auditoria_invasao_linux.sh` para o servidor (por SCP/SFTP, por exemplo) e acesse a pasta de destino.

**Dica:** não é necessário executar `chmod +x` ao utilizar `sudo bash ...`.

## 4. Executar a análise

### 4.1 Varredura rápida (recomendada inicialmente)

```bash
sudo bash auditoria_invasao_linux.sh --days 7
```

### 4.2 Investigar período maior

```bash
sudo bash auditoria_invasao_linux.sh --days 30
```

### 4.3 Verificação mais profunda

```bash
sudo bash auditoria_invasao_linux.sh --days 30 --deep
```

O `--deep` executa `dpkg --verify` (Debian/Ubuntu) ou `rpm -Va` (RHEL e derivados), quando disponíveis. Alterações administrativas legítimas podem aparecer como diferenças. A verificação pode levar tempo, e há limite de execução para esses comandos.

### 4.4 Direcionar o relatório

```bash
sudo mkdir -p /var/log/auditoria-invasao
sudo chmod 700 /var/log/auditoria-invasao
sudo bash auditoria_invasao_linux.sh --days 7 --output-dir /var/log/auditoria-invasao
```

O diretório passado em `--output-dir` **precisa existir**. O script cria dentro dele uma subpasta exclusiva.

## 5. Localizar os resultados

Ao terminar, a tela exibe algo semelhante a:

```text
Auditoria concluida.
Pasta: /root/auditoria-linux-20261020T120000Z-ABC123
Relatorio: /root/auditoria-linux-20261020T120000Z-ABC123/relatorio.txt
Alertas: /root/auditoria-linux-20261020T120000Z-ABC123/alertas.tsv
Contagem: ALTO=0 MEDIO=1 REVISAO=2
```

O nome, os horários e as contagens acima são apenas exemplos.

Anote o caminho real retornado pelo comando:

```bash
sudo less /root/auditoria-linux-.../relatorio.txt
sudo cat /root/auditoria-linux-.../alertas.tsv
```

Substitua `...` pelo nome da pasta efetivamente gerada. Para listar as pastas existentes:

```bash
sudo ls -ld /root/auditoria-linux-*/
```

### Principais arquivos

| Arquivo | Finalidade |
| --- | --- |
| `relatorio.txt` | Detalhes da auditoria organizados em seções |
| `alertas.tsv` | Alertas em duas colunas (nível e descrição) |
| `ssh_eventos.txt` | Eventos SSH coletados, quando disponíveis |
| `ips_com_falha.txt` e `ips_com_sucesso.txt` | IPs identificados na análise SSH, se houve eventos |
| `processos_suspeitos.txt` | Processos executando de diretórios temporários ou binários removidos |
| `executaveis_temporarios.txt` | Executáveis recentes em diretórios temporários |
| `suid_sgid_atipicos.txt` | Arquivos com privilégios especiais fora dos caminhos usuais |

## 6. Como investigar os achados

### 6.1 Logins SSH

Procure acessos aceitos fora dos horários esperados, IPs desconhecidos e logins com senha de `root`.

```bash
sudo grep -E 'Accepted |Failed password|Invalid user' /root/auditoria-linux-.../ssh_eventos.txt
```

Compare IP, horário, usuário e os registros de manutenção autorizada. **Muitas falhas SSH isoladas não provam invasão.**

### 6.2 Contas privilegiadas e chaves

Verifique contas com UID 0 além de `root`, alterações no `sudoers` e fingerprints de chaves SSH. Compare com seu inventário e com solicitações de acesso aprovadas.

### 6.3 Processos e conexões

Um programa legítimo pode usar `/tmp` e alguns executáveis podem aparecer como removidos após atualizações. Valide nome, caminho, hash, origem do pacote e necessidade do processo antes de classificá-lo como malicioso.

```bash
sudo ss -lntup
sudo ss -tnp state established
```

Esses comandos mostram **o estado no momento da execução**, não o histórico completo da rede.

### 6.4 Persistência

Compare tarefas cron, serviços systemd, timers e arquivos de inicialização com a configuração homologada. Mudanças recentes exigem correlação com a janela de manutenção.

### 6.5 Integridade de pacotes

O modo `--deep` pode listar arquivos modificados legitimamente pelo administrador e pacotes com integridade alterada. Verifique a documentação do gerenciador de pacotes e o histórico de mudanças antes de agir.

## 7. Erros comuns

| Situação | Ação recomendada |
| --- | --- |
| `Execute como root` | Execute com `sudo` ou uma sessão root autorizada |
| `diretorio pai indisponivel` | Crie o diretório informado e confira as permissões |
| `ss nao encontrado` | Verifique se `iproute2` está disponível na distribuição; a coleta de sockets será limitada |
| Sem registros SSH | Confira retenção dos logs, `journald`, `auth.log`/`secure` e tipo de serviço SSH |
| `systemctl` ausente | O sistema pode não usar systemd; essa parte da coleta será reduzida |
| Muitos alertas em `/tmp` | Correlacione com instaladores, atualizações e aplicações autorizadas |
| Sem alertas | **Não significa ausência de invasão**; amplie a investigação conforme o contexto |

## 8. Após uma suspeita real

1. Registre a linha do tempo e preserve os logs originais, quando possível.
2. Verifique o escopo: contas, máquinas, credenciais, serviços e conexões afetadas.
3. Siga o plano de resposta a incidentes da organização e, se necessário, isole o host **pela rede** de forma coordenada.
4. Não apague evidências nem execute comandos destrutivos antes da decisão do responsável pelo incidente.
5. Não publique relatórios brutos no GitHub: eles podem conter informações sensíveis da infraestrutura.

## 9. Observações operacionais

- Varredura padrão: últimos **7 dias**.
- Período aceito: **1–365 dias**.
- Saída padrão: pasta privada sob `/root`.
- A rotina não instala nem remove pacotes e não modifica configurações do servidor.
- O script **escreve relatórios** e pode gerar carga de leitura em disco e CPU.
- A integridade dos logs do próprio host não pode ser garantida se houver comprometimento com privilégios elevados.