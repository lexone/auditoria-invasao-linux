# Auditoria de Invasão Linux

Script Bash de **auditoria defensiva e triagem de indícios de comprometimento** em servidores Linux. Coleta evidências locais de autenticação, contas, processos, conexões, persistência e arquivos suspeitos e gera um relatório organizado, sem executar correções automáticas.

> [!IMPORTANT]
> Este script **não é um antivírus, EDR ou análise forense completa**. Alertas indicam pontos para investigação, não confirmam uma invasão. A ausência de alertas também não garante que o servidor esteja íntegro.

## Funcionalidades

| Verificação | O que é analisado |
| --- | --- |
| SSH | Falhas de autenticação, logins aceitos, IPs envolvidos e login de `root` por senha |
| Contas e privilégios | Contas UID 0, senhas locais vazias, sessões, concessões `NOPASSWD` |
| Chaves SSH | Existência, permissões e fingerprints de `authorized_keys` |
| Processos | Execução de binários em `/tmp`, `/var/tmp`, `/dev/shm` ou marcados como removidos |
| Rede | Portas TCP/UDP em escuta e conexões TCP estabelecidas, usando `ss` |
| Persistência | Cron, systemd, timers, scripts de inicialização e alterações recentes |
| Arquivos suspeitos | Executáveis recentes em diretórios temporários e SUID/SGID atípicos |
| Arquivos sensíveis | Data de alteração, proprietário e permissões de configurações importantes |
| Integridade opcional | `dpkg --verify` ou `rpm -Va`, de acordo com a distribuição |

## Requisitos

- Linux com **Bash**, utilitários básicos do sistema (`find`, `awk`, `grep`, `ps`, `stat` etc.) e permissões de **root**.
- Testado sintaticamente com `bash -n`. As fontes de logs e utilitários disponíveis variam conforme a distribuição.
- Recomendado para Ubuntu, Debian, Rocky Linux, AlmaLinux, RHEL e distribuições equivalentes; **algumas verificações podem não estar disponíveis** em ambientes minimalistas ou contêineres.
- `journalctl`, `ss`, `sshd`, `ssh-keygen`, `crontab`, `systemctl` e `timeout` são usados quando disponíveis.

## Instalação

Após a publicação deste repositório, no servidor Linux:

```bash
git clone https://github.com/lexone/auditoria-invasao-linux.git
cd auditoria-invasao-linux
bash -n auditoria_invasao_linux.sh
```

Alternativamente, copie o arquivo `auditoria_invasao_linux.sh` para o servidor via SCP/SFTP ou outro meio confiável. **Revise o código antes de executá-lo como root.**

## Execução rápida

Auditoria padrão (últimos 7 dias):

```bash
sudo bash auditoria_invasao_linux.sh
```

Auditoria dos últimos 30 dias:

```bash
sudo bash auditoria_invasao_linux.sh --days 30
```

Auditoria aprofundada, com verificação de integridade de pacotes:

```bash
sudo bash auditoria_invasao_linux.sh --days 30 --deep
```

Salvar relatórios em outro diretório pai (ele **deve existir**):

```bash
sudo mkdir -p /var/log/auditoria-invasao
sudo chmod 700 /var/log/auditoria-invasao
sudo bash auditoria_invasao_linux.sh --days 7 --output-dir /var/log/auditoria-invasao
```

Ajuda:

```bash
bash auditoria_invasao_linux.sh --help
```

### Parâmetros

| Parâmetro | Descrição |
| --- | --- |
| `--days N` | Período de análise, de **1 a 365 dias**; padrão: `7` |
| `--deep` | Executa verificações de integridade de pacotes com `dpkg` ou `rpm` |
| `--output-dir DIRETORIO` | Diretório pai dos resultados; padrão: `/root` |
| `-h`, `--help` | Mostra a ajuda |

## Relatórios

O programa cria automaticamente uma pasta exclusiva, por exemplo:

```text
/root/auditoria-linux-AAAAMMDDTHHMMSSZ-XXXXXX/
├── relatorio.txt
├── alertas.tsv
├── ssh_eventos.txt
├── ips_com_falha.txt                  # quando houver eventos SSH
├── ips_com_sucesso.txt                # quando houver eventos SSH
├── processos_suspeitos.txt
├── executaveis_temporarios.txt
└── suid_sgid_atipicos.txt
```

A pasta é criada com acesso restrito e os relatórios principais com permissões `600`. Alguns arquivos opcionais dependem de haver registros ou comandos disponíveis.

Para ler o resumo:

```bash
sudo cat /root/auditoria-linux-*/alertas.tsv
```

Se já houver vários relatórios, escolha a pasta desejada primeiro:

```bash
sudo ls -ld /root/auditoria-linux-*/
```

### Interpretação dos alertas

- **ALTO:** indício de risco elevado, como conta adicional com UID 0 ou permissões de autenticação particularmente inseguras. Investigar com prioridade.
- **MEDIO:** comportamento ou configuração que merece investigação, como processos em diretórios temporários ou muitas tentativas de SSH.
- **REVISAO:** condição potencialmente legítima que deve ser comparada com inventário, janelas de manutenção e mudanças autorizadas.

Os alertas são de triagem, não um cálculo de probabilidade de comprometimento. Confirme a sequência temporal, a origem dos acessos e a legitimidade das mudanças antes de tomar medidas.

## Segurança e privacidade

- **Não** instala pacotes, modifica contas, bloqueia endereços IP, altera firewall nem remove arquivos de sistema.
- Cria apenas os arquivos necessários para os relatórios no diretório de saída.
- Pode consumir recursos de CPU/disco durante buscas em diretórios e, principalmente, com `--deep`.
- Logs e relatórios podem conter **IP, usuários, caminhos de arquivos, argumentos de processos e outros dados sensíveis**. Não faça commit nem compartilhe resultados brutos publicamente.
- O `.gitignore` do projeto ignora diretórios de relatório locais; isso **não substitui** os cuidados com dados sensíveis.

Se houver suspeita forte de invasão, preserve evidências e procure seguir o procedimento de resposta a incidentes. Em comprometimentos privilegiados, o próprio sistema e seus logs podem ter sido adulterados.

## Manual detalhado

Consulte [MANUAL_EXECUCAO.md](MANUAL_EXECUCAO.md) para o procedimento completo, leitura dos achados, solução de problemas e orientações de investigação.

## Limitações conhecidas

- Não verifica todas as técnicas de intrusão, rootkits, memória ou tráfego histórico de rede.
- A coleta SSH prioriza registros disponíveis via `journalctl`; na ausência deles, tenta `auth.log`/`secure`. Logs ausentes, rotacionados ou alterados podem limitar a análise.
- As verificações de integridade usam o banco local de pacotes; não constituem comparação com uma fonte externa independente.
- Algumas verificações analisam **amostras limitadas** para evitar relatórios excessivos e não devem ser interpretadas como busca exaustiva.

---

Desenvolvido para apoiar administradores Linux em auditorias preliminares e resposta inicial a incidentes.