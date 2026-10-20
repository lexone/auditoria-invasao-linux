#!/usr/bin/env bash
# Auditoria de indícios de comprometimento em Linux (somente leitura).
# Compatível com distribuições com utilitários Linux usuais; executa como root.
# Não instala pacotes, não abre conexões de rede, não altera regras ou serviços.

set -uo pipefail
umask 077
export LC_ALL=C

DAYS=7
DEEP=0
DEST_PARENT=/root

usage() {
  cat <<'HELP'
Uso: sudo bash auditoria_invasao_linux.sh [--days N] [--deep] [--output-dir DIRETORIO]

  --days N               Janela dos eventos e arquivos recentes (padrão: 7 dias)
  --deep                 Verificação adicional de integridade de pacotes (pode demorar)
  --output-dir DIRETORIO  Diretório pai onde será criada uma pasta exclusiva de relatório
  -h, --help             Mostrar esta ajuda

O script é SOMENTE LEITURA em relação à configuração do sistema.
Os únicos arquivos criados são os do relatório, com acesso restrito (modo 700/600).
HELP
}

while (($#)); do
  case "$1" in
    --days)
      if (($# < 2)) || ! [[ "$2" =~ ^[0-9]+$ ]] || ((10#$2 < 1 || 10#$2 > 365)); then
        echo 'ERRO: --days deve ser um inteiro de 1 a 365.' >&2; exit 2
      fi
      DAYS=$((10#$2)); shift 2 ;;
    --deep) DEEP=1; shift ;;
    --output-dir)
      if (($# < 2)) || [[ -z "$2" ]]; then echo 'ERRO: faltou diretorio.' >&2; exit 2; fi
      DEST_PARENT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERRO: argumento invalido: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if (( EUID != 0 )); then
  echo 'Execute como root: sudo bash auditoria_invasao_linux.sh' >&2
  exit 1
fi

if [[ ! -d "$DEST_PARENT" ]] || [[ ! -w "$DEST_PARENT" ]]; then
  echo "ERRO: diretorio pai indisponivel: $DEST_PARENT" >&2
  exit 1
fi

OUT=$(mktemp -d -- "$DEST_PARENT/auditoria-linux-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || exit 1
REPORT="$OUT/relatorio.txt"
ALERTS="$OUT/alertas.tsv"
: > "$REPORT"
: > "$ALERTS"
chmod 600 "$REPORT" "$ALERTS"
exec 3>&1
exec >>"$REPORT" 2>&1

section() { printf '\n%s\n### %s\n%s\n' '================================================================================' "$1" '================================================================================'; }
note() { printf '%s\n' "$*"; }
alert() {
  local level=$1 message=$2
  printf '%s\t%s\n' "$level" "$message" >> "$ALERTS"
  printf '[%s] %s\n' "$level" "$message"
}
have() { command -v "$1" >/dev/null 2>&1; }
limit_file() {
  local file=$1 lines=${2:-120}
  if [[ -s "$file" ]]; then
    sed -n "1,${lines}p" "$file"
    local total
    total=$(wc -l < "$file")
    if ((total > lines)); then note "... (${total} linhas no arquivo; mostrando ${lines})"; fi
  else
    note '(sem dados disponíveis)'
  fi
}
safe_timeout() {
  if have timeout; then timeout "$@"; else shift; "$@"; fi
}

section 'IDENTIFICACAO E ESCOPO'
note "Host: $(hostname 2>/dev/null || printf "indisponivel")"
note "Coleta UTC: $(date -u -Is)"
note "Janela solicitada: ultimos $DAYS dias"
note "Modo de integridade profunda: $DEEP"
note "Pasta privada: $OUT"
uname -a 2>/dev/null || true
cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION|PRETTY_NAME)=' || true
uptime 2>/dev/null || true
if have ip; then ip -br addr 2>/dev/null || true; fi

section 'USUARIOS PRIVILEGIADOS / CONTAS INTERATIVAS'
awk -F: '$3 == 0 {print "UID 0:", $1, "home=" $6, "shell=" $7}' /etc/passwd 2>/dev/null || true
while IFS=: read -r user _ uid _ _ home shell; do
  if [[ "$uid" =~ ^[0-9]+$ ]] && ((uid == 0)) && [[ "$user" != root ]]; then
    alert ALTO "Conta adicional com UID 0: $user"
  fi
done < /etc/passwd
note '-- Contas com senha local vazia:'
if [[ -r /etc/shadow ]]; then
  empty_passwords=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || true)
  if [[ -n "$empty_passwords" ]]; then
    printf '%s\n' "$empty_passwords"
    alert ALTO 'Uma ou mais contas possuem campo de senha local vazio em /etc/shadow; verificar politica PAM e acessos'
  else
    note '(nenhuma encontrada)'
  fi
fi
note '-- Contas com shell interativo (UID >= 1000 ou root):'
awk -F: '($3>=1000 || $3==0) && $7 !~ /(nologin|false)$/ {print $1, "UID=" $3, "HOME=" $6, "SHELL=" $7}' /etc/passwd 2>/dev/null || true
note '-- Sessões atuais:'
who -a 2>/dev/null || true
note '-- Logins anteriores (amostra):'
if have last; then last -F -w -n 35 2>/dev/null || true; fi
note '-- Entradas NOPASSWD do sudoers (revise concessões autorizadas):'
if have grep; then
  grep -nEH '^[[:space:]]*[^#[:space:]].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -n 70 || true
fi

section 'CHAVES SSH AUTORIZADAS E CONFIGURACAO DO SERVIDOR'
while IFS=: read -r user _ uid _ _ home shell; do
  [[ -n "$home" && "$home" == /* ]] || continue
  keyfile="${home%/}/.ssh/authorized_keys"
  if [[ -f "$keyfile" && ! -L "$keyfile" ]]; then
    note "Usuario: $user | arquivo: $keyfile"
    stat -c 'Permissoes=%a Proprietario=%U Alterado=%y' -- "$keyfile" 2>/dev/null || true
    if have ssh-keygen; then
      ssh-keygen -lf "$keyfile" 2>/dev/null | head -n 50 || true
    else
      note 'ssh-keygen indisponivel (chaves nao exibidas para preservar conteudo)'
    fi
    if [[ "$user" == root ]]; then
      alert REVISAO 'Chaves SSH autorizadas para root: validar fingerprints com inventario'
    fi
  fi
done < /etc/passwd
note '-- Politicas efetivas do sshd, quando disponivel:'
if have sshd; then
  sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|allowusers|allowgroups) ' || true
  config=$(sshd -T 2>/dev/null || true)
  if grep -qx 'permitrootlogin yes' <<< "$config"; then
    alert MEDIO 'sshd permite login remoto direto de root (configuracao de risco, nao prova de invasao)'
  fi
  if grep -qx 'permitemptypasswords yes' <<< "$config"; then
    alert ALTO 'sshd permite autenticacao com senha vazia'
  fi
else
  note 'sshd indisponivel; ignorando avaliacao da politica efetiva.'
fi

section 'AUTENTICACAO SSH - FALHAS E LOGINS'
SSHLOG="$OUT/ssh_eventos.txt"
: > "$SSHLOG"
if have journalctl; then
  journalctl -t sshd -t sshd-session --since "$DAYS days ago" -o short-iso --no-pager 2>/dev/null >> "$SSHLOG" || true
fi
# Fallback para sistemas que nao encaminham sshd ao journal. Arquivos .1 podem
# incluir registros anteriores a DAYS, portanto sao referencia complementar.
if [[ ! -s "$SSHLOG" ]]; then
  for logfile in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure.1; do
    if [[ -r "$logfile" ]]; then
      grep -Ei 'sshd|sshd-session' "$logfile" >> "$SSHLOG" 2>/dev/null || true
    fi
  done
  note 'Origem: /var/log/auth.log ou secure (se disponivel; logs rotacionados podem exceder a janela).'
else
  note 'Origem: journalctl (identificadores sshd e sshd-session).'
fi
F_COUNT=$(grep -Eic 'Failed password|Invalid user|authentication failure|maximum authentication attempts' "$SSHLOG" 2>/dev/null || true)
S_COUNT=$(grep -Eic 'Accepted (password|publickey|keyboard-interactive|gssapi)' "$SSHLOG" 2>/dev/null || true)
F_COUNT=${F_COUNT:-0}; S_COUNT=${S_COUNT:-0}
note "Falhas de autenticacao (eventos, podem se sobrepor): $F_COUNT"
note "Logins aceitos: $S_COUNT"
if (( F_COUNT >= 100 )); then
  alert ALTO "Volume alto de falhas de autenticacao SSH ($F_COUNT eventos); investigar origem e sucesso posterior"
elif (( F_COUNT >= 20 )); then
  alert MEDIO "Multiplas falhas de autenticacao SSH ($F_COUNT eventos); investigar se houve brute force"
fi
if grep -Eiq 'Accepted password for root from ' "$SSHLOG"; then
  alert MEDIO 'Login SSH com senha aceito para root: conferir IP e autorizacao'
fi
# IP que teve falha de senha e depois aparece em um login aceito: investigacao prioritária.
if [[ -s "$SSHLOG" ]]; then
  grep -E 'Failed password' "$SSHLOG" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort -u > "$OUT/ips_com_falha.txt" || true
  grep -E 'Accepted (password|publickey|keyboard-interactive|gssapi)' "$SSHLOG" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort -u > "$OUT/ips_com_sucesso.txt" || true
  matching_ips=$(comm -12 "$OUT/ips_com_falha.txt" "$OUT/ips_com_sucesso.txt" | head -n 10 || true)
  if [[ -n "$matching_ips" ]]; then
    note 'IP(s) com falha de senha e algum login aceito no periodo:'
    printf '%s\n' "$matching_ips"
    alert REVISAO 'IP(s) aparecem em tentativas SSH falhas e logins aceitos; confirmar se e atividade legitima'
  fi
fi
note '-- IPs encontrados em tentativas com senha falha:'
grep -Ei 'Failed password' "$SSHLOG" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -nr | head -n 25 || true
note '-- Logins aceitos (ultimos 100 registros; revisar IP/usuario/horario):'
grep -Ei 'Accepted (password|publickey|keyboard-interactive|gssapi)' "$SSHLOG" | tail -n 100 || true
note '-- Exemplos de falhas recentes (ultimos 70):'
grep -Ei 'Failed password|Invalid user|authentication failure|maximum authentication attempts' "$SSHLOG" | tail -n 70 || true

section 'PROCESSOS E EXECUTAVEIS EM EXECUCAO'
ps axo pid,ppid,user,stat,lstart,%cpu,%mem,comm,args --sort=-%cpu 2>/dev/null | head -n 110 || true
: > "$OUT/processos_suspeitos.txt"
for exe in /proc/[0-9]*/exe; do
  [[ -L "$exe" ]] || continue
  target=$(readlink "$exe" 2>/dev/null || true)
  [[ -n "$target" ]] || continue
  case "$target" in
    /tmp/*|/var/tmp/*|/dev/shm/*|*' (deleted)')
      pid=${exe#/proc/}; pid=${pid%/exe}
      printf 'PID=%s EXE=%s CMD=%s\n' "$pid" "$target" "$(ps -p "$pid" -o args= 2>/dev/null | head -c 300)" >> "$OUT/processos_suspeitos.txt" ;;
  esac
done
note '-- Processos executados em diretórios temporarios ou com executavel removido:'
limit_file "$OUT/processos_suspeitos.txt" 100
if [[ -s "$OUT/processos_suspeitos.txt" ]]; then
  alert MEDIO 'Processos executando de /tmp, /var/tmp, /dev/shm ou binarios removidos; revisar (atualizacoes podem gerar falsos positivos)'
fi

section 'CONEXOES DE REDE E PORTAS ABERTAS'
if have ss; then
  ss -lntup 2>/dev/null | head -n 130 || true
  note '-- Conexoes TCP estabelecidas (amostra):'
  ss -Htnp state established 2>/dev/null | head -n 140 || true
else
  note 'Comando ss nao encontrado (instale iproute2 caso queira coletar sockets).'
fi

section 'PERSISTENCIA: CRON, SYSTEMD E INICIALIZACAO'
note '-- Cron de sistema:'
for file in /etc/crontab /etc/cron.d/*; do
  if [[ -f "$file" && -r "$file" ]]; then
    note "Arquivo: $file"
    grep -nEv '^[[:space:]]*(#|$)' "$file" | head -n 65 || true
  fi
done
note '-- Crontabs de usuarios com shell interativo:'
if have crontab; then
  while IFS=: read -r user _ uid _ _ home shell; do
    if [[ "$uid" =~ ^[0-9]+$ ]] && { ((uid == 0 || uid >= 1000)) && [[ "$shell" != *nologin && "$shell" != */false ]]; }; then
      jobs=$(crontab -u "$user" -l 2>/dev/null || true)
      if [[ -n "$jobs" ]]; then note "Usuario: $user"; printf '%s\n' "$jobs" | grep -Ev '^[[:space:]]*(#|$)' | head -n 80 || true; fi
    fi
  done < /etc/passwd
fi
if have systemctl; then
  note '-- Servicos habilitados:'
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | head -n 125 || true
  note '-- Timers habilitados:'
  systemctl list-unit-files --type=timer --state=enabled --no-pager --no-legend 2>/dev/null | head -n 90 || true
fi
note '-- Arquivos de persistencia alterados recentemente:'
for dir in /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/init.d /etc/profile.d; do
  [[ -d "$dir" ]] || continue
  find "$dir" -xdev -type f -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | head -n 100 || true
done
for file in /etc/rc.local /etc/ld.so.preload; do
  if [[ -s "$file" ]]; then
    note "Arquivo presente e nao vazio: $file"
    stat -c 'Alterado=%y Permissoes=%a' "$file" 2>/dev/null || true
    if [[ "$file" == /etc/ld.so.preload ]]; then
      alert MEDIO '/etc/ld.so.preload nao vazio: verificar bibliotecas carregadas globalmente'
    fi
  fi
done
note '-- Indicadores de download/execucao codificada em cron ou units:'
if have grep; then
  suspicious=$(grep -rEnI --include='*.service' --include='*.timer' --include='*.conf' -E 'curl.{0,100}\|[[:space:]]*(sh|bash)|wget.{0,100}\|[[:space:]]*(sh|bash)|base64[[:space:]]+(-d|--decode)|/dev/tcp/' /etc/cron.d /etc/systemd/system 2>/dev/null | head -n 40 || true)
  if [[ -n "$suspicious" ]]; then
    printf '%s\n' "$suspicious"
    alert REVISAO 'Comandos potencialmente perigosos em cron/systemd; validar origem (pode ser automacao legitima)'
  fi
fi

section 'ARQUIVOS EXECUTAVEIS RECENTES EM AREAS TEMPORARIAS'
: > "$OUT/executaveis_temporarios.txt"
for dir in /tmp /var/tmp /dev/shm; do
  [[ -d "$dir" ]] || continue
  safe_timeout 35s find "$dir" -xdev -type f -mtime "-$DAYS" -perm /111 -printf '%TY-%Tm-%Td %TH:%TM %m %u %p\n' 2>/dev/null | head -n 100 >> "$OUT/executaveis_temporarios.txt" || true
done
limit_file "$OUT/executaveis_temporarios.txt" 100
if [[ -s "$OUT/executaveis_temporarios.txt" ]]; then
  alert REVISAO 'Executaveis recentes em /tmp, /var/tmp ou /dev/shm: revisar origem (nem todo executavel e malware)'
fi

section 'PERMISSOES SUID/SGID FORA DOS DIRETORIOS PADRAO'
: > "$OUT/suid_sgid_atipicos.txt"
for dir in /home /opt /tmp /var/tmp /dev/shm; do
  [[ -d "$dir" ]] || continue
  # Reduz falsos positivos: apenas binarios com bit de execucao, SUID/SGID e dono root.
  safe_timeout 35s find "$dir" -xdev -type f -user root -perm /111 \( -perm -4000 -o -perm -2000 \) -printf '%m %u %g %p\n' 2>/dev/null | head -n 60 >> "$OUT/suid_sgid_atipicos.txt" || true
done
limit_file "$OUT/suid_sgid_atipicos.txt" 100
if [[ -s "$OUT/suid_sgid_atipicos.txt" ]]; then
  alert MEDIO 'Arquivos SUID/SGID em /home, /opt ou diretorios temporarios; confirmar necessidade'
fi

section 'ALTERACOES RECENTES EM ARQUIVOS SENSIVEIS'
for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts /etc/ld.so.preload; do
  if [[ -e "$file" ]]; then
    stat -c '%y %a %U:%G %n' "$file" 2>/dev/null || true
  fi
done

section 'INTEGRIDADE DOS PACOTES INSTALADOS'
if ((DEEP)); then
  if have dpkg; then
    note 'Executando dpkg --verify (pode relatar mudancas administrativas legitimas):'
    safe_timeout 180s dpkg --verify 2>&1 | head -n 150 || true
    note 'Observacao: validacao contra banco de dados local, nao uma referencia externa confiavel.'
  elif have rpm; then
    note 'Executando rpm -Va (pode relatar mudancas administrativas legitimas):'
    safe_timeout 180s rpm -Va 2>&1 | head -n 150 || true
    note 'Observacao: validacao contra banco de dados local, nao uma referencia externa confiavel.'
  else
    note 'Nenhum gerenciador dpkg/rpm encontrado.'
  fi
else
  note 'Ignorado para manter a varredura rapida. Use --deep para verificar arquivos dos pacotes.'
fi

section 'RESUMO E ORIENTACOES'
for level in ALTO MEDIO REVISAO; do
  total=$(awk -F '\t' -v level="$level" '$1 == level {n++} END {print n+0}' "$ALERTS")
  note "$level: $total alerta(s)"
done
note 'ALTO/MEDIO/REVISAO nao sao prova de comprometimento; correlacione com mudancas autorizadas e logs.'
note 'Ausencia de alertas NAO comprova que o servidor esteja limpo (rootkit pode ocultar atividade).'
note 'Se houver incidente real: preserve logs/evidencias, restrinja o acesso pela camada de rede e acione resposta a incidentes.'
note "Relatorio principal: $REPORT"
note "Lista de alertas: $ALERTS"
note 'O relatorio pode incluir IPs, nomes de usuarios e argumentos de processos; compartilhe de forma segura.'

printf '\nAuditoria concluida.\nPasta: %s\nRelatorio: %s\nAlertas: %s\n' "$OUT" "$REPORT" "$ALERTS" >&3
printf 'Contagem: ' >&3
awk -F '\t' '{c[$1]++} END {printf "ALTO=%d MEDIO=%d REVISAO=%d\n", c["ALTO"], c["MEDIO"], c["REVISAO"]}' "$ALERTS" >&3