# Playbook — Ransomware em Instância EC2

> **Cenário:** GuardDuty, CloudWatch ou monitoramento de aplicação alertou criptografia massiva e repentina de arquivos em volume EBS, processos desconhecidos consumindo CPU/IO de forma anômala, extensões de arquivo alteradas em massa (ex.: `.locked`, `.encrypted`), ou nota de resgate (`ransom note`) detectada no sistema de arquivos.

**Tempo alvo de contenção:** 10 minutos  
**Criticidade LGPD:** 🔴 Alta — ransomware frequentemente acompanha exfiltração prévia de dados (modelo "double extortion"); presumir comprometimento de dados pessoais até que se prove o contrário

---

## Detecção — Sinais de Alerta

| Fonte | Finding ou sintoma que indica ransomware |
|---|---|
| GuardDuty | `Impact:EC2/SuspiciousFile` |
| GuardDuty | `Execution:EC2/MaliciousFile` |
| GuardDuty | `Behavior:EC2/TrafficVolumeUnusual` |
| CloudWatch | Pico súbito de IOPS / utilização de CPU sem correlação com carga de trabalho |
| CloudWatch | Espaço em disco caindo rapidamente (criação de cópias criptografadas) |
| Aplicação | Arquivos inacessíveis, extensões alteradas em massa |
| Usuário | Nota de resgate em diretórios (`README_DECRYPT.txt`, `HOW_TO_DECRYPT.html` etc.) |
| CloudTrail | `CreateSnapshot` ou `DeleteSnapshot` não reconhecidos — atacante tentando destruir backups |

---

## Fase 1 — Contenção: Isolar em 10 Minutos

> ⚠️ **Regra de ouro:** Ransomware em execução continua criptografando enquanto a instância estiver ligada e com acesso ao disco. Isolar a rede IMEDIATAMENTE — mas **NÃO desligar a instância**. A memória RAM pode conter a chave de criptografia, processos do ransomware e indicadores que se perdem com o shutdown.

### 1.1 Isolar a instância via Security Group de quarentena

```bash
INSTANCE_ID="i-xxxxxxxxxxxxxxxxx"
REGION="sa-east-1"

# Usar o script padronizado de isolamento (ver scripts/isolate-ec2.sh)
./scripts/isolate-ec2.sh --instance-id "$INSTANCE_ID" --region "$REGION"

# Isso já cria SG de quarentena, snapshot forense e coleta metadados/CloudTrail
```

### 1.2 Verificar se o ransomware está se propagando para outras instâncias

```bash
# Listar instâncias na mesma VPC/sub-rede que possam ter sido alcançadas
aws ec2 describe-instances \
  --filters "Name=vpc-id,Values=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].VpcId' --output text)" \
  --region "$REGION" \
  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,State.Name,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Verificar conexões de rede recentes da instância afetada via VPC Flow Logs
# (origem de movimento lateral costuma aparecer como tráfego SMB/RDP/SSH interno)
```

### 1.3 PROTEGER OS BACKUPS — prioridade crítica

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Listar snapshots existentes do(s) volume(s) da instância afetada
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' \
  --output text)

for VOL in $VOLUMES; do
  aws ec2 describe-snapshots \
    --filters "Name=volume-id,Values=$VOL" \
    --owner-ids "$ACCOUNT_ID" \
    --region "$REGION" \
    --query 'Snapshots[].[SnapshotId,StartTime,State]' \
    --output table
done

# Habilitar AWS Backup Vault Lock (se ainda não estiver ativo) para impedir
# exclusão de recovery points — ação preventiva permanente, não reversível
# durante o período de bloqueio. Avaliar com CISO antes de aplicar.
aws backup describe-backup-vault --backup-vault-name "Default" --region "$REGION"

# Verificar se o atacante tentou deletar snapshots recentemente (CloudTrail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteSnapshot \
  --start-time "$(date -d '24 hours ago' --iso-8601=seconds)" \
  --region "$REGION" \
  --query 'Events[].{Time:EventTime,User:Username,Event:EventName}' \
  --output table
```

---

## Fase 2 — Identificação da Variante e do Vetor (H+1 a H+8)

### 2.1 Coletar amostra da nota de resgate (sem executar nada)

```bash
EVIDENCE_DIR="/tmp/evidencias-ransomware-$(date +%Y%m%d-%H%M)"
mkdir -p "$EVIDENCE_DIR"

# Via SSM Run Command — ler (não executar) o conteúdo da nota de resgate
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["find / -iname \"*decrypt*\" -o -iname \"*ransom*\" 2>/dev/null | head -20","cat $(find / -iname \"*decrypt*\" 2>/dev/null | head -1) 2>/dev/null"]' \
  --region "$REGION" \
  --output text
```

> A nota de resgate frequentemente identifica a família de ransomware (ou um identificador único de campanha), o que orienta a busca por IOCs (Indicators of Compromise) conhecidos e por possíveis ferramentas públicas de descriptografia.

### 2.2 Timeline de execução — quando o ransomware começou a agir

```bash
# Eventos CloudTrail das últimas 72h relacionados à instância
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -d '72 hours ago' --iso-8601=seconds)" \
  --region "$REGION" \
  --output json > "$EVIDENCE_DIR/cloudtrail-instancia.json"

# CloudWatch Logs — buscar picos de CPU/IO que indicam início da criptografia em massa
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value="$INSTANCE_ID" \
  --start-time "$(date -d '72 hours ago' --iso-8601=seconds)" \
  --end-time "$(date --iso-8601=seconds)" \
  --period 300 \
  --statistics Average Maximum \
  --region "$REGION" \
  --query 'Datapoints[?Maximum > `80`]' \
  --output table
```

### 2.3 Vetor de entrada — como o ransomware chegou

```
□ RDP/SSH exposto à internet com credencial fraca? → verificar Security Groups (0.0.0.0/0 nas portas 22/3389)
□ Vulnerabilidade não corrigida (CVE conhecida)? → verificar versão de SO e patches via SSM Inventory
□ Phishing / execução de anexo malicioso? → verificar logs de e-mail e EDR, se disponível
□ Credencial IAM comprometida usada para mover lateralmente? → ver playbook credencial-comprometida.md
□ Supply chain (dependência/pacote comprometido)? → verificar histórico de instalação de pacotes
```

---

## Fase 3 — Preservação de Evidências (Antes de Qualquer Recuperação)

```bash
# Snapshot já foi criado na Fase 1 pelo isolate-ec2.sh — confirmar
aws ec2 describe-snapshots \
  --filters "Name=tag:IncidentId,Values=$INCIDENT_ID" \
  --region "$REGION" \
  --query 'Snapshots[].[SnapshotId,VolumeId,State,Progress]' \
  --output table

# Coletar memória RAM, se a ferramenta estiver disponível (ex.: via SSM + LiME)
# Memória contém: chave de criptografia em uso, processos do ransomware, conexões de rede ativas
# Caso não seja possível coletar memória, documentar essa limitação na ficha de registro

# Copiar logs do sistema antes de qualquer reinicialização
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["tar czf /tmp/logs-forense.tar.gz /var/log/ 2>/dev/null"]' \
  --region "$REGION"
```

> Ver `runbook/02-preservacao-evidencias.md` para o procedimento completo de preservação por tipo de evidência.

---

## Fase 4 — Decisão: Pagar, Restaurar ou Aguardar Descriptografador

```
Existe backup limpo anterior ao início da criptografia (confirmado pela timeline 2.2)?
│
├─ SIM → NÃO PAGAR. Proceder para restauração a partir de snapshot limpo.
│        → runbook/05-recuperacao-licoes.md, seção "Restaurar a partir de snapshot limpo"
│
└─ NÃO ou backup também comprometido →
         │
         ├─ Existe descriptografador público para a variante identificada?
         │   (consultar No More Ransom — nomoreransom.org)
         │   → SIM: testar em cópia forense, nunca no sistema original
         │
         └─ Decisão sobre pagamento de resgate:
             □ NUNCA é decisão técnica unilateral — envolve CISO, jurídico, alta direção
             □ Pagamento NÃO garante descriptografia nem elimina obrigação de notificar ANPD
             □ Pagamento a entidade sancionada pode configurar ilícito adicional — checar OFAC/listas de sanções
             □ Documentar toda a decisão e seus fundamentos na ficha de registro
```

---

## Fase 5 — Avaliação de Impacto LGPD

```
□ A instância afetada armazenava ou processava dados pessoais?
□ Há evidência de exfiltração ANTES da criptografia? (ver playbook exfiltracao-dados.md)
  → Ransomware moderno frequentemente exfiltra dados antes de criptografar
    (double extortion). Mesmo sem evidência de exfiltração confirmada,
    documentar a ausência de evidência — não presumir ausência de risco.
□ Os dados criptografados ficaram indisponíveis para os titulares ou para a operação?
  → Indisponibilidade de dados pessoais também é incidente de segurança sob a LGPD
    (Art. 46), mesmo sem confirmação de acesso por terceiros.

DECISÃO → seguir para runbook/03-avaliacao-impacto-lgpd.md
```

---

## Checklist Rápido — Resumo da Resposta

```
□ Instância isolada via SG de quarentena (NÃO desligada)
□ Snapshot forense de todos os volumes criado
□ Backups/snapshots existentes protegidos (verificar tentativas de DeleteSnapshot)
□ Nota de resgate coletada como evidência (sem executar nada)
□ Timeline de início da criptografia reconstituída via CloudWatch/CloudTrail
□ Vetor de entrada identificado ou hipóteses documentadas
□ Decisão sobre pagamento/restauração documentada e aprovada por CISO/jurídico
□ Avaliação de impacto LGPD iniciada — presumir exfiltração até prova em contrário
```

---

*Retornar ao índice: [README](../README.md) · Ver também: [Exfiltração de Dados](exfiltracao-dados.md) · [Isolamento EC2](../scripts/isolate-ec2.sh) · [Avaliação de Impacto LGPD](../runbook/03-avaliacao-impacto-lgpd.md)*
