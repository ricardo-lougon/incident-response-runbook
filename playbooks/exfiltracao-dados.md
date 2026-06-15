# Playbook — Suspeita de Exfiltração de Dados

> **Cenário:** GuardDuty alertou tráfego de saída anômalo (volume, destino ou horário atípicos), VPC Flow Logs mostram grande volume de bytes para IP externo desconhecido, S3 Access Logs mostram série anômala de `GetObject`/`download` em curto intervalo, ou DLP/Macie identificou transferência de dados classificados como pessoais para fora do perímetro.

**Tempo alvo de contenção:** 20 minutos  
**Criticidade LGPD:** 🔴 Alta — exfiltração confirmada de dados pessoais é, por definição, incidente com risco relevante (LGPD Art. 48)

---

## Detecção — Sinais de Alerta

| Fonte | Finding ou sintoma que indica exfiltração |
|---|---|
| GuardDuty | `Exfiltration:S3/ObjectRead.Unusual` |
| GuardDuty | `Exfiltration:S3/AnomalousBehavior` |
| GuardDuty | `Behavior:EC2/TrafficVolumeUnusual` |
| GuardDuty | `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom` |
| VPC Flow Logs | Grande volume de bytes (`ACCEPT`) para IP externo fora de faixas conhecidas, especialmente fora do horário comercial |
| S3 Access Logs | Sequência de `GetObject` em centenas/milhares de chaves por um único principal em curto intervalo |
| CloudTrail | `GetObject`, `CopyObject`, `Select` (S3 Select) em volume atípico; `rds:CreateDBSnapshot` seguido de `ModifyDBSnapshotAttribute` (compartilhamento de snapshot RDS com outra conta) |
| Macie | Finding de dados sensíveis classificados em bucket com atividade de leitura recente anômala |

---

## Fase 1 — Contenção: Cortar o Canal de Saída (20 minutos)

> ⚠️ **Regra de ouro:** O objetivo imediato é interromper a transferência em curso sem destruir a evidência do que já saiu. Bloquear o canal de saída primeiro; investigar o volume já transferido depois.

### 1.1 Identificar o recurso de origem do tráfego

```bash
REGION="sa-east-1"

# Identificar a ENI/instância de origem a partir do finding do GuardDuty
aws guardduty get-findings \
  --detector-id "$(aws guardduty list-detectors --region $REGION --query 'DetectorIds[0]' --output text)" \
  --finding-ids "<finding-id>" \
  --region "$REGION" \
  --query 'Findings[].Resource'
```

### 1.2 Bloquear o destino externo via Network ACL (efeito imediato em toda a sub-rede)

```bash
SUBNET_ID="subnet-xxxxxxxx"
SUSPICIOUS_IP="203.0.113.50/32"

NACL_ID=$(aws ec2 describe-network-acls \
  --filters "Name=association.subnet-id,Values=$SUBNET_ID" \
  --region "$REGION" \
  --query 'NetworkAcls[0].NetworkAclId' --output text)

# Bloquear saída (egress) para o IP suspeito com prioridade alta (número baixo)
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 50 \
  --protocol -1 \
  --egress \
  --rule-action deny \
  --cidr-block "$SUSPICIOUS_IP" \
  --region "$REGION"

echo "✓ Bloqueio de saída para $SUSPICIOUS_IP aplicado na NACL $NACL_ID"
```

### 1.3 Se a origem for uma credencial/role — revogar imediatamente

```bash
# Ver playbook credencial-comprometida.md para o procedimento completo de
# desativação de access key ou revogação de sessão via política DENY temporal
```

### 1.4 Se a exfiltração for via S3 (acesso direto, não via instância)

```bash
BUCKET_NAME="nome-do-bucket-afetado"

# Bloquear acesso público imediatamente (caso aplicável)
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Revogar credenciais temporárias emitidas para o principal suspeito
# (ver playbook credencial-comprometida.md, seção de revogação por DENY temporal)
```

---

## Fase 2 — Quantificação do Volume Exfiltrado (H+1 a H+8)

### 2.1 Quantificar via VPC Flow Logs

```bash
EVIDENCE_DIR="/tmp/evidencias-exfiltracao-$(date +%Y%m%d-%H%M)"
mkdir -p "$EVIDENCE_DIR"

# Baixar e descompactar os Flow Logs do período relevante
aws s3 sync "s3://<bucket-flow-logs>/" "$EVIDENCE_DIR/flowlogs/" --region "$REGION"
cd "$EVIDENCE_DIR/flowlogs" && gunzip -f *.gz 2>/dev/null

# Somar bytes transferidos (ACCEPT) para o IP suspeito
grep "$SUSPICIOUS_IP" * | grep ACCEPT | awk '{sum+=$10} END {print "Total bytes:", sum, "(" sum/1024/1024/1024 " GB)"}'

# Janela temporal da exfiltração — primeiro e último timestamp de tráfego para o IP
grep "$SUSPICIOUS_IP" * | grep ACCEPT | awk '{print $11}' | sort -n | head -1 | xargs -I{} date -d @{}
grep "$SUSPICIOUS_IP" * | grep ACCEPT | awk '{print $11}' | sort -n | tail -1 | xargs -I{} date -d @{}
```

### 2.2 Quantificar via S3 Access Logs (se aplicável)

```bash
LOGS_BUCKET="nome-do-bucket-de-logs"
LOG_PREFIX="s3-access-logs/$BUCKET_NAME/"

aws s3 sync "s3://$LOGS_BUCKET/$LOG_PREFIX" "$EVIDENCE_DIR/s3-access-logs/" --region "$REGION"

# Listar todos os objetos baixados pelo principal suspeito, com timestamps
cd "$EVIDENCE_DIR/s3-access-logs"
grep "GetObject" * | grep "<principal-suspeito>" | awk '{print $4, $8, $9}' | sort > objetos-baixados.txt

echo "Total de objetos potencialmente exfiltrados:"
wc -l < objetos-baixados.txt
```

### 2.3 Cruzar objetos exfiltrados com classificação de dados pessoais (Macie)

```bash
# Se ainda não houver job Macie para o bucket, criar (ver playbook s3-bucket-exposto.md, 2.4)
aws macie2 list-classification-jobs \
  --filter-criteria '{"includes":{"simpleCriterion":[{"comparator":"CONTAINS","key":"name","values":["incident"]}]}}' \
  --region "$REGION" \
  --query 'items[].{Nome:name,Status:jobStatus}' \
  --output table

# Cruzar a lista de objetos exfiltrados (2.2) com os findings do Macie para
# determinar quantos dos objetos baixados continham dados pessoais
```

### 2.4 Verificar exfiltração via snapshot RDS compartilhado

```bash
# Snapshots RDS compartilhados com outra conta AWS são um vetor de exfiltração
# silenciosa — verificar se algum snapshot recente teve atributos de
# compartilhamento modificados
aws rds describe-db-snapshot-attributes \
  --db-snapshot-identifier "<snapshot-id>" \
  --region "$REGION"

# Se 'restore' contiver um Account ID desconhecido, a exfiltração ocorreu
# via cópia completa do banco de dados para outra conta
```

---

## Fase 3 — Preservação de Evidências

```bash
# 1. Salvar todos os artefatos da Fase 2
echo "Evidências consolidadas em $EVIDENCE_DIR"

# 2. Salvar configuração de rede no momento do incidente
aws ec2 describe-network-acls --network-acl-ids "$NACL_ID" --region "$REGION" \
  > "$EVIDENCE_DIR/nacl-state.json"

# 3. Upload para bucket forense com Object Lock
FORENSICS_BUCKET="forensics-evidence-$(aws sts get-caller-identity --query Account --output text)"
aws s3 cp "$EVIDENCE_DIR/" "s3://$FORENSICS_BUCKET/incident-exfil-$(date +%Y%m%d)/" --recursive

echo "✓ Evidências preservadas e enviadas ao bucket forense"
```

> Ver `runbook/02-preservacao-evidencias.md` para o procedimento completo, especialmente as seções 2.2 (VPC Flow Logs) e 2.5 (S3 Access Logs).

---

## Fase 4 — Avaliação de Impacto e Decisão de Notificação

```
Os objetos/registros exfiltrados continham dados pessoais? (cruzamento com Macie, 2.3)
│
├─ NÃO → Documentar conclusão técnica e fundamentação. Avaliar com jurídico
│        se ainda assim há obrigação de notificação (ex.: segredo
│        empresarial, dados de terceiros não-titulares).
│
└─ SIM → Quantificar:
         □ Número de registros/titulares afetados: __________
         □ Categorias de dados (comuns/sensíveis/financeiros/crianças): __________
         □ Volume total exfiltrado: __________ GB
         □ Janela temporal da exfiltração: de __________ até __________

         → NOTIFICAÇÃO À ANPD PROVAVELMENTE OBRIGATÓRIA
         → Prosseguir para runbook/03-avaliacao-impacto-lgpd.md
         → Em paralelo, runbook/04-notificacao-anpd.md (gestão do prazo de 72h)
```

---

## Checklist Rápido — Resumo da Resposta

```
□ Canal de saída bloqueado (NACL e/ou revogação de credencial)
□ Origem do tráfego identificada (instância, role, usuário)
□ Volume exfiltrado quantificado (VPC Flow Logs e/ou S3 Access Logs)
□ Janela temporal da exfiltração reconstituída
□ Objetos exfiltrados cruzados com classificação de dados pessoais (Macie)
□ Snapshots RDS verificados quanto a compartilhamento indevido
□ Evidências preservadas em bucket forense
□ Avaliação de impacto LGPD e notificação ANPD iniciadas (se dados pessoais confirmados)
```

---

*Retornar ao índice: [README](../README.md) · Ver também: [Credencial Comprometida](credencial-comprometida.md) · [Bucket S3 Exposto](s3-bucket-exposto.md) · [Avaliação de Impacto LGPD](../runbook/03-avaliacao-impacto-lgpd.md)*
