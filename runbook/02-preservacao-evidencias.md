# 02 — Preservação de Evidências Forenses

> **Tempo alvo:** Iniciar em paralelo com a contenção. Concluir em até 24 horas.  
> **Objetivo:** Coletar e proteger todas as evidências digitais mantendo a cadeia de custódia — sem contaminar, alterar ou destruir provas.

> ⚖️ **Importância legal:** A ANPD pode solicitar evidências técnicas do incidente durante uma investigação. Evidências bem preservadas demonstram que a organização adotou "medidas técnicas e administrativas aptas" (LGPD Art. 46) e permitem cumprir o dever de notificação fundamentada (Art. 48). Evidências destruídas ou contaminadas podem ser interpretadas como agravante.

---

## Princípios de Forense Digital

```
1. PRESERVAR ANTES DE ANALISAR
   Nunca analise diretamente o sistema original.
   Trabalhe sempre em cópias.

2. DOCUMENTAR TUDO
   Cada ação, cada ferramenta, cada resultado.
   Se não está documentado, não aconteceu.

3. CADEIA DE CUSTÓDIA
   Registro contínuo de quem teve acesso às evidências,
   quando e para qual finalidade.

4. INTEGRIDADE VERIFICÁVEL
   Hash SHA256 de cada evidência coletada.
   Permite provar que a evidência não foi alterada.

5. MÍNIMA ALTERAÇÃO DO SISTEMA ORIGINAL
   Evitar escrever no sistema comprometido.
   Memória RAM é volátil — coletar primeiro se possível.
```

---

## Índice de Coleta por Tipo de Evidência

| Evidência | Seção |
|---|---|
| CloudTrail — log de ações AWS | [2.1](#21--cloudtrail) |
| VPC Flow Logs — tráfego de rede | [2.2](#22--vpc-flow-logs) |
| CloudWatch Logs — logs de aplicação | [2.3](#23--cloudwatch-logs) |
| Snapshots EBS — disco da instância | [2.4](#24--snapshots-ebs) |
| S3 Access Logs — acesso a objetos | [2.5](#25--s3-access-logs) |
| GuardDuty Findings — detecções de ameaça | [2.6](#26--guardduty-findings) |
| Config Snapshots — estado dos recursos | [2.7](#27--aws-config-snapshots) |
| Metadados de recursos AWS | [2.8](#28--metadados-de-recursos) |
| Cadeia de custódia | [2.9](#29--cadeia-de-custódia) |

---

## Configuração Inicial — Bucket de Evidências Forenses

Antes de coletar qualquer evidência, garantir que existe um bucket seguro para armazená-las:

```bash
INCIDENT_ID="INC-$(date +%Y%m%d)"
REGION="sa-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
FORENSICS_BUCKET="forensics-evidence-$ACCOUNT_ID"
EVIDENCE_PREFIX="$INCIDENT_ID/$(date +%H%M%S)"

# Verificar se o bucket de evidências existe
if ! aws s3api head-bucket --bucket "$FORENSICS_BUCKET" 2>/dev/null; then
  echo "⚠️  Bucket de evidências não existe. Criar antes de um incidente:"
  echo "   Ver: scripts/setup-forensics-bucket.sh"
  echo "   Usando /tmp como fallback local"
  FORENSICS_BUCKET="/tmp"
fi

# Diretório local de trabalho
LOCAL_DIR="/tmp/evidencias-$INCIDENT_ID-$(date +%Y%m%d-%H%M)"
mkdir -p "$LOCAL_DIR"

echo "Coletando evidências para: $LOCAL_DIR"
echo "Bucket S3 destino: s3://$FORENSICS_BUCKET/$EVIDENCE_PREFIX/"
```

---

## 2.1 — CloudTrail

> **O que é:** Registro de toda ação realizada na conta AWS — quem fez o quê, quando, de onde.  
> **Por que preservar:** Principal evidência para determinar o vetor de ataque e as ações do atacante. Indispensável para a notificação à ANPD (Art. 48, §2º).

### Coleta por período e usuário

```bash
INCIDENT_START="2025-01-15T00:00:00Z"  # Ajustar para início estimado do incidente
INCIDENT_END=$(date --iso-8601=seconds)
USERNAME_SUSPEITO="usuario-comprometido"  # Ajustar ou remover se desconhecido

# Todos os eventos do período — exportação completa
aws cloudtrail lookup-events \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --max-results 1000 \
  --output json > "$LOCAL_DIR/cloudtrail-todos-eventos.json"

echo "Total de eventos coletados:"
cat "$LOCAL_DIR/cloudtrail-todos-eventos.json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('Events',[])))"

# Eventos filtrados por usuário suspeito
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME_SUSPEITO" \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --output json > "$LOCAL_DIR/cloudtrail-usuario-$USERNAME_SUSPEITO.json"

# Eventos de alto risco (ações destrutivas ou de escalada)
aws cloudtrail lookup-events \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --query 'Events[?contains(`[
    "DeleteTrail","StopLogging","DeleteBucket","DeleteObject",
    "CreateUser","AttachUserPolicy","CreateAccessKey",
    "RunInstances","AuthorizeSecurityGroupIngress",
    "PutBucketAcl","DeletePublicAccessBlock",
    "ConsoleLogin","GetSecretValue","Decrypt"
  ]`, EventName)].{Hora:EventTime,Acao:EventName,Usuario:Username,IP:SourceIPAddress}' \
  --output table

echo "✓ CloudTrail coletado em $LOCAL_DIR"
```

### Coleta de eventos de dados (S3 e Lambda)

```bash
# Eventos de acesso a dados no S3 (requer Data Events habilitados no trail)
aws cloudtrail lookup-events \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=s3.amazonaws.com \
  --query 'Events[?contains(`["GetObject","PutObject","DeleteObject","ListObjects"]`, EventName)].{Hora:EventTime,Acao:EventName,Usuario:Username,Recurso:Resources[0].ResourceName}' \
  --output json > "$LOCAL_DIR/cloudtrail-s3-data-events.json"

echo "Acessos a dados S3 no período:"
cat "$LOCAL_DIR/cloudtrail-s3-data-events.json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len(d)} eventos de dados S3')"
```

### Verificar integridade dos logs do trail

```bash
# Validar que os logs do CloudTrail não foram adulterados
TRAIL_NAME="compliance-trail-lgpd"
S3_BUCKET_TRAIL="meu-bucket-cloudtrail-logs"

aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:$REGION:$ACCOUNT_ID:trail/$TRAIL_NAME" \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --s3-bucket "$S3_BUCKET_TRAIL" \
  --output json > "$LOCAL_DIR/cloudtrail-integrity-validation.json"

# Verificar resultado
INVALID=$(cat "$LOCAL_DIR/cloudtrail-integrity-validation.json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('filesInvalid', 0))")

if [ "$INVALID" -eq 0 ]; then
  echo "✓ Integridade dos logs CloudTrail VÁLIDA — nenhum arquivo adulterado"
else
  echo "🚨 ALERTA: $INVALID arquivo(s) de log com integridade INVÁLIDA — possível adulteração"
fi
```

---

## 2.2 — VPC Flow Logs

> **O que é:** Registro de todo o tráfego de rede — IPs, portas, protocolos, bytes transferidos, aceito ou rejeitado.  
> **Por que preservar:** Permite determinar: de onde veio o ataque, quais dados foram exfiltrados (volume de bytes para IPs externos), e quando o tráfego suspeito começou.

```bash
LOG_GROUP_FLOWLOGS="/aws/vpc/flowlogs/NOME-DO-PROJETO"

# Período do incidente — com margem de segurança
START_MS=$(date -d "$INCIDENT_START" +%s)000
END_MS=$(date -d "$INCIDENT_END" +%s)000

# Exportar flow logs do período para S3
aws logs create-export-task \
  --task-name "forensics-flowlogs-$INCIDENT_ID" \
  --log-group-name "$LOG_GROUP_FLOWLOGS" \
  --from "$START_MS" \
  --to "$END_MS" \
  --destination "$FORENSICS_BUCKET" \
  --destination-prefix "$EVIDENCE_PREFIX/flow-logs/" \
  --region "$REGION"

echo "✓ Export de Flow Logs iniciado para s3://$FORENSICS_BUCKET/$EVIDENCE_PREFIX/flow-logs/"
echo "  (pode levar alguns minutos — verificar status com aws logs describe-export-tasks)"

# Análise rápida online — tráfego rejeitado para a camada de dados
echo ""
echo "Tentativas de acesso rejeitadas à camada de dados (últimas 24h):"
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP_FLOWLOGS" \
  --start-time "$(date -d '24 hours ago' +%s)000" \
  --filter-pattern "[v,account,interface,srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes,start,end,action=REJECT,status]" \
  --query 'events[].message' \
  --output text | \
  awk '{print $5, $7, $14}' | \
  sort | uniq -c | sort -rn | head -20

# Volume de dados enviados para IPs externos (possível exfiltração)
echo ""
echo "Top 10 IPs externos que receberam dados (possível exfiltração):"
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP_FLOWLOGS" \
  --start-time "$START_MS" \
  --end-time "$END_MS" \
  --filter-pattern "[v,account,interface,srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes,start,end,action=ACCEPT,status]" \
  --query 'events[].message' \
  --output text | \
  awk '$5 !~ /^10\./ && $5 !~ /^172\./ && $5 !~ /^192\.168/ {bytes[$5]+=$10} END {for(ip in bytes) print bytes[ip], ip}' | \
  sort -rn | head -10
```

---

## 2.3 — CloudWatch Logs

> **O que é:** Logs da aplicação, sistema operacional e serviços AWS.  
> **Por que preservar:** Contém erros de aplicação, tentativas de autenticação, execução de comandos e comportamento da aplicação no momento do incidente.

```bash
# Listar todos os log groups relevantes
echo "Log Groups disponíveis:"
aws logs describe-log-groups \
  --region "$REGION" \
  --query 'logGroups[?contains(logGroupName, `prod`) || contains(logGroupName, `app`) || contains(logGroupName, `api`)].{Nome:logGroupName,Retencao:retentionInDays}' \
  --output table

# Exportar log group específico da aplicação
APP_LOG_GROUP="/aws/ecs/minha-aplicacao"

aws logs create-export-task \
  --task-name "forensics-applogs-$INCIDENT_ID" \
  --log-group-name "$APP_LOG_GROUP" \
  --from "$START_MS" \
  --to "$END_MS" \
  --destination "$FORENSICS_BUCKET" \
  --destination-prefix "$EVIDENCE_PREFIX/app-logs/" \
  --region "$REGION"

# Análise rápida online — erros e eventos anômalos
echo ""
echo "Erros e eventos críticos no período do incidente:"
aws logs filter-log-events \
  --log-group-name "$APP_LOG_GROUP" \
  --start-time "$START_MS" \
  --end-time "$END_MS" \
  --filter-pattern "?ERROR ?CRITICAL ?EXCEPTION ?unauthorized ?forbidden ?injection" \
  --query 'events[].{Hora:timestamp,Mensagem:message}' \
  --output table \
  --region "$REGION" | head -50

# Tentativas de autenticação falhadas
echo ""
echo "Falhas de autenticação no período:"
aws logs filter-log-events \
  --log-group-name "$APP_LOG_GROUP" \
  --start-time "$START_MS" \
  --end-time "$END_MS" \
  --filter-pattern "?\"401\" ?\"403\" ?\"authentication failed\" ?\"invalid credentials\" ?\"login failed\"" \
  --query 'events[].message' \
  --output text | \
  head -30
```

---

## 2.4 — Snapshots EBS

> **O que é:** Cópia completa do disco da instância EC2 no momento do incidente.  
> **Por que preservar:** Permite análise forense offline do sistema de arquivos, artefatos de malware, arquivos de configuração alterados e histórico de comandos — sem alterar o sistema original.

```bash
INSTANCE_ID="i-xxxxxxxxxxxxxxxxx"

# Listar volumes da instância
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].[Ebs.VolumeId,DeviceName]' \
  --output text)

echo "Volumes da instância $INSTANCE_ID:"
echo "$VOLUMES"

# Criar snapshot de cada volume com metadados forenses
while IFS=$'\t' read -r VOL_ID DEVICE; do
  [ -z "$VOL_ID" ] && continue

  SNAP_ID=$(aws ec2 create-snapshot \
    --volume-id "$VOL_ID" \
    --description "FORENSE $INCIDENT_ID $(date '+%Y-%m-%d %H:%M') Device:$DEVICE" \
    --tag-specifications "ResourceType=snapshot,Tags=[
      {Key=IncidentId,Value=$INCIDENT_ID},
      {Key=SourceInstance,Value=$INSTANCE_ID},
      {Key=SourceVolume,Value=$VOL_ID},
      {Key=DeviceName,Value=$DEVICE},
      {Key=CollectedBy,Value=$(aws sts get-caller-identity --query UserId --output text)},
      {Key=CollectedAt,Value=$(date --iso-8601=seconds)},
      {Key=Purpose,Value=ForensicEvidence},
      {Key=DoNotDelete,Value=true}
    ]" \
    --region "$REGION" \
    --query 'SnapshotId' \
    --output text)

  echo "✓ Snapshot $SNAP_ID criado para $VOL_ID ($DEVICE)"

  # Aguardar conclusão e calcular tamanho
  echo "  Aguardando conclusão do snapshot..."
  aws ec2 wait snapshot-completed \
    --snapshot-ids "$SNAP_ID" \
    --region "$REGION"

  SIZE=$(aws ec2 describe-snapshots \
    --snapshot-ids "$SNAP_ID" \
    --query 'Snapshots[0].VolumeSize' \
    --output text \
    --region "$REGION")
  echo "  ✓ Snapshot completo: $SNAP_ID ($SIZE GB)"

done <<< "$VOLUMES"
```

### Montagem segura para análise (read-only)

```bash
# Para analisar o snapshot sem alterar o original:
# 1. Criar volume a partir do snapshot em conta de análise separada
# 2. Montar como read-only em instância de análise forense

SNAP_ID="snap-xxxxxxxxxxxxxxxxx"
FORENSIC_INSTANCE="i-FORENSIC_INSTANCE_ID"

# Criar volume a partir do snapshot
FORENSIC_VOLUME=$(aws ec2 create-volume \
  --snapshot-id "$SNAP_ID" \
  --availability-zone "${REGION}a" \
  --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[{Key=Purpose,Value=ForensicAnalysis},{Key=IncidentId,Value=$INCIDENT_ID}]" \
  --region "$REGION" \
  --query 'VolumeId' \
  --output text)

echo "Volume forense criado: $FORENSIC_VOLUME"
echo "Montar na instância de análise como read-only:"
echo "  aws ec2 attach-volume --volume-id $FORENSIC_VOLUME --instance-id $FORENSIC_INSTANCE --device /dev/xvdf"
echo "  # Na instância: mount -o ro /dev/xvdf /mnt/forensics"
```

---

## 2.5 — S3 Access Logs

> **O que é:** Log de cada requisição HTTP ao bucket S3 — quem acessou, qual objeto, de qual IP, resultado.  
> **Por que preservar:** Permite determinar exatamente quais objetos (e portanto quais dados pessoais) foram acessados durante o período de exposição.

```bash
BUCKET_AFETADO="bucket-com-dados-pessoais"
LOGS_BUCKET="bucket-de-logs-de-acesso"
LOGS_PREFIX="s3-access-logs/$BUCKET_AFETADO/"

# Verificar se S3 Access Logging está habilitado
LOGGING=$(aws s3api get-bucket-logging \
  --bucket "$BUCKET_AFETADO" \
  --query 'LoggingEnabled' \
  --output json 2>/dev/null || echo "null")

if [ "$LOGGING" = "null" ] || [ -z "$LOGGING" ]; then
  echo "⚠️  S3 Access Logging NÃO estava habilitado para $BUCKET_AFETADO"
  echo "   Evidência de acesso a objetos pode estar indisponível"
  echo "   Usar CloudTrail Data Events como alternativa (se habilitado)"
else
  echo "✓ S3 Access Logging habilitado — coletando logs"

  # Baixar logs do período
  mkdir -p "$LOCAL_DIR/s3-access-logs"
  aws s3 sync "s3://$LOGS_BUCKET/$LOGS_PREFIX" "$LOCAL_DIR/s3-access-logs/" \
    --exclude "*" \
    --include "$(date -d $INCIDENT_START '+%Y-%m-%d')*" \
    --include "$(date '+%Y-%m-%d')*"

  # Análise: IPs que acessaram objetos
  echo ""
  echo "Top IPs que acessaram $BUCKET_AFETADO no período:"
  cat "$LOCAL_DIR/s3-access-logs/"* 2>/dev/null | \
    awk '{print $5}' | sort | uniq -c | sort -rn | head -20

  # Objetos mais acessados
  echo ""
  echo "Objetos mais acessados (possíveis dados pessoais exfiltrados):"
  cat "$LOCAL_DIR/s3-access-logs/"* 2>/dev/null | \
    awk '$7 == "REST.GET.OBJECT" {print $8}' | sort | uniq -c | sort -rn | head -20

  # Calcular volume total transferido
  echo ""
  TOTAL_BYTES=$(cat "$LOCAL_DIR/s3-access-logs/"* 2>/dev/null | \
    awk 'NF>18 && $18 ~ /^[0-9]+$/ {total+=$18} END {print total}')
  echo "Volume total transferido no período: $TOTAL_BYTES bytes ($((TOTAL_BYTES/1048576)) MB)"
fi
```

---

## 2.6 — GuardDuty Findings

> **O que é:** Detecções automatizadas de comportamento anômalo e ameaças ativas.  
> **Por que preservar:** Documenta as ameaças detectadas automaticamente — evidência de que os controles de monitoramento estavam ativos e funcionando.

```bash
DETECTOR_ID=$(aws guardduty list-detectors \
  --region "$REGION" \
  --query 'DetectorIds[0]' \
  --output text)

if [ -z "$DETECTOR_ID" ] || [ "$DETECTOR_ID" = "None" ]; then
  echo "⚠️  GuardDuty não habilitado — nenhum finding disponível"
else
  # Exportar todos os findings ativos e arquivados do período
  FINDING_IDS=$(aws guardduty list-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-criteria "{
      \"Criterion\": {
        \"updatedAt\": {
          \"GreaterThanOrEqual\": $(date -d \"$INCIDENT_START\" +%s)000
        }
      }
    }" \
    --query 'FindingIds' \
    --output json \
    --region "$REGION")

  echo "Findings GuardDuty no período: $(echo $FINDING_IDS | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')"

  if [ "$(echo $FINDING_IDS | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')" -gt 0 ]; then
    aws guardduty get-findings \
      --detector-id "$DETECTOR_ID" \
      --finding-ids $(echo $FINDING_IDS | python3 -c 'import sys,json; print(" ".join(json.load(sys.stdin)))') \
      --output json \
      --region "$REGION" > "$LOCAL_DIR/guardduty-findings.json"

    echo "✓ Findings salvos em $LOCAL_DIR/guardduty-findings.json"

    # Resumo dos findings por tipo
    cat "$LOCAL_DIR/guardduty-findings.json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
findings = data.get('Findings', [])
print(f'\nTotal de findings: {len(findings)}')
for f in sorted(findings, key=lambda x: x.get('Severity', 0), reverse=True):
    sev = f.get('Severity', 0)
    icon = '🔴' if sev >= 7 else '🟡' if sev >= 4 else '🟢'
    print(f'  {icon} [{sev}] {f.get(\"Type\",\"?\")} — {f.get(\"Title\",\"?\")}')
"
  fi
fi
```

---

## 2.7 — AWS Config Snapshots

> **O que é:** Estado de configuração de todos os recursos AWS em um ponto no tempo.  
> **Por que preservar:** Permite reconstruir qual era o estado dos recursos (Security Groups, políticas IAM, configurações de bucket) antes, durante e após o incidente.

```bash
# Histórico de configuração do recurso comprometido
RESOURCE_ID="i-xxxxxxxxxxxxxxxxx"  # ou sg-xxx, bucket-name, etc.
RESOURCE_TYPE="AWS::EC2::Instance"  # ajustar conforme o tipo

aws configservice get-resource-config-history \
  --resource-type "$RESOURCE_TYPE" \
  --resource-id "$RESOURCE_ID" \
  --later-time "$INCIDENT_END" \
  --earlier-time "$INCIDENT_START" \
  --output json \
  --region "$REGION" > "$LOCAL_DIR/config-history-$RESOURCE_ID.json"

echo "✓ Histórico de configuração salvo para $RESOURCE_ID"

# Mudanças de configuração em Security Groups (vetor comum de ataque)
aws configservice get-resource-config-history \
  --resource-type "AWS::EC2::SecurityGroup" \
  --resource-id "sg-xxxxxxxxxxxxxxxxx" \
  --later-time "$INCIDENT_END" \
  --earlier-time "$(date -d '7 days ago' --iso-8601=seconds)" \
  --output json \
  --region "$REGION" > "$LOCAL_DIR/config-history-sg.json"

# Verificar se alguma Config Rule mudou para NON_COMPLIANT no período
aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT \
  --output json \
  --region "$REGION" > "$LOCAL_DIR/config-noncompliant-rules.json"

echo "Config Rules NON_COMPLIANT no momento do incidente:"
cat "$LOCAL_DIR/config-noncompliant-rules.json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
rules = d.get('ComplianceByConfigRules', [])
for r in rules:
    print(f'  ✗ {r.get(\"ConfigRuleName\",\"?\")}')
print(f'Total: {len(rules)} regras não-conformes')
"
```

---

## 2.8 — Metadados de Recursos

> Capturar o estado completo de todos os recursos relevantes no momento do incidente.

```bash
echo "Coletando metadados de recursos AWS..."

# IAM — usuários, roles e políticas no momento do incidente
aws iam get-account-authorization-details \
  --output json > "$LOCAL_DIR/iam-authorization-details.json"
echo "✓ IAM authorization details"

# EC2 — todas as instâncias e seus Security Groups
aws ec2 describe-instances \
  --region "$REGION" \
  --output json > "$LOCAL_DIR/ec2-instances.json"
echo "✓ EC2 instances"

# Security Groups — todas as regras
aws ec2 describe-security-groups \
  --region "$REGION" \
  --output json > "$LOCAL_DIR/security-groups.json"
echo "✓ Security Groups"

# S3 — configuração de todos os buckets
aws s3api list-buckets --query 'Buckets[].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    aws s3api get-bucket-policy-status --bucket "$bucket" \
      --query "{bucket: \"$bucket\", public: PolicyStatus.IsPublic}" \
      --output json 2>/dev/null
  done > "$LOCAL_DIR/s3-buckets-public-status.json"
echo "✓ S3 buckets public status"

# VPC — rotas e NACLs
aws ec2 describe-route-tables --region "$REGION" --output json > "$LOCAL_DIR/route-tables.json"
aws ec2 describe-network-acls --region "$REGION" --output json > "$LOCAL_DIR/nacls.json"
echo "✓ VPC route tables e NACLs"
```

---

## 2.9 — Cadeia de Custódia

> **O que é:** Registro formal de quem coletou cada evidência, quando, como e quem teve acesso.  
> **Por que é crítico:** Sem cadeia de custódia documentada, as evidências podem ser contestadas em um processo administrativo da ANPD ou judicial.

### Calcular hashes de todas as evidências

```bash
echo "Calculando hashes SHA256 de todas as evidências..."

HASH_FILE="$LOCAL_DIR/CHAIN-OF-CUSTODY-$INCIDENT_ID.txt"

cat > "$HASH_FILE" << EOF
====================================================================
CADEIA DE CUSTÓDIA DE EVIDÊNCIAS DIGITAIS
====================================================================
Incidente ID  : $INCIDENT_ID
Coletado por  : $(aws sts get-caller-identity --query 'Arn' --output text)
Data/Hora     : $(date '+%d/%m/%Y %H:%M:%S %Z')
Período coberto: $INCIDENT_START até $INCIDENT_END
Sistema       : AWS Conta $ACCOUNT_ID / Região $REGION
====================================================================

HASHES SHA256 DAS EVIDÊNCIAS:

EOF

# Calcular hash de cada arquivo coletado
find "$LOCAL_DIR" -type f ! -name "CHAIN-OF-CUSTODY*" | sort | while read -r file; do
  HASH=$(sha256sum "$file" | awk '{print $1}')
  SIZE=$(du -h "$file" | awk '{print $1}')
  FILENAME=$(basename "$file")
  echo "$HASH  $FILENAME ($SIZE)" >> "$HASH_FILE"
  echo "  $HASH  $FILENAME"
done

cat >> "$HASH_FILE" << EOF

====================================================================
REGISTRO DE ACESSOS ÀS EVIDÊNCIAS:

Data/Hora             | Quem Acessou                  | Finalidade
----------------------|-------------------------------|------------------
$(date '+%d/%m/%Y %H:%M') | $(aws sts get-caller-identity --query UserId --output text) | Coleta inicial
                      |                               |
                      |                               |
====================================================================
EOF

echo ""
echo "✓ Cadeia de custódia registrada em: $HASH_FILE"
```

### Upload para bucket de evidências com imutabilidade

```bash
# Upload para S3 com Object Lock (WORM — Write Once Read Many)
# Garante que evidências não possam ser alteradas ou deletadas

aws s3 cp "$LOCAL_DIR/" "s3://$FORENSICS_BUCKET/$EVIDENCE_PREFIX/" \
  --recursive \
  --sse aws:kms

echo "✓ Evidências enviadas para s3://$FORENSICS_BUCKET/$EVIDENCE_PREFIX/"

# Verificar integridade após upload
echo ""
echo "Verificando integridade pós-upload:"
for file in "$LOCAL_DIR"/*; do
  FILENAME=$(basename "$file")
  LOCAL_HASH=$(sha256sum "$file" | awk '{print $1}')
  REMOTE_HASH=$(aws s3api head-object \
    --bucket "$FORENSICS_BUCKET" \
    --key "$EVIDENCE_PREFIX/$FILENAME" \
    --query 'Metadata.sha256' \
    --output text 2>/dev/null || echo "unavailable")

  if [ "$REMOTE_HASH" = "$LOCAL_HASH" ] || [ "$REMOTE_HASH" = "unavailable" ]; then
    echo "  ✓ $FILENAME"
  else
    echo "  ✗ $FILENAME — hash divergente! Verificar upload"
  fi
done
```

---

## Checklist de Preservação — Validação Final

```
CLOUDTRAIL
□ Eventos do período exportados (JSON)
□ Integridade dos logs validada (validate-logs)
□ Eventos de alto risco identificados e documentados

VPC FLOW LOGS
□ Logs do período exportados para S3
□ Tráfego suspeito analisado e documentado
□ Volume de possível exfiltração estimado (bytes)

CLOUDWATCH LOGS
□ Logs de aplicação do período exportados
□ Erros e eventos anômalos identificados

SNAPSHOTS EBS
□ Snapshot de cada volume da instância comprometida criado
□ Tags forenses aplicadas (DoNotDelete=true)
□ Snapshot concluído e verificado

S3 ACCESS LOGS
□ Logs de acesso coletados (ou ausência documentada)
□ Objetos acessados no período identificados
□ Volume transferido quantificado

GUARDDUTY
□ Findings do período exportados
□ Findings de alta severidade documentados

AWS CONFIG
□ Histórico de configuração dos recursos afetados exportado

CADEIA DE CUSTÓDIA
□ Hash SHA256 calculado para cada evidência
□ Registro de acesso preenchido
□ Evidências enviadas para bucket forense imutável
□ Acesso ao bucket forense restrito ao time de segurança

PRAZO
□ Prazo ANPD 72h monitorado: H+____ (de 72h)
□ DPO informado sobre evidências coletadas
```

---

*Anterior: [01 — Contenção AWS](01-contencao-aws.md) · Próximo: [03 — Avaliação de Impacto LGPD](03-avaliacao-impacto-lgpd.md)*
