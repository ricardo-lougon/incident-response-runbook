#!/bin/bash
# =============================================================================
# collect-forensic-evidence.sh
# Coleta consolidada de evidências forenses de um incidente: CloudTrail,
# VPC Flow Logs, CloudWatch Logs, snapshots EBS, S3 Access Logs, GuardDuty
# Findings, AWS Config e metadados de recursos — com hash SHA256 e cadeia
# de custódia.
#
# Uso: ./collect-forensic-evidence.sh --incident-id INC-20260615-1200
#                                      [--instance-id i-xxxxxxxxxx]
#                                      [--bucket-name nome-bucket]
#                                      [--region sa-east-1] [--days 7]
# Autor: Ricardo Neves Lougon — github.com/ricardolougon
# =============================================================================

set -euo pipefail

INCIDENT_ID=""
INSTANCE_ID=""
BUCKET_NAME=""
REGION="sa-east-1"
DAYS=7

while [[ $# -gt 0 ]]; do
  case "$1" in
    --incident-id) INCIDENT_ID="$2"; shift 2 ;;
    --instance-id) INSTANCE_ID="$2"; shift 2 ;;
    --bucket-name) BUCKET_NAME="$2"; shift 2 ;;
    --region)      REGION="$2"; shift 2 ;;
    --days)        DAYS="$2"; shift 2 ;;
    *) echo "Uso: $0 --incident-id INC-xxx [--instance-id i-xxx] [--bucket-name nome] [--region sa-east-1] [--days 7]"; exit 1 ;;
  esac
done

[ -z "$INCIDENT_ID" ] && { echo "ERRO: --incident-id obrigatório"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
EVIDENCE_DIR="/tmp/forensic-evidence-$INCIDENT_ID-$TIMESTAMP"
START_TIME="$(date -d "$DAYS days ago" --iso-8601=seconds)"
FORENSICS_BUCKET="forensics-evidence-$ACCOUNT_ID"

mkdir -p "$EVIDENCE_DIR"/{cloudtrail,vpc-flow-logs,cloudwatch-logs,ebs-snapshots,s3-access-logs,guardduty,config,metadata}

echo "======================================================================"
echo "  COLETA DE EVIDÊNCIAS FORENSES — $INCIDENT_ID"
echo "  Período: $START_TIME até agora ($DAYS dias)"
echo "  Diretório local: $EVIDENCE_DIR"
echo "======================================================================"
echo ""

# -----------------------------------------------------------------------
# 1. CloudTrail
# -----------------------------------------------------------------------
echo "[ 1/8 ] CloudTrail — registro de ações na conta..."

if [ -n "$INSTANCE_ID" ]; then
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue="$INSTANCE_ID" \
    --start-time "$START_TIME" \
    --region "$REGION" \
    --output json > "$EVIDENCE_DIR/cloudtrail/eventos-instancia.json"
  echo "  ✓ Eventos relacionados à instância $INSTANCE_ID salvos"
fi

if [ -n "$BUCKET_NAME" ]; then
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue="$BUCKET_NAME" \
    --start-time "$START_TIME" \
    --region "$REGION" \
    --output json > "$EVIDENCE_DIR/cloudtrail/eventos-bucket.json"
  echo "  ✓ Eventos relacionados ao bucket $BUCKET_NAME salvos"
fi

# Verificar integridade do trail (validação de log file)
aws cloudtrail describe-trails --region "$REGION" \
  --query 'trailList[].{Nome:Name,LogValidation:LogFileValidationEnabled,Bucket:S3BucketName}' \
  --output json > "$EVIDENCE_DIR/cloudtrail/trails-config.json"
echo "  ✓ Configuração dos trails salva"

# -----------------------------------------------------------------------
# 2. VPC Flow Logs
# -----------------------------------------------------------------------
echo ""
echo "[ 2/8 ] VPC Flow Logs — tráfego de rede..."

aws ec2 describe-flow-logs --region "$REGION" \
  --query 'FlowLogs[].{FlowLogId:FlowLogId,ResourceId:ResourceId,Destination:LogDestination,Status:FlowLogStatus}' \
  --output json > "$EVIDENCE_DIR/vpc-flow-logs/flow-logs-config.json"

# Identificar bucket de destino dos flow logs e sincronizar (se configurado)
FLOWLOG_BUCKET=$(aws ec2 describe-flow-logs --region "$REGION" \
  --query 'FlowLogs[0].LogDestination' --output text 2>/dev/null | sed 's#arn:aws:s3:::##')

if [ -n "$FLOWLOG_BUCKET" ] && [ "$FLOWLOG_BUCKET" != "None" ]; then
  echo "  Sincronizando logs do bucket $FLOWLOG_BUCKET (pode levar alguns minutos)..."
  aws s3 sync "s3://$FLOWLOG_BUCKET/" "$EVIDENCE_DIR/vpc-flow-logs/raw/" --region "$REGION" --quiet || true
  echo "  ✓ Flow logs sincronizados"
else
  echo "  Nenhum destino S3 de Flow Logs configurado — registrar essa lacuna na ficha"
fi

# -----------------------------------------------------------------------
# 3. CloudWatch Logs
# -----------------------------------------------------------------------
echo ""
echo "[ 3/8 ] CloudWatch Logs — aplicação e sistema..."

aws logs describe-log-groups --region "$REGION" \
  --query 'logGroups[].{Nome:logGroupName,Retencao:retentionInDays}' \
  --output json > "$EVIDENCE_DIR/cloudwatch-logs/log-groups.json"
echo "  ✓ Lista de log groups salva — exportar grupos relevantes manualmente via export task se necessário"

# -----------------------------------------------------------------------
# 4. Snapshots EBS
# -----------------------------------------------------------------------
echo ""
echo "[ 4/8 ] Snapshots EBS — estado dos volumes..."

aws ec2 describe-snapshots \
  --owner-ids "$ACCOUNT_ID" \
  --filters "Name=tag:IncidentId,Values=$INCIDENT_ID" \
  --region "$REGION" \
  --query 'Snapshots[].{SnapshotId:SnapshotId,VolumeId:VolumeId,State:State,StartTime:StartTime}' \
  --output json > "$EVIDENCE_DIR/ebs-snapshots/snapshots-incidente.json"
echo "  ✓ Snapshots marcados com IncidentId=$INCIDENT_ID listados"

# -----------------------------------------------------------------------
# 5. S3 Access Logs
# -----------------------------------------------------------------------
echo ""
echo "[ 5/8 ] S3 Access Logs — requisições ao bucket..."

if [ -n "$BUCKET_NAME" ]; then
  LOGGING_CONFIG=$(aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null || echo "{}")
  echo "$LOGGING_CONFIG" > "$EVIDENCE_DIR/s3-access-logs/logging-config.json"

  TARGET_BUCKET=$(echo "$LOGGING_CONFIG" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('LoggingEnabled',{}).get('TargetBucket',''))" 2>/dev/null || echo "")
  TARGET_PREFIX=$(echo "$LOGGING_CONFIG" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('LoggingEnabled',{}).get('TargetPrefix',''))" 2>/dev/null || echo "")

  if [ -n "$TARGET_BUCKET" ]; then
    aws s3 sync "s3://$TARGET_BUCKET/$TARGET_PREFIX" "$EVIDENCE_DIR/s3-access-logs/raw/" --region "$REGION" --quiet || true
    echo "  ✓ S3 Access Logs sincronizados de $TARGET_BUCKET/$TARGET_PREFIX"
  else
    echo "  S3 Access Logging não estava habilitado para $BUCKET_NAME — registrar essa lacuna na ficha"
  fi
else
  echo "  Nenhum bucket informado — pulando"
fi

# -----------------------------------------------------------------------
# 6. GuardDuty Findings
# -----------------------------------------------------------------------
echo ""
echo "[ 6/8 ] GuardDuty Findings — detecções de ameaça..."

DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")

if [ -n "$DETECTOR_ID" ] && [ "$DETECTOR_ID" != "None" ]; then
  FINDING_IDS=$(aws guardduty list-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-criteria "{\"Criterion\":{\"updatedAt\":{\"Gte\":$(date -d "$START_TIME" +%s)000}}}" \
    --region "$REGION" \
    --query 'FindingIds' --output json)

  echo "$FINDING_IDS" > "$EVIDENCE_DIR/guardduty/finding-ids.json"

  COUNT=$(echo "$FINDING_IDS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
  if [ "$COUNT" -gt 0 ]; then
    aws guardduty get-findings \
      --detector-id "$DETECTOR_ID" \
      --finding-ids $(echo "$FINDING_IDS" | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)))") \
      --region "$REGION" \
      --output json > "$EVIDENCE_DIR/guardduty/findings-detalhados.json"
    echo "  ✓ $COUNT findings do período coletados"
  else
    echo "  Nenhum finding no período"
  fi
else
  echo "  GuardDuty não está habilitado nesta região — registrar essa lacuna na ficha"
fi

# -----------------------------------------------------------------------
# 7. AWS Config Snapshots
# -----------------------------------------------------------------------
echo ""
echo "[ 7/8 ] AWS Config — histórico de configuração dos recursos..."

if [ -n "$INSTANCE_ID" ]; then
  aws configservice get-resource-config-history \
    --resource-type "AWS::EC2::Instance" \
    --resource-id "$INSTANCE_ID" \
    --region "$REGION" \
    --output json > "$EVIDENCE_DIR/config/historico-instancia.json" 2>/dev/null || \
    echo "  AWS Config não está habilitado ou sem histórico para $INSTANCE_ID"
fi

if [ -n "$BUCKET_NAME" ]; then
  aws configservice get-resource-config-history \
    --resource-type "AWS::S3::Bucket" \
    --resource-id "$BUCKET_NAME" \
    --region "$REGION" \
    --output json > "$EVIDENCE_DIR/config/historico-bucket.json" 2>/dev/null || \
    echo "  AWS Config não está habilitado ou sem histórico para $BUCKET_NAME"
fi
echo "  ✓ Histórico de configuração coletado (quando disponível)"

# -----------------------------------------------------------------------
# 8. Metadados de recursos AWS
# -----------------------------------------------------------------------
echo ""
echo "[ 8/8 ] Metadados de recursos..."

if [ -n "$INSTANCE_ID" ]; then
  aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
    --output json > "$EVIDENCE_DIR/metadata/instancia.json"
fi

if [ -n "$BUCKET_NAME" ]; then
  {
    aws s3api get-bucket-acl --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null || echo "{}"
  } > "$EVIDENCE_DIR/metadata/bucket-acl.json"
  {
    aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null || echo "{}"
  } > "$EVIDENCE_DIR/metadata/bucket-policy.json"
fi
echo "  ✓ Metadados coletados"

# -----------------------------------------------------------------------
# Cadeia de custódia — hash SHA256 de todos os arquivos coletados
# -----------------------------------------------------------------------
echo ""
echo "Gerando hashes SHA256 (cadeia de custódia)..."

CUSTODY_FILE="$EVIDENCE_DIR/CADEIA_DE_CUSTODIA.txt"
{
  echo "Cadeia de Custódia — Incidente $INCIDENT_ID"
  echo "Coleta realizada em: $(date)"
  echo "Coletado por: $(aws sts get-caller-identity --query Arn --output text)"
  echo "Período coberto: $START_TIME até $(date --iso-8601=seconds)"
  echo ""
  echo "Hashes SHA256:"
  find "$EVIDENCE_DIR" -type f ! -name "CADEIA_DE_CUSTODIA.txt" -exec sha256sum {} \;
} > "$CUSTODY_FILE"

echo "  ✓ Cadeia de custódia gerada em $CUSTODY_FILE"

# -----------------------------------------------------------------------
# Upload para bucket forense (Object Lock)
# -----------------------------------------------------------------------
echo ""
echo "Enviando evidências ao bucket forense ($FORENSICS_BUCKET)..."

if aws s3api head-bucket --bucket "$FORENSICS_BUCKET" --region "$REGION" 2>/dev/null; then
  aws s3 cp "$EVIDENCE_DIR/" "s3://$FORENSICS_BUCKET/$INCIDENT_ID/" --recursive --region "$REGION"
  echo "  ✓ Evidências enviadas para s3://$FORENSICS_BUCKET/$INCIDENT_ID/"
else
  echo "  ⚠️  Bucket forense $FORENSICS_BUCKET não encontrado."
  echo "      Criar com versionamento + Object Lock antes do próximo incidente:"
  echo "      aws s3api create-bucket --bucket $FORENSICS_BUCKET --region $REGION \\"
  echo "        --create-bucket-configuration LocationConstraint=$REGION --object-lock-enabled-for-bucket"
fi

# -----------------------------------------------------------------------
# Sumário
# -----------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  COLETA DE EVIDÊNCIAS CONCLUÍDA"
echo ""
echo "  Incident ID: $INCIDENT_ID"
echo "  Diretório local: $EVIDENCE_DIR"
echo "  Cadeia de custódia: $CUSTODY_FILE"
echo ""
echo "  PRÓXIMOS PASSOS OBRIGATÓRIOS:"
echo "  1. Registrar cada item coletado na tabela 'Evidências Coletadas' da"
echo "     ficha-registro-incidente.md, com o hash correspondente"
echo "  2. Anotar qualquer lacuna identificada (Flow Logs/Access Logs/GuardDuty"
echo "     não habilitados) como item de hardening pós-incidente"
echo "  3. Restringir acesso ao bucket forense apenas à equipe de investigação"
echo "  4. Prosseguir com a análise — ver runbook/02-preservacao-evidencias.md"
echo "======================================================================"
