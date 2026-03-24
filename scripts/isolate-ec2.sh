#!/bin/bash
# =============================================================================
# isolate-ec2.sh
# Isola uma instância EC2 comprometida: quarentena de rede + snapshot forense
#
# Uso: ./isolate-ec2.sh --instance-id i-xxxxxxxxxx [--region sa-east-1] [--dry-run]
# Autor: Ricardo Neves Lougon — github.com/ricardolougon
# =============================================================================

set -euo pipefail

INSTANCE_ID=""
REGION="sa-east-1"
DRY_RUN=false
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance-id) INSTANCE_ID="$2"; shift 2 ;;
    --region)      REGION="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=true; shift ;;
    *) echo "Uso: $0 --instance-id i-xxx [--region sa-east-1] [--dry-run]"; exit 1 ;;
  esac
done

[ -z "$INSTANCE_ID" ] && { echo "ERRO: --instance-id obrigatório"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')

echo "======================================================================"
echo "  ISOLAMENTO DE INSTÂNCIA EC2 — $INCIDENT_ID"
echo "  Instância: $INSTANCE_ID | Região: $REGION | Dry-run: $DRY_RUN"
echo "  ATENÇÃO: Documentar uso desta ação no ticket de incidente"
echo "======================================================================"
echo ""

# -----------------------------------------------------------------------
# 1. Coletar informações da instância antes de qualquer ação
# -----------------------------------------------------------------------
echo "[ 1/5 ] Coletando informações da instância..."

INSTANCE_INFO=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0]' \
  --output json)

CURRENT_SGS=$(echo "$INSTANCE_INFO" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sgs = [sg['GroupId'] for sg in d.get('SecurityGroups', [])]
print(' '.join(sgs))
")
VPC_ID=$(echo "$INSTANCE_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('VpcId',''))")
VOLUMES=$(echo "$INSTANCE_INFO" | python3 -c "
import sys, json
d = json.load(sys.stdin)
vols = [v['Ebs']['VolumeId'] for v in d.get('BlockDeviceMappings', []) if 'Ebs' in v]
print(' '.join(vols))
")

echo "  VPC: $VPC_ID"
echo "  Security Groups atuais: $CURRENT_SGS"
echo "  Volumes EBS: $VOLUMES"
echo ""

# Salvar estado original
echo "$INSTANCE_INFO" > "/tmp/pre-isolation-state-$INSTANCE_ID-$TIMESTAMP.json"
echo "  Estado original salvo em /tmp/pre-isolation-state-$INSTANCE_ID-$TIMESTAMP.json"

# -----------------------------------------------------------------------
# 2. Criar Security Group de quarentena (sem tráfego entrada/saída)
# -----------------------------------------------------------------------
echo ""
echo "[ 2/5 ] Criando Security Group de quarentena..."

if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Criaria SG de quarentena em VPC $VPC_ID"
  QUARANTINE_SG="sg-DRY-RUN-ONLY"
else
  QUARANTINE_SG=$(aws ec2 create-security-group \
    --group-name "QUARANTINE-$INCIDENT_ID-$TIMESTAMP" \
    --description "Quarentena de incidente $INCIDENT_ID — NÃO REMOVER sem aprovação do CISO" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" \
    --query 'GroupId' \
    --output text)

  # Remover a regra de saída padrão (0.0.0.0/0)
  aws ec2 revoke-security-group-egress \
    --group-id "$QUARANTINE_SG" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
    --region "$REGION" 2>/dev/null || true

  echo "  ✓ SG de quarentena criado: $QUARANTINE_SG (sem regras de entrada/saída)"
fi

# -----------------------------------------------------------------------
# 3. Aplicar quarentena (substituir todos os SGs pelo de quarentena)
# -----------------------------------------------------------------------
echo ""
echo "[ 3/5 ] Aplicando isolamento de rede..."

if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Substituiria SGs [$CURRENT_SGS] por [$QUARANTINE_SG]"
else
  aws ec2 modify-instance-attribute \
    --instance-id "$INSTANCE_ID" \
    --groups "$QUARANTINE_SG" \
    --region "$REGION"

  echo "  ✓ Security Groups substituídos — instância isolada da rede"
  echo "  ⚠️  Security Groups originais: $CURRENT_SGS (salvar para restauração)"
fi

# -----------------------------------------------------------------------
# 4. Snapshot forense de todos os volumes
# -----------------------------------------------------------------------
echo ""
echo "[ 4/5 ] Criando snapshots forenses..."

for VOLUME_ID in $VOLUMES; do
  echo "  Snapshot do volume $VOLUME_ID..."
  
  if [ "$DRY_RUN" = true ]; then
    echo "  [DRY-RUN] Criaria snapshot de $VOLUME_ID"
  else
    SNAPSHOT_ID=$(aws ec2 create-snapshot \
      --volume-id "$VOLUME_ID" \
      --description "FORENSE-$INCIDENT_ID-$TIMESTAMP" \
      --tag-specifications "ResourceType=snapshot,Tags=[{Key=IncidentId,Value=$INCIDENT_ID},{Key=InstanceId,Value=$INSTANCE_ID},{Key=Purpose,Value=ForensicEvidence},{Key=DoNotDelete,Value=true}]" \
      --region "$REGION" \
      --query 'SnapshotId' \
      --output text)
    
    echo "  ✓ Snapshot criado: $SNAPSHOT_ID (marcado como evidência forense)"
  fi
done

# -----------------------------------------------------------------------
# 5. Coletar logs pré-isolamento
# -----------------------------------------------------------------------
echo ""
echo "[ 5/5 ] Coletando logs do CloudTrail para o período..."

if [ "$DRY_RUN" = false ]; then
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue="$INSTANCE_ID" \
    --start-time "$(date -d '7 days ago' --iso-8601=seconds)" \
    --region "$REGION" \
    --output json > "/tmp/cloudtrail-$INSTANCE_ID-$TIMESTAMP.json"
  
  echo "  ✓ Logs CloudTrail salvos em /tmp/cloudtrail-$INSTANCE_ID-$TIMESTAMP.json"
fi

# -----------------------------------------------------------------------
# Sumário
# -----------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  ISOLAMENTO CONCLUÍDO"
echo ""
echo "  Instância: $INSTANCE_ID"
echo "  SG de quarentena: $QUARANTINE_SG"
echo "  SGs originais (para restauração): $CURRENT_SGS"
echo ""
echo "  PRÓXIMOS PASSOS OBRIGATÓRIOS:"
echo "  1. Documentar ação no ticket $INCIDENT_ID"
echo "  2. Notificar CISO e DPO"
echo "  3. Iniciar análise forense ANTES de qualquer reinicialização"
echo "  4. Avaliar impacto em dados pessoais — ver runbook/03-avaliacao-impacto-lgpd.md"
echo "  5. NÃO restaurar SGs originais sem aprovação do CISO"
if [ "$DRY_RUN" = true ]; then
  echo ""
  echo "  Modo dry-run — nenhuma alteração foi feita."
fi
echo "======================================================================"
