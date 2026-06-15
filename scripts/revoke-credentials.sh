#!/bin/bash
# =============================================================================
# revoke-credentials.sh
# Revoga credenciais IAM comprometidas: access keys, sessões de console e
# sessões assumidas de roles — com preservação de evidências antes da revogação
#
# Uso: ./revoke-credentials.sh --user-name nome-usuario [--access-key-id AKIAxxx]
#                               [--role-name nome-role] [--region sa-east-1] [--dry-run]
# Autor: Ricardo Neves Lougon — github.com/ricardolougon
# =============================================================================

set -euo pipefail

USER_NAME=""
ACCESS_KEY_ID=""
ROLE_NAME=""
REGION="sa-east-1"
DRY_RUN=false
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user-name)      USER_NAME="$2"; shift 2 ;;
    --access-key-id)  ACCESS_KEY_ID="$2"; shift 2 ;;
    --role-name)      ROLE_NAME="$2"; shift 2 ;;
    --region)         REGION="$2"; shift 2 ;;
    --dry-run)        DRY_RUN=true; shift ;;
    *) echo "Uso: $0 --user-name nome [--access-key-id AKIAxxx] [--role-name nome] [--region sa-east-1] [--dry-run]"; exit 1 ;;
  esac
done

[ -z "$USER_NAME" ] && [ -z "$ROLE_NAME" ] && { echo "ERRO: informe --user-name ou --role-name"; exit 1; }

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
EVIDENCE_DIR="/tmp/revoke-credentials-$INCIDENT_ID-$TIMESTAMP"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================================"
echo "  REVOGAÇÃO DE CREDENCIAIS — $INCIDENT_ID"
echo "  Usuário: ${USER_NAME:-N/A} | Role: ${ROLE_NAME:-N/A} | Dry-run: $DRY_RUN"
echo "  ATENÇÃO: Documentar uso desta ação no ticket de incidente"
echo "======================================================================"
echo ""

# -----------------------------------------------------------------------
# 1. Preservar estado atual ANTES de qualquer revogação
# -----------------------------------------------------------------------
echo "[ 1/5 ] Preservando estado atual das credenciais..."

if [ -n "$USER_NAME" ]; then
  aws iam list-access-keys --user-name "$USER_NAME" --region "$REGION" \
    > "$EVIDENCE_DIR/access-keys-antes.json" 2>/dev/null || echo "{}" > "$EVIDENCE_DIR/access-keys-antes.json"

  aws iam list-user-policies --user-name "$USER_NAME" --region "$REGION" \
    > "$EVIDENCE_DIR/inline-policies-antes.json" 2>/dev/null || echo "{}" > "$EVIDENCE_DIR/inline-policies-antes.json"

  aws iam list-attached-user-policies --user-name "$USER_NAME" --region "$REGION" \
    > "$EVIDENCE_DIR/attached-policies-antes.json" 2>/dev/null || echo "{}" > "$EVIDENCE_DIR/attached-policies-antes.json"

  echo "  ✓ Estado de $USER_NAME salvo em $EVIDENCE_DIR"
fi

if [ -n "$ROLE_NAME" ]; then
  aws iam list-role-policies --role-name "$ROLE_NAME" --region "$REGION" \
    > "$EVIDENCE_DIR/role-inline-policies-antes.json" 2>/dev/null || echo "{}" > "$EVIDENCE_DIR/role-inline-policies-antes.json"

  echo "  ✓ Estado da role $ROLE_NAME salvo em $EVIDENCE_DIR"
fi

# -----------------------------------------------------------------------
# 2. Desativar access key específica (se informada)
# -----------------------------------------------------------------------
echo ""
echo "[ 2/5 ] Tratando access key..."

if [ -n "$ACCESS_KEY_ID" ]; then
  if [ "$DRY_RUN" = true ]; then
    echo "  [DRY-RUN] Desativaria a access key $ACCESS_KEY_ID de $USER_NAME"
  else
    aws iam update-access-key \
      --user-name "$USER_NAME" \
      --access-key-id "$ACCESS_KEY_ID" \
      --status Inactive \
      --region "$REGION"
    echo "  ✓ Access key $ACCESS_KEY_ID desativada (status: Inactive)"
  fi

  # Listar outras keys ativas do mesmo usuário — podem precisar do mesmo tratamento
  echo ""
  echo "  Outras access keys do usuário $USER_NAME:"
  aws iam list-access-keys --user-name "$USER_NAME" --region "$REGION" \
    --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Status:Status,Criada:CreateDate}' \
    --output table
else
  echo "  Nenhuma access key especificada — pulando esta etapa"
fi

# -----------------------------------------------------------------------
# 3. Revogar sessões de console (forçar troca de senha)
# -----------------------------------------------------------------------
echo ""
echo "[ 3/5 ] Revogando sessões de console (se aplicável)..."

if [ -n "$USER_NAME" ]; then
  if [ "$DRY_RUN" = true ]; then
    echo "  [DRY-RUN] Redefiniria a senha de $USER_NAME com password-reset-required"
  else
    # Verificar se o usuário tem login profile (acesso ao console)
    if aws iam get-login-profile --user-name "$USER_NAME" --region "$REGION" >/dev/null 2>&1; then
      NEW_PASSWORD=$(openssl rand -base64 32)
      aws iam update-login-profile \
        --user-name "$USER_NAME" \
        --password "$NEW_PASSWORD" \
        --password-reset-required \
        --region "$REGION"
      echo "  ✓ Senha de console redefinida para $USER_NAME (troca obrigatória no próximo login)"
    else
      echo "  Usuário $USER_NAME não possui acesso ao console — pulando"
    fi
  fi
fi

# -----------------------------------------------------------------------
# 4. Revogar todas as sessões temporárias (DENY temporal baseado em TokenIssueTime)
# -----------------------------------------------------------------------
echo ""
echo "[ 4/5 ] Aplicando política de revogação temporal (EMERGENCY-REVOKE-ALL-SESSIONS)..."

REVOKE_POLICY_DOC='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {"aws:TokenIssueTime": "'$(date --iso-8601=seconds)'"}
    }
  }]
}'

if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Aplicaria política EMERGENCY-REVOKE-ALL-SESSIONS"
  [ -n "$USER_NAME" ] && echo "    → usuário: $USER_NAME"
  [ -n "$ROLE_NAME" ] && echo "    → role: $ROLE_NAME"
else
  if [ -n "$USER_NAME" ]; then
    aws iam put-user-policy \
      --user-name "$USER_NAME" \
      --policy-name "EMERGENCY-REVOKE-ALL-SESSIONS" \
      --policy-document "$REVOKE_POLICY_DOC" \
      --region "$REGION"
    echo "  ✓ Todas as sessões anteriores a $(date) revogadas para o usuário $USER_NAME"
  fi

  if [ -n "$ROLE_NAME" ]; then
    aws iam put-role-policy \
      --role-name "$ROLE_NAME" \
      --policy-name "EMERGENCY-REVOKE-ALL-SESSIONS" \
      --policy-document "$REVOKE_POLICY_DOC" \
      --region "$REGION"
    echo "  ✓ Todas as sessões anteriores a $(date) revogadas para a role $ROLE_NAME"
  fi
fi

# -----------------------------------------------------------------------
# 5. Coletar histórico recente de uso da credencial (CloudTrail)
# -----------------------------------------------------------------------
echo ""
echo "[ 5/5 ] Coletando histórico de uso (CloudTrail, últimos 7 dias)..."

LOOKUP_NAME="${USER_NAME:-$ROLE_NAME}"

if [ "$DRY_RUN" = false ]; then
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP_NAME" \
    --start-time "$(date -d '7 days ago' --iso-8601=seconds)" \
    --region "$REGION" \
    --output json > "$EVIDENCE_DIR/cloudtrail-$LOOKUP_NAME-$TIMESTAMP.json"

  echo "  ✓ Histórico salvo em $EVIDENCE_DIR/cloudtrail-$LOOKUP_NAME-$TIMESTAMP.json"
fi

# -----------------------------------------------------------------------
# Sumário
# -----------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  REVOGAÇÃO CONCLUÍDA"
echo ""
echo "  Usuário: ${USER_NAME:-N/A}"
echo "  Role: ${ROLE_NAME:-N/A}"
echo "  Access key tratada: ${ACCESS_KEY_ID:-N/A}"
echo "  Evidências preservadas em: $EVIDENCE_DIR"
echo ""
echo "  PRÓXIMOS PASSOS OBRIGATÓRIOS:"
echo "  1. Documentar ação no ticket $INCIDENT_ID"
echo "  2. Notificar CISO e DPO"
echo "  3. Investigar o que foi feito com a credencial antes da revogação"
echo "     (ver playbooks/credencial-comprometida.md, Fase 2)"
echo "  4. Avaliar impacto em dados pessoais — ver runbook/03-avaliacao-impacto-lgpd.md"
echo "  5. NÃO remover a política EMERGENCY-REVOKE-ALL-SESSIONS sem aprovação do CISO"
echo "  6. Após investigação concluída, prosseguir para erradicação:"
echo "     ver runbook/05-recuperacao-licoes.md, seção 'Credencial comprometida'"
if [ "$DRY_RUN" = true ]; then
  echo ""
  echo "  Modo dry-run — nenhuma alteração foi feita."
fi
echo "======================================================================"
