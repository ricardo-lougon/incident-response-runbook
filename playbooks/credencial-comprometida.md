# Playbook — Credencial IAM Comprometida

> **Cenário:** GuardDuty alertou acesso de IP suspeito/malicioso, ou access key foi vazada em repositório público (GitHub, etc.), ou comportamento anômalo detectado no CloudTrail.

**Tempo alvo de contenção:** 15 minutos  
**Criticidade LGPD:** Depende do que a credencial podia acessar

---

## Detecção — Sinais de Alerta

| Fonte | Finding que indica credencial comprometida |
|---|---|
| GuardDuty | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` |
| GuardDuty | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` |
| GuardDuty | `Recon:IAMUser/MaliciousIPCaller` |
| GuardDuty | `CredentialAccess:IAMUser/AnomalousBehavior` |
| CloudTrail | Login console de país/IP não usual |
| CloudTrail | `CreateUser`, `AttachUserPolicy` por usuário que não é admin |
| GitHub Alert | Secret scanning — access key detectada em commit público |

---

## Fase 1 — Contenção: Revogar em 15 Minutos

### 1.1 Se for uma access key (programática)
```bash
KEY_ID="AKIAXXXXXXXXXXXXXXXX"
USERNAME="nome-do-usuario"

# PASSO 1: Desativar imediatamente (não deletar ainda)
aws iam update-access-key \
  --user-name "$USERNAME" \
  --access-key-id "$KEY_ID" \
  --status Inactive

echo "✓ Access key $KEY_ID desativada"

# PASSO 2: Verificar outras keys ativas do mesmo usuário
aws iam list-access-keys --user-name "$USERNAME"

# PASSO 3: Verificar se o usuário criou outros usuários ou recursos nas últimas horas
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME" \
  --start-time "$(date -d '24 hours ago' --iso-8601=seconds)" \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table
```

### 1.2 Se for uma sessão de console
```bash
USERNAME="nome-do-usuario"

# Forçar logout invalidando a senha (requer redefinição no próximo login)
aws iam update-login-profile \
  --user-name "$USERNAME" \
  --password "$(openssl rand -base64 32)" \
  --password-reset-required

# Revogar todas as sessões ativas (attach inline policy de deny)
aws iam put-user-policy \
  --user-name "$USERNAME" \
  --policy-name "EMERGENCY-REVOKE-ALL-SESSIONS" \
  --policy-document '{
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

echo "✓ Todas as sessões anteriores a $(date) revogadas para $USERNAME"
```

### 1.3 Se for uma role comprometida
```bash
ROLE_NAME="nome-da-role"

# Revogar todas as sessões assumidas desta role
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "EMERGENCY-REVOKE-ALL-SESSIONS" \
  --policy-document '{
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
```

---

## Fase 2 — Investigação (H+1 até H+4)

### 2.1 O que foi feito com a credencial comprometida?
```bash
USERNAME="nome-do-usuario"
START_TIME="$(date -d '7 days ago' --iso-8601=seconds)"

# Timeline completa de ações da credencial
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME" \
  --start-time "$START_TIME" \
  --output json | python3 -c "
import sys, json
events = json.load(sys.stdin)['Events']
for e in sorted(events, key=lambda x: x['EventTime']):
    print(f\"{e['EventTime']} | {e['EventName']} | {e.get('EventSource','')} | {e.get('Resources','')}\")
"
```

### 2.2 Recursos criados ou modificados
```bash
# Verificar se foram criados usuários, roles ou políticas
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME" \
  --query 'Events[?contains(EventName,`Create`) || contains(EventName,`Attach`) || contains(EventName,`Put`)].{Time:EventTime,Action:EventName}' \
  --output table

# Verificar se foram acessados dados em S3
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME" \
  --query 'Events[?EventSource==`s3.amazonaws.com`].{Time:EventTime,Action:EventName,Resource:Resources}' \
  --output table
```

### 2.3 Avaliar impacto em dados pessoais
```
□ A credencial tinha acesso a buckets S3 com dados pessoais?
  → Verificar IAM policies do usuário/role + logs de acesso ao S3

□ A credencial tinha acesso a RDS com dados pessoais?
  → Verificar CloudTrail por eventos rds:* e tentativas de conexão

□ Dados foram exfiltrados? (volume anormal de GetObject, downloads)
  → Verificar S3 Access Logs + VPC Flow Logs por tráfego de saída suspeito
```

---

## Fase 3 — Limpeza e Hardening

```bash
# 1. Deletar a access key comprometida (após confirmação de inativação)
aws iam delete-access-key \
  --user-name "$USERNAME" \
  --access-key-id "$KEY_ID"

# 2. Remover política de revogação de emergência
aws iam delete-user-policy \
  --user-name "$USERNAME" \
  --policy-name "EMERGENCY-REVOKE-ALL-SESSIONS"

# 3. Criar nova access key (somente se necessário e com novo processo seguro de distribuição)
# aws iam create-access-key --user-name "$USERNAME"

# 4. Revisar e reduzir permissões do usuário/role
# Verificar IAM Access Advisor para remover permissões nunca usadas
aws iam generate-service-last-accessed-details \
  --arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):user/$USERNAME"
```

---

## Decisão de Notificação LGPD

```
A credencial tinha acesso a dados pessoais?
│
├─ NÃO → Sem obrigação de notificação LGPD (documentar conclusão)
│
└─ SIM → Há evidência de que dados pessoais foram acessados/exfiltrados?
         │
         ├─ SIM → Notificação ANPD obrigatória → [04-notificacao-anpd.md]
         │
         └─ NÃO confirmado → Avaliar com DPO e jurídico
                              Princípio da precaução: notificação preventiva recomendada
```

---

*Retornar ao índice: [README](../README.md) · Ver também: [Notificação ANPD](../runbook/04-notificacao-anpd.md)*
