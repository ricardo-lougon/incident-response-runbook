# 01 — Contenção Técnica na AWS

> **Tempo alvo:** Contenção inicial em até 8 horas após a detecção.  
> **Objetivo:** Parar o dano ativo, preservar evidências e impedir que o incidente se expanda — sem destruir provas.

> ⚠️ **Regra de ouro:** Contenção antes de erradicação. Nunca desligue, formate ou delete recursos comprometidos antes de criar evidências forenses. Um snapshot de 2 minutos pode ser a diferença entre provar o vetor de ataque para a ANPD ou não.

---

## Pré-requisito: Assumir a Role de Incident Responder

```bash
# A role IncidentResponder deve ser assumida com o ID do ticket
aws sts assume-role \
  --role-arn "arn:aws:iam::ACCOUNT_ID:role/IncidentResponderRole" \
  --role-session-name "INC-$(date +%Y%m%d)-SEU_NOME" \
  --duration-seconds 3600

# Exportar credenciais temporárias
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

echo "Sessão ativa por 1 hora. Documentar todas as ações no ticket de incidente."
```

---

## Índice de Contenções por Tipo

| Tipo de incidente | Seção |
|---|---|
| Instância EC2 comprometida | [1.1](#11--contenção-de-instância-ec2-comprometida) |
| Credencial IAM comprometida | [1.2](#12--contenção-de-credencial-iam-comprometida) |
| Bucket S3 exposto publicamente | [1.3](#13--contenção-de-bucket-s3-exposto) |
| Tráfego de rede suspeito / exfiltração | [1.4](#14--contenção-de-tráfego-suspeito) |
| RDS com acesso não autorizado | [1.5](#15--contenção-de-rds-comprometido) |
| Lambda ou ECS com comportamento anômalo | [1.6](#16--contenção-de-lambda--ecs-anômalo) |

---

## 1.1 — Contenção de Instância EC2 Comprometida

### Passo 1 — Snapshot forense (FAZER PRIMEIRO, SEMPRE)

```bash
INSTANCE_ID="i-xxxxxxxxxxxxxxxxx"
REGION="sa-east-1"

# Listar volumes da instância
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' \
  --output text)

echo "Volumes: $VOLUMES"

# Criar snapshot de cada volume ANTES de qualquer outra ação
for VOL in $VOLUMES; do
  SNAP_ID=$(aws ec2 create-snapshot \
    --volume-id "$VOL" \
    --description "FORENSE-INC-$(date +%Y%m%d-%H%M)-$INSTANCE_ID" \
    --tag-specifications "ResourceType=snapshot,Tags=[
      {Key=IncidentId,Value=INC-$(date +%Y%m%d)},
      {Key=InstanceId,Value=$INSTANCE_ID},
      {Key=Purpose,Value=ForensicEvidence},
      {Key=DoNotDelete,Value=true}
    ]" \
    --region "$REGION" \
    --query 'SnapshotId' \
    --output text)
  echo "✓ Snapshot criado: $SNAP_ID para volume $VOL"
done
```

### Passo 2 — Criar Security Group de quarentena

```bash
VPC_ID=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].VpcId' \
  --output text)

# Criar SG sem nenhuma regra de entrada ou saída
QUARANTINE_SG=$(aws ec2 create-security-group \
  --group-name "QUARANTINE-INC-$(date +%Y%m%d-%H%M)" \
  --description "Quarentena de incidente — NÃO REMOVER sem aprovação do CISO" \
  --vpc-id "$VPC_ID" \
  --region "$REGION" \
  --query 'GroupId' \
  --output text)

# Remover a regra de saída padrão (allow all outbound)
aws ec2 revoke-security-group-egress \
  --group-id "$QUARANTINE_SG" \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
  --region "$REGION" 2>/dev/null || true

echo "✓ SG de quarentena criado: $QUARANTINE_SG (zero entrada, zero saída)"
```

### Passo 3 — Salvar SGs atuais e aplicar quarentena

```bash
# Salvar SGs originais para restauração posterior
ORIGINAL_SGS=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
  --output text)

echo "SGs originais (guardar no ticket): $ORIGINAL_SGS"

# Aplicar quarentena
aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --groups "$QUARANTINE_SG" \
  --region "$REGION"

echo "✓ Instância $INSTANCE_ID isolada da rede"
echo "  SGs originais: $ORIGINAL_SGS"
echo "  SG quarentena: $QUARANTINE_SG"
```

### Passo 4 — Coletar metadados da instância

```bash
OUTPUT_DIR="/tmp/evidencias-ec2-$INSTANCE_ID-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

# Estado completo da instância no momento do incidente
aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --output json > "$OUTPUT_DIR/instance-state.json"

# Console output (últimas mensagens de boot/sistema)
aws ec2 get-console-output \
  --instance-id "$INSTANCE_ID" \
  --region "$REGION" \
  --output text > "$OUTPUT_DIR/console-output.txt"

# IAM instance profile (que permissões a instância tinha)
aws ec2 describe-iam-instance-profile-associations \
  --filters "Name=instance-id,Values=$INSTANCE_ID" \
  --region "$REGION" \
  --output json > "$OUTPUT_DIR/iam-profile.json"

echo "✓ Evidências salvas em $OUTPUT_DIR"
```

### Passo 5 — Coletar CloudTrail da instância

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -d '30 days ago' --iso-8601=seconds)" \
  --region "$REGION" \
  --output json > "$OUTPUT_DIR/cloudtrail-events.json"

# Ações suspeitas: criação de usuários, alteração de SGs, execução de comandos
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -d '7 days ago' --iso-8601=seconds)" \
  --query 'Events[?contains(`["RunInstances","ModifyInstanceAttribute","AssociateIamInstanceProfile"]`, EventName)].{Time:EventTime,Event:EventName,User:Username}' \
  --output table \
  --region "$REGION"

echo "✓ CloudTrail coletado"
```

---

## 1.2 — Contenção de Credencial IAM Comprometida

### Passo 1 — Identificar e desativar a credencial imediatamente

```bash
# Para access key comprometida
COMPROMISED_KEY="AKIAXXXXXXXXXXXXXXXX"
USERNAME="nome-do-usuario"

# DESATIVAR (não deletar ainda — manter para evidência)
aws iam update-access-key \
  --user-name "$USERNAME" \
  --access-key-id "$COMPROMISED_KEY" \
  --status Inactive

echo "✓ Access key $COMPROMISED_KEY desativada para $USERNAME"

# Verificar outras keys ativas do mesmo usuário
echo "Outras keys ativas do usuário:"
aws iam list-access-keys --user-name "$USERNAME" \
  --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,CreateDate]' \
  --output table
```

### Passo 2 — Revogar todas as sessões ativas

```bash
# Adicionar política inline que nega tudo para sessões emitidas antes de agora
# Força logout imediato de qualquer sessão ativa — console ou API
REVOKE_TIME=$(date --iso-8601=seconds)

aws iam put-user-policy \
  --user-name "$USERNAME" \
  --policy-name "EMERGENCY-REVOKE-$(date +%Y%m%d%H%M)" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$REVOKE_TIME\"
        }
      }
    }]
  }"

echo "✓ Todas as sessões de $USERNAME anteriores a $REVOKE_TIME revogadas"
```

### Passo 3 — Para role comprometida

```bash
ROLE_NAME="nome-da-role-comprometida"
REVOKE_TIME=$(date --iso-8601=seconds)

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "EMERGENCY-REVOKE-$(date +%Y%m%d%H%M)" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$REVOKE_TIME\"
        }
      }
    }]
  }"

echo "✓ Todas as sessões da role $ROLE_NAME anteriores a $REVOKE_TIME revogadas"
```

### Passo 4 — Investigar o que foi feito com a credencial

```bash
# Timeline completa das últimas 48h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME" \
  --start-time "$(date -d '48 hours ago' --iso-8601=seconds)" \
  --output json > "/tmp/cloudtrail-$USERNAME-$(date +%Y%m%d).json"

# Ações de alto risco: criação de usuários, anexação de políticas, acesso a S3
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$USERNAME" \
  --start-time "$(date -d '48 hours ago' --iso-8601=seconds)" \
  --query 'Events[?contains(`["CreateUser","AttachUserPolicy","AttachRolePolicy","CreateAccessKey","PutUserPolicy","GetObject","ListBuckets"]`, EventName)].{Hora:EventTime,Acao:EventName,Recurso:Resources}' \
  --output table

echo ""
echo "⚠️  Verificar manualmente:"
echo "  1. Foram criados novos usuários IAM?"
echo "  2. Foram acessados buckets S3 com dados pessoais?"
echo "  3. Foram criadas novas access keys para outros usuários?"
echo "  4. Foram alteradas políticas de segurança?"
```

### Passo 5 — Verificar recursos criados pelo atacante

```bash
# Instâncias EC2 criadas nas últimas 48h
echo "EC2 criadas recentemente:"
aws ec2 describe-instances \
  --region "sa-east-1" \
  --query 'Reservations[].Instances[?LaunchTime>=`'$(date -d '48 hours ago' --iso-8601=seconds)'`].[InstanceId,LaunchTime,InstanceType,Tags]' \
  --output table

# Usuários IAM criados recentemente
echo "Usuários IAM criados recentemente:"
aws iam list-users \
  --query 'Users[?CreateDate>=`'$(date -d '48 hours ago' --iso-8601=seconds)'`].[UserName,CreateDate]' \
  --output table

# Access keys criadas recentemente (possível backdoor)
echo "Access keys criadas recentemente (todas as contas):"
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[?CreateDate>=`'$(date -d '48 hours ago' --iso-8601=seconds)'`].[UserName,AccessKeyId,CreateDate,Status]' \
    --output text
done
```

---

## 1.3 — Contenção de Bucket S3 Exposto

### Passo 1 — Bloquear acesso público imediatamente

```bash
BUCKET_NAME="nome-do-bucket-exposto"

# Block public access — impedir qualquer acesso público
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,\
IgnorePublicAcls=true,\
BlockPublicPolicy=true,\
RestrictPublicBuckets=true"

echo "✓ Acesso público bloqueado para $BUCKET_NAME"
```

### Passo 2 — Remover ACL e política pública

```bash
# Redefinir ACL para private
aws s3api put-bucket-acl \
  --bucket "$BUCKET_NAME" \
  --acl private

# Verificar se há política pública e suspendê-la temporariamente
POLICY_STATUS=$(aws s3api get-bucket-policy-status \
  --bucket "$BUCKET_NAME" \
  --query 'PolicyStatus.IsPublic' \
  --output text 2>/dev/null || echo "false")

if [ "$POLICY_STATUS" = "true" ]; then
  # Salvar política atual antes de deletar
  aws s3api get-bucket-policy --bucket "$BUCKET_NAME" \
    --query 'Policy' --output text > "/tmp/s3-policy-backup-$BUCKET_NAME-$(date +%Y%m%d).json"
  
  aws s3api delete-bucket-policy --bucket "$BUCKET_NAME"
  echo "✓ Política pública removida (backup salvo)"
fi
```

### Passo 3 — Avaliar período de exposição

```bash
OUTPUT_DIR="/tmp/evidencias-s3-$BUCKET_NAME-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

# Quando o bucket ficou público? (CloudTrail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$BUCKET_NAME" \
  --start-time "$(date -d '90 days ago' --iso-8601=seconds)" \
  --query 'Events[?contains(`["PutBucketAcl","PutBucketPolicy","DeletePublicAccessBlock","PutPublicAccessBlock"]`, EventName)].{Hora:EventTime,Acao:EventName,Usuario:Username}' \
  --output table

# Listar objetos expostos
aws s3api list-objects-v2 \
  --bucket "$BUCKET_NAME" \
  --output json > "$OUTPUT_DIR/objects-list.json"

TOTAL=$(aws s3api list-objects-v2 --bucket "$BUCKET_NAME" \
  --query 'length(Contents)' --output text 2>/dev/null || echo "0")
echo "Total de objetos potencialmente expostos: $TOTAL"

# Lançar job Amazon Macie para classificar dados pessoais
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws macie2 create-classification-job \
  --name "incident-s3-$(date +%Y%m%d)-${BUCKET_NAME:0:30}" \
  --job-type ONE_TIME \
  --s3-job-definition "{
    \"bucketDefinitions\": [{
      \"accountId\": \"$ACCOUNT_ID\",
      \"buckets\": [\"$BUCKET_NAME\"]
    }]
  }" \
  --description "Classificação forense — incidente de exposição de bucket" 2>/dev/null && \
  echo "✓ Job Amazon Macie iniciado para classificar dados do bucket" || \
  echo "⚠️  Macie não disponível — classificar manualmente"
```

---

## 1.4 — Contenção de Tráfego Suspeito / Exfiltração

### Passo 1 — Identificar o recurso gerando tráfego suspeito

```bash
REGION="sa-east-1"

# Verificar findings do GuardDuty de exfiltração
aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text | \
xargs -I{} aws guardduty get-findings \
  --detector-id {} \
  --finding-ids $(aws guardduty list-findings \
    --detector-id {} \
    --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
    --query 'FindingIds' \
    --output text \
    --region "$REGION") \
  --query 'Findings[?contains(Type,`Exfiltration`) || contains(Type,`Trojan`) || contains(Type,`UnauthorizedAccess`)].{Type:Type,Resource:Resource.ResourceType,IP:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4}' \
  --output table \
  --region "$REGION"
```

### Passo 2 — Bloquear IP externo suspeito via NACL

```bash
VPC_ID="vpc-xxxxxxxxxx"
SUSPICIOUS_IP="1.2.3.4"

# Obter NACL da subnet afetada
NACL_ID=$(aws ec2 describe-network-acls \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'NetworkAcls[0].NetworkAclId' \
  --output text \
  --region "$REGION")

# Adicionar regra de deny para o IP suspeito (nível 1 — maior prioridade)
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --protocol "-1" \
  --rule-action deny \
  --cidr-block "$SUSPICIOUS_IP/32" \
  --ingress \
  --region "$REGION"

aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --protocol "-1" \
  --rule-action deny \
  --cidr-block "$SUSPICIOUS_IP/32" \
  --egress \
  --region "$REGION"

echo "✓ IP $SUSPICIOUS_IP bloqueado via NACL $NACL_ID (entrada e saída)"
```

### Passo 3 — Analisar VPC Flow Logs para quantificar exfiltração

```bash
LOG_GROUP="/aws/vpc/flowlogs/NOME-DO-PROJETO"
SUSPICIOUS_IP="1.2.3.4"
START_TIME=$(date -d '24 hours ago' +%s)000
END_TIME=$(date +%s)000

# Conexões para o IP suspeito — volume de dados enviados
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --filter-pattern "[version, account, interface, srcaddr, dstaddr=\"$SUSPICIOUS_IP\", srcport, dstport, protocol, packets, bytes, ...]" \
  --query 'events[].message' \
  --output text | \
  awk '{bytes+=$10} END {print "Total bytes enviados para IP suspeito:", bytes, "(" int(bytes/1048576) "MB)"}'
```

---

## 1.5 — Contenção de RDS Comprometido

### Passo 1 — Revogar acesso ao banco imediatamente

```bash
DB_INSTANCE="meu-banco-producao"
REGION="sa-east-1"

# Modificar o Security Group para remover qualquer acesso externo inesperado
# Criar SG de quarentena para o RDS
VPC_ID=$(aws rds describe-db-instances \
  --db-instance-identifier "$DB_INSTANCE" \
  --query 'DBInstances[0].DBSubnetGroup.VpcId' \
  --output text \
  --region "$REGION")

QUARANTINE_SG=$(aws ec2 create-security-group \
  --group-name "RDS-QUARANTINE-$(date +%Y%m%d%H%M)" \
  --description "Quarentena RDS — incidente ativo" \
  --vpc-id "$VPC_ID" \
  --region "$REGION" \
  --query 'GroupId' \
  --output text)

aws ec2 revoke-security-group-egress \
  --group-id "$QUARANTINE_SG" \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
  --region "$REGION" 2>/dev/null || true

# Aplicar ao RDS
aws rds modify-db-instance \
  --db-instance-identifier "$DB_INSTANCE" \
  --vpc-security-group-ids "$QUARANTINE_SG" \
  --apply-immediately \
  --region "$REGION"

echo "✓ RDS $DB_INSTANCE isolado com SG de quarentena: $QUARANTINE_SG"
```

### Passo 2 — Snapshot forense do RDS

```bash
SNAP_ID="forense-inc-$(date +%Y%m%d%H%M)-$DB_INSTANCE"

aws rds create-db-snapshot \
  --db-instance-identifier "$DB_INSTANCE" \
  --db-snapshot-identifier "$SNAP_ID" \
  --tags Key=IncidentId,Value="INC-$(date +%Y%m%d)" \
         Key=Purpose,Value=ForensicEvidence \
         Key=DoNotDelete,Value=true \
  --region "$REGION"

echo "✓ Snapshot RDS criado: $SNAP_ID"
```

### Passo 3 — Rotacionar credenciais do banco

```bash
SECRET_NAME="prod/database/credentials"

# Rotacionar imediatamente via Secrets Manager
aws secretsmanager rotate-secret \
  --secret-id "$SECRET_NAME" \
  --region "$REGION"

echo "✓ Credenciais do banco rotacionadas via Secrets Manager"
echo "⚠️  Reiniciar a aplicação para usar as novas credenciais"
```

---

## 1.6 — Contenção de Lambda / ECS Anômalo

### Lambda

```bash
FUNCTION_NAME="minha-funcao-lambda"
REGION="sa-east-1"

# Opção 1: Throttle total (zero concorrência — para a função completamente)
aws lambda put-function-concurrency \
  --function-name "$FUNCTION_NAME" \
  --reserved-concurrent-executions 0 \
  --region "$REGION"

echo "✓ Lambda $FUNCTION_NAME throttled (zero execuções concorrentes)"

# Opção 2: Desabilitar trigger (menos agressivo)
# Listar event source mappings
aws lambda list-event-source-mappings \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --query 'EventSourceMappings[].[UUID,EventSourceArn,State]' \
  --output table
```

### ECS Task / Service

```bash
CLUSTER_NAME="meu-cluster"
SERVICE_NAME="meu-servico-comprometido"
REGION="sa-east-1"

# Zerar desired count do service (para todas as tasks)
aws ecs update-service \
  --cluster "$CLUSTER_NAME" \
  --service "$SERVICE_NAME" \
  --desired-count 0 \
  --region "$REGION"

echo "✓ ECS Service $SERVICE_NAME com desired count = 0"

# Parar tasks em execução imediatamente
for TASK in $(aws ecs list-tasks \
  --cluster "$CLUSTER_NAME" \
  --service-name "$SERVICE_NAME" \
  --query 'taskArns[]' \
  --output text \
  --region "$REGION"); do
  aws ecs stop-task \
    --cluster "$CLUSTER_NAME" \
    --task "$TASK" \
    --reason "INCIDENTE DE SEGURANÇA — contenção em $(date)" \
    --region "$REGION"
  echo "  Stopped: $TASK"
done
```

---

## Checklist de Contenção — Validação Final

Antes de encerrar a fase de contenção, confirmar:

```
□ Snapshot/backup forense criado para todos os recursos afetados
□ Recurso comprometido isolado da rede (quarentena)
□ Credenciais comprometidas desativadas e sessões revogadas
□ SGs/NACLs originais documentados no ticket de incidente
□ CloudTrail do período do incidente exportado
□ VPC Flow Logs do período exportados
□ DPO notificado com resumo da contenção
□ CISO notificado com estimativa de impacto
□ Prazo de 72h para ANPD monitorado: H+____ (de 72h)
```

---

## Desfazer Contenção (Pós-Erradicação)

Após confirmar que o incidente foi erradicado e o recurso está limpo:

```bash
# Restaurar SGs originais de uma instância EC2
INSTANCE_ID="i-xxxxxxxxxxxxxxxxx"
ORIGINAL_SGS="sg-aaa sg-bbb sg-ccc"  # do ticket de incidente

aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --groups $ORIGINAL_SGS

# Deletar SG de quarentena
aws ec2 delete-security-group \
  --group-id "$QUARANTINE_SG"

echo "✓ Instância restaurada. Monitorar por 72h após restauração."
```

---

*Anterior: [00 — Classificação e Triagem](00-classificacao-triagem.md) · Próximo: [02 — Preservação de Evidências](02-preservacao-evidencias.md)*
