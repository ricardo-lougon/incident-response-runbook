# Playbook — Bucket S3 Público com Dados Pessoais

> **Cenário:** Amazon Macie ou GuardDuty alertou que um bucket S3 contendo dados pessoais está publicamente acessível. Ou foi detectado acesso massivo anômalo a um bucket.

**Tempo alvo de contenção:** 30 minutos  
**Criticidade LGPD:** 🔴 Alta — dado pessoal potencialmente exposto na internet

---

## Fase 1 — Contenção Imediata (0–30 min)

### 1.1 Bloquear acesso público IMEDIATAMENTE
```bash
BUCKET_NAME="nome-do-bucket-afetado"

# Bloquear TODO acesso público ao bucket
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "✓ Acesso público bloqueado para $BUCKET_NAME"
```

### 1.2 Verificar e remover ACL pública
```bash
# Verificar ACL atual
aws s3api get-bucket-acl --bucket "$BUCKET_NAME"

# Se houver AllUsers ou AuthenticatedUsers na ACL, remover
aws s3api put-bucket-acl \
  --bucket "$BUCKET_NAME" \
  --acl private
```

### 1.3 Verificar se existe política de bucket com acesso público
```bash
# Verificar status de política pública
aws s3api get-bucket-policy-status --bucket "$BUCKET_NAME"

# Se IsPublic = true, suspender a política
aws s3api delete-bucket-policy --bucket "$BUCKET_NAME"
# ATENÇÃO: isso remove toda a política — recriar corretamente depois
```

---

## Fase 2 — Avaliação do Impacto (30 min – 4h)

### 2.1 Quais objetos foram expostos?
```bash
# Listar todos os objetos do bucket com tamanho e data de modificação
aws s3api list-objects-v2 \
  --bucket "$BUCKET_NAME" \
  --query 'Contents[].{Key:Key,Size:Size,LastModified:LastModified}' \
  --output table > /tmp/objetos-expostos-$(date +%Y%m%d).txt

echo "Total de objetos:"
aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --query 'length(Contents)' --output text
```

### 2.2 Quando o bucket ficou público? (CloudTrail)
```bash
# Buscar quando a configuração de acesso público foi alterada
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$BUCKET_NAME" \
  --start-time "$(date -d '30 days ago' --iso-8601=seconds)" \
  --query 'Events[?contains(EventName,`PutBucketAcl`) || contains(EventName,`PutBucketPolicy`) || contains(EventName,`DeletePublicAccessBlock`)].{Time:EventTime,User:Username,Event:EventName}' \
  --output table
```

### 2.3 Quem acessou os objetos? (S3 Access Logs)
```bash
# Se S3 Access Logging estiver habilitado — verificar o bucket de logs
LOGS_BUCKET="nome-do-bucket-de-logs"
LOG_PREFIX="s3-access-logs/$BUCKET_NAME/"

# Baixar logs do período de exposição
aws s3 sync "s3://$LOGS_BUCKET/$LOG_PREFIX" /tmp/s3-access-logs/

# Analisar IPs que acessaram
cat /tmp/s3-access-logs/* | awk '{print $5}' | sort | uniq -c | sort -rn | head -20
```

### 2.4 Os objetos contêm dados pessoais? (Amazon Macie)
```bash
# Criar job Macie para classificar os objetos do bucket
aws macie2 create-classification-job \
  --name "incident-$(date +%Y%m%d)-$BUCKET_NAME" \
  --job-type ONE_TIME \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "'$(aws sts get-caller-identity --query Account --output text)'",
      "buckets": ["'$BUCKET_NAME'"]
    }]
  }' \
  --description "Classificação forense pós-incidente"
```

---

## Fase 3 — Preservação de Evidências

```bash
EVIDENCE_DIR="/tmp/evidencias-s3-$(date +%Y%m%d-%H%M)"
mkdir -p "$EVIDENCE_DIR"

# 1. Salvar configuração atual do bucket
aws s3api get-bucket-acl --bucket "$BUCKET_NAME" > "$EVIDENCE_DIR/acl.json"
aws s3api get-bucket-policy --bucket "$BUCKET_NAME" > "$EVIDENCE_DIR/policy.json" 2>/dev/null || echo "{}" > "$EVIDENCE_DIR/policy.json"
aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" > "$EVIDENCE_DIR/encryption.json"
aws s3api get-public-access-block --bucket "$BUCKET_NAME" > "$EVIDENCE_DIR/public-access-block.json"

# 2. Salvar lista completa de objetos
aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --output json > "$EVIDENCE_DIR/objects-list.json"

# 3. Salvar logs CloudTrail do bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$BUCKET_NAME" \
  --start-time "$(date -d '90 days ago' --iso-8601=seconds)" \
  --output json > "$EVIDENCE_DIR/cloudtrail-events.json"

echo "✓ Evidências preservadas em $EVIDENCE_DIR"
echo "  IMPORTANTE: Copiar para bucket de evidências forenses imutável"

# 4. Upload para bucket forense (com Object Lock)
FORENSICS_BUCKET="bucket-evidencias-forenses"
aws s3 cp "$EVIDENCE_DIR/" "s3://$FORENSICS_BUCKET/incident-s3-$(date +%Y%m%d)/" --recursive
```

---

## Fase 4 — Avaliação Legal e Decisão de Notificação

Responder antes de H+24:

```
□ O bucket contém dados pessoais? (resultado Macie)
□ Há evidência de acesso por IPs externos? (S3 Access Logs)
□ Período de exposição: ____ dias/horas
□ Número estimado de registros pessoais expostos: ______
□ Categoria dos dados: ( ) comuns ( ) sensíveis

DECISÃO:
□ Notificar ANPD? → Se sim: iniciar [04-notificacao-anpd.md]
□ Notificar titulares? → Se sim: usar [comunicado-titular.md]
□ Notificar BCB (se IF)? → Se sim: usar canal BCB
```

---

## Fase 5 — Hardening Pós-Incidente

```bash
# 1. Aplicar política de bucket segura (HTTPS obrigatório + sem acesso público)
aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyHTTP",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::'"$BUCKET_NAME"'", "arn:aws:s3:::'"$BUCKET_NAME"'/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}'

# 2. Habilitar versionamento (se não estiver ativo)
aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled

# 3. Habilitar S3 Access Logging (para futuros incidentes)
aws s3api put-bucket-logging \
  --bucket "$BUCKET_NAME" \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "bucket-de-logs-acesso",
      "TargetPrefix": "s3-access-logs/'"$BUCKET_NAME"'/"
    }
  }'

# 4. Verificar e habilitar notificação do Amazon Macie para este bucket
aws macie2 put-findings-publication-configuration \
  --security-hub-configuration publishClassificationFindings=true,publishPolicyFindings=true
```

---

*Retornar ao índice: [README](../README.md) · Ver também: [Notificação ANPD](../runbook/04-notificacao-anpd.md)*
