# 05 — Erradicação, Recuperação e Lições Aprendidas

> **Tempo alvo:** Erradicação em até 72 horas. Recuperação completa em até 7 dias. Relatório de lições aprendidas em até 30 dias.  
> **Objetivo:** Eliminar definitivamente a causa raiz, restaurar os sistemas com segurança reforçada e transformar o incidente em melhoria permanente.

> ⚖️ **Base legal:** A Res. BCB 4.893/2021 (Art. 4º, VIII) exige que procedimentos de resposta a incidentes incluam "ações de recuperação". O relatório de lições aprendidas é evidência para a ANPD de que a organização implementou melhorias após o incidente — demonstração de "boas práticas" (LGPD Art. 50).

---

## Pré-requisito: Confirmações Antes de Iniciar a Erradicação

```
Antes de qualquer ação de erradicação, confirmar:

□ Contenção concluída — [01-contencao-aws.md]
□ Evidências preservadas — [02-preservacao-evidencias.md]
□ Avaliação de impacto LGPD concluída — [03-avaliacao-impacto-lgpd.md]
□ Notificação à ANPD enviada (se obrigatória) — [04-notificacao-anpd.md]
□ DPO e CISO aprovaram início da erradicação
□ Causa raiz identificada (ao menos preliminarmente)
  → Sem identificar a causa raiz, a erradicação pode ser incompleta
```

---

## Fase 1 — Erradicação

> **Objetivo:** Remover completamente o vetor de ataque, artefatos maliciosos e acessos indevidos criados pelo atacante.

### 1.1 Erradicação por tipo de vetor

#### Credencial comprometida

```bash
USERNAME="usuario-comprometido"
REGION="sa-east-1"

# 1. Deletar a access key comprometida (já estava desativada desde a contenção)
COMPROMISED_KEY="AKIAXXXXXXXXXXXXXXXX"
aws iam delete-access-key \
  --user-name "$USERNAME" \
  --access-key-id "$COMPROMISED_KEY"
echo "✓ Access key deletada: $COMPROMISED_KEY"

# 2. Remover política de revogação de emergência (criada na contenção)
REVOKE_POLICY=$(aws iam list-user-policies \
  --user-name "$USERNAME" \
  --query 'PolicyNames[?starts_with(@,`EMERGENCY-REVOKE`)]' \
  --output text)

for policy in $REVOKE_POLICY; do
  aws iam delete-user-policy \
    --user-name "$USERNAME" \
    --policy-name "$policy"
  echo "✓ Política de revogação removida: $policy"
done

# 3. Verificar e remover backdoors criados pelo atacante
echo ""
echo "Verificando backdoors criados pelo atacante:"

# Usuários IAM criados no período do incidente
echo "Usuários criados durante o incidente:"
aws iam list-users \
  --query 'Users[?CreateDate>=`INICIO_DO_INCIDENTE`].[UserName,CreateDate]' \
  --output table

# Access keys criadas para outros usuários durante o incidente
echo "Access keys criadas durante o incidente:"
for user in $(aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n'); do
  aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[?CreateDate>=`INICIO_DO_INCIDENTE`].[UserName,AccessKeyId,CreateDate]' \
    --output text
done

# Roles com trust policy alterada recentemente
echo "Roles com trust policy modificada recentemente:"
aws iam list-roles \
  --query 'Roles[?CreateDate>=`INICIO_DO_INCIDENTE`].[RoleName,CreateDate]' \
  --output table
```

#### Instância EC2 comprometida

```bash
INSTANCE_ID="i-xxxxxxxxxxxxxxxxx"
REGION="sa-east-1"

# Opção A — Terminar instância e lançar nova a partir de AMI limpa (recomendado)
echo "Terminando instância comprometida..."
aws ec2 terminate-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION"

# Lançar nova instância a partir de AMI limpa e auditada
CLEAN_AMI="ami-xxxxxxxxxxxxxxxxx"  # AMI hardened e auditada
aws ec2 run-instances \
  --image-id "$CLEAN_AMI" \
  --instance-type t3.medium \
  --subnet-id "subnet-PRIVADA_APP" \
  --security-group-ids "sg-APP_LIMPO" \
  --iam-instance-profile "Name=AppInstanceProfile" \
  --tag-specifications "ResourceType=instance,Tags=[
    {Key=Name,Value=app-server-rebuilt-$(date +%Y%m%d)},
    {Key=RebuiltAfterIncident,Value=INCIDENT_ID},
    {Key=RebuiltAt,Value=$(date --iso-8601=seconds)}
  ]" \
  --region "$REGION"

echo "✓ Nova instância lançada a partir de AMI limpa"
echo "⚠️  NÃO restaurar dados do snapshot comprometido — usar backup limpo anterior ao incidente"

# Opção B — Limpar instância existente (apenas se AMI limpa não estiver disponível)
# Requer acesso via SSM Session Manager para:
# - Verificar e remover arquivos suspeitos
# - Verificar crontabs e serviços de startup
# - Verificar chaves SSH autorizadas
# - Fazer scan com ferramenta de segurança
echo ""
echo "Se optar pela Opção B — checklist de limpeza manual:"
echo "  □ Verificar /tmp, /var/tmp por arquivos suspeitos"
echo "  □ Verificar crontab -l e /etc/cron.*"
echo "  □ Verificar ~/.ssh/authorized_keys"
echo "  □ Verificar /etc/passwd por usuários novos"
echo "  □ Verificar processos suspeitos: ps aux"
echo "  □ Verificar conexões de rede: netstat -tulpn"
echo "  □ Executar scan: amazon-linux-extras install -y epel && yum install -y clamav && clamscan -r /"
```

#### Bucket S3 exposto

```bash
BUCKET_NAME="bucket-afetado"

# 1. Confirmar que acesso público está bloqueado (aplicado na contenção)
aws s3api get-public-access-block --bucket "$BUCKET_NAME"

# 2. Aplicar política de bucket segura definitiva
aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Sid\": \"DenyHTTP\",
      \"Effect\": \"Deny\",
      \"Principal\": \"*\",
      \"Action\": \"s3:*\",
      \"Resource\": [
        \"arn:aws:s3:::$BUCKET_NAME\",
        \"arn:aws:s3:::$BUCKET_NAME/*\"
      ],
      \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}
    }
  ]
}"

# 3. Habilitar versionamento e logging (se não estavam ativos)
aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-logging \
  --bucket "$BUCKET_NAME" \
  --bucket-logging-status "{
    \"LoggingEnabled\": {
      \"TargetBucket\": \"bucket-de-logs-acesso\",
      \"TargetPrefix\": \"s3-access-logs/$BUCKET_NAME/\"
    }
  }"

echo "✓ Bucket $BUCKET_NAME hardened com política segura, versionamento e logging"
```

### 1.2 Verificação pós-erradicação

```bash
REGION="sa-east-1"

echo "====== Verificação de Erradicação ======"
echo ""

# Verificar se ainda há Security Groups com portas críticas abertas para 0.0.0.0/0
echo "[ SGs com portas de banco expostas à internet ]"
EXPOSED=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`3306` || FromPort==`5432` || FromPort==`1433`)]].GroupId' \
  --output text)
[ -z "$EXPOSED" ] && echo "  ✓ Nenhum SG com banco exposto" || echo "  ✗ ATENÇÃO: $EXPOSED"

# Verificar se ainda há buckets S3 públicos
echo ""
echo "[ Buckets S3 públicos ]"
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n'); do
  IS_PUBLIC=$(aws s3api get-bucket-policy-status \
    --bucket "$bucket" \
    --query 'PolicyStatus.IsPublic' \
    --output text 2>/dev/null || echo "false")
  [ "$IS_PUBLIC" = "true" ] && echo "  ✗ PÚBLICO: $bucket" || echo "  ✓ $bucket"
done

# Verificar Access Analyzer — novos findings
echo ""
echo "[ IAM Access Analyzer — findings ativos ]"
aws accessanalyzer list-analyzers --region "$REGION" \
  --query 'analyzers[].name' --output text | tr '\t' '\n' | while read -r analyzer; do
  FINDINGS=$(aws accessanalyzer list-findings \
    --analyzer-name "$analyzer" \
    --filter '{"status":{"eq":["ACTIVE"]}}' \
    --query 'length(findings)' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "0")
  [ "$FINDINGS" -gt 0 ] \
    && echo "  ✗ $analyzer: $FINDINGS finding(s) ativo(s)" \
    || echo "  ✓ $analyzer: nenhum finding ativo"
done

# Security Hub score
echo ""
echo "[ Security Hub — score de conformidade ]"
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}]}' \
  --query 'length(Findings)' \
  --output text \
  --region "$REGION" | xargs -I{} echo "  Findings críticos não tratados: {}"
```

---

## Fase 2 — Recuperação

> **Objetivo:** Restaurar os sistemas ao estado operacional normal com segurança verificada, usando backups limpos e configurações hardened.

### 2.1 Validar o backup limpo antes de restaurar

```bash
# NUNCA restaurar do snapshot tirado durante o incidente para produção
# Usar o backup anterior ao início estimado do incidente

DB_INSTANCE="meu-banco-producao"
REGION="sa-east-1"
CLEAN_BACKUP_DATE="2025-01-14"  # Data antes do início do incidente

# Listar snapshots disponíveis antes do incidente
echo "Snapshots RDS disponíveis antes do incidente ($CLEAN_BACKUP_DATE):"
aws rds describe-db-snapshots \
  --db-instance-identifier "$DB_INSTANCE" \
  --query "DBSnapshots[?SnapshotCreateTime<='${CLEAN_BACKUP_DATE}T23:59:59'].{ID:DBSnapshotIdentifier,Data:SnapshotCreateTime,Status:Status}" \
  --output table \
  --region "$REGION"

# Verificar integridade do snapshot antes de restaurar
SNAPSHOT_ID="rds:meu-banco-producao-2025-01-14-00-00"
aws rds describe-db-snapshots \
  --db-snapshot-identifier "$SNAPSHOT_ID" \
  --query 'DBSnapshots[0].{Status:Status,Encrypted:Encrypted,KmsKeyId:KmsKeyId}' \
  --output table \
  --region "$REGION"
```

### 2.2 Restaurar RDS a partir de snapshot limpo

```bash
SNAPSHOT_ID="rds:meu-banco-producao-2025-01-14-00-00"
NEW_INSTANCE_ID="meu-banco-producao-restored-$(date +%Y%m%d)"
REGION="sa-east-1"

# Restaurar para nova instância (não sobreescrever a original ainda)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "$NEW_INSTANCE_ID" \
  --db-snapshot-identifier "$SNAPSHOT_ID" \
  --db-instance-class db.t3.medium \
  --vpc-security-group-ids "sg-DATA_LIMPO" \
  --db-subnet-group-name "subnet-group-privado-dados" \
  --storage-encrypted \
  --kms-key-id "arn:aws:kms:$REGION:ACCOUNT_ID:key/KMS_KEY_ID" \
  --tags Key=RestoredAfterIncident,Value="INCIDENT_ID" \
         Key=RestoredAt,Value="$(date --iso-8601=seconds)" \
         Key=SourceSnapshot,Value="$SNAPSHOT_ID" \
  --region "$REGION"

echo "✓ Restauração iniciada: $NEW_INSTANCE_ID"
echo "  Aguardar status 'available' antes de redirecionar tráfego"

# Aguardar disponibilidade
aws rds wait db-instance-available \
  --db-instance-identifier "$NEW_INSTANCE_ID" \
  --region "$REGION"

echo "✓ Instância restaurada disponível"
echo ""
echo "ANTES DE REDIRECIONAR O TRÁFEGO:"
echo "  □ Validar integridade dos dados na instância restaurada"
echo "  □ Executar testes de sanidade na aplicação"
echo "  □ Confirmar que a instância comprometida está terminada"
echo "  □ Atualizar connection string / Secrets Manager com novo endpoint"
```

### 2.3 Credenciais — nova emissão segura

```bash
USERNAME="usuario-comprometido"

# Criar nova access key com processo seguro
NEW_KEY=$(aws iam create-access-key \
  --user-name "$USERNAME" \
  --output json)

NEW_KEY_ID=$(echo "$NEW_KEY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['AccessKey']['AccessKeyId'])")
NEW_KEY_SECRET=$(echo "$NEW_KEY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['AccessKey']['SecretAccessKey'])")

echo "✓ Nova access key criada: $NEW_KEY_ID"
echo ""
echo "⚠️  DISTRIBUIÇÃO SEGURA OBRIGATÓRIA:"
echo "  1. NÃO enviar por e-mail ou chat"
echo "  2. Usar AWS Secrets Manager ou cofre de senhas corporativo"
echo "  3. Confirmar recebimento pelo usuário antes de encerrar o ticket"
echo ""

# Armazenar no Secrets Manager
aws secretsmanager create-secret \
  --name "iam/users/$USERNAME/access-key" \
  --description "Access key pós-incidente INCIDENT_ID — $(date '+%Y-%m-%d')" \
  --secret-string "{\"AccessKeyId\":\"$NEW_KEY_ID\",\"SecretAccessKey\":\"$NEW_KEY_SECRET\"}" \
  --region "$REGION"

echo "✓ Credencial armazenada no Secrets Manager"
echo "  Instruir $USERNAME a buscar no Secrets Manager ou via processo seguro"
```

### 2.4 Checklist de validação pré-retorno à produção

```
VALIDAÇÃO TÉCNICA
□ Causa raiz completamente eliminada (confirmado pela equipe de segurança)
□ Sistemas restaurados a partir de backups anteriores ao incidente
□ Nenhum artefato malicioso encontrado nos sistemas restaurados
□ Credenciais rotacionadas: IAM + banco de dados + Secrets Manager
□ Security Groups e NACLs revisados e confirmados
□ Monitoring e alertas reativados e testados
□ GuardDuty, Macie e Security Hub sem findings críticos novos

VALIDAÇÃO FUNCIONAL
□ Testes de integração executados e passando
□ Testes de sanidade de dados — integridade dos dados restaurados confirmada
□ Performance em nível normal
□ Logs fluindo corretamente para CloudWatch e CloudTrail

VALIDAÇÃO DE SEGURANÇA
□ Scan de vulnerabilidades executado nos sistemas restaurados
□ AWS Config Rules todas em COMPLIANT
□ IAM Access Analyzer sem findings ativos
□ Penetration test ou security review agendado (pós-incidente)

APROVAÇÃO PARA RETORNO À PRODUÇÃO
□ Security Team: _________________________ Data: ____/____/________
□ DPO: __________________________________ Data: ____/____/________
□ CISO: _________________________________ Data: ____/____/________
```

---

## Fase 3 — Monitoramento Intensificado Pós-Incidente

```bash
REGION="sa-east-1"

# Criar alarme CloudWatch com threshold reduzido para os próximos 30 dias
# Qualquer anomalia deve ser investigada imediatamente

# Alarme: tentativas de login falhadas (threshold mais baixo que o normal)
aws cloudwatch put-metric-alarm \
  --alarm-name "POST-INCIDENT-ConsoleLoginFailures-30d" \
  --alarm-description "Pós-incidente: monitoramento intensificado por 30 dias" \
  --namespace "CloudTrailMetrics" \
  --metric-name "ConsoleLoginFailures" \
  --statistic Sum \
  --period 300 \
  --threshold 3 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:$REGION:ACCOUNT_ID:alertas-seguranca-criticos" \
  --treat-missing-data notBreaching \
  --region "$REGION"

# Alarme: qualquer acesso root
aws cloudwatch put-metric-alarm \
  --alarm-name "POST-INCIDENT-RootAccountUsage-30d" \
  --alarm-description "Pós-incidente: uso da conta root — investigar imediatamente" \
  --namespace "CloudTrailMetrics" \
  --metric-name "RootAccountUsage" \
  --statistic Sum \
  --period 60 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:$REGION:ACCOUNT_ID:alertas-seguranca-criticos" \
  --region "$REGION"

echo "✓ Alarmes de monitoramento intensificado criados (válidos por 30 dias)"
echo "  Lembrete: remover ou ajustar thresholds após 30 dias"
```

---

## Fase 4 — Relatório de Lições Aprendidas

> Prazo: até **30 dias** após o encerramento do incidente.  
> Quem deve participar: Security Team, DPO, CISO, Jurídico, times afetados.

### 4.1 Template do relatório

```
====================================================================
RELATÓRIO DE LIÇÕES APRENDIDAS — PÓS-INCIDENTE
====================================================================
Incidente ID   : ___________________________
Data do incidente: ____/____/________
Data do relatório: ____/____/________
Elaborado por  : ___________________________
Revisado por   : ___________________________

--------------------------------------------------------------------
1. LINHA DO TEMPO FINAL DO INCIDENTE
--------------------------------------------------------------------

Data/Hora           | Evento
--------------------|------------------------------------------------
                    | Origem estimada do incidente
                    | Primeira evidência técnica
                    | Detecção pela equipe
                    | Contenção inicial
                    | Contenção completa
                    | Avaliação de impacto concluída
                    | Notificação ANPD (se aplicável)
                    | Erradicação concluída
                    | Sistemas em produção restaurados
                    | Monitoramento intensificado encerrado
                    | Este relatório finalizado

--------------------------------------------------------------------
2. CAUSA RAIZ
--------------------------------------------------------------------

Causa raiz identificada:
___________________________________________________________________
___________________________________________________________________

Fatores contribuintes (condições que permitiram a causa raiz existir):
1. ________________________________________________________________
2. ________________________________________________________________
3. ________________________________________________________________

Como a causa raiz poderia ter sido detectada mais cedo?
___________________________________________________________________

--------------------------------------------------------------------
3. IMPACTO FINAL CONSOLIDADO
--------------------------------------------------------------------

Sistemas afetados       : ___________________________________________
Dados pessoais afetados : □ Sim (categorias: _______)  □ Não
Titulares afetados      : ___________ titulares
Duração do incidente    : ___________ horas
Tempo de indisponibilidade: ___________ horas
Impacto financeiro estimado: R$ ___________________________________
Notificação ANPD        : □ Sim (protocolo: _______)  □ Não

--------------------------------------------------------------------
4. O QUE FUNCIONOU BEM
--------------------------------------------------------------------

(Reconhecer o que foi eficaz — para manter e reforçar)

□ ________________________________________________________________
□ ________________________________________________________________
□ ________________________________________________________________

--------------------------------------------------------------------
5. O QUE PODE MELHORAR
--------------------------------------------------------------------

(Sem atribuição de culpa — foco em sistemas e processos)

Detecção:
□ ________________________________________________________________

Contenção:
□ ________________________________________________________________

Comunicação interna:
□ ________________________________________________________________

Comunicação externa (titulares, ANPD):
□ ________________________________________________________________

Recuperação:
□ ________________________________________________________________

--------------------------------------------------------------------
6. PLANO DE AÇÃO — MELHORIAS (obrigatório)
--------------------------------------------------------------------

Item | Melhoria | Responsável | Prazo | Prioridade | Status
-----|----------|-------------|-------|------------|-------
  1  |          |             |       | 🔴 Alta    | Pendente
  2  |          |             |       | 🟡 Média   | Pendente
  3  |          |             |       | 🟢 Baixa   | Pendente
  4  |          |             |       |            | Pendente
  5  |          |             |       |            | Pendente

--------------------------------------------------------------------
7. ATUALIZAÇÃO DE CONTROLES E DOCUMENTAÇÃO
--------------------------------------------------------------------

□ Playbook de resposta a incidentes atualizado com aprendizados
□ Runbooks de contenção atualizados
□ Políticas IAM revisadas e endurecidas
□ Arquitetura de segurança atualizada se necessário
□ Treinamento da equipe atualizado

--------------------------------------------------------------------
8. PRÓXIMO EXERCÍCIO DE SIMULAÇÃO (Tabletop Exercise)
--------------------------------------------------------------------

Data proposta: ____/____/________
Cenário a simular: __________________________________________________
Participantes: ______________________________________________________

--------------------------------------------------------------------
ASSINATURAS
--------------------------------------------------------------------

Security Team: _______________________ Data: ____/____/________
DPO:          _______________________ Data: ____/____/________
CISO:         _______________________ Data: ____/____/________
```

---

## Fase 5 — Encerramento Formal do Incidente

### 5.1 Checklist de encerramento

```
ENCERRAMENTO TÉCNICO
□ Causa raiz eliminada e verificada
□ Sistemas em produção normalizados e monitorados
□ Todos os SGs de quarentena deletados
□ Instâncias e volumes forenses descartados conforme política de retenção
□ Secrets e credenciais temporárias revogadas
□ Alarmes de monitoramento intensificado agendados para remoção (D+30)

ENCERRAMENTO LEGAL E REGULATÓRIO
□ Notificação ANPD enviada (se aplicável) — protocolo: _____________
□ Comunicação aos titulares enviada (se aplicável)
□ Notificação BCB enviada (se IF aplicável)
□ Toda documentação do incidente arquivada

DOCUMENTAÇÃO OBRIGATÓRIA PARA ARQUIVO
(Retenção mínima: 5 anos — BCB 4.893 Art. 4º VI)
□ Ficha de registro do incidente (preenchida e assinada)
□ Evidências forenses (bucket S3 com Object Lock)
□ Relatório de avaliação de impacto LGPD
□ Cópia da notificação à ANPD e protocolo de envio
□ Cópia do comunicado enviado aos titulares e registro de envio
□ Relatório de lições aprendidas
□ Plano de ação com status de implementação

ENCERRAMENTO DO INCIDENTE
□ Ticket de incidente encerrado formalmente no sistema de ITSM
□ Relatório de lições aprendidas distribuído para todas as partes
□ Data de encerramento registrada: ____/____/________
□ Próximo exercício de simulação agendado: ____/____/________
```

### 5.2 Arquivamento das evidências

```bash
INCIDENT_ID="INC-XXXXXXXX"
FORENSICS_BUCKET="forensics-evidence-ACCOUNT_ID"
REGION="sa-east-1"

# Confirmar que todas as evidências estão no bucket forense
echo "Evidências arquivadas para $INCIDENT_ID:"
aws s3 ls "s3://$FORENSICS_BUCKET/$INCIDENT_ID/" \
  --recursive \
  --human-readable \
  --region "$REGION"

# Aplicar tag de encerramento em todos os objetos do incidente
aws s3 cp "s3://$FORENSICS_BUCKET/$INCIDENT_ID/" \
  "s3://$FORENSICS_BUCKET/$INCIDENT_ID/" \
  --recursive \
  --metadata-directive REPLACE \
  --metadata "IncidentStatus=CLOSED,ClosedAt=$(date --iso-8601=seconds),RetainUntil=$(date -d '+5 years' '+%Y-%m-%d')" \
  --region "$REGION"

echo "✓ Evidências marcadas como encerradas — retenção até $(date -d '+5 years' '+%Y-%m-%d')"
```

---

## Checklist Final de Encerramento

```
□ Fases 1 a 5 concluídas e documentadas
□ Todos os sistemas restaurados e validados em produção
□ Todas as obrigações legais cumpridas (ANPD, titulares, BCB)
□ Toda documentação arquivada com retenção de 5 anos
□ Relatório de lições aprendidas aprovado e distribuído
□ Plano de ação em execução com responsáveis definidos
□ Próximo exercício de simulação agendado
□ Incidente formalmente encerrado no ITSM

Data de encerramento formal: ____/____/________
Encerrado por: _________________________________
Aprovado pelo CISO: ____________________________
```

---

*Anterior: [04 — Notificação à ANPD](04-notificacao-anpd.md) · Retornar ao início: [README](../README.md)*
