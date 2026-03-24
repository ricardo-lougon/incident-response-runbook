# 03 — Avaliação de Impacto LGPD

> **Tempo alvo:** Concluir em até 24 horas após a contenção.  
> **Objetivo:** Determinar com precisão se dados pessoais foram afetados, qual o risco aos titulares e se a notificação à ANPD é obrigatória.

> ⚖️ **Base legal:** LGPD Art. 48 — o controlador deve comunicar à ANPD e ao titular a ocorrência de incidente que possa **acarretar risco ou dano relevante** aos titulares. A avaliação de impacto é o instrumento que fundamenta essa decisão — e sua documentação é evidência perante a ANPD de que a organização agiu com diligência.

---

## Quem Deve Conduzir Esta Avaliação

| Papel | Responsabilidade nesta etapa |
|---|---|
| **DPO / Encarregado** | Conduzir a avaliação, assinar o documento final, decidir sobre notificação |
| **Security Team** | Fornecer dados técnicos: quais sistemas, quais logs, o que os dados mostram |
| **Jurídico** | Avaliar base legal, risco regulatório, responsabilidade |
| **CISO** | Validar conclusões técnicas, aprovar o relatório |

---

## Etapa 1 — Mapear os Dados Pessoais Afetados

### 1.1 Quais sistemas foram comprometidos?

```
Sistemas confirmadamente afetados:

□ Banco de dados de clientes (RDS/DynamoDB)
  → Identificador: _________________________________
  → Dados armazenados: _____________________________

□ Bucket S3 com dados pessoais
  → Nome do bucket: ________________________________
  → Prefixos/pastas afetados: ______________________

□ Aplicação web (EC2/ECS/Lambda)
  → ARN/ID: _______________________________________
  → Dados em memória/cache: ________________________

□ Sistema de autenticação (Cognito/IAM)
  → Escopo: ________________________________________

□ Outros: ________________________________________
```

### 1.2 Verificar com Amazon Macie quais dados pessoais existem nos recursos afetados

```bash
REGION="sa-east-1"
BUCKET_AFETADO="nome-do-bucket-afetado"
INCIDENT_ID="INC-$(date +%Y%m%d)"

# Verificar se já existe um job Macie do incidente (criado na contenção)
aws macie2 list-classification-jobs \
  --filter-criteria '{"includes":{"simpleCriterion":[{"comparator":"CONTAINS","key":"name","values":["incident"]}]}}' \
  --region "$REGION" \
  --query 'items[].{Nome:name,Status:jobStatus,Criado:createdAt}' \
  --output table

# Se não existir, criar agora
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

JOB_ID=$(aws macie2 create-classification-job \
  --name "impact-assessment-$INCIDENT_ID" \
  --job-type ONE_TIME \
  --s3-job-definition "{
    \"bucketDefinitions\": [{
      \"accountId\": \"$ACCOUNT_ID\",
      \"buckets\": [\"$BUCKET_AFETADO\"]
    }]
  }" \
  --description "Avaliação de impacto LGPD — $INCIDENT_ID" \
  --region "$REGION" \
  --query 'jobId' \
  --output text 2>/dev/null || echo "")

if [ -n "$JOB_ID" ]; then
  echo "✓ Job Macie criado: $JOB_ID"
  echo "  Aguardar conclusão antes de continuar a avaliação (pode levar minutos a horas)"
fi

# Verificar findings de dados sensíveis do Macie
echo ""
echo "Findings Macie de dados pessoais e sensíveis:"
aws macie2 get-findings \
  --finding-ids $(aws macie2 list-findings \
    --finding-criteria '{"criterion":{"category":{"eq":["CLASSIFICATION"]}}}' \
    --region "$REGION" \
    --query 'findingIds' \
    --output text) \
  --region "$REGION" \
  --query 'findings[].{
    Tipo:type,
    Bucket:resourcesAffected.s3Bucket.name,
    Objeto:resourcesAffected.s3Object.key,
    Categoria:classificationDetails.result.sensitiveData[0].category,
    Ocorrencias:classificationDetails.result.sensitiveData[0].totalCount
  }' \
  --output table 2>/dev/null || echo "Nenhum finding Macie disponível ainda"
```

### 1.3 Categorias de dados pessoais — classificação LGPD

Preencher com base nos sistemas afetados e nos resultados do Macie:

```
DADOS PESSOAIS COMUNS (Art. 5º, I)
□ Nome completo                    Quantidade estimada de registros: _______
□ CPF / RG / documentos            Quantidade estimada de registros: _______
□ Data de nascimento               Quantidade estimada de registros: _______
□ Endereço                         Quantidade estimada de registros: _______
□ E-mail                           Quantidade estimada de registros: _______
□ Telefone                         Quantidade estimada de registros: _______
□ IP / dados de navegação          Quantidade estimada de registros: _______
□ Dados financeiros (conta, cartão) Quantidade estimada de registros: _______
□ Outros: _______________          Quantidade estimada de registros: _______

DADOS PESSOAIS SENSÍVEIS (Art. 5º, II) — TRATAMENTO AGRAVADO
□ Origem racial ou étnica
□ Convicção religiosa
□ Opinião política
□ Filiação a sindicato ou organização
□ Dado referente à saúde ou à vida sexual
□ Dado genético ou biométrico
□ Dado de criança ou adolescente (< 18 anos)

⚠️  Se qualquer dado sensível for afetado → notificação ANPD é praticamente obrigatória
```

---

## Etapa 2 — Quantificar os Titulares Afetados

### 2.1 Contagem técnica de registros expostos

```bash
DB_INSTANCE="meu-banco-producao"
TABLE_NAME="customers"
REGION="sa-east-1"

# Estimativa de registros no RDS (via consulta de contagem)
# ATENÇÃO: executar em réplica de leitura, nunca na primária durante incidente
echo "Estimativa de registros na tabela afetada:"
echo "  Conectar na réplica de leitura e executar:"
echo "  SELECT COUNT(*) FROM $TABLE_NAME;"
echo "  SELECT COUNT(*) FROM $TABLE_NAME WHERE created_at >= 'DATA_INICIO_INCIDENTE';"

# Para S3 — contar objetos afetados
BUCKET_AFETADO="nome-do-bucket-afetado"

TOTAL_OBJECTS=$(aws s3api list-objects-v2 \
  --bucket "$BUCKET_AFETADO" \
  --query 'length(Contents)' \
  --output text 2>/dev/null || echo "desconhecido")

TOTAL_SIZE=$(aws s3api list-objects-v2 \
  --bucket "$BUCKET_AFETADO" \
  --query 'sum(Contents[].Size)' \
  --output text 2>/dev/null || echo "desconhecido")

echo ""
echo "S3 $BUCKET_AFETADO:"
echo "  Total de objetos: $TOTAL_OBJECTS"
echo "  Tamanho total: $TOTAL_SIZE bytes ($(( ${TOTAL_SIZE:-0} / 1048576 )) MB)"
```

### 2.2 Formulário de quantificação

```
TITULARES AFETADOS

Número exato de titulares:          _______________
  (se não disponível) Estimativa:   _______________
  Margem de erro da estimativa:     _______________

Perfil dos titulares:
  □ Clientes / consumidores         Quantidade: _______________
  □ Funcionários / colaboradores    Quantidade: _______________
  □ Menores de 18 anos              Quantidade: _______________
  □ Pacientes (dado de saúde)       Quantidade: _______________
  □ Usuários em geral               Quantidade: _______________
  □ Outros: ____________________    Quantidade: _______________

Localização dos titulares:
  □ Apenas no Brasil
  □ Brasil e outros países → listar: _____________________
  (titulares no exterior podem acionar obrigações adicionais)

Dados de titulares vulneráveis:
  □ Crianças (< 12 anos)            Quantidade: _______________
  □ Adolescentes (12–18 anos)       Quantidade: _______________
  □ Idosos (> 60 anos)              Quantidade: _______________
  □ Pessoas com deficiência         Quantidade: _______________
```

---

## Etapa 3 — Avaliar o Risco aos Titulares

Esta é a etapa mais importante juridicamente. O Art. 48 exige notificação quando o incidente possa "acarretar **risco ou dano relevante**" — a organização deve avaliar e documentar esse risco.

### 3.1 Matriz de risco por tipo de dado

```
Para cada tipo de dado afetado, avaliar:

╔═══════════════════════════════╦═══════════╦═══════════╦═══════════════════╗
║ Tipo de dado                  ║ Afetado?  ║ Prob.risco║ Nível de risco    ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ CPF + nome completo           ║  □ S □ N  ║  Alta     ║ 🔴 CRÍTICO        ║
║ (fraude de identidade)        ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Dados bancários / cartão      ║  □ S □ N  ║  Alta     ║ 🔴 CRÍTICO        ║
║ (dano financeiro direto)      ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Dados de saúde / biométricos  ║  □ S □ N  ║  Alta     ║ 🔴 CRÍTICO        ║
║ (dado sensível — Art. 5º II)  ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Dados de crianças             ║  □ S □ N  ║  Alta     ║ 🔴 CRÍTICO        ║
║ (proteção agravada — Art. 14) ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Senhas / credenciais          ║  □ S □ N  ║  Alta     ║ 🔴 CRÍTICO        ║
║ (acesso não autorizado)       ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ E-mail + nome                 ║  □ S □ N  ║  Média    ║ 🟡 ALTO           ║
║ (phishing, spam)              ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Endereço físico               ║  □ S □ N  ║  Média    ║ 🟡 ALTO           ║
║ (dano à segurança física)     ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Dados de navegação / IP       ║  □ S □ N  ║  Baixa    ║ 🟢 MÉDIO          ║
║ (perfil comportamental)       ║           ║           ║                   ║
╠═══════════════════════════════╬═══════════╬═══════════╬═══════════════════╣
║ Nome apenas (sem outros dados)║  □ S □ N  ║  Baixa    ║ 🟢 BAIXO          ║
╚═══════════════════════════════╩═══════════╩═══════════╩═══════════════════╝
```

### 3.2 Fatores agravantes de risco

```
FATORES QUE AUMENTAM O RISCO (marcar todos que se aplicam):

□ Dados foram confirmadamente exfiltrados (não apenas acessados)
  → Evidência: logs de saída de rede / S3 transfer bytes

□ O atacante é um agente malicioso (não erro interno)
  → Evidência: IP de país diferente, malware detectado

□ Dados já foram encontrados em fórum de vazamento / dark web
  → Evidência: threat intelligence, Have I Been Pwned, etc.

□ Período de exposição longo (> 24 horas)
  → Período: ___________ horas/dias

□ Dados não estavam criptografados em repouso
  → Evidência: Config Rule s3-default-encryption-kms = NON_COMPLIANT

□ Dados não estavam pseudonimizados
  → Identificadores diretos (CPF, nome) em texto claro

□ Grande volume de titulares (> 1.000)
  → Quantidade: _______________

□ Titulares vulneráveis afetados (crianças, idosos, pacientes)
```

### 3.3 Fatores mitigantes de risco

```
FATORES QUE REDUZEM O RISCO (marcar todos que se aplicam):

□ Dados estavam criptografados com chave que o atacante não possui
  → Algoritmo: _________ / Chave: _________

□ Dados foram pseudonimizados (IDs em vez de identificadores diretos)
  → Chave de mapeamento permaneceu segura: □ Sim  □ Não

□ Período de exposição muito curto (< 1 hora)
  → Período: ___________ minutos

□ Atacante não teve tempo suficiente para exfiltrar volume relevante
  → Evidência: Flow Logs mostram ___ bytes transferidos

□ Dados já eram de conhecimento público por outra razão

□ Acesso foi interno (funcionário) com contrato de confidencialidade
```

---

## Etapa 4 — Análise Técnica de Confirmação de Acesso

### 4.1 Os dados foram apenas acessíveis ou foram confirmadamente acessados?

```bash
BUCKET_AFETADO="nome-do-bucket-afetado"
LOGS_BUCKET="bucket-de-logs-de-acesso"
INCIDENT_START_DATE="2025-01-15"

# Verificar acessos GetObject no S3 Access Log
echo "Objetos confirmadamente acessados (GetObject) por IPs externos:"
cat /tmp/evidencias-*/s3-access-logs/* 2>/dev/null | \
  awk '$7 == "REST.GET.OBJECT" && $5 !~ /^10\./ && $5 !~ /^172\./ {
    print $5, $8, $10, $11
  }' | sort | while read ip key bytes status; do
    echo "  IP: $ip | Objeto: $key | Bytes: $bytes | Status: $status"
  done

# Verificar CloudTrail para GetObject (requer Data Events habilitados)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "$(date -d '7 days ago' --iso-8601=seconds)" \
  --query 'Events[?SourceIPAddress != `AWS Internal`].{
    Hora: EventTime,
    IP: SourceIPAddress,
    Usuario: Username,
    Recurso: Resources[0].ResourceName
  }' \
  --output table 2>/dev/null | head -30
```

### 4.2 Reconstituição da timeline de acesso

```
TIMELINE DE ACESSO AOS DADOS PESSOAIS

Data/Hora           | Evento                           | Fonte
--------------------|----------------------------------|------------------
                    | Dados pessoais criados/inseridos |
                    |                                  |
                    | [primeiro acesso suspeito]        | CloudTrail / S3 log
                    |                                  |
                    | [contenção aplicada]             | Ação da equipe
                    |                                  |
                    | [último acesso suspeito]         | CloudTrail / S3 log
                    |                                  |
                    | [acesso encerrado]               | Ação da equipe

Duração total de exposição: _____ horas/minutos
Volume estimado de dados acessados: _____ registros / _____ MB
```

---

## Etapa 5 — Decisão de Notificação

### 5.1 Árvore de decisão

```
Dados pessoais foram afetados (acessados, vazados, destruídos ou alterados)?
│
├─ NÃO (comprovado tecnicamente)
│  → Sem obrigação LGPD Art. 48
│  → Documentar conclusão e arquivar
│  → Monitorar por 30 dias para confirmar
│
└─ SIM ou NÃO DETERMINADO
   │
   ├─ Dados SENSÍVEIS afetados? (Art. 5º II)
   │  → SIM → NOTIFICAÇÃO OBRIGATÓRIA 🔴
   │
   ├─ Dados de CRIANÇAS afetados?
   │  → SIM → NOTIFICAÇÃO OBRIGATÓRIA 🔴
   │
   ├─ Risco de FRAUDE DE IDENTIDADE ou DANO FINANCEIRO?
   │  → SIM → NOTIFICAÇÃO OBRIGATÓRIA 🔴
   │
   ├─ Mais de 500 titulares afetados?
   │  → SIM → NOTIFICAÇÃO FORTEMENTE RECOMENDADA 🟡
   │
   ├─ Dados criptografados E chave não comprometida?
   │  → SIM → Avaliar com DPO — risco pode ser baixo o suficiente
   │
   └─ Todos os fatores apontam para risco BAIXO?
      → Documentar análise + consultar jurídico antes de decidir não notificar
      → Princípio da precaução: em dúvida, notifique
```

### 5.2 Documento formal de decisão

```
DECISÃO SOBRE NOTIFICAÇÃO À ANPD
Incidente: ___________________________
Data: ____/____/________

DECISÃO: □ NOTIFICAR À ANPD   □ NÃO NOTIFICAR

FUNDAMENTAÇÃO:

[Descrever os fatos técnicos que embasam a decisão, citando
os artigos da LGPD aplicáveis e as evidências coletadas]

_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

SE NÃO NOTIFICAR — justificativa obrigatória (Art. 48 c/c princípio
da precaução):

_________________________________________________________________
_________________________________________________________________

Assinaturas:

DPO: __________________________ Data: ____/____/________
Jurídico: _____________________ Data: ____/____/________
CISO: _________________________ Data: ____/____/________
```

---

## Etapa 6 — Relatório de Avaliação de Impacto

### Template de relatório técnico para o DPO

```
RELATÓRIO DE AVALIAÇÃO DE IMPACTO — LGPD ART. 48
==================================================
Incidente ID  : ___________________________
Data          : ____/____/________
Classificação : CONFIDENCIAL

1. RESUMO EXECUTIVO
   _______________________________________________________________
   _______________________________________________________________

2. SISTEMAS E DADOS AFETADOS
   Sistemas: ______________________________________________________
   Categorias de dados: ___________________________________________
   Dados sensíveis: □ Sim □ Não — Quais: __________________________
   Dados de crianças: □ Sim □ Não

3. TITULARES AFETADOS
   Número: _______________ (□ exato  □ estimado)
   Perfil: ___________________________________________________________
   Vulneráveis: _____________________________________________________

4. PERÍODO DE EXPOSIÇÃO
   Início: ____/____/________ às ____:____
   Fim (contenção): ____/____/________ às ____:____
   Duração total: ___________ horas

5. CONFIRMAÇÃO DE ACESSO / EXFILTRAÇÃO
   □ Dados confirmadamente acessados
   □ Dados confirmadamente exfiltrados — Volume: _____ MB
   □ Acesso não confirmado — apenas exposição
   Evidência técnica: ______________________________________________

6. AVALIAÇÃO DE RISCO AOS TITULARES
   Risco de fraude de identidade:   □ Alto □ Médio □ Baixo □ Nenhum
   Risco financeiro:                □ Alto □ Médio □ Baixo □ Nenhum
   Risco de discriminação:          □ Alto □ Médio □ Baixo □ Nenhum
   Risco de dano físico:            □ Alto □ Médio □ Baixo □ Nenhum
   Avaliação geral de risco:        □ 🔴 Alto □ 🟡 Médio □ 🟢 Baixo

7. FATORES MITIGANTES
   □ Criptografia ativa e chave não comprometida
   □ Pseudonimização dos dados
   □ Exposição de curta duração
   □ Outros: _____________________________________________________

8. DECISÃO
   □ NOTIFICAR ANPD — Prazo: até ____/____/________ às ____:____
   □ NÃO NOTIFICAR — Justificativa documentada e assinada

9. PRÓXIMAS AÇÕES
   □ Notificação ANPD → [04-notificacao-anpd.md]
   □ Comunicação aos titulares → [templates/comunicado-titular.md]
   □ Notificação BCB (se IF) → canal BCB
   □ Erradicação → [05-recuperacao-licoes.md]

Responsável pela avaliação: ____________________________
DPO: ________________________ Assinatura: ______________
Data: ____/____/________
```

---

## Checklist de Avaliação — Validação Final

```
MAPEAMENTO DE DADOS
□ Sistemas afetados identificados e documentados
□ Categorias de dados pessoais classificadas (comuns / sensíveis)
□ Presença de dados de crianças verificada
□ Job Amazon Macie concluído e findings analisados

QUANTIFICAÇÃO
□ Número de titulares afetados determinado (ou estimado com margem)
□ Perfil dos titulares documentado
□ Titulares vulneráveis identificados

AVALIAÇÃO DE RISCO
□ Matriz de risco preenchida por tipo de dado
□ Fatores agravantes avaliados
□ Fatores mitigantes avaliados
□ Confirmação técnica de acesso analisada (logs, Flow Logs, Macie)

DECISÃO E DOCUMENTAÇÃO
□ Decisão sobre notificação ANPD tomada e documentada
□ Decisão assinada pelo DPO e jurídico
□ Relatório de avaliação de impacto finalizado
□ Prazo de 72h para ANPD verificado: H+____ (de 72h)

SE NOTIFICAR:
□ Iniciar [04-notificacao-anpd.md] imediatamente
□ Iniciar comunicação aos titulares se necessário
```

---

*Anterior: [02 — Preservação de Evidências](02-preservacao-evidencias.md) · Próximo: [04 — Notificação à ANPD](04-notificacao-anpd.md)*
