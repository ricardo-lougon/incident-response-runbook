# Template — Comunicação de Incidente à ANPD

> **Base legal:** LGPD Art. 48 e Resolução ANPD CD/ANPD nº 15/2024  
> **Canal:** https://www.gov.br/anpd/pt-br/assuntos/incidentes-de-seguranca  
> **Prazo:** 72 horas a partir da ciência do incidente  
> **Instrução:** Este template serve como rascunho para organizar as informações antes de inserir no portal oficial da ANPD.

---

## COMUNICAÇÃO DE INCIDENTE DE SEGURANÇA COM DADOS PESSOAIS

**ID do Incidente (interno):** INC-[ANO]-[SEQUENCIAL]  
**Data desta comunicação:** ____/____/________

---

### 1. IDENTIFICAÇÃO DO CONTROLADOR

| Campo | Valor |
|---|---|
| **Razão social** | |
| **CNPJ** | |
| **Setor de atuação** | |
| **Endereço** | |
| **Nome do DPO / Encarregado** | |
| **E-mail do DPO** | |
| **Telefone do DPO** | |

---

### 2. DESCRIÇÃO DO INCIDENTE

**Data/hora de ocorrência (estimada):** ____/____/________ às ____:____  
**Data/hora de detecção:** ____/____/________ às ____:____  
**Data/hora de ciência pela organização:** ____/____/________ às ____:____

**Natureza do incidente:**
- ( ) Acesso não autorizado a dados pessoais
- ( ) Vazamento / exposição indevida de dados
- ( ) Perda ou destruição de dados pessoais
- ( ) Alteração não autorizada de dados pessoais
- ( ) Outro: _________________________________

**Descrição detalhada:**

```
[Descrever o que ocorreu de forma objetiva e factual, em linguagem compreensível.
Incluir: sistemas afetados, como foi detectado, cronologia do incidente]




```

---

### 3. DADOS PESSOAIS AFETADOS (Art. 48, §2º, I)

**Categorias de dados pessoais afetados:**
- ( ) Dados de identificação (nome, CPF, RG, data de nascimento)
- ( ) Dados de contato (e-mail, telefone, endereço)
- ( ) Dados financeiros (conta bancária, cartão, renda)
- ( ) Dados de saúde ou vida sexual *(dado sensível — Art. 5º II)*
- ( ) Dados biométricos *(dado sensível)*
- ( ) Origem racial ou étnica *(dado sensível)*
- ( ) Convicção religiosa *(dado sensível)*
- ( ) Opinião política *(dado sensível)*
- ( ) Dados de crianças ou adolescentes
- ( ) Outros: _________________________________

**Os dados incluem dados sensíveis (Art. 5º, XI)?** ( ) Sim ( ) Não

---

### 4. TITULARES AFETADOS (Art. 48, §2º, II)

**Número de titulares afetados:**
- ( ) Exato: ___________ titulares
- ( ) Estimado: ___________ titulares (margem de erro: _____%)
- ( ) Desconhecido — investigação em andamento

**Perfil dos titulares:**
- ( ) Clientes / consumidores
- ( ) Funcionários / colaboradores
- ( ) Menores de 18 anos
- ( ) Outros: _________________________________

**Localização dos titulares:** ( ) Brasil ( ) Brasil e exterior

---

### 5. MEDIDAS DE SEGURANÇA PREVIAMENTE ADOTADAS (Art. 48, §2º, III)

*Descrever as medidas técnicas e administrativas que estavam implementadas antes do incidente:*

```
□ Criptografia em repouso (SSE-KMS): ( ) Sim ( ) Não
□ Criptografia em trânsito (TLS): ( ) Sim ( ) Não
□ Controle de acesso (IAM/MFA): ( ) Sim ( ) Não
□ Monitoramento (GuardDuty/CloudTrail): ( ) Sim ( ) Não
□ Política de segurança da informação: ( ) Sim ( ) Não

Descrição adicional:
_________________________________________________________________
```

---

### 6. RISCOS DECORRENTES DO INCIDENTE (Art. 48, §2º, IV)

*Para cada risco identificado, marcar e descrever brevemente:*

| Risco | Presente? | Descrição |
|---|---|---|
| Discriminação | ( ) Sim ( ) Não | |
| Dano financeiro | ( ) Sim ( ) Não | |
| Violação de integridade física | ( ) Sim ( ) Não | |
| Violação de integridade psíquica | ( ) Sim ( ) Não | |
| Fraude de identidade | ( ) Sim ( ) Não | |
| Dano à reputação | ( ) Sim ( ) Não | |
| Dano à imagem | ( ) Sim ( ) Não | |

---

### 7. MEDIDAS ADOTADAS OU A ADOTAR (Art. 48, §2º, V)

**Medidas já adotadas:**
```
[Descrever ações tomadas para conter o incidente, revogar acessos,
preservar evidências, corrigir vulnerabilidades]




```

**Medidas planejadas:**
```
[Descrever ações preventivas que serão implementadas para evitar
recorrência — com prazos estimados]




```

---

### 8. COMUNICAÇÃO AOS TITULARES

Os titulares afetados serão comunicados? ( ) Sim ( ) Não

Se sim:
- Canal de comunicação: ( ) E-mail ( ) SMS ( ) Portal ( ) Outro: ____
- Data prevista: ____/____/________

Se não — justificativa:
```
[Fundamentar por que não é necessário comunicar os titulares]
```

---

### 9. MOTIVO DE EVENTUAL DEMORA (se comunicação não for imediata)

```
[Caso esta comunicação seja enviada com mais de 72h da ciência,
justificar o motivo da demora]
```

---

### 10. INFORMAÇÕES COMPLEMENTARES

```
[Qualquer informação adicional relevante para a análise da ANPD]
```

---

### DECLARAÇÃO

Declaro que as informações prestadas neste comunicado são verdadeiras e completas conforme o conhecimento disponível no momento da elaboração, comprometendo-me a complementar com informações adicionais assim que disponíveis.

**Nome:** ___________________________  
**Cargo:** ___________________________  
**Qualidade:** ( ) DPO / Encarregado ( ) Representante legal ( ) Outro: ____  
**Data:** ____/____/________

---

*Template mantido por: Ricardo Neves Lougon — github.com/ricardolougon/incident-response-runbook*
