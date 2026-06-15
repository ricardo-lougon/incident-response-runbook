# Template — Relatório de Lições Aprendidas Pós-Incidente

> **Base legal:** LGPD Art. 50 — incentiva a adoção de programas de governança e boas práticas, incluindo "mecanismos de supervisão interna" e "planos de resposta a incidentes e remediação". Res. BCB 4.893/2021, Art. 4º, VIII — exige que os procedimentos de resposta a incidentes sejam "testados e atualizados periodicamente"; este relatório é o instrumento que formaliza essa atualização.  
> **Prazo:** Até **30 dias** após o encerramento formal do incidente (ver `runbook/05-recuperacao-licoes.md`, Fase 5).  
> **Participantes obrigatórios:** Security Team, DPO, CISO, Jurídico e representantes dos times afetados.  
> **Instrução:** Este relatório NÃO substitui a ficha de registro do incidente — ele a complementa, com foco em causas sistêmicas e melhorias estruturais. Deve ser redigido de forma factual e sem caráter punitivo individual; o objetivo é melhoria de processo, não atribuição de culpa.

---

## IDENTIFICAÇÃO

| Campo | Valor |
|---|---|
| **ID do Incidente** | INC-[ANO]-[SEQUENCIAL] |
| **Título resumido do incidente** | |
| **Data de detecção** | ____/____/________ |
| **Data de encerramento formal** | ____/____/________ |
| **Data desta reunião de lições aprendidas** | ____/____/________ |
| **Facilitador da reunião** | |
| **Participantes** | |

---

## 1. RESUMO EXECUTIVO

```
[2-3 parágrafos em linguagem acessível a não-técnicos: o que aconteceu,
qual foi o impacto, e o que muda a partir deste incidente. Este resumo
pode ser usado como base para comunicação à alta direção e, se aplicável,
para complementar a notificação à ANPD.]




```

---

## 2. LINHA DO TEMPO CONSOLIDADA

*Reconstituir a partir da ficha de registro do incidente — incluir também eventos anteriores à detecção, se identificados durante a investigação (ex.: data real de comprometimento vs. data de detecção).*

| Data/Hora | Evento | Fonte da informação |
|---|---|---|
| | Comprometimento inicial (estimado/confirmado): | |
| | Primeira atividade maliciosa registrada: | |
| | Detecção: | |
| | Ciência formal pelo controlador: | |
| | Contenção iniciada: | |
| | Contenção concluída: | |
| | Erradicação concluída: | |
| | Recuperação concluída: | |
| | Notificação ANPD (se aplicável): | |
| | Encerramento formal: | |

**Tempo de permanência do atacante (dwell time):** entre a estimativa de comprometimento inicial e a detecção: __________

---

## 3. CAUSA RAIZ

### 3.1 Causa raiz técnica

```
[O que, especificamente, permitiu o incidente ocorrer? Ser específico:
não "falha de segurança", mas "Security Group X permitia 0.0.0.0/0 na
porta 22, configurado em DD/MM/AAAA durante o lab Y, sem revisão
posterior".]




```

### 3.2 Causas contribuintes (técnica dos "5 porquês")

| Por quê? | Resposta |
|---|---|
| 1. Por que o incidente ocorreu? | |
| 2. Por que essa condição existia? | |
| 3. Por que não foi detectada antes? | |
| 4. Por que os controles existentes não preveniram? | |
| 5. Causa raiz sistêmica (processo, não pessoa): | |

### 3.3 Classificação da causa raiz

```
( ) Configuração incorreta de recurso AWS
( ) Credencial comprometida / vazada
( ) Vulnerabilidade não corrigida (patch faltante)
( ) Ausência de monitoramento/alerta para este tipo de evento
( ) Processo manual sujeito a erro humano
( ) Ausência de revisão periódica de configurações
( ) Falha de terceiro (fornecedor, biblioteca, serviço)
( ) Outro: _________________________________________
```

---

## 4. O QUE FUNCIONOU BEM

*Importante registrar — reforça práticas que devem ser mantidas e expandidas.*

```
□ Detecção: o que permitiu identificar o incidente? Funcionou conforme esperado?
□ Contenção: as ações de contenção foram eficazes e dentro do prazo (8h)?
□ Evidências: a coleta de evidências (CloudTrail, Flow Logs, snapshots) foi
  suficiente para a investigação, ou houve lacunas?
□ Comunicação: a cadeia de comunicação (CISO/DPO/jurídico) funcionou nos
  prazos definidos em 00-classificacao-triagem.md?
□ Runbook: os procedimentos documentados foram suficientes, ou foi
  necessário improvisar passos não documentados?
```

---

## 5. O QUE NÃO FUNCIONOU / LACUNAS IDENTIFICADAS

```
□ Houve demora em alguma fase em relação às metas do runbook? Qual e por quê?
  (Triagem: 4h / Contenção: 8h / Evidências: 24h / Avaliação LGPD: 24h /
   Notificação ANPD: 72h / Erradicação: 72h / Recuperação: 7 dias)

□ Algum log ou fonte de evidência não estava disponível ou habilitado?
  (ex.: Flow Logs não configurados, S3 Access Logging desabilitado,
   GuardDuty não habilitado na região)

□ Algum procedimento do runbook estava desatualizado ou não se aplicava
  ao cenário real?

□ Ferramentas ou acessos necessários não estavam prontos no momento do
  incidente (ex.: bucket forense não existia, role IncidentResponder
  sem permissão suficiente)?
```

---

## 6. MELHORIAS — PLANO DE AÇÃO

*Cada item deve ter responsável e prazo. Sem essa tabela preenchida, o relatório é incompleto.*

| # | Melhoria proposta | Categoria | Responsável | Prazo | Status |
|---|---|---|---|---|---|
| 1 | | ( ) Técnica ( ) Processo ( ) Runbook ( ) Treinamento | | | ( ) Pendente ( ) Em andamento ( ) Concluído |
| 2 | | ( ) Técnica ( ) Processo ( ) Runbook ( ) Treinamento | | | ( ) Pendente ( ) Em andamento ( ) Concluído |
| 3 | | ( ) Técnica ( ) Processo ( ) Runbook ( ) Treinamento | | | ( ) Pendente ( ) Em andamento ( ) Concluído |
| 4 | | ( ) Técnica ( ) Processo ( ) Runbook ( ) Treinamento | | | ( ) Pendente ( ) Em andamento ( ) Concluído |
| 5 | | ( ) Técnica ( ) Processo ( ) Runbook ( ) Treinamento | | | ( ) Pendente ( ) Em andamento ( ) Concluído |

### 6.1 Atualizações necessárias no runbook

```
□ Algum playbook precisa de novo cenário? Qual?
□ Algum comando CLI usado durante o incidente não estava documentado e
  deveria ser incorporado?
□ Algum link entre documentos (referências cruzadas) estava quebrado ou
  ausente?
```

---

## 7. IMPACTO CONSOLIDADO

| Dimensão | Impacto |
|---|---|
| **Sistemas afetados** | |
| **Titulares de dados afetados (número)** | |
| **Categorias de dados envolvidas** | |
| **Tempo de indisponibilidade (se houver)** | |
| **Custo estimado de resposta (horas/equipe)** | |
| **Custo de recursos AWS adicionais durante a resposta** | |
| **Notificação à ANPD enviada?** | ( ) Sim ( ) Não — Protocolo: __________ |
| **Notificação a titulares enviada?** | ( ) Sim ( ) Não — Quantidade: __________ |
| **Sanções/multas aplicadas ou em avaliação?** | ( ) Sim ( ) Não ( ) Em avaliação |

---

## 8. EVIDÊNCIA DE BOAS PRÁTICAS (LGPD Art. 50 / Res. BCB 4.893)

```
[Descrever objetivamente como a resposta a este incidente demonstra a
adoção de "medidas técnicas e administrativas aptas" e de "boas práticas
e governança" — citando especificamente os controles que funcionaram e
as melhorias implementadas. Este texto pode ser reutilizado em eventuais
solicitações de complementação pela ANPD.]




```

---

## 9. ASSINATURAS E APROVAÇÃO

| Papel | Nome | Assinatura | Data |
|---|---|---|---|
| Facilitador / Responsável pela investigação | | | |
| DPO | | | |
| CISO | | | |
| Jurídico | | | |
| Representante do time afetado | | | |

**Data de arquivamento final:** ____/____/________  
**Local de arquivamento:** (referenciar o bucket forense / sistema de gestão de documentos)  
**Retenção:** mínimo 5 anos (Res. BCB 4.893/2021) / indeterminado (recomendação LGPD)

---

*Template mantido por: Ricardo Neves Lougon — github.com/ricardolougon/incident-response-runbook*  
*Retornar ao índice: [README](../README.md) · Ver também: [05 — Recuperação e Lições Aprendidas](../runbook/05-recuperacao-licoes.md) · [Ficha de Registro de Incidente](ficha-registro-incidente.md)*
