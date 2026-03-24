# Ficha de Registro de Incidente de Segurança

> **Instrução:** Preencher imediatamente ao confirmar o incidente. Esta ficha é evidência legal — documente tudo, mesmo que parcial. Atualizar continuamente até o encerramento.  
> **Retenção:** Mínimo 5 anos (Res. BCB 4.893/2021) / Prazo indeterminado recomendado (LGPD)

---

## IDENTIFICAÇÃO

| Campo | Valor |
|---|---|
| **ID do Incidente** | INC-[ANO]-[SEQUENCIAL] |
| **Data/hora de detecção** | ____/____/________ às ____:____ |
| **Data/hora de abertura desta ficha** | ____/____/________ às ____:____ |
| **Detectado por** | |
| **Canal de detecção** | ( ) GuardDuty ( ) Macie ( ) CloudWatch ( ) Usuário ( ) Externo ( ) Outro: |
| **Responsável pela investigação** | |
| **Status atual** | ( ) Triagem ( ) Contenção ( ) Investigação ( ) Erradicação ( ) Encerrado |

---

## DESCRIÇÃO DO INCIDENTE

**Descrição inicial (em linguagem clara):**

```
[Descrever o que foi detectado, quando, em qual sistema]




```

**Sistemas AWS afetados:**

| Recurso AWS | Tipo | Region | Dados pessoais? |
|---|---|---|---|
| | | | ( ) Sim ( ) Não ( ) Desconhecido |
| | | | ( ) Sim ( ) Não ( ) Desconhecido |
| | | | ( ) Sim ( ) Não ( ) Desconhecido |

---

## CLASSIFICAÇÃO (preencher em até 4h)

| Campo | Resposta |
|---|---|
| **Dados pessoais afetados?** | ( ) Sim ( ) Não ( ) Sob investigação |
| **Categorias de dados** | ( ) Comuns ( ) Sensíveis ( ) Financeiros ( ) Crianças |
| **Titulares afetados (estimativa)** | |
| **Período de exposição** | De ________ até ________ |
| **Vetor do incidente** | ( ) Credencial ( ) Configuração ( ) Vulnerabilidade ( ) Interno ( ) Desconhecido |
| **Severidade** | ( ) 🔴 Crítica ( ) 🟡 Alta ( ) 🟢 Média |
| **Incidente ainda ativo?** | ( ) Sim ( ) Não |

---

## CADEIA DE COMUNICAÇÃO

| Papel | Nome | Notificado em | Canal |
|---|---|---|---|
| CISO | | | |
| DPO | | | |
| CEO/Responsável | | | |
| Equipe Jurídica | | | |
| BCB (se IF) | | | |

---

## LINHA DO TEMPO DO INCIDENTE

| Data/Hora | Evento | Responsável |
|---|---|---|
| | Detecção: | |
| | Ciência formal pelo controlador: | |
| | Contenção iniciada: | |
| | Contenção concluída: | |
| | DPO notificado: | |
| | Avaliação de impacto LGPD concluída: | |
| | Decisão sobre notificação ANPD: | |
| | Notificação ANPD enviada: | |
| | Titulares notificados: | |
| | Erradicação concluída: | |
| | Encerramento do incidente: | |

**Protocolo de notificação ANPD:** ___________________________  
**Data/hora do envio:** ____/____/________ às ____:____

---

## EVIDÊNCIAS COLETADAS

| # | Tipo de evidência | Localização | Hash SHA256 | Coletado por |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

---

## AÇÕES DE CONTENÇÃO E REMEDIAÇÃO

| # | Ação tomada | Data/hora | Responsável | Resultado |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

---

## DECISÃO DE NOTIFICAÇÃO LGPD

```
Dados pessoais afetados?  ( ) Sim  ( ) Não

Se SIM:
  Notificação à ANPD necessária?  ( ) Sim  ( ) Não
  Justificativa: _________________________________________________

  Se NÃO notificar — fundamentação legal (obrigatório):
  ____________________________________________________________
  Assinatura DPO: ____________________  Data: ____/____/________
  Assinatura Jurídico: ________________  Data: ____/____/________
```

---

## ENCERRAMENTO

**Data de encerramento:** ____/____/________  
**Causa raiz identificada:** _______________________________________________  
**Lições aprendidas:** ____________________________________________________  
**Melhorias implementadas:** _______________________________________________

**Assinaturas:**

| Papel | Nome | Assinatura | Data |
|---|---|---|---|
| Responsável pela investigação | | | |
| DPO | | | |
| CISO | | | |

---

*Template mantido por: Ricardo Neves Lougon — github.com/ricardolougon/incident-response-runbook*
