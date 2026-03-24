# 00 — Classificação e Triagem do Incidente

> **Tempo alvo:** Concluir em até 4 horas após a detecção.  
> **Objetivo:** Determinar se dados pessoais foram afetados e qual a criticidade.

---

## Passo 1 — Registrar o Incidente Imediatamente

Abra a [ficha de registro](../templates/ficha-registro-incidente.md) e preencha os campos obrigatórios:
- Data/hora da detecção
- Quem detectou e como
- Sistemas aparentemente afetados

> ⚠️ **Regra de ouro:** A ficha de registro é evidência legal. Documente tudo, mesmo que parcial. Não espere ter todas as informações para começar a registrar.

---

## Passo 2 — Árvore de Decisão de Criticidade

```
O incidente envolve sistemas que armazenam ou processam dados pessoais?
│
├─ NÃO → Classificar como incidente de segurança padrão (sem obrigação LGPD imediata)
│        Continuar monitorando para confirmar ausência de dados pessoais
│
└─ SIM → Dados pessoais foram ou podem ter sido acessados/exfiltrados/corrompidos?
         │
         ├─ NÃO CONFIRMADO (suspeita) → SEVERIDADE MÉDIA — investigar em 8h
         │
         └─ SIM CONFIRMADO →
              │
              ├─ Dados sensíveis* afetados? → SEVERIDADE CRÍTICA 🔴
              │    * saúde, biometria, origem racial, religião, político, sexual, judicial
              │
              ├─ Dados de crianças/adolescentes afetados? → SEVERIDADE CRÍTICA 🔴
              │
              ├─ +10.000 titulares afetados? → SEVERIDADE CRÍTICA 🔴
              │
              ├─ Risco de fraude financeira? → SEVERIDADE CRÍTICA 🔴
              │
              └─ Dados pessoais comuns, poucos titulares, risco limitado → SEVERIDADE ALTA 🟡
```

---

## Passo 3 — Perguntas de Triagem Obrigatórias

Responder em até 4 horas:

```
SISTEMA E DADOS
□ Quais sistemas AWS foram afetados? (IDs de recursos)
□ Esses sistemas armazenam dados pessoais? ( ) Sim ( ) Não ( ) Desconhecido
□ Quais categorias de dados pessoais? 
  ( ) Nome/e-mail/telefone    ( ) CPF/RG/documentos
  ( ) Dados financeiros        ( ) Dados de saúde
  ( ) Biometria                ( ) Localização
  ( ) Dados de crianças        ( ) Outros: ___________

EXTENSÃO DO INCIDENTE
□ O incidente ainda está ativo? ( ) Sim ( ) Não ( ) Desconhecido
□ Número estimado de titulares afetados: ____________
□ Período de exposição estimado: de ________ até ________

VETOR
□ Como o incidente ocorreu? (hipótese inicial)
  ( ) Credencial comprometida    ( ) Configuração incorreta (ex: S3 público)
  ( ) Vulnerabilidade técnica    ( ) Ameaça interna
  ( ) Phishing/engenharia social  ( ) Desconhecido

IMPACTO AOS TITULARES
□ Risco de discriminação?         ( ) Sim ( ) Não
□ Risco de fraude de identidade?  ( ) Sim ( ) Não
□ Risco de dano financeiro?       ( ) Sim ( ) Não
□ Risco de dano físico?           ( ) Sim ( ) Não
```

---

## Passo 4 — Ativar a Cadeia de Comunicação

| Severidade | Notificar imediatamente | Notificar em 4h | Notificar em 24h |
|---|---|---|---|
| 🔴 CRÍTICA | CISO + DPO + CEO | Equipe jurídica + Board | BCB (se IF) + Avaliação ANPD |
| 🟡 ALTA | CISO + DPO | Gestor responsável | |
| 🟢 MÉDIA | CISO | DPO (informativo) | |

**Contatos de emergência** *(preencher antes de precisar usar)*:

| Papel | Nome | Telefone | E-mail |
|---|---|---|---|
| CISO | | | |
| DPO | | | |
| CEO / Responsável | | | |
| Jurídico | | | |
| Equipe AWS | | | |
| Seguro cibernético | | | |

---

## Passo 5 — Decidir Próximos Passos

| Se... | Então... |
|---|---|
| Incidente ainda ativo | → Ir imediatamente para [01 — Contenção](01-contencao-aws.md) |
| Incidente contido, dados afetados | → Ir para [02 — Preservação de Evidências](02-preservacao-evidencias.md) |
| Dados pessoais confirmados | → Iniciar simultaneamente [03 — Avaliação de Impacto LGPD](03-avaliacao-impacto-lgpd.md) |
| Prazo de 72h em risco | → Iniciar [04 — Notificação ANPD](04-notificacao-anpd.md) preventivamente |

---

*Próximo: [01 — Contenção AWS](01-contencao-aws.md)*
