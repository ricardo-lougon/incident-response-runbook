# 04 — Notificação à ANPD (Prazo: 72 Horas)

> **Base legal:** LGPD Art. 48 — O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante aos titulares.

---

## ⏱️ Gestão do Prazo de 72 Horas

```
H+0   Detecção confirmada
H+4   Triagem: dados pessoais afetados? → Se sim, iniciar contagem
H+24  DPO recebe avaliação de impacto completa
H+48  Decisão formal: notificar ANPD? → DEVE estar tomada aqui
H+72  ⚠️  DEADLINE — Notificação à ANPD enviada (se aplicável)
```

> **Atenção:** A contagem das 72h começa do momento em que o controlador tem **ciência** do incidente, não da detecção técnica. Documente o momento exato de ciência.

---

## Passo 1 — Decidir se Notificação é Obrigatória

A ANPD deve ser notificada quando o incidente **puder** acarretar risco ou dano relevante. Aplica o princípio da precaução: em caso de dúvida, notifique.

**Notificação SEMPRE obrigatória:**
- Dados sensíveis afetados (saúde, biometria, racial, religiosos, político-partidários, sexual, criminal)
- Dados de crianças ou adolescentes
- Número significativo de titulares (threshold conservador: ≥ 500 titulares)
- Risco de fraude de identidade ou dano financeiro
- Acesso não autorizado a credenciais + dados pessoais no mesmo sistema

**Notificação provavelmente necessária:**
- Dados comuns + pequeno número de titulares + risco limitado → avaliar com o jurídico

**Justificar por escrito se decidir NÃO notificar** — essa decisão deve ser documentada e assinada pelo DPO e pelo jurídico.

---

## Passo 2 — Reunir as Informações Obrigatórias (Art. 48, §2º)

A notificação deve conter **no mínimo**:

```
1. NATUREZA DOS DADOS PESSOAIS AFETADOS
   □ Categorias: _______________________________________
   □ São dados sensíveis? ( ) Sim ( ) Não
   □ Incluem dados de crianças? ( ) Sim ( ) Não

2. INFORMAÇÕES SOBRE OS TITULARES
   □ Número estimado (ou exato, se conhecido): ___________
   □ Perfil: ( ) Clientes  ( ) Funcionários  ( ) Ambos  ( ) Outro

3. MEDIDAS TÉCNICAS E DE SEGURANÇA UTILIZADAS ANTES DO INCIDENTE
   □ Criptografia em repouso: ( ) Sim  ( ) Não
   □ Controle de acesso (IAM): ( ) Sim  ( ) Não
   □ Monitoramento (GuardDuty/CloudTrail): ( ) Sim  ( ) Não
   □ Outras medidas: _________________________________

4. RISCOS RELACIONADOS AO INCIDENTE
   □ Discriminação         ( ) Sim  ( ) Não  ( ) Possível
   □ Dano financeiro        ( ) Sim  ( ) Não  ( ) Possível
   □ Fraude de identidade   ( ) Sim  ( ) Não  ( ) Possível
   □ Dano reputacional      ( ) Sim  ( ) Não  ( ) Possível
   □ Outros: ___________________________________________

5. MEDIDAS ADOTADAS OU A SEREM ADOTADAS
   □ Contenção: ________________________________________
   □ Erradicação: ______________________________________
   □ Comunicação aos titulares: _________________________
   □ Melhorias preventivas: ____________________________

6. MOTIVO DE EVENTUAL DEMORA (se não for comunicação imediata)
   □ Justificativa: _____________________________________
```

---

## Passo 3 — Enviar a Notificação à ANPD

**Canal oficial:** Portal Gov.br — Sistema de Peticionamento da ANPD

**URL:** https://www.gov.br/anpd/pt-br/assuntos/incidentes-de-seguranca

**Passos:**
1. Acessar o portal com certificado digital (e-CNPJ da organização)
2. Selecionar: "Comunicação de Incidente de Segurança"
3. Preencher o formulário com as informações do Passo 2
4. Anexar: relatório técnico inicial + evidências disponíveis
5. **Salvar o protocolo de envio** — é a evidência de cumprimento do prazo

> **Importante:** A notificação inicial pode ser **preliminar** se todas as informações ainda não estiverem disponíveis. A ANPD permite complementação posterior. É melhor notificar preliminarmente dentro do prazo do que aguardar completude e perder o prazo.

---

## Passo 4 — Notificar os Titulares Afetados

Além da ANPD, a notificação aos titulares é obrigatória quando o incidente puder causar dano relevante.

**Use o template:** [comunicado-titular.md](../templates/comunicado-titular.md)

**Canais recomendados (em ordem de preferência):**
1. E-mail direto ao titular (se disponível e verificado)
2. Notificação via conta/perfil do titular na plataforma
3. SMS para celular cadastrado
4. Carta registrada (para dados críticos sem e-mail)
5. Publicação em site/comunicado público (apenas se não for possível contato individual)

**O comunicado ao titular deve conter:**
- O que aconteceu (em linguagem clara, não técnica)
- Quais dados foram afetados
- O que a organização está fazendo
- O que o titular pode fazer para se proteger
- Canal de contato para dúvidas (preferencialmente o DPO)

---

## Passo 5 — Notificação ao BCB (Instituições Financeiras)

Para IFs reguladas pelo Banco Central, a notificação ao BCB é obrigação adicional à ANPD.

**Canal:** Portal de Relacionamento do BCB  
**Prazo:** A Res. BCB 4.893/2021 não define prazo específico — adotar o mesmo prazo da ANPD (72h) como padrão conservador.

**Informações adicionais exigidas pelo BCB:**
- Impacto na continuidade dos serviços financeiros
- Número de clientes afetados
- Sistemas financeiros comprometidos (PIX, TED, etc.)
- Plano de recuperação e prazo estimado

---

## Documentação Pós-Notificação

```
□ Protocolo de envio à ANPD salvo e arquivado
□ Data/hora do envio documentada
□ Nome e cargo do responsável pelo envio documentados
□ Resposta/recibo da ANPD arquivado quando recebido
□ Registro de notificações a titulares (quem, quando, canal)
□ Toda documentação retida por mínimo 5 anos (BCB) / indeterminado (LGPD)
```

---

*Anterior: [03 — Avaliação de Impacto LGPD](03-avaliacao-impacto-lgpd.md) · Próximo: [05 — Recuperação e Lições Aprendidas](05-recuperacao-licoes.md)*
