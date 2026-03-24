# 🚨 Incident Response Runbook — AWS + LGPD + BCB 4.893

> Runbook completo de resposta a incidentes de segurança em ambientes AWS, com cumprimento das obrigações legais brasileiras — incluindo notificação à ANPD em 72 horas.

---

## ⚖️ Por Que um Runbook é Obrigação Legal

| Norma | Dispositivo | Exigência |
|---|---|---|
| **LGPD** | Art. 48 | Comunicar à ANPD e titulares incidentes com risco relevante, em prazo razoável (regulamentado como 72h) |
| **Res. BCB 4.893/2021** | Art. 4º, VIII | Procedimentos de resposta a incidentes documentados, testados e atualizados periodicamente |
| **ISO 27001:2022** | Controle 5.26 | Plano de resposta a incidentes de segurança da informação |
| **NIST CSF 2.0** | RS (Respond) | Plano de comunicação, análise, mitigação e melhoria |

---

## 📁 Estrutura do Repositório

```
incident-response-runbook/
│
├── README.md
│
├── runbook/
│   ├── 00-classificacao-triagem.md      # Como classificar o incidente
│   ├── 01-contencao-aws.md              # Contenção técnica na AWS (comandos prontos)
│   ├── 02-preservacao-evidencias.md     # Forense: preservar sem contaminar
│   ├── 03-avaliacao-impacto-lgpd.md     # Avaliação legal de impacto em dados pessoais
│   ├── 04-notificacao-anpd.md           # Passo a passo da notificação à ANPD (72h)
│   └── 05-recuperacao-licoes.md        # Erradicação, recuperação e lições aprendidas
│
├── playbooks/
│   ├── credencial-comprometida.md       # Cenário: access key ou senha vazada
│   ├── s3-bucket-exposto.md             # Cenário: bucket S3 público com dados pessoais
│   ├── ransomware-ec2.md               # Cenário: instância EC2 com ransomware
│   └── exfiltracao-dados.md            # Cenário: suspeita de exfiltração de dados
│
├── templates/
│   ├── ficha-registro-incidente.md      # Registro formal do incidente
│   ├── comunicado-anpd.md              # Template de notificação à ANPD
│   ├── comunicado-titular.md           # Template de comunicação ao titular
│   └── relatorio-pos-incidente.md      # Relatório de lições aprendidas
│
└── scripts/
    ├── isolate-ec2.sh                   # Isolar instância comprometida
    ├── revoke-credentials.sh            # Revogar credenciais comprometidas
    └── collect-forensic-evidence.sh     # Coletar evidências forenses
```

---

## ⏱️ Linha do Tempo Legal

```
H+0    Detecção do incidente
H+4    Triagem concluída — dados pessoais afetados? Sim/Não
H+8    Contenção implementada
H+24   Avaliação de impacto concluída — DPO notificado
H+48   Decisão sobre notificação à ANPD tomada
H+72   ⚠️  PRAZO LGPD — Notificação à ANPD enviada (se aplicável)
H+72+  Erradicação, recuperação e relatório final
```

---

## 🚀 Início Rápido — Incidente Ativo

**Se você está respondendo a um incidente agora:**

1. **Abra uma ficha de registro:** [ficha-registro-incidente.md](templates/ficha-registro-incidente.md)
2. **Classifique o incidente:** [00-classificacao-triagem.md](runbook/00-classificacao-triagem.md)
3. **Execute a contenção:** [01-contencao-aws.md](runbook/01-contencao-aws.md)
4. **Consulte o playbook específico** em `playbooks/` se disponível
5. **Não perca o prazo de 72h:** [04-notificacao-anpd.md](runbook/04-notificacao-anpd.md)

---

## 👤 Autor

**Ricardo Neves Lougon**  
Bacharel em Direito · Especialista AWS Security · Compliance Cloud  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-ricardolougon-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/ricardolougon)
[![Playbook](https://img.shields.io/badge/Ver%20também-AWS%20Security%20Playbook%20LGPD-2E4057?style=flat)](https://github.com/ricardolougon/aws-security-playbook-lgpd)

---

*Keywords: Incident Response · LGPD Art. 48 · ANPD · AWS Security · GuardDuty · Forensics · BCB 4.893 · ISO 27001 · Runbook · Playbook*
