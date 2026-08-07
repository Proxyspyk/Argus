# Argus

**Cem olhos, nenhum descanso.** Na mitologia grega, Argus Panoptes era o
gigante de cem olhos que nunca dormia por completo — sempre havia algum
olho aberto vigiando. Esse é o espírito da ferramenta: vigiar continuamente
as versões de componentes críticos do seu sistema Linux contra vulnerabilidades conhecidas.

Scanner que detecta componentes críticos de um sistema Linux (kernel, glibc,
sudo, systemd, polkit, openssl, docker, podman, snap, etc.) e cruza as
versões instaladas com o **NVD** (CVEs + CVSS) e o **EPSS** (probabilidade
real de exploração), gerando um relatório de risco priorizado.

Diferente de ferramentas como LinPEAS/LinEnum (que enumeram possíveis
vetores de escalada de privilégio), este projeto foca em **correlacionar
versões instaladas com vulnerabilidades conhecidas e sua probabilidade real
de exploração**, para ajudar a priorizar o que corrigir primeiro.

> ⚠️ **Uso defensivo.** Esta ferramenta é somente leitura: não executa
> exploits nem explora vulnerabilidades. Ela detecta versões e consulta
> bases públicas de CVE. Use apenas em sistemas que você tem autorização
> para auditar.

## Como funciona

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐     ┌──────────┐
│  collectors  │ --> │    matcher    │ --> │    report    │ --> │  saída   │
│ (kernel,     │     │ (NVD + EPSS + │     │ (terminal /  │     │ terminal │
│  pacotes...) │     │  risk score)  │     │   JSON)      │     │ / JSON   │
└──────────────┘     └───────────────┘     └──────────────┘     └──────────┘
```

1. **`collectors.py`** — coleta local, somente leitura (kernel via
   `platform`, distro via `/etc/os-release`, versões de pacotes via
   `dpkg`/`rpm` ou `--version` dos binários).
2. **`nvd_client.py`** — consulta a [API pública do NVD 2.0](https://nvd.nist.gov/developers/vulnerabilities)
   por palavra-chave (nome do componente).
3. **`epss_client.py`** — consulta a [API EPSS do FIRST.org](https://www.first.org/epss/api)
   para estimar a probabilidade de exploração real nos próximos 30 dias.
4. **`matcher.py`** — filtra CVEs cuja descrição menciona a versão
   instalada (heurística, reduz falsos positivos) e calcula um
   `risk_score` (0–100) combinando CVSS + EPSS + indício de exploit público.
5. **`report.py`** — imprime um relatório no terminal e, opcionalmente,
   exporta JSON (útil para CI/CD ou outras ferramentas).

## Instalação

```bash
git clone https://github.com/Proxyspyk/argus.git
cd argus
pip install -e .
```

Requer Python 3.10+.

## Uso

```bash
# scan simples, imprime relatório no terminal
argus scan

# salva também um relatório JSON
argus scan --json report.json

# desativa o filtro de versão (mais resultados, mais ruído)
argus scan --no-version-filter

# usa uma API key do NVD (aumenta o rate limit de 5 para 50 req/30s)
# gratuita em https://nvd.nist.gov/developers/request-an-api-key
argus scan --api-key SUA_KEY
# ou: export NVD_API_KEY=SUA_KEY
```

### Exemplo de saída

```
[+] Sistema
    Distro : Ubuntu 24.04
    Kernel : 6.12.23
    Arch   : x86_64

[+] Componentes detectados
    sudo       1.9.15p5             (binary)
    systemd    255.4                (dpkg)
    openssl    3.0.13               (dpkg)

[+] Possíveis vulnerabilidades (1)

CVE-2026-XXXXX  risco: 87.4/100
    Componente : sudo 1.9.15p5
    CVSS       : 8.8 (HIGH)
    EPSS       : 93.0%
    Exploit    : ✔ indício de exploit público
    Descrição  : ...
```

## Limitações conhecidas (leia antes de confiar no resultado)

- O matching é feito por **palavra-chave + heurística de versão na
  descrição da CVE**, não por CPE 2.3 exato. Isso significa que pode haver
  **falsos positivos e falsos negativos**. Trate o relatório como uma
  lista de priorização, não como confirmação definitiva.
- A API do NVD tem rate limit agressivo sem API key (5 req/30s), então
  scans com muitos componentes podem demorar. Use `NVD_API_KEY` para
  acelerar.
- "Indício de exploit público" é uma heurística baseada nas referências
  do próprio NVD — não é uma checagem contra ExploitDB/GitHub PoCs
  (contribuições bem-vindas, veja abaixo).

## Roadmap / ideias para contribuir

- [ ] Matching por CPE 2.3 real (usar o dicionário oficial de CPEs)
- [ ] Integração com ExploitDB (mirror CSV) e busca de PoCs no GitHub
- [ ] Exportar relatório em HTML
- [ ] Modo "apenas kernel" para scans rápidos
- [ ] Suporte a mais distros/gerenciadores de pacote (apk, pacman)

## Testes

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Licença

MIT — veja [LICENSE](LICENSE).

## Autor

**Gabriel Knobbe da Silveira** ([@Proxyspyk](https://github.com/Proxyspyk))
Hacker ético focado em Bug Bounty, Pentest e Red Team.

[LinkedIn](https://www.linkedin.com/in/gabriel-knobbe-da-silveira-628620362/)
