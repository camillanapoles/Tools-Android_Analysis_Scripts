# AGENTS.md — Contrato Operacional (Tools-Android_Analysis_Scripts)

Lei de projeto para toda sessão (humana ou de agente) que produz software aqui.
Infração = PR bloqueado pelos gates; não existe merge humano no circuito.

## 1. Unidade de trabalho

**1 solicitação = 1 sessão = 1 incremento = 1 PR mergeado por gates.**
Nada de push direto em `main`. Nada de merge manual: `gh pr merge --auto`
dispara sozinho quando TODOS os checks required estão verdes.

## 2. O loop determinístico (R1–R9)

```
spec (critérios verificáveis M==N) → branch {feat|fix|refactor|chore|docs}/slug
→ commit → push origin/branch (mesmo nome) → CI gateia
→ VERMELHO? corrige NO branch → push → re-gateia (loop até verde)
→ PR (critérios + evidência) → merge auto → main → tag v* → CD Release
```

- **R1** Spec primeiro: sem critérios verificáveis, sem branch.
- **R3** Branch local e origin com o MESMO nome, sem renomeação.
- **R5** PR somente com critérios da spec TODOS atendidos (M==N) + checks verdes.
- **R6** Main protegido: required checks + PR obrigatório + strict.
- **R7** Tag `v*` dispara CD (Release com `--verify-tag`).
- **R9** Nova sessão começa com `bash scripts/iniciar-sessao.sh`
  (git + PRs + débitos + WAL) — nunca do zero, nunca de memória.

## 3. Arquitetura obrigatória (código de feature)

Toda feature é **micro-software entregue por CI/CD** e obedece, sem exceção:

1. **Orientação a objetos total** — entidades com comportamento; nada de
   dicionários/arrays soltos carregando semântica de domínio.
2. **Zero hardcoded** — nenhum caminho, segredo, valor de ambiente ou
   configuração literal no código; tudo vem de config/env/DB.
3. **DB = fonte única de informação** — persistência somente via backend
   **FastAPI** que gerencia CRUD, gestão e queries. Nenhum consumidor
   escreve no DB por fora do backend.
4. **Event-driven ou gate-driven sempre** — efeitos e integrações por
   eventos/gates determinísticos; nenhuma lógica de negócio em script solto.
5. **ORM com relacionamentos** — entidades mapeadas com FK, IDs como objetos
   e relacionamentos declarados (padrão SQLModel/SQLAlchemy); proibido SQL
   concatenado em string.
6. **Best practices** — o incremento que introduz um stack (ex.: Python)
   introduz no MESMO incremento o gate dele no CI (testes, lint, tipos).

## 4. Gates do CI (checks required de main)

| Check (nome exato) | Garante |
|---|---|
| `Sintaxe Bash (bash -n)` | todo `.sh` trackeado parseia |
| `ShellCheck erros` | nível error (exclusões = débitos em TODO.md) |
| `Workflows YAML validos` | todo workflow parseia |

## 5. Continuidade de sessão

- `scripts/iniciar-sessao.sh` — estado completo antes de planejar.
- `HISTORY.md` — WAL: cada sessão anexa o que fez + evidência (append-only).
- `TODO.md` — débitos (D-*): o que ficou pendente e por quê.
