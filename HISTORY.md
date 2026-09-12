# HISTORY — WAL do projeto (append-only; sessão nova no topo)

## 2026-09-12 · chore/contrato-ci-cd — Contrato operacional + CI/CD + proteção de main

- **Spec (M==N):** C1 contrato codificado em `AGENTS.md` · C2 CI com gates
  verdes no main commitado · C3 CD por tag `v*` · C4 main protegido com
  auto-merge · C5 incremento mergeado pelo loop, sem humano.
- **Evidência:** gates executados localmente contra main commitado ANTES do
  push — `bash -n` 43/43 OK; `shellcheck --exclude=SC1087,SC1128 -S error`
  exit 0. No PR: `statusCheckRollup` todo verde → merge `--auto`.
- **Débito criado:** D-1 — shellcheck error no main (ver TODO.md), adiado
  porque `07_audit_kernel.sh` está em modificação local do dono do repo.
