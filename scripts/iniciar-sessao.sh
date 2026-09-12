#!/usr/bin/env bash
# ============================================================================
# github-ops-cicd — iniciar-sessao: bootstrap de continuidade da sessão local.
# Imprime o estado que a nova sessão precisa ANTES de planejar qualquer
# incremento: git + PRs + débitos/TODO + WAL do projeto.
# Config (env ou flags):
#   WAL_FILE   — changelog/HISTORY do projeto   (default: HISTORY.md|CHANGELOG.md)
#   DEBTS_FILE — fonte de débitos/TODO          (default: TODO.md se existir)
# Uso: bash iniciar-sessao.sh            (de dentro do repo)
# ============================================================================
set -uo pipefail
# opere no CWD: rode DENTRO do repo alvo (skill ou cópia local do repo)
[ -d .git ] || { echo "rode este script dentro do repo do projeto"; exit 1; }

echo "═══════════════════════════════════════════════════════════════"
echo " SESSÃO LOCAL — ESTADO DE CONTINUIDADE ($(date -u +%FT%TZ))"
echo "═══════════════════════════════════════════════════════════════"

echo -e "\n[1] GIT — branch atual, últimos commits, PRs abertos"
git branch --show-current
git log --oneline -3
gh pr list --state open --limit 5 \
  --template '{{range .}}PR #{{.number}} [{{.headRefName}}] {{.title}}{{"\n"}}{{end}}' \
  2>/dev/null || echo "  (gh indisponível ou sem PRs)"

echo -e "\n[2] DÉBITOS / TODO"
DEBTS_FILE="${DEBTS_FILE:-TODO.md}"
if [ -f "$DEBTS_FILE" ]; then
  head -20 "$DEBTS_FILE"
else
  echo "  (defina DEBTS_FILE=<fonte de débitos> para listá-los aqui)"
fi

echo -e "\n[3] ÚLTIMO WAL (o que aconteceu na sessão anterior)"
for f in "${WAL_FILE:-HISTORY.md}" CHANGELOG.md; do
  if [ -f "$f" ]; then tail -12 "$f"; break; fi
done

echo -e "\n[4] PRÓXIMO INCREMENTO — o loop (fluxo-gitops R1–R9)"
cat <<'EOF'
  spec (critérios verificáveis) → branch {feat|fix|refactor|chore|docs}/slug
  → commit → push origin/branch → CI gateia → VERMELHO? corrige no branch e
  push de novo (loop até verde) → PR → merge --auto (dispara sozinho no verde)
  → main → tag v* → release
EOF
echo "═══════════════════════════════════════════════════════════════"
