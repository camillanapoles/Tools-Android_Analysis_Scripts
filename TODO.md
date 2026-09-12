# TODO — Débitos abertos (D-*)

## D-1 — ShellCheck nível error no main (exclusões ativas no CI)

- `07_audit_kernel.sh`: SC1087 ×15 — `"$taint_list[N=...]"` dentro de aspas;
  corrigir para `${taint_list}` + `[N=...]` fora da expansão.
- `23_audit_network_deep.sh`: SC1128 — shebang não está na linha 1.
- Ao sanar: remover `--exclude=SC1087,SC1128` do job `ShellCheck erros`
  em `.github/workflows/ci.yml`.
- **Bloqueio:** arquivos em WIP local do dono do repo — não alterar sem
  alinhar primeiro.
