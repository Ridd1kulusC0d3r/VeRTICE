# 🔺 COMECE AQUI — VÉRTICE

> **Uma ação por vez.** Faça só o passo atual, confira o resultado esperado, e
> só então vá para o próximo. Não precisa instalar nada além do Python.

**O que é o VÉRTICE:** plataforma OSINT de *Attack Surface Mapping & Intelligence
Gathering* — mapeia a superfície de ataque de um alvo autorizado, guarda as
evidências com custódia criptográfica e prepara a fase de pentest. Família
DEIVOSINT. Python stdlib puro (zero dependências).

---

## ✅ Passo 0 — confirme o Python (uma ação)

No terminal, rode:

```
python3 --version
```

**Esperado:** algo como `Python 3.9` ou superior. Se aparecer, siga.
(No Windows use `python --version`.)

➡️ Deu certo? Vá ao Passo 1.

---

## ✅ Passo 1 — veja o VÉRTICE funcionando (uma ação)

Na pasta do projeto, rode a demonstração offline (dados fictícios, sem internet):

```
python3 -m vertice demo demo-vertice
```

**Esperado:** `[ok] workspace de demonstração criado em: demo-vertice`.

➡️ Apareceu? Vá ao Passo 2.

---

## ✅ Passo 2 — gere o dossiê (uma ação)

```
python3 -m vertice report demo-vertice -o demo-vertice/dossie.html
```

**Esperado:** `[ok] dossiê gerado: demo-vertice/dossie.html`.
Abra esse arquivo no navegador: você verá o grafo, os alvos priorizados, o menu
de pivô e a verificação da cadeia de custódia.

> Atalho: dê **dois cliques** em `launchers/vertice-demo.sh` (Linux),
> `launchers/vertice-demo.command` (macOS) ou `launchers/vertice-demo.bat`
> (Windows) — ele faz os Passos 1 e 2 e abre o dossiê sozinho.

➡️ Viu o dossiê? Vá ao Passo 3.

---

## ✅ Passo 3 — confirme a integridade das evidências (uma ação)

```
python3 -m vertice verify demo-vertice
```

**Esperado:** `[ok] cadeia íntegra — 51 registros`. Isso prova que nenhuma
evidência foi adulterada (cada registro é selado por SHA-256 encadeado).

➡️ Funcionou? Você já domina o básico. Vá ao Passo 4 quando quiser investigar de verdade.

---

## ✅ Passo 4 — sua primeira investigação real (uma ação de cada vez)

> ⚠️ **Só investigue alvos que você está autorizado a investigar.** O escopo
> entra aqui e o VÉRTICE respeita-o para qualquer coleta ativa.

1. Crie o engajamento (troque pelo seu alvo e sua autorização):

   ```
   python3 -m vertice init meu-caso --scope alvo-autorizado.com --by "Contrato X"
   ```

2. Rode a coleta **passiva** (profundidade 2 = segue os subdomínios achados):

   ```
   python3 -m vertice run meu-caso --seed alvo-autorizado.com --depth 2
   ```

3. Gere o dossiê:

   ```
   python3 -m vertice report meu-caso -o meu-caso/dossie.html
   ```

**Pronto.** Para o manual completo (ilustrado, com telas, diagramas e solução de
problemas), abra **`docs/manual.html`** no navegador.

---

## Onde está cada coisa

| Arquivo | O que é |
|--------|---------|
| `docs/manual.html` | Manual ilustrado completo (comece por aqui se tiver dúvida) |
| `docs/ENGENHARIA-REVERSA.md` | Como as 13 ferramentas viraram o VÉRTICE |
| `RELATORIO-TESTES.md` | O que foi testado em nuvem e o resultado |
| `launchers/` | Lançadores de dois cliques |
| `vertice/` | O código (núcleo, collectors, pivôs, relatório) |
| `tests/` | Testes automatizados (`python3 -m unittest discover -s tests`) |

Dúvida de comando? `python3 -m vertice --help`.
