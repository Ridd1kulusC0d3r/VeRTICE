# VÉRTICE 1.1 — arquitetura implementada e limites

A versão mantém o aplicativo Python stdlib-only existente. A evolução sugerida para
API, banco PostgreSQL, workers persistentes e frontend separado é um caminho futuro,
não uma capacidade já implementada. SQLite + JSON permitem testar a jornada inteira no Colab.

## Decisões

| Decisão | Motivo | Consequência |
|---|---|---|
| Ledger como histórico de observações | Preservar versões sem apagar divergências | Grafo agregado não é snapshot de disponibilidade atual |
| Comparação por execução | Comparar conjuntos efetivamente observados | Falha não vira desaparecimento |
| `observed_at` separado de `collected_at` | Não tratar dados históricos como recentes | Datas ausentes permanecem desconhecidas |
| Origem no vínculo e hash da evidência | Explicar associações | Última evidência no grafo, histórico inteiro no ledger |
| Limite de tarefas e bytes | Conter expansão e memória | Resultados limitados ficam marcados como incompletos |
| Escopo explícito para atividade direta | Evitar expansão indevida a terceiros | IP resolvido não entra automaticamente no escopo |
| Imports em vez de executar ferramentas no Colab | Reproduzir resultados sem instalar scanners | Subfinder/Nmap precisam produzir seus arquivos fora do notebook |
| ZIP com lista permitida | Evitar incluir arquivo de credenciais | Exportação contém apenas os artefatos previstos |

## Contrato dos collectors

`Collector` declara nome, tipos de entrada, modo passivo/ativo, credencial e descrição.
Recebe entidade/workspace e devolve `Finding` com valor, tipo, relação, atributos,
dados de suporte e data observada opcional. `vertice collectors` lista esse contrato.
O engine captura chamadas dos helpers HTTP por thread e registra status/duração e
respostas limitadas. Exceções não são convertidas silenciosamente em ausência de achados.

Tipos de retorno inesperados de provedores podem ainda exigir validadores específicos.
Não há retentativa automática, rate limiting por provedor nem paginação completa em
todos os conectores. `completed` significa término das tarefas configuradas, não
exaustividade da fonte. As APIs comerciais requerem testes contratuais com contas reais.

## Modelo e compatibilidade

Workspaces v1.0 continuam legíveis. Não há migração destrutiva: metadados temporais
novos só existem nas novas observações. Uma execução interrompida fica identificada
pela ausência de `run-end`; não existe ainda retomada transacional da fila.

Atributos agregados do grafo mantêm o primeiro valor conhecido quando há conflito.
A comparação usa os atributos das observações por execução; o analista deve usar
as evidências para examinar divergências. Não há pontuação probabilística de confiança,
resolução automática de propriedade nem inferência automática de vulnerabilidade.

## Caminho para produção

1. Adicionar testes contratuais por fonte, paginação, retries com backoff e orçamento por API.
2. Tornar execuções retomáveis e os parsers reprocessáveis a partir das evidências brutas.
3. Implementar claims contraditórios, expiração de evidências e revisão humana persistida.
4. Migrar o estado para PostgreSQL e blobs para armazenamento de objetos quando necessário.
5. Expor API autenticada, isolamento por projeto, auditoria e retenção antes de multiusuário.
6. Criar interface React apenas após estabilizar contratos e consultas do produto.

Fontes de implementação: [Subfinder](https://github.com/projectdiscovery/subfinder),
[Nmap XML](https://nmap.org/book/output-formats-xml-output.html),
[proxy de saída do Colab](https://github.com/googlecolab/colabtools/blob/main/google/colab/output/_util.py).
Essas referências não implicam cópia de código ou integração integral.
