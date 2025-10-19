# Firebird Log Advisor (FB 3+)

Analisador open source que lê **`firebird.log`** e **traces do Firebird 3+** (via `fbtracemgr`), produzindo um relatório com **achados** e **recomendações** (índices, reescrita de SQL, ajuste de transações, I/O, etc.).  
**Licença:** MIT

> **Objetivo:** transformar logs em ações práticas para melhorar desempenho, estabilidade e segurança de bancos Firebird 3+.

---

## Conteúdo
- [Recursos principais](#recursos-principais)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso rápido](#uso-rápido)
- [Como gerar um trace no Firebird 3](#como-gerar-um-trace-no-firebird-3)
- [Saída (exemplo)](#saída-exemplo)
- [Heurísticas de recomendações](#heurísticas-de-recomendações)
- [Limitações](#limitações)
- [Roadmap](#roadmap)
- [Contribuindo](#contribuindo)
- [Licença](#licença)
- [Agradecimentos](#agradecimentos)

---

## Recursos principais
- **Parse de `firebird.log`**: identifica erros de I/O, conflitos de bloqueio (*deadlocks*), mensagens de corrupção, reinícios de serviço, falhas de autenticação, etc.
- **Parse de trace (fbtracemgr)**: detecta **statements lentos**, **acessos NATURAL** (varreduras de tabela), **excesso de PREPARE**, **commits lentos**, contadores de I/O por execução e **planos**.
- **Relatório consolidado**: gera um **JSON** com achados e recomendações **priorizadas por severidade**.
- **CLI simples**: defina limiar de “consulta lenta” (`--slow-ms`) e **amostras mínimas** para consolidar repetidos (`--min-count`).

---

## Requisitos
- **Python** 3.8+  
- **Sistema operacional**: Linux ou Windows  
- **Dependências Python**:
  - `firebird-lib` (parser de logs/trace do Firebird)
  - (demais dependências estão na biblioteca padrão)

> **Instale** a dependência principal:
```bash
pip install firebird-lib
