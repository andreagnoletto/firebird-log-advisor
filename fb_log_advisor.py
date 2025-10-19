#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fb_log_advisor.py — Analisa firebird.log e/ou um trace do Firebird 3+ e sugere melhorias.
Licença: MIT (este arquivo). Requer: firebird-lib (MIT).

Instalação:
    pip install firebird-lib

Uso:
    python fb_log_advisor.py --firebird-log /caminho/para/firebird.log
    python fb_log_advisor.py --trace-log /caminho/para/trace.log --slow-ms 500 --min-count 5 --out fb_advice.json

Saída:
    - Impressão resumida no console
    - Arquivo JSON com achados e recomendações (--out)
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

# Tipos opcionais se firebird-lib não estiver instalado
try:
    from firebird.lib.log import LogParser, Severity, Facility, LogMessage  # type: ignore
    from firebird.lib.trace import TraceParser  # type: ignore
    # Os tipos de evento variam por versão; importamos por nome quando possível
    from firebird.lib.trace import (
        EventStatementFinish, EventStatementStart, EventPrepareStatement,
        EventCommit, EventRollback, SQLInfo, AccessStats
    )  # type: ignore
except Exception as exc:  # pragma: no cover
    LogParser = None          # type: ignore
    TraceParser = None        # type: ignore
    Severity = Facility = None  # type: ignore
    EventStatementFinish = EventStatementStart = EventPrepareStatement = None  # type: ignore
    EventCommit = EventRollback = SQLInfo = AccessStats = None  # type: ignore
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


@dataclass
class Finding:
    kind: str
    title: str
    evidence: Any
    recommendation: str
    severity: str  # low | medium | high


def _require_deps():
    if _IMPORT_ERROR is not None:
        raise SystemExit(
            "ERRO: Dependência 'firebird-lib' não encontrada.\n"
            "Instale com:  pip install firebird-lib\n"
            f"Detalhes: {repr(_IMPORT_ERROR)}"
        )


def analyze_firebird_log(path: str) -> Dict[str, Any]:
    """Analisa firebird.log com heurísticas simples."""
    _require_deps()
    findings: List[Finding] = []
    counters = Counter()
    errors = []
    warnings = []

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        parser = LogParser()
        for msg in parser.parse(f):
            counters[(msg.level.name if hasattr(msg.level, "name") else str(msg.level),
                      msg.facility.name if hasattr(msg.facility, "name") else str(msg.facility))] += 1
            text = (msg.message or "").lower()
            rec: Optional[Finding] = None

            # Heurísticas por palavras‑chave
            if any(k in text for k in ["i/o error", "no space left", "permission denied"]):
                rec = Finding(
                    kind="os_io",
                    title="Erros de I/O no servidor",
                    evidence={"line": msg.message, "timestamp": str(msg.timestamp)},
                    recommendation=(
                        "Verifique disco e permissões do volume dos arquivos .fdb e diretório de logs. "
                        "Garanta espaço livre e backups recentes; avalie mover TEMP e logs para discos separados."
                    ),
                    severity="high",
                )
            elif "deadlock" in text or "lock conflict" in text:
                rec = Finding(
                    kind="concurrency",
                    title="Conflitos de bloqueio / deadlocks",
                    evidence={"line": msg.message, "timestamp": str(msg.timestamp)},
                    recommendation=(
                        "Revise isolamento/transações do aplicativo e índices nas colunas usadas em UPDATE/DELETE. "
                        "Use TRACE para identificar as consultas envolvidas e reduza a duração das transações."
                    ),
                    severity="medium",
                )
            elif "database appears corrupt" in text or "page" in text and "error" in text:
                rec = Finding(
                    kind="validation",
                    title="Possível corrupção/erro de página",
                    evidence={"line": msg.message, "timestamp": str(msg.timestamp)},
                    recommendation=(
                        "Execute gfix -v -full e avalie backup/restore. Verifique hardware (RAM/Disco) e atualize para a última versão estável do Firebird."
                    ),
                    severity="high",
                )
            elif "guardian" in text and ("restart" in text or "starting" in text):
                rec = Finding(
                    kind="stability",
                    title="Reinícios do serviço (Guardian)",
                    evidence={"line": msg.message, "timestamp": str(msg.timestamp)},
                    recommendation=(
                        "Investigue falhas do serviço (analisar trace e logs de sistema). "
                        "Atualize plugins/drivers; isole queries/rotinas que precedem o crash."
                    ),
                    severity="high",
                )
            elif "authentication" in text or "auth" in text and "failed" in text:
                rec = Finding(
                    kind="security",
                    title="Falhas de autenticação repetidas",
                    evidence={"line": msg.message, "timestamp": str(msg.timestamp)},
                    recommendation=(
                        "Habilite auditoria para ATTACH/DISCONNECT e revise credenciais/origens. "
                        "Considere limitar acesso de rede e ativar SRP com políticas fortes."
                    ),
                    severity="low",
                )

            if rec:
                findings.append(rec)

            if hasattr(Severity, "ERROR") and msg.level == Severity.ERROR:
                errors.append(msg.message)
            elif hasattr(Severity, "WARNING") and msg.level == Severity.WARNING:
                warnings.append(msg.message)

    top_pairs = counters.most_common(10)
    return {
        "summary": {
            "by_severity_facility": [{ "key": f"{k[0]}/{k[1]}", "count": v } for k, v in top_pairs],
            "errors_sample": errors[:10],
            "warnings_sample": warnings[:10],
        },
        "findings": [asdict(f) for f in findings],
    }


def analyze_trace_log(path: str, slow_ms: int, min_count: int) -> Dict[str, Any]:
    """Analisa um arquivo de trace do fbtracemgr com heurísticas de performance"""
    _require_deps()
    parser = TraceParser()
    findings: List[Finding] = []

    # Mapas auxiliares
    sql_text: Dict[int, str] = {}
    sql_plan: Dict[int, str] = {}

    slow_statements: List[Dict[str, Any]] = []
    natural_scans: Counter = Counter()
    prepares_per_sql: Counter = Counter()
    txn_commit_times: List[int] = []
    stmt_counts: Counter = Counter()

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for item in parser.parse(f):
            cname = item.__class__.__name__
            # SQLInfo leva o texto/plan
            if SQLInfo and isinstance(item, SQLInfo):
                sql_text[item.sql_id] = item.sql
                sql_plan[item.sql_id] = item.plan
            # Preparos (muitos prepares do mesmo SQL podem indicar falta de cache no app)
            elif EventPrepareStatement and isinstance(item, EventPrepareStatement):
                prepares_per_sql[item.sql_id] += 1
            # Execução de statement (finish tem run_time, contadores e sql_id)
            elif EventStatementFinish and isinstance(item, EventStatementFinish):
                stmt_counts[item.sql_id] += 1
                rt = int(getattr(item, "run_time", 0) or 0)  # ms
                acc = getattr(item, "access", None)
                nat = getattr(acc, "natural", 0) if acc else 0
                reads = int(getattr(item, "reads", 0) or 0)
                writes = int(getattr(item, "writes", 0) or 0)
                records = int(getattr(item, "records", 0) or 0)

                if rt >= slow_ms:
                    slow_statements.append({
                        "sql_id": item.sql_id,
                        "sql": sql_text.get(item.sql_id, ""),
                        "plan": sql_plan.get(item.sql_id, ""),
                        "run_time_ms": rt,
                        "reads": reads,
                        "writes": writes,
                        "records": records,
                        "natural_scans": nat,
                    })
                if nat and nat > 0:
                    natural_scans[item.sql_id] += nat

            elif EventCommit and isinstance(item, EventCommit):
                if getattr(item, "run_time", None) is not None:
                    txn_commit_times.append(int(item.run_time))

    # Heurísticas de recomendações
    slow_statements.sort(key=lambda x: x["run_time_ms"], reverse=True)
    top_slow = slow_statements[:20]

    if top_slow:
        examples = [{
            "run_time_ms": s["run_time_ms"],
            "sql": s["sql"][:300],
            "plan": s["plan"]
        } for s in top_slow[:5]]
        findings.append(Finding(
            kind="slow_sql",
            title=f"{len(top_slow)} statements acima de {slow_ms} ms",
            evidence={"examples": examples},
            recommendation=(
                "Crie índices nas colunas de filtros/junções (WHERE/JOIN), evite funções em colunas indexadas, "
                "considere planos forçados apenas temporariamente e reescreva consultas com NATURAL/varredura ampla."
            ),
            severity="high" if top_slow and top_slow[0]['run_time_ms'] > 5000 else "medium"
        ))

    # NATURAL scans
    worst_natural = natural_scans.most_common(10)
    if worst_natural:
        ex = [{
            "sql": sql_text.get(sql_id, "")[:300],
            "plan": sql_plan.get(sql_id, ""),
            "natural_ops": count
        } for sql_id, count in worst_natural[:5]]
        findings.append(Finding(
            kind="natural_scan",
            title="Acesso NATURAL (varredura de tabela) detectado",
            evidence={"examples": ex},
            recommendation=(
                "Verifique estatísticas de índices (SET STATISTICS) e crie índices apropriados para as condições "
                "de filtro. Avalie segmentação de índices compostos e cobertura de consultas frequentes."
            ),
            severity="high"
        ))

    # Prepares excessivos
    many_prepares = [ (sid, c) for sid, c in prepares_per_sql.items() if c >= max(min_count, 10) ]
    if many_prepares:
        ex = [{
            "count_prepares": c,
            "sql": sql_text.get(sid, "")[:300]
        } for sid, c in sorted(many_prepares, key=lambda x: x[1], reverse=True)[:5]]
        findings.append(Finding(
            kind="prepare_hotspot",
            title="Excesso de PREPARE do mesmo SQL",
            evidence={"examples": ex},
            recommendation=(
                "Reutilize statements preparados e parâmetros no pool de conexões/ORM. "
                "Evite reconstruir a mesma string SQL a cada execução."
            ),
            severity="medium"
        ))

    # Commits lentos indicam I/O ou transações muito grandes
    if txn_commit_times:
        p95 = sorted(txn_commit_times)[int(0.95 * (len(txn_commit_times) - 1))]
        if p95 >= max(slow_ms, 500):
            findings.append(Finding(
                kind="commit_slow",
                title="Commits lentos",
                evidence={"p95_commit_ms": p95, "samples": txn_commit_times[:20]},
                recommendation=(
                    "Reduza o tamanho de transações, confirme mais frequentemente, "
                    "avalie forced writes e dispositivo de armazenamento (latência/IOPS)."
                ),
                severity="medium"
            ))

    return {
        "summary": {
            "slow_statements_total": len(top_slow),
            "distinct_sql_seen": len(stmt_counts),
        },
        "findings": [asdict(f) for f in findings],
        "samples": {
            "top_slow": top_slow[:10],
        }
    }


def main():
    ap = argparse.ArgumentParser(description="Analisa logs do Firebird (server log e trace) e sugere melhorias.")
    ap.add_argument("--firebird-log", help="Caminho para firebird.log")
    ap.add_argument("--trace-log", help="Caminho para o arquivo de trace gerado pelo fbtracemgr")
    ap.add_argument("--slow-ms", type=int, default=500, help="Limiar de 'consulta lenta' (ms) para o trace")
    ap.add_argument("--min-count", type=int, default=5, help="Mínimo para consolidar achados repetidos")
    ap.add_argument("--out", default="fb_advice.json", help="Arquivo JSON de saída com achados e recomendações")
    args = ap.parse_args()

    if not args.firebird_log and not args.trace_log:
        ap.error("Informe pelo menos --firebird-log ou --trace-log")

    report: Dict[str, Any] = {"advisor_version": "1.0.0"}
    if args.firebird_log:
        if not os.path.isfile(args.firebird_log):
            raise SystemExit(f"Arquivo não encontrado: {args.firebird_log}")
        report["server_log"] = analyze_firebird_log(args.firebird_log)

    if args.trace_log:
        if not os.path.isfile(args.trace_log):
            raise SystemExit(f"Arquivo não encontrado: {args.trace_log}")
        report["trace_log"] = analyze_trace_log(args.trace_log, args.slow_ms, args.min_count)

    # Consolidação de recomendações
    recommendations: List[Finding] = []
    for section in ("server_log", "trace_log"):
        if section in report:
            for f in report[section]["findings"]:
                recommendations.append(Finding(**f))

    # Ordena por severidade (high > medium > low)
    order = {"high": 0, "medium": 1, "low": 2}
    recommendations_sorted = sorted(recommendations, key=lambda x: order.get(x.severity, 3))

    report["recommendations"] = [asdict(f) for f in recommendations_sorted]

    with open(args.out, "w", encoding="utf-8") as fp:
        json.dump(report, fp, ensure_ascii=False, indent=2)

    # Resumo humano
    print("=== FB Log Advisor ===")
    if "server_log" in report:
        print(f"- Itens do firebird.log: {len(report['server_log']['findings'])}")
    if "trace_log" in report:
        print(f"- Statements lentos: {report['trace_log']['summary']['slow_statements_total']}")
    print(f"Arquivo salvo: {args.out}")


if __name__ == "__main__":
    main()
