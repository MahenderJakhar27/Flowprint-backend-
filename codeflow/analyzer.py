from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Any, Iterable
import warnings


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
}

FLOW_PATTERN = re.compile(
    r"\b(if|elif|else if|switch|case|when|guard|match|return|raise|throw|await|try|catch)\b",
    re.IGNORECASE,
)
CHECK_HINTS = {
    "validation": ("validate", "validator", "invalid", "valid"),
    "eligibility": ("eligible", "eligibility", "allow", "deny"),
    "status": ("status", "state", "active", "inactive"),
    "risk": ("risk", "fraud", "score", "threshold"),
    "kyc": ("kyc", "aml", "document", "verification"),
    "feature_flag": ("flag", "feature", "toggle", "enabled"),
    "limit": ("limit", "quota", "cap", "maximum", "minimum"),
}
PARTNER_PATTERNS = [
    re.compile(r"""(?ix)\bpartner\b\s*(?:==|=|:)\s*["'`]([a-z0-9_-]{2,})["'`]"""),
    re.compile(r"""(?ix)["'`]partner["'`]\s*:\s*["'`]([a-z0-9_-]{2,})["'`]"""),
    re.compile(r"""(?ix)\bpartner\.equals\(\s*["'`]([a-z0-9_-]{2,})["'`]\s*\)"""),
]
INBOUND_PATTERNS = [
    re.compile(r"""(?ix)(?:app|router|bp)\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?ix)@(?:app|router|bp)\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?ix)(?:app|router)\.route\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*methods\s*=\s*\[([^\]]+)\]"""),
]
OUTBOUND_PATTERNS = [
    re.compile(r"""(?ix)\b(fetch|axios\.(?:get|post|put|patch|delete)|requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?ix)\b(url|endpoint|base_url)\s*[:=]\s*["'`](https?://[^"'`]+|/[^"'`]+)["'`]"""),
]
DATABASE_PATTERNS = [
    ("read", re.compile(r"""(?ix)\bselect\b.+?\bfrom\b\s+([a-z_][a-z0-9_\.]*)""")),
    ("read", re.compile(r"""(?ix)\bjoin\b\s+([a-z_][a-z0-9_\.]*)""")),
    ("write", re.compile(r"""(?ix)\binsert\b\s+into\b\s+([a-z_][a-z0-9_\.]*)""")),
    ("write", re.compile(r"""(?ix)\bupdate\b\s+([a-z_][a-z0-9_\.]*)""")),
    ("write", re.compile(r"""(?ix)\bdelete\b\s+from\b\s+([a-z_][a-z0-9_\.]*)""")),
    ("read", re.compile(r"""(?ix)\bfrom_\s*\(\s*["'`]([a-z_][a-z0-9_]*)["'`]""")),
    ("write", re.compile(r"""(?ix)\binto\s*\(\s*["'`]([a-z_][a-z0-9_]*)["'`]""")),
    ("read", re.compile(r"""(?ix)\btable\s*\(\s*["'`]([a-z_][a-z0-9_]*)["'`]""")),
]
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

# --- Django Specific Patterns ---
DJANGO_URL_PATTERNS = [
    re.compile(r"""path\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)"""),
    re.compile(r"""re_path\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)"""),
    re.compile(r"""@action\s*\(\s*.*?methods\s*=\s*\[([^\]]+)\]"""),
]

DJANGO_ORM_PATTERNS = [
    ("read", re.compile(r"""\b([A-Z][a-zA-Z0-9_]+)\.objects\.(filter|get|all|exclude|select_related|prefetch_related)""")),
    ("write", re.compile(r"""\b([A-Z][a-zA-Z0-9_]+)\.objects\.(create|update|update_or_create|get_or_create|bulk_create)""")),
    ("write", re.compile(r"""\.save\(\)""")),
    ("write", re.compile(r"""\.delete\(\)""")),
]

DJANGO_CHECK_PATTERNS = [
    re.compile(r"""permission_classes\s*=\s*\[([^\]]+)\]"""),
    re.compile(r"""\bis_authenticated\b"""),
    re.compile(r"""\bhas_perm\b"""),
    re.compile(r"""\bis_valid\(\s*raise_exception\s*=\s*True\s*\)"""),
    re.compile(r"""\bclean\(\)"""),
]


@dataclass
class FlowPoint:
    file: str
    line: int
    summary: str
    partners: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)


@dataclass
class ApiPoint:
    file: str
    line: int
    label: str
    context: str
    partners: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    direction: str = "inbound"
    payload: list[str] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    success_paths: list[str] = field(default_factory=list)
    app: str = "root"
    view_name: str | None = None
    action: str | None = None
    permission_classes: list[str] = field(default_factory=list)
    auth_classes: list[str] = field(default_factory=list)
    db_ops: list[str] = field(default_factory=list)
    outbound_calls: list[str] = field(default_factory=list)
    serializer_class: str | None = None
    auth_decorator: str | None = None  # e.g. @authorize('submit_bomtype') → 'submit_bomtype'


@dataclass
class DatabasePoint:
    file: str
    line: int
    table: str
    operation: str
    label: str
    context: str
    partners: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)


@dataclass
class ModelField:
    name: str
    type: str
    related_to: str | None = None

@dataclass
class ModelSchema:
    name: str
    file: str
    fields: list[ModelField] = field(default_factory=list)

@dataclass
class ConfigPoint:
    key: str
    value: str
    file: str
    line: int

@dataclass
class SerializerSchema:
    name: str
    file: str
    fields: list[str] = field(default_factory=list)
    model: str | None = None

@dataclass
class FunctionFlow:
    name: str
    file: str
    line: int
    end_line: int
    summary: str
    is_generic: bool = False
    class_name: str | None = None
    serializer_class: str | None = None
    routes: list[str] = field(default_factory=list)
    partners: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    decision_points: list[dict] = field(default_factory=list)
    outbound_apis: list[dict] = field(default_factory=list)
    database_tables: list[dict] = field(default_factory=list)
    returns: list[dict] = field(default_factory=list)
    internal_calls: list[dict] = field(default_factory=list) # [{class, method}]
    ordered_steps: list[dict] = field(default_factory=list)
    payload_fields: list[str] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    permission_classes: list[str] = field(default_factory=list)
    auth_classes: list[str] = field(default_factory=list)
    auth_decorator: str | None = None  # e.g. @authorize('submit_bomtype') → 'submit_bomtype'


@dataclass
class FileReport:
    path: str
    summary: str
    partners: list[str]
    checks: list[str]
    inbound_apis: list[ApiPoint]
    outbound_apis: list[ApiPoint]
    database_tables: list[DatabasePoint]
    flow_points: list[FlowPoint]
    functions: list[FunctionFlow]
    models: list[ModelSchema] = field(default_factory=list)
    configs: list[ConfigPoint] = field(default_factory=list)
    serializers: list[SerializerSchema] = field(default_factory=list)


@dataclass
class Diagnostic:
    type: str  # 'Security', 'Performance', 'Logic'
    severity: str # 'Critical', 'Warning', 'Info'
    message: str
    file: str
    line: int

@dataclass
class AnalysisReport:
    overview: dict[str, Any]
    partners: dict[str, dict]
    apis: dict[str, list[dict]]
    databases: list[dict]
    files: list[dict]
    schema: list[dict] = field(default_factory=list)
    configs: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return make_json_safe(asdict(self))


def analyze_paths(paths: Iterable[Path]) -> AnalysisReport:
    file_reports: list[FileReport] = []
    partner_map: dict[str, dict] = {}
    inbound_all: list[dict] = []
    outbound_all: list[dict] = []
    database_all: list[dict] = []
    total_flow_points = 0
    total_functions = 0

    # Phase 1: Deep Scan all files
    for path in paths:
        for file_path in iter_supported_files(path):
            report = analyze_file(file_path)
            if report:
                file_reports.append(report)

    # Phase 2: Build global lookups
    view_data_map = {}
    serializer_map: dict[str, list[str]] = {}

    # Build a model → field names map so __all__ serializers can fall back to it
    model_fields_map: dict[str, list[str]] = {}
    for report in file_reports:
        for m in report.models:
            model_fields_map[m.name] = [f.name for f in m.fields]

    for report in file_reports:
        for s in report.serializers:
            fields = s.fields
            if not fields and s.model and s.model in model_fields_map:
                fields = model_fields_map[s.model]
            serializer_map[s.name] = fields
            
    for report in file_reports:
        for func in report.functions:
            # Link serializer fields
            if func.serializer_class and func.serializer_class in serializer_map:
                func.payload_fields = list(set(func.payload_fields + serializer_map[func.serializer_class]))
                
            key = f"{func.class_name}:{func.name}" if func.class_name else func.name
            view_data_map[key] = func

    # Recursive Trace for Handlers
    for _ in range(3): # Max depth 3
        for report in file_reports:
            for func in report.functions:
                for call in func.internal_calls:
                    if not isinstance(call, dict):
                        continue
                    cls = call.get("class", "")
                    method = call.get("method", "")
                    # Resolve Django classmethod pattern: cls.X -> ClassName.X
                    if cls == "cls" and func.class_name:
                        cls = func.class_name
                    target_key = f"{cls}:{method}" if cls else method
                    target = view_data_map.get(target_key) or view_data_map.get(method)
                    if target:
                        func.payload_fields = sorted(list(set(func.payload_fields + target.payload_fields)))
                        func.exceptions = sorted(list(set(func.exceptions + target.exceptions)))
                        # Bubble auth_decorator up — handler knows the permission key, ViewSet delegates to it
                        if not func.auth_decorator and target.auth_decorator:
                            func.auth_decorator = target.auth_decorator
                        # Bubble database_tables up so ViewSet methods inherit ORM calls from helpers
                        existing_db = {(d["operation"], d["table"]) for d in func.database_tables}
                        for d in target.database_tables:
                            if (d["operation"], d["table"]) not in existing_db:
                                func.database_tables.append(d)
                                existing_db.add((d["operation"], d["table"]))
                        # Bubble HTTP 2xx/201 returns up through the call chain
                        target_http = [r for r in target.returns if re.search(r"HTTP [12]\d{2}", r["summary"])]
                        if target_http:
                            existing = {r["summary"] for r in func.returns}
                            for r in target_http:
                                if r["summary"] not in existing:
                                    func.returns.append(r)
                                    existing.add(r["summary"])

    # Phase 3: Enrich and Aggregate
    for report in file_reports:
        enriched_apis = []
        for api in report.inbound_apis:
            lookup_key = f"{api.view_name}:{api.action}" if api.view_name and api.action else api.action
            match = view_data_map.get(lookup_key) or view_data_map.get(api.action) or view_data_map.get(api.view_name)
            if match:
                api.payload = sorted(list(set(api.payload + match.payload_fields)))
                api.exceptions = sorted(list(set(api.exceptions + match.exceptions)))
                # Auth / permissions
                if not api.permission_classes:
                    api.permission_classes = match.permission_classes
                if not api.auth_classes:
                    api.auth_classes = match.auth_classes
                # Serializer
                if not api.serializer_class:
                    api.serializer_class = match.serializer_class
                # DB ops — deduplicated labels
                db_labels = [f"{d['operation']} {d['table']}" for d in match.database_tables]
                api.db_ops = sorted(list(set(db_labels)))[:8]
                # Outbound calls
                api.outbound_calls = sorted(list({d.get("label", "") for d in match.outbound_apis if d.get("label")}))[:6]
                # Custom authorize decorator
                if not api.auth_decorator and match.auth_decorator:
                    api.auth_decorator = match.auth_decorator
                if not api.success_paths:
                    # Prefer explicit HTTP 2xx return messages; fall back to callee if this
                    # function only delegates (e.g. return cls.create_or_update(...))
                    success = [r["summary"] for r in match.returns if re.search(r"HTTP [12]\d{2}", r["summary"])]
                    if not success:
                        for call in match.internal_calls[:4]:
                            cls_name = call.get("class", "")
                            if cls_name == "cls" and match.class_name:
                                cls_name = match.class_name
                            callee = view_data_map.get(f"{cls_name}:{call.get('method', '')}")
                            if callee:
                                success = [r["summary"] for r in callee.returns if re.search(r"HTTP [12]\d{2}", r["summary"])]
                                if success:
                                    break
                    api.success_paths = success[:3] or [r["summary"] for r in match.returns[:2]] or [f"Returns from {match.name}"]
            enriched_apis.append(api)
        report.inbound_apis = enriched_apis

        # Determine App name for aggregation
        app_name = "root"
        for p in paths:
            if str(report.path).startswith(str(p)):
                rel = Path(report.path).relative_to(p)
                app_name = rel.parts[0] if len(rel.parts) > 1 else "root"
                break

        total_flow_points += len(report.flow_points)
        total_functions += len(report.functions)
        
        for item in report.inbound_apis:
            item_dict = asdict(item)
            item_dict["app"] = app_name
            inbound_all.append(item_dict)
            
        for item in report.outbound_apis:
            item_dict = asdict(item)
            item_dict["app"] = app_name
            outbound_all.append(item_dict)
            
        for item in report.database_tables:
            item_dict = asdict(item)
            item_dict["app"] = app_name
            database_all.append(item_dict)
            
        # Group partners
        for partner in report.partners:
            bucket = partner_map.setdefault(
                f"{app_name}:{partner}",
                {
                    "files": set(),
                    "checks": set(),
                    "flow_points": [],
                    "inbound_apis": [],
                    "outbound_apis": [],
                    "database_tables": [],
                    "functions": [],
                    "narrative": [],
                },
            )
            bucket["files"].add(report.path)
            bucket["checks"].update(report.checks)
            bucket["flow_points"].extend(
                asdict(point)
                for point in report.flow_points
                if partner in point.partners or not point.partners
            )
            bucket["inbound_apis"].extend(
                asdict(item)
                for item in report.inbound_apis
                if partner in item.partners or not item.partners
            )
            bucket["outbound_apis"].extend(
                asdict(item)
                for item in report.outbound_apis
                if partner in item.partners or not item.partners
            )
            bucket["database_tables"].extend(
                asdict(item)
                for item in report.database_tables
                if partner in item.partners or not item.partners
            )
            bucket["functions"].extend(
                asdict(item)
                for item in report.functions
                if partner in item.partners or not item.partners
            )

    normalized_partner_map = {}
    for partner, value in sorted(partner_map.items()):
        checks = sorted(value["checks"])
        flow_points = dedupe_points(value["flow_points"])[:16]
        inbound = dedupe_points(value["inbound_apis"])[:12]
        outbound = dedupe_points(value["outbound_apis"])[:12]
        database_tables = dedupe_database_points(value["database_tables"])[:12]
        functions = dedupe_functions(value["functions"])[:8]
        normalized_partner_map[partner] = {
            "files": sorted(value["files"]),
            "checks": checks,
            "flow_points": flow_points,
            "inbound_apis": inbound,
            "outbound_apis": outbound,
            "database_tables": database_tables,
            "functions": functions,
            "narrative": build_partner_narrative(partner, checks, inbound, outbound, database_tables, functions, flow_points),
        }

    check_types = sorted({check for report in file_reports for check in report.checks})
    all_models = [asdict(m) for r in file_reports for m in r.models]
    all_configs = [asdict(c) for r in file_reports for c in r.configs]
    diagnostics = run_diagnostics(file_reports)
    
    return AnalysisReport(
        overview={
            "files_scanned": len(file_reports),
            "partners_found": len(normalized_partner_map),
            "flow_points": total_flow_points,
            "checks_found": len(check_types),
            "check_types": check_types,
            "inbound_apis": len(dedupe_points(inbound_all)),
            "outbound_apis": len(dedupe_points(outbound_all)),
            "database_tables": len(dedupe_database_points(database_all)),
            "functions_analyzed": total_functions,
            "models_found": len(all_models),
            "configs_found": len(all_configs),
            "bugs_found": len([d for d in diagnostics if d["severity"] == "Critical"]),
        },
        partners=normalized_partner_map,
        apis={
            "inbound": dedupe_points(inbound_all),
            "outbound": dedupe_points(outbound_all),
        },
        databases=dedupe_database_points(database_all),
        schema=all_models,
        configs=all_configs,
        diagnostics=diagnostics,
        files=[
            {
                "path": report.path,
                "summary": report.summary,
                "partners": report.partners,
                "checks": report.checks,
                "inbound_apis": [asdict(item) for item in report.inbound_apis],
                "outbound_apis": [asdict(item) for item in report.outbound_apis],
                "database_tables": [asdict(item) for item in report.database_tables],
                "flow_points": [asdict(point) for point in report.flow_points],
                "functions": [asdict(item) for item in report.functions],
            }
            for report in sorted(file_reports, key=lambda item: item.path)
        ],
    )


EXCLUDE_DIRS = frozenset({
    ".git", "venv", "node_modules", "__pycache__",
    "static", "media", ".pytest_cache", ".tox", ".mypy_cache",
})

# Files that may contain secrets — never scanned
CONFIDENTIAL_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    "secrets.py", "secrets.json", "secrets.yaml", "secrets.yml",
    ".secrets", "credentials.json", "credentials.py",
    "local_settings.py",  # Django local overrides often have real passwords
})


def iter_supported_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        if path.suffix.lower() in SUPPORTED_EXTENSIONS and path.name not in CONFIDENTIAL_NAMES:
            yield path
        return

    for file_path in sorted(path.rglob("*")):
        if any(part in EXCLUDE_DIRS for part in file_path.parts):
            continue
        if not file_path.is_file():
            continue
        if file_path.name in CONFIDENTIAL_NAMES:
            continue
        if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        yield file_path


def analyze_file(path: Path) -> FileReport | None:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    lines = content.splitlines()
    functions = analyze_python_functions(path, content, lines) if path.suffix.lower() == ".py" else []
    
    inbound_apis = extract_api_points(lines, path, direction="inbound", fallback_partners=extract_partners(content))
    # Add Django Path detections
    inbound_apis.extend(extract_django_urls(lines, path, extract_partners(content)))
    
    outbound_apis = extract_api_points(lines, path, direction="outbound", fallback_partners=extract_partners(content))
    
    database_tables = extract_database_points(lines, path, fallback_partners=extract_partners(content))
    # Add Django ORM detections
    database_tables.extend(extract_django_orm(lines, path, extract_partners(content)))
    
    flow_points = build_flow_points(path, lines, extract_partners(content))
    
    models = []
    if "models.py" in str(path) or "models/" in str(path):
        models = analyze_django_models(path, content)
        
    configs = extract_configs(lines, path)

    partners = sorted(
        {
            *extract_partners(content),
            *(partner for function in functions for partner in function.partners),
        }
    )
    checks = sorted(
        {
            *extract_checks(content),
            *(check for function in functions for check in function.checks),
        }
    )

    if functions:
        inbound_apis = merge_api_points(inbound_apis, functions, "routes")
        outbound_apis = merge_api_points(outbound_apis, functions, "outbound_apis")
        database_tables = merge_database_points(database_tables, functions)
        flow_points = merge_flow_points(flow_points, functions)

    serializers = analyze_serializers(path, content)
        
    return FileReport(
        path=str(path),
        summary=build_file_summary(partners, checks, inbound_apis, outbound_apis, database_tables, flow_points, functions),
        partners=partners,
        checks=checks,
        inbound_apis=inbound_apis[:20],
        outbound_apis=outbound_apis[:20],
        database_tables=database_tables[:20],
        flow_points=flow_points[:50],
        functions=functions[:20],
        models=models,
        configs=configs,
        serializers=serializers,
    )


def analyze_python_functions(path: Path, content: str, lines: list[str]) -> list[FunctionFlow]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except SyntaxError:
        return []

    functions: list[FunctionFlow] = []
    method_ids: set[int] = set()

    def _extract_auth_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        """Return the first @authorize('key') / @login_required / @permission_required('key') value found."""
        for dec in node.decorator_list:
            # @authorize('submit_bomtype') or @require_permission('key')
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                fname = dec.func.id
                if fname in ("authorize", "require_permission", "permission_required", "auth_required"):
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        return dec.args[0].value
            # @authorize on an attribute: e.g. @Auth.authorize('key')
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in ("authorize", "require_permission", "auth_required"):
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        return dec.args[0].value
            # bare @login_required / @staff_member_required (no key, just flag)
            if isinstance(dec, ast.Name) and dec.id in ("login_required", "staff_member_required"):
                return dec.id
        return None

    CBV_BASES = {
        "APIView", "GenericAPIView", "View", "ModelViewSet", "ViewSet",
        "ReadOnlyModelViewSet", "ListAPIView", "CreateAPIView", "RetrieveAPIView",
        "UpdateAPIView", "DestroyAPIView", "ListCreateAPIView",
        "RetrieveUpdateAPIView", "RetrieveDestroyAPIView", "RetrieveUpdateDestroyAPIView",
    }
    STANDARD_ACTIONS = ("list", "create", "retrieve", "update", "partial_update", "destroy")

    _DATA_VARS = frozenset(("request.data", "request.POST", "validated_data", "payload", "data"))

    def _scan_body(
        func_node: ast.FunctionDef | ast.AsyncFunctionDef, init_serializer: str | None
    ) -> tuple[list[str], list[str], str | None, list[dict]]:
        payload_fields: list[str] = []
        exceptions: list[str] = []
        internal_calls: list[dict] = []
        serializer = init_serializer
        for sub in ast.walk(func_node):
            code = ast.unparse(sub)

            # --- Payload detection ---

            # 1. validations = {"field": {...}, ...}  — explicit validation dict pattern
            if isinstance(sub, ast.Assign) and len(sub.targets) == 1:
                t = sub.targets[0]
                if isinstance(t, ast.Name) and t.id == "validations" and isinstance(sub.value, ast.Dict):
                    for k in sub.value.keys:
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            payload_fields.append(k.value)

            # 2. payload["key"] / request.data["key"] — subscript access
            if isinstance(sub, ast.Subscript):
                obj_code = ast.unparse(sub.value)
                if any(v in obj_code for v in _DATA_VARS):
                    key_match = re.search(r"['\"]([^'\"]+)['\"]", code)
                    if key_match:
                        payload_fields.append(key_match.group(1))

            # 3. payload.get("key") / request.data.get("key") — .get() call
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "get"
                and sub.args
            ):
                obj_code = ast.unparse(sub.func.value)
                if any(v in obj_code for v in _DATA_VARS):
                    arg = sub.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        payload_fields.append(arg.value)

            # --- Exception detection ---

            # 1. explicit raise statements
            if isinstance(sub, ast.Raise) and sub.exc is not None:
                if isinstance(sub.exc, ast.Call):
                    exceptions.append(ast.unparse(sub.exc.func))
                elif isinstance(sub.exc, ast.Name):
                    exceptions.append(sub.exc.id)

            # 2. DRF serializer.is_valid(raise_exception=True)
            if isinstance(sub, ast.Call) and ".is_valid(" in code and "raise_exception=True" in code:
                exceptions.append("ValidationError")

            # 3. except SomeError / except (A, B) — caught exceptions
            if isinstance(sub, ast.ExceptHandler) and sub.type is not None:
                if isinstance(sub.type, ast.Name):
                    exceptions.append(sub.type.id)
                elif isinstance(sub.type, ast.Tuple):
                    for elt in sub.type.elts:
                        if isinstance(elt, ast.Name):
                            exceptions.append(elt.id)

            # 4. return HTTP_4xx / HTTP_5xx — Django/DRF handler error returns
            if isinstance(sub, ast.Return) and sub.value is not None:
                val = sub.value
                # Extract inline message from tuple: return HTTP_STATUS, "message", ...
                inline_msg = ""
                if isinstance(val, ast.Tuple) and len(val.elts) >= 2:
                    msg_node = val.elts[1]
                    if isinstance(msg_node, ast.Constant) and isinstance(msg_node.value, str):
                        inline_msg = msg_node.value

                ret_code = ast.unparse(val)
                for m in re.finditer(r"\bHTTP_([45]\d{2})(?:_([A-Z_]+))?", ret_code):
                    num = m.group(1)
                    label_part = (m.group(2) or "").replace("_", " ").title()
                    label = f"HTTP {num}{(' ' + label_part) if label_part else ''}"
                    if inline_msg:
                        label += f' — "{inline_msg}"'
                    exceptions.append(label)
                # Response(status=4xx) / Response(status=HTTP_4xx)
                for m in re.finditer(r"status\s*=\s*(?:HTTP_)?([45]\d{2})", ret_code):
                    exceptions.append(f"HTTP {m.group(1)}")

            # --- Serializer / internal call detection ---
            if "Serializer(" in code:
                s_match = re.search(r"([A-Z][a-zA-Z0-9_]+Serializer)\s*\(", code)
                if s_match:
                    serializer = s_match.group(1)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if isinstance(sub.func.value, ast.Name):
                    c = {"class": sub.func.value.id, "method": sub.func.attr}
                    if c not in internal_calls:
                        internal_calls.append(c)
        return payload_fields, exceptions, serializer, internal_calls

    # --- Pass 1: Class-based views ---
    for class_node in ast.walk(tree):
        if not isinstance(class_node, ast.ClassDef):
            continue

        base_names: set[str] = set()
        for base in class_node.bases:
            if isinstance(base, ast.Name):
                base_names.add(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.add(base.attr)
        is_view = bool(base_names & CBV_BASES)

        class_serializer: str | None = None
        class_payload: list[str] = []
        class_permissions: list[str] = []
        class_auth: list[str] = []
        for stmt in class_node.body:
            if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1):
                continue
            target = stmt.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if target.id == "serializer_class":
                if isinstance(stmt.value, ast.Name):
                    class_serializer = stmt.value.id
                elif isinstance(stmt.value, ast.Attribute):
                    class_serializer = stmt.value.attr
            elif target.id in ("filterset_fields", "search_fields", "ordering_fields", "filter_fields"):
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    for elt in stmt.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            class_payload.append(elt.value)
            elif target.id == "permission_classes":
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    for elt in stmt.value.elts:
                        name = elt.id if isinstance(elt, ast.Name) else (elt.attr if isinstance(elt, ast.Attribute) else None)
                        if name:
                            class_permissions.append(name)
            elif target.id == "authentication_classes":
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    for elt in stmt.value.elts:
                        name = elt.id if isinstance(elt, ast.Name) else (elt.attr if isinstance(elt, ast.Attribute) else None)
                        if name:
                            class_auth.append(name)

        class_source = ast.get_source_segment(content, class_node) or ""
        class_partners = sorted(extract_partners(class_source))

        if is_view:
            defined_methods = {
                item.name for item in class_node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for action in STANDARD_ACTIONS:
                if action not in defined_methods:
                    functions.append(FunctionFlow(
                        name=action,
                        file=str(path),
                        line=class_node.lineno,
                        end_line=class_node.lineno + 1,
                        summary=f"Inherited {action} from {class_node.name}",
                        is_generic=True,
                        class_name=class_node.name,
                        serializer_class=class_serializer,
                        payload_fields=sorted(class_payload) if action in ("list", "retrieve") else [],
                        exceptions=[],
                        routes=[f"{action.upper()} (Action)"],
                    ))

        for method in class_node.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            method_ids.add(id(method))

            start = method.lineno
            end = getattr(method, "end_lineno", start)
            source = ast.get_source_segment(content, method) or "\n".join(lines[start - 1:end])
            local_lines = lines[start - 1:end]

            partners = sorted(extract_partners(source)) or class_partners
            checks = sorted(extract_checks(source))
            routes = extract_routes_from_decorators(method)
            if not routes and is_view:
                routes = [f"{method.name.upper()} (Action)"]

            # Method-level permission/auth decorators override class-level
            method_permissions = list(class_permissions)
            method_auth = list(class_auth)
            for dec in method.decorator_list:
                dec_code = ast.unparse(dec)
                if "permission_classes" in dec_code and isinstance(dec, ast.Call) and dec.args:
                    arg = dec.args[0]
                    if isinstance(arg, (ast.List, ast.Tuple)):
                        method_permissions = []
                        for elt in arg.elts:
                            name = elt.id if isinstance(elt, ast.Name) else (elt.attr if isinstance(elt, ast.Attribute) else None)
                            if name:
                                method_permissions.append(name)
                if "authentication_classes" in dec_code and isinstance(dec, ast.Call) and dec.args:
                    arg = dec.args[0]
                    if isinstance(arg, (ast.List, ast.Tuple)):
                        method_auth = []
                        for elt in arg.elts:
                            name = elt.id if isinstance(elt, ast.Name) else (elt.attr if isinstance(elt, ast.Attribute) else None)
                            if name:
                                method_auth.append(name)

            outbound = [asdict(a) for a in extract_api_points(local_lines, path, "outbound", partners, line_offset=start - 1)]
            database = [asdict(d) for d in extract_database_points(local_lines, path, partners, line_offset=start - 1)]
            database += [asdict(d) for d in extract_django_orm(local_lines, path, set(partners), line_offset=start - 1)]
            decision_points = collect_python_decisions(method, content, path, partners, checks)
            returns = collect_python_returns(method, content)

            init_payload = list(class_payload) if method.name in ("list", "retrieve") else []
            payload_fields, exceptions, method_serializer, internal_calls = _scan_body(method, class_serializer)
            payload_fields = init_payload + payload_fields

            ordered_steps = build_ordered_steps(routes, decision_points, database, outbound, returns, start)
            summary = build_function_summary(method.name, routes, checks, database, outbound, returns, decision_points, is_view)

            functions.append(FunctionFlow(
                name=method.name,
                file=str(path),
                line=start,
                end_line=end,
                summary=summary,
                routes=routes,
                partners=partners,
                checks=checks,
                decision_points=decision_points[:10],
                outbound_apis=outbound[:10],
                database_tables=database[:10],
                returns=returns[:10],
                internal_calls=internal_calls[:10],
                ordered_steps=ordered_steps[:24],
                is_generic=is_view,
                class_name=class_node.name,
                serializer_class=method_serializer or class_serializer,
                payload_fields=sorted(list(set(payload_fields))),
                exceptions=sorted(list(set(exceptions))),
                permission_classes=method_permissions,
                auth_classes=method_auth,
                auth_decorator=_extract_auth_decorator(method),
            ))

    # --- Pass 2: standalone functions (FBVs) ---
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if id(node) in method_ids:
            continue

        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        source = ast.get_source_segment(content, node) or "\n".join(lines[start - 1:end])
        local_lines = lines[start - 1:end]

        partners = sorted(extract_partners(source))
        checks = sorted(extract_checks(source))
        routes = extract_routes_from_decorators(node)

        # FBV decorator-level permission/auth detection
        fbv_permissions: list[str] = []
        fbv_auth: list[str] = []
        for dec in node.decorator_list:
            dec_code = ast.unparse(dec)
            if "permission_classes" in dec_code and isinstance(dec, ast.Call) and dec.args:
                arg = dec.args[0]
                if isinstance(arg, (ast.List, ast.Tuple)):
                    for elt in arg.elts:
                        name = elt.id if isinstance(elt, ast.Name) else (elt.attr if isinstance(elt, ast.Attribute) else None)
                        if name:
                            fbv_permissions.append(name)
            if "authentication_classes" in dec_code and isinstance(dec, ast.Call) and dec.args:
                arg = dec.args[0]
                if isinstance(arg, (ast.List, ast.Tuple)):
                    for elt in arg.elts:
                        name = elt.id if isinstance(elt, ast.Name) else (elt.attr if isinstance(elt, ast.Attribute) else None)
                        if name:
                            fbv_auth.append(name)
            # @login_required → IsAuthenticated equivalent
            if dec_code.strip() in ("login_required", "staff_member_required"):
                fbv_permissions.append(dec_code.strip())

        outbound = [asdict(a) for a in extract_api_points(local_lines, path, "outbound", partners, line_offset=start - 1)]
        database = [asdict(d) for d in extract_database_points(local_lines, path, partners, line_offset=start - 1)]
        database += [asdict(d) for d in extract_django_orm(local_lines, path, set(partners), line_offset=start - 1)]
        decision_points = collect_python_decisions(node, content, path, partners, checks)
        returns = collect_python_returns(node, content)

        payload_fields, exceptions, fbv_serializer, internal_calls = _scan_body(node, None)

        ordered_steps = build_ordered_steps(routes, decision_points, database, outbound, returns, start)
        summary = build_function_summary(node.name, routes, checks, database, outbound, returns, decision_points, False)

        functions.append(FunctionFlow(
            name=node.name,
            file=str(path),
            line=start,
            end_line=end,
            summary=summary,
            routes=routes,
            partners=partners,
            checks=checks,
            decision_points=decision_points[:10],
            outbound_apis=outbound[:10],
            database_tables=database[:10],
            returns=returns[:10],
            internal_calls=internal_calls[:10],
            ordered_steps=ordered_steps[:24],
            is_generic=False,
            class_name=None,
            serializer_class=fbv_serializer,
            payload_fields=sorted(list(set(payload_fields))),
            exceptions=sorted(list(set(exceptions))),
            permission_classes=fbv_permissions,
            auth_classes=fbv_auth,
            auth_decorator=_extract_auth_decorator(node),
        ))

    return sorted(functions, key=lambda item: item.line)


def extract_routes_from_decorators(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    routes: list[str] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        func = decorator.func
        if isinstance(func, ast.Attribute) and func.attr.lower() in {"get", "post", "put", "patch", "delete"}:
            if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                routes.append(f"{func.attr.upper()} {decorator.args[0].value}")
        elif isinstance(func, ast.Attribute) and func.attr.lower() == "route":
            route = ""
            methods = "ROUTE"
            if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                route = decorator.args[0].value
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    values = []
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            values.append(elt.value.upper())
                    methods = "/".join(values) if values else methods
            if route:
                routes.append(f"{methods} {route}")
    return routes


def collect_python_decisions(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    content: str,
    path: Path,
    partners: list[str],
    fallback_checks: list[str],
) -> list[dict]:
    decisions: list[dict] = []
    for child in ast.walk(node):
        if isinstance(child, ast.If):
            condition = ast.get_source_segment(content, child.test) or "conditional branch"
            checks = sorted(extract_checks(condition)) or fallback_checks
            decisions.append(
                {
                    "file": str(path),
                    "line": child.lineno,
                    "summary": f"IF {collapse_whitespace(condition)}",
                    "partners": partners,
                    "checks": checks,
                }
            )
    return sorted(decisions, key=lambda item: item["line"])


def collect_python_returns(node: ast.FunctionDef | ast.AsyncFunctionDef, content: str) -> list[dict]:
    returns: list[dict] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Return) and child.value is not None:
            val = child.value
            # Structured tuple return: (HTTP_STATUS, "message", ...) or (status, "message")
            if isinstance(val, ast.Tuple) and len(val.elts) >= 2:
                status_code = ast.unparse(val.elts[0])
                msg_node = val.elts[1]
                msg = msg_node.value if isinstance(msg_node, ast.Constant) and isinstance(msg_node.value, str) else ""
                http_m = re.search(r"\bHTTP_(\d{3})(?:_([A-Z_]+))?", status_code)
                if http_m:
                    num = http_m.group(1)
                    label = f"HTTP {num}"
                    if msg:
                        label += f' — "{msg}"'
                    returns.append({"line": child.lineno, "summary": label})
                    continue
            # Plain return value
            value = ast.get_source_segment(content, val) or ast.unparse(val)
            returns.append({"line": child.lineno, "summary": f"return {collapse_whitespace(value)}"})
    return sorted(returns, key=lambda item: item["line"])


def collect_python_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    calls: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = get_call_name(child.func)
            if name and name not in calls:
                calls.append(name)
    return calls


def get_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = get_call_name(node.value)
        return f"{root}.{node.attr}" if root else node.attr
    return ""


def build_ordered_steps(
    routes: list[str],
    decisions: list[dict],
    database: list[dict],
    outbound: list[dict],
    returns: list[dict],
    start_line: int,
) -> list[dict]:
    steps: list[dict] = []
    for route in routes:
        steps.append({"line": start_line, "type": "route", "label": route})
    for item in decisions:
        steps.append({"line": item["line"], "type": "decision", "label": item["summary"]})
    for item in database:
        steps.append({"line": item["line"], "type": "database", "label": item["label"]})
    for item in outbound:
        steps.append({"line": item["line"], "type": "external_api", "label": item["label"]})
    for item in returns:
        steps.append({"line": item["line"], "type": "return", "label": item["summary"]})
    return sorted(steps, key=lambda item: item["line"])




def build_flow_points(path: Path, lines: list[str], fallback_partners: set[str]) -> list[FlowPoint]:
    flow_points: list[FlowPoint] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or len(stripped) < 3:
            continue
        if not FLOW_PATTERN.search(stripped) and not partner_or_check_hint(stripped):
            continue
        local_context = collect_context(lines, index)
        point_partners = sorted(extract_partners(local_context)) or sorted(fallback_partners)
        point_checks = sorted(extract_checks(local_context))
        flow_points.append(
            FlowPoint(
                file=str(path),
                line=index,
                summary=collapse_whitespace(stripped)[:220],
                partners=point_partners,
                checks=point_checks,
            )
        )
    return flow_points


def extract_partners(content: str) -> set[str]:
    found: set[str] = set()
    for pattern in PARTNER_PATTERNS:
        for match in pattern.finditer(content):
            partner = match.group(1)
            if partner:
                found.add(partner.lower())
    return found


def extract_checks(content: str) -> set[str]:
    lowered = content.lower()
    checks = set()
    for label, hints in CHECK_HINTS.items():
        if any(hint in lowered for hint in hints):
            checks.add(label)
            
    # Add Django Specific checks
    for pattern in DJANGO_CHECK_PATTERNS:
        if pattern.search(content):
            if "permission" in pattern.pattern:
                checks.add("permission")
            if "auth" in pattern.pattern:
                checks.add("authentication")
            if "valid" in pattern.pattern:
                checks.add("validation")
    return checks


def _parse_view_class(raw_view: str | None) -> str | None:
    if not raw_view:
        return None
    clean = re.sub(r"\.as_view\s*[\(\{].*$", "", raw_view.strip())
    clean = re.sub(r"\s*\(.*$", "", clean)
    parts = [p for p in clean.split(".") if p]
    return parts[-1] if parts else None


def extract_django_urls(lines: list[str], path: Path, partners: set[str]) -> list[ApiPoint]:
    points = []
    # Patterns for all Django URL types
    PATH_PATTERNS = [
        ("DJANGO", re.compile(r"""path\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)""")),
        ("REGEX", re.compile(r"""re_path\s*\(\s*r?["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)""")),
        ("LEGACY", re.compile(r"""url\s*\(\s*r?["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)""")),
        ("INCLUDE", re.compile(r"""include\s*\(\s*["'`]([^"'`]+)["'`]""")),
        ("ROUTER", re.compile(r"""router\.register\s*\(\s*r?["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)""")),
        ("ROUTER", re.compile(r"""route\.register\s*\(\s*r?["'`]([^"'`]+)["'`]\s*,\s*([^,)\s]+)""")),
    ]
    
    # Standard DRF ViewSet methods
    VIEWSET_METHODS = ["list", "create", "retrieve", "update", "partial_update", "destroy"]
    
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        for label_type, pattern in PATH_PATTERNS:
            match = pattern.search(stripped)
            if not match:
                continue
                
            route = match.group(1)
            raw_view = match.group(2) if len(match.groups()) > 1 else None
            view_class = _parse_view_class(raw_view)
            
            # Special handling for ViewSet.as_view({...})
            if "as_view" in stripped:
                methods_match = re.search(r"as_view\s*\(\s*\{([^}]+)\}", stripped)
                if methods_match:
                    # Extract individual methods like "get": "list"
                    method_pairs = re.findall(r"['\"]([a-z]+)['\"]\s*:\s*['\"]([a-z_]+)['\"]", methods_match.group(1))
                    for http_method, action in method_pairs:
                        points.append(ApiPoint(
                            file=str(path),
                            line=index,
                            label=f"{http_method.upper()} {route} ({action})",
                            context=stripped,
                            partners=sorted(list(partners)),
                            checks=[],
                            direction="inbound",
                            view_name=view_class,
                            action=action
                        ))
                    continue 

            # Special handling for Routers (Expand to 6 APIs)
            if label_type == "ROUTER":
                for action in VIEWSET_METHODS:
                    method = "GET" if action in ("list", "retrieve") else "POST" if action == "create" else "PUT/PATCH" if "update" in action else "DELETE"
                    points.append(ApiPoint(
                        file=str(path),
                        line=index,
                        label=f"{method} {route} ({action})",
                        context=f"Router expansion: {stripped}",
                        partners=sorted(list(partners)),
                        checks=[],
                        direction="inbound",
                        view_name=view_class,
                        action=action
                    ))
                continue

            # Standard path/url
            points.append(ApiPoint(
                file=str(path),
                line=index,
                label=f"{label_type} {route}",
                context=stripped,
                partners=sorted(list(partners)),
                checks=[],
                direction="inbound"
            ))
    return points


def extract_django_orm(lines: list[str], path: Path, partners: set[str], line_offset: int = 0) -> list[DatabasePoint]:
    points = []
    for index, line in enumerate(lines, start=1):
        for op, pattern in DJANGO_ORM_PATTERNS:
            match = pattern.search(line)
            if match:
                if len(match.groups()) > 0:
                    model_name = match.group(1)
                else:
                    # .save() / .delete() — extract the variable name from the line
                    var_match = re.search(r"(\w+)\.(save|delete)\s*\(", line)
                    model_name = var_match.group(1).capitalize() if var_match else "Unknown"
                points.append(DatabasePoint(
                    file=str(path),
                    line=index + line_offset,
                    table=model_name,
                    operation=op,
                    label=f"ORM {op.upper()} {model_name}",
                    context=line.strip(),
                    partners=sorted(list(partners)),
                    checks=[]
                ))
    return points


def extract_api_points(
    lines: list[str],
    path: Path,
    direction: str,
    fallback_partners: list[str],
    line_offset: int = 0,
) -> list[ApiPoint]:
    patterns = INBOUND_PATTERNS if direction == "inbound" else OUTBOUND_PATTERNS
    points: list[ApiPoint] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        local_context = collect_context(lines, index)
        for pattern in patterns:
            match = pattern.search(stripped)
            if not match:
                continue
            label = build_api_label(match, direction)
            if not label:
                continue
            partners = sorted(extract_partners(local_context)) or fallback_partners
            checks = sorted(extract_checks(local_context))
            points.append(
                ApiPoint(
                    file=str(path),
                    line=index + line_offset,
                    label=label,
                    context=collapse_whitespace(stripped)[:220],
                    partners=partners,
                    checks=checks,
                    direction=direction,
                )
            )
            break
    return points


def extract_database_points(
    lines: list[str],
    path: Path,
    fallback_partners: list[str],
    line_offset: int = 0,
) -> list[DatabasePoint]:
    points: list[DatabasePoint] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        local_context = collect_context(lines, index)
        for operation, pattern in DATABASE_PATTERNS:
            match = pattern.search(stripped)
            if not match:
                continue
            table = normalize_table_name(match.group(1))
            if not table:
                continue
            partners = sorted(extract_partners(local_context)) or fallback_partners
            checks = sorted(extract_checks(local_context))
            points.append(
                DatabasePoint(
                    file=str(path),
                    line=index + line_offset,
                    table=table,
                    operation=operation,
                    label=f"{operation.upper()} {table}",
                    context=collapse_whitespace(stripped)[:220],
                    partners=partners,
                    checks=checks,
                )
            )
            break
    return points


def build_api_label(match: re.Match[str], direction: str) -> str:
    groups = [group for group in match.groups() if group]
    if not groups:
        return ""
    if direction == "inbound":
        if len(groups) >= 2 and groups[0].upper() in HTTP_METHODS:
            return f"{groups[0].upper()} {groups[1]}"
        if len(groups) >= 2:
            methods = normalize_method_list(groups[1])
            return f"{methods} {groups[0]}"
        return groups[0]

    method = groups[0]
    route = groups[1] if len(groups) > 1 else ""
    method_prefix = method.upper() if method.upper() in HTTP_METHODS else method
    return f"{method_prefix} {route}".strip()


def normalize_method_list(raw: str) -> str:
    found = []
    for token in re.findall(r"[A-Za-z]+", raw):
        upper = token.upper()
        if upper in HTTP_METHODS:
            found.append(upper)
    return "/".join(found) if found else "ROUTE"


def normalize_table_name(value: str) -> str:
    cleaned = value.strip().strip(",;")
    if "." in cleaned:
        cleaned = cleaned.split(".")[-1]
    return cleaned.lower()


def collect_context(lines: list[str], index: int, radius: int = 2) -> str:
    start = max(0, index - radius - 1)
    end = min(len(lines), index + radius)
    return " ".join(lines[start:end])


def partner_or_check_hint(line: str) -> bool:
    lowered = line.lower()
    return (
        "partner" in lowered
        or any(hint in lowered for hints in CHECK_HINTS.values() for hint in hints)
        or "http" in lowered
        or "route(" in lowered
        or "fetch(" in lowered
        or "axios." in lowered
        or "requests." in lowered
        or "httpx." in lowered
        or any(keyword in lowered for keyword in ("select ", "insert ", "update ", "delete ", " from ", " join "))
    )


def collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def dedupe_points(items: list[dict]) -> list[dict]:
    seen = set()
    output = []
    for item in items:
        key = (item["file"], item["line"], item.get("label", item.get("summary", "")))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def dedupe_database_points(items: list[dict]) -> list[dict]:
    seen = set()
    output = []
    for item in items:
        key = (item["file"], item["line"], item["table"], item["operation"])
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def dedupe_functions(items: list[dict]) -> list[dict]:
    seen = set()
    output = []
    for item in items:
        key = (item["file"], item["name"], item["line"])
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def merge_api_points(points: list[ApiPoint], functions: list[FunctionFlow], source_key: str) -> list[ApiPoint]:
    merged = [*points]
    seen = {(item.file, item.label, item.direction) for item in merged}
    for function in functions:
        for item in getattr(function, source_key):
            if source_key == "routes":
                # Skip virtual action-only labels like "CREATE (Action)" — no real path
                if "/" not in item:
                    continue
                key = (function.file, item, "inbound")
                if key in seen:
                    continue
                seen.add(key)
                merged.append(
                    ApiPoint(
                        file=function.file,
                        line=function.line,
                        label=item,
                        context=f"{function.name} route",
                        partners=function.partners,
                        checks=function.checks,
                        direction="inbound",
                    )
                )
            else:
                key = (item["file"], item["label"], item["direction"])
                if key in seen:
                    continue
                seen.add(key)
                merged.append(ApiPoint(**item))
    merged_dicts = dedupe_points([asdict(item) for item in merged])
    return [ApiPoint(**item) for item in merged_dicts]


def merge_database_points(points: list[DatabasePoint], functions: list[FunctionFlow]) -> list[DatabasePoint]:
    merged = [*points]
    for function in functions:
        merged.extend(DatabasePoint(**item) for item in function.database_tables)
    merged_dicts = dedupe_database_points([asdict(item) for item in merged])
    return [DatabasePoint(**item) for item in merged_dicts]


def merge_flow_points(points: list[FlowPoint], functions: list[FunctionFlow]) -> list[FlowPoint]:
    merged = [*points]
    for function in functions:
        for item in function.decision_points:
            merged.append(
                FlowPoint(
                    file=item["file"],
                    line=item["line"],
                    summary=item["summary"],
                    partners=item["partners"],
                    checks=item["checks"],
                )
            )
    merged_dicts = dedupe_points([asdict(item) for item in merged])
    return [FlowPoint(**item) for item in merged_dicts]


def build_file_summary(
    partners: list[str],
    checks: list[str],
    inbound_apis: list[ApiPoint],
    outbound_apis: list[ApiPoint],
    database_tables: list[DatabasePoint],
    flow_points: list[FlowPoint],
    functions: list[FunctionFlow],
) -> str:
    fragments = []
    if functions:
        fragments.append(f"{len(functions)} function flows")
    if partners:
        fragments.append(f"{len(partners)} partner paths")
    if checks:
        fragments.append(f"{len(checks)} check types")
    if inbound_apis or outbound_apis:
        fragments.append(f"{len(inbound_apis) + len(outbound_apis)} API touchpoints")
    if database_tables:
        fragments.append(f"{len(database_tables)} table touches")
    if flow_points:
        fragments.append(f"{len(flow_points)} flow hints")
    return ", ".join(fragments) if fragments else "No major flow signals detected"


def analyze_django_models(path: Path, content: str) -> list[ModelSchema]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except SyntaxError:
        return []
    
    models = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check if it's likely a Django Model
            is_model = any(
                (isinstance(base, ast.Attribute) and base.attr == "Model") or
                (isinstance(base, ast.Name) and "Model" in base.id)
                for base in node.bases
            )
            if not is_model:
                continue
                
            fields = []
            for item in node.body:
                if isinstance(item, ast.Assign) and len(item.targets) == 1:
                    target = item.targets[0]
                    if isinstance(target, ast.Name):
                        field_name = target.id
                        field_type = "Unknown"
                        related_to = None
                        
                        if isinstance(item.value, ast.Call):
                            func = item.value.func
                            if isinstance(func, ast.Attribute):
                                field_type = func.attr
                            elif isinstance(func, ast.Name):
                                field_type = func.id
                                
                            # Extract relationships
                            for arg in item.value.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    related_to = arg.value
                                elif isinstance(arg, ast.Name):
                                    related_to = arg.id
                                    
                        fields.append(ModelField(name=field_name, type=field_type, related_to=related_to))
            
            models.append(ModelSchema(name=node.name, file=str(path), fields=fields))
    return models


def analyze_serializers(path: Path, content: str) -> list[SerializerSchema]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except SyntaxError:
        return []
    
    serializers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Detect Serializers
            is_serializer = any(
                (isinstance(base, ast.Attribute) and "Serializer" in base.attr) or
                (isinstance(base, ast.Name) and "Serializer" in base.id)
                for base in node.bases
            )
            if not is_serializer:
                continue
                
            fields: list[str] = []
            meta_model: str | None = None
            for item in node.body:
                if isinstance(item, ast.Assign) and len(item.targets) == 1:
                    target = item.targets[0]
                    if isinstance(target, ast.Name):
                        if target.id not in ("Meta", "queryset", "serializer_class"):
                            fields.append(target.id)

                if isinstance(item, ast.ClassDef) and item.name == "Meta":
                    for meta_item in item.body:
                        if not (isinstance(meta_item, ast.Assign) and len(meta_item.targets) == 1):
                            continue
                        m_target = meta_item.targets[0]
                        if not isinstance(m_target, ast.Name):
                            continue
                        if m_target.id == "model":
                            if isinstance(meta_item.value, ast.Name):
                                meta_model = meta_item.value.id
                            elif isinstance(meta_item.value, ast.Attribute):
                                meta_model = meta_item.value.attr
                        elif m_target.id == "fields":
                            if isinstance(meta_item.value, (ast.List, ast.Tuple)):
                                for elt in meta_item.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        fields.append(elt.value)
                            # fields = '__all__' — leave fields empty; model lookup fills it in Phase 2

            serializers.append(SerializerSchema(
                name=node.name,
                file=str(path),
                fields=sorted(list(set(fields))),
                model=meta_model,
            ))
    return serializers


_SENSITIVE_KEY = re.compile(
    r"(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|SIGNING_KEY|"
    r"ENCRYPTION_KEY|AUTH_KEY|DATABASE_URL|DB_URL|DB_PASS|HASH|SALT|CREDENTIAL|"
    r"ACCESS_KEY|CLIENT_SECRET|WEBHOOK_SECRET|TWILIO|SENDGRID|STRIPE|AWS)",
    re.IGNORECASE,
)


def extract_configs(lines: list[str], path: Path) -> list[ConfigPoint]:
    configs = []
    path_str = str(path).lower()
    if "settings" not in path_str and "config" not in path_str:
        return configs

    pattern = re.compile(r"^([A-Z_][A-Z0-9_]+)\s*=\s*(.*)$")
    for idx, line in enumerate(lines, start=1):
        match = pattern.match(line.strip())
        if not match:
            continue
        key = match.group(1)
        value = match.group(2)[:100]
        if _SENSITIVE_KEY.search(key):
            value = "[REDACTED]"
        configs.append(ConfigPoint(key=key, value=value, file=str(path), line=idx))
    return configs


def build_function_summary(
    name: str,
    routes: list[str],
    checks: list[str],
    database: list[dict],
    outbound: list[dict],
    returns: list[dict],
    decisions: list[dict],
    is_generic: bool = False,
) -> str:
    type_label = "Generic" if is_generic else "Specific"
    fragments = [f"{type_label} function `{name}`"]
    if routes:
        fragments.append(f"serves {routes[0]}")
    if checks:
        fragments.append(f"checks {', '.join(checks[:3])}")
    if database:
        fragments.append(f"touches {', '.join(item['table'] for item in database[:2])}")
    if outbound:
        fragments.append(f"calls {', '.join(item['label'] for item in outbound[:1])}")
    if decisions:
        fragments.append(f"contains {len(decisions)} decision gate(s)")
    return ", ".join(fragments)


def build_partner_narrative(
    partner: str,
    checks: list[str],
    inbound_apis: list[dict],
    outbound_apis: list[dict],
    database_tables: list[dict],
    functions: list[dict],
    flow_points: list[dict],
) -> list[str]:
    narrative = [f"Partner `{partner}` appears in {len(functions) or len(flow_points)} structured flow area(s)."]
    if inbound_apis:
        narrative.append(f"Requests likely enter through {inbound_apis[0]['label']}.")
    if checks:
        narrative.append(f"Primary checks: {', '.join(checks[:5])}.")
    if database_tables:
        narrative.append(f"Table access includes {', '.join(item['table'] for item in database_tables[:3])}.")
    if outbound_apis:
        narrative.append(f"External integration includes {outbound_apis[0]['label']}.")
    if functions:
        narrative.append(f"Key function: {functions[0]['name']} at line {functions[0]['line']}.")
    return narrative


def run_diagnostics(reports: list[FileReport]) -> list[dict]:
    diagnostics = []
    for report in reports:
        content = Path(report.path).read_text(errors="ignore")
        
        # 1. Security: Unprotected APIs
        for api in report.inbound_apis:
            if "views.py" in report.path and "permission_classes" not in content:
                diagnostics.append(asdict(Diagnostic(
                    "Security", "Warning", f"API {api.label} might be missing permission checks.", report.path, api.line
                )))
        
        # 2. Logic: Missing is_valid() before save/create
        if ".save()" in content and "is_valid()" not in content:
            diagnostics.append(asdict(Diagnostic(
                "Logic", "Critical", "Model.save() called without visible is_valid() check nearby.", report.path, 0
            )))
            
        # 3. Performance: N+1 Hint
        for func in report.functions:
            loops = [s for s in func.ordered_steps if s["type"] == "decision" and ("for " in s["label"] or "while " in s["label"])]
            db_touches = [s for s in func.ordered_steps if s["type"] == "database"]
            if loops and db_touches:
                diagnostics.append(asdict(Diagnostic(
                    "Performance", "Info", f"Function {func.name} contains a loop and DB touches. Check for N+1 issues.", report.path, func.line
                )))
                
    return diagnostics


def generate_mermaid(report: dict[str, Any]) -> str:
    _SKIP_CLASSES = frozenset(("self", "super", "cls", "re", "os", "json", "response",
                               "Response", "transaction", "Q", "request", "serializer",
                               "queryset", "instance", "obj", "data"))

    def safe_id(text: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", text).strip("_") or "node"
        cleaned = cleaned[:48].strip("_") or "node"
        return ("n_" + cleaned) if cleaned[0].isdigit() else cleaned

    def safe_label(text: str) -> str:
        return (
            text.replace('"', "'").replace("<", "(").replace(">", ")")
            .replace("\n", " ").replace("\r", " ").replace("#", "")
        )

    def trunc(text: str, n: int = 36) -> str:
        return text if len(text) <= n else text[: n - 2] + ".."

    # Build comprehensive function lookup
    func_map: dict[str, dict] = {}
    for file_report in report["files"]:
        for func in file_report["functions"]:
            key = f"{func['class_name']}:{func['name']}" if func.get("class_name") else func["name"]
            func_map[key] = func

    # Group every inbound API by app — no limits yet
    app_apis: dict[str, list] = {}
    for api in report["apis"]["inbound"]:
        app = api.get("app", "root")
        app_apis.setdefault(app, []).append(api)

    if not app_apis:
        return "graph LR\n  A[No API data found]"

    node_ids: set[str] = set()
    api_nodes: list[str] = []
    handler_nodes: list[str] = []
    db_nodes: list[str] = []
    outbound_nodes: list[str] = []

    sg_lines: list[str] = []
    outer_lines: list[str] = []
    edge_lines: list[str] = []
    seen_edges: set[tuple] = set()

    def add_edge(src: str, dst: str, label: str = "") -> None:
        key = (src, dst, label)
        if key not in seen_edges:
            seen_edges.add(key)
            arrow = f"  {src} -->|{safe_label(label)}| {dst}" if label else f"  {src} --> {dst}"
            edge_lines.append(arrow)

    def resolve_db_for(handler_id: str, fn: dict, depth: int = 0) -> None:
        for db in fn.get("database_tables", [])[:4]:
            tbl = db.get("table", "")
            if not tbl or tbl.lower() in ("unknown", "a", "b", "c", "d"):
                continue
            db_id = safe_id(f"db_{tbl}")
            if db_id not in node_ids:
                outer_lines.append(f'  {db_id}[("{safe_label(trunc(tbl))}")]')
                node_ids.add(db_id)
                db_nodes.append(db_id)
            add_edge(handler_id, db_id)
        if depth < 1:
            for sub_call in fn.get("internal_calls", [])[:3]:
                sub_cls = sub_call.get("class", "")
                sub_method = sub_call.get("method", "")
                if sub_cls == "cls":
                    sub_cls = fn.get("class_name", "")
                if not sub_cls or sub_cls.lower() in _SKIP_CLASSES:
                    continue
                sub_fn = func_map.get(f"{sub_cls}:{sub_method}")
                if sub_fn:
                    resolve_db_for(handler_id, sub_fn, depth + 1)

    def resolve_outbound_for(handler_id: str, fn: dict) -> None:
        for out in fn.get("outbound_apis", [])[:2]:
            lbl = out.get("label", "")
            if not lbl:
                continue
            out_id = safe_id(f"ext_{lbl}")
            if out_id not in node_ids:
                outer_lines.append(f'  {out_id}[/"  {safe_label(trunc(lbl, 28))}  "/]')
                node_ids.add(out_id)
                outbound_nodes.append(out_id)
            add_edge(handler_id, out_id)

    # Build one subgraph per app — up to 12 APIs each
    for app, apis in app_apis.items():
        sg_id = safe_id(app) + "_sg"
        sg_lines.append(f'  subgraph {sg_id}["{safe_label(app)}"]')

        for api in apis[:12]:
            api_id = safe_id(f"{safe_id(app)}_{api['label']}")
            if api_id in node_ids:
                continue
            label = safe_label(trunc(api["label"]))
            if api.get("payload"):
                label += f" | {safe_label(trunc(', '.join(api['payload'][:3]), 28))}"
            sg_lines.append(f'    {api_id}["{label}"]')
            node_ids.add(api_id)
            api_nodes.append(api_id)

        sg_lines.append("  end")

    # Connect every API to its handler(s) and trace through to DB / outbound
    for api in report["apis"]["inbound"]:
        app = api.get("app", "root")
        api_id = safe_id(f"{safe_id(app)}_{api['label']}")
        if api_id not in node_ids:
            continue

        view_name = api.get("view_name")
        action = api.get("action")

        # Try multiple lookup strategies
        func = None
        for lookup in [
            f"{view_name}:{action}" if (view_name and action) else None,
            action,
            view_name,
        ]:
            if lookup:
                func = func_map.get(lookup)
                if func:
                    break

        if not func:
            continue

        # Find handler(s) via internal_calls
        handler_found = False
        for call in func.get("internal_calls", [])[:4]:
            cls = call.get("class", "")
            method = call.get("method", "")
            if cls == "cls":
                cls = func.get("class_name", "")
            if not cls or cls.lower() in _SKIP_CLASSES:
                continue

            handler_id = safe_id(f"{cls}_{method}")
            handler_fn = func_map.get(f"{cls}:{method}")

            if handler_id not in node_ids:
                outer_lines.append(f'  {handler_id}("{safe_label(trunc(cls + "." + method))}")')
                node_ids.add(handler_id)
                handler_nodes.append(handler_id)
            add_edge(api_id, handler_id)
            handler_found = True

            target_fn = handler_fn or func
            resolve_db_for(handler_id, target_fn)
            resolve_outbound_for(handler_id, target_fn)

        if not handler_found:
            # Fall back: show the matched function itself as the handler
            cls = func.get("class_name", "")
            fname = func.get("name", "")
            if cls and fname:
                handler_id = safe_id(f"{cls}_{fname}")
                if handler_id not in node_ids:
                    outer_lines.append(f'  {handler_id}("{safe_label(trunc(cls + "." + fname))}")')
                    node_ids.add(handler_id)
                    handler_nodes.append(handler_id)
                add_edge(api_id, handler_id)
                resolve_db_for(handler_id, func)
                resolve_outbound_for(handler_id, func)

    parts = (
        ["%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#1e3a5f', 'background': '#0a1628', 'mainBkg': '#0a1628'}}}%%",
         "flowchart LR"]
        + sg_lines
        + outer_lines
        + edge_lines
        + [
            "  classDef apiNode fill:#1d5f8a,stroke:#38bdf8,color:#ffffff,font-weight:bold",
            "  classDef handlerNode fill:#5b2d8e,stroke:#c084fc,color:#ffffff,font-weight:bold",
            "  classDef dbNode fill:#166534,stroke:#4ade80,color:#ffffff,font-weight:bold",
            "  classDef outNode fill:#7c2d12,stroke:#fb923c,color:#ffffff,font-weight:bold",
        ]
    )
    if api_nodes:
        parts.append(f"  class {','.join(api_nodes)} apiNode")
    if handler_nodes:
        parts.append(f"  class {','.join(handler_nodes)} handlerNode")
    if db_nodes:
        parts.append(f"  class {','.join(db_nodes)} dbNode")
    if outbound_nodes:
        parts.append(f"  class {','.join(outbound_nodes)} outNode")

    return "\n".join(parts)


def make_json_safe(value):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        return {key: make_json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [make_json_safe(item) for item in value]
    if isinstance(value, set):
        return [make_json_safe(item) for item in sorted(value, key=str)]
    return value
