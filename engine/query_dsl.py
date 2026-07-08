import re

# Regex de tokenizado: separa por espacios pero mantiene juntas las
# frases entre comillas ("login denied") como un solo token.
TOKEN_RE = re.compile(r'"[^"]*"|\S+')


def _strip_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return token


def parse_query(
    query: str | None,
    field_columns: dict[str, str],
    free_text_column: str,
    numeric_fields: set[str] = frozenset(),
) -> tuple[str, tuple]:
    """
    Parsea una búsqueda tipo Lucene/KQL simplificada -- "campo:valor",
    texto libre (busca por substring en `free_text_column`), y los
    conectores AND/OR/NOT -- a un fragmento SQL parametrizado, listo
    para pegar después de un "WHERE 1=1 {clause}" ya existente.

    No soporta paréntesis/agrupación explícita (fuera de alcance para
    este proyecto, igual que la mayoría de las búsquedas simples de un
    SIEM): las condiciones se pliegan de izquierda a derecha en el
    orden en que se escriben (ej. "a OR b AND c" se evalúa como
    "(a OR b) AND c", no con la precedencia normal de AND-antes-que-OR).

    field_columns mapea alias de campo (en minúsculas) -> columna real
    de la tabla -- un campo no reconocido no rompe la búsqueda, cae a
    buscar el token completo como texto libre. numeric_fields son las
    columnas que comparan con "=" en vez de LIKE substring.
    """
    query = (query or "").strip()
    if not query:
        return "", ()

    tokens = TOKEN_RE.findall(query)
    expr: str | None = None
    params: list = []
    pending_connector = "AND"
    pending_negate = False

    for raw_token in tokens:
        upper = raw_token.upper()
        if upper in ("AND", "OR"):
            pending_connector = upper
            continue
        if upper == "NOT":
            pending_negate = True
            continue

        token = _strip_quotes(raw_token)
        if not token:
            continue

        field, sep, value = token.partition(":")
        column = field_columns.get(field.lower()) if sep else None

        if column is None:
            condition = f"LOWER({free_text_column}) LIKE ?"
            params.append(f"%{token.lower()}%")
        elif column in numeric_fields:
            condition = f"{column} = ?"
            params.append(value)
        else:
            condition = f"LOWER({column}) LIKE ?"
            params.append(f"%{value.lower()}%")

        if pending_negate:
            condition = f"NOT ({condition})"

        expr = condition if expr is None else f"({expr} {pending_connector} {condition})"
        pending_connector = "AND"
        pending_negate = False

    if expr is None:
        return "", ()
    return f"AND ({expr})", tuple(params)
