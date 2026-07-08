"""
Selección curada de técnicas de MITRE ATT&CK Enterprise, agrupadas por
táctica, para el tablero de cobertura del dashboard (dashboard/pages/2_🎯_MITRE.py).

No es el dataset STIX oficial completo (~200 técnicas) — con 6 reglas de
detección, un heatmap de todo el framework se vería casi vacío. Esta es
una selección representativa de las 13 tácticas de Enterprise ATT&CK que
SÍ incluye, exactas, las técnicas que producen nuestras reglas
(engine/detectors/rules.py) para que aparezcan resaltadas con datos
reales; el resto queda como referencia de lo que un SIEM más maduro
también cubriría.
"""

# (tactic, technique_id, technique_name) — technique_id debe calzar
# exacto con el string "ID - Nombre" que arma engine/detectors/rules.py.
MITRE_REFERENCE = [
    # Reconnaissance
    ("Reconnaissance", "T1595", "Active Scanning"),
    ("Reconnaissance", "T1592", "Gather Victim Host Information"),
    ("Reconnaissance", "T1589", "Gather Victim Identity Information"),

    # Initial Access
    ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    ("Initial Access", "T1133", "External Remote Services"),
    ("Initial Access", "T1566", "Phishing"),

    # Execution
    ("Execution", "T1059", "Command and Scripting Interpreter"),
    ("Execution", "T1203", "Exploitation for Client Execution"),
    ("Execution", "T1053", "Scheduled Task/Job"),
    ("Execution", "T1053.005", "Scheduled Task"),

    # Persistence
    ("Persistence", "T1098", "Account Manipulation"),
    ("Persistence", "T1543", "Create or Modify System Process"),
    ("Persistence", "T1543.003", "Windows Service"),
    ("Persistence", "T1136", "Create Account"),
    ("Persistence", "T1554", "Compromise Client Software Binary"),

    # Privilege Escalation
    ("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
    ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("Privilege Escalation", "T1055", "Process Injection"),

    # Defense Evasion
    ("Defense Evasion", "T1078", "Valid Accounts"),
    ("Defense Evasion", "T1070", "Indicator Removal"),
    ("Defense Evasion", "T1027", "Obfuscated Files or Information"),

    # Credential Access
    ("Credential Access", "T1110", "Brute Force"),
    ("Credential Access", "T1110.003", "Password Spraying"),
    ("Credential Access", "T1552", "Unsecured Credentials"),
    ("Credential Access", "T1003", "OS Credential Dumping"),

    # Discovery
    ("Discovery", "T1087", "Account Discovery"),
    ("Discovery", "T1082", "System Information Discovery"),
    ("Discovery", "T1046", "Network Service Discovery"),

    # Lateral Movement
    ("Lateral Movement", "T1021", "Remote Services"),
    ("Lateral Movement", "T1550", "Use Alternate Authentication Material"),

    # Collection
    ("Collection", "T1005", "Data from Local System"),
    ("Collection", "T1114", "Email Collection"),

    # Command and Control
    ("Command and Control", "T1071", "Application Layer Protocol"),
    ("Command and Control", "T1105", "Ingress Tool Transfer"),

    # Exfiltration
    ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("Exfiltration", "T1567", "Exfiltration Over Web Service"),

    # Impact
    ("Impact", "T1565.001", "Stored Data Manipulation"),
    ("Impact", "T1490", "Inhibit System Recovery"),
    ("Impact", "T1489", "Service Stop"),
]

# Orden en que se dibujan las tácticas — sigue el "kill chain" de ATT&CK.
TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
