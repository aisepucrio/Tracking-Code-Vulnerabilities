import os
import re
import subprocess
from collections import defaultdict
from pprint import pformat
import matplotlib.pyplot as plt
import numpy as np

nome_projeto = input("Digite o nome do projeto que deseja analisar: ").strip()

base_dir = os.getcwd()
vuln_dir = os.path.join(base_dir, "vulnerabilidades", nome_projeto)
os.makedirs(vuln_dir, exist_ok=True)

relatorio_bandit = os.path.join(vuln_dir, "relatorio.txt")
arquivo_cwe = os.path.join(vuln_dir, "cwe.txt")

print(f"\n--> Executando Bandit no projeto '{nome_projeto}'...\n")

caminho_projeto = os.path.join(base_dir, nome_projeto)

if not os.path.isdir(caminho_projeto):
    print(f"Erro: A pasta '{caminho_projeto}' não foi encontrada.")
    exit(1)

result = subprocess.run(
    ["bandit", "-r", caminho_projeto, "-f", "txt", "-o", relatorio_bandit],
    capture_output=True,
    text=True
)

if result.returncode == 0 or os.path.exists(relatorio_bandit):
    print(f" - Relatório Bandit criado em: {relatorio_bandit}")
else:
    print("Erro ao executar o Bandit. Saída completa abaixo:\n")
    print(result.stderr or result.stdout)
    exit(1)

cwe_nomes = {
    "CWE-259": "CWE-259: Use of Hard-coded Password",
    "CWE-400": "CWE-400: Uncontrolled Resource Consumption",
    "CWE-78": "CWE-78: OS Command Injection",
    "CWE-703": "CWE-703: Improper Check or Handling of Exceptional Conditions",
    "CWE-732": "CWE-732: Incorrect Permission Assignment for Critical Resource",
    "CWE-838": "CWE-838: Inappropriate Encoding for Output Context",
    "CWE-22": "CWE-22: Path Traversal",
    "CWE-20": "CWE-20: Improper Input Validation",
    "CWE-330": "CWE-330: Use of Insufficiently Random Values",
    "CWE-327": "CWE-327: Broken or Risky Crypto Algorithm",
    "CWE-377": "CWE-377: Insecure Temporary File",
    "CWE-502": "CWE-502: Deserialization of Untrusted Data",
    "CWE-89": "CWE-89: SQL Injection"
}

regex_cwe = re.compile(r"CWE:\s+(CWE-\d+)")
regex_sev = re.compile(r"Severity:\s+(High|Medium|Low)")

contagem = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0})

with open(relatorio_bandit, "r", encoding="utf-8") as f:
    linhas = f.readlines()

for i in range(len(linhas)):
    linha = linhas[i]
    if "Issue:" in linha:
        sev_match = regex_sev.search(linhas[i+1]) if i+1 < len(linhas) else None
        cwe_match = regex_cwe.search(linhas[i+2]) if i+2 < len(linhas) else None

        if cwe_match and sev_match:
            codigo_cwe = cwe_match.group(1)
            severidade = sev_match.group(1)
            nome_cwe = cwe_nomes.get(codigo_cwe, codigo_cwe)
            contagem[nome_cwe][severidade] += 1

with open(arquivo_cwe, "w", encoding="utf-8") as file:
    file.write(pformat(dict(contagem)))

print(f"- Arquivo CWE salvo em: {arquivo_cwe}")

def gerar_grafico(contagem, top_n=10, severidades=["High", "Medium", "Low"], titulo=""):
    soma_total = {cwe: sum(contagem[cwe][sev] for sev in severidades) for cwe in contagem}
    top_cwes = sorted(soma_total.items(), key=lambda item: item[1], reverse=True)[:top_n]
    top_labels = [item[0] for item in top_cwes]

    valores = {sev: [contagem[cwe][sev] for cwe in top_labels] for sev in severidades}

    x = np.arange(len(top_labels))
    largura = 0.2

    plt.figure(figsize=(10, 5))
    for i, sev in enumerate(severidades):
        plt.bar(x + (i - len(severidades)/2)*largura + largura/2, valores[sev], width=largura, label=sev)

    plt.xticks(x, top_labels, rotation=30, ha='right')
    plt.ylabel('Número de Ocorrências')
    plt.xlabel('CWEs')
    plt.title(titulo)
    plt.legend(title='Severidade')
    plt.tight_layout()

    for i, sev in enumerate(severidades):
        for j, val in enumerate(valores[sev]):
            plt.text(x[j] + (i - len(severidades)/2)*largura + largura/2, val + 0.1, str(val),
                     ha='center', va='bottom', fontsize=8)
    plt.show()

gerar_grafico(contagem, top_n=10, severidades=["High", "Medium", "Low"], titulo=f"Top 10 CWEs - High/Medium/Low - {nome_projeto}")
gerar_grafico(contagem, top_n=5, severidades=["High", "Medium", "Low"], titulo=f"Top 5 CWEs - High/Medium/Low - {nome_projeto}")
gerar_grafico(contagem, top_n=10, severidades=["High", "Medium"], titulo=f"Top 10 CWEs - High/Medium - {nome_projeto}")
gerar_grafico(contagem, top_n=5, severidades=["High", "Medium"], titulo=f"Top 5 CWEs - High/Medium - {nome_projeto}")

print("\n --> Análise concluída com sucesso!\n")
