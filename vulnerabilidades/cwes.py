import matplotlib.pyplot as plt
import numpy as np
import ast

# Mapeamento para nomes bonitos
cwe_nomes = {
    "CWE-78": "CWE-78: OS Command Injection",
    "CWE-22": "CWE-22: Path Traversal",
    "CWE-20": "CWE-20: Improper\n Input Validation"
}

# Arquivos dos 3 projetos
arquivos = {
    "API": "cwe-api.txt",
    "Snow": "cwe-snow.txt",
    "Smells": "cwe-smells.txt"
}

# Filtrar apenas essas CWEs
cwes_alvo = ["CWE-20", "CWE-22", "CWE-78"]

# Função para carregar os dicionários salvos
def carregar_dados(arquivo):
    with open(arquivo, "r", encoding="utf-8") as f:
        conteudo = f.read()
    return ast.literal_eval(conteudo)  # converte texto -> dict

# Carregar os dados de cada projeto
dados_projetos = {nome: carregar_dados(arq) for nome, arq in arquivos.items()}

# Agora gera um gráfico por CWE
for cwe in cwes_alvo:
    labels_proj = list(dados_projetos.keys())  # ["API", "Snow", "Smells"]
    
    highs = [dados_projetos[proj].get(cwe, {}).get("High", 0) for proj in labels_proj]
    mids  = [dados_projetos[proj].get(cwe, {}).get("Medium", 0) for proj in labels_proj]
    low  = [dados_projetos[proj].get(cwe, {}).get("Low", 0) for proj in labels_proj]
    
    x = np.arange(len(labels_proj))
    largura = 0.35
    
    fig, ax = plt.subplots(figsize=(7, 5))
    
    bars_high = ax.bar(x - largura/2, highs, largura, color='crimson', label='High')
    bars_mid  = ax.bar(x + largura/2, mids, largura, color='orange', label='Medium')
    
    # Configurações
    ax.set_xticks(x)
    ax.set_xticklabels(labels_proj)
    ax.set_ylabel("Número de Ocorrências")
    ax.set_title(f"Comparação de Severidade - {cwe_nomes[cwe]}")
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.6)
    
    # Mostrar valores nas barras
    for bar in bars_high + bars_mid:
        altura = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, altura + 0.5, str(altura),
                ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.show()
