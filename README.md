# Análise de Vulnerabilidades em Código-Fonte 

Este repositório descreve o procedimento para executar uma análise automática de vulnerabilidades em código fonte em linguagem Python usando a ferramenta **Bandit** que as classifica por severidade, sobre os projetos do laboratório AISE. Após gerar os relatórios, o script `analise_cwe.py` é usados para plotar e analisar os resultados.

## Pré-requisitos
* Python 3.11 (recomendado).
* pip instalado.
* (Opcional) Ambiente Virtual para isolar o ambiente.
* Clonar os projetos que serão analisados
* Instalação da ferramenta e das bibliotecas necessárias


## Ambiente Virtual
É recomendável usar um ambiente virtual. Exemplo rápido:
```bash
# criar e ativar venv (opcional)
python -m venv .venv
source .venv/bin/activate   # Linux / macOS
.venv\Scripts\activate    # Windows 
```

## Clonar os projetos
Baixe (clone / faça download) os projetos listados abaixo antes de rodar a análise:
* `forward-snowballing`: https://github.com/aisepucrio/stnl-dataminer-api.git
* `stnl-dataminer-api`: https://github.com/aisepucrio/forward-snowballing.git

## Instalação da ferramenta e das bibliotecas 
* bandit - ferramenta vulnerabilidade 
* matplotlib e numpy - bibliotecas de plotar resultados

`pip install bandit matplotlib numpy`

## Como rodar o script  `analise_cwe.py`
Siga os passos abaixo para executar a análise automática de vulnerabilidades:
1. Abra o **terminal** ou **prompt de comando** no diretório onde está o script `analise_cwe.py`.
2. Execute o comando:
`python analise_cwe.py`
3. Quando solicitado, digite o nome do projeto que deseja analisar
4. O script fará automaticamente:
    - Executar o Bandit no projeto selecionado;
    - Criar o arquivo relatorio.txt com todas as vulnerabilidades detectadas;
    - Gerar o arquivo cwe.txt com o resumo das CWEs e suas severidades;
    - Exibir 4 gráficos com as principais CWEs encontradas:
        - Top 10 CWEs - High / Medium / Low
        - Top 5 CWEs - High / Medium / Low
        - Top 10 CWEs - High / Medium
        - Top 5 CWEs - High / Medium


### CWEs analisadas
| CWE     | Descrição                                         |
|---------|--------------------------------------------------|
| CWE-20  | Improper Input Validation                        |
| CWE-22  | Path Traversal                                   |
| CWE-78  | OS Command Injection                              |
| CWE-89  | SQL Injection                                    |
| CWE-259 | Use of Hard-coded Password                        |
| CWE-327 | Broken or Risky Crypto Algorithm                 |
| CWE-330 | Use of Insufficiently Random Values              |
| CWE-377 | Insecure Temporary File                           |
| CWE-400 | Uncontrolled Resource Consumption                |
| CWE-502 | Deserialization of Untrusted Data                |
| CWE-703 | Improper Check or Handling of Exceptional Conditions |
| CWE-732 | Incorrect Permission Assignment for Critical Resource |
| CWE-838 | Inappropriate Encoding for Output Context       |


## Estrutura sugerida do repositório

```bash
/
├─ README.md
├─ vulnerabilidades/
  ├─ forward-snowballing/  #análise de vulnerabilidade nesse projeto
  │  ├─ relatorio.txt/
  │  ├─ cwe.txt/
  ├─ stnl-dataminer-api/  #análise de vulnerabilidade nesse projeto
  │  ├─ relatorio.txt/
  │  ├─ cwe.txt/
├─ forward-snowballing/      # clone deste projeto 
└─ stnl-dataminer-api/       # clone deste projeto
...
```

