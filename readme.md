<div align="center">

```text
          _____                _____                    _____            _____                    _____        _____                    _____                    _____                    _____
         /\    \              /\    \                  /\    \          /\    \                  /\    \      |\    \                  /\    \                  /\    \                  /\    \
        /::\    \            /::\    \                /::\____\        /::\    \                /::\____\     |:\____\                /::\    \                /::\    \                /::\    \
       /::::\    \           \:::\    \              /:::/    /       /::::\    \              /:::/    /     |::|   |                \:::\    \              /::::\    \              /::::\    \
      /::::::\    \           \:::\    \            /:::/    /       /::::::\    \            /:::/    /      |::|   |                 \:::\    \            /::::::\    \            /::::::\    \
     /:::/\:::\    \           \:::\    \          /:::/    /       /:::/\:::\    \          /:::/    /       |::|   |                  \:::\    \          /:::/\:::\    \          /:::/\:::\    \
    /:::/__\:::\    \           \:::\    \        /:::/    /       /:::/__\:::\    \        /:::/    /        |::|   |                   \:::\    \        /:::/__\:::\    \        /:::/__\:::\    \
   /::::\   \:::\    \          /::::\    \      /:::/    /       /::::\   \:::\    \      /:::/    /         |::|   |                    \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \
  /::::::\   \:::\    \        /::::::\    \    /:::/    /       /::::::\   \:::\    \    /:::/    /          |::|___|______               \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \
 /:::/\:::\   \:::\    \      /:::/\:::\    \  /:::/    /       /:::/\:::\   \:::\    \  /:::/    /           /::::::::\    \               \:::\    \  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\____\
/:::/  \:::\   \:::\____\    /:::/  \:::\____\/:::/____/       /:::/  \:::\   \:::\____\/:::/____/           /::::::::::\____\_______________\:::\____\/:::/__\:::\   \:::\____\/:::/  \:::\   \:::|    |
\::/    \:::\  /:::/    /   /:::/    \::/    /\:::\    \       \::/    \:::\  /:::/    /\:::\    \          /:::/~~~~/~~      \::::::::::::::::::/    /\:::\   \:::\   \::/    /\::/   |::::\  /:::|____|
 \/____/ \:::\/:::/    /   /:::/    / \/____/  \:::\    \       \/____/ \:::\/:::/    /  \:::\    \        /:::/    /          \::::::::::::::::/____/  \:::\   \:::\   \/____/  \/____|:::::\/:::/    /
          \::::::/    /   /:::/    /            \:::\    \               \::::::/    /    \:::\    \      /:::/    /            \:::\~~~~\~~~~~~         \:::\   \:::\    \            |:::::::::/    /
           \::::/    /   /:::/    /              \:::\    \               \::::/    /      \:::\    \    /:::/    /              \:::\    \               \:::\   \:::\____\           |::|\::::/    /
           /:::/    /    \::/    /                \:::\    \              /:::/    /        \:::\    \   \::/    /                \:::\    \               \:::\   \::/    /           |::| \::/____/
          /:::/    /      \/____/                  \:::\    \            /:::/    /          \:::\    \   \/____/                  \:::\    \               \:::\   \/____/            |::|  ~|
         /:::/    /                                 \:::\    \          /:::/    /            \:::\    \                            \:::\    \               \:::\    \                |::|   |
        /:::/    /                                   \:::\____\        /:::/    /              \:::\____\                            \:::\____\               \:::\____\               \::|   |
        \::/    /                                     \::/    /        \::/    /                \::/    /                             \::/    /                \::/    /                \:|   |
         \/____/                                       \/____/          \/____/                  \/____/                               \/____/                  \/____/                  \|___|

```

</div>

# atlalyzer // file analyzer

> uma cópia barata e humilde do virustotal, feita do zero, com python e vontade de aprender.

o **atlalyzer** começou com uma ideia simples: criar uma ferramenta capaz de analisar arquivos, identificar informações importantes e encontrar possíveis anomalias.

a proposta inicial era fazer o básico bem feito. verificar se um arquivo existe, descobrir seu tamanho e calcular seu hash sha-256. mas a ideia é ir além.

quero transformar esse projeto em um pequeno laboratório de análise de arquivos suspeitos, evoluindo uma versão de cada vez, aprendendo no processo e tentando lançar uma atualização por dia.

sem pressa para parecer algo gigante. primeiro, fazer funcionar. depois, entender como funciona. por último, deixar melhor.

---

## `roadmap.log`

### v0 — the beginning

- verificação da existência do arquivo
- validação do caminho informado
- identificação do tamanho em bytes
- cálculo do hash sha-256
- leitura em blocos para evitar carregar arquivos inteiros na memória

### v1 — making it stronger

- analisador mais robusto
- tratamento de erros para evitar encerramentos inesperados
- validações mais seguras
- primeiros testes manuais

### v2 — file signatures

- identificação de formatos por assinatura binária
- comparação entre a extensão e o formato detectado
- identificação de possíveis incompatibilidades entre extensão e conteúdo

### v3 — structured output

- resultados organizados em objetos python
- geração de relatórios em json
- separação entre lógica de análise e apresentação dos resultados

### v4 — automated testing

- criação do `teste_main.py`
- testes automatizados com `unittest`
- validação dos dados identificados
- comparação do sha-256 com hashes previamente calculados
- testes de tratamento de erros e geração de relatórios json

### v5 — extension awareness

- suporte à identificação de diferentes extensões
- validação mais consistente entre extensão e formato detectado

### v7 — metadata extraction

- pulei a v6 pelo motivo óbvio
- tratamento de arquivos inválidos ou corrompidos
- extração de metadados de imagens
- identificação de informações ausentes
- preservação dos arquivos originais durante a análise

### v10 — anomaly detection & database

aqui o projeto começou a ganhar mais cara de ferramenta de análise.

- detector de anomalias baseado em regras
- pontuação e classificação de risco
- integração com banco de dados sqlite
- análise de múltiplos arquivos em lote
- geração de relatórios individuais em json
- histórico persistente de análises
- **27 testes automatizados aprovados**

---

## `how_to_test.md`

para executar os testes automatizados, entre na pasta do projeto e rode:

```bash
python -m unittest -v
```

os testes ajudam a validar o comportamento das funções e a evitar que novas alterações quebrem o que já funciona.

---

## `what's next?`

o atlalyzer ainda está em desenvolvimento. a ideia é continuar evoluindo a ferramenta aos poucos, adicionando recursos que façam sentido e entendendo cada parte antes de avançar.

alguns dos objetivos para o futuro:

- ampliar a identificação de formatos
- melhorar a detecção de arquivos suspeitos
- adicionar novas verificações e indicadores
- evoluir o histórico e os relatórios
- construir uma base para um laboratório de análise de arquivos

---

## `disclaimer.txt`

o atlalyzer é um projeto educacional e experimental. a pontuação de risco é baseada em regras heurísticas e não confirma, por si só, que um arquivo é malicioso.

**não é um substituto para o virustotal ou para soluções profissionais de segurança.** é um projeto em evolução, feito para aprender, testar ideias e construir algo útil de verdade.

---

_building it one version at a time. learning by breaking things, fixing them, and trying again._
