# atlalyzer [file analyzer]

o objetivo inicial é criar uma cópia "barata e humilde" do virus total, mas visando ser uma ferramenta simples que consiga verificar arquivos, identificar seu tamanho e calcular seu hash sha-256. atualmente quero lançar uma versão/mvp por dia (ou ao mesmo tentar). futuramente, o projeto pode evoluir para um laboratório de análise de arquivos suspeitos.

## funcionalidades (v0)

- verificaçao da existência do arquivo
- verificação se o caminho informado aponta para um arquivo
- identificação do tamanho em bytes
- cálculo do hash sha-256
- leitura em blocos para evitar carregar o arquivo inteiro na memória

## código

```python
from pathlib import Path  # biblioteca usada para trabalhar com caminhos de arquivos
import hashlib  # biblioteca para calcular hashes

def analyze_file(file_path):
    # crio um objeto path para trabalhar com o caminho do arquivo de forma mais simples
    path = Path(file_path)

    # verifico se o caminho informado realmente existe antes de tentar acessar o arquivo
    if not path.exists():
        print("erro: arquivo não encontrado.")
        return

    # verifico se o caminho informado aponta para um arquivo, e não para uma pasta
    if not path.is_file():
        print("erro: o caminho informado não é um arquivo.")
        return

    # obtenho o tamanho do arquivo em bytes usando as informações do próprio arquivo
    file_size = path.stat().st_size

    # crio um objeto sha-256 que vai acumular os dados usados para calcular o hash
    sha256 = hashlib.sha256()

    # abro o arquivo em modo binário para ler os bytes originais, sem tentar interpretar o conteúdo como texto
    with path.open("rb") as file:

        # leio o arquivo em blocos de 4096 bytes para não precisar carregar tudo na memória de uma vez
        # o iter continua lendo até o arquivo retornar b"", que indica que chegou ao final
        for chunk in iter(lambda: file.read(4096), b""):

            # adiciono cada bloco ao cálculo do hash, permitindo processar o arquivo aos poucos
            sha256.update(chunk)

    # mostro os resultados da análise no terminal
    print("\n+++++ atLalyZer +++++")
    print(f"Arquivo: {path.name}")
    print(f"Tamanho: {file_size} bytes")
    print(f"SHA256: {sha256.hexdigest()}")

# esse bloco garante que a entrada do usuário só seja executada quando eu rodar esse arquivo diretamente
if __name__ == "__main__":

    # peço o caminho do arquivo e removo espaços extras no início e no final da entrada
    file_path = input("caminho do arquivo para analisar: ").strip()

    # chamo a função que realiza a análise do arquivo informado
    analyze_file(file_path)
```
