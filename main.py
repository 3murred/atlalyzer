from pathlib import Path
import hashlib

def analyze_file(file_path): 
    path = Path(file_path) 
    if not path.exists(): 
        print("Arquivo não existe") 
        return
    if not path.is_file(): 
        print("Não é um arquivo") 
        return
    try:
        file_size = path.stat().st_size
    
        sha256 = hashlib.sha256() 
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        print("\n+++++ ATLALYZER +++++")
        print(f"Arquivo: {path.name}")
        print(f"Tamanho: {file_size}b")
        print(f"SHA256: {sha256.hexdigest()}")

    except PermissionError:
        print("Sem permissão para acessar o arquivo")
    except OSError as error:
        print(f"Erro ao acessar o arquivo {error}")

if __name__ == "__main__":
    file_path = input("Caminho do arquivo para analisar: " ).strip()
    analyze_file(file_path)