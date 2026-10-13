from pathlib import Path
import hashlib

FILE_SIGNATURES = {b"\x89PNG\r\n\x1a\n": ("PNG", {".png"}), 
    b"\xff\xd8\xff": ("JPEG", {".jpg", ".jpeg"}), 
    b"GIF87a": ("GIF", {".gif"}), 
    b"GIF89a": ("GIF", {".gif"}), 
    b"%PDF-": ("PDF", {".pdf"}), 
    b"PK\x03\x04": ("ZIP ou baseado em ZIP", {".zip", ".docx", ".xlsx", ".pptx", ".jar"}), 
    b"MZ": ("Executável Windows (PE)", {".exe", ".dll"}),}

def detect_file_type(file_path):
    with file_path.open("rb") as file:
        header = file.read(16)
    for signature, file_info in FILE_SIGNATURES.items():
        if header.startswith(signature):
            return file_info
    return "Formato desconhecido", set()

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
        detected_type, expected_extensions = detect_file_type(path)
        extension = path.suffix.lower()
        sha256 = hashlib.sha256() 
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        print("\n+++++ ATLALYZER +++++")
        print(f"Arquivo: {path.name}")
        print(f"Tamanho: {file_size}b")
        print(f"SHA256: {sha256.hexdigest()}")
        print(f"Tipo: {detected_type}")

        if expected_extensions:
            if extension in expected_extensions:
                print("Extensão é compatível com o tipo detectado")
            else:
                print("Extensao não é compatível com o tipo detectado")
        else:
            print("Não foi possível validar a extensão do arquivo")

    except PermissionError:
        print("Sem permissão para acessar o arquivo")
    except OSError as error:
        print(f"Erro ao acessar o arquivo {error}")

if __name__ == "__main__":
    file_path = input("Caminho do arquivo para analisar: " ).strip()
    analyze_file(file_path)