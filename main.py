from pathlib import Path
import hashlib
import json
from datetime import datetime, timezone

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
        return None
    
    if not path.is_file(): 
        print("Não é um arquivo") 
        return None
    
    try:
        file_size = path.stat().st_size
        detected_type, expected_extensions = detect_file_type(path)
        extension = path.suffix.lower()
        sha256 = hashlib.sha256() 
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        if expected_extensions:
            extension_matches = extension in expected_extensions
            extension_status = ("compatível" if extension_matches else "incompatível")
        else:
            extension_matches = None
            extension_status = "Não é possível validar"

        report = {"file_name": path.name,
                  "file_size_bytes": file_size,
                  "sha256": sha256.hexdigest(),
                  "detected_type": detected_type,
                  "extension": extension,
                  "extension_status": extension_status,
                  "extension_matches": extension_matches,
                  "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                  "analysis_status": "completed",}
        return report

    except PermissionError:
        print("Sem permissão para acessar o arquivo")
    except OSError as error:
        print(f"Erro ao acessar o arquivo {error}")
    return None

def save_report(report, output_dir = None):
    destination = Path(output_dir) if output_dir else Path.cwd()
    report_name = Path(report["file_name"]).with_suffix(".json").name
    report_path = destination / report_name
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)
    return report_path

if __name__ == "__main__":
    file_path = input("Caminho do arquivo para analisar: " ).strip()
    report = analyze_file(file_path)

    if report is not None:
        try:
            report_path = save_report(report)

            print("\n+++++ ATLALYZER +++++")
            print(f"Arquivo: {report['file_name']}")
            print(f"Tamanho: {report['file_size_bytes']}b")
            print(f"SHA256: {report['sha256']}")
            print(f"Tipo: {report['detected_type']}")
            print(f"Extensão: {report['extension_status']}")
            print(f"Relatório salvo em: {report_path}")

        except OSError as error:
            print(f"Erro para salvar o relatório: {error}")
        