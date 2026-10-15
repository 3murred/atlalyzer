from pathlib import Path
import hashlib
import json
from datetime import datetime, timezone
import zipfile
from PIL import Image, UnidentifiedImageError

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

    if header.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(file_path, "r") as archive:
                corrupted_file = archive.testzip()
                if corrupted_file is not None:
                    return "ZIP corrompido", set()
                names = set(archive.namelist())
            if ("word/document.xml" in names):
                return "DOCX", {".docx"}
            if ("xl/workbook.xml" in names):
                return "XLSX", {".xlsx"}
            if ("ppt/presentation.xml" in names):
                return "PPTX", {".pptx"}
            if "META-INF/MANIFEST.MF" in names:
                return "JAR", {".jar"}
            return "ZIP", {".zip"}
        except zipfile.BadZipFile:
            return("ZIP inválido ou corrompido", set())

    for signature, file_info in FILE_SIGNATURES.items():
        if signature == b"PK\x03\x04":
            continue
        if header.startswith(signature):
            return file_info
        
    return "Formato desconhecido", set()

def extract_image_metadata(file_path):
    metadata = {"image_format": None, "image_width": None, "image_height": None, "exif": {},}
    try:
        with Image.open(file_path) as image:
            metadata["image_format"] = image.format
            metadata["image_width"] = image.width
            metadata["image_height"] = image.height
            exif_data = image.getexif()
            for tag_id, value in exif_data.items():
                tag_name = str(tag_id)
                try:
                    from PIL.ExifTags import TAGS
                    tag_name = TAGS.get(tag_id, str(tag_id))
                except (ImportError, AttributeError):
                    pass
                if isinstance(value, bytes):
                    value = value.hex()
                if isinstance(value, (str, int, float, bool)) or value is None:
                    metadata["exif"][tag_name] = value
                else:
                    metadata["exif"][tag_name] = str(value)
    except (UnidentifiedImageError, OSError, ValueError):
        return None
    return metadata

def analyze_file(file_path): 
    path = Path(file_path) 

    if not path.exists(): 
        print("Arquivo não existe") 
        return None
    
    if not path.is_file(): 
        print("Não é um arquivo") 
        return None
    
    try:
        file_stat = path.stat()
        file_size = file_stat.st_size
        created_at = datetime.fromtimestamp(file_stat.st_ctime, tz=timezone.utc).isoformat()
        modified_at = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat()
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
                  "file_created_at": created_at,
                  "file_modified_at": modified_at,
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
        