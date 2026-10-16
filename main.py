
from pathlib import Path
import hashlib
import json
import sqlite3
import zipfile
from datetime import datetime, timezone
import argparse
import logging
import sys

from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import TAGS

FILE_SIGNATURES = {b"\x89PNG\r\n\x1a\n": ("PNG", {".png"}),
    b"\xff\xd8\xff": ("JPEG", {".jpg", ".jpeg"}),
    b"GIF87a": ("GIF", {".gif"}),
    b"GIF89a": ("GIF", {".gif"}),
    b"%PDF-": ("PDF", {".pdf"}),
    b"PK\x03\x04": ("ZIP ou baseado em ZIP",{".zip", ".docx", ".xlsx", ".pptx", ".jar"},),
    b"MZ": ("Executável Windows (PE)", {".exe", ".dll"}),}

IMAGE_EXTENSIONS = {"PNG": {".png"},"JPEG": {".jpg", ".jpeg"},"GIF": {".gif"},}

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".ps1", ".vbs", ".js", ".msi",}

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx",".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png",}

MAX_LARGE_FILE_BYTES = 100 * 1024 * 1024


def detect_file_type(file_path):
    path = Path(file_path)

    with path.open("rb") as file:
        header = file.read(16)

    if header.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(path, "r") as archive:
                corrupted_file = archive.testzip()

                if corrupted_file is not None:
                    return "ZIP corrompido", set()

                names = set(archive.namelist())

            if "word/document.xml" in names:
                return "DOCX", {".docx"}

            if "xl/workbook.xml" in names:
                return "XLSX", {".xlsx"}

            if "ppt/presentation.xml" in names:
                return "PPTX", {".pptx"}

            if "META-INF/MANIFEST.MF" in names:
                return "JAR", {".jar"}

            return "ZIP", {".zip"}

        except zipfile.BadZipFile:
            return "ZIP inválido ou corrompido", set()

    for signature, file_info in FILE_SIGNATURES.items():
        if signature == b"PK\x03\x04":
            continue

        if header.startswith(signature):
            return file_info

    return "Formato desconhecido", set()

def analyze_archive_structure(file_path):
    """Analisa a estrutura interna de arquivos .zip sem a necessidade de extraí-los"""
    path = Path(file_path)
    if not zipfile.is_zipfile(path):
        return None

    suspicios_extensions = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi",}
    max_entries = 10_000
    max_reported_items = 100
    max_compression_ratio = 100

    findings = []
    total_uncompressed_size = 0
    total_compressed_size = 0
    encrypted_count = 0
    suspicious_files = []
    path_traversal_entries = []
    entry_count = 0

    try:
        with zipfile.ZipFile(path, "r") as archive:
            for entry in archive.infolist():
                entry_count += 1
                if entry_count > max_entries:
                    findings.append(f"O arquivo compactado excede o limite de {max_entries} entradas")
                    break
                normalized_name = entry.filename.replace("\\", "/")
                parts = normalized_name.split("/")
                if (normalized_name.startswith("/") or any(part == ".." for part in parts) or (len(normalized_name) >= 2 and normalized_name[1] == ":")):
                    if len(path_traversal_entries) < max_reported_items:
                        path_traversal_entries.append(entry.filename)
                suffix = Path(normalized_name).suffix.lower()
                if (not entry.is_dir() and suffix in suspicios_extensions and len(suspicious_files) < max_reported_items):
                    suspicious_files.append(entry.filename)
                if entry.flag_bits & 0x1:
                    encrypted_count += 1
                total_uncompressed_size += entry.file_size
                total_compressed_size += entry.compress_size
            compression_ratio = (total_uncompressed_size / max(total_compressed_size, 1))
            if compression_ratio > max_compression_ratio:
                findings.append("Taxa de compressão muito elevada; possível arquivo compactado anormalmente")
            if encrypted_count: 
                findings.append(f"{encrypted_count} entrada(s) criptografada(s)")
            if suspicious_files:
                findings.append("Arquivos com extensões potencialmente executáveis ou interpretáveis foram encontrados")
            if path_traversal_entries:
                findings.append("Entradas com caminhos potencialmente inseguros foram encontradas")
            return { "entry_count": entry_count, "total_uncompressed_size": total_uncompressed_size, "total_compressed_size": total_compressed_size, "compression_ratio": round(compression_ratio, 2), "encrypted_entries": encrypted_count, "suspicious_files": suspicious_files, "unsafe_paths": path_traversal_entries, "findings": findings,}
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        return {"Error": f"Não foi possível analisar a estrutura: {error}", "Findings": ["estrutura do arquivo compactado ainda não foi validada"],}

def extract_image_metadata(file_path):
    metadata = {
        "image_format": None,
        "image_width": None,
        "image_height": None,
        "image_validation": "invalid",
        "exif": {},
    }

    try:
        with Image.open(file_path) as image:
            metadata["image_format"] = image.format
            metadata["image_width"] = image.width
            metadata["image_height"] = image.height

            for tag_id, value in image.getexif().items():
                tag_name = TAGS.get(tag_id, str(tag_id))

                if isinstance(value, bytes):
                    value = value.hex()
                elif (
                    not isinstance(value, (str, int, float, bool))
                    and value is not None
                ):
                    value = str(value)

                metadata["exif"][tag_name] = value

        # verify() deve ser executado em uma abertura nova.
        with Image.open(file_path) as image:
            image.verify()

        metadata["image_validation"] = "valid"

    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
        SyntaxError,
    ):
        return None

    return metadata


def detect_anomalies(report):
    anomalies = []
    file_name = report["file_name"]
    path = Path(file_name)
    extension = report["extension"]
    detected_type = report["detected_type"]
    file_size = report["file_size_bytes"]

    def add_anomaly(code, severity, points, description):
        anomalies.append({
            "code": code,
            "severity": severity,
            "points": points,
            "description": description,
        })

    if file_size == 0:
        add_anomaly(
            "empty_file",
            "low",
            10,
            "O arquivo está vazio.",
        )

    if detected_type == "Formato desconhecido":
        add_anomaly(
            "unknown_format",
            "low",
            10,
            "O formato não corresponde às assinaturas conhecidas.",
        )

    if report["extension_matches"] is False:
        add_anomaly(
            "extension_mismatch",
            "medium",
            25,
            "A extensão não corresponde ao formato detectado.",
        )

    if detected_type in {
        "ZIP corrompido",
        "ZIP inválido ou corrompido",
    }:
        add_anomaly(
            "invalid_archive",
            "high",
            35,
            "O arquivo aparenta ser um ZIP inválido ou corrompido.",
        )

    if detected_type == "Executável Windows (PE)":
        add_anomaly(
            "windows_executable",
            "medium",
            20,
            "O conteúdo possui assinatura de executável Windows.",
        )

    suffixes = [suffix.lower() for suffix in path.suffixes]

    if (
        len(suffixes) >= 2
        and suffixes[-1] in EXECUTABLE_EXTENSIONS
        and suffixes[-2] in DOCUMENT_EXTENSIONS
    ):
        add_anomaly(
            "double_extension",
            "high",
            30,
            "O nome combina uma extensão de documento "
            "com uma extensão executável.",
        )

    if file_size > MAX_LARGE_FILE_BYTES:
        add_anomaly(
            "large_file",
            "low",
            5,
            "O arquivo excede 100 MiB.",
        )

    if (
        detected_type in {"PNG", "JPEG", "GIF"}
        and report["image_metadata"] is None
    ):
        add_anomaly(
            "image_validation_failed",
            "medium",
            20,
            "O conteúdo parece ser uma imagem, mas não foi "
            "possível extrair e validar seus metadados.",
        )

    risk_score = min(
        100,
        sum(item["points"] for item in anomalies),
    )

    if risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    archive_analysis = report.get("archive_analysis")
    if archive_analysis:
        if archive_analysis.get("error"):
            anomalies.append("Não foi possível validar a estrutura do arquivo compactado")
        if archive_analysis.get("unsafe_paths"):
            anomalies.append("Arquivo compactado contém caminhos que são potencialmente inseguros")
        if archive_analysis.get("suspicious_files"):
            anomalies.append("Arquivo compactado contém caminhos que são potencialmente executáveis")
        if archive_analysis.get("suspicious_files", 0) > 0:
            anomalies.append("Arquivo compactado contém entradas criptografadas")
        if archive_analysis.get("compression_ratio", 0) > 100:
            anomalies.append("Arquivo compactado apresenta taxa de compressão muito elevada")


    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "anomalies": anomalies,
    }


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

        created_at = datetime.fromtimestamp(
            file_stat.st_ctime,
            tz=timezone.utc,
        ).isoformat()

        modified_at = datetime.fromtimestamp(
            file_stat.st_mtime,
            tz=timezone.utc,
        ).isoformat()

        detected_type, expected_extensions = detect_file_type(path)
        archive_analysis = analyze_archive_structure(file_path)
        
        extension = path.suffix.lower()
        image_metadata = extract_image_metadata(path)

        if image_metadata is not None:
            actual_format = image_metadata["image_format"]
            expected_extensions = IMAGE_EXTENSIONS.get(
                actual_format, set()
            )

        sha256 = hashlib.sha256()

        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        if expected_extensions:
            extension_matches = extension in expected_extensions
            extension_status = (
                "compatível"
                if extension_matches
                else "incompatível"
            )
        else:
            extension_matches = None
            extension_status = "Não é possível validar"

        report = {
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": file_size,
            "sha256": sha256.hexdigest(),
            "detected_type": detected_type,
            "archive_analysis": archive_analysis,
            "extension": extension,
            "extension_status": extension_status,
            "extension_matches": extension_matches,
            "file_created_at": created_at,
            "file_modified_at": modified_at,
            "image_metadata": image_metadata,
            "analysis_timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "analysis_status": "completed",
        }

        report.update(detect_anomalies(report))
        return report

    except PermissionError:
        print("Sem permissão para acessar o arquivo")

    except OSError as error:
        print(f"Erro ao acessar o arquivo: {error}")

    return None


def save_report(report, output_dir=None, filename=None):
    destination = (
        Path(output_dir)
        if output_dir is not None
        else Path.cwd()
    )

    destination.mkdir(parents=True, exist_ok=True)

    report_name = (
        Path(filename).name
        if filename
        else Path(report["file_name"]).with_suffix(".json").name
    )

    report_path = destination / report_name

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return report_path



def init_database(db_path):
    database_path = Path(db_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path)

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                detected_type TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                analysis_timestamp TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        connection.commit()
    finally:
        connection.close()


def store_report(report, db_path):
    init_database(db_path)

    connection = sqlite3.connect(db_path)

    try:
        cursor = connection.execute("""
            INSERT INTO analyses (
                file_name,
                file_path,
                sha256,
                detected_type,
                file_size_bytes,
                risk_score,
                risk_level,
                analysis_timestamp,
                report_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report["file_name"],
            report["file_path"],
            report["sha256"],
            report["detected_type"],
            report["file_size_bytes"],
            report["risk_score"],
            report["risk_level"],
            report["analysis_timestamp"],
            json.dumps(report, ensure_ascii=False),
        ))

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()



def get_analysis_history(db_path, limit=20):
    if limit < 1:
        raise ValueError("O limite precisa ser maior que zero.")

    init_database(db_path)

    connection = sqlite3.connect(db_path)

    try:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT
                id,
                file_name,
                file_path,
                sha256,
                detected_type,
                file_size_bytes,
                risk_score,
                risk_level,
                analysis_timestamp
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()

def analyze_batch(
    input_dir,
    output_dir=None,
    db_path=None,
    recursive=False,
):
    source = Path(input_dir).resolve()

    if not source.exists() or not source.is_dir():
        raise NotADirectoryError(
            f"A pasta de entrada não existe: {source}"
        )

    destination = (
        Path(output_dir).resolve()
        if output_dir is not None
        else (Path.cwd() / "atlalyzer_reports").resolve()
    )

    if destination == source:
        raise ValueError("A pasta de relatórios não pode ser a própria pasta de entrada.")

    destination.mkdir(parents=True, exist_ok=True)

    database_path = (
        Path(db_path).resolve()
        if db_path is not None
        else (destination / "atlalyzer.db").resolve()
    )

    init_database(database_path)

    candidates = (
        source.rglob("*")
        if recursive
        else source.iterdir()
    )

    results = []

    for path in sorted(candidates):
        if not path.is_file():
            continue

        resolved_path = path.resolve()

        if destination in resolved_path.parents:
            continue

        if resolved_path == database_path:
            continue

        report = analyze_file(resolved_path)

        if report is None:
            continue

        report_filename = (
            f"{resolved_path.stem}_"
            f"{report['sha256'][:8]}.json"
        )

        report_path = save_report(
            report,
            destination,
            report_filename,
        )

        database_id = store_report(report, database_path)

        results.append({
            "file_name": report["file_name"],
            "report_path": str(report_path),
            "database_id": database_id,
            "risk_score": report["risk_score"],
            "risk_level": report["risk_level"],
        })

    return results


def print_report(report, report_path=None, database_id=None):
    print("\n+++++ ATLALYZER v10 +++++")
    print(f"Arquivo: {report['file_name']}")
    print(f"Tamanho: {report['file_size_bytes']} bytes")
    print(f"SHA-256: {report['sha256']}")
    print(f"Tipo: {report['detected_type']}")
    print(f"Extensão: {report['extension_status']}")
    print(f"Risco: {report['risk_level']} ({report['risk_score']}/100)")

    if report["image_metadata"] is not None:
        metadata = report["image_metadata"]
        print(f"Formato da imagem: {metadata['image_format']}")
        print(
            f"Dimensões: {metadata['image_width']} x "
            f"{metadata['image_height']}"
        )
        print(f"Validação da imagem: {metadata['image_validation']}")
        print(f"Quantidade de tags EXIF: {len(metadata['exif'])}")

    if report["anomalies"]:
        print("\nAnomalias identificadas:")

        for anomaly in report["anomalies"]:
            print(
                f"- [{anomaly['severity']}] "
                f"{anomaly['code']}: {anomaly['description']}"
            )
    else:
        print("Nenhuma anomalia identificada pelas regras atuais.")

    if report_path is not None:
        print(f"\nRelatório JSON: {report_path}")

    if database_id is not None:
        print(f"Registro no SQLite: {database_id}")

# def main():
def run_interactive():
    database_path = Path.cwd() / "atlalyzer.db"

    print("\n+++++ ATLALYZER v10 +++++")
    print("1. Analisar um arquivo")
    print("2. Analisar uma pasta")
    print("3. Consultar histórico")
    choice = input("Escolha uma opção: ").strip()

    if choice == "1":
        file_path = input("Caminho do arquivo: ").strip()
        report = analyze_file(file_path)

        if report is None:
            return

        try:
            report_path = save_report(report)
            database_id = store_report(report, database_path)
            print_report(report, report_path, database_id)

        except OSError as error:
            print(f"Erro de arquivo: {error}")
        except sqlite3.Error as error:
            print(f"Erro no banco de dados: {error}")

    elif choice == "2":
        input_dir = input("Caminho da pasta: ").strip()
        recursive_answer = input(
            "Incluir subpastas? (s/n): "
        ).strip().lower()

        try:
            results = analyze_batch(
                input_dir,
                recursive=recursive_answer == "s",
                db_path=database_path,
            )

            print(f"\nArquivos analisados: {len(results)}")

            for result in results:
                print(
                    f"- {result['file_name']}: "
                    f"risco {result['risk_level']} "
                    f"({result['risk_score']}/100)"
                )
                print(f"  Relatório: {result['report_path']}")

        except (OSError, ValueError, sqlite3.Error) as error:
            print(f"Erro na análise em lote: {error}")

    elif choice == "3":
        try:
            limit_input = input(
                "Quantos registros mostrar? (padrão 20): "
            ).strip()
            limit = int(limit_input) if limit_input else 20

            for item in get_analysis_history(database_path, limit):
                print(
                    f"#{item['id']} | {item['file_name']} | "
                    f"{item['detected_type']} | "
                    f"risco {item['risk_level']} "
                    f"({item['risk_score']}/100) | "
                    f"{item['analysis_timestamp']}"
                )

        except (ValueError, sqlite3.Error) as error:
            print(f"Erro ao consultar histórico: {error}")

    else:
        print("Opção inválida.")

def main(argv=None):
    parser = argparse.ArgumentParser(prog="atlalyzer", description="Analisador de arquivos e detector de anomalias",)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--file", metavar="CAMINHO", help="Analisa um arquivo individual",)
    actions.add_argument("--dir", metavar="PASTA", help="Analisa os arquivos de uma pasta",)
    actions.add_argument("--history", nargs="?", const = 20, type= int, metavar = "Limite", help="Consultar o histórico; padrão: 20 registros por vez",)
    parser.add_argument("--recursive", action="store_true", help="Inclui as subpastas na análise em lote",)
    actions.add_argument("--output", metavar="PASTA", help="Define a pasta de saída dos relatórios",)
    actions.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Define o nível de logging",)
    parser.add_argument("--db", metavar="CAMINHO", help="Define o caminho do banco SQLite")
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s | %(levelname)s | %(message)s", handlers=[logging.StreamHandler(), logging.FileHandler("atlalyzer.log", encoding="utf-8",),], force=True)
    logger = logging.getLogger("atlalyzer")
    if args.recursive and not args.dir:
        parser.error("O --recursive exige o uso de --dir")
    database_path = (Path(args.db).resolve() if args.db else Path.cwd() / "atlalyzer.db")
    try:
        if args.file:
            report = analyze_file(args.file)
            if report is None:
                logger.error("A análise do arquivo não foi concluída. Tente novamente")
                return 1
            report_path = save_report(report, output_dir=args.output,)
            database_id = store_report(report, database_path,)
            print_report(report, report_path, database_id,)
            logger.info("Análise individual foi concluída")
            return 0
        if args.dir:
            results = analyze_batch(args.dir, output_dir=args.output, db_path=database_path, recursive=args.recursive,)
            print(f"\nArquivos analisados: {len(results)}")
            for result in results:
                print(f"- {result['file_name']} | "f"Risco: {result['risk_level']} "f"({result['risk_score']}/100)")
                print(f" Relatório: {result['report_path']}")
            logger.info("Análise em lote concluída: %d arquivos", len(results),)
            return 0
        if args.history is not None:
            history = get_analysis_history(database_path, args.history,)
            if not history:
                print("Nenhuma análise foi encontrada")
                return 0
            for item in history:
                print(f"#{item['id']} | {item['file_name']} | "f"{item['detected_type']} | "f"risco: {item['risk_level']} "f"({item['risk_score']}/100) | "f"{item['analysis_timestamp']}")
                return 0
            run_interactive()
            return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        logger.exception("A operação não foi concluída: %s", error)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())