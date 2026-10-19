
import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from PIL import Image

from main import (
    analyze_batch,
    analyze_file,
    detect_anomalies,
    detect_file_type,
    extract_iocs,
    extract_image_metadata,
    get_analysis_history,
    save_report,
    store_report,
)

class TestAtlalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        self.test_content = b"%PDF-1.4\nAtlalyzer Test File\n"
        self.test_file = self.test_dir / "documento.pdf"
        self.test_file.write_bytes(self.test_content)
        self.db_path = self.test_dir / "atlalyzer.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detect_pdf(self):
        detected_type, extensions = detect_file_type(self.test_file)
        self.assertEqual(detected_type, "PDF")
        self.assertIn(".pdf", extensions)

    def test_detect_docx(self):
        file_path = self.test_dir / "documento.docx"

        with zipfile.ZipFile(file_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", "<document/>")

        detected_type, extensions = detect_file_type(file_path)
        self.assertEqual(detected_type, "DOCX")
        self.assertIn(".docx", extensions)

    def test_detect_pptx(self):
        file_path = self.test_dir / "apresentacao.pptx"

        with zipfile.ZipFile(file_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("ppt/presentation.xml", "<presentation/>")

        detected_type, extensions = detect_file_type(file_path)
        self.assertEqual(detected_type, "PPTX")
        self.assertIn(".pptx", extensions)

    def test_detect_xlsx(self):
        file_path = self.test_dir / "planilha.xlsx"

        with zipfile.ZipFile(file_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("xl/workbook.xml", "<workbook/>")

        detected_type, extensions = detect_file_type(file_path)
        self.assertEqual(detected_type, "XLSX")
        self.assertIn(".xlsx", extensions)

    def test_detect_unknown_format(self):
        unknown_file = self.test_dir / "arquivo.xyz"
        unknown_file.write_text(
            "Conteúdo sem assinatura conhecida",
            encoding="utf-8",
        )

        detected_type, extensions = detect_file_type(unknown_file)
        self.assertEqual(detected_type, "Formato desconhecido")
        self.assertEqual(extensions, set())

    def test_detect_invalid_zip(self):
        invalid_file = self.test_dir / "arquivo.zip"
        invalid_file.write_bytes(
            b"PK\x03\x04isso nao e um zip valido"
        )

        detected_type, extensions = detect_file_type(invalid_file)
        self.assertEqual(
            detected_type,
            "ZIP inválido ou corrompido",
        )
        self.assertEqual(extensions, set())

    def test_detect_valid_zip(self):
        zip_file = self.test_dir / "arquivo.zip"

        with zipfile.ZipFile(zip_file, "w") as archive:
            archive.writestr("exemplo.txt", "arquivo de teste")

        detected_type, extensions = detect_file_type(zip_file)
        self.assertEqual(detected_type, "ZIP")
        self.assertIn(".zip", extensions)

    def test_analyze_file_hash(self):
        expected_hash = hashlib.sha256(self.test_content).hexdigest()
        report = analyze_file(self.test_file)

        self.assertIsNotNone(report)
        self.assertEqual(report["sha256"], expected_hash)
        self.assertEqual(report["analysis_status"], "completed")

    def test_analyze_file_size(self):
        report = analyze_file(self.test_file)
        self.assertEqual(
            report["file_size_bytes"],
            len(self.test_content),
        )

    def test_extension_mismatch(self):
        renamed_file = self.test_dir / "documento.png"
        renamed_file.write_bytes(self.test_content)

        report = analyze_file(renamed_file)

        self.assertEqual(report["detected_type"], "PDF")
        self.assertFalse(report["extension_matches"])
        self.assertEqual(report["extension_status"], "incompatível")

    def test_missing_file(self):
        missing_file = self.test_dir / "nao_existe.pdf"
        self.assertIsNone(analyze_file(missing_file))

    def test_directory_is_not_a_file(self):
        self.assertIsNone(analyze_file(self.test_dir))

    def test_save_and_read_json_report(self):
        report = analyze_file(self.test_file)
        report_path = save_report(report, self.test_dir)

        with report_path.open("r", encoding="utf-8") as file:
            saved_report = json.load(file)

        self.assertTrue(report_path.exists())
        self.assertEqual(saved_report["file_name"], "documento.pdf")
        self.assertEqual(saved_report["sha256"], report["sha256"])
        self.assertEqual(saved_report["detected_type"], "PDF")

    def test_file_metadata(self):
        report = analyze_file(self.test_file)

        self.assertIn("file_created_at", report)
        self.assertIn("file_modified_at", report)
        self.assertTrue(report["file_created_at"])
        self.assertTrue(report["file_modified_at"])

    def test_extract_image_metadata(self):
        image_path = self.test_dir / "imagem_teste.png"
        Image.new("RGB", (100, 50), color="red").save(image_path)

        metadata = extract_image_metadata(image_path)

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["image_format"], "PNG")
        self.assertEqual(metadata["image_width"], 100)
        self.assertEqual(metadata["image_height"], 50)
        self.assertIsInstance(metadata["exif"], dict)

    def test_image_validation(self):
        image_path = self.test_dir / "imagem_valida.png"
        Image.new("RGB", (100, 100), color="red").save(image_path)

        metadata = extract_image_metadata(image_path)

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["image_validation"], "valid")

    def test_image_metadata_in_report(self):
        image_path = self.test_dir / "imagem_relatorio.png"
        Image.new("RGB", (320, 240), color="blue").save(image_path)

        report = analyze_file(image_path)

        self.assertIsNotNone(report)
        self.assertEqual(report["image_metadata"]["image_format"], "PNG")
        self.assertEqual(report["image_metadata"]["image_width"], 320)
        self.assertEqual(report["image_metadata"]["image_height"], 240)

    def test_image_metadata_saved_to_json(self):
        image_path = self.test_dir / "imagem_json.png"
        Image.new("RGB", (640, 480), color="green").save(image_path)

        report = analyze_file(image_path)
        report_path = save_report(report, self.test_dir)

        with report_path.open("r", encoding="utf-8") as file:
            saved_report = json.load(file)

        metadata = saved_report["image_metadata"]
        self.assertEqual(metadata["image_format"], "PNG")
        self.assertEqual(metadata["image_width"], 640)
        self.assertEqual(metadata["image_height"], 480)
        self.assertIsInstance(metadata["exif"], dict)

    def test_image_extension_mismatch(self):
        image_path = self.test_dir / "imagem_falsa.jpg"
        Image.new("RGB", (100, 100), color="red").save(
            image_path,
            format="PNG",
        )

        report = analyze_file(image_path)

        self.assertIsNotNone(report)
        self.assertEqual(report["detected_type"], "PNG")
        self.assertEqual(report["extension"], ".jpg")
        self.assertFalse(report["extension_matches"])
        self.assertEqual(report["extension_status"], "incompatível")

    def test_detect_anomalies(self):
        suspicious_file = self.test_dir / "documento.exe"
        suspicious_file.write_bytes(self.test_content)

        report = analyze_file(suspicious_file)

        self.assertIn("anomalies", report)
        self.assertIn("risk_score", report)
        self.assertIn("risk_level", report)
        self.assertTrue(
            any(
                item["code"] == "extension_mismatch"
                for item in report["anomalies"]
            )
        )

    def test_double_extension_anomaly(self):
        suspicious_file = self.test_dir / "fatura.pdf.exe"
        suspicious_file.write_bytes(b"MZ" + b"\x00" * 20)

        report = analyze_file(suspicious_file)

        self.assertTrue(
            any(
                item["code"] == "double_extension"
                for item in report["anomalies"]
            )
        )

    def test_store_report_and_history(self):
        report = analyze_file(self.test_file)
        record_id = store_report(report, self.db_path)

        history = get_analysis_history(self.db_path)

        self.assertGreater(record_id, 0)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["file_name"], "documento.pdf")
        self.assertEqual(history[0]["sha256"], report["sha256"])

    def test_database_preserves_multiple_analyses(self):
        first_report = analyze_file(self.test_file)
        store_report(first_report, self.db_path)

        second_file = self.test_dir / "outro.pdf"
        second_file.write_bytes(b"%PDF-1.4\nOutro arquivo\n")
        second_report = analyze_file(second_file)
        store_report(second_report, self.db_path)

        history = get_analysis_history(self.db_path)

        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["file_name"], "outro.pdf")
        self.assertEqual(history[1]["file_name"], "documento.pdf")

    def test_analyze_batch(self):
        input_dir = self.test_dir / "entrada"
        input_dir.mkdir()
        (input_dir / "um.pdf").write_bytes(b"%PDF-1.4\nArquivo um")
        (input_dir / "dois.txt").write_text(
            "arquivo de teste",
            encoding="utf-8",
        )

        output_dir = self.test_dir / "relatorios"
        results = analyze_batch(
            input_dir,
            output_dir=output_dir,
            db_path=self.db_path,
        )

        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(Path(item["report_path"]).exists() for item in results)
        )
        self.assertEqual(len(get_analysis_history(self.db_path)), 2)

    def test_analyze_batch_recursive(self):
        input_dir = self.test_dir / "entrada"
        sub_dir = input_dir / "subpasta"
        sub_dir.mkdir(parents=True)

        (input_dir / "um.pdf").write_bytes(b"%PDF-1.4\nUm")
        (sub_dir / "dois.pdf").write_bytes(b"%PDF-1.4\nDois")

        results = analyze_batch(
            input_dir,
            output_dir=self.test_dir / "relatorios",
            db_path=self.db_path,
            recursive=True,
        )

        self.assertEqual(len(results), 2)

    def test_analyze_batch_rejects_missing_directory(self):
        missing_dir = self.test_dir / "nao_existe"

        with self.assertRaises(NotADirectoryError):
            analyze_batch(missing_dir, db_path=self.db_path)

    def test_database_limit_validation(self):
        with self.assertRaises(ValueError):
            get_analysis_history(self.db_path, limit=0)

    def test_extract_iocs_from_file(self):
        file_path = self.test_dir / "indicadores.txt"
        file_path.write_text("Acesse https://murred.com/path e verifique o IP 7.7.7.7", encoding="utf-8",)
        result = extract_iocs(file_path)
        self.assertEqual(result["ipv4_addresses"], ["7.7.7.7"],)

    def test_extract_iocs_ignores_ivalid_ip(self):
        file_path= self.test_dir / "ip_invalido.txt"
        file_path.write_text("IP inválido: 777.777.777.777", encoding="utf-8",)
        result = extract_iocs(file_path)
        self.assertEqual(result["ipv4_addresses"], [])

    def test_extract_iocs_ignores_duplicates(self):
        file_path = self.test_dir / "duplicados.txt"
        file_path.write_text("https://murred.com https://murred.com 7.7.7.7 7.7.7.7", encoding="utf-8",)
        result = extract_iocs(file_path)
        self.assertEqual(result["urls"], ["https://murred.com"],)
        self.assertEqual(result["ipv4_addresses"], ["7.7.7.7"],)

if __name__ == "__main__":
    unittest.main()