import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import zipfile
from PIL import Image

from main import extract_image_metadata
from main import analyze_file, detect_file_type, save_report

class TestAtlalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        self.test_content = b"%PDF-1.4\nAtlalyzer Test File\n"
        self.test_file = self.test_dir / "documento.pdf"
        self.test_file.write_bytes(self.test_content)
        # return super().setUp()

    def test_extract_image_metadata(self):
        image_path = self.test_dir / "imagem_test.png"
        image = Image.new("RGB", (100, 50), color = "red")
        image.save(image_path)
        metadata = extract_image_metadata(image_path)
        self.assertIsNotNone(metadata) 
        self.assertEqual(metadata["image_format"], "PNG")
        self.assertEqual(metadata["image_width"], 100)
        self.assertEqual(metadata["image_height"], 50)
        self.assertIsInstance(metadata["exif"], dict)

    def tearDown(self):
        # return super().tearDown()
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
        unknown_file.write_bytes("Conteúdo não possui uma assinatura conhecida".encode("utf-8"))
        detected_type, extensions = detect_file_type(unknown_file)
        self.assertEqual(detected_type, "Formato desconhecido")
        self.assertEqual(extensions, set())

    def test_analyze_file_hash(self):
        expected_hash = hashlib.sha256(self.test_content).hexdigest()
        report = analyze_file(self.test_file)
        self.assertIsNotNone(report)
        self.assertEqual(report["sha256"], expected_hash)
        self.assertEqual(report["analysis_status"], "completed")
    
    def test_analyze_file_size(self):
        report = analyze_file(self.test_file)
        self.assertEqual(report["file_size_bytes"], len(self.test_content),)
    
    def test_extension_mismatch(self):
        renamed_file = self.test_dir / "documento.png"
        renamed_file.write_bytes(self.test_content)
        report = analyze_file(renamed_file)
        self.assertEqual(report["detected_type"], "PDF")
        self.assertFalse(report["extension_matches"])
        self.assertEqual(report["extension_status"], "incompatível")
    
    def test_missing_file(self):
        missing_file = self.test_dir / "não_existe.pdf"
        report = analyze_file(missing_file)
        self.assertIsNone(report)
    
    def test_directory_is_not_a_file(self):
        report = analyze_file(self.test_dir)
        self.assertIsNone(report)
    
    def test_save_and_read_json_report(self):
        report = analyze_file(self.test_file)
        report_path = save_report(report, self.test_dir)
        with report_path.open("r", encoding="utf-8") as file:
            saved_report = json.load(file)
        self.assertTrue(report_path.exists())
        self.assertEqual(saved_report["file_name"], "documento.pdf")
        self.assertEqual(saved_report["sha256"], report["sha256"])
        self.assertEqual(saved_report["detected_type"], "PDF")

    def test_detect_invalid_zip(self):
        invalid_file = self.test_dir / "arquivo.zip"
        invalid_file.write_bytes("PK\x03\x04isso não é um zip válido".encode("utf-8"))
        detected_type, extensions = detect_file_type(invalid_file)
        self.assertEqual(detected_type, "ZIP inválido ou corrompido")
        self.assertEqual(extensions, set())

    def test_detect_valid_zip(self):
        zip_file = self.test_dir / "arquivo.zip"
        with zipfile.ZipFile(zip_file, "w") as archive:
            archive.writestr("exemplo.txt", "arquivo de teste")
        detected_type, extensions = detect_file_type(zip_file)
        self.assertEqual(detected_type, "ZIP")
        self.assertIn(".zip", extensions)

    def test_file_metadata(self):
        report = analyze_file(self.test_file)
        self.assertIsNotNone(report)
        self.assertIn("file_created_at", report)
        self.assertIn("file_modified_at", report)
        self.assertTrue(report["file_created_at"])
        self.assertTrue(report["file_modified_at"])

if __name__ == "__main__":
    unittest.main()