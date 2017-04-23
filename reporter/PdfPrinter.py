from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph
from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus import Spacer

from reporter.models import Report


class PdfPrinter:
    subtitleStyle = ParagraphStyle(
        name='Normal',
        fontName='Helvetica-Bold',
        textColor='blue',
        fontSize=14,
    )
    contentTitleStyle = ParagraphStyle(
        name='Normal',
        fontName='Helvetica-Bold',
        fontSize=10,
    )

    contentStyle = ParagraphStyle(
        name='Normal',
        fontName='Times-Roman',
        fontSize=10,
    )

    space = Spacer(0, 0.25 * inch)

    def __init__(self, buffer, pageSize):
        self.buffer = buffer

        if pageSize == 'A4':
            self.pageSize = A4
        elif pageSize == 'Letter':
            self.pageSize = letter
        self.width, self.height = self.pageSize

    def report(self, title, report_name):
        doc = SimpleDocTemplate(
            self.buffer,
            pagesize=self.pageSize)
        styles = getSampleStyleSheet()

        data = [Paragraph(title, styles['Title']), self.space]

        try:
            report = Report.objects.get(report_name=report_name)
            self.parse_report_description(data, report)
            self.parse_malware_basic_info(data, report)

        except ObjectDoesNotExist:
            Http404('Not found')

        return self.create_pdf_return_response(data, doc)

    def create_pdf_return_response(self, data, doc):
        doc.build(data)
        pdf = self.buffer.getvalue()
        self.buffer.close()
        return pdf

    def parse_report_description(self, data, report):
        data.append(Paragraph("I. Report description:", self.subtitleStyle))
        data.append(self.space)

        data.append(Paragraph("Report name:", self.contentTitleStyle))
        data.append(Paragraph(report.report_name, self.contentStyle))

        data.append(Paragraph("Date of creation:", self.contentTitleStyle))
        data.append(Paragraph(report.create_date.strftime('%d-%m-%Y'), self.contentStyle))

        data.append(Paragraph("Additional findings:", self.contentTitleStyle))
        data.append(Paragraph(report.additional_findings, self.contentStyle))

        data.append(Paragraph("Additional recommendations:", self.contentTitleStyle))
        data.append(Paragraph(report.additional_recommendations, self.contentStyle))

        data.append(Paragraph("Report type:", self.contentTitleStyle))
        data.append(Paragraph(report.report_type, self.contentStyle))

        data.append(self.space)

    def parse_malware_basic_info(self, data, report):
        data.append(Paragraph("II. Malware file basic informations:", self.subtitleStyle))
        data.append(self.space)

        data.append(Paragraph("Malware name:", self.contentTitleStyle))
        data.append(Paragraph(report.malware_file_info.malware_name, self.contentStyle))

        data.append(Paragraph("Size:", self.contentTitleStyle))
        data.append(Paragraph(str(report.malware_file_info.size), self.contentStyle))

        data.append(Paragraph("Date found:", self.contentTitleStyle))
        data.append(Paragraph(report.malware_file_info.found_date.strftime('%d-%m-%Y'), self.contentStyle))

        data.append(Paragraph("Found place:", self.contentTitleStyle))
        data.append(Paragraph(report.malware_file_info.found_place, self.contentStyle))

        data.append(Paragraph("Malware type:", self.contentTitleStyle))
        data.append(Paragraph(report.malware_file_info.malware_type, self.contentStyle))

        data.append(Paragraph("Antyvirus detection capabilities:", self.contentTitleStyle))
        data.append(Paragraph(report.malware_file_info.antyvirus_detection_capabilities, self.contentStyle))

        data.append(Paragraph("File type:", self.contentTitleStyle))
        data.append(Paragraph(report.malware_file_info.file_type, self.contentStyle))

        data.append(self.space)

        self.parse_malware_dependencies_info(data, report)
        self.parse_malware_characteristics(data, report)
        self.parse_analysis_findings(data, report)
        self.parse_supporting_figures(data, report)

    def parse_malware_dependencies_info(self, data, report):
        malware_dependencies = report.malware_file_info.malware_dependencies

        data.append(Paragraph("III. Malware file dependencies informations:", self.subtitleStyle))
        data.append(self.space)

        data.append(Paragraph("Support OS version:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.support_OS_version, self.contentStyle))

        data.append(Paragraph("Required files:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.required_files, self.contentStyle))

        data.append(Paragraph("Custom DLLs:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.custom_DLLs, self.contentStyle))

        data.append(Paragraph("Executables:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.executables, self.contentStyle))

        data.append(Paragraph("Scripts:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.scripts, self.contentStyle))

        data.append(Paragraph("Urls:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.urls, self.contentStyle))

        data.append(Paragraph("Others:", self.contentTitleStyle))
        data.append(Paragraph(malware_dependencies.others, self.contentStyle))

        data.append(self.space)

    def parse_malware_characteristics(self, data, report):
        malware_characteristic = report.malware_file_info.malware_characteristic

        data.append(self.space)
        data.append(self.space)
        data.append(Paragraph("IV. Malware file characteristic:", self.subtitleStyle))
        data.append(self.space)

        data.append(Paragraph("Capabilities for infecting files:", self.contentTitleStyle))
        data.append(Paragraph(malware_characteristic.capabilities_for_infecting_files, self.contentStyle))

        data.append(Paragraph("Self preservation:", self.contentTitleStyle))
        data.append(Paragraph(malware_characteristic.self_preservation, self.contentStyle))

        data.append(Paragraph("Leaking data:", self.contentTitleStyle))
        data.append(Paragraph(malware_characteristic.leaking_data, self.contentStyle))

        data.append(Paragraph("Interaction with attackers:", self.contentTitleStyle))
        data.append(Paragraph(malware_characteristic.interaction_with_attackers, self.contentStyle))

        data.append(Paragraph("Others:", self.contentTitleStyle))
        data.append(Paragraph(malware_characteristic.others, self.contentStyle))

        data.append(self.space)

    def parse_analysis_findings(self, data, report):
        analysis_findings = report.malware_file_info.analysis_findings

        data.append(Paragraph("V. Analysis findings:", self.subtitleStyle))
        data.append(self.space)

        data.append(Paragraph("Static code analysis:", self.contentTitleStyle))
        data.append(Paragraph(analysis_findings.static_code_analysis, self.contentStyle))

        data.append(Paragraph("Dynamic code analysis:", self.contentTitleStyle))
        data.append(Paragraph(analysis_findings.dynamic_code_analysis, self.contentStyle))

        data.append(Paragraph("Others:", self.contentTitleStyle))
        data.append(Paragraph(analysis_findings.others, self.contentStyle))

        data.append(self.space)

    def parse_supporting_figures(self, data, report):
        supporting_figures = report.malware_file_info.supporting_figures

        data.append(Paragraph("VI. Supporting figures:", self.subtitleStyle))
        data.append(self.space)

        data.append(Paragraph("Logs:", self.contentTitleStyle))
        data.append(Paragraph(supporting_figures.logs, self.contentStyle))

        data.append(Paragraph("Others:", self.contentTitleStyle))
        data.append(Paragraph(supporting_figures.others, self.contentStyle))
