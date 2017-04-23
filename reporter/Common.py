from django.http import HttpResponse

from reporter.forms import ReportForm, MalwareFileForm, MalwareDependenciesForm, MalwareCharacteristicForm, \
    AnalysisFindingsForm, SupportingFiguresForm


class Common:
    @staticmethod
    def create_file_attachment_response():
        response = HttpResponse(content_type='application/pdf')
        filename = 'report'
        response['Content-Disposition'] = 'attachement; filename={0}.pdf'.format(filename)
        return response

    def get_data_from_request(request):
        report_form = ReportForm(request.POST)
        malware_info_form = MalwareFileForm(request.POST)
        malware_dependencies_form = MalwareDependenciesForm(request.POST)
        malware_characteristic_form = MalwareCharacteristicForm(request.POST)
        analysis_findings_form = AnalysisFindingsForm(request.POST)
        supporting_figures_form = SupportingFiguresForm(request.POST)
        return analysis_findings_form, malware_characteristic_form, malware_dependencies_form, malware_info_form, report_form, supporting_figures_form

    def save_report(malware_file, report):
        report.malware_file_info = malware_file
        report.save()

    def save_malware_file_info(analysis_findings, malware_characteristic, malware_dependencies, malware_file,
                               supporting_figures):
        malware_file.malware_dependencies = malware_dependencies
        malware_file.malware_characteristic = malware_characteristic
        malware_file.analysis_findings = analysis_findings
        malware_file.supporting_figures = supporting_figures
        malware_file.save()

    def save_malware_info_segments(analysis_findings, malware_characteristic, malware_dependencies, supporting_figures):
        malware_dependencies.save()
        malware_characteristic.save()
        analysis_findings.save()
        supporting_figures.save()
