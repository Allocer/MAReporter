from io import BytesIO

from django.shortcuts import render, redirect

from reporter.PdfPrinter import PdfPrinter
from reporter.Common import Common

from reporter.forms import MalwareFileForm, MalwareDependenciesForm, MalwareCharacteristicForm, AnalysisFindingsForm, \
    SupportingFiguresForm, ReportForm
from reporter.models import Report


def index_view(request, template_name='reporter/index.html'):
    return render(request, template_name)


def list_view(request, template_name='reporter/list.html'):
    all_reports = Report.objects.all()
    return render(request, template_name, {'reports': all_reports})


def delete_view(request):
    report_name = request.POST.get("report_name", "")
    report = Report.objects.get(report_name=report_name)

    if request.method == 'POST':
        report.delete()

    return redirect('reporter:list')


def help_view(request, template_name='reporter/help.html'):
    return render(request, template_name)


def new_report_view(request, template_name='reporter/report_info.html'):
    report_form = ReportForm()
    malware_info_form = MalwareFileForm()
    malware_dependencies_form = MalwareDependenciesForm()
    malware_characteristic_form = MalwareCharacteristicForm()
    analysis_findings_form = AnalysisFindingsForm()
    supporting_figures_form = SupportingFiguresForm()

    return render(request, template_name, {'report_form': report_form,
                                           'malware_info_form': malware_info_form,
                                           'malware_dependencies_form': malware_dependencies_form,
                                           'malware_characteristic_form': malware_characteristic_form,
                                           'analysis_findings_form': analysis_findings_form,
                                           'supporting_figures_form': supporting_figures_form})


def list_of_all_reports_view(request, template_name='reporter/list.html'):
    if request.POST:
        analysis_findings_form, malware_characteristic_form, malware_dependencies_form, malware_info_form, report_form, supporting_figures_form = Common.get_data_from_request(
            request)

        if report_form.is_valid() and malware_info_form.is_valid():
            report = report_form.save(commit=False)
            malware_file = malware_info_form.save(commit=False)
            malware_dependencies = malware_dependencies_form.save(commit=False)
            malware_characteristic = malware_characteristic_form.save(commit=False)
            analysis_findings = analysis_findings_form.save(commit=False)
            supporting_figures = supporting_figures_form.save(commit=False)

            Common.save_malware_info_segments(analysis_findings, malware_characteristic, malware_dependencies,
                                              supporting_figures)
            Common.save_malware_file_info(analysis_findings, malware_characteristic, malware_dependencies, malware_file,
                                          supporting_figures)
            Common.save_report(malware_file, report)

            all_reports = Report.objects.all()
            return render(request, template_name, {'reports': all_reports})

    return redirect('reporter:empty_form')


def generate_pdf(request):
    if 'pdf' in request.POST:
        report_name = request.POST.get("report_name", "")

        response = Common.create_file_attachment_response()
        buffer = BytesIO()

        report_pdf = PdfPrinter(buffer, 'A4')
        pdf = report_pdf.report('Malware Analysis Report', report_name)

        response.write(pdf)

        return response
