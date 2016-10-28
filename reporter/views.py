from django.shortcuts import render, redirect

from reporter.forms import MalwareFileForm, MalwareDependenciesForm, MalwareCharacteristicForm, AnalysisFindingsForm, \
    SupportingFiguresForm, ReportForm


def get_empty_form(request, template_name='reporter/report_info.html'):
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


def report_create(request, template_name='reporter/created.html'):
    if request.POST:
        analysis_findings_form, malware_characteristic_form, malware_dependencies_form, malware_info_form, report_form, supporting_figures_form = get_data_from_request(
            request)

        if report_form.is_valid() and malware_info_form.is_valid():
            report = report_form.save(commit=False)
            malware_file = malware_info_form.save(commit=False)
            malware_dependencies = malware_dependencies_form.save(commit=False)
            malware_characteristic = malware_characteristic_form.save(commit=False)
            analysis_findings = analysis_findings_form.save(commit=False)
            supporting_figures = supporting_figures_form.save(commit=False)

            save_malware_info_segments(analysis_findings, malware_characteristic, malware_dependencies,
                                       supporting_figures)
            save_malware_file_info(analysis_findings, malware_characteristic, malware_dependencies, malware_file,
                                   supporting_figures)
            save_report(malware_file, report)

            return render(request, template_name, {})

    return redirect('reporter:empty_form')


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
