from betterforms.multiform import MultiModelForm
from django import forms

from reporter.models import *


class ReportForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = ['report_name', 'create_date', 'additional_findings',
                  'additional_recommendations', 'report_type']


class MalwareFileForm(forms.ModelForm):
    class Meta:
        file_type = forms.Select
        model = MalwareFile
        fields = ['malware_name', 'size', 'found_date', 'found_place', "malware_type",
                  'antyvirus_detection_capabilities', 'file_type']


class MalwareCharacteristicForm(forms.ModelForm):
    class Meta:
        model = MalwareCharacteristic
        fields = ['capabilities_for_infecting_files', 'self_preservation', 'leaking_data', 'interaction_with_attackers',
                  'others']


class MalwareDependenciesForm(forms.ModelForm):
    class Meta:
        model = MalwareDependencies
        fields = ['support_OS_version', 'required_files', 'custom_DLLs', 'executables', 'scripts', 'urls', 'others']


class AnalysisFindingsForm(forms.ModelForm):
    class Meta:
        model = AnalysisFindings
        fields = ['static_code_analysis', 'dynamic_code_analysis', 'others']


class SupportingFiguresForm(forms.ModelForm):
    class Meta:
        model = SupportingFigures
        fields = ['logs', 'others']


class MalwareReportMultiForm(MultiModelForm):
    form_classes = {
        'report': ReportForm,
        'malwareFile': MalwareFileForm,
        'malwareCharacteristic': MalwareCharacteristicForm,
        'malwareDependencies': MalwareDependenciesForm,
        'analysisFindings': AnalysisFindingsForm,
        'supportingFigures': SupportingFiguresForm,
    }
