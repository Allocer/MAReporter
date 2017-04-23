from django.db import models


class MalwareCharacteristic(models.Model):
    capabilities_for_infecting_files = models.TextField(max_length=10000, blank=True)
    self_preservation = models.TextField(max_length=10000, blank=True)
    leaking_data = models.TextField(max_length=10000, blank=True)
    interaction_with_attackers = models.TextField(max_length=10000, blank=True)
    others = models.TextField(max_length=10000, blank=True)


class MalwareDependencies(models.Model):
    WINDOWS = 'WINDOWS'
    LINUX = 'LINUX'
    UNIX = 'UNIX'
    OS = 'OS'
    OTHER = 'OTHER'
    SUPPORT_OS_VERSION = (
        (WINDOWS, 'Windows'),
        (LINUX, 'Linux'),
        (UNIX, 'UNIX'),
        (OS, 'OS'),
    )
    support_OS_version = models.CharField(max_length=50, choices=SUPPORT_OS_VERSION)
    required_files = models.TextField(max_length=1000, blank=True)
    custom_DLLs = models.TextField(max_length=1000, blank=True)
    executables = models.TextField(max_length=1000, blank=True)
    scripts = models.TextField(max_length=1000, blank=True)
    urls = models.TextField(max_length=1000, blank=True)
    others = models.TextField(max_length=10000, blank=True)


class AnalysisFindings(models.Model):
    static_code_analysis = models.TextField(max_length=50000, blank=True)
    dynamic_code_analysis = models.TextField(max_length=50000, blank=True)
    others = models.TextField(max_length=10000, blank=True)


class SupportingFigures(models.Model):
    logs = models.TextField(max_length=10000, blank=True)
    others = models.TextField(max_length=10000, blank=True)


class MalwareFile(models.Model):
    malware_name = models.CharField(max_length=100)
    size = models.IntegerField(default=0)
    found_date = models.DateField('date found', blank=True)
    found_place = models.CharField(max_length=100)

    ROOTKIT = 'ROOTKIT'
    BACKDOOR = 'BACKDOOR'
    VIRUS = 'VIRUS'
    KEYLOGGER = 'KEYLOGGER'
    TROJAN = 'TROJAN'
    WORM = 'WORM'
    ADWARE = 'ADWARE'
    SPYWERE = 'SPYWERE'
    DIALER = 'DIALER'
    OTROS = 'OTROS'
    OTHER = 'OTHER'
    MALWARE_TYPE = (
        (ROOTKIT, 'Rootkit'),
        (BACKDOOR, 'Backdoor'),
        (VIRUS, 'Virus'),
        (KEYLOGGER, 'Keylogger'),
        (TROJAN, 'Trojan'),
        (WORM, 'Worm'),
        (ADWARE, 'Adware'),
        (SPYWERE, 'Spywere'),
        (DIALER, 'Dialer'),
        (OTROS, 'Otros'),
        (OTHER, 'Other'),
    )

    malware_type = models.CharField(max_length=50, choices=MALWARE_TYPE, default=VIRUS)
    antyvirus_detection_capabilities = models.TextField(max_length=3000)

    EXE = 'EXE'
    OTHER = 'OTHER'
    FILE_TYPE = (
        (EXE, 'Exe'),
        (OTHER, 'Other')
    )
    file_type = models.CharField(max_length=10, choices=FILE_TYPE, default=EXE)

    malware_characteristic = models.ForeignKey(MalwareCharacteristic, on_delete=models.CASCADE, blank=True)
    malware_dependencies = models.ForeignKey(MalwareDependencies, on_delete=models.CASCADE, blank=True)
    analysis_findings = models.ForeignKey(AnalysisFindings, on_delete=models.CASCADE, blank=True)
    supporting_figures = models.ForeignKey(SupportingFigures, on_delete=models.CASCADE, blank=True)


class Report(models.Model):
    report_name = models.CharField(max_length=100, unique=True)
    create_date = models.DateField('date of creation', default='2016-05-09', blank=True)
    malware_file_info = models.ForeignKey(MalwareFile)
    additional_findings = models.TextField(max_length=10000, blank=True)
    additional_recommendations = models.TextField(max_length=10000, blank=True)

    FULL_REPORT = 'FULL REPORT'
    NOT_FULL_REPORT = 'NOT FULL REPORT'

    REPORT_TYPE = (
        (FULL_REPORT, 'Full report'),
        (NOT_FULL_REPORT, 'Not full report')
    )
    report_type = models.CharField(max_length=100, choices=REPORT_TYPE, default=FULL_REPORT, blank=True)
