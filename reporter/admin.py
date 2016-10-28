from django.contrib import admin

from reporter.models import *

admin.site.register(Report)
admin.site.register(MalwareFile)
admin.site.register(MalwareCharacteristic)
admin.site.register(MalwareDependencies)
admin.site.register(SupportingFigures)
admin.site.register(AnalysisFindings)
