from django.conf.urls import url

from reporter import views

urlpatterns = [
    url(r'^new/malware_info$', views.get_empty_form, name='empty_form'),
    url(r'^new/report$', views.report_create, name='new_report')
]
