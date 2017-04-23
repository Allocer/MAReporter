from django.conf.urls import url

from reporter import views

urlpatterns = [
    url(r'^$', views.index_view, name='index'),
    url(r'^new/malware_info$', views.new_report_view, name='empty_form'),
    url(r'^new/report$', views.list_of_all_reports_view, name='new_report'),
    url(r'^new/report/pdf$', views.generate_pdf, name='generate_pdf'),
    url(r'^new/report/list$', views.list_view, name='list'),
    url(r'^new/report/delete$', views.delete_view, name='delete_report'),
    url(r'^help$', views.help_view, name='help'),
]
