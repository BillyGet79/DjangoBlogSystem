from django.urls import path

from home.views import IndexView, DetailView

urlpatterns = [
    # 首页的路由
    path('', IndexView.as_view(), name='index'),
    path('detail/', DetailView.as_view(), name='detail'),
]