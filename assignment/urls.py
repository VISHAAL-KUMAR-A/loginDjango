from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('profile/', views.profile, name='profile'),
    path('logout/', views.logout_view, name='logout'),
    path('change-password/', views.change_password, name='change_password'),
    path('forget-password/', views.forget_password, name='forget_password'),
    path('reset-password/<str:token>/',
         views.reset_password, name='reset_password'),
    path('register/', views.register_view, name='register'),
    path('forget-password/', views.forget_password, name='forget_password'),
    path('reset-password/',
         auth_views.PasswordResetView.as_view(
             template_name='assignment/forgetpassword.html',
             email_template_name='assignment/password_reset_email.html',
             success_url='/reset-password-sent/'
         ),
         name='password_reset'),
    path('reset-password-sent/',
         auth_views.PasswordResetDoneView.as_view(
             template_name='assignment/password_reset_sent.html'
         ),
         name='password_reset_done'),
    path('reset-password/<str:uidb64>/<str:token>/',
         views.reset_password, name='password_reset_confirm'),
    path('reset-password-complete/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name='assignment/password_reset_complete.html'
         ),
         name='password_reset_complete'),
]
