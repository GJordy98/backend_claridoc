"""
URL routing configuration for the accounts application of ClariDoc Pro.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    UserViewSet, ClientViewSet, SuccursaleViewSet, LicenceViewSet,
    CustomTokenObtainPairView, StartupVerifyView, FichierViewSet, LogViewSet,
    MachineViewSet, SuccursaleConfigView, PaymentRequestViewSet, RegisterView,
    VerifyOTPView, UniversalResetPasswordView, VisiteurViewSet
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'clients', ClientViewSet, basename='client')
router.register(r'succursales', SuccursaleViewSet, basename='succursale')
router.register(r'licences', LicenceViewSet, basename='licence')
router.register(r'fichiers', FichierViewSet, basename='fichier')
router.register(r'logs', LogViewSet, basename='log')
router.register(r'machines', MachineViewSet, basename='machine')
router.register(r'payments', PaymentRequestViewSet, basename='payment')
router.register(r'visiteurs', VisiteurViewSet, basename='visiteur')

urlpatterns = [
    # Route PUBLIQUE : vérification de licence au démarrage de l'app C#
    path('startup/verify/', StartupVerifyView.as_view(), name='startup_verify'),

    # Routes pour l'authentification JWT et Inscription
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Route pour la configuration FTP de la succursale
    path('config/', SuccursaleConfigView.as_view(), name='succursale_config'),

    # Route de maintenance pour réinitialiser n'importe quel mot de passe
    path(
        'maintenance/reset-password/<str:username>/<str:password>/',
        UniversalResetPasswordView.as_view(),
        name='universal_reset'
    ),

    # Routes API REST (CRUD Users, Clients, Succursales)
    path('', include(router.urls)),
]
