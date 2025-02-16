from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views import defaults as default_views
from django.views.i18n import JavaScriptCatalog
from accounts.views import get_csrf_token

admin.site.site_header = "Dj-LMS Admin"

urlpatterns = [
    path("admin/", admin.site.urls),
    
    # ✅ Keep API Routes Only
    path("", include("accounts.urls")), 
    path("api/get_csrf_token/", get_csrf_token, name="get_csrf_token"),  # Ensure CSRF token retrieval

    path("i18n/", include("django.conf.urls.i18n")),
    path("jsi18n/", JavaScriptCatalog.as_view(), name="javascript-catalog"),
    
    path("", include("core.urls")),  # Core application
    path("jet/", include("jet.urls", "jet")),  
    path("jet/dashboard/", include("jet.dashboard.urls", "jet-dashboard")),  

    path("programs/", include("course.urls")),
    path("result/", include("result.urls")),
    path("search/", include("search.urls")),
    path("quiz/", include("quiz.urls")),
    path("payments/", include("payments.urls")),
]

# ✅ Remove this line because it duplicates authentication endpoints:
# path("accounts/", include("accounts.urls"))  🚨 REMOVE THIS LINE

# Debug Mode - Static & Media Files
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Debug Mode - Error Pages
if settings.DEBUG:
    urlpatterns += [
        path("400/", default_views.bad_request, kwargs={"exception": Exception("Bad Request!")}),
        path("403/", default_views.permission_denied, kwargs={"exception": Exception("Permission Denied")}),
        path("404/", default_views.page_not_found, kwargs={"exception": Exception("Page not Found")}),
        path("500/", default_views.server_error),
    ]
