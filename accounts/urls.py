from django.urls import path, include
from .views import get_csrf_token
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from .views import (
    profile,
    profile_single,
    admin_panel,
    profile_update,
    change_password,
    LecturerFilterView,
    StudentListView,
    staff_add_view,
    edit_staff,
    delete_staff,
    student_add_view,
    edit_student,
    delete_student,
    edit_student_program,
    ParentAdd,
    validate_username,
    render_lecturer_pdf_list,
    render_student_pdf_list,
    register_user,  # ✅ API VIEW
    login_user,     # ✅ API VIEW
    logout_user,    # ✅ API VIEW
)
from .forms import EmailValidationOnForgotPassword

urlpatterns = [
    path("", include("django.contrib.auth.urls")),  

    # ✅ API Authentication Routes (Fixed)
    path("api/register/", register_user, name="api_register"),
    path("api/login/", login_user, name="api_login"),
    path("api/logout/", logout_user, name="api_logout"),

    # ✅ CSRF Token Route (Fixed)
    path("api/get_csrf_token/", get_csrf_token, name="get_csrf_token"),

    # ✅ Admin & Profile Routes
    path("admin_panel/", admin_panel, name="admin_panel"),
    path("profile/", profile, name="profile"),
    path("profile/<int:id>/detail/", profile_single, name="profile_single"),
    path("setting/", profile_update, name="edit_profile"),
    path("change_password/", change_password, name="change_password"),

    # ✅ Lecturer Routes
    path("lecturers/", LecturerFilterView.as_view(), name="lecturer_list"),
    path("lecturer/add/", staff_add_view, name="add_lecturer"),
    path("staff/<int:pk>/edit/", edit_staff, name="staff_edit"),
    path("lecturers/<int:pk>/delete/", delete_staff, name="lecturer_delete"),

    # ✅ Student Routes
    path("students/", StudentListView.as_view(), name="student_list"),
    path("student/add/", student_add_view, name="add_student"),
    path("student/<int:pk>/edit/", edit_student, name="student_edit"),
    path("students/<int:pk>/delete/", delete_student, name="student_delete"),
    path("edit_student_program/<int:pk>/", edit_student_program, name="student_program_edit"),

    # ✅ Parent & AJAX Routes
    path("parents/add/", ParentAdd.as_view(), name="add_parent"),
    path("ajax/validate-username/", validate_username, name="validate_username"),

    # ✅ Paths for PDF Reports
    path("create_lecturers_pdf_list/", render_lecturer_pdf_list, name="lecturer_list_pdf"),
    path("create_students_pdf_list/", render_student_pdf_list, name="student_list_pdf"),

    # ✅ Password Reset Routes
    path("password-reset/", PasswordResetView.as_view(
         form_class=EmailValidationOnForgotPassword,
         template_name="registration/password_reset.html"
    ), name="password_reset"),
    path("password-reset/done/", PasswordResetDoneView.as_view(
         template_name="registration/password_reset_done.html"
    ), name="password_reset_done"),
    path("password-reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(
         template_name="registration/password_reset_confirm.html"
    ), name="password_reset_confirm"),
    path("password-reset-complete/", PasswordResetCompleteView.as_view(
         template_name="registration/password_reset_complete.html"
    ), name="password_reset_complete"),
]
