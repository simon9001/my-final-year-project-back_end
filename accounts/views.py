from django.views.decorators.csrf import csrf_exempt
from django.http.response import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.views.generic import CreateView, ListView
from django.db.models import Q
from django.utils.decorators import method_decorator
from django.contrib.auth.forms import PasswordChangeForm
from django_filters.views import FilterView
from core.models import Session, Semester
from course.models import Course
from result.models import TakenCourse
from .decorators import admin_required

from .forms import (
    StaffAddForm,
    StudentAddForm,
    ProfileUpdateForm,
    ParentAddForm,
    ProgramUpdateForm,
)
from .models import User, Student, Parent
from .filters import LecturerFilter, StudentFilter

# to generate pdf from template we need the following
from django.http import HttpResponse
from django.template.loader import get_template  # to get template which render as pdf
from xhtml2pdf import pisa
from django.template.loader import (
    render_to_string,
)  # to render a template into a string

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.http.response import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate

from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import get_token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

# Custom imports
from core.models import Session, Semester
from course.models import Course
from result.models import TakenCourse
from .decorators import admin_required
from .models import Student, Parent
from .serializers import UserSerializer, RegisterSerializer
from django.http import JsonResponse



@api_view(['GET'])
@permission_classes([AllowAny])
def get_csrf_token(request):
    response = JsonResponse({'csrfToken': get_token(request)})  
    response.set_cookie("csrftoken", get_token(request))  # ✅ Set CSRF Token in Cookie
    response["X-CSRFToken"] = get_token(request)  # ✅ Include CSRF token in Response Header
    return response



@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    print("Received Data:", request.data)  # Debugging Line ✅
    
    serializer = RegisterSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        response_data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data,
        }
        print("Registration Successful:", response_data)  # Debugging Line ✅
        return Response(response_data, status=status.HTTP_201_CREATED)
    
    print("Serializer Errors:", serializer.errors)  # Debugging Line ✅
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    print("🔹 Raw Request Body:", request.body)  # ✅ Debugging
    print("🔹 Parsed Request Data:", request.data)  # ✅ Debugging

    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'error': 'Missing username or password'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if user is not None:
        refresh = RefreshToken.for_user(user)
        login(request, user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data,
        })
    
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        refresh_token = request.data.get('refresh')
        token = RefreshToken(refresh_token)
        token.blacklist()
        logout(request)
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    
@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def get_csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})


def custom_logout_view(request):
    logout(request)
    return redirect('home')  # Redirect to the home page or any other page


def validate_username(request):
    username = request.GET.get("username", None)
    data = {"is_taken": User.objects.filter(username__iexact=username).exists()}
    return JsonResponse(data)


def register(request):
    if request.method == "POST":
        form = StudentAddForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, f"Account created successfuly.")
        else:
            messages.error(
                request, f"Somthing is not correct, please fill all fields correctly."
            )
    else:
        form = StudentAddForm(request.POST)
    return render(request, "registration/register.html", {"form": form})


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])  # <-- Ensures only logged-in users can access
def profile(request):
    current_session = Session.objects.filter(is_current_session=True).first()
    current_semester = Semester.objects.filter(
        is_current_semester=True, session=current_session
    ).first()

    if request.user.is_lecturer:
        courses = Course.objects.filter(
            allocated_course__lecturer__pk=request.user.id
        ).filter(semester=current_semester)
        return Response({
            "title": request.user.get_full_name,
            "courses": list(courses.values()),
            "current_session": str(current_session),
            "current_semester": str(current_semester),
        })

    elif request.user.is_student:
        level = Student.objects.get(student__pk=request.user.id)
        parent = Parent.objects.filter(student=level).first()
        courses = TakenCourse.objects.filter(
            student__student__id=request.user.id, course__level=level.level
        )
        return Response({
            "title": request.user.get_full_name,
            "parent": str(parent),
            "courses": list(courses.values()),
            "level": str(level),
            "current_session": str(current_session),
            "current_semester": str(current_semester),
        })

    return Response({
        "title": request.user.get_full_name,
        "message": "User type not recognized"
    })


# function that generate pdf by taking Django template and its context,
def render_to_pdf(template_name, context):
    """Renders a given template to PDF format."""
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'filename="profile.pdf"'  # Set default filename

    template = render_to_string(template_name, context)
    pdf = pisa.CreatePDF(template, dest=response)
    if pdf.err:
        return HttpResponse("We had some problems generating the PDF")

    return response


@login_required
@admin_required
def profile_single(request, id):
    """Show profile of any selected user"""
    if request.user.id == id:
        return redirect("/profile/")

    current_session = Session.objects.filter(is_current_session=True).first()
    current_semester = Semester.objects.filter(
        is_current_semester=True, session=current_session
    ).first()

    user = User.objects.get(pk=id)
    """
    If download_pdf exists, instead of calling render_to_pdf directly, 
    pass the context dictionary built for the specific user type 
    (lecturer, student, or superuser) to the render_to_pdf function.
    """
    if request.GET.get("download_pdf"):
        if user.is_lecturer:
            courses = Course.objects.filter(allocated_course__lecturer__pk=id).filter(
                semester=current_semester
            )
            context = {
                "title": user.get_full_name,
                "user": user,
                "user_type": "Lecturer",
                "courses": courses,
                "current_session": current_session,
                "current_semester": current_semester,
            }
        elif user.is_student:
            student = Student.objects.get(student__pk=id)
            courses = TakenCourse.objects.filter(
                student__student__id=id, course__level=student.level
            )
            context = {
                "title": user.get_full_name,
                "user": user,
                "user_type": "student",
                "courses": courses,
                "student": student,
                "current_session": current_session,
                "current_semester": current_semester,
            }
        else:
            context = {
                "title": user.get_full_name,
                "user": user,
                "user_type": "superuser",
                "current_session": current_session,
                "current_semester": current_semester,
            }
        return render_to_pdf("pdf/profile_single.html", context)

    else:
        if user.is_lecturer:
            courses = Course.objects.filter(allocated_course__lecturer__pk=id).filter(
                semester=current_semester
            )
            context = {
                "title": user.get_full_name,
                "user": user,
                "user_type": "Lecturer",
                "courses": courses,
                "current_session": current_session,
                "current_semester": current_semester,
            }
            return render(request, "accounts/profile_single.html", context)
        elif user.is_student:
            student = Student.objects.get(student__pk=id)
            courses = TakenCourse.objects.filter(
                student__student__id=id, course__level=student.level
            )
            context = {
                "title": user.get_full_name,
                "user": user,
                "user_type": "student",
                "courses": courses,
                "student": student,
                "current_session": current_session,
                "current_semester": current_semester,
            }
            return render(request, "accounts/profile_single.html", context)
        else:
            context = {
                "title": user.get_full_name,
                "user": user,
                "user_type": "superuser",
                "current_session": current_session,
                "current_semester": current_semester,
            }
            return render(request, "accounts/profile_single.html", context)


@login_required
@admin_required
def admin_panel(request):
    return render(
        request, "setting/admin_panel.html", {"title": request.user.get_full_name}
    )


# ########################################################


# ########################################################
# Setting views
# ########################################################
@login_required
def profile_update(request):
    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the error(s) below.")
    else:
        form = ProfileUpdateForm(instance=request.user)
    return render(
        request,
        "setting/profile_info_change.html",
        {
            "title": "Setting",
            "form": form,
        },
    )


@login_required
def change_password(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Your password was successfully updated!")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the error(s) below. ")
    else:
        form = PasswordChangeForm(request.user)
    return render(
        request,
        "setting/password_change.html",
        {
            "form": form,
        },
    )


# ########################################################


@login_required
@admin_required
def staff_add_view(request):
    if request.method == "POST":
        form = StaffAddForm(request.POST)
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")

        if form.is_valid():

            form.save()
            messages.success(
                request,
                "Account for lecturer "
                + first_name
                + " "
                + last_name
                + " has been created. An email with account credentials will be sent to "
                + email
                + " within a minute.",
            )
            return redirect("lecturer_list")
    else:
        form = StaffAddForm()

    context = {
        "title": "Lecturer Add",
        "form": form,
    }

    return render(request, "accounts/add_staff.html", context)


@login_required
@admin_required
def edit_staff(request, pk):
    instance = get_object_or_404(User, is_lecturer=True, pk=pk)
    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, request.FILES, instance=instance)
        full_name = instance.get_full_name
        if form.is_valid():
            form.save()

            messages.success(request, "Lecturer " + full_name + " has been updated.")
            return redirect("lecturer_list")
        else:
            messages.error(request, "Please correct the error below.")
    else:
        form = ProfileUpdateForm(instance=instance)
    return render(
        request,
        "accounts/edit_lecturer.html",
        {
            "title": "Edit Lecturer",
            "form": form,
        },
    )


@method_decorator([login_required, admin_required], name="dispatch")
class LecturerFilterView(FilterView):
    filterset_class = LecturerFilter
    queryset = User.objects.filter(is_lecturer=True)
    template_name = "accounts/lecturer_list.html"
    paginate_by = 10  # if pagination is desired

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Lecturers"
        return context


# lecturers list pdf
def render_lecturer_pdf_list(request):
    lecturers = User.objects.filter(is_lecturer=True)
    template_path = "pdf/lecturer_list.html"
    context = {"lecturers": lecturers}
    response = HttpResponse(
        content_type="application/pdf"
    )  # convert the response to pdf
    response["Content-Disposition"] = 'filename="lecturers_list.pdf"'
    # find the template and render it.
    template = get_template(template_path)
    html = template.render(context)
    # create a pdf
    pisa_status = pisa.CreatePDF(html, dest=response)
    # if error then show some funny view
    if pisa_status.err:
        return HttpResponse("We had some errors <pre>" + html + "</pre>")
    return response


# @login_required
# @lecturer_required
# def delete_staff(request, pk):
#     staff = get_object_or_404(User, pk=pk)
#     staff.delete()
#     return redirect('lecturer_list')


@login_required
@admin_required
def delete_staff(request, pk):
    lecturer = get_object_or_404(User, pk=pk)
    full_name = lecturer.get_full_name
    lecturer.delete()
    messages.success(request, "Lecturer " + full_name + " has been deleted.")
    return redirect("lecturer_list")


# ########################################################


# ########################################################
# Student views
# ########################################################
@login_required
@admin_required
def student_add_view(request):
    if request.method == "POST":
        form = StudentAddForm(request.POST)
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        if form.is_valid():
            form.save()
            messages.success(
                request,
                "Account for "
                + first_name
                + " "
                + last_name
                + " has been created. An email with account credentials will be sent to "
                + email
                + " within a minute.",
            )
            return redirect("student_list")
        else:
            messages.error(request, "Correct the error(s) below.")
    else:
        form = StudentAddForm()

    return render(
        request,
        "accounts/add_student.html",
        {"title": "Add Student", "form": form},
    )


@login_required
@admin_required
def edit_student(request, pk):
    # instance = User.objects.get(pk=pk)
    instance = get_object_or_404(User, is_student=True, pk=pk)
    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, request.FILES, instance=instance)
        full_name = instance.get_full_name
        if form.is_valid():
            form.save()

            messages.success(request, ("Student " + full_name + " has been updated."))
            return redirect("student_list")
        else:
            messages.error(request, "Please correct the error below.")
    else:
        form = ProfileUpdateForm(instance=instance)
    return render(
        request,
        "accounts/edit_student.html",
        {
            "title": "Edit-profile",
            "form": form,
        },
    )


@method_decorator([login_required, admin_required], name="dispatch")
class StudentListView(FilterView):
    queryset = Student.objects.all()
    filterset_class = StudentFilter
    template_name = "accounts/student_list.html"
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Students"
        return context


# student list pdf
def render_student_pdf_list(request):
    students = Student.objects.all()
    template_path = "pdf/student_list.html"
    context = {"students": students}
    response = HttpResponse(
        content_type="application/pdf"
    )  # convert the response to pdf
    response["Content-Disposition"] = 'filename="students_list.pdf"'
    # find the template and render it.
    template = get_template(template_path)
    html = template.render(context)
    # create a pdf
    pisa_status = pisa.CreatePDF(html, dest=response)
    # if error then show some funny view
    if pisa_status.err:
        return HttpResponse("We had some errors <pre>" + html + "</pre>")
    return response


@login_required
@admin_required
def delete_student(request, pk):
    student = get_object_or_404(Student, pk=pk)
    # full_name = student.user.get_full_name
    student.delete()
    messages.success(request, "Student has been deleted.")
    return redirect("student_list")


@login_required
@admin_required
def edit_student_program(request, pk):

    instance = get_object_or_404(Student, student_id=pk)
    user = get_object_or_404(User, pk=pk)
    if request.method == "POST":
        form = ProgramUpdateForm(request.POST, request.FILES, instance=instance)
        full_name = user.get_full_name
        if form.is_valid():
            form.save()
            messages.success(request, message=full_name + " program has been updated.")
            url = (
                "/accounts/profile/" + user.id.__str__() + "/detail/"
            )  # Botched job, must optimize
            return redirect(to=url)
        else:
            messages.error(request, "Please correct the error(s) below.")
    else:
        form = ProgramUpdateForm(instance=instance)
    return render(
        request,
        "accounts/edit_student_program.html",
        context={"title": "Edit-program", "form": form, "student": instance},
    )


# ########################################################


class ParentAdd(CreateView):
    model = Parent
    form_class = ParentAddForm
    template_name = "accounts/parent_form.html"






# def parent_add(request):
#     if request.method == 'POST':
#         form = ParentAddForm(request.POST)
#         if form.is_valid():
#             form.save()
#             return redirect('student_list')
#     else:
#         form = ParentAddForm(request.POST)
