from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import (
    UserAttributeSimilarityValidator,
    MinimumLengthValidator,
    CommonPasswordValidator,
    NumericPasswordValidator
)
from django.contrib.auth import update_session_auth_hash, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes

# Create your views here.


def login_view(request):
    if request.method == 'POST':
        # Try to authenticate with username or email
        username_or_email = request.POST.get('username')
        password = request.POST.get('password')

        # Check if the input is an email
        if '@' in username_or_email:
            try:
                user = User.objects.get(email=username_or_email)
                username = user.username
            except User.DoesNotExist:
                messages.error(request, 'Invalid credentials')
                return render(request, 'assignment/login.html')
        else:
            username = username_or_email

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')
        messages.error(request, 'Invalid credentials')
    return render(request, 'assignment/login.html')


@login_required
def index(request):
    return render(request, 'assignment/index.html')


@login_required
def profile(request):
    return render(request, 'assignment/profile.html', {
        'user': request.user
    })


@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update the session to prevent the user from being logged out
            update_session_auth_hash(request, user)
            messages.success(
                request, 'Your password was successfully changed!')
            # First logout the user
            logout(request)
            # Then redirect to login page
            return redirect('login')
        else:
            # Add error messages for specific validation failures
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'assignment/changepassword.html', {
        'form': form
    })


def forget_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Build password reset link
            reset_link = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={
                        'uidb64': uid, 'token': token})
            )

            # Send email
            send_mail(
                'Password Reset Request',
                f'Click the following link to reset your password: {reset_link}',
                'vkthedon123@gmail.com',  # Your sender email
                [email],
                fail_silently=False,
            )
            messages.success(
                request, 'Password reset link has been sent to your email.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email address.')
    return render(request, 'assignment/forgetpassword.html')


def reset_password(request, uidb64, token):
    try:
        # Decode the user ID and get the user
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        # Verify token is valid
        if not default_token_generator.check_token(user, token):
            messages.error(request, 'Invalid or expired password reset link.')
            return redirect('login')

        if request.method == 'POST':
            password1 = request.POST.get('new_password1')
            password2 = request.POST.get('new_password2')

            if password1 != password2:
                messages.error(request, 'Passwords do not match')
                return render(request, 'assignment/resetpassword.html')

            # Print out password errors for debugging
            password_errors = validate_password(password1, user)
            print("Password Errors:", password_errors)  # Add this line

            if password_errors:
                for error in password_errors:
                    messages.error(request, error)
                return render(request, 'assignment/resetpassword.html')

            # Set new password
            user.set_password(password1)
            user.save()
            messages.success(request, 'Your password was successfully reset!')
            return redirect('login')

        return render(request, 'assignment/resetpassword.html')

    except (TypeError, ValueError, User.DoesNotExist, OverflowError):
        messages.error(request, 'Invalid password reset link.')
        return redirect('login')


def logout_view(request):
    logout(request)
    return redirect('login')


def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password1')
        confirm_password = request.POST.get('password2')

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return render(request, 'assignment/register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
            return render(request, 'assignment/register.html')

        # Validate password
        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors:
                messages.error(request, error)
            return render(request, 'assignment/register.html')

        # Check password match
        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return render(request, 'assignment/register.html')

        # Create user
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )

            # Authenticate and login the user
            authenticated_user = authenticate(
                request, username=username, password=password)
            if authenticated_user:
                login(request, authenticated_user)
                return redirect('index')
            else:
                messages.error(request, 'Authentication failed')
                return render(request, 'assignment/register.html')

        except Exception as e:
            messages.error(request, f'Registration failed: {str(e)}')
            return render(request, 'assignment/register.html')

    return render(request, 'assignment/register.html')


def validate_password(password, user=None):
    errors = []
    validators = [
        UserAttributeSimilarityValidator(),
        MinimumLengthValidator(min_length=8),
        CommonPasswordValidator(),
        NumericPasswordValidator()
    ]

    for validator in validators:
        try:
            validator.validate(password, user)
        except Exception as e:
            errors.append(str(e))

    return errors
