# Django Authentication using Django Rest Framework

We will be using **session based authentication** along with **django-rest-framework** in our web application by leveraging the built-in Django session framework.

WHY YOU SHOULD AVOID **JWT** FOR DJANGO REST FRAMEWORK AUTHENTICATION
JWT (Json Web Token) is a very popular method to provide authentication in APIs. If you are developing a modern web application with Vue.js or React as the frontend and Django Rest Framework as the backend, there is an high probability that you are considering JWT as the best method to implement authentication.

The reality is that JWT is just one method, and unfortunately not the simpler, nor the most reliable. JWT is not supported out-of-the-box in Django Rest Framework and requires additional libraries and additional configuration for your project. [source](https://www.guguweb.com/2022/01/23/django-rest-framework-authentication-the-easy-way/)

<br><br>

### 1) Add Authentication Classes to Settings

In settings.py add the following:

```py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

```

TIP: *Authentication* deals with recognizing the users that are connecting to your API,
while *Permissions* involves giving access to some resources to the users.

<br><br>

### 2) Create your Login Serializer

In your **api app** create a `serializers.py` file and add the following:

```py
from django.contrib.auth import authenticate
from rest_framework import serializers


class LoginSerializer(serializers.Serializer):
    """
    This serializer defines two fields for authentication:
      * username
      * password.
    It will try to authenticate the user with when validated.
    """
    username = serializers.CharField(
        label="Username",
        write_only=True
    )
    password = serializers.CharField(
        label="Password",
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )

    def validate(self, attrs):
        # Get username and password from request
        username = attrs.get('username')
        password = attrs.get('password')


        if username and password:
            # Try to authenticate the user using DRF built in method authenticate()
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)

            if not user:
                # If we don't have a valid user, raise a ValidationError
                msg = 'Access denied: wrong username or password.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Both "username" and "password" are required.'
            raise serializers.ValidationError(msg, code='authorization')
        # We have a valid user, put it in the serializer's validated_data.
        # It will be used in the view.
        attrs['user'] = user
        return attrs

```

<br><br>

### 3) Create your Login View

Add the following to your `views.py`:

```py
from django.shortcuts import render
from rest_framework import permissions
from rest_framework.views import APIView
from django.contrib.auth import login
from rest_framework import status
from rest_framework.response import Response

from .serializers import LoginSerializer

class LoginView(APIView):
    # This view should be accessible also for unauthenticated users.
    permission_classes = (permissions.AllowAny)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data,
            context={ 'request': request })
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return Response(None, status=status.HTTP_202_ACCEPTED)

```

<br><br>

### 4) Add LoginView to URLS

Then add your LoginView to your list of **url patterns** in the main `urls.py`:

```py
from django.contrib import admin
from django.urls import path

from api import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.LoginView.as_view())
]
```

<br><br>

### 5) The UserModel

At the core of Django's authentication, is the provided UserModel which by default has the following attributes:

- username
- password
- email
- first_name
- last_name

This means that we do not create the model OR need migration file for it.

**Let's migrate:**

```shell
# python3 manage.py makemigrations -> no need for this, django handles the user model

python3 manage.py migrate
python3 manage.py createsuperuser

(... follow instructions ...)

Username (leave blank to use 'yourdefaultusername'):
Email address: me@email.com
Password:
Password (again):
Superuser created successfully.
```

**Save these credentials somewhere, you don't want to get locked out of the django admin portal later.**

Now lets run our server:

```shell
python3 manage.py runserver
```

Go to **localhost:8000** to see.... nothing.

We don't have a view here, but it will give you some suggestions:

**localhost:8000/admin/
localhost:8000/login/**

<br><br>

## 6) Django Admin Portal

Go to **localhost:8000/admin/** to see the most magical thing:

- Your very own admin portal, provided by django when you created a superuser!
- Enter the credentials that you just made to log in.

Now you have full visibility of your models:

- Groups
- Users

You can actually perform full crud operations right from the portal.

Let's make a user so we can test our Login functions:

- click **`+Add`** next to the user model

**Create a user.**

## 7) Login with User

Test your new user in postman by sending a **POST** request to

- localhost:8000/login/

**Add the user credentials to the body:**

username: myusername
password: mypassword

If you entered them correctly you'll notice that a couple of cookies were returned with your response.

If we will persist that session cookie in each request, our user will be persistently authenticated.

<br><br>

### 8) SignUp View

We can create a new user in the admin portal... great. 
Now we need an endpoint to collect user info for the first time.

Add a new view for **SignUp**:

```py
class SignUpView(generics.CreateAPIView):
    # This view should be accessible also for unauthenticated users.
    authentication_classes = ()
    permission_classes = ()

    def post(self, request):
        print(request.data)
        user = UserRegisterSerializer(data=request.data)
        if user.is_valid():
            created_user = UserSerializer(data=user.data)
            if created_user.is_valid():
                created_user.save()
                return Response({ 'user': created_user.data }, status=status.HTTP_201_CREATED)
            else:
                return Response(created_user.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)
```



We will also need two new serializers to handle the incoming user credentials:

Create a **UserRegisterSerializer** and  **UserSerializer**:

```py
from django.contrib.auth import authenticate, get_user_model

class UserRegisterSerializer(serializers.Serializer):
    # Required fields for signup
    username = serializers.CharField(max_length=100, required=True)
    email = serializers.CharField(max_length=100, required=True)
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=True)
    password = serializers.CharField(required=True)
    password_confirmation = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        # Ensure password & password_confirmation exist
        if not data['password'] or not data['password_confirmation']:
            raise serializers.ValidationError('Please include a password and password confirmation.')
        # Ensure password & password_confirmation match
        if data['password'] != data['password_confirmation']:
            raise serializers.ValidationError('Please make sure your passwords match.')
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'first_name',
            'last_name',
        ]
        extra_kwargs = { 'password': { 'write_only': True, 'min_length': 5 } }

    # This create method will be used for model creation
    def create(self, validated_data):
        return get_user_model().objects.create_user(**validated_data)
```
<br>

Finally, add the **SignUpView** to our list of url patterns in `urls.py`:

```py
path('signup/', views.SignUpView.as_view()),
```

Test it out! Sign up a new user is postman.  
Can you login and get a cookie with your new user? 

<br><br>



### 9) Logout

Add the following to `views.py` to use the build in logout method provided by Django:


```py
from django.contrib.auth import login, logout # <- import built in logout method


class LogoutView(APIView):
    # This view needs no protection, but you can require it if desired
    authentication_classes = ()
    permission_classes = ()

    def post(self, request, format=None):
        logout(request) # <- this handy built in method deletes the users cookie in the browser
        return Response(None, status=status.HTTP_204_NO_CONTENT)
```


Add your logout url to url patterns in `urls.py`: 


```py
 path('logout/', views.LogoutView.as_view()),
```
<br><br>


### 10) Protecting Profile Views


  Note: We added `rest_framework.permissions.IsAuthenticated` in our `DEFAULT_PERMISSION_CLASSES` setting, so each view will require that the user is authenticated, unless otherwise specified.


Add a **Profile view** for the user: 

```py
#add to top
from .serializers import LoginSerializer, UserSerializer


class ProfileView(APIView): # will be protected by default
    
    def get(self, request):
        user = UserSerializer(request.user).data
        return Response(user)
```


Add this new view to our url patterns:

```py
path('profile/', views.ProfileView.as_view())
```

Any future views you create and add to your URL patterns will be protected too by default. 

