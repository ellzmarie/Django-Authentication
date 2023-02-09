from django.shortcuts import render
from rest_framework import permissions
from rest_framework.views import APIView
from django.contrib.auth import login, logout
from rest_framework import status, generics
from rest_framework.response import Response

from .serializers import LoginSerializer, UserSerializer, UserRegisterSerializer

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

class LoginView(APIView):
    # This view should be accessible also for unauthenticated users.
    authentication_classes = ()
    permission_classes = ()

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data,
            context={ 'request': request })
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return Response(None, status=status.HTTP_202_ACCEPTED)

class LogoutView(APIView):
    # This view needs no protection, but you can require it if desired
    authentication_classes = ()
    permission_classes = ()

    def post(self, request, format=None):
        logout(request)
        return Response(None, status=status.HTTP_204_NO_CONTENT)


class ProfileView(APIView): # will be protected by default

    def get(self, request):
        user = UserSerializer(request.user).data
        return Response(user)