from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class LoginSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super(LoginSerializer, cls).get_token(user)
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super(LoginSerializer, self).validate(attrs)
        data.update({'username': self.user.username})
        data.update({'user_id': self.user.id})
        return data


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        max_length=128,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        max_length=128, min_length=8, write_only=True,
        validators=[validate_password]
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def create(self, validated_data):
        user = super().create(validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user