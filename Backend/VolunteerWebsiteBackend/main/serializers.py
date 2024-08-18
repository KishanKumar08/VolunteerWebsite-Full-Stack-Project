from .models import User,userProfile, Organization, Opportunity, Review, Event, Application, Skill, EventRegistration
from rest_framework import serializers
import re

# Serializer for user creation
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = userProfile
        fields = ['id','username','email','password']
        extra_kwargs = {'password':{'write_only':True}}

    def create(self,validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            is_user=True
        )
        raw_password = validated_data['password']
        user.set_password(raw_password)
        user.save()

        userprofile = userProfile.objects.create(**validated_data)
        userprofile.save()
        return userprofile

    def validate_username(self, value):
        if userProfile.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        return value

    def validate_email(self, value):
        if userProfile.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value


    def validate_password(self,value):
        if len(value) < 6:
            raise serializers.ValidationError("Password must be at least 6 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        
        return value

# Serializer for login
class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=50)
    password = serializers.CharField(max_length=50)

# Serializer for user details (update and retrieve)
class userSerializer(serializers.ModelSerializer):
    class Meta:
        model = userProfile
        fields = '__all__'
        extra_kwargs = {'password': {'write_only': True}}  # Ensure password is write-only

# Serializer for organization creation
class OrganizationRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'email', 'password', 'address', 'mission']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        if Organization.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def validate_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError("Password must be at least 6 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

    def create(self, validated_data):

        user = User.objects.create(
            username=validated_data['name'],
            email=validated_data['email'],
            is_company=True
        )
        raw_password = validated_data['password']
        user.set_password(raw_password)
        user.save()

        return Organization.objects.create(**validated_data)

# Serializer for organization details (update and retrieve)
class organizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'
        extra_kwargs = {'password': {'write_only': True}}  # Ensure password is write-only

# Serializer for skills
class skillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = '__all__'

# Serializer for opportunities
class opportunitySerializer(serializers.ModelSerializer):
    skills = serializers.PrimaryKeyRelatedField(queryset=Skill.objects.all(), many=True)  # Associate with multiple Skills

    class Meta:
        model = Opportunity
        fields = '__all__'

    def create(self, validated_data):
        # Create a new Opportunity instance
        skills = validated_data.pop('skills', [])
        opportunity = Opportunity.objects.create(**validated_data)
        opportunity.skills.set(skills)  # Set multiple skills
        return opportunity

# Serializer for reviews
class reviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = '__all__'

# Serializer for events
class eventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = '__all__'

# Serializer for applications
class applicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application
        fields = '__all__'

# Serializer for event registrations
class eventRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventRegistration
        fields = '__all__'