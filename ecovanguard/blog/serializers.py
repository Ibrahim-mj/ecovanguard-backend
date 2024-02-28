from rest_framework import serializers

from .models import Blog, BlogImage, Category

class CategorySerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=100, required=False)
    class Meta:
        model = Category
        fields = "__all__"

class BlogImageSerializer(serializers.ModelSerializer):
    blog = serializers.PrimaryKeyRelatedField(queryset=Blog.objects.all())
    image = serializers.ImageField(max_length=None, use_url=True)
    class Meta:
        model = BlogImage
        fields = "__all__"

class BlogSerializer(serializers.ModelSerializer):
    category = CategorySerializer(required=False)
    blog_images = BlogImageSerializer(required=False)

    class Meta:
        model = Blog
        fields = "__all__"
        read_only_fields = ("date_posted",)

    def create(self, validated_data):
        category_data = validated_data.pop('category', None)
        blog_images_data = validated_data.pop('blog_images', [])
        category = None
        if category_data is not None:
            try:
                category, created = Category.objects.get_or_create(name=category_data['name'])
            except KeyError:
                category, created = Category.objects.get_or_create(name='Uncategorized')
        blog = Blog.objects.create(category=category, **validated_data)
        for blog_image_data in blog_images_data:
            print(type(blog_image_data))
            # if isinstance(blog_image_data, dict):
            BlogImage.objects.create(blog=blog, image=blog_image_data['image'])
        return blog

    def update(self, instance, validated_data):
        blog_images = validated_data.pop("blog_images")
        blog = super().update(instance, validated_data)
        if blog_images:
            # blog.blogimage_set.all().delete()
            for blog_image in blog_images:
                BlogImage.objects.create(blog=blog, **blog_image)
        return blog

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["approximate_reading_time"] = f'{instance.get_approximate_reading_time} min read'
        return data