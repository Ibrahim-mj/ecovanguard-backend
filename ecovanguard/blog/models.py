from django.db import models

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name.title()

    @property
    def get_related_blogs(self):
        """Returns the blogs related to the category."""
        return Blog.objects.filter(category=self)

class Blog(models.Model):
    title = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.PROTECT)
    content = models.TextField() # Any Image or Video can be added in the content as a link in markdown format
    date_posted = models.DateTimeField(auto_now_add=True)
    author = models.CharField(max_length=100)

    def __str__(self):
        return self.title.title()

    @property
    def get_approximate_reading_time(self):
        """Returns the approximate reading time of the blog."""
        word_count = len(self.content.split())
        return round(word_count / 200) if word_count > 200 else 1

    @property
    def get_blog_images(self):
        """Returns the images related to the blog."""
        return BlogImage.objects.filter(blog=self)
    
    def save(self, *args, **kwargs):
        """Overriding the save method to update the approximate_reading_time."""
        if not self.category:
            self.category = Category.objects.get_or_create(name='Uncategorized')[0] # In a case where category is not provided
        super().save(*args, **kwargs)

class BlogImage(models.Model):
    """Model for main blog images that are displayed on the blog page as title images."""
    blog = models.ForeignKey(Blog, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='blog_images')

    def __str__(self):
        return f'{self.blog.title} Image'

    @property
    def get_image_url(self):
        return self.image.url if self.image else None