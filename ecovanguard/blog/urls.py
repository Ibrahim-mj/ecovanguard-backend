from django.urls import path

from .views import BlogListView, BlogDetailView, BlogCreateView, CategoryListCreateView, CategoryDetailView

urlpatterns = [
    path("articles/", BlogListView.as_view(), name="blog-list"),
    path("articles/<int:pk>/", BlogDetailView.as_view(), name="blog-detail"),
    path("articles/create/", BlogCreateView.as_view(), name="blog-create"),
    path("categories/", CategoryListCreateView.as_view(), name="category-list"),
    path("categories/<int:pk>/", CategoryDetailView.as_view(), name="category-detail"),
]