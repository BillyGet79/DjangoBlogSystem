from django.shortcuts import render
from django.views import View
from home.models import ArticleCategory, Article
from django.http.response import HttpResponseNotFound
from django.core.paginator import Paginator, EmptyPage


# Create your views here.
class IndexView(View):
    def get(self, request):
        # 1.获取所有分类信息
        categories = ArticleCategory.objects.all()
        # 2.接收用户点击的分类id
        cat_id = request.GET.get('cat_id', 1)
        # 3.根据分类id进行分类的查询
        try:
            category = ArticleCategory.objects.get(id=cat_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseNotFound('没有此分类')
        # 4.获取分页参数
        page_num = request.GET.get('page_num', 1)
        page_size = request.GET.get('page_size', 10)
        # 5.根据分类信息查询文章数据
        articles = Article.objects.filter(category=category)
        # 6.创建分页器
        paginator = Paginator(articles, per_page=page_size)
        # 7.进行分页处理
        try:
            page_articles = paginator.page(page_num)
        except EmptyPage:
            return HttpResponseNotFound('empty page')
        # 总页数
        total_page = paginator.num_pages
        # 8.组织数据传递给模板
        context = {
            'categories': categories,
            'category': category,
            'articles': page_articles,
            'total_page': total_page,
            'page_size': page_size,
            'page_num': page_num,
        }
        return render(request, 'index.html', context)


class DetailView(View):
    def get(self, request):
        # 1.接收文章id信息
        id = request.GET.get('id')
        # 2.根据文章id进行文章数据的查询
        try:
            article = Article.objects.get(id=id)
        except Article.DoesNotExist:
            return render(request, '404.html')
        # 3.查询分类数据
        categories = ArticleCategory.objects.all()
        # 4.组织模板数据
        context = {
            'article': article,
            'categories': categories,
            'category': article.category,
        }
        return render(request, 'detail.html', context)


