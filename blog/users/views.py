import io
import random
import re
import string

from django.contrib.auth import authenticate
from django.contrib.auth import login, logout
from django.db import DatabaseError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from django.http.response import HttpResponseBadRequest
from django.contrib.auth.mixins import LoginRequiredMixin
from captcha.image import ImageCaptcha
from django_redis import get_redis_connection
from ronglian_sms_sdk import SmsSDK
from random import randint
from home.models import ArticleCategory, Article

from users.models import User
from utils.response_code import RETCODE
import logging

logger = logging.getLogger('django')


# Create your views here.
#注册视图
class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        # 1.接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        sms_code = request.POST.get('sms_code')
        # 2.验证信息
        if not all([mobile, password, password2, sms_code]):
            return HttpResponseBadRequest('缺少必要的参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位密码，密码是数字，字母')
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if sms_code != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        # 3.将用户信息保存到数据库当中
        # create_user可以使用系统的方法来对密码进行加密
        try:
            user = User.objects.create_user(username=mobile, password=password, mobile=mobile)
        except DatabaseError as e:
            logger.error(e)
            if User.objects.filter(mobile=mobile).exists():
                return redirect(reverse('home:index'))
            return HttpResponseBadRequest('注册失败')
        login(request, user)
        # 4.返回响应调转到指定页面
        # 暂时返回一个注册成功的信息，后期再实现跳转到指定页面
        # reverse 是可以通过namespace:name   来获取到视图所对应的路由
        response = redirect(reverse('home:index'))

        # 设置cookie信息，以方便首页中用户信息展示的判断和用户信息的展示
        response.set_cookie('is_login', True)
        response.set_cookie('username', user.username, max_age=7 * 24 * 3600)

        return response


class ImageCodeView(View):

    def get(self, request):
        """
        1.接收前端传递过来的uuid
        2.判断uuid是否获取到
        3.通过调用captcha来生成图片验证码（图片二进制和图片内容）
        4.将图片内容保存到redis中，uuid作为一个key，图片内容作为一个value，同时我们还需要设置一个时效
        5.返回图片二进制
        :param request:
        :return:
        """
        # 1.接收前端传递过来的uuid
        uuid = request.GET.get('uuid')
        # 2.判断uuid是否获取到
        if uuid is None:
            return HttpResponseBadRequest('没有传递uuid')
        # 3.通过调用captcha来生成图片验证码（图片二进制和图片内容）
        characters = string.digits + string.ascii_uppercase
        text = ''.join([random.choice(characters) for j in range(4)])
        captcha = ImageCaptcha()
        image = captcha.generate_image(chars=text)
        buffer = io.BytesIO()
        image.save(buffer, format='PNG')
        image_binary = buffer.getvalue()
        # 4.将图片内容保存到redis中，uuid作为一个key，图片内容作为一个value，同时我们还需要设置一个时效
        redis_conn = get_redis_connection('default')
        # key   设置为uuid
        # seconds   过期秒数    300秒    5分钟过期时间
        # value text
        redis_conn.setex('img:%s' % uuid, 300, text)
        # 5.返回图片二进制
        return HttpResponse(image_binary, content_type='image/jpeg')


class SmsCodeView(View):

    def get(self, request):
        """
        1.接收参数
        2.参数的验证
        3.生成短信验证码
        4.保存短信验证码到redis中
        5.发送短信
        6.返回响应
        :param request:
        :return:
        """
        # 1.接收参数
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        # 2.参数的验证
        # 验证参数是否齐全
        if not all([mobile, image_code, uuid]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要的参数'})
        # 图片验证码的验证  连接redis，获取redis中的图片验证码  判断图片验证码是否存在
        redis_conn = get_redis_connection('default')
        redis_img_code = redis_conn.get('img:%s' % uuid)
        if redis_img_code is None:
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码已过期'})
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
        # 比对，注意大小写问题，redis的数据是bytes类型
        if redis_img_code.decode().lower() != image_code.lower():
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码错误'})
        # 3.生成短信验证码
        sms_code = '%04d' % randint(0, 9999)
        # 为了后期比对方便，我们可以将短信验证码记录到日志中
        logger.info(sms_code)
        # 4.保存短信验证码到redis中
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        # 5.发送短信
        accId = '2c94811c8cd4da0a018f95f7595310aa'
        accToken = 'ee6a9ec6d9744dd4a669a9b5b41fbc65'
        appId = '2c94811c8cd4da0a018f95f75ac610b1'
        sdk = SmsSDK(accId, accToken, appId)
        tid = '1'
        datas = (sms_code, '5')
        sdk.sendMessage(tid, mobile, datas)
        # 6.返回响应
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功'})


class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        # 1.接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        # 2.验证参数
        # 验证参数是否齐全
        if not all([mobile, password]):
            return HttpResponseBadRequest('缺少关键参数')
        # 判断手机号是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号')
        # 判断密码是否为8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码最少8位，最长20位')
        # 认证登录用户
        user = authenticate(mobile=mobile, password=password)
        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')

        # 实现状态保持
        login(request, user)

        # 根据next参数来进行页面的跳转
        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))

        # 设置状态保持的周期
        if remember != 'on':
            # 没有记住用户，浏览器会话结束就过期
            request.session.set_expiry(0)
            # 设置cookie
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        else:
            # 记住用户，None表示两周后过期
            request.session.set_expiry(None)
            # 设置cookie
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        return response


class LogoutView(View):
    def get(self, request):
        # 1.session数据清除
        logout(request)
        # 2.删除部分cookie数据
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')
        # 3.跳转到首页
        return response


class ForgetPasswordView(View):
    def get(self, request):
        return render(request, 'forget_password.html')

    def post(self, request):
        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        sms_code = request.POST.get('sms_code')
        # 2.验证数据
        # 判断参数是否齐全
        if not all([mobile, password, password2, sms_code]):
            return HttpResponseBadRequest('参数不全')
        # 手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        # 判断密码是否符合规则
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合规则')
        # 判断确认密码和密码是否一致
        if password != password2:
            return HttpResponseBadRequest('密码不一致')
        # 判断短信验证码是否正确
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if redis_sms_code.decode() != sms_code:
            return HttpResponseBadRequest('短信验证码错误')
        # 3.根据手机号进行用户信息的查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 5.如果手机号没有哦查询出用户信息，则进行新用户的创建
            try:
                user = User.objects.create_user(mobile=mobile, password=password)
            except Exception as e:
                logger.error(e)
                return HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 4.如果手机号查询出用户信息则进行用户的修改
            user.set_password(password)
            user.save()
        # 6.进行页面跳转，跳转到登陆页面
        response = redirect(reverse('users:login'))
        # 7.返回响应
        return response


# 如果用户未登录的话，则会进行默认的跳转
# 默认的跳转链接是：accoutn/login/?next=xxx
class UserCenterView(LoginRequiredMixin, View):
    def get(self, request):
        # 获取登录用户信息
        user = request.user
        # 组织获取用户的信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar,
            'user_desc': user.user_desc,
        }
        return render(request, 'center.html', context)

    def post(self, request):
        user = request.user
        username = request.POST.get('username')
        avatar = request.FILES.get('avatar')
        desc = request.POST.get('desc')

        try:
            user.username = username
            user.user_desc = desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面
        response = redirect(reverse('users:center'))
        # 更新cookie信息
        response.set_cookie('username', username, max_age=14 * 24 * 3600)
        return response


class WriteBlogView(LoginRequiredMixin, View):

    def get(self, request):
        # 查询所有分类模型
        categories = ArticleCategory.objects.all()
        context = {
            'categories': categories,
        }
        return render(request, 'write_blog.html', context)

    def post(self, request):
        # 接收参数
        title = request.POST.get('title')
        avatar = request.FILES.get('avatar')
        category = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user
        # 判断参数是否齐全
        if not all([title, avatar, category, tags, sumary, content]):
            return HttpResponseBadRequest('缺少参数')

        # 判断文章分类id数据是否正确
        try:
            article_category = ArticleCategory.objects.get(id=category)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类信息')

        # 向数据库中存入数据
        try:
            Article.objects.create(author=user, title=title, avatar=avatar, category=article_category, tags=tags, sumary=sumary, content=content)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('保存失败，请稍后再试')

        response = redirect(reverse('home:index'))
        return response


