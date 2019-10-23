#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""Bilibili Toolkit 哔哩哔哩工具箱
https://github.com/Hsury/Bilibili-Toolkit"""

banner = r"""
        \\         //
         \\       //
    #####################     ________   ___   ___        ___   ________   ___   ___        ___
    ##                 ##    |\   __  \ |\  \ |\  \      |\  \ |\   __  \ |\  \ |\  \      |\  \
    ##    //     \\    ##    \ \  \|\ /_\ \  \\ \  \     \ \  \\ \  \|\ /_\ \  \\ \  \     \ \  \
    ##   //       \\   ##     \ \   __  \\ \  \\ \  \     \ \  \\ \   __  \\ \  \\ \  \     \ \  \
    ##                 ##      \ \  \|\  \\ \  \\ \  \____ \ \  \\ \  \|\  \\ \  \\ \  \____ \ \  \
    ##       www       ##       \ \_______\\ \__\\ \_______\\ \__\\ \_______\\ \__\\ \_______\\ \__\
    ##                 ##        \|_______| \|__| \|_______| \|__| \|_______| \|__| \|_______| \|__|
    #####################
        \/         \/                               哔哩哔哩 (゜-゜)つロ 干杯~
"""

import base64
import chardet
import hashlib
import json
import os
import platform
import random
import requests
import rsa
import shutil
import subprocess
import sys
import threading
import time
import toml
from multiprocessing import freeze_support, Manager, Pool, Process
from selenium import webdriver
from urllib import parse

__author__ = "Hsury"
__email__ = "i@hsury.com"
__license__ = "SATA"
__version__ = "2019.9.15"

class Bilibili:
    app_key = "1d8b6e7d45233436"
    patterns = {
        'video': {
            'id': 1,
            'prefix': "https://www.bilibili.com/video/av",
        },
        'activity': {
            'id': 4,
            'prefix': "https://www.bilibili.com/blackboard/",
        },
        'gallery': {
            'id': 11,
            'prefix': "https://h.bilibili.com/",
        },
        'article': {
            'id': 12,
            'prefix': "https://www.bilibili.com/read/cv",
        },
    }

    def __init__(self, https=True, queue=None):
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36"})
        self.__queue = queue
        self.get_cookies = lambda: self._session.cookies.get_dict(domain=".bilibili.com")
        self.get_csrf = lambda: self.get_cookies().get("bili_jct", "")
        self.get_sid = lambda: self.get_cookies().get("sid", "")
        self.get_uid = lambda: self.get_cookies().get("DedeUserID", "")
        self.access_token = ""
        self.refresh_token = ""
        self.username = ""
        self.password = ""
        self.info = {
            'ban': False,
            'coins': 0,
            'experience': {
                'current': 0,
                'next': 0,
            },
            'face': "",
            'level': 0,
            'nickname': "",
        }
        self.protocol = "https" if https else "http"
        self.proxy = None
        self.proxy_pool = set()

    def _log(self, message):
        log = f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}][{self.username if self.username else '#' + self.get_uid() if self.get_uid() else ''}] {message}"
        print(log)
        self.__push_to_queue("log", log)

    def _requests(self, method, url, decode_level=2, enable_proxy=True, retry=10, timeout=15, **kwargs):
        if method in ["get", "post"]:
            for _ in range(retry + 1):
                try:
                    response = getattr(self._session, method)(url, timeout=timeout, proxies=self.proxy if enable_proxy else None, **kwargs)
                    return response.json() if decode_level == 2 else response.content if decode_level == 1 else response
                except:
                    if enable_proxy:
                        self.set_proxy()
        return None

    def _solve_captcha(self, image):
        url = "https://bili.dev:2233/captcha"
        payload = {'image': base64.b64encode(image).decode("utf-8")}
        response = self._requests("post", url, json=payload)
        return response['message'] if response and response.get("code") == 0 else None

    def __push_to_queue(self, manufacturer, data):
        if self.__queue:
            self.__queue.put({
                'uid': self.get_uid(),
                'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                'manufacturer': manufacturer,
                'data': data,
            })

    @staticmethod
    def calc_sign(param):
        salt = "560c52ccd288fed045859ed18bffd973"
        sign_hash = hashlib.md5()
        sign_hash.update(f"{param}{salt}".encode())
        return sign_hash.hexdigest()

    def set_proxy(self, add=None):
        if isinstance(add, str):
            self.proxy_pool.add(add)
        elif isinstance(add, list):
            self.proxy_pool.update(add)
        if self.proxy_pool:
            proxy = random.sample(self.proxy_pool, 1)[0]
            self.proxy = {self.protocol: f"{self.protocol}://{proxy}"}
            # self._log(f"使用{self.protocol.upper()}代理: {proxy}")
        else:
            self.proxy = None
        return self.proxy

    # 登录
    def login(self, **kwargs):
        def by_cookie():
            url = f"{self.protocol}://api.bilibili.com/x/space/myinfo"
            headers = {'Host': "api.bilibili.com"}
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") != -101:
                self._log("Cookie仍有效")
                return True
            else:
                self._log("Cookie已失效")
                return False

        def by_token(force_refresh=False):
            if not force_refresh:
                param = f"access_key={self.access_token}&appkey={Bilibili.app_key}&ts={int(time.time())}"
                url = f"{self.protocol}://passport.bilibili.com/api/v2/oauth2/info?{param}&sign={self.calc_sign(param)}"
                response = self._requests("get", url)
                if response and response.get("code") == 0:
                    self._session.cookies.set('DedeUserID', str(response['data']['mid']), domain=".bilibili.com")
                    self._log(f"Token仍有效, 有效期至{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + int(response['data']['expires_in'])))}")
                    param = f"access_key={self.access_token}&appkey={Bilibili.app_key}&gourl={self.protocol}%3A%2F%2Faccount.bilibili.com%2Faccount%2Fhome&ts={int(time.time())}"
                    url = f"{self.protocol}://passport.bilibili.com/api/login/sso?{param}&sign={self.calc_sign(param)}"
                    self._requests("get", url, decode_level=0)
                    if all(key in self.get_cookies() for key in ["bili_jct", "DedeUserID", "DedeUserID__ckMd5", "sid", "SESSDATA"]):
                        self._log("Cookie获取成功")
                        return True
                    else:
                        self._log("Cookie获取失败")
            url = f"{self.protocol}://passport.bilibili.com/api/v2/oauth2/refresh_token"
            param = f"access_key={self.access_token}&appkey={Bilibili.app_key}&refresh_token={self.refresh_token}&ts={int(time.time())}"
            payload = f"{param}&sign={self.calc_sign(param)}"
            headers = {'Content-type': "application/x-www-form-urlencoded"}
            response = self._requests("post", url, data=payload, headers=headers)
            if response and response.get("code") == 0:
                for cookie in response['data']['cookie_info']['cookies']:
                    self._session.cookies.set(cookie['name'], cookie['value'], domain=".bilibili.com")
                self.access_token = response['data']['token_info']['access_token']
                self.refresh_token = response['data']['token_info']['refresh_token']
                self._log(f"Token刷新成功, 有效期至{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + int(response['data']['token_info']['expires_in'])))}")
                return True
            else:
                self.access_token = ""
                self.refresh_token = ""
                self._log("Token刷新失败")
                return False

        def by_password():
            def get_key():
                url = f"{self.protocol}://passport.bilibili.com/api/oauth2/getKey"
                payload = {
                    'appkey': Bilibili.app_key,
                    'sign': self.calc_sign(f"appkey={Bilibili.app_key}"),
                }
                while True:
                    response = self._requests("post", url, data=payload)
                    if response and response.get("code") == 0:
                        return {
                            'key_hash': response['data']['hash'],
                            'pub_key': rsa.PublicKey.load_pkcs1_openssl_pem(response['data']['key'].encode()),
                        }
                    else:
                        time.sleep(1)

            while True:
                key = get_key()
                key_hash, pub_key = key['key_hash'], key['pub_key']
                url = f"{self.protocol}://passport.bilibili.com/api/v2/oauth2/login"
                param = f"appkey={Bilibili.app_key}&password={parse.quote_plus(base64.b64encode(rsa.encrypt(f'{key_hash}{self.password}'.encode(), pub_key)))}&username={parse.quote_plus(self.username)}"
                payload = f"{param}&sign={self.calc_sign(param)}"
                headers = {'Content-type': "application/x-www-form-urlencoded"}
                response = self._requests("post", url, data=payload, headers=headers)
                while True:
                    if response and response.get("code") is not None:
                        if response['code'] == -105:
                            url = f"{self.protocol}://passport.bilibili.com/captcha"
                            headers = {'Host': "passport.bilibili.com"}
                            response = self._requests("get", url, headers=headers, decode_level=1)
                            captcha = self._solve_captcha(response)
                            if captcha:
                                self._log(f"登录验证码识别结果: {captcha}")
                                key = get_key()
                                key_hash, pub_key = key['key_hash'], key['pub_key']
                                url = f"{self.protocol}://passport.bilibili.com/api/v2/oauth2/login"
                                param = f"appkey={Bilibili.app_key}&captcha={captcha}&password={parse.quote_plus(base64.b64encode(rsa.encrypt(f'{key_hash}{self.password}'.encode(), pub_key)))}&username={parse.quote_plus(self.username)}"
                                payload = f"{param}&sign={self.calc_sign(param)}"
                                headers = {'Content-type': "application/x-www-form-urlencoded"}
                                response = self._requests("post", url, data=payload, headers=headers)
                            else:
                                self._log(f"登录验证码识别服务暂时不可用, {'尝试更换代理' if self.proxy else '10秒后重试'}")
                                if not self.set_proxy():
                                    time.sleep(10)
                                break
                        elif response['code'] == 0 and response['data']['status'] == 0:
                            for cookie in response['data']['cookie_info']['cookies']:
                                self._session.cookies.set(cookie['name'], cookie['value'], domain=".bilibili.com")
                            self.access_token = response['data']['token_info']['access_token']
                            self.refresh_token = response['data']['token_info']['refresh_token']
                            self._log("登录成功")
                            return True
                        else:
                            self._log(f"登录失败 {response}")
                            return False
                    else:
                        self._log(f"当前IP登录过于频繁, {'尝试更换代理' if self.proxy else '1分钟后重试'}")
                        if not self.set_proxy():
                            time.sleep(60)
                        break

        self._session.cookies.clear()
        for name in ["bili_jct", "DedeUserID", "DedeUserID__ckMd5", "sid", "SESSDATA"]:
            value = kwargs.get(name)
            if value:
                self._session.cookies.set(name, value, domain=".bilibili.com")
        self.access_token = kwargs.get("access_token", "")
        self.refresh_token = kwargs.get("refresh_token", "")
        self.username = kwargs.get("username", "")
        self.password = kwargs.get("password", "")
        force_refresh_token = kwargs.get("force_refresh_token", False)
        if (not force_refresh_token or not self.access_token or not self.refresh_token) and all(key in self.get_cookies() for key in ["bili_jct", "DedeUserID", "DedeUserID__ckMd5", "sid", "SESSDATA"]) and by_cookie():
            return True
        elif self.access_token and self.refresh_token and by_token(force_refresh_token):
            return True
        elif self.username and self.password and by_password():
            return True
        else:
            self._session.cookies.clear()
            return False

    # 获取用户信息
    def get_user_info(self):
        url = f"{self.protocol}://api.bilibili.com/x/space/myinfo?jsonp=jsonp"
        headers = {
            'Host': "api.bilibili.com",
            'Referer': f"https://space.bilibili.com/{self.get_uid()}/",
        }
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.info['ban'] = bool(response['data']['silence'])
            self.info['coins'] = response['data']['coins']
            self.info['experience']['current'] = response['data']['level_exp']['current_exp']
            self.info['experience']['next'] = response['data']['level_exp']['next_exp']
            self.info['face'] = response['data']['face']
            self.info['level'] = response['data']['level']
            self.info['nickname'] = response['data']['name']
            self._log(f"{self.info['nickname']}(UID={self.get_uid()}), Lv.{self.info['level']}({self.info['experience']['current']}/{self.info['experience']['next']}), 拥有{self.info['coins']}枚硬币, 账号{'状态正常' if not self.info['ban'] else '被封禁'}")
            return True
        else:
            self._log("用户信息获取失败")
            return False

    # 修改隐私设置
    def set_privacy(self, show_favourite=None, show_bangumi=None, show_tag=None, show_reward=None, show_info=None, show_game=None):
        # show_favourite = 展示[我的收藏夹]
        # show_bangumi = 展示[订阅番剧]
        # show_tag = 展示[订阅标签]
        # show_reward = 展示[最近投币的视频]
        # show_info = 展示[个人资料]
        # show_game = 展示[最近玩过的游戏]
        privacy = {
            'fav_video': show_favourite,
            'bangumi': show_bangumi,
            'tags': show_tag,
            'coins_video': show_reward,
            'user_info': show_info,
            'played_game': show_game,
        }
        url = f"{self.protocol}://space.bilibili.com/ajax/settings/getSettings?mid={self.get_uid()}"
        headers = {
            'Host': "space.bilibili.com",
            'Referer': f"https://space.bilibili.com/{self.get_uid()}/",
        }
        response = self._requests("get", url, headers=headers)
        if response and response.get("status") == True:
            for key, value in privacy.items():
                if response['data']['privacy'][key] == value:
                    privacy[key] = None
        else:
            self._log(f"隐私设置获取失败 {response}")
            return False
        url = f"{self.protocol}://space.bilibili.com/ajax/settings/setPrivacy"
        headers = {
            'Host': "space.bilibili.com",
            'Origin': "https://space.bilibili.com",
            'Referer': f"https://space.bilibili.com/{self.get_uid()}/",
        }
        fail = []
        for key, value in privacy.items():
            if value is not None:
                payload = {
                    key: 1 if value else 0,
                    'csrf': self.get_csrf(),
                }
                response = self._requests("post", url, data=payload, headers=headers)
                if not response or response.get("status") != True:
                    fail.append(key)
        if not fail:
            self._log("隐私设置修改成功")
            return True
        else:
            self._log(f"隐私设置修改失败 {fail}")
            return False

    # 银瓜子兑换硬币
    def silver_to_coin(self, app=True, pc=False):
        # app = APP通道
        # pc = PC通道
        if app:
            param = f"access_key={self.access_token}&appkey={Bilibili.app_key}&ts={int(time.time())}"
            url = f"{self.protocol}://api.live.bilibili.com/AppExchange/silver2coin?{param}&sign={self.calc_sign(param)}"
            response = self._requests("get", url)
            if response and response.get("code") == 0:
                self._log("银瓜子兑换硬币(APP通道)成功")
            else:
                self._log(f"银瓜子兑换硬币(APP通道)失败 {response}")
        if pc:
            url = f"{self.protocol}://api.live.bilibili.com/pay/v1/Exchange/silver2coin"
            payload = {
                'platform': "pc",
                'csrf_token': self.get_csrf(),
            }
            headers = {
                'Host': "api.live.bilibili.com",
                'Origin': "https://live.bilibili.com",
                'Referer': "https://live.bilibili.com/exchange",
            }
            response = self._requests("post", url, data=payload, headers=headers)
            if response and response.get("code") == 0:
                self._log("银瓜子兑换硬币(PC通道)成功")
            else:
                self._log(f"银瓜子兑换硬币(PC通道)失败 {response}")

    # 观看
    def watch(self, aid):
        # aid = 稿件av号
        url = f"{self.protocol}://api.bilibili.com/x/web-interface/view?aid={aid}"
        response = self._requests("get", url)
        if response and response.get("data") is not None:
            cid = response['data']['cid']
            duration = response['data']['duration']
        else:
            self._log(f"av{aid}信息解析失败")
            return False
        url = f"{self.protocol}://api.bilibili.com/x/report/click/h5"
        payload = {
            'aid': aid,
            'cid': cid,
            'part': 1,
            'did': self.get_sid(),
            'ftime': int(time.time()),
            'jsonp': "jsonp",
            'lv': None,
            'mid': self.get_uid(),
            'csrf': self.get_csrf(),
            'stime': int(time.time()),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            url = f"{self.protocol}://api.bilibili.com/x/report/web/heartbeat"
            payload = {
                'aid': aid,
                'cid': cid,
                'jsonp': "jsonp",
                'mid': self.get_uid(),
                'csrf': self.get_csrf(),
                'played_time': 0,
                'pause': False,
                'realtime': duration,
                'dt': 7,
                'play_type': 1,
                'start_ts': int(time.time()),
            }
            response = self._requests("post", url, data=payload, headers=headers)
            if response and response.get("code") == 0:
                time.sleep(5)
                payload['played_time'] = duration - 1
                payload['play_type'] = 0
                payload['start_ts'] = int(time.time())
                response = self._requests("post", url, data=payload, headers=headers)
                if response and response.get("code") == 0:
                    self._log(f"av{aid}观看成功")
                    return True
        self._log(f"av{aid}观看失败 {response}")
        return False

    # 点赞
    def like(self, aid):
        # aid = 稿件av号
        url = f"{self.protocol}://api.bilibili.com/x/web-interface/archive/like"
        payload = {
            'aid': aid,
            'like': 1,
            'csrf': self.get_csrf(),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"av{aid}点赞成功")
            return True
        else:
            self._log(f"av{aid}点赞失败 {response}")
            return False

    # 投币
    def reward(self, aid, double=True):
        # aid = 稿件av号
        # double = 双倍投币
        url = f"{self.protocol}://api.bilibili.com/x/web-interface/coin/add"
        payload = {
            'aid': aid,
            'multiply': 2 if double else 1,
            'cross_domain': "true",
            'csrf': self.get_csrf(),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"av{aid}投{2 if double else 1}枚硬币成功")
            return True
        else:
            self._log(f"av{aid}投{2 if double else 1}枚硬币失败 {response}")
            return self.reward(aid, False) if double else False

    # 收藏
    def favour(self, aid):
        # aid = 稿件av号
        url = f"{self.protocol}://api.bilibili.com/x/v2/fav/folder"
        headers = {'Host': "api.bilibili.com"}
        response = self._requests("get", url, headers=headers)
        if response and response.get("data"):
            fid = response['data'][0]['fid']
        else:
            self._log("fid获取失败")
            return False
        url = f"{self.protocol}://api.bilibili.com/x/v2/fav/video/add"
        payload = {
            'aid': aid,
            'fid': fid,
            'jsonp': "jsonp",
            'csrf': self.get_csrf(),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"av{aid}收藏成功")
            return True
        else:
            self._log(f"av{aid}收藏失败 {response}")
            return False

    # 三连推荐
    def combo(self, aid):
        # aid = 稿件av号
        url = f"{self.protocol}://api.bilibili.com/x/web-interface/archive/like/triple"
        payload = {
            'aid': aid,
            'csrf': self.get_csrf(),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"av{aid}三连推荐成功")
            return True
        else:
            self._log(f"av{aid}三连推荐失败 {response}")
            return False

    # 分享
    def share(self, aid):
        # aid = 稿件av号
        url = f"{self.protocol}://api.bilibili.com/x/web-interface/share/add"
        payload = {
            'aid': aid,
            'jsonp': "jsonp",
            'csrf': self.get_csrf(),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"av{aid}分享成功")
            return True
        else:
            self._log(f"av{aid}分享失败 {response}")
            return False

    # 关注
    def follow(self, mid, secret=False):
        # mid = 被关注用户UID
        # secret = 悄悄关注
        url = f"{self.protocol}://api.bilibili.com/x/relation/modify"
        payload = {
            'fid': mid,
            'act': 3 if secret else 1,
            're_src': 11,
            'jsonp': "jsonp",
            'csrf': self.get_csrf(),
        }
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://space.bilibili.com",
            'Referer': f"https://space.bilibili.com/{mid}/",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"用户{mid}{'悄悄' if secret else ''}关注成功")
            return True
        else:
            self._log(f"用户{mid}{'悄悄' if secret else ''}关注失败 {response}")
            return False

    # 弹幕发送
    def danmaku_post(self, aid, message, page=1, moment=-1):
        # aid = 稿件av号
        # message = 弹幕内容
        # page = 分P
        # moment = 弹幕发送时间
        url = f"{self.protocol}://api.bilibili.com/x/web-interface/view?aid={aid}"
        response = self._requests("get", url)
        if response and response.get("data") is not None:
            page_info = {page['page']: {
                'cid': page['cid'],
                'duration': page['duration'],
            } for page in response['data']['pages']}
            if page in page_info:
                oid = page_info[page]['cid']
                duration = page_info[page]['duration']
            else:
                self._log(f"av{aid}不存在P{page}")
                return False
        else:
            self._log(f"av{aid}信息解析失败")
            return False
        url = f"{self.protocol}://api.bilibili.com/x/v2/dm/post"
        headers = {
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        while True:
            payload = {
                'type': 1,
                'oid': oid,
                'msg': message,
                'aid': aid,
                'progress': int(moment * 1E3) if moment != -1 else random.randint(0, duration * 1E3),
                'color': 16777215,
                'fontsize': 25,
                'pool': 0,
                'mode': 1,
                'rnd': int(time.time() * 1E6),
                'plat': 1,
                'csrf': self.get_csrf(),
            }
            response = self._requests("post", url, data=payload, headers=headers)
            if response and response.get("code") is not None:
                if response['code'] == 0:
                    self._log(f"av{aid}(P{page})弹幕\"{message}\"发送成功")
                    return True
                elif response['code'] == 36703:
                    self._log(f"av{aid}(P{page})弹幕发送频率过快, 10秒后重试")
                    time.sleep(10)
                else:
                    self._log(f"av{aid}(P{page})弹幕\"{message}\"发送失败 {response}")
                    return False

    # 评论点赞
    def comment_like(self, otype, oid, rpid):
        # otype = 作品类型
        # oid = 作品ID
        # rpid = 评论ID
        if Bilibili.patterns.get(otype) is None:
            return False
        url = f"{self.protocol}://api.bilibili.com/x/v2/reply/action"
        payload = {
            'oid': oid,
            'type': Bilibili.patterns[otype]['id'],
            'rpid': rpid,
            'action': 1,
            'jsonp': "jsonp",
            'csrf': self.get_csrf(),
        }
        headers = {
            'Content-Type': "application/x-www-form-urlencoded; charset=UTF-8",
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"{Bilibili.patterns[otype]['prefix']}{oid}",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"评论{rpid}点赞成功")
            return True
        else:
            self._log(f"评论{rpid}点赞失败 {response}")
            return False

    # 评论发表
    def comment_post(self, otype, oid, message):
        # otype = 作品类型
        # oid = 作品ID
        # message = 评论内容
        if Bilibili.patterns.get(otype) is None:
            return False
        url = f"{self.protocol}://api.bilibili.com/x/v2/reply/add"
        while True:
            payload = {
                'oid': oid,
                'type': Bilibili.patterns[otype]['id'],
                'message': message,
                'plat': 1,
                'jsonp': "jsonp",
                'csrf': self.get_csrf(),
            }
            headers = {
                'Content-Type': "application/x-www-form-urlencoded; charset=UTF-8",
                'Host': "api.bilibili.com",
                'Origin': "https://www.bilibili.com",
                'Referer': f"{Bilibili.patterns[otype]['prefix']}{oid}",
            }
            response = self._requests("post", url, data=payload, headers=headers)
            if response and response.get("code") is not None:
                if response['code'] == 0:
                    self._log(f"作品{oid}提交评论\"{message}\"成功")
                    return True
                elif response['code'] == 12015:
                    response = self._requests("get", response['data']['url'], headers=headers, decode_level=1)
                    captcha = self._solve_captcha(response)
                    if captcha:
                        self._log(f"评论验证码识别结果: {captcha}")
                        payload['code'] = captcha
                    else:
                        self._log(f"评论验证码识别服务暂时不可用, 1分钟后重试")
                        time.sleep(60)
                elif response['code'] == 12035:
                    self._log(f"作品{oid}提交评论\"{message}\"失败, 该账号被UP主列入评论黑名单")
                    return False
                elif response['code'] == -105:
                    if "code" in payload:
                        payload.pop("code")
                else:
                    self._log(f"作品{oid}提交评论\"{message}\"失败 {response}")
                    return False

    # 动态点赞
    def dynamic_like(self, did):
        # did = 动态ID
        url = f"{self.protocol}://api.vc.bilibili.com/dynamic_like/v1/dynamic_like/thumb"
        payload = {
            'uid': self.get_uid(),
            'dynamic_id': did,
            'up': 1,
            'csrf_token': self.get_csrf(),
        }
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Host': "api.vc.bilibili.com",
            'Origin': "https://space.bilibili.com",
            'Referer': "https://space.bilibili.com/208259/",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"动态{did}点赞成功")
            return True
        else:
            self._log(f"动态{did}点赞失败 {response}")
            return False

    # 动态转发
    def dynamic_repost(self, did, message="转发动态", ats=[]):
        # did = 动态ID
        # message = 转发内容
        # ats = 被@用户UID列表
        def uid_to_nickname(mid):
            url = f"{self.protocol}://api.bilibili.com/x/web-interface/card?mid={mid}"
            response = self._requests("get", url)
            if response and response.get("code") == 0:
                return response['data']['card']['name']
            else:
                return ""

        url = f"{self.protocol}://api.vc.bilibili.com/dynamic_repost/v1/dynamic_repost/repost"
        ctrl = []
        for at in zip(ats, [uid_to_nickname(mid) for mid in ats]):
            ctrl.append({
                'data': str(at[0]),
                'location': len(message) + 1,
                'length': len(at[1]) + 1,
                'type': 1,
            })
            message = f"{message} @{at[1]}"
        payload = {
            'uid': self.get_uid(),
            'dynamic_id': did,
            'content': message,
            'at_uids': ",".join([str(at) for at in ats]),
            'ctrl': json.dumps(ctrl),
            'csrf_token': self.get_csrf(),
        }
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Host': "api.vc.bilibili.com",
            'Origin': "https://space.bilibili.com",
            'Referer': "https://space.bilibili.com/208259/",
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self._log(f"动态{did}转发成功")
            return True
        else:
            self._log(f"动态{did}转发失败 {response}")
            return False

    # 动态清理
    def dynamic_purge(self):
        def get_lottery_dynamics():
            headers = {
                'Host': "api.vc.bilibili.com",
                'Origin': "https://space.bilibili.com",
                'Referer': f"https://space.bilibili.com/{self.get_uid()}/dynamic",
            }
            dynamics = []
            offset = 0
            while True:
                url = f"{self.protocol}://api.vc.bilibili.com/dynamic_svr/v1/dynamic_svr/space_history?visitor_uid={self.get_uid()}&host_uid={self.get_uid()}&offset_dynamic_id={offset}"
                response = self._requests("get", url, headers=headers)
                if response and response.get("code") == 0:
                    if response['data']['has_more']:
                        dynamics.extend([{
                            'did': card['desc']['dynamic_id'],
                            'lottery_did': card['desc']['orig_dy_id'],
                        } for card in response['data']['cards'] if card['desc']['orig_type'] == 2 or card['desc']['orig_type'] == 1024])
                        offset = response['data']['cards'][-1]['desc']['dynamic_id']
                    else:
                        return dynamics

        dynamics = get_lottery_dynamics()
        self._log(f"发现{len(dynamics)}条互动抽奖动态")
        delete = 0
        for dynamic in dynamics:
            url = f"{self.protocol}://api.vc.bilibili.com/lottery_svr/v2/lottery_svr/lottery_notice?dynamic_id={dynamic['lottery_did']}"
            headers = {
                'Host': "api.vc.bilibili.com",
                'Origin': "https://t.bilibili.com",
                'Referer': "https://t.bilibili.com/lottery/h5/index/",
            }
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                expired = response['data']['status'] == 2 or response['data']['status'] == -1
                winning = any(self.get_uid() in winners for winners in [response['data'].get("lottery_result", {}).get(f"{level}_prize_result", []) for level in ["first", "second", "third"]])
                if not expired:
                    self._log(f"动态{dynamic['lottery_did']}尚未开奖({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(response['data']['lottery_time']))}), 跳过")
                else:
                    if winning:
                        self._log(f"动态{dynamic['lottery_did']}中奖, 跳过")
                    else:
                        url = f"{self.protocol}://api.vc.bilibili.com/dynamic_repost/v1/dynamic_repost/rm_rp_dyn"
                        payload = {
                            'uid': self.get_uid(),
                            'dynamic_id': dynamic['did'],
                            'csrf_token': self.get_csrf(),
                        }
                        headers = {
                            'Content-Type': "application/x-www-form-urlencoded",
                            'Host': "api.vc.bilibili.com",
                            'Origin': "https://space.bilibili.com",
                            'Referer': f"https://space.bilibili.com/{self.get_uid()}/dynamic",
                        }
                        response = self._requests("post", url, data=payload, headers=headers)
                        if response and response.get("code") == 0:
                            delete += 1
                            self._log(f"动态{dynamic['lottery_did']}未中奖, 清理成功")
                        else:
                            self._log(f"动态{dynamic['lottery_did']}未中奖, 清理失败")
            time.sleep(1)
        self._log(f"清理了{delete}条动态")

    # 系统通知查询
    def system_notice(self, time_span=["", ""], keyword=[]):
        # time_span = 时间范围
        # keyword = 包含关键字
        cursor_span = [int(time.mktime(time.strptime(element, "%Y-%m-%d %H:%M:%S")) * 1E9) if element else "" for element in time_span]
        headers = {
            'Host': "message.bilibili.com",
            'Referer': "https://message.bilibili.com/",
        }
        notice_list = []
        cursor = cursor_span[1]
        while True:
            url = f"{self.protocol}://message.bilibili.com/api/notify/query.sysnotify.list.do?data_type=1{'&cursor=' + str(cursor) if cursor else ''}"
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                for notice in response['data']:
                    if not cursor_span[0] or notice['cursor'] > cursor_span[0]:
                        if not keyword or any(keyword in notice['title'] or keyword in notice['content'] for keyword in keyword):
                            notice_list.append({
                                'time': notice['time_at'],
                                'title': notice['title'],
                                'content': notice['content'],
                            })
                    else:
                        break
                else:
                    if len(response['data']) == 20:
                        cursor = notice['cursor']
                        continue
                self._log(f"系统通知获取成功, 总计{len(notice_list)}条通知")
                for notice in notice_list:
                    self._log(f"{notice['title']}({notice['time']}): {notice['content']}")
                self.__push_to_queue("system_notice", notice_list)
                return notice_list

    # 会员购抢购
    def mall_rush(self, item_id, thread=1, headless=True, timeout=10):
        # item_id = 商品ID
        # thread = 线程数
        # headless = 隐藏窗口
        # timeout = 超时刷新
        def executor(thread_id):
            def find_and_click(class_name):
                try:
                    element = driver.find_element_by_class_name(class_name)
                    element.click()
                except:
                    element = None
                return element

            options = webdriver.ChromeOptions()
            options.add_argument("log-level=3")
            if headless:
                options.add_argument("headless")
            else:
                options.add_argument("disable-infobars")
                options.add_argument("window-size=374,729")
            if platform.system() == "Linux":
                options.add_argument("no-sandbox")
            options.add_experimental_option("mobileEmulation", {'deviceName': "Nexus 5"})
            if platform.system() == "Windows":
                options.binary_location = "chrome-win\\chrome.exe"
            driver = webdriver.Chrome(executable_path="chromedriver.exe" if platform.system() == "Windows" else "chromedriver", options=options)
            driver.get(f"{self.protocol}://mall.bilibili.com/detail.html?itemsId={item_id}")
            for key, value in self.get_cookies().items():
                driver.add_cookie({
                    'name': key,
                    'value': value,
                    'domain': ".bilibili.com",
                })
            self._log(f"(线程{thread_id})商品{item_id}开始监视库存")
            url = f"{self.protocol}://mall.bilibili.com/mall-c/items/info?itemsId={item_id}"
            while True:
                response = self._requests("get", url)
                if response and response.get("code") == 0 and response['data']['activityInfoVO']['serverTime'] >= response['data']['activityInfoVO']['startTime'] if response['data']['activityInfoVO'] else True:
                    break
            timestamp = time.time()
            in_stock = False
            while True:
                try:
                    result = {class_name: find_and_click(class_name) for class_name in ["bottom-buy-button", "button", "dot", "pay-btn", "expire-time-format", "alert-ok", "error-button"]}
                    if result['bottom-buy-button']:
                        if "bottom-buy-disable" not in result['bottom-buy-button'].get_attribute("class"):
                            if not in_stock:
                                self._log(f"(线程{thread_id})商品{item_id}已开放购买")
                                in_stock = True
                        else:
                            if in_stock:
                                self._log(f"(线程{thread_id})商品{item_id}暂无法购买, 原因为{result['bottom-buy-button'].text}")
                                in_stock = False
                            driver.refresh()
                            timestamp = time.time()
                    if result['pay-btn']:
                        timestamp = time.time()
                    if result['alert-ok']:
                        driver.refresh()
                    if result['expire-time-format']:
                        self._log(f"(线程{thread_id})商品{item_id}订单提交成功, 请在{result['expire-time-format'].text}内完成支付")
                        driver.quit()
                        return True
                    if time.time() - timestamp > timeout:
                        self._log(f"(线程{thread_id})商品{item_id}操作超时, 当前页面为{driver.current_url}")
                        driver.get(f"{self.protocol}://mall.bilibili.com/detail.html?itemsId={item_id}")
                        timestamp = time.time()
                except:
                    pass

        threads = []
        for i in range(thread):
            threads.append(threading.Thread(target=executor, args=(i + 1,)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    # 会员购优惠卷领取
    def mall_coupon(self, coupon_id, thread=1):
        # coupon_id = 优惠券ID
        # thread = 线程数
        def get_coupon_info(coupon_id):
            url = f"{self.protocol}://mall.bilibili.com/mall-c/coupon/user_coupon_code_receive_status_list"
            payload = {
                'couponIds': [str(coupon_id)],
                'mid': "",
                'csrf': self.get_csrf(),
            }
            headers = {
                'Host': "mall.bilibili.com",
                'Origin': "https://www.bilibili.com",
            }
            response = self._requests("post", url, json=payload, headers=headers)
            if response and response.get("code") == 0:
                return {
                    'end': response['data'][0]['receiveEndTime'],
                    'message': response['data'][0]['couponStatusMsg'],
                    'name': response['data'][0]['couponName'],
                    'total': response['data'][0]['provideNum'],
                    'remain': response['data'][0]['remainNum'],
                    'start': response['data'][0]['receiveStartTime'],
                    'status': response['data'][0]['receiveStatus'],
                }

        def get_server_time(target_time=0):
            url = f"{self.protocol}://mall.bilibili.com/mall-c/common/time/remain?v={int(time.time())}&targetTime={target_time}"
            headers = {
                'Host': "mall.bilibili.com",
                'Origin': "https://www.bilibili.com",
            }
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                return {
                    'current': response['data']['serverTime'],
                    'remain': response['data']['remainSeconds'],
                }

        def executor(thread_id):
            url = f"{self.protocol}://mall.bilibili.com/mall-c/coupon/create_coupon_code?couponId={coupon_id}&deviceId="
            payload = {'csrf': self.get_csrf()}
            headers = {
                'Host': "mall.bilibili.com",
                'Origin': "https://www.bilibili.com",
            }
            nonlocal flag
            while not flag:
                response = self._requests("post", url, json=payload, headers=headers)
                if response and response.get("code") is not None:
                    if response['code'] == 83094004:
                        self._log(f"(线程{thread_id})会员购优惠卷\"{coupon_info['name']}\"(ID={coupon_id})领取成功")
                    elif response['code'] == 83110005:
                        self._log(f"(线程{thread_id})会员购优惠卷\"{coupon_info['name']}\"(ID={coupon_id})领取失败, 优惠券领取数量已达到上限")
                    elif response['code'] == 83110015:
                        self._log(f"(线程{thread_id})会员购优惠卷\"{coupon_info['name']}\"(ID={coupon_id})领取失败, 优惠券库存不足")
                    else:
                        continue
                else:
                    self._log(f"(线程{thread_id})会员购优惠卷\"{coupon_info['name']}\"(ID={coupon_id})领取失败, 当前IP请求过于频繁")
                flag = True

        coupon_info = get_coupon_info(coupon_id)
        if coupon_info:
            if coupon_info['message'] == "可领取":
                server_time = get_server_time(coupon_info['start'])
                if server_time:
                    delay = max(server_time['remain'] - 3, 0)
                    self._log(f"会员购优惠卷\"{coupon_info['name']}\"(ID={coupon_id})可领取时间为{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(coupon_info['start']))}至{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(coupon_info['end']))}, 库存{coupon_info['remain']}张, 将于{delay}秒后开始领取")
                    time.sleep(delay)
                else:
                    self._log(f"会员购服务器时间获取失败")
                    return
            else:
                self._log(f"会员购优惠卷\"{coupon_info['name']}\"(ID={coupon_id}){coupon_info['message']}")
                return
        else:
            self._log(f"会员购优惠卷{coupon_id}信息获取失败")
            return
        flag = False
        threads = []
        for i in range(thread):
            threads.append(threading.Thread(target=executor, args=(i + 1,)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    # 会员购订单列表查询
    def mall_order_list(self, status=0, type=[2]):
        # status = 订单状态
        # type = 订单类型
        def get_order_list(status, type):
            headers = {
                'Origin': "https://mall.bilibili.com",
                'Referer': "https://mall.bilibili.com/orderlist.html",
            }
            order_list = []
            page = 0
            while True:
                url = f"{self.protocol}://show.bilibili.com/api/ticket/ordercenter/list?pageNum={page}&pageSize=20&status={status}&customer=0&platform=h5&v={int(time.time())}"
                response = self._requests("get", url, headers=headers)
                if response and response.get("errno") == 0:
                    data = response['data']['list']
                    if data:
                        for order in data:
                            if not type or order['order_type'] in type:
                                order_list.append(order)
                        page += 1
                    else:
                        self._log(f"会员购订单列表获取成功, 总计{len(order_list)}个订单")
                        break
                else:
                    self._log(f"会员购订单列表获取失败 {response}")
            return order_list

        def get_order_detail(order_id):
            url = f"{self.protocol}://mall.bilibili.com/mall-c/order/detail?orderId={order_id}&platform=h5&time={int(time.time())}"
            headers = {
                'Origin': "https://mall.bilibili.com",
                'Referer': f"https://mall.bilibili.com/orderdetail.html?orderId={order_id}",
            }
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0 and response['data']['vo']:
                data = response['data']['vo']
                self._log(f"会员购订单{order_id}详情获取成功, 包含\"{data['skuList'][0]['itemsName']}\"等{len(data['skuList'])}件商品")
                return data
            else:
                self._log(f"会员购订单{order_id}详情获取失败 {response}")
                return {}

        def get_order_express(order_id):
            url = f"{self.protocol}://mall.bilibili.com/mall-c/order/express/detail?orderId={order_id}"
            headers = {
                'Origin': "https://mall.bilibili.com",
                'Referer': f"https://mall.bilibili.com/orderdetail.html?orderId={order_id}",
            }
            for _ in range(5):
                response = self._requests("get", url, headers=headers)
                if response and response.get("code") == 0 and response['data']['vo']:
                    data = response['data']['vo']
                    self._log(f"会员购订单{order_id}物流获取成功, 状态为{data['state_v']}")
                    return data
                time.sleep(3)
            self._log(f"会员购订单{order_id}物流获取失败 {response}")
            return {}

        order_list = []
        for order in get_order_list(status, type):
            order_detail = get_order_detail(order['order_id'])
            order_express = get_order_express(order['order_id']) if order_detail and order_detail['orderExpress'] else {}
            order_list.append({
                'id': order.get("order_id"),
                'item': [{
                    'id': item.get("itemsId"),
                    'name': item.get("itemsName"),
                    'spec': item.get("skuSpec"),
                    'number': item.get("skuNum"),
                    'price': item.get("price"),
                } for item in order_detail.get("skuList", [])],
                'create': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(order.get("order_ctime"))) if order.get("current_timestamp") else None,
                'status': {
                    'code': order.get("status"),
                    'name': order.get("status_name"),
                },
                'pay': {
                    'id': order_detail['orderBasic'].get("payId") if order_detail.get("orderBasic") else None,
                    'time': order.get("pay_ctime") if order.get("pay_ctime") != "0000-00-00 00:00:00" else None,
                    'channel': order_detail['orderBasic'].get("paymentChannel") if order_detail.get("orderBasic") else None,
                    'total': order.get("show_money") / 100 if order.get("show_money") else None,
                    'origin': order_detail['orderBasic'].get("payTotalMoney") if order_detail.get("orderBasic") else None,
                    'discount': order_detail['orderBasic'].get("discountMoneys") if order_detail.get("orderBasic") else None,
                    'express': order.get("express_fee") / 100 if order.get("express_fee") else None,
                },
                'preorder': {
                    'phone': order_detail['extData'].get("notifyPhoneOrigin") if order_detail.get("extData") else None,
                    'front': {
                        'total': order_detail['extData'].get("frontPayMoney") if order_detail.get("extData") else None,
                        'origin': order_detail['extData'].get("frontMoney") if order_detail.get("extData") else None,
                        'discount': order_detail['extData'].get("frontDisMoney") if order_detail.get("extData") else None,
                    },
                    'final': {
                        'total': order_detail['extData'].get("finalPayMoney") if order_detail.get("extData") else None,
                        'origin': order_detail['extData'].get("finalMoney") if order_detail.get("extData") else None,
                        'discount': order_detail['extData'].get("finalDisMoney") if order_detail.get("extData") else None,
                        'start': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(order_detail['extData'].get("finalMoneyStart") / 1E3)) if order_detail.get("extData") and order_detail['extData'].get("finalMoneyStart") else None,
                        'end': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(order_detail['extData'].get("finalMoneyEnd") / 1E3)) if order_detail.get("extData") and order_detail['extData'].get("finalMoneyStart") else None,
                    },
                },
                'shipping': {
                    'name': order_detail['orderDeliver'].get("deliverName") if order_detail.get("orderDeliver") else None,
                    'phone': order_detail['orderDeliver'].get("deliverPhone") if order_detail.get("orderDeliver") else None,
                    'address': order_detail['orderDeliver'].get("deliverAddr") if order_detail.get("orderDeliver") else None,
                    'company': order_detail['orderExpress'].get("com_v") if order_detail.get("orderExpress") else None,
                    'number': order_detail['orderExpress'].get("sno") if order_detail.get("orderExpress") else None,
                    'status': order_express.get("state_v"),
                    'detail': order_express.get("detail"),
                },
            })
        self.__push_to_queue("mall_order_list", order_list)
        return order_list

    # 会员购优惠券列表查询
    def mall_coupon_list(self, status=1):
        # status = 优惠券状态
        status_map = {
            1: "validList",
            2: "usedList",
            3: "invalidList",
        }
        if status not in status_map:
            return []
        headers = {
            'Referer': "https://mall.bilibili.com/couponlist.html?noTitleBar=1",
        }
        coupon_list = []
        page = 1
        while True:
            url = f"{self.protocol}://mall.bilibili.com/mall-c/coupon/list?status={status}&pageIndex={page}&pageSize=20"
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                if response['data'][status_map[status]]:
                    for coupon in response['data'][status_map[status]]['list']:
                        coupon_list.append({
                            'name': coupon['couponCodeName'],
                            'description': coupon['couponDesc'],
                            'detail': coupon['couponDetail'],
                            'discount': coupon['couponDiscount'],
                            'status': coupon['status'],
                            'type': coupon['couponCodeType'],
                            'start': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(coupon['useStartTime'] / 1E3)) if coupon['useStartTime'] else None,
                            'end': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(coupon['useEndTime'] / 1E3)) if coupon['useEndTime'] else None,
                            'use': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(coupon['useTime'] / 1E3)) if coupon['useTime'] else None,
                            'expire': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(coupon['expireDate'] / 1E3)) if coupon['expireDate'] else None,
                        })
                    if response['data'][status_map[status]]['hasNextPage']:
                        page += 1
                        continue
                self._log(f"会员购优惠券列表获取成功, 总计{len(coupon_list)}张优惠券")
                for coupon in coupon_list:
                    self._log(f"会员购优惠券: {coupon['name']}" + (f", 失效时间为{coupon['expire']}" if coupon['expire'] else f", 使用时间为{coupon['use']}" if coupon['use'] else f", 使用有效期为{coupon['start']}至{coupon['end']}" if coupon['start'] and coupon['end'] else ""))
                break
            else:
                self._log(f"会员购优惠券列表获取失败 {response}")
                break
        self.__push_to_queue("mall_coupon_list", coupon_list)
        return coupon_list

    # 会员购奖品列表查询
    def mall_prize_list(self, status=0, type=[1, 2]):
        # status = 奖品状态
        # type = 奖品类型
        headers = {
            'Referer': "https://mall.bilibili.com/prizecenter.html",
        }
        prize_list = []
        page = 1
        while True:
            url = f"{self.protocol}://mall.bilibili.com/mall-c/prize/list?pageNum={page}&pageSize=20&type={status}&v={int(time.time())}"
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                for prize in response['data']['pageInfo']['list']:
                    if not type or prize['prizeType'] in type:
                        prize_list.append({
                            'name': prize['prizeName'],
                            'source': prize['sourceName'],
                            'status': prize['status'],
                            'type': prize['prizeType'],
                            'expire': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(prize['expireTime'])),
                        })
                if response['data']['pageInfo']['hasNextPage']:
                    page += 1
                else:
                    self._log(f"会员购奖品列表获取成功, 总计{len(prize_list)}个奖品, {response['data']['waitDeliveryNum']}个奖品待发货")
                    for prize in prize_list:
                        self._log(f"会员购奖品: {prize['name']}, 来自{prize['source']}, 领取有效期至{prize['expire']}")
                    break
            else:
                self._log(f"会员购奖品列表获取失败 {response}")
                break
        self.__push_to_queue("mall_prize_list", prize_list)
        return prize_list

    # 直播奖品列表查询
    def live_prize_list(self):
        headers = {
            'Origin': "https://link.bilibili.com",
            'Referer': "https://link.bilibili.com/p/center/index",
        }
        prize_list = []
        page = 1
        while True:
            url = f"{self.protocol}://api.live.bilibili.com/lottery/v1/award/award_list?page={page}&month="
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                for prize in response['data']['list']:
                    prize_list.append({
                        'name': prize['gift_name'],
                        'number': prize['gift_num'],
                        'source': prize['source'],
                        'status': prize['status'],
                        'type': prize['gift_type'],
                        'create': prize['create_time'],
                        'expire': prize['expire_time'],
                    })
                if page < response['data']['total_page']:
                    page += 1
                else:
                    self._log(f"直播奖品列表获取成功, 总计{len(prize_list)}个奖品")
                    for prize in prize_list:
                        self._log(f"直播奖品: {prize['name']} x{prize['number']}, 来自{prize['source']}, 中奖时间为{prize['create']}, 领取有效期至{prize['expire']}")
                    break
            else:
                self._log(f"直播奖品列表获取失败 {response}")
                break
        self.__push_to_queue("live_prize_list", prize_list)
        return prize_list

def detect_charset(file, fallback="utf-8"):
    with open(file, "rb") as f:
        detector = chardet.UniversalDetector()
        for line in f.readlines():
            detector.feed(line)
            if detector.done:
                return detector.result['encoding']
    return fallback

def download(url, save_as=None):
    print(f"正在下载{url}")
    if save_as is None:
        save_as = url.split("/")[-1]
    with open(save_as, "wb") as f:
        response = requests.get(url, stream=True)
        length = response.headers.get("content-length")
        if length:
            length = int(length)
            receive = 0
            for data in response.iter_content(chunk_size=100 * 1024):
                f.write(data)
                receive += len(data)
                percent = receive / length
                print(f"\r[{'=' * int(50 * percent)}{' ' * (50 - int(50 * percent))}] {percent:.0%}", end="", flush=True)
            print()
        else:
            f.write(response.content)
    return save_as

def decompress(file, remove=True):
    shutil.unpack_archive(file)
    if remove:
        os.remove(file)
    print(f"{file}解压完毕")

def export(queue, config):
    bucket = {}
    log_file = open(config['global']['log'], "a", encoding="utf-8") if config['global']['log'] else None
    try:
        while True:
            packet = queue.get()
            if isinstance(packet, dict) and all(key in packet for key in ['uid', 'manufacturer', 'data']):
                if packet['manufacturer'] == "log":
                    if log_file:
                        log_file.write(packet['data'] + "\n")
                else:
                    if packet['manufacturer'] not in bucket:
                        bucket[packet['manufacturer']] = {}
                    if packet['uid'] not in bucket[packet['manufacturer']]:
                        bucket[packet['manufacturer']][packet['uid']] = []
                    if isinstance(packet['data'], list):
                        bucket[packet['manufacturer']][packet['uid']].extend(packet['data'])
                    else:
                        bucket[packet['manufacturer']][packet['uid']].append(packet['data'])
            elif packet is None:
                for manufacturer, data in bucket.items():
                    if config.get(manufacturer, {}).get("export"):
                        with open(config[manufacturer]['export'], "w", encoding="utf-8") as f:
                            f.write(json.dumps(data, indent=4, ensure_ascii=False))
                return
    finally:
        if log_file:
            log_file.close()

def wrapper(arg):
    def delay_wrapper(func, interval, arg_list=[()], shuffle=False):
        if shuffle:
            random.shuffle(arg_list)
        for i in range(len(arg_list)):
            func(*arg_list[i])
            if i < len(arg_list) - 1:
                time.sleep(interval)

    config, account, queue = arg['config'], arg['account'], arg['queue']
    instance = Bilibili(config['global']['https'], queue)
    if config['proxy']['enable']:
        if isinstance(config['proxy']['pool'], str):
            try:
                with open(config['proxy']['pool'], "r", encoding=detect_charset(config['proxy']['pool'])) as f:
                    instance.set_proxy(add=[proxy for proxy in f.read().strip().splitlines() if proxy and proxy[0] != "#"])
            except:
                pass
        elif isinstance(config['proxy']['pool'], list):
            instance.set_proxy(add=config['proxy']['pool'])
    if instance.login(force_refresh_token=config['user']['force_refresh_token'], **account):
        threads = []
        if config['get_user_info']['enable']:
            threads.append(threading.Thread(target=instance.get_user_info))
        if config['set_privacy']['enable']:
            threads.append(threading.Thread(target=instance.set_privacy, args=(config['set_privacy']['show_favourite'], config['set_privacy']['show_bangumi'], config['set_privacy']['show_tag'], config['set_privacy']['show_reward'], config['set_privacy']['show_info'], config['set_privacy']['show_game'])))
        if config['silver_to_coin']['enable']:
            threads.append(threading.Thread(target=instance.silver_to_coin))
        if config['watch']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.watch, 5, list(zip(config['watch']['aid'])))))
        if config['like']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.like, 5, list(zip(config['like']['aid'])))))
        if config['reward']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.reward, 5, list(zip(config['reward']['aid'], config['reward']['double'])))))
        if config['favour']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.favour, 5, list(zip(config['favour']['aid'])))))
        if config['combo']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.combo, 5, list(zip(config['combo']['aid'])))))
        if config['share']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.share, 5, list(zip(config['share']['aid'])))))
        if config['follow']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.follow, 5, list(zip(config['follow']['mid'], config['follow']['secret'])))))
        if config['danmaku_post']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.danmaku_post, 5, list(zip(config['danmaku_post']['aid'], config['danmaku_post']['message'], config['danmaku_post']['page'], config['danmaku_post']['moment'])))))
        if config['comment_like']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.comment_like, 5, list(zip(config['comment_like']['otype'], config['comment_like']['oid'], config['comment_like']['rpid'])))))
        if config['comment_post']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.comment_post, 5, list(zip(config['comment_post']['otype'], config['comment_post']['oid'], config['comment_post']['message'])))))
            # for comment in zip(config['comment_post']['otype'], config['comment_post']['oid'], config['comment_post']['message']):
            #     threads.append(threading.Thread(target=instance.comment_post, args=(comment[0], comment[1], comment[2])))
        if config['dynamic_like']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.dynamic_like, 5, list(zip(config['dynamic_like']['did'])))))
        if config['dynamic_repost']['enable']:
            threads.append(threading.Thread(target=delay_wrapper, args=(instance.dynamic_repost, 5, list(zip(config['dynamic_repost']['did'], config['dynamic_repost']['message'], config['dynamic_repost']['ats'])))))
        if config['dynamic_purge']['enable']:
            threads.append(threading.Thread(target=instance.dynamic_purge))
        if config['system_notice']['enable']:
            threads.append(threading.Thread(target=instance.system_notice, args=(config['system_notice']['time_span'], config['system_notice']['keyword'])))
        if config['mall_rush']['enable']:
            for item in zip(config['mall_rush']['item_id'], config['mall_rush']['thread']):
                threads.append(threading.Thread(target=instance.mall_rush, args=(item[0], item[1], config['mall_rush']['headless'], config['mall_rush']['timeout'])))
        if config['mall_coupon']['enable']:
            for coupon in zip(config['mall_coupon']['coupon_id'], config['mall_coupon']['thread']):
                threads.append(threading.Thread(target=instance.mall_coupon, args=(coupon[0], coupon[1])))
        if config['mall_order_list']['enable']:
            threads.append(threading.Thread(target=instance.mall_order_list, args=(config['mall_order_list']['status'], config['mall_order_list']['type'])))
        if config['mall_coupon_list']['enable']:
            threads.append(threading.Thread(target=instance.mall_coupon_list, args=(config['mall_coupon_list']['status'],)))
        if config['mall_prize_list']['enable']:
            threads.append(threading.Thread(target=instance.mall_prize_list, args=(config['mall_prize_list']['status'], config['mall_prize_list']['type'])))
        if config['live_prize_list']['enable']:
            threads.append(threading.Thread(target=instance.live_prize_list))
        # instance._log("任务开始执行")
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # instance._log("任务执行完毕")
    return {
        'username': instance.username,
        'password': instance.password,
        'access_token': instance.access_token,
        'refresh_token': instance.refresh_token,
        'cookie': instance.get_cookies(),
    }

def main():
    print(f"{banner}\n{__doc__}\n版本: {__version__}\n")
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.toml"
    try:
        with open(config_file, "r", encoding=detect_charset(config_file)) as f:
            config = toml.load(f)
    except:
        print(f"无法加载{config_file}")
        return
    accounts = []
    for line in config['user']['account'].splitlines():
        try:
            if line[0] == "#":
                continue
            pairs = {}
            for pair in line.strip(";").split(";"):
                if len(pair.split("=")) == 2:
                    key, value = pair.split("=")
                    pairs[key] = value
            password = all(key in pairs for key in ["username", "password"])
            token = all(key in pairs for key in ["access_token", "refresh_token"])
            cookie = all(key in pairs for key in ["bili_jct", "DedeUserID", "DedeUserID__ckMd5", "sid", "SESSDATA"])
            if password or token or cookie:
                accounts.append(pairs)
        except:
            pass
    config['user'].pop("account")
    print(f"导入了{len(accounts)}个用户")
    if not accounts:
        return
    if config['mall_rush']['enable']:
        if platform.system() == "Linux" and os.path.exists("/etc/debian_version"):
            prefix = "sudo " if shutil.which("sudo") else ""
            if shutil.which("chromium-browser") is None:
                os.system(f"{prefix}apt -y install chromium-browser")
            if shutil.which("chromedriver") is None:
                os.system(f"{prefix}apt -y install chromium-chromedriver")
                os.system(f"{prefix}ln -s /usr/lib/chromium-browser/chromedriver /usr/bin")
        elif platform.system() == "Linux" and os.path.exists("/etc/redhat-release"):
            prefix = "sudo " if shutil.which("sudo") else ""
            if shutil.which("chromium-browser") is None:
                os.system(f"{prefix}yum -y install chromium")
            if shutil.which("chromedriver") is None:
                os.system(f"{prefix}yum -y install chromedriver")
        elif platform.system() == "Windows":
            if not os.path.exists("chrome-win\\chrome.exe"):
                decompress(download("https://npm.taobao.org/mirrors/chromium-browser-snapshots/Win/686378/chrome-win.zip"))
            if not os.path.exists("chromedriver.exe"):
                decompress(download("https://npm.taobao.org/mirrors/chromedriver/78.0.3904.11/chromedriver_win32.zip"))
        else:
            print("会员购抢购组件不支持在当前平台上运行")
            config['mall_rush']['enable'] = False
    queue = Manager().Queue()
    export_process = Process(target=export, args=(queue, config))
    export_process.start()
    with Pool(min(config['global']['process'], len(accounts))) as p:
        result = p.map(wrapper, [{
            'config': config,
            'account': account,
            'queue': queue,
        } for account in accounts])
        p.close()
        p.join()
    if config['user']['update']:
        with open(config_file, "r+", encoding=detect_charset(config_file)) as f:
            content = f.read()
            before = content.split("account")[0]
            after = content.split("account")[-1].split("\"\"\"")[-1]
            f.seek(0)
            f.truncate()
            f.write(before)
            f.write("account = \"\"\"\n")
            for credential in result:
                new_line = False
                for key, value in credential.items():
                    if value:
                        if key == "cookie":
                            f.write(f"{';'.join(f'{key}={value}' for key, value in value.items())};")
                        else:
                            f.write(f"{key}={value};")
                        new_line = True
                if new_line:
                    f.write("\n")
            f.write("\"\"\"")
            f.write(after)
        print("凭据已更新")
    queue.put(None)
    export_process.join()

if __name__ == "__main__":
    freeze_support()
    main()
    if platform.system() == "Windows":
        os.system("pause >nul | set /p =请按任意键退出")
