#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import math
import os
import requests
import time
import types
from bilibili import Bilibili
from PIL import Image

def log(message):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}] {message}")

def calc_md5(data, hexdigest=False):
    md5 = hashlib.md5()
    if isinstance(data, types.GeneratorType):
        for chunk in data:
            md5.update(chunk)
    else:
        md5.update(data)
    return md5.hexdigest() if hexdigest else md5.digest()

def read_in_chunks(file_name, chunk_size=1024 * 1024):
    with open(file_name, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if data != b"":
                yield data
            else:
                return

def image_dump(data, file_name):
    md5 = calc_md5(data)
    merged_data = data + md5 + b"\xff"
    pixel_number = math.ceil(len(merged_data) / 3)
    width =  math.ceil(math.sqrt(pixel_number))
    height = math.ceil(pixel_number / width)
    image = Image.new("RGB", (width, height))
    image_data = [[]]
    for byte in merged_data:
        if len(image_data[-1]) == 3:
            image_data[-1] = tuple(image_data[-1])
            image_data.append([])
        image_data[-1].append(byte)
    image_data[-1] = tuple(image_data[-1] + [0] * (3 - len(image_data[-1])))
    image.putdata(image_data)
    image.save(file_name)

def image_load(file_name):
    image = Image.open(file_name)
    merged_data = b"".join(bytes(pixel_data) for pixel_data in image.getdata())
    merged_data = merged_data.rstrip(b"\x00")
    if merged_data[-1] == 255:
        data, md5 = merged_data[:-(1 + 16)], merged_data[-(1 + 16):-1]
        if calc_md5(data) == md5:
            return data
    return b""

def image_upload(file_name, cookies):
    url = "https://api.vc.bilibili.com/api/v1/drawImage/upload"
    headers = {
        'Origin': "https://t.bilibili.com",
        'Referer': "https://t.bilibili.com/",
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
    }
    files = {
        'file_up': (file_name, open(file_name, "rb")),
        'biz': "draw",
        'category': "daily",
    }
    response = requests.post(url, headers=headers, cookies=cookies, files=files).json()
    return response

def image_download(url, file_name=None):
    if file_name is None:
        file_name = url.split("/")[-1]
    with open(file_name, "wb") as f:
        response = requests.get(url, stream=True)
        length = response.headers.get("content-length")
        if length:
            length = int(length)
            receive = 0
            for data in response.iter_content(chunk_size=100 * 1024):
                f.write(data)
                receive += len(data)
                # percent = receive / length
                # print(f"\r{file_name} [{'=' * int(50 * percent)}{' ' * (50 - int(50 * percent))}] {percent:.0%}", end="", flush=True)
            # print()
        else:
            f.write(response.content)
    return file_name

def login_handle(args):
    bilibili = Bilibili()
    bilibili.login(username=args.username, password=args.password)
    with open(args.cookies_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(bilibili.get_cookies(), ensure_ascii=False, indent=2))

def info_handle(args):
    if args.url.startswith("http://") or args.url.startswith("https://"):
        meta_file_name = image_download(args.url)
    else:
        meta_file_name = args.url
    try:
        meta_data = json.loads(image_load(meta_file_name).decode("utf-8"))
        os.remove(meta_file_name)
        log(f"文件名: {meta_data['filename']}")
        log(f"大小: {meta_data['size'] / 1024 / 1024:.2f} MB")
        log(f"MD5: {meta_data['md5']}")
        log(f"上传时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_data['time']))}")
        log(f"分块数: {len(meta_data['block'])}")
        for index, url in enumerate(meta_data['block']):
            log(f"分块{index} URL: {url}")
    except:
        os.remove(meta_file_name)
        log("元数据解析出错")

def upload_handle(args):
    start_time = time.time()
    try:
        with open(args.cookies_file, "r", encoding="utf-8") as f:
            cookies = json.loads(f.read())
    except:
        log("Cookies文件加载失败")
        return None
    file_name = args.file
    url_list = []
    log(f"上传: {file_name} ({os.path.getsize(file_name) / 1024 / 1024:.2f} MB)")
    md5 = calc_md5(read_in_chunks(file_name), hexdigest=True)
    log(f"MD5: {md5}")
    for index, chunk in enumerate(read_in_chunks(file_name, chunk_size=args.block_size * 1024 * 1024)):
        part_file_name = f"{md5}_{index}.png"
        image_dump(chunk, part_file_name)
        for _ in range(3):
            response = image_upload(part_file_name, cookies)
            if response['code'] == 0:
                url = response['data']['image_url']
                log(f"分块{index} ({os.path.getsize(part_file_name) / 1024 / 1024:.2f} MB) 已上传")
                url_list.append(url)
                os.remove(part_file_name)
                break
            elif response['code'] == -4:
                log(f"上传失败, 账号未登录")
                os.remove(part_file_name)
                return None
        else:
            log(f"分块{index} ({os.path.getsize(part_file_name) / 1024 / 1024:.2f} MB) 上传失败, 服务器返回{response}")
            os.remove(part_file_name)
            return None
    meta_data = {
        'time': int(time.time()),
        'filename': file_name,
        'size': os.path.getsize(file_name),
        'md5': md5,
        'block': url_list,
    }
    meta_file_name = f"{md5}_meta.png"
    image_dump(json.dumps(meta_data, ensure_ascii=False).encode("utf-8"), meta_file_name)
    for _ in range(3):
        response = image_upload(meta_file_name, cookies)
        if response['code'] == 0:
            url = response['data']['image_url']
            log(f"元数据已上传")
            os.remove(meta_file_name)
            log(f"{file_name}上传完毕, 共有{index + 1}个分块, 耗时{int(time.time() - start_time)}秒")
            log(f"META URL: {url}")
            return url
    else:
        log(f"元数据上传失败, 保留本地文件{meta_file_name}, 服务器返回{response}")
        return meta_file_name

def download_handle(args):
    start_time = time.time()
    if args.url.startswith("http://") or args.url.startswith("https://"):
        meta_file_name = image_download(args.url)
    else:
        meta_file_name = args.url
    try:
        meta_data = json.loads(image_load(meta_file_name).decode("utf-8"))
        os.remove(meta_file_name)
        file_name = args.save_as if args.save_as else meta_data['filename']
        log(f"下载: {file_name} ({meta_data['size'] / 1024 / 1024:.2f} MB), 共有{len(meta_data['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_data['time']))}")
    except:
        os.remove(meta_file_name)
        log("元数据解析出错")
        return None
    with open(file_name, "wb") as f:
        for index, url in enumerate(meta_data['block']):
            for _ in range(3):
                part_file_name = image_download(url)
                part_data = image_load(part_file_name)
                if part_data != b"":
                    log(f"分块{index} ({len(part_data) / 1024 / 1024:.2f} MB) 已下载")
                    f.write(part_data)
                    os.remove(part_file_name)
                    break
            else:
                log(f"分块{index}校验出错")
                os.remove(part_file_name)
                return None
    log(f"{file_name}下载完毕, 耗时{int(time.time() - start_time)}秒")
    md5 = calc_md5(read_in_chunks(file_name), hexdigest=True)
    log(f"MD5: {md5}")
    if md5 == meta_data['md5']:
        log(f"{file_name}校验通过")
        return file_name
    else:
        log(f"{file_name}校验出错, MD5与元数据中的记录{meta_data['md5']}不匹配")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="BiliDrive", description="Bilibili Drive", epilog="By Hsury, 2019/10/23")
    parser.add_argument("-c", "--cookies-file", default="cookies.json", help="cookies json file name")

    subparsers = parser.add_subparsers()

    login_parser = subparsers.add_parser("login", help="login to bilibili")
    login_parser.add_argument("username", help="username")
    login_parser.add_argument("password", help="password")
    login_parser.set_defaults(func=login_handle)

    info_parser = subparsers.add_parser("info", help="get meta info")
    info_parser.add_argument("url", help="meta url")
    info_parser.set_defaults(func=info_handle)

    upload_parser = subparsers.add_parser("upload", help="upload a file")
    upload_parser.add_argument("file", help="file name")
    upload_parser.add_argument("-b", "--block-size", default=1, type=int, help="block size in MB")
    upload_parser.set_defaults(func=upload_handle)

    download_parser = subparsers.add_parser("download", help="download a file")
    download_parser.add_argument("url", help="meta url")
    download_parser.add_argument("save_as", nargs="?", default="", help="save as file name")
    download_parser.set_defaults(func=download_handle)

    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
