#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import math
import os
import re
import requests
import threading
import time
import types
from bilibili import Bilibili
from PIL import Image

def log(message):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}] {message}")

def calc_sha1(data, hexdigest=False):
    sha1 = hashlib.sha1()
    if isinstance(data, types.GeneratorType):
        for chunk in data:
            sha1.update(chunk)
    else:
        sha1.update(data)
    return sha1.hexdigest() if hexdigest else sha1.digest()

def read_in_chunks(file_name, chunk_size=1024 * 1024):
    with open(file_name, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if data != b"":
                yield data
            else:
                return

def image_dump(data, file_name):
    merged_data = data + b"\xff"
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
        return merged_data[:-1]
    else:
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

def fetch_meta(string):
    if string.startswith("http://") or string.startswith("https://"):
        meta_file_name = image_download(string)
    elif re.match(r"^[a-fA-F0-9]{40}$", string):
        meta_file_name = image_download(f"http://i0.hdslb.com/bfs/album/{string}.png")
    else:
        meta_file_name = string
    try:
        meta_data = json.loads(image_load(meta_file_name).decode("utf-8"))
        return meta_data
    except:
        return None
    finally:
        os.remove(meta_file_name)

def login_handle(args):
    bilibili = Bilibili()
    bilibili.login(username=args.username, password=args.password)
    bilibili.get_user_info()
    with open(args.cookies_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(bilibili.get_cookies(), ensure_ascii=False, indent=2))

def info_handle(args):
    meta_data = fetch_meta(args.meta)
    if meta_data:
        log(f"文件名: {meta_data['filename']}")
        log(f"大小: {meta_data['size'] / 1024 / 1024:.2f} MB")
        log(f"SHA-1: {meta_data['sha1']}")
        log(f"上传时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_data['time']))}")
        log(f"分块数: {len(meta_data['block'])}")
        for index, block in enumerate(meta_data['block']):
            log(f"分块{index} ({block['size'] / 1024 / 1024:.2f} MB) URL: {block['url']}")
    else:
        log("元数据解析出错")

def upload_handle(args):
    def core(index, block):
        block_file_name = f"{sha1}_{index}.png"
        image_dump(block, block_file_name)
        block_sha1 = calc_sha1(read_in_chunks(block_file_name), hexdigest=True)
        url = skippable(block_sha1)
        if url:
            log(f"分块{index} ({os.path.getsize(block_file_name) / 1024 / 1024:.2f} MB) 已存在于服务器")
            block_dict[index] = {
                'url': url,
                'size': os.path.getsize(block_file_name),
                'sha1': block_sha1,
            }
            done_flag.release()
        else:
            for _ in range(3):
                response = image_upload(block_file_name, cookies)
                if response['code'] == 0:
                    url = response['data']['image_url']
                    log(f"分块{index} ({os.path.getsize(block_file_name) / 1024 / 1024:.2f} MB) 已上传")
                    block_dict[index] = {
                        'url': url,
                        'size': os.path.getsize(block_file_name),
                        'sha1': block_sha1,
                    }
                    done_flag.release()
                    break
                elif response['code'] == -4:
                    terminate_flag.set()
                    log("上传失败, 请先登录")
                    break
            else:
                terminate_flag.set()
                log(f"分块{index} ({os.path.getsize(block_file_name) / 1024 / 1024:.2f} MB) 上传失败, 服务器返回{response}")
        os.remove(block_file_name)

    def skippable(sha1):
        url = f"http://i0.hdslb.com/bfs/album/{sha1}.png"
        response = requests.head(url)
        return url if response.status_code == 200 else None

    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    thread_pool = []
    start_time = time.time()
    try:
        with open(args.cookies_file, "r", encoding="utf-8") as f:
            cookies = json.loads(f.read())
    except:
        log("Cookies加载失败, 请先登录")
        return None
    file_name = args.file
    block_dict = {}
    log(f"上传: {file_name} ({os.path.getsize(file_name) / 1024 / 1024:.2f} MB)")
    sha1 = calc_sha1(read_in_chunks(file_name), hexdigest=True)
    log(f"SHA-1: {sha1}")
    log(f"线程数: {args.thread}")
    for index, block in enumerate(read_in_chunks(file_name, chunk_size=args.block_size * 1024 * 1024 - 1)):
        if len(thread_pool) >= args.thread:
            done_flag.acquire()
        if not terminate_flag.is_set():
            thread_pool.append(threading.Thread(target=core, args=(index, block)))
            thread_pool[-1].start()
        else:
            log("已终止上传, 等待线程回收")
    for thread in thread_pool:
        thread.join()
    if terminate_flag.is_set():
        return None
    meta_data = {
        'time': int(time.time()),
        'filename': file_name,
        'size': os.path.getsize(file_name),
        'sha1': sha1,
        'block': [block_dict[i] for i in range(len(block_dict))],
    }
    meta_file_name = f"{sha1}_meta.png"
    image_dump(json.dumps(meta_data, ensure_ascii=False).encode("utf-8"), meta_file_name)
    for _ in range(3):
        response = image_upload(meta_file_name, cookies)
        if response['code'] == 0:
            url = response['data']['image_url']
            log("元数据已上传")
            os.remove(meta_file_name)
            log(f"{file_name}上传完毕, 共有{index + 1}个分块, 耗时{int(time.time() - start_time)}秒")
            log(f"META: {re.findall(r'[a-fA-F0-9]{40}', url)[0] if re.match(r'^http(s?)://i0.hdslb.com/bfs/album/[a-fA-F0-9]{40}.png$', url) else url}")
            return url
    else:
        log(f"元数据上传失败, 保留文件{meta_file_name}, 服务器返回{response}")
        return meta_file_name

def download_handle(args):
    def core(index, block):
        block_file_name = f"{meta_data['sha1']}_{index}.png"
        if os.path.exists(block_file_name) and calc_sha1(read_in_chunks(block_file_name), hexdigest=True) == block['sha1']:
            log(f"分块{index} ({os.path.getsize(block_file_name) / 1024 / 1024:.2f} MB) 已存在于本地")
            block_file_name_dict[index] = block_file_name
            done_flag.release()
        else:
            for _ in range(3):
                image_download(block['url'], file_name=block_file_name)
                if calc_sha1(read_in_chunks(block_file_name), hexdigest=True) == block['sha1']:
                    log(f"分块{index} ({os.path.getsize(block_file_name) / 1024 / 1024:.2f} MB) 已下载")
                    block_file_name_dict[index] = block_file_name
                    done_flag.release()
                    break
            else:
                terminate_flag.set()
                log(f"分块{index}校验未通过, SHA-1与元数据中的记录{block['sha1']}不匹配")
                os.remove(block_file_name)
                return

    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    thread_pool = []
    block_file_name_dict = {}
    start_time = time.time()
    meta_data = fetch_meta(args.meta)
    if meta_data:
        file_name = args.file if args.file else meta_data['filename']
        log(f"下载: {file_name} ({meta_data['size'] / 1024 / 1024:.2f} MB), 共有{len(meta_data['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_data['time']))}")
    else:
        log("元数据解析出错")
        return None
    log(f"线程数: {args.thread}")
    if not (os.path.exists(file_name) and calc_sha1(read_in_chunks(file_name), hexdigest=True) == meta_data['sha1']):
        for index, block in enumerate(meta_data['block']):
            if len(thread_pool) >= args.thread:
                done_flag.acquire()
            if not terminate_flag.is_set():
                thread_pool.append(threading.Thread(target=core, args=(index, block)))
                thread_pool[-1].start()
            else:
                log("已终止下载, 等待线程回收")
        for thread in thread_pool:
            thread.join()
        if terminate_flag.is_set():
            return None
        with open(file_name, "wb") as f:
            for index in range(len(meta_data['block'])):
                block_file_name = block_file_name_dict[index]
                f.write(image_load(block_file_name))
                os.remove(block_file_name)
        sha1 = calc_sha1(read_in_chunks(file_name), hexdigest=True)
        log(f"SHA-1: {sha1}")
        if sha1 == meta_data['sha1']:
            log(f"{file_name}校验通过")
            log(f"{file_name}下载完毕, 耗时{int(time.time() - start_time)}秒")
            return file_name
        else:
            log(f"{file_name}校验未通过, SHA-1与元数据中的记录{meta_data['sha1']}不匹配")
            return None
    else:
        log(f"{file_name}已存在于本地")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="BiliDrive", description="Bilibili Drive", epilog="By Hsury, 2019/10/24")
    parser.add_argument("-c", "--cookies-file", default="cookies.json", help="cookies json file name")

    subparsers = parser.add_subparsers()

    login_parser = subparsers.add_parser("login", help="login to bilibili")
    login_parser.add_argument("username", help="username")
    login_parser.add_argument("password", help="password")
    login_parser.set_defaults(func=login_handle)

    info_parser = subparsers.add_parser("info", help="get meta info")
    info_parser.add_argument("meta", help="meta url")
    info_parser.set_defaults(func=info_handle)

    upload_parser = subparsers.add_parser("upload", help="upload a file")
    upload_parser.add_argument("file", help="file name")
    upload_parser.add_argument("-b", "--block-size", default=4, type=int, help="block size in MB")
    upload_parser.add_argument("-t", "--thread", default=2, type=int, help="thread number")
    upload_parser.set_defaults(func=upload_handle)

    download_parser = subparsers.add_parser("download", help="download a file")
    download_parser.add_argument("meta", help="meta url")
    download_parser.add_argument("file", nargs="?", default="", help="save as file name")
    download_parser.add_argument("-t", "--thread", default=4, type=int, help="thread number")
    download_parser.set_defaults(func=download_handle)

    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
