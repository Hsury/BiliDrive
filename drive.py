#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import math
import os
import re
import requests
import struct
import threading
import time
import types
from bilibili import Bilibili

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

def bmp_header(data):
    return b"BM" \
        + struct.pack("<l", 14 + 40 + 8 + len(data)) \
        + b"\x00\x00" \
        + b"\x00\x00" \
        + b"\x3e\x00\x00\x00" \
        + b"\x28\x00\x00\x00" \
        + struct.pack("<l", len(data)) \
        + b"\x01\x00\x00\x00" \
        + b"\x01\x00" \
        + b"\x01\x00" \
        + b"\x00\x00\x00\x00" \
        + struct.pack("<l", math.ceil(len(data) / 8)) \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00\xff\xff\xff\x00"

def image_upload(data, cookies):
    url = "https://api.vc.bilibili.com/api/v1/drawImage/upload"
    headers = {
        'Origin': "https://t.bilibili.com",
        'Referer': "https://t.bilibili.com/",
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
    }
    files = {
        'file_up': (f"{int(time.time() * 1000)}.bmp", data),
        'biz': "draw",
        'category': "daily",
    }
    response = requests.post(url, headers=headers, cookies=cookies, files=files).json()
    return response

def image_download(url):
    response = requests.get(url)
    return response.content

def fetch_meta(string):
    if string.startswith("http://") or string.startswith("https://"):
        full_meta = image_download(string)
    elif re.match(r"^[a-fA-F0-9]{40}$", string):
        full_meta = image_download(f"http://i0.hdslb.com/bfs/album/{string}.x-ms-bmp")
    else:
        return None
    try:
        meta_dict = json.loads(full_meta[62:].decode("utf-8"))
        return meta_dict
    except:
        return None

def login_handle(args):
    bilibili = Bilibili()
    bilibili.login(username=args.username, password=args.password)
    bilibili.get_user_info()
    with open(args.cookies_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(bilibili.get_cookies(), ensure_ascii=False, indent=2))

def info_handle(args):
    meta_dict = fetch_meta(args.meta)
    if meta_dict:
        log(f"文件名: {meta_dict['filename']}")
        log(f"大小: {meta_dict['size'] / 1024 / 1024:.2f} MB")
        log(f"SHA-1: {meta_dict['sha1']}")
        log(f"上传时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
        log(f"分块数: {len(meta_dict['block'])}")
        for index, block_dict in enumerate(meta_dict['block']):
            log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) URL: {block_dict['url']}")
    else:
        log("元数据解析出错")

def upload_handle(args):
    def core(index, block):
        block_sha1 = calc_sha1(block, hexdigest=True)
        full_block = bmp_header(block) + block
        full_block_sha1 = calc_sha1(full_block, hexdigest=True)
        url = skippable(full_block_sha1)
        if url:
            log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 已存在于服务器")
            block_dict[index] = {
                'url': url,
                'size': len(block),
                'sha1': block_sha1,
            }
            done_flag.release()
        else:
            for _ in range(3):
                response = image_upload(full_block, cookies)
                if response['code'] == 0:
                    url = response['data']['image_url']
                    log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 已上传")
                    block_dict[index] = {
                        'url': url,
                        'size': len(block),
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
                log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 上传失败, 服务器返回{response}")

    def skippable(sha1):
        url = f"http://i0.hdslb.com/bfs/album/{sha1}.x-ms-bmp"
        response = requests.head(url)
        return url if response.status_code == 200 else None

    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    thread_pool = []
    block_dict = {}
    start_time = time.time()
    try:
        with open(args.cookies_file, "r", encoding="utf-8") as f:
            cookies = json.loads(f.read())
    except:
        log("Cookies加载失败, 请先登录")
        return None
    file_name = args.file
    log(f"上传: {os.path.basename(file_name)} ({os.path.getsize(file_name) / 1024 / 1024:.2f} MB)")
    sha1 = calc_sha1(read_in_chunks(file_name), hexdigest=True)
    log(f"SHA-1: {sha1}")
    log(f"线程数: {args.thread}")
    for index, block in enumerate(read_in_chunks(file_name, chunk_size=args.block_size * 1024 * 1024)):
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
    meta_dict = {
        'time': int(time.time()),
        'filename': os.path.basename(file_name),
        'size': os.path.getsize(file_name),
        'sha1': sha1,
        'block': [block_dict[i] for i in range(len(block_dict))],
    }
    meta = json.dumps(meta_dict, ensure_ascii=False).encode("utf-8")
    full_meta = bmp_header(meta) + meta
    for _ in range(3):
        response = image_upload(full_meta, cookies)
        if response['code'] == 0:
            url = response['data']['image_url']
            log("元数据已上传")
            log(f"{os.path.basename(file_name)}上传完毕, 共有{len(meta_dict['block'])}个分块, 用时{int(time.time() - start_time)}秒, 平均速度{meta_dict['size'] / 1024 / 1024 / (time.time() - start_time):.2f} MB/s")
            log(f"META: {re.findall(r'[a-fA-F0-9]{40}', url)[0] if re.match(r'^http(s?)://i0.hdslb.com/bfs/album/[a-fA-F0-9]{40}.x-ms-bmp$', url) else url}")
            return url
    else:
        log(f"元数据上传失败, 服务器返回{response}")
        return None

def download_handle(args):
    def core(index, block_dict, f):
        for _ in range(3):
            block = image_download(block_dict['url'])[62:]
            if calc_sha1(block, hexdigest=True) == block_dict['sha1']:
                f.seek(block_offset(index))
                f.write(block)
                log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 已下载")
                done_flag.release()
                break
        else:
            terminate_flag.set()
            log(f"分块{index}校验未通过, SHA-1与元数据中的记录{block_dict['sha1']}不匹配")
            return

    def block_offset(index):
        return sum(meta_dict['block'][i]['size'] for i in range(index))

    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    thread_pool = []
    download_block_list = []
    start_time = time.time()
    meta_dict = fetch_meta(args.meta)
    if meta_dict:
        file_name = args.file if args.file else meta_dict['filename']
        log(f"下载: {file_name} ({meta_dict['size'] / 1024 / 1024:.2f} MB), 共有{len(meta_dict['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
    else:
        log("元数据解析出错")
        return None
    log(f"线程数: {args.thread}")
    if os.path.exists(file_name) and os.path.getsize(file_name) == meta_dict['size']:
        if calc_sha1(read_in_chunks(file_name), hexdigest=True) == meta_dict['sha1']:
            log(f"{file_name}已存在于本地")
            return file_name
        else:
            with open(file_name, "rb") as f:
                for index, block_dict in enumerate(meta_dict['block']):
                    f.seek(block_offset(index))
                    if calc_sha1(f.read(block_dict['size']), hexdigest=True) == block_dict['sha1']:
                        log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 已存在于本地")
                    else:
                        download_block_list.append(index)
    else:
        download_block_list = list(range(len(meta_dict['block'])))
    with open(file_name, "r+b" if os.path.exists(file_name) else "wb") as f:
        for index in download_block_list:
            if len(thread_pool) >= args.thread:
                done_flag.acquire()
            if not terminate_flag.is_set():
                thread_pool.append(threading.Thread(target=core, args=(index, meta_dict['block'][index], f)))
                thread_pool[-1].start()
            else:
                log("已终止下载, 等待线程回收")
        for thread in thread_pool:
            thread.join()
        if terminate_flag.is_set():
            return None
        f.truncate(sum(block['size'] for block in meta_dict['block']))
    sha1 = calc_sha1(read_in_chunks(file_name), hexdigest=True)
    log(f"SHA-1: {sha1}")
    if sha1 == meta_dict['sha1']:
        log(f"{file_name}校验通过")
        log(f"{file_name}下载完毕, 用时{int(time.time() - start_time)}秒, 平均速度{meta_dict['size'] / 1024 / 1024 / (time.time() - start_time):.2f} MB/s")
        return file_name
    else:
        log(f"{file_name}校验未通过, SHA-1与元数据中的记录{meta_dict['sha1']}不匹配")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="BiliDrive", description="Bilibili Drive", epilog="By Hsury, 2019/10/25")
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
