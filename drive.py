#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import math
import os
import re
import requests
import shlex
import signal
import struct
import sys
import threading
import time
import traceback
import types
from bilibili import Bilibili

bundle_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))

default_url = lambda sha1: f"http://i0.hdslb.com/bfs/album/{sha1}.x-ms-bmp"
meta_string = lambda url: ("bdrive://" + re.findall(r"[a-fA-F0-9]{40}", url)[0]) if re.match(r"^http(s?)://i0.hdslb.com/bfs/album/[a-fA-F0-9]{40}.x-ms-bmp$", url) else url

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

def calc_sha1(data, hexdigest=False):
    sha1 = hashlib.sha1()
    if isinstance(data, types.GeneratorType):
        for chunk in data:
            sha1.update(chunk)
    else:
        sha1.update(data)
    return sha1.hexdigest() if hexdigest else sha1.digest()

def fetch_meta(string):
    if re.match(r"^bdrive://[a-fA-F0-9]{40}$", string) or re.match(r"^[a-fA-F0-9]{40}$", string):
        full_meta = image_download(default_url(re.findall(r"[a-fA-F0-9]{40}", string)[0]))
    elif string.startswith("http://") or string.startswith("https://"):
        full_meta = image_download(string)
    else:
        return None
    try:
        meta_dict = json.loads(full_meta[62:].decode("utf-8"))
        return meta_dict
    except:
        return None

def image_upload(data, cookies):
    url = "https://api.vc.bilibili.com/api/v1/drawImage/upload"
    headers = {
        'Origin': "https://t.bilibili.com",
        'Referer': "https://t.bilibili.com/",
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36",
    }
    files = {
        'file_up': (f"{int(time.time() * 1000)}.bmp", data),
        'biz': "draw",
        'category': "daily",
    }
    try:
        response = requests.post(url, headers=headers, cookies=cookies, files=files, timeout=10).json()
    except:
        response = None
    return response

def image_download(url):
    headers = {
        'Referer': "http://t.bilibili.com/",
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36",
    }
    content = []
    last_chunk_time = None
    try:
        for chunk in requests.get(url, headers=headers, timeout=10, stream=True).iter_content(64 * 1024):
            if last_chunk_time is not None and time.time() - last_chunk_time > 5:
                return None
            content.append(chunk)
            last_chunk_time = time.time()
        return b"".join(content)
    except:
        return None

def log(message):
    Bilibili._log(message)

def read_history():
    try:
        with open(os.path.join(bundle_dir, "history.json"), "r", encoding="utf-8") as f:
            history = json.loads(f.read())
    except:
        history = {}
    return history

def read_in_chunks(file_name, chunk_size=16 * 1024 * 1024, chunk_number=-1):
    chunk_counter = 0
    with open(file_name, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if data != b"" and (chunk_number == -1 or chunk_counter < chunk_number):
                yield data
                chunk_counter += 1
            else:
                return

def history_handle(args):
    history = read_history()
    if history:
        for index, meta_dict in enumerate(history.values()):
            prefix = f"[{index}]"
            print(f"{prefix} {meta_dict['filename']} ({meta_dict['size'] / 1024 / 1024:.2f} MB), 共有{len(meta_dict['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
            print(f"{' ' * len(prefix)} {meta_string(meta_dict['url'])}")
    else:
        print(f"暂无历史记录")

def info_handle(args):
    meta_dict = fetch_meta(args.meta)
    if meta_dict:
        print(f"文件名: {meta_dict['filename']}")
        print(f"大小: {meta_dict['size'] / 1024 / 1024:.2f} MB")
        print(f"SHA-1: {meta_dict['sha1']}")
        print(f"上传时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
        print(f"分块数: {len(meta_dict['block'])}")
        for index, block_dict in enumerate(meta_dict['block']):
            print(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) URL: {block_dict['url']}")
    else:
        print("元数据解析失败")

def login_handle(args):
    bilibili = Bilibili()
    if bilibili.login(username=args.username, password=args.password):
        bilibili.get_user_info()
        with open(os.path.join(bundle_dir, "cookies.json"), "w", encoding="utf-8") as f:
            f.write(json.dumps(bilibili.get_cookies(), ensure_ascii=False, indent=2))

def upload_handle(args):
    def core(index, block):
        try:
            block_sha1 = calc_sha1(block, hexdigest=True)
            full_block = bmp_header(block) + block
            full_block_sha1 = calc_sha1(full_block, hexdigest=True)
            url = skippable(full_block_sha1)
            if url:
                # log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 已存在于服务器")
                block_dict[index] = {
                    'url': url,
                    'size': len(block),
                    'sha1': block_sha1,
                }
            else:
                # log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 开始上传")
                for _ in range(10):
                    if terminate_flag.is_set():
                        return
                    response = image_upload(full_block, cookies)
                    if response:
                        if response['code'] == 0:
                            url = response['data']['image_url']
                            log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 上传完毕")
                            block_dict[index] = {
                                'url': url,
                                'size': len(block),
                                'sha1': block_sha1,
                            }
                            return
                        elif response['code'] == -4:
                            terminate_flag.set()
                            log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 第{_ + 1}次上传失败, 请重新登录")
                            return
                    log(f"分块{index} ({len(block) / 1024 / 1024:.2f} MB) 第{_ + 1}次上传失败")
                else:
                    terminate_flag.set()
        except:
            terminate_flag.set()
            traceback.print_exc()
        finally:
            done_flag.release()

    def skippable(sha1):
        url = default_url(sha1)
        headers = {
            'Referer': "http://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36",
        }
        for _ in range(5):
            try:
                response = requests.head(url, headers=headers, timeout=10)
                return url if response.status_code == 200 else None
            except:
                pass
        return None

    def write_history(first_4mb_sha1, meta_dict, url):
        history = read_history()
        history[first_4mb_sha1] = meta_dict
        history[first_4mb_sha1]['url'] = url
        with open(os.path.join(bundle_dir, "history.json"), "w", encoding="utf-8") as f:
            f.write(json.dumps(history, ensure_ascii=False, indent=2))

    start_time = time.time()
    file_name = args.file
    if not os.path.exists(file_name):
        log(f"{file_name}不存在")
        return None
    log(f"上传: {os.path.basename(file_name)} ({os.path.getsize(file_name) / 1024 / 1024:.2f} MB)")
    first_4mb_sha1 = calc_sha1(read_in_chunks(file_name, chunk_size=4 * 1024 * 1024, chunk_number=1), hexdigest=True)
    history = read_history()
    if first_4mb_sha1 in history:
        url = history[first_4mb_sha1]['url']
        log(f"该文件已于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(history[first_4mb_sha1]['time']))}上传, 共有{len(history[first_4mb_sha1]['block'])}个分块")
        log(meta_string(url))
        return url
    try:
        with open(os.path.join(bundle_dir, "cookies.json"), "r", encoding="utf-8") as f:
            cookies = json.loads(f.read())
    except:
        log("Cookies加载失败, 请先登录")
        return None
    log(f"线程数: {args.thread}")
    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    thread_pool = []
    block_dict = {}
    for index, block in enumerate(read_in_chunks(file_name, chunk_size=args.block_size * 1024 * 1024)):
        if len(thread_pool) >= args.thread:
            done_flag.acquire()
        if not terminate_flag.is_set():
            thread_pool.append(threading.Thread(target=core, args=(index, block)))
            thread_pool[-1].start()
        else:
            log("已终止上传, 等待线程回收")
            break
    for thread in thread_pool:
        thread.join()
    if terminate_flag.is_set():
        return None
    sha1 = calc_sha1(read_in_chunks(file_name), hexdigest=True)
    meta_dict = {
        'time': int(time.time()),
        'filename': os.path.basename(file_name),
        'size': os.path.getsize(file_name),
        'sha1': sha1,
        'block': [block_dict[i] for i in range(len(block_dict))],
    }
    meta = json.dumps(meta_dict, ensure_ascii=False).encode("utf-8")
    full_meta = bmp_header(meta) + meta
    for _ in range(10):
        response = image_upload(full_meta, cookies)
        if response and response['code'] == 0:
            url = response['data']['image_url']
            log("元数据上传完毕")
            log(f"{os.path.basename(file_name)}上传完毕, 共有{len(meta_dict['block'])}个分块, 用时{int(time.time() - start_time)}秒, 平均速度{meta_dict['size'] / 1024 / 1024 / (time.time() - start_time):.2f} MB/s")
            log(meta_string(url))
            write_history(first_4mb_sha1, meta_dict, url)
            return url
        log(f"元数据第{_ + 1}次上传失败")
    else:
        return None

def download_handle(args):
    def core(index, block_dict):
        try:
            # log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 开始下载")
            for _ in range(10):
                if terminate_flag.is_set():
                    return
                block = image_download(block_dict['url'])
                if block:
                    block = block[62:]
                    if calc_sha1(block, hexdigest=True) == block_dict['sha1']:
                        file_lock.acquire()
                        f.seek(block_offset(index))
                        f.write(block)
                        file_lock.release()
                        log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 下载完毕")
                        return
                    else:
                        log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 校验未通过")
                else:
                    log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 第{_ + 1}次下载失败")
            else:
                terminate_flag.set()
        except:
            terminate_flag.set()
            traceback.print_exc()
        finally:
            done_flag.release()

    def block_offset(index):
        return sum(meta_dict['block'][i]['size'] for i in range(index))

    def is_overwrite(file_name):
        if args.force:
            return True
        else:
            return (input(f"{os.path.basename(file_name)}已存在于本地, 是否覆盖? [y/N] ") in ["y", "Y"])

    start_time = time.time()
    meta_dict = fetch_meta(args.meta)
    if meta_dict:
        file_name = args.file if args.file else meta_dict['filename']
        log(f"下载: {os.path.basename(file_name)} ({meta_dict['size'] / 1024 / 1024:.2f} MB), 共有{len(meta_dict['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
    else:
        log("元数据解析失败")
        return None
    log(f"线程数: {args.thread}")
    download_block_list = []
    if os.path.exists(file_name):
        if os.path.getsize(file_name) == meta_dict['size'] and calc_sha1(read_in_chunks(file_name), hexdigest=True) == meta_dict['sha1']:
            log(f"{os.path.basename(file_name)}已存在于本地, 且与服务器端文件内容一致")
            return file_name
        elif is_overwrite(file_name):
            with open(file_name, "rb") as f:
                for index, block_dict in enumerate(meta_dict['block']):
                    f.seek(block_offset(index))
                    if calc_sha1(f.read(block_dict['size']), hexdigest=True) == block_dict['sha1']:
                        # log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 已存在于本地")
                        pass
                    else:
                        # log(f"分块{index} ({block_dict['size'] / 1024 / 1024:.2f} MB) 需要重新下载")
                        download_block_list.append(index)
            log(f"{len(download_block_list)}个分块待下载")
        else:
            return None
    else:
        download_block_list = list(range(len(meta_dict['block'])))        
    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    file_lock = threading.Lock()
    thread_pool = []
    with open(file_name, "r+b" if os.path.exists(file_name) else "wb") as f:
        for index in download_block_list:
            if len(thread_pool) >= args.thread:
                done_flag.acquire()
            if not terminate_flag.is_set():
                thread_pool.append(threading.Thread(target=core, args=(index, meta_dict['block'][index])))
                thread_pool[-1].start()
            else:
                log("已终止下载, 等待线程回收")
                break
        for thread in thread_pool:
            thread.join()
        if terminate_flag.is_set():
            return None
        f.truncate(sum(block['size'] for block in meta_dict['block']))
    log(f"{os.path.basename(file_name)}下载完毕, 用时{int(time.time() - start_time)}秒, 平均速度{meta_dict['size'] / 1024 / 1024 / (time.time() - start_time):.2f} MB/s")
    sha1 = calc_sha1(read_in_chunks(file_name), hexdigest=True)
    if sha1 == meta_dict['sha1']:
        log(f"{os.path.basename(file_name)}校验通过")
        return file_name
    else:
        log(f"{os.path.basename(file_name)}校验未通过")
        return None

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda signum, frame: os.kill(os.getpid(), 9))
    parser = argparse.ArgumentParser(description="BiliDrive", epilog="By Hsury, 2019/11/3")
    subparsers = parser.add_subparsers()
    history_parser = subparsers.add_parser("history", help="view upload history")
    history_parser.set_defaults(func=history_handle)
    info_parser = subparsers.add_parser("info", help="view meta info")
    info_parser.add_argument("meta", help="meta url")
    info_parser.set_defaults(func=info_handle)
    login_parser = subparsers.add_parser("login", help="log in to bilibili")
    login_parser.add_argument("username", help="username")
    login_parser.add_argument("password", help="password")
    login_parser.set_defaults(func=login_handle)
    upload_parser = subparsers.add_parser("upload", help="upload a file")
    upload_parser.add_argument("file", help="name of the file to upload")
    upload_parser.add_argument("-b", "--block-size", default=4, type=int, help="block size in MB")
    upload_parser.add_argument("-t", "--thread", default=4, type=int, help="upload thread number")
    upload_parser.set_defaults(func=upload_handle)
    download_parser = subparsers.add_parser("download", help="download a file")
    download_parser.add_argument("meta", help="meta url")
    download_parser.add_argument("file", nargs="?", default="", help="new file name")
    download_parser.add_argument("-f", "--force", action="store_true", help="force to overwrite if file exists")
    download_parser.add_argument("-t", "--thread", default=8, type=int, help="download thread number")
    download_parser.set_defaults(func=download_handle)
    shell = False
    while True:
        if shell:
            args = shlex.split(input("BiliDrive > "))
            if args == ["exit"]:
                break
            elif args == ["help"]:
                parser.print_help()
            else:
                try:
                    args = parser.parse_args(args)
                    args.func(args)
                except:
                    pass
        else:
            args = parser.parse_args()
            try:
                args.func(args)
                break
            except AttributeError:
                shell = True
