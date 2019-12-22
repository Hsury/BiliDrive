<p align="center">
<img src="https://cdn.kagamiz.com/BiliDrive/bilidrive.png" width="128">
</p>

<h1 align="center">- BiliDrive -</h1>

<h4 align="center">☁️ 哔哩哔哩云，支持任意文件的全速上传与下载 ☁️</h4>

<p align="center">
<img src="https://img.shields.io/badge/version-2019.12.22-green.svg?longCache=true&style=for-the-badge">
<img src="https://img.shields.io/badge/license-SATA-blue.svg?longCache=true&style=for-the-badge">
<img src="https://img.shields.io/travis/com/Hsury/BiliDrive?style=for-the-badge">
</p>

<p align="center">
<img src="https://cdn.kagamiz.com/BiliDrive/demo.png" width="750">
</p>

## 特色

- 轻量：无复杂依赖，资源占用少
- 自由：无文件格式与大小限制，无容量限制
- 安全：上传的文件需要通过生成的META URL才能访问，他人无法随意查看
- 稳定：带有分块校验与超时重试机制，在较差的网络环境中依然能确保文件的完整性
- 快速：支持多线程传输与断点续传，同时借助B站的CDN资源，能最大化地利用网络环境进行上传与下载

## 使用指南

### 准备

前往[发布页](https://github.com/Hsury/BiliDrive/releases/latest)获取可直接运行的二进制文件

或使用Python软件包管理器pip从[PyPI仓库](https://pypi.org/project/BiliDrive/)安装

亦可下载[源代码](https://github.com/Hsury/BiliDrive/archive/master.zip)后使用Python 3.6或更高版本运行

### 登录

```
python -m BiliDrive login [-h] username password

username: Bilibili用户名
password: Bilibili密码
```

### 上传

```
python -m BiliDrive upload [-h] [-b BLOCK_SIZE] [-t THREAD] file

file: 待上传的文件路径

-b BLOCK_SIZE: 分块大小(MB), 默认值为4
-t THREAD: 上传线程数, 默认值为4
```

上传完毕后，终端会打印一串META URL（通常以`bdrive://`开头）用于下载或分享，请妥善保管

### 下载

```
python -m BiliDrive download [-h] [-f] [-t THREAD] meta [file]

meta: META URL(通常以bdrive://开头)
file: 另存为新的文件名, 不指定则保存为上传时的文件名

-f: 覆盖已有文件
-t THREAD: 下载线程数, 默认值为8
```

下载完毕后会自动进行文件完整性校验，对于大文件该过程可能需要较长时间，若不愿等待可直接退出

### 查看文件元数据

```
python -m BiliDrive info [-h] meta

meta: META URL(通常以bdrive://开头)
```

### 查看历史记录

```
python -m BiliDrive history [-h]
```

### 交互模式

不传入任何命令行参数，直接运行程序即可进入交互模式

该模式下，程序会打印命令提示符`BiliDrive > `，并等待用户输入命令

## 技术实现

将任意文件分块编码为图片后上传至B站，对该操作逆序即可下载并还原文件

## 性能指标

### 测试文件

文件名：[Vmoe]Hatsune Miku「Magical Mirai 2017」[BDrip][1920x1080p][HEVC_YUV420p10_60fps_2FLAC_5.1ch&2.0ch_Chapter][Effect Subtitles].mkv

大小：14.5 GB (14918.37 MB)

分块：10 MB * 1492

META URL：bdrive://d28784bff1086450a6c331fb322accccd382228e

### 上传

地理位置：四川成都

运营商：教育网

上行速率：20 Mbps

用时：02:16:39

平均速度：1.82 MB/s

### 下载

### 测试点1

地理位置：福建福州

运营商：中国电信

下行速率：100 Mbps

用时：00:18:15

平均速度：13.62 MB/s

### 测试点2

地理位置：上海

运营商：中国电信

下行速率：1 Gbps

用时：00:02:22

平均速度：104.97 MB/s

## 免责声明

请自行对重要文件做好本地备份

请勿使用本项目上传不符合社会主义核心价值观的文件

请合理使用本项目，避免对哔哩哔哩的存储与带宽资源造成无意义的浪费

该项目仅用于学习和技术交流，开发者不承担任何由使用者的行为带来的法律责任

## 许可证

BiliDrive is under The Star And Thank Author License (SATA)

本项目基于MIT协议发布，并增加了SATA协议

您有义务为此开源项目点赞，并考虑额外给予作者适当的奖励 ∠( ᐛ 」∠)＿
