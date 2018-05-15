# Lite Yun 个人版（python版停止支持）

## 简介

本版本是最初始的版本，使用python编写。  
本项目的目标用户主要是那些有自己的vps服务器，想要快速地获取服务器信息并想充分利用服务器剩余存储资源的个人用户。
要想监控服务器信息，传统的做法是通过ssh连接到服务器并输入命令，得到的结果为一串数字，很不直观；而传输文件则需要ftp或者sftp服务；而且一旦ssh服务出现故障进程结束后，我们便没有办法继续远程连接服务器，而重装服务器则是一件非常麻烦的事情。而lite yun则将这些功能全部整合进了web页面，并且提供十分直观的图表来展示服务器用量、清晰且使用简便的方式来操作所有进程。而且独立的vnc终端也可以应对不时之需。

---
## 使用说明
本版本部署比较复杂，但是支持vnc。
```
运行环境：ubuntu 16.04 x64
安装说明：
    1、 确保服务器上安装有python3，然后运行sudo apt install python3-pip安装pip3
    2、 运行sudo pip3 install py-cpuinfo psutil tornado 安装python包。由于国内网络环境不是很好，这个过程可能十分缓慢。
    3、 运行sudo apt install xauth xterm x11-common x11-xkb-utils xfonts-base xfonts-encodings xfonts-utils xserver-common xvfb x11vnc 安装vnc依赖
    4、 运行sudo x11vnc -rfbport 5901 -create -forever -rawfb console &开启vnc服务
    5、 切换至普通用户，git clone https://github.com/SBOrg666/Lite-Yun.git 将源码下载至服务器，进入Lite-Yun/static/noVNC/utils目录，执行./launch.sh --vnc 127.0.0.1:5901 &命令
    6、 进入Lite-Yun目录内，运行python3 run.py
    7、 如果需要长期后台运行，请搭配screen进行操作。
```

vnc服务由于各个服务器间有差异，因此个别运行参数需要自行调整。

默认的登录帐号是admin@liteyun.com，密码是lite_yun_admin，如果需要修改，请使用sqlite客户端修改ACCOUNT.sqlite数据库文件。