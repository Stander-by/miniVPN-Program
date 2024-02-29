# 使用说明

- 根据实验报告的“测试环境搭建”创建相应网络拓扑：

```shell
# 创建docker网络extranet
root@VM:/$ sudo docker network create --subnet=10.0.2.0/24 --gateway=10.0.2.8 --opt "com.docker.network.bridge.name"="docker1" extranet
# 创建docker网络intranet
root@VM:/$ sudo docker network create --subnet=192.168.60.0/24 --gateway=192.168.60.1 --opt "com.docker.network.bridge.name"="docker2" intranet

# 创建并运行容器HostU并删除默认路由
seed@VM:~$ sudo docker run -it --name=HostU --hostname=HostU --net=extranet --ip=10.0.2.7 --privileged "seedubuntu" /bin/bash
root@HostU:/# route del default
root@HostU:/# cd home
root@HostU:/home# mkdir xr
root@HostU:/home# cd xr
# 创建并运行容器HostU2并删除默认路由
seed@VM:~$ sudo docker run -it --name=HostU2 --hostname=HostU2 --net=extranet --ip=10.0.2.27 --privileged "seedubuntu" /bin/bash
root@HostU2:/# route del default
root@HostU2:/# cd home
root@HostU2:/home# mkdir xr
root@HostU2:/home# cd xr
# 创建并运行容器HostV并删除默认路由
seed@VM:~$ sudo docker run -it --name=HostV --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash
root@HostV:/# route del default
root@HostV:/# route add -net 192.168.53.0/24 gw 192.168.60.1
root@HostV:/# sudo /etc/init.d/openbsd-inetd restart
```

- 编译`VPN_Program`文件夹下的`tlsserver,c`以及`tlsclient.c`：
```shell
gcc -o tlsclient tlsclient.c -lssl -lcrypto
gcc -o tlsserver tlsserver.c -lssl -lcrypto -lcrypt -lpthread
```
- 将编译好的程序复制到服务端和客户端
- 在服务端( `VM` )
```shell
seed@VM:~/tls$ sudo ./tlsserver 
Enter PEM pass phrase:123456
```
- 在客户端( `HostU / HostU2` )
```shell
root@HostU:/xr# sudo ./tlsclient 10.0.2.8 4433 
SSL connection is successful
SSL connection using AES256-GCM-SHA384
username:seed
passwd:dees
recvbuf:Client verify succeed
client verify succeed!
virtual ip: 192.168.53.6/24
tunid:0
Setup TUN interface success!
Got a packet from TUN
```
