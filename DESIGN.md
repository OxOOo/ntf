## 核心逻辑

一个线程监听unix socket，处理和web的配置以及信息同步。
对于每个tcp forward，启动一个线程监听网络请求。
    每次新来一个网络请求，放入一个链表中。
一个超时线程，定时关闭链表中没有用的请求。
一个线程监听port，所有client连接这个port。
    每次网络请求来，启动新线程进行处理。
    普通情况下，同步心跳数据。
    如果有新的网络转发请求，server向client发送一个数据包。
        client和port创建新连接
        client发起认证数据包
        server从链表中拿到相应网络请求，进行数据转发。

心跳：每10秒钟一个心跳包，60s没有收到心跳包则断开链接。这条规则对server-client之间的控制链路和转发链路都成立。

## web 和 server 通信

web 和 server 通过unix domain socket进行通信。
web每次重新配置，server都会关闭所有连接并重新和client连接。

每个消息/命令为一行，以\n结尾。

1. 同步配置 web -> server
CONFIG config_json_str

config_json_str:
{
    clients: [{
        id: string,
        key: string
    }],
    tcp_forwards: [{
        client_id: string,
        listen_port: int,
        forward_client_ip: string,
        forward_client_port: int
    }]
}

2. 同步配置OK
CONFIG_OK

3. 获取状态
FETCH_STATUS

4. 返回状态
STATUS status_json_str

status_json_str:
{
    startup_time: string
}

5. 返回错误信息
ERR message

## server 和 client 通信

通用格式:

[4-bytes id size][plain id]
[4-bytes header size][64-bytes header hmac][plain binary header]
[encrypted body]

id size应该不超过1KB
header size应该不超过1MB
