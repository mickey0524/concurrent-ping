# concurrent-ping

异步并发ping多个站点

## single\_ping

一次ping一个站点，原生socket发送icmp包

## multiple\_ping

一次ping多个站点，不过是同步的，也就是ping一个站点，等待包全部回来或超时，再ping下一个站点

## async\_multiple\_ping

和multiple\_ping完成类似的功能，不过是异步的，建立多个socket，一次性发送所有的icmp报文，回来一个响应包处理一个

## 注意

使用gcc编译生成可执行文件后，需要使用sudo调用root权限ping

## 例子

```
gcc -o ping async_multiple_ping.c -lpthread

sudo ./ping 127.0.0.1 www.baidu.com www.toutiao.com www.taobao.com www.sina.com www.tmall.com 18.231.41.23 www.google.com
```
