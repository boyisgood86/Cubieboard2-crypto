Cubieboard2-crypto
==================

A20 hardwave crypto

分为驱动和调用驱动的API框架层

驱动是注册到一个加密框架里面去了，而为上层提供API也是一个框架，有多种方法可以使用这个加密驱动。一般的，openssl或者设备节点模式。
我这里提供了设备节点模式的API，把它们分别放到linux/driver/ 目录下，然后按照随带的Makefile修改下即可。最后去 make menuconfig里面select


newleaves@126.com


