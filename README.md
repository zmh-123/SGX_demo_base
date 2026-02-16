# 我的毕设

这个项目是本人的毕设，目前只跑通了一个小demo，其实也就是把环境配了一下，当然配环境的过程还是很痛苦的，我的cpu是AMD的所以只能用Simulation Mode，但又由于这个SDK找不到，我目前只能找到最新版的，但是最新版的SDK确实非常难用，旧版说是要付费订阅，所以只好用新版＋手动配置Simulation来实现相同的效果，但是最后肯定是要打包到Intel处理器上进行测试的，当然这都是后话了。

## 前置知识

**1.Enclave**

SGX 在内存中划出了一块受硬件保护的区域，叫做 **Enclave** ，直译为飞地，可以理解为安全区，这里面的数据都是加密的，即使是操作系统，虚拟机甚至是BIOS都无法查看或者修改里面的内容，外部程序只能通过特定的“窗口”（接口）把数据递进去，Enclave处理完再递出来。

**2.Attestation**

简单来说就是就是信任链与认证机制，为了知道自己访问的那个Enclave是真的，引入了认证机制。CPU 会记录 Enclave 初始化时的代码和数据（像指纹一样），生成一个签名，通过第三方实体（Intel 认证服务或自建认证服务）来验证这个签名 。只有签名对上了，才证明这个 Enclave 是原本那个“好人”，且运行在安全的 SGX 平台上 。

**3.ECALL 与 OCALL**

App是不可信部分，负责读文件、联网、处理ui，而Enclave是可信部分，负责存密钥、算加密，连接这两个部分的就是进出通道ECALL 与 OCALL，App通过前者呼叫Enclave进行，Enclave通过后者呼叫App。

**4.密码学相关**

需要一点AES和DES的相关知识，不再赘述。

## 环境要求

我是在Windows上做的，最好是Intel处理器，AMD的话非常及其之麻烦，另外Visual Studio需要2019或者2017的，2022的有问题，安装SDK的时候不会被识别，然后SDK的话自己有 Intel® Software Guard Extensions SDK for Windows 1.16或者更古早的版本是最好的，没有的话我之后会给出如何找最新版的，Intel的产品非常反人类，即使是这个包也非常难找

## 主要结构

需要说明的是一些临时文件和包文件因为太大了传不上来遂弃，需要自己照然后通过NuGet进行安装

```
SGX_demo_base/
├── App/                   # 非安全区应用程序
│   ├── App.cpp            # 主程序入口
│   ├── SGX_demo1_u.h      # 自动生成的不可信桥接头文件
│   └── SGX_demo1_u.c      # 自动生成的桥接代码
├── SGX_demo1/             # Enclave
|   ├── SGX_demo1_private.pem # 私钥 我这里没传
│   ├── SGX_demo1.cpp      # Enclave实现
│   ├── SGX_demo1.edl      # EDL接口定义
│   ├── SGX_demo1_t.h      # 自动生成的可信桥接头文件
│   └── SGX_demo1_t.c      # 自动生成的桥接代码
├── packages/              # NuGet 依赖包（通过nuget restore恢复）太大了传不上
├── SGX_demo1.sln          # 解决方案
├── readme.md
└── .gitignore
```

## 前置工作

##### 1.准备Visual Studio 2019

这个比较简单，不再赘述

##### 2.下载安装SDK

> **注意：一定要先装vs再装SDK**

必装Intel SGX SDK，PSW的话如果有支持SGX的硬件必装，如果是模拟模式，就可以不装了，最后算数据的时候在Intel电脑上装就行。

[产品连接]: https://lemcenter.intel.com/productDownload/?Product=3407

从这个连接点进去，你大概率还没有注册，先注册一手，推荐用谷歌邮箱，qq或者163容易收不到消息,然后申请你要的sdk，点击download就可以看到了

![Intel_SDK](./images/Intel_sdk.png)

然后下载那个安装包。

> 可以看到The product updates/upgrades below are available based on your support subscription status，基本上就是说根据你的账号订阅级别（是否付费/VIP），我们决定给你看哪些下载链接，通俗一点就是Intel 并没有向你的（免费）账号开放旧版本的下载权限。

另：下载了最新版的意味着我们必须手动构建启动器来进行了

