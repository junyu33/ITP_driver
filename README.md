# ITP_driver
环境配置见：https://blog.junyu33.me/2023/01/10/winkernel_environ.html

也可以使用 VS2017+windbg+virtualKD-redux

源代码位于 `ITP_driver/KMDF Driver1/Source.c` 与`ITP_driver/ConsoleApplication1/ConsoleApplication1.cpp`

## to-do list
大创大致路径
- ~~写出 hello world 驱动~~
- ~~写出能控制路径访问的驱动~~

> 具体而言，可以对指定路径，例如`C:/Users/WDKRemoteUser/Desktop/hello_junyu33`这个路径禁止访问。

- 零信任算法实现
- 将零信任算法与路径访问相结合

## changelog

- ver 0.0.1：初步实现手动修改代码对路径访问的控制。（2/4）
- ver 0.0.2：可以通过命令行来控制对单次路径访问的控制。（2/11）

> bugs:
>
> - ~~反应很慢很慢，以分钟计。~~
> - 卸载驱动后，无法重新加载驱动，必须重启系统。

- ver 0.0.3：单次允许之后暂时将路径加入白名单；将路径移到了结构体数组，为下一步添加路径做准备；解决了反应慢的问题。（2/11）

- ver 0.0.4：实现自动化添加路径（默认为白名单），准备下一步定时移除白名单。（2/12）

> bugs:
>
> - ~~目前用的判定是如果父文件夹访问，则子文件夹也可以访问，之后应改成**子文件夹需再次确认**。~~
> - ~~还没有将访问的路径信息从内核端输出到应用端。~~

- ver 0.1.0：修复了0.0.4中的两个bug（第一个修改把`wcsstr`改成了`_wcsicmp`）。另外实现了一个简易的定时移除白名单功能（最开始允许2次访问，如果之后再允许就改成65536次）。（2/15）

> bugs:
>
> - 驱动的关键变量都是全局变量，并发性脆弱。

- ver 0.1.1：为了方便测试，将测试的路径范围限制在`\Users\WDKRemoteUser\Desktop\123`内。
