# IoC_Mem_Scan_Tool
高性能的威胁情报IOC Windows终端搜索工具，使用go语言编写，可实现指定IOC在当前主机内存下的搜索。

底层使用Boyer-Moore-Horspool算法优化查询速度，同时使用异步协程的方式，加快整机查询速度。

实测单个IOC 16G内存可在30s内完成整体检索。

# 使用场景

主要适用于在网络侧 NDR或IDS中检测到主机端侧存在IOC外联相关威胁行为，安服上机取证或受害者自行排查，方便基于检测出的IOC外联，快速定位存在外联的进程，从而最快完成取证和威胁发现。

# 使用方式
## 1、交互式方式
### 1-1  式输入待查询IOC
直接打开程序文件，根据提示输入IOC，按确认键输入即可

<img width="852" height="328" alt="image" src="https://github.com/user-attachments/assets/b21439cd-1e1d-4503-83cc-d08226c5512c" />

### 1-2 交互式输入待查询IOC文件
也可以将IOC存入文件中，通过换行进行分割，交互式输入框中，在提示输入待查询IOC时按回车跳过，在接下来提示输入待查询IOC文件时输入文件路径

<img width="1690" height="240" alt="image" src="https://github.com/user-attachments/assets/9c49c419-25ee-4911-8117-2e84cc0b19f1" />


## 2、命令行方式
### 2-1  命令行输入待查询IOC

windows_ioc_scan.exe -ioc "待查询IOC"

如 windows_ioc_scan.exe -ioc "baidu.com"

程序会自动开始扫描

<img width="1694" height="574" alt="image" src="https://github.com/user-attachments/assets/86c2a0da-f493-4bf0-9853-de70527eb8b9" />


也可以同时输入多个IOC，使用英文逗号分割。程序会自动记录多个IOC进行检索。（目前算法未对过多输入IOC做优化，可能会导致查询时间增长）如  

windows_ioc_scan.exe -ioc "baidu.com,google.com"

<img width="1697" height="587" alt="image" src="https://github.com/user-attachments/assets/7f4fd323-b87b-478f-a323-782014fbcabf" />

### 2-2  命令行输入待查询IOC文件

程序支持读取包含多个IOC的文件输入，文件中不同IOC通过换行进行区分。

举例如下图

<img width="643" height="109" alt="image" src="https://github.com/user-attachments/assets/1cf5632c-7f3f-4d5b-b63f-bfe552cf677b" />

在命令行中输入

windows_ioc_scan.exe -iocfile "test_ioc.txt"

<img width="1709" height="391" alt="image" src="https://github.com/user-attachments/assets/fb511a63-c345-42a4-bf54-3f4abaa52467" />



