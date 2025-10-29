# IoC_Mem_Scan_Tool
高性能的威胁情报IOC终端搜索工具，使用go语言编写，可实现指定IOC在当前主机内存下的搜索。



# 使用方式
## 命令行方式
### 命令行输入待查询IOC

windows_ioc_scan.exe -ioc "待查询IOC"

如 windows_ioc_scan.exe -ioc "baidu.com"

程序会自动开始扫描

<img width="1694" height="574" alt="image" src="https://github.com/user-attachments/assets/86c2a0da-f493-4bf0-9853-de70527eb8b9" />


也可以同时输入多个IOC，使用英文逗号分割。程序会自动记录多个IOC进行检索。如  

windows_ioc_scan.exe -ioc "baidu.com,google.com"

<img width="1697" height="587" alt="image" src="https://github.com/user-attachments/assets/7f4fd323-b87b-478f-a323-782014fbcabf" />
