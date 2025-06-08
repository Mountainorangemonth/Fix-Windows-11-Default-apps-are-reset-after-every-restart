# Fix Windows 11 Default apps are reset after every restart
***

**这个问题我发现解决方案很少有可以恢复，为了懒人操作的所以有了这个项目，其实我不感觉这是个项目**

**在哔哩哔哩上有 UP 主针对该问题进行了详细分析，通过跟踪事件查看器日志发现默认应用被重置与注册表权限被重置或错误有关，要解决这个问题也不难，只需要手动修改注册表权限即可。**

**问题是在 Windows 11 中 `ALL APPLICATION PACKAGES` 是个特殊的用户组，微软使用该用户组运行权限受限的进程或应用程序，通常情况下该用户组用于文件和文件夹的访问控制。**

**但是在`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`这里面用户没有了，只需要在注册表这个文件夹权限添加`ALL APPLICATION PACKAGES`用户，懒人就用软件。**

***

