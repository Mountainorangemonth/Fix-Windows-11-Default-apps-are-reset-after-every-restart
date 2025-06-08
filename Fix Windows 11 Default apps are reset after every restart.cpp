#include <windows.h>      // Windows API核心头文件
#include <aclapi.h>       // 访问控制列表API
#include <tchar.h>        // 通用字符支持
#include <iostream>       // 输入输出流
#include <shellapi.h>     // ShellExecuteEx自提升

#pragma comment(lib, "advapi32.lib")  // 链接安全API库

// 判断当前进程是否以管理员权限运行
bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE; // 标记是否为管理员
    PSID adminGroup = NULL; // 管理员组SID指针
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY; // NT权限标识
    if (AllocateAndInitializeSid(&NtAuthority, 2, // 分配并初始化管理员组SID
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin); // 检查当前进程是否属于管理员组
        FreeSid(adminGroup); // 释放SID内存
    }
    return isAdmin == TRUE; // 返回是否为管理员
}

// 如果不是管理员则自提升
void SelfElevateIfNotAdmin()
{
    if (!IsRunAsAdmin()) // 如果不是管理员
    {
        TCHAR szPath[MAX_PATH]; // 存储程序路径
        if (GetModuleFileName(NULL, szPath, MAX_PATH)) // 获取当前程序路径
        {
            SHELLEXECUTEINFO sei = { sizeof(sei) }; // 初始化结构体
            sei.lpVerb = _T("runas"); // 以管理员方式运行
            sei.lpFile = szPath; // 程序路径
            sei.hwnd = NULL; // 无窗口句柄
            sei.nShow = SW_NORMAL; // 正常显示窗口
            if (!ShellExecuteEx(&sei)) // 执行自提升
            {
                std::cerr << "[错误] 无法自提升为管理员权限。" << std::endl; // 提示错误
            }
        }
        exit(0); // 退出当前进程
    }
}

// 为“ALL APPLICATION PACKAGES”添加注册表权限
bool AddAllAppPackagesPermission() {
    DWORD dwRes = ERROR_SUCCESS; // 返回值
    PACL pOldDACL = nullptr; // 原DACL指针
    PACL pNewDACL = nullptr; // 新DACL指针
    PSECURITY_DESCRIPTOR pSD = nullptr; // 安全描述符指针
    EXPLICIT_ACCESS ea; // 显式访问结构体

    // 1. 打开注册表项
    HKEY hKey = NULL; // 注册表句柄
    LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, // 打开HKEY_CURRENT_USER下的子键
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
        0, READ_CONTROL | WRITE_DAC, &hKey);
    if (lResult != ERROR_SUCCESS) { // 打开失败
        std::cerr << "[错误] 打开注册表项失败 (错误代码: " << lResult << ")" << std::endl;
        return false;
    }

    // 2. 获取注册表项的现有安全信息
    dwRes = GetSecurityInfo(
        hKey, // 注册表句柄
        SE_REGISTRY_KEY, // 对象类型为注册表
        DACL_SECURITY_INFORMATION, // 获取DACL
        NULL, NULL, // 不获取所有者和主组
        &pOldDACL, // 原DACL
        NULL, // 不获取SACL
        &pSD // 安全描述符
    );

    if (dwRes != ERROR_SUCCESS) { // 获取失败
        std::cerr << "[错误] 获取安全信息失败 (错误代码: " << dwRes << ")" << std::endl;
        if (pSD) LocalFree(pSD); // 释放安全描述符
        RegCloseKey(hKey); // 关闭注册表
        return false;
    }

    // 3. 初始化EXPLICIT_ACCESS结构
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS)); // 清零结构体
    ea.grfAccessPermissions = KEY_READ; // 允许读取和执行
    ea.grfAccessMode = GRANT_ACCESS; // 授予权限
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT; // 权限继承
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME; // 受托人类型为名称
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP; // 受托人是组
    ea.Trustee.ptstrName = (LPTSTR)_T("ALL APPLICATION PACKAGES"); // 组名

    // 4. 创建新的DACL
    dwRes = SetEntriesInAcl(
        1, // 1个访问项
        &ea, // 访问项数组
        pOldDACL, // 原DACL
        &pNewDACL // 新DACL
    );

    if (dwRes != ERROR_SUCCESS) { // 创建失败
        std::cerr << "[错误] 创建访问控制列表失败 (错误代码: " << dwRes << ")" << std::endl;
        if (pSD) LocalFree(pSD); // 释放安全描述符
        RegCloseKey(hKey); // 关闭注册表
        return false;
    }

    // 5. 将新DACL应用到注册表项
    dwRes = SetSecurityInfo(
        hKey, // 注册表句柄
        SE_REGISTRY_KEY, // 对象类型
        DACL_SECURITY_INFORMATION, // 设置DACL
        NULL, // 不设置所有者
        NULL, // 不设置主组
        pNewDACL, // 新DACL
        NULL // 不设置SACL
    );

    // 6. 清理分配的内存
    if (pSD) {
        LocalFree(pSD); // 释放安全描述符
        pSD = nullptr;
    }
    if (pNewDACL) {
        LocalFree(pNewDACL); // 释放新DACL
        pNewDACL = nullptr;
    }
    if (hKey) {
        RegCloseKey(hKey); // 关闭注册表句柄
        hKey = nullptr;
    }

    if (dwRes != ERROR_SUCCESS) { // 应用失败
        std::cerr << "[错误] 应用安全设置失败 (错误代码: " << dwRes << ")" << std::endl;
        return false;
    }

    return true; // 成功
}

int main() {
    // 自提升管理员权限
    SelfElevateIfNotAdmin();

    std::wcout << L"目标注册表项: HKEY_CURRENT_USER\\"; // 输出注册表根键
    std::wcout << L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" << std::endl; // 输出子键

    std::cout << "正在为'ALL APPLICATION PACKAGES'添加安全权限..." << std::endl; // 提示信息

    if (AddAllAppPackagesPermission()) { // 调用权限设置函数
        std::cout << "权限设置成功!" << std::endl; // 成功提示
        std::cout << "已添加到'组或用户名'列表并授予权限" << std::endl; // 详细提示
        std::cout << "权限: KEY_READ" << std::endl; // 权限说明
        system("pause"); // 暂停，等待用户按键
        return 0; // 正常退出
    }
    else {
        std::cerr << "权限设置失败!" << std::endl; // 失败提示
        system("pause"); // 暂停
        return 1; // 非正常退出
    }
}