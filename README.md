# Hikari Deobfuscator

针对 [Hikari](https://github.com/HikariObfuscator/Hikari) LLVM 混淆器的静态分析还原工具。

写这个工具的起因很简单——拿到一个 Hikari 混淆过的 dylib，IDA 打开全是 `br x8` 跳转表和一堆算术垃圾指令，F5 出来的伪代码完全没法看。所以就写了两个脚本，一个命令行跑，一个丢 IDA 里用。

目前主要面向 iOS/macOS 平台的 ARM64 Mach-O 文件，对 Logos tweak（Theos/MonkeyDev 项目）的 hook 识别效果比较好。

## 能干什么

- **识别 Hook 目标** — 从符号表自动提取 hook 了哪个类的哪个方法，不需要源码
- **控制流平坦化 (CFF) 分析** — 统计 `br x8` 分发器和跳转表数量
- **不透明谓词求值** — 静态计算 Hikari 插入的恒真/恒假条件，IDA 版可以直接 patch 掉
- **加密字符串定位** — 通过熵值分析找出 `__DATA` 段中的加密字符串区域
- **函数包装器还原** — 解析 `MacXKFunctionWrapper` 调用链，还原实际调用目标

<img width="816" height="849" alt="image" src="https://github.com/user-attachments/assets/9a45b2cc-b310-4f0b-bb11-5e106905c35a" />
<img width="520" height="365" alt="image" src="https://github.com/user-attachments/assets/6b157d26-2e1a-498e-8864-ec539afef6d8" />
<img width="816" height="849" alt="image" src="https://github.com/user-attachments/assets/0ce4e8d9-8bbc-4a3f-90ef-29e8cc11a132" />

## 文件说明

```
deobfuscate.py    # 命令行工具，基于 lief + capstone，不依赖 IDA
hikari_ida.py     # IDA Pro 插件，PyQt5 界面，直接在 IDA 里用
```

## 命令行工具

### 安装依赖

```bash
pip3 install lief capstone
```

### 使用

```bash
python3 deobfuscate.py <target.dylib>
```

跑完会在同目录下生成 `<文件名>_report.txt`。

### 输出示例

拿一个 hook 了 UIViewController 和 NSURLSession 的 tweak 测试：

```
========================================================================
## Hook 目标
========================================================================

  Hook 框架: MSHookMessageEx

  Hook 类: UIViewController
    方法: -[UIViewController viewDidLoad]  (0xd61c)
    方法: -[UIViewController viewWillAppear]  (0xfb08)

  Hook 类: UIApplication
    方法: -[UIApplication openURL]  (0x11a14)

  Hook 类: NSURLSession
    方法: -[NSURLSession dataTaskWithRequest]  (0x14084)

========================================================================
## 混淆概览
========================================================================

  总指令数:              20020
  br x8 分发器数量:      665
  不透明谓词数量:        2
  跳转表数量:            476
  函数包装器数量:        18
  加密字符串区域:        14
```

原始源码大概 20 行，混淆后膨胀到 2 万条指令，但 hook 目标还是能准确提取出来。

## IDA Pro 插件

### 安装

把 `hikari_ida.py` 复制到 IDA 的 plugins 目录：

```
# macOS
cp hikari_ida.py /Applications/IDA\ Pro.app/Contents/MacOS/plugins/

# Windows
copy hikari_ida.py "C:\Program Files\IDA Pro\plugins\"

# Linux
cp hikari_ida.py ~/ida/plugins/
```

重启 IDA。

### 使用

1. 用 IDA 打开目标 dylib
2. **Edit → Plugins → Hikari 混淆还原**（快捷键 `Ctrl+Shift+H`）
3. 弹出界面后选择输出目录（默认就是文件所在目录）
4. 按需勾选分析选项，点「生成报告」

插件会做两件事：
- 在 IDA 数据库里加注释和 patch（不透明谓词 NOP 掉、函数标注 hook 目标等），F5 反编译会干净一些
- 在指定目录生成一份 txt 报告

### 界面选项

| 选项 | 说明 |
|------|------|
| 函数包装器还原 | 解析 MacXKFunctionWrapper 间接调用，标注实际目标 |
| 控制流平坦化分析 | 识别并 patch 不透明谓词，统计 CFF 分发器 |
| 加密字符串标注 | 在 `__DATA` 段标记高熵数据区域 |
| Hook 目标提取 | 从 Logos 符号提取 hook 的类和方法 |

## 原理简述

Hikari 的混淆手法和对应的还原思路：

**控制流平坦化** — 把正常的 if/else/for 拆成一个大 switch，用一个 dispatch 变量控制跳转。特征是函数开头分配巨大栈帧，中间全是 `br x8` 间接跳转。还原思路是追踪跳转表和 dispatch 变量赋值。

**不透明谓词** — 插入一堆 `eor`/`mul`/`udiv` 运算，最后 `cset` 得到一个条件值，但这个条件其实是编译期常量。静态模拟这些运算就能算出恒真还是恒假，然后把假分支干掉。

**字符串加密** — NSLog 之类的格式串在编译后被加密存到 `__DATA`，运行时解密。目前只做了定位（通过熵值），还没做自动解密。

**函数包装** — 把直接调用包一层 `MacXKFunctionWrapper`，增加间接性。顺着调用链追下去就能找到真正的目标函数。

## 局限

- Hook 识别依赖 Logos 符号（`_logos_method$`），如果符号被 strip 了就只能从 MSHookMessageEx 的调用参数去猜
- 不透明谓词的求值率还不够高，有些复杂的运算链追踪不完整
- 字符串解密目前只能定位，还不能自动还原明文
- 只支持 ARM64，不支持 x86_64

## 环境要求

- Python 3.8+
- 命令行工具：`lief`、`capstone`
- IDA 插件：IDA Pro 7.x / 8.x（自带 PyQt5）

## License

MIT
