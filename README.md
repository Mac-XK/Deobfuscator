# Hikari Deobfuscator

针对 [Hikari](https://github.com/HikariObfuscator/Hikari) LLVM 混淆器的静态分析还原工具。

提供 **桌面应用 (macOS)** 和 **命令行/IDA 插件** 两种使用方式。

## 功能特性

- **Hook 目标识别** — 从 Logos 符号表自动提取 hook 了哪个类的哪个方法
- **控制流平坦化 (CFF) 分析** — 统计 `br x8` 分发器、跳转表数量，逐函数展示
- **不透明谓词求值** — 静态模拟 ARM64 算术链，计算恒真/恒假条件
- **加密字符串定位** — 通过熵值分析找出 `__DATA` 段中的加密字符串区域
- **函数包装器还原** — 解析 `MacXKFunctionWrapper` 调用链，还原实际调用目标
- **ObjC 类层级浏览** — 提取类名、父类、方法、属性，树形展示
- **交叉引用 (Xref)** — 分析函数间调用/跳转关系，按引用次数排序
- **Hex 查看器** — 浏览文件原始十六进制数据，支持地址跳转
- **导出报告** — 支持导出 JSON / TXT 格式分析报告

## 桌面应用

基于 Tauri v2 + Rust 构建，拖入二进制文件即可自动分析，结果以可视化仪表盘展示。

<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/5a46add5-7f00-446c-8be9-48d0168ef112" />
<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/0925cf63-809b-45f6-978b-7d52e3fd2cf3" />
<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/a5050174-60ee-4c50-bba1-5ec6c7123a60" />
<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/4beae331-66bb-4bea-bcad-f92e22cf43d5" />


### 支持格式

- Mach-O (macOS/iOS dylib, 可执行文件, Fat Binary)
- ELF (Linux)
- PE (Windows)

### 安装

从 [Releases](../../releases) 下载最新的 `.dmg` 文件，拖入 Applications 即可。

### 使用

1. 打开应用，点击「选择文件」或拖入目标二进制文件
2. 等待分析完成（进度条实时显示）
3. 在仪表盘中查看分析结果
4. 点击各卡片的「查看全部」展开详情
5. 使用导出按钮保存报告

## 命令行工具

适用于无 GUI 环境或批量处理场景。

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

```
========================================================================
## Hook 目标
========================================================================

  Hook 框架: MSHookMessageEx

  Hook 类: UIViewController
    方法: -[UIViewController viewDidLoad]  (0xd61c)
    方法: -[UIViewController viewWillAppear]  (0xfb08)

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

## IDA Pro 插件

### 安装

把 `hikari_ida.py` 复制到 IDA 的 plugins 目录：

```bash
# macOS
cp hikari_ida.py /Applications/IDA\ Pro.app/Contents/MacOS/plugins/

# Windows
copy hikari_ida.py "C:\Program Files\IDA Pro\plugins\"
```

### 使用

1. 用 IDA 打开目标 dylib
2. **Edit → Plugins → Hikari 混淆还原**（快捷键 `Ctrl+Shift+H`）
3. 弹出界面后选择输出目录，点「生成报告」

插件会在 IDA 数据库里加注释和 patch（不透明谓词 NOP 掉、函数标注 hook 目标等），同时生成 txt 报告。

## 原理简述

| 混淆手法 | 特征 | 还原思路 |
|----------|------|----------|
| 控制流平坦化 | 巨大栈帧 + `br x8` 间接跳转 | 追踪跳转表和 dispatch 变量赋值 |
| 不透明谓词 | `eor`/`mul`/`udiv` → `cset` | 静态模拟算术链，算出恒真/恒假 |
| 字符串加密 | `__DATA` 段高熵数据 | 熵值分析定位加密区域 |
| 函数包装 | `MacXKFunctionWrapper` 间接调用 | 顺调用链追踪到真实目标 |

## 局限

- Hook 识别依赖 Logos 符号（`_logos_method$`），strip 后需从调用参数推断
- 部分复杂运算链的不透明谓词求值率有限
- 字符串解密目前只能定位，暂不支持自动还原明文
- 分析引擎主要面向 ARM64 架构

## 环境要求

**桌面应用：** macOS 11.0+ (Apple Silicon / Intel)

**命令行工具：** Python 3.8+ / `lief` / `capstone`

**IDA 插件：** IDA Pro 7.x / 8.x

## License

MIT
