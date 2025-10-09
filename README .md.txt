# S-DES 加密解密工具

## 1. 用户指南

### 1.1 软件概述
S-DES加密解密工具是一个基于简化版DES算法的图形化应用程序，支持ASCII文本和二进制数据的加密解密操作，并提供暴力破解和封闭测试功能。

### 1.2 系统要求
- **操作系统**: Windows 7/10/11, Linux, macOS
- **Python版本**: Python 3.6 或更高版本
- **依赖库**: PyQt5

### 1.3 安装说明
1. 确保系统已安装Python 3.6或更高版本
2. 安装PyQt5库：
   pip install PyQt5
3. 下载源代码文件 `sdes_gui.py`
4. 运行程序：
   python sdes_gui.py

### 1.4 使用说明

#### 1.4.1 基本加解密功能
1. **设置密钥**:
   - 输入10位二进制密钥（如：`1010101010`）
   - 点击"设置密钥"按钮验证并激活

2. **选择操作**:
   - **加密**: 将明文转换为密文
   - **解密**: 将密文恢复为明文

3. **输入数据**:
   - 输入8位二进制数据（如：`11001100`）
   - 点击"执行"按钮进行操作

#### 1.4.2 字符串处理功能
1. **设置密钥**: 同上
2. **选择操作**: 加密或解密
3. **输入ASCII字符串**: 在文本框中输入要处理的文本
4. **执行操作**: 点击"执行"按钮，结果将显示在输出框中
5. **复制结果**: 可使用"复制结果"按钮将输出复制到剪贴板

#### 1.4.3 暴力破解功能
1. **输入明密文对**:
   - 在"明文"框中输入8位二进制明文
   - 在"密文"框中输入8位二进制密文
2. **执行破解**:
   - 点击"开始破解"按钮
   - 实时查看进度条和破解状态
   - 可随时点击"停止破解"按钮中断过程
3. **查看结果**: 破解完成后显示所有有效密钥列表

#### 1.4.4 封闭测试功能
1. **输入明文**: 输入8位二进制明文
2. **执行测试**: 点击"开始测试"按钮
3. **查看结果**: 显示是否存在多密钥等价性（多个密钥产生相同密文）

## 2. 开发手册

### 2.1 代码结构
```
sdes_gui.py
├── S_DES类 (核心算法)
├── BruteForceWorker类 (暴力破解线程)
└── S_DES_GUI类 (图形界面)
```

### 2.2 核心类说明

#### 2.2.1 `S_DES` 类
S-DES算法核心实现类。
- **关键方法**:
  - `set_key()`: 设置10位二进制密钥
  - `encrypt_block()`: 加密8位二进制块
  - `decrypt_block()`: 解密8位二进制块
  - `encrypt_text()`: 加密ASCII字符串
  - `decrypt_text()`: 解密ASCII字符串
  - `generate_subkeys()`: 生成子密钥k1和k2

#### 2.2.2 `BruteForceWorker` 类
暴力破解的多线程实现。
- **关键方法**:
  - `run()`: 线程执行函数，遍历所有可能的密钥
  - `stop()`: 停止破解过程

#### 2.2.3 `S_DES_GUI` 类
主窗口类，负责UI界面和功能调度。
- **关键方法**:
  - `_init_ui()`: 界面初始化
  - `_process_basic()`: 处理基本加解密
  - `_process_string()`: 处理字符串加解密
  - `_start_brute_force()`: 启动暴力破解
  - `_start_closed_test()`: 执行封闭测试

### 2.3 接口文档

#### 2.3.1 加密解密接口
```python
# 设置密钥
def set_key(self, key: list) -> None

# 块加密解密
def encrypt_block(self, plaintext_block: list) -> list
def decrypt_block(self, ciphertext_block: list) -> list

# 字符串加密解密
def encrypt_text(self, plaintext: str) -> str
def decrypt_text(self, ciphertext: str) -> str
```

#### 2.3.2 工具函数接口
```python
# 二进制与字符串转换
@staticmethod
def ascii_to_bits(text: str) -> list
@staticmethod
def bits_to_ascii(bits_list: list) -> str

# 二进制字符串与列表转换
@staticmethod
def binary_str_to_list(binary_str: str) -> list
@staticmethod
def binary_list_to_str(binary_list: list) -> str
```

