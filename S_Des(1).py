import sys
import time
# 导入PyQt5 GUI组件，用于构建图形界面（窗口、布局、按钮、输入框等）
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QGroupBox, QRadioButton, QProgressBar,
                             QTabWidget, QMessageBox, QSplitter)
# 导入PyQt5线程与信号模块，用于多线程处理和界面更新通信
from PyQt5.QtCore import Qt, QThread, pyqtSignal


class S_DES:
    """S-DES（简化版DES）加密算法核心类，封装密钥生成、数据块加解密、ASCII字符串转换等核心功能。"""
    # 定义S-DES算法所需的置换表和S盒（遵循标准S-DES规范）
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]       # 10位密钥初始置换表
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]             # 生成子密钥的8位置换表
    LEFT_SHIFT1 = [2, 3, 4, 5, 1]             # 子密钥k1生成时的循环左移规则
    LEFT_SHIFT2 = [3, 4, 5, 1, 2]             # 子密钥k2生成时的循环左移规则
    IP = [2, 6, 3, 1, 4, 8, 5, 7]             # 明文块初始置换表
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]         # 最终置换表（IP的逆置换）
    EP_BOX = [4, 1, 2, 3, 2, 3, 4, 1]         # 轮函数中4位→8位的扩展置换表
    S_BOX1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]  # 非线性S盒1
    S_BOX2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]  # 非线性S盒2
    SP_BOX = [2, 4, 3, 1]                     # 轮函数中4位的置换表

    def __init__(self, key=None):
        """初始化S-DES对象，若提供密钥则立即生成子密钥。
        :param key: 可选参数，10位二进制密钥（列表形式，元素为0或1）
        """
        self.key = key        # 存储10位二进制密钥（列表，元素为0/1）
        self.subkeys = []     # 存储生成的两个子密钥k1、k2（各为8位列表）
        if key:  # 若初始化时提供密钥，直接生成子密钥
            self.generate_subkeys()

    def set_key(self, key):
        """设置10位二进制密钥，并生成对应的子密钥k1和k2。
        :param key: 10位二进制密钥（列表形式，元素为0或1）
        :raises ValueError: 当密钥长度不为10或包含非0/1字符时抛出
        """
        # 验证密钥合法性：长度必须为10，且所有元素只能是0或1
        if len(key) != 10 or not all(bit in (0, 1) for bit in key):
            raise ValueError("密钥必须是10位二进制数（仅包含0和1）")
        self.key = key
        self.generate_subkeys()  # 调用方法生成子密钥

    @staticmethod
    def permute(block, table):
        """根据置换表对数据块进行置换操作。
        :param block: 待置换的二进制数据块（列表形式）
        :param table: 置换表（元素为目标位置对应的原始索引，从1开始）
        :return: 置换后的数据块（列表形式）
        """
        return [block[i - 1] for i in table]

    @staticmethod
    def left_shift(block, shift_table):
        """对数据块执行循环左移操作（根据移位表指定的规则）。
        :param block: 待移位的二进制数据块（列表形式）
        :param shift_table: 移位表（元素为移位后位置对应的原始索引，从1开始）
        :return: 左移后的数据块（列表形式）
        """
        return [block[i - 1] for i in shift_table]

    def generate_subkeys(self):
        """生成子密钥k1和k2（密钥扩展流程）。
        步骤：1. 对10位密钥执行P10置换；2. 分割为左右5位；3. 左移生成k1；4. 再次左移生成k2。
        """
        # 1. 对10位密钥执行P10置换
        p10_result = self.permute(self.key, self.P10)
        # 2. 将置换结果分割为左5位和右5位
        left, right = p10_result[:5], p10_result[5:]
        # 3. 生成k1：对左右部分各左移1位，然后执行P8置换
        left1 = self.left_shift(left, self.LEFT_SHIFT1)
        right1 = self.left_shift(right, self.LEFT_SHIFT1)
        k1 = self.permute(left1 + right1, self.P8)
        # 4. 生成k2：对k1的左右部分各再左移2位，然后执行P8置换
        left2 = self.left_shift(left1, self.LEFT_SHIFT2)
        right2 = self.left_shift(right1, self.LEFT_SHIFT2)
        k2 = self.permute(left2 + right2, self.P8)
        self.subkeys = [k1, k2]  # 存储生成的两个子密钥

    def f_function(self, right, subkey):
        """Feistel网络的轮函数：实现扩展置换→异或→S盒替换→SP置换的流程。
        :param right: 8位数据块的右4位（列表形式，元素为0/1）
        :param subkey: 当前轮使用的子密钥（8位列表，元素为0/1）
        :return: 轮函数处理后的4位结果（列表形式）
        """
        # 步骤1：扩展置换（将4位扩展为8位）
        expanded = self.permute(right, self.EP_BOX)
        # 步骤2：扩展结果与子密钥进行按位异或
        xor_result = [expanded[i] ^ subkey[i] for i in range(8)]
        # 步骤3：将异或结果分割为左4位和右4位，分别送入S盒1和S盒2
        left_s, right_s = xor_result[:4], xor_result[4:]
        # 处理S盒1：根据第1、4位确定行，第2、3位确定列，查找S盒1得到2位输出
        row1 = left_s[0] * 2 + left_s[3]
        col1 = left_s[1] * 2 + left_s[2]
        s1_val = self.S_BOX1[row1][col1]
        s1_bits = [(s1_val >> 1) & 1, s1_val & 1]  # 转换为2位二进制
        # 处理S盒2：根据第1、4位确定行，第2、3位确定列，查找S盒2得到2位输出
        row2 = right_s[0] * 2 + right_s[3]
        col2 = right_s[1] * 2 + right_s[2]
        s2_val = self.S_BOX2[row2][col2]
        s2_bits = [(s2_val >> 1) & 1, s2_val & 1]
        # 步骤4：合并S盒输出（共4位），并执行SP置换
        return self.permute(s1_bits + s2_bits, self.SP_BOX)

    def encrypt_block(self, plaintext_block):
        """加密单个8位二进制数据块。
        :param plaintext_block: 8位二进制明文块（列表形式，元素为0/1）
        :return: 8位二进制密文块（列表形式）
        :raises ValueError: 当密钥未设置或明文块格式非法时抛出
        """
        # 检查子密钥是否生成（验证密钥已设置）
        if len(self.subkeys) != 2:
            raise ValueError("请先设置密钥")
        # 验证明文块格式：必须是8位且仅包含0或1
        if len(plaintext_block) != 8 or not all(bit in (0, 1) for bit in plaintext_block):
            raise ValueError("明文块必须是8位二进制数（仅包含0和1）")
        # 步骤1：对明文块执行初始置换IP
        ip_result = self.permute(plaintext_block, self.IP)
        left, right = ip_result[:4], ip_result[4:]
        # 步骤2：第一轮Feistel网络（使用子密钥k1）
        f_out = self.f_function(right, self.subkeys[0])
        new_left = [left[i] ^ f_out[i] for i in range(4)]  # 左半部分与轮函数结果异或
        left, right = right, new_left  # 交换左右部分
        # 步骤3：第二轮Feistel网络（使用子密钥k2）
        f_out = self.f_function(right, self.subkeys[1])
        new_left = [left[i] ^ f_out[i] for i in range(4)]
        # 步骤4：合并结果并执行最终置换IP_INV
        return self.permute(new_left + right, self.IP_INV)

    def decrypt_block(self, ciphertext_block):
        """解密单个8位二进制数据块。
        :param ciphertext_block: 8位二进制密文块（列表形式，元素为0/1）
        :return: 8位二进制明文块（列表形式）
        :raises ValueError: 当密钥未设置或密文块格式非法时抛出
        """
        # 检查子密钥是否生成（验证密钥已设置）
        if len(self.subkeys) != 2:
            raise ValueError("请先设置密钥")
        # 验证密文块格式：必须是8位且仅包含0或1
        if len(ciphertext_block) != 8 or not all(bit in (0, 1) for bit in ciphertext_block):
            raise ValueError("密文块必须是8位二进制数（仅包含0和1）")
        # 步骤1：对密文块执行初始置换IP（与加密时相同）
        ip_result = self.permute(ciphertext_block, self.IP)
        left, right = ip_result[:4], ip_result[4:]
        # 步骤2：第一轮Feistel网络（解密时使用子密钥k2，与加密方向相反）
        f_out = self.f_function(right, self.subkeys[1])
        new_left = [left[i] ^ f_out[i] for i in range(4)]
        left, right = right, new_left  # 交换左右部分
        # 步骤3：第二轮Feistel网络（使用子密钥k1）
        f_out = self.f_function(right, self.subkeys[0])
        new_left = [left[i] ^ f_out[i] for i in range(4)]
        # 步骤4：合并结果并执行最终置换IP_INV
        return self.permute(new_left + right, self.IP_INV)

    @staticmethod
    def ascii_to_bits(text):
        """将ASCII字符串转换为8位二进制块的列表。
        :param text: 要转换的ASCII字符串
        :return: 列表，每个元素是表示一个字符的8位二进制列表（元素为0/1）
        """
        return [
            [int(bit) for bit in bin(ord(char))[2:].zfill(8)]  # 字符→ASCII码→8位二进制列表
            for char in text
        ]

    @staticmethod
    def bits_to_ascii(bits_list):
        """将8位二进制块的列表转换为ASCII字符串。
        :param bits_list: 列表，每个元素是8位二进制列表（元素为0/1）
        :return: 转换后的ASCII字符串
        """
        return ''.join(
            chr(int(''.join(map(str, bits)), 2))  # 二进制列表→字符串→整数（ASCII码）→字符
            for bits in bits_list
        )

    def encrypt_text(self, plaintext):
        """加密ASCII字符串（按字节分组，对每个字节的8位二进制块分别加密）。
        :param plaintext: 要加密的ASCII字符串
        :return: 加密后的ASCII字符串（可能包含不可打印字符）
        """
        blocks = self.ascii_to_bits(plaintext)  # 将字符串转换为8位二进制块列表
        encrypted_blocks = [self.encrypt_block(block) for block in blocks]  # 逐块加密
        return self.bits_to_ascii(encrypted_blocks)  # 加密块列表转换为字符串

    def decrypt_text(self, ciphertext):
        """解密ASCII字符串（按字节分组，对每个字节的8位二进制块分别解密）。
        :param ciphertext: 要解密的ASCII字符串（加密结果）
        :return: 解密后的原始ASCII字符串
        """
        blocks = self.ascii_to_bits(ciphertext)  # 将加密字符串转换为8位二进制块列表
        decrypted_blocks = [self.decrypt_block(block) for block in blocks]  # 逐块解密
        return self.bits_to_ascii(decrypted_blocks)  # 解密块列表转换为字符串

    @staticmethod
    def binary_str_to_list(binary_str):
        """将二进制字符串（如"11001100"）转换为二进制列表（元素为0/1）。
        :param binary_str: 由'0'和'1'组成的字符串
        :return: 二进制列表（元素为int型0或1）
        :raises ValueError: 当字符串包含非0/1字符时抛出
        """
        if not all(bit in '01' for bit in binary_str):
            raise ValueError("二进制字符串只能包含0和1")
        return [int(bit) for bit in binary_str]

    @staticmethod
    def binary_list_to_str(binary_list):
        """将二进制列表（元素为0/1）转换为二进制字符串（如"11001100"）。
        :param binary_list: 由0和1组成的列表
        :return: 由'0'和'1'组成的字符串
        """
        return ''.join(map(str, binary_list))


class BruteForceWorker(QThread):
    """暴力破解工作线程：多线程遍历所有10位可能的密钥，寻找能匹配给定明密文对的有效密钥。"""
    # 定义信号：用于向主线程传递进度更新、破解结果、线程结束状态
    progress_updated = pyqtSignal(int)  # 进度更新信号（参数为百分比）
    results_found = pyqtSignal(list, float)  # 找到有效密钥时的信号（参数：密钥列表、耗时）
    finished = pyqtSignal()  # 线程完成信号

    def __init__(self, plaintext_bin, ciphertext_bin):
        """初始化暴力破解线程。
        :param plaintext_bin: 8位二进制明文字符串（如"11001100"）
        :param ciphertext_bin: 8位二进制密文字符串（如"00110011"）
        """
        super().__init__()
        self.plaintext_bin = plaintext_bin  # 明文的二进制字符串
        self.ciphertext_bin = ciphertext_bin  # 密文的二进制字符串
        self.running = True  # 线程运行标记（用于控制线程停止）

    def run(self):
        """线程执行逻辑：遍历所有10位密钥，验证是否能加密明文得到目标密文。"""
        start_time = time.time()  # 记录破解开始时间
        total_keys = 2 ** 10  # 10位密钥共有2^10=1024种可能
        sdes = S_DES()  # 临时S_DES对象，用于验证每个密钥
        valid_keys = []  # 存储所有能匹配明密文对的有效密钥

        try:
            # 将明密文字符串转换为二进制列表，并验证长度为8位
            plain_block = S_DES.binary_str_to_list(self.plaintext_bin)
            cipher_block = S_DES.binary_str_to_list(self.ciphertext_bin)
            if len(plain_block) != 8 or len(cipher_block) != 8:
                raise ValueError("明文和密文必须是8位二进制数")
        except Exception as e:
            # 格式错误时弹出提示，并结束线程
            QMessageBox.warning(None, "格式错误", f"明密文格式错误: {str(e)}")
            self.finished.emit()
            return

        # 遍历所有可能的10位密钥（范围：0 ~ 2^10-1）
        for key_int in range(total_keys):
            if not self.running:  # 检查是否需要停止线程
                break
            # 计算当前进度并发射进度更新信号
            progress = int((key_int / total_keys) * 100)
            self.progress_updated.emit(progress)
            # 生成10位二进制密钥（整数→二进制字符串→补前导0→转换为列表）
            key_str = bin(key_int)[2:].zfill(10)
            key = [int(bit) for bit in key_str]
            try:
                sdes.set_key(key)  # 设置当前密钥
                encrypted = sdes.encrypt_block(plain_block)  # 用当前密钥加密明文块
                if encrypted == cipher_block:  # 如果加密结果与目标密文一致，记录该密钥
                    valid_keys.append(key)
            except Exception:
                continue  # 忽略可能的异常（如密钥设置过程中的错误）

        # 确保进度条最终显示100%（处理最后一个密钥后更新进度）
        self.progress_updated.emit(100)
        elapsed_time = time.time()-start_time  # 计算破解耗时
        self.results_found.emit(valid_keys, elapsed_time)  # 发射找到的有效密钥和耗时
        self.finished.emit()  # 发射线程完成信号

    def stop(self):
        """停止暴力破解线程（通过设置运行标记为False来控制）。"""
        self.running = False


class S_DES_GUI(QMainWindow):
    """S-DES加解密工具的图形界面类，包含4个功能标签页：
    1. 基本加解密：处理8位二进制块的加密/解密
    2. 字符串处理：处理ASCII字符串的加密/解密
    3. 暴力破解：遍历所有10位密钥，寻找匹配明密文对的有效密钥
    4. 封闭测试：检测是否存在多密钥加密同一明文得到相同密文的情况（多密钥等价性）
    """
    def __init__(self):
        super().__init__()
        self.sdes = S_DES()  # 主S_DES对象，用于加解密操作
        self.brute_worker = None  # 暴力破解线程对象（运行时动态赋值）
        self.init_ui()  # 调用方法初始化用户界面

    def init_ui(self):
        """初始化主界面，创建标签页布局并添加各功能标签页。"""
        self.setWindowTitle('S-DES加解密工具')  # 设置窗口标题
        self.setGeometry(100, 100, 800, 600)  # 设置窗口位置和大小（x, y, 宽, 高）

        central_widget = QWidget()  # 创建中央部件
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)  # 主垂直布局

        tab_widget = QTabWidget()  # 创建标签页容器
        # 初始化并添加各功能标签页
        self._init_basic_tab(tab_widget)
        self._init_string_tab(tab_widget)
        self._init_brute_tab(tab_widget)
        self._init_closed_tab(tab_widget)

        main_layout.addWidget(tab_widget)  # 将标签页容器加入主布局
        self.statusBar().showMessage("就绪")  # 状态栏显示初始状态

    def _init_basic_tab(self, tab_widget):
        """初始化「基本加解密」标签页：处理8位二进制块的加密/解密。"""
        tab = QWidget()  # 创建标签页部件
        layout = QVBoxLayout(tab)  # 标签页的垂直布局

        # ---------- 密钥设置分组 ----------
        key_group = QGroupBox("密钥设置 (10位二进制数)")  # 密钥设置分组框
        key_layout = QHBoxLayout()  # 密钥设置的水平布局
        self.key_input_basic = QLineEdit()  # 密钥输入框
        self.key_input_basic.setPlaceholderText("输入10位0/1密钥，如：1010101010")
        set_key_btn = QPushButton("设置密钥")  # 密钥设置按钮
        # 点击按钮时，调用公共密钥设置方法（传入当前输入框和状态标签）
        set_key_btn.clicked.connect(
            lambda: self._set_key_common(self.key_input_basic, self.key_status_basic)
        )
        self.key_status_basic = QLabel("未设置密钥")  # 密钥状态提示标签
        self.key_status_basic.setStyleSheet("color: red;")  # 初始为红色提示
        # 将部件加入密钥设置布局
        key_layout.addWidget(self.key_input_basic)
        key_layout.addWidget(set_key_btn)
        key_layout.addWidget(self.key_status_basic)
        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # ---------- 操作选择分组 ----------
        op_group = QGroupBox("操作选择")  # 操作选择分组框
        op_layout = QHBoxLayout()  # 操作选择的水平布局
        self.encrypt_radio_basic = QRadioButton("加密")  # 加密单选按钮
        self.decrypt_radio_basic = QRadioButton("解密")  # 解密单选按钮
        self.encrypt_radio_basic.setChecked(True)  # 默认选中“加密”
        # 将单选按钮加入布局
        op_layout.addWidget(self.encrypt_radio_basic)
        op_layout.addWidget(self.decrypt_radio_basic)
        op_group.setLayout(op_layout)
        layout.addWidget(op_group)

        # ---------- 输入输出分组 ----------
        input_group = QGroupBox("输入 (8位二进制数)")  # 输入分组框
        input_layout = QHBoxLayout()  # 输入的水平布局
        self.input_basic = QLineEdit()  # 8位二进制输入框
        self.input_basic.setPlaceholderText("输入8位0/1数据，如：11001100")
        process_btn = QPushButton("执行")  # 执行按钮
        process_btn.clicked.connect(self._process_basic)  # 点击时处理加解密请求
        # 将部件加入输入布局
        input_layout.addWidget(self.input_basic)
        input_layout.addWidget(process_btn)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        self.output_basic = QTextEdit()  # 输出文本框（只读）
        self.output_basic.setReadOnly(True)
        layout.addWidget(self.output_basic)
        layout.addStretch()  # 拉伸空间，使组件布局更合理

        tab_widget.addTab(tab, "基本加解密")  # 将标签页加入标签页容器

    def _set_key_common(self, input_field, status_label):
        """公共密钥设置逻辑：验证输入的密钥、设置密钥、更新状态提示。
        :param input_field: 密钥输入框组件
        :param status_label: 密钥状态提示标签组件
        """
        key_str = input_field.text().strip()  # 获取输入的密钥字符串（去除首尾空格）
        try:
            # 验证密钥长度必须为10位
            if len(key_str) != 10:
                raise ValueError("密钥长度必须为10位")
            # 将二进制字符串转换为列表
            key = S_DES.binary_str_to_list(key_str)
            self.sdes.set_key(key)  # 设置密钥并生成子密钥
            # 更新状态为成功提示（绿色文字）
            status_label.setText("密钥设置成功")
            status_label.setStyleSheet("color: green;")
            self.statusBar().showMessage(f"已设置密钥: {key_str}")
        except ValueError as e:
            # 错误时更新为错误提示（红色文字）
            status_label.setText(f"错误: {str(e)}")
            status_label.setStyleSheet("color: red;")
            self.statusBar().showMessage(f"密钥设置失败: {str(e)}")

    def _process_basic(self):
        """处理「基本加解密」标签页的二进制块加密/解密请求。"""
        # 检查密钥是否已设置（子密钥数量为2表示已生成）
        if not self.sdes.key or len(self.sdes.subkeys) != 2:
            QMessageBox.warning(self, "密钥未设置", "请先设置10位二进制密钥")
            return

        data_str = self.input_basic.text().strip()  # 获取输入的二进制数据字符串
        is_encrypt = self.encrypt_radio_basic.isChecked()  # 判断是加密还是解密操作
        operation = "加密" if is_encrypt else "解密"  # 操作类型字符串

        try:
            # 验证输入长度必须为8位
            if len(data_str) != 8:
                raise ValueError("输入必须是8位二进制数")
            # 将二进制字符串转换为列表
            data_block = S_DES.binary_str_to_list(data_str)
            # 根据操作类型执行加密或解密
            result_block = (
                self.sdes.encrypt_block(data_block)
                if is_encrypt
                else self.sdes.decrypt_block(data_block)
            )
            # 将结果列表转换为字符串
            result_str = S_DES.binary_list_to_str(result_block)
            # 在输出框显示输入和结果
            self.output_basic.setText(f"输入: {data_str}\n{operation}结果: {result_str}")
            self.statusBar().showMessage(f"成功{operation}: {data_str} -> {result_str}")
        except ValueError as e:
            # 输入格式错误时弹出提示
            QMessageBox.warning(self, "输入错误", f"{str(e)}")
        except Exception as e:
            # 其他处理错误时弹出提示
            QMessageBox.critical(self, "处理错误", f"处理错误: {str(e)}")

    def _init_string_tab(self, tab_widget):
        """初始化「字符串处理」标签页：处理ASCII字符串的加密/解密。"""
        tab = QWidget()  # 创建标签页部件
        layout = QVBoxLayout(tab)  # 标签页的垂直布局

        # ---------- 密钥设置分组 ----------
        key_group = QGroupBox("密钥设置 (10位二进制数)")  # 密钥设置分组框
        key_layout = QHBoxLayout()  # 密钥设置的水平布局
        self.key_input_string = QLineEdit()  # 密钥输入框
        self.key_input_string.setPlaceholderText("输入10位0/1密钥，如：1010101010")
        set_key_btn = QPushButton("设置密钥")  # 密钥设置按钮
        # 点击按钮时，调用公共密钥设置方法（传入当前输入框和状态标签）
        set_key_btn.clicked.connect(
            lambda: self._set_key_common(self.key_input_string, self.key_status_string)
        )
        self.key_status_string = QLabel("未设置密钥")  # 密钥状态提示标签
        self.key_status_string.setStyleSheet("color: red;")  # 初始为红色提示
        # 将部件加入密钥设置布局
        key_layout.addWidget(self.key_input_string)
        key_layout.addWidget(set_key_btn)
        key_layout.addWidget(self.key_status_string)
        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # ---------- 操作选择分组 ----------
        op_group = QGroupBox("操作选择")  # 操作选择分组框
        op_layout = QHBoxLayout()  # 操作选择的水平布局
        self.encrypt_radio_string = QRadioButton("加密")  # 加密单选按钮
        self.decrypt_radio_string = QRadioButton("解密")  # 解密单选按钮
        self.encrypt_radio_string.setChecked(True)  # 默认选中“加密”
        # 将单选按钮加入布局
        op_layout.addWidget(self.encrypt_radio_string)
        op_layout.addWidget(self.decrypt_radio_string)
        op_group.setLayout(op_layout)
        layout.addWidget(op_group)

        # ---------- 输入输出分栏（用QSplitter实现上下分割） ----------
        io_splitter = QSplitter(Qt.Vertical)  # 垂直分割的输入输出分栏

        # 输入分组
        input_group = QGroupBox("输入 (ASCII字符串)")  # 输入分组框
        input_layout = QVBoxLayout()  # 输入的垂直布局
        self.input_string = QTextEdit()  # 多行文本输入框
        self.input_string.setPlaceholderText("输入要加密/解密的ASCII字符串")
        input_buttons = QHBoxLayout()  # 输入按钮的水平布局
        process_btn = QPushButton("执行")  # 执行按钮
        process_btn.clicked.connect(self._process_string)  # 点击时处理字符串加解密
        clear_btn = QPushButton("清空")  # 清空按钮
        clear_btn.clicked.connect(self.input_string.clear)  # 点击时清空输入框
        # 将按钮加入输入按钮布局
        input_buttons.addWidget(process_btn)
        input_buttons.addWidget(clear_btn)
        # 将输入框和按钮布局加入输入布局
        input_layout.addWidget(self.input_string)
        input_layout.addLayout(input_buttons)
        input_group.setLayout(input_layout)

        # 输出分组
        output_group = QGroupBox("输出结果")  # 输出分组框
        output_layout = QVBoxLayout()  # 输出的垂直布局
        self.output_string = QTextEdit()  # 输出文本框（只读）
        self.output_string.setReadOnly(True)
        output_buttons = QHBoxLayout()  # 输出按钮的水平布局
        copy_btn = QPushButton("复制结果")  # 复制按钮
        copy_btn.clicked.connect(self._copy_string_result)  # 点击时复制结果到剪贴板
        # 将按钮加入输出按钮布局
        output_buttons.addWidget(copy_btn)
        # 将输出框和按钮布局加入输出布局
        output_layout.addWidget(self.output_string)
        output_layout.addLayout(output_buttons)
        output_group.setLayout(output_layout)

        # 将输入和输出分组加入分割栏
        io_splitter.addWidget(input_group)
        io_splitter.addWidget(output_group)
        layout.addWidget(io_splitter)

        tab_widget.addTab(tab, "字符串处理")  # 将标签页加入标签页容器

    def _process_string(self):
        """处理「字符串处理」标签页的ASCII字符串加密/解密请求。"""
        # 检查密钥是否已设置
        if not self.sdes.key or len(self.sdes.subkeys) != 2:
            QMessageBox.warning(self, "密钥未设置", "请先设置10位二进制密钥")
            return

        text = self.input_string.toPlainText().strip()  # 获取输入的ASCII字符串
        if not text:  # 输入为空时提示
            QMessageBox.warning(self, "输入为空", "请输入要处理的字符串")
            return

        is_encrypt = self.encrypt_radio_string.isChecked()  # 判断是加密还是解密操作
        operation = "加密" if is_encrypt else "解密"  # 操作类型字符串

        try:
            # 根据操作类型执行字符串加密或解密
            result_text = (
                self.sdes.encrypt_text(text)
                if is_encrypt
                else self.sdes.decrypt_text(text)
            )
            self.output_string.setText(result_text)  # 在输出框显示结果
            self.statusBar().showMessage(f"成功{operation}字符串，长度: {len(text)}")
        except Exception:
            # 处理错误时提示“输入必须是ASCII字符串”
            QMessageBox.critical(self, "处理错误", "输入必须是ASCII字符串")

    def _copy_string_result(self):
        """复制「字符串处理」标签页的输出结果到系统剪贴板。"""
        result = self.output_string.toPlainText()  # 获取输出结果文本
        if result:  # 如果结果非空
            QApplication.clipboard().setText(result)  # 复制到剪贴板
            self.statusBar().showMessage("结果已复制到剪贴板")

    def _init_brute_tab(self, tab_widget):
        """初始化「暴力破解」标签页：遍历所有10位密钥，寻找匹配明密文对的有效密钥。"""
        tab = QWidget()  # 创建标签页部件
        layout = QVBoxLayout(tab)  # 标签页的垂直布局

        # ---------- 明密文对输入分组 ----------
        pair_group = QGroupBox("明密文对 (8位二进制数)")  # 明密文对分组框
        pair_layout = QVBoxLayout()  # 明密文对的垂直布局

        # 明文输入行
        plain_layout = QHBoxLayout()
        plain_layout.addWidget(QLabel("明文:"))
        self.plaintext_brute = QLineEdit()  # 明文输入框
        self.plaintext_brute.setPlaceholderText("8位二进制数，如：11001100")
        plain_layout.addWidget(self.plaintext_brute)

        # 密文输入行
        cipher_layout = QHBoxLayout()
        cipher_layout.addWidget(QLabel("密文:"))
        self.ciphertext_brute = QLineEdit()  # 密文输入框
        self.ciphertext_brute.setPlaceholderText("8位二进制数，如：00110011")
        cipher_layout.addWidget(self.ciphertext_brute)

        # 将明文和密文输入行加入布局
        pair_layout.addLayout(plain_layout)
        pair_layout.addLayout(cipher_layout)
        pair_group.setLayout(pair_layout)
        layout.addWidget(pair_group)

        # ---------- 破解控制分组 ----------
        control_group = QGroupBox("破解控制")  # 破解控制分组框
        control_layout = QHBoxLayout()  # 破解控制的水平布局
        self.start_brute = QPushButton("开始破解")  # 开始破解按钮
        self.start_brute.clicked.connect(self._start_brute_force)  # 点击时启动暴力破解
        self.stop_brute = QPushButton("停止破解")  # 停止破解按钮
        self.stop_brute.clicked.connect(self._stop_brute_force)  # 点击时停止暴力破解
        self.stop_brute.setEnabled(False)  # 初始时“停止”按钮不可用
        # 将按钮加入布局
        control_layout.addWidget(self.start_brute)
        control_layout.addWidget(self.stop_brute)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # ---------- 进度条 ----------
        self.brute_progress = QProgressBar()  # 破解进度条
        self.brute_progress.setRange(0, 100)  # 设置进度范围为0-100
        layout.addWidget(self.brute_progress)

        # ---------- 破解结果显示 ----------
        self.brute_result = QTextEdit()  # 破解结果文本框（只读）
        self.brute_result.setReadOnly(True)
        layout.addWidget(self.brute_result)
        layout.addStretch()  # 拉伸空间

        tab_widget.addTab(tab, "暴力破解")  # 将标签页加入标签页容器

    def _start_brute_force(self):
        """启动暴力破解线程，验证明密文格式并执行破解。"""
        plaintext = self.plaintext_brute.text().strip()  # 获取明文输入
        ciphertext = self.ciphertext_brute.text().strip()  # 获取密文输入

        try:
            # 验证明密文格式：必须是8位二进制字符串
            if len(plaintext) != 8 or len(ciphertext) != 8:
                raise ValueError("明文和密文必须是8位")
            # 验证为合法二进制字符串（调用方法转换，若非法会抛出异常）
            S_DES.binary_str_to_list(plaintext)
            S_DES.binary_str_to_list(ciphertext)
        except ValueError as e:
            # 格式错误时弹出提示
            QMessageBox.warning(self, "输入错误", f"明密文格式错误: {str(e)}")
            return

        # 初始化并启动暴力破解线程
        self.brute_worker = BruteForceWorker(plaintext, ciphertext)
        # 连接线程的信号到界面更新方法
        self.brute_worker.progress_updated.connect(self._update_brute_progress)
        self.brute_worker.results_found.connect(self._handle_brute_results)
        self.brute_worker.finished.connect(self._brute_finished)

        # 初始化结果显示
        self.brute_result.clear()
        self.brute_result.append("开始暴力破解...")
        self.brute_result.append(f"明文: {plaintext}")
        self.brute_result.append(f"密文: {ciphertext}")
        self.brute_result.append("正在尝试所有10位二进制密钥...")

        # 更新界面状态：禁用“开始”、启用“停止”，进度条置0
        self.start_brute.setEnabled(False)
        self.stop_brute.setEnabled(True)
        self.brute_progress.setValue(0)
        self.statusBar().showMessage("正在进行暴力破解...")
        self.brute_worker.start()  # 启动线程

    def _stop_brute_force(self):
        """停止暴力破解线程（调用线程的stop方法）。"""
        if self.brute_worker and self.brute_worker.isRunning():  # 线程存在且正在运行
            self.brute_worker.stop()  # 设置线程的运行标记为False以停止
            self.brute_result.append("正在停止破解...")
            self.statusBar().showMessage("正在停止破解...")

    def _update_brute_progress(self, value):
        """更新暴力破解进度条的显示值。
        :param value: 进度百分比（0-100）
        """
        self.brute_progress.setValue(value)

    def _handle_brute_results(self, keys, elapsed_time):
        """处理暴力破解找到的有效密钥结果，显示密钥列表和耗时。
        :param keys: 有效密钥列表（每个密钥为10位二进制列表）
        :param elapsed_time: 破解耗时（秒）
        """
        if not keys:  # 没有找到有效密钥
            self.brute_result.append("\n未找到有效密钥")
            self.statusBar().showMessage(f"未找到有效密钥，耗时 {elapsed_time:.4f} 秒")
            return

        # 显示找到的有效密钥信息
        self.brute_result.append("\n找到有效密钥!")
        self.brute_result.append(f"共找到 {len(keys)} 个有效密钥")
        self.brute_result.append(f"破解耗时: {elapsed_time:.4f} 秒")
        for i, key in enumerate(keys):
            key_str = S_DES.binary_list_to_str(key)  # 将密钥列表转换为字符串
            self.brute_result.append(f"密钥 {i+1} (10位二进制): {key_str}")
        self.statusBar().showMessage(f"找到 {len(keys)} 个有效密钥，耗时 {elapsed_time:.4f} 秒")

    def _brute_finished(self):
        """暴力破解线程结束后，恢复界面按钮状态并更新状态栏。"""
        # 恢复按钮状态：启用“开始”、禁用“停止”
        self.start_brute.setEnabled(True)
        self.stop_brute.setEnabled(False)
        self.statusBar().showMessage("暴力破解已完成")
        # 如果进度为100%但未找到有效密钥，补充提示
        if self.brute_progress.value() == 100 and "找到有效密钥" not in self.brute_result.toPlainText():
            self.brute_result.append("\n破解完成，未找到有效密钥")

    def _init_closed_tab(self, tab_widget):
        """初始化「封闭测试」标签页：检测是否存在多密钥加密同一明文得到相同密文的情况（多密钥等价性）。"""
        tab = QWidget()  # 创建标签页部件
        layout = QVBoxLayout(tab)  # 标签页的垂直布局

        # ---------- 明文输入分组 ----------
        plain_group = QGroupBox("明文输入 (8位二进制数)")  # 明文输入分组框
        plain_layout = QHBoxLayout()  # 明文输入的水平布局
        self.plaintext_closed = QLineEdit()  # 明文输入框
        self.plaintext_closed.setPlaceholderText("8位二进制数，如：11001100")
        plain_layout.addWidget(self.plaintext_closed)
        plain_group.setLayout(plain_layout)
        layout.addWidget(plain_group)

        # ---------- 测试控制分组 ----------
        control_group = QGroupBox("测试控制")  # 测试控制分组框
        control_layout = QHBoxLayout()  # 测试控制的水平布局
        self.start_closed = QPushButton("开始测试")  # 开始测试按钮
        self.start_closed.clicked.connect(self._start_closed_test)  # 点击时启动封闭测试
        control_layout.addWidget(self.start_closed)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # ---------- 进度条 ----------
        self.closed_progress = QProgressBar()  # 测试进度条
        self.closed_progress.setRange(0, 100)  # 设置进度范围为0-100
        layout.addWidget(self.closed_progress)

        # ---------- 测试结果显示 ----------
        self.closed_result = QTextEdit()  # 测试结果文本框（只读）
        self.closed_result.setReadOnly(True)
        layout.addWidget(self.closed_result)
        layout.addStretch()  # 拉伸空间

        tab_widget.addTab(tab, "封闭测试")  # 将标签页加入标签页容器

    def _start_closed_test(self):
        """执行封闭测试：遍历所有10位密钥，检查是否存在多密钥等价性（同一明文加密得到相同密文）。"""
        plaintext = self.plaintext_closed.text().strip()  # 获取明文输入

        try:
            # 验证明文格式：必须是8位二进制字符串
            if len(plaintext) != 8:
                raise ValueError("明文必须是8位二进制数")
            plain_block = S_DES.binary_str_to_list(plaintext)  # 转换为二进制列表
        except ValueError as e:
            # 格式错误时弹出提示
            QMessageBox.warning(self, "输入错误", f"明文格式错误: {str(e)}")
            return

        # 初始化结果显示
        self.closed_result.clear()
        self.closed_result.append(f"开始封闭测试...")
        self.closed_result.append(f"明文: {plaintext}")
        self.closed_result.append("正在检查多密钥等价性...")

        # 更新界面状态：禁用“开始”按钮，进度条置0
        self.start_closed.setEnabled(False)
        self.closed_progress.setValue(0)
        self.statusBar().showMessage("正在进行封闭测试...")

        total_keys = 2 ** 10  # 10位密钥共有1024种可能
        sdes = S_DES()  # 临时S_DES对象，用于加密
        cipher_key_map = {}  # 字典：密文字符串 → 生成该密文的密钥列表

        # 遍历所有可能的10位密钥
        for key_int in range(total_keys):
            # 更新进度条
            progress = int((key_int / total_keys) * 100)
            self.closed_progress.setValue(progress)
            # 生成10位二进制密钥
            key_str = bin(key_int)[2:].zfill(10)
            key = [int(bit) for bit in key_str]
            try:
                sdes.set_key(key)  # 设置当前密钥
                cipher_block = sdes.encrypt_block(plain_block)  # 加密明文块
                cipher_str = S_DES.binary_list_to_str(cipher_block)  # 密文转换为字符串
                # 记录密文与密钥的对应关系（若密文已存在，追加密钥；否则新建条目）
                if cipher_str in cipher_key_map:
                    cipher_key_map[cipher_str].append(key)
                else:
                    cipher_key_map[cipher_str] = [key]
            except Exception:
                continue  # 忽略可能的异常

        # 确保进度条最终显示100%
        self.closed_progress.setValue(100)

        # 筛选多密钥等价的密文（由多个密钥生成的密文）
        multi_key_ciphers = {
            cipher: keys
            for cipher, keys in cipher_key_map.items()
            if len(keys) > 1  # 只保留由多个密钥生成的密文
        }

        if multi_key_ciphers:  # 存在多密钥等价的密文
            self.closed_result.append("\n找到多密钥等价的密文：")
            for cipher, keys in multi_key_ciphers.items():
                self.closed_result.append(f"密文 {cipher} 可由 {len(keys)} 个不同密钥生成：")
                for i, key in enumerate(keys):
                    key_str = S_DES.binary_list_to_str(key)
                    self.closed_result.append(f"  密钥 {i+1}: {key_str}")
        else:  # 无多密钥等价的密文
            self.closed_result.append("\n未找到多密钥等价的密文（所有密文均由唯一密钥生成）")

        # 恢复“开始”按钮状态，更新状态栏
        self.start_closed.setEnabled(True)
        self.statusBar().showMessage("封闭测试已完成")


if __name__ == '__main__':
    # 程序入口：创建Qt应用实例，显示窗口，进入事件循环
    app = QApplication(sys.argv)
    window = S_DES_GUI()
    window.show()
    sys.exit(app.exec_())
