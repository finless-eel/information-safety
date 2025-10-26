import tkinter as tk
from tkinter import ttk, messagebox
import random

# S-AES核心组件定义
S_BOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

INV_S_BOX = [
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
]

# 列混淆矩阵
MIX_COLUMN_MATRIX = [
    [1, 4],
    [4, 1]
]

# 逆列混淆矩阵
INV_MIX_COLUMN_MATRIX = [
    [9, 2],
    [2, 9]
]

# 轮常量
ROUND_CONSTANTS = [0x80, 0x30]


def sub_nibbles(state, inverse=False):
    """半字节替换操作

    参数:
        state: 4元素列表，代表当前状态
        inverse: 是否使用逆S盒，默认为False（正向替换）

    返回:
        替换后的状态列表
    """
    s_box = S_BOX if not inverse else INV_S_BOX
    return [s_box[state[0]], s_box[state[1]], s_box[state[2]], s_box[state[3]]]


def shift_rows(state):
    """行移位操作

    参数:
        state: 4元素列表，代表当前状态

    返回:
        行移位后的状态列表
    """
    return [state[0], state[2], state[1], state[3]]


def mix_columns(state, inverse=False):
    """列混淆操作

    参数:
        state: 4元素列表，代表当前状态
        inverse: 是否使用逆列混淆矩阵，默认为False（正向混淆）

    返回:
        列混淆后的状态列表
    """
    matrix = MIX_COLUMN_MATRIX if not inverse else INV_MIX_COLUMN_MATRIX
    state0, state1, state2, state3 = state
    return [
        galois_mult(state0, matrix[0][0]) ^ galois_mult(state1, matrix[0][1]),
        galois_mult(state0, matrix[1][0]) ^ galois_mult(state1, matrix[1][1]),
        galois_mult(state2, matrix[0][0]) ^ galois_mult(state3, matrix[0][1]),
        galois_mult(state2, matrix[1][0]) ^ galois_mult(state3, matrix[1][1])
    ]


def galois_mult(a, b):
    """伽罗瓦域乘法 (GF(2^4))

    参数:
        a: 乘数（4位半字节）
        b: 乘数（4位半字节）

    返回:
        乘积结果（4位半字节）
    """
    product = 0
    for _ in range(4):
        if b & 1:
            product ^= a
        high_bit = a & 0x8
        a <<= 1
        if high_bit:
            a ^= 0x3  # 多项式x^4 + x + 1的十六进制表示为0x13，取低4位为0x3
        b >>= 1
    return product & 0xF


def add_round_key(state, round_key):
    """轮密钥加操作

    参数:
        state: 4元素列表，代表当前状态
        round_key: 4元素列表，代表当前轮的密钥

    返回:
        轮密钥加后的状态列表
    """
    return [state_val ^ key_val for state_val, key_val in zip(state, round_key)]


def key_expansion(key):
    """密钥扩展函数，生成轮密钥

    参数:
        key: 16位整数，原始密钥

    返回:
        轮密钥列表，包含3个16位轮密钥
    """
    round_words = [
        (key >> 12) & 0xF,  # 提取高4位
        (key >> 8) & 0xF,  # 提取次高4位
        (key >> 4) & 0xF,  # 提取次低4位
        key & 0xF  # 提取低4位
    ]

    # 生成第5-8个轮密钥字
    round_words.append(round_words[0] ^ S_BOX[round_words[3]] ^ (ROUND_CONSTANTS[0] >> 4))
    round_words.append(round_words[1] ^ round_words[4])
    round_words.append(round_words[2] ^ round_words[5])
    round_words.append(round_words[3] ^ round_words[6])

    # 生成第9-12个轮密钥字
    round_words.append(round_words[4] ^ S_BOX[round_words[7]] ^ (ROUND_CONSTANTS[1] >> 4))
    round_words.append(round_words[5] ^ round_words[8])
    round_words.append(round_words[6] ^ round_words[9])
    round_words.append(round_words[7] ^ round_words[10])

    # 组合轮密钥（每个轮密钥由4个16位字组成）
    return [
        (round_words[0] << 12) | (round_words[1] << 8) | (round_words[2] << 4) | round_words[3],
        (round_words[4] << 12) | (round_words[5] << 8) | (round_words[6] << 4) | round_words[7],
        (round_words[8] << 12) | (round_words[9] << 8) | (round_words[10] << 4) | round_words[11]
    ]


def encrypt_block(plaintext_block, key):
    """单块加密函数（16位明文块）

    参数:
        plaintext_block: 16位整数，明文块
        key: 16位整数，加密密钥

    返回:
        16位整数，加密后的密文块
    """
    round_keys = key_expansion(key)

    # 初始轮密钥加
    state = [
        (plaintext_block >> 12) & 0xF,
        (plaintext_block >> 8) & 0xF,
        (plaintext_block >> 4) & 0xF,
        plaintext_block & 0xF
    ]
    initial_round_key = [
        (round_keys[0] >> 12) & 0xF,
        (round_keys[0] >> 8) & 0xF,
        (round_keys[0] >> 4) & 0xF,
        round_keys[0] & 0xF
    ]
    state = add_round_key(state, initial_round_key)

    # 第一轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    first_round_key = [
        (round_keys[1] >> 12) & 0xF,
        (round_keys[1] >> 8) & 0xF,
        (round_keys[1] >> 4) & 0xF,
        round_keys[1] & 0xF
    ]
    state = add_round_key(state, first_round_key)

    # 第二轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    second_round_key = [
        (round_keys[2] >> 12) & 0xF,
        (round_keys[2] >> 8) & 0xF,
        (round_keys[2] >> 4) & 0xF,
        round_keys[2] & 0xF
    ]
    state = add_round_key(state, second_round_key)

    # 组合状态为16位密文块
    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]


def decrypt_block(ciphertext_block, key):
    """单块解密函数（16位密文块）

    参数:
        ciphertext_block: 16位整数，密文块
        key: 16位整数，解密密钥

    返回:
        16位整数，解密后的明文块
    """
    round_keys = key_expansion(key)

    # 初始轮密钥加（使用最后一轮密钥）
    state = [
        (ciphertext_block >> 12) & 0xF,
        (ciphertext_block >> 8) & 0xF,
        (ciphertext_block >> 4) & 0xF,
        ciphertext_block & 0xF
    ]
    initial_round_key = [
        (round_keys[2] >> 12) & 0xF,
        (round_keys[2] >> 8) & 0xF,
        (round_keys[2] >> 4) & 0xF,
        round_keys[2] & 0xF
    ]
    state = add_round_key(state, initial_round_key)

    # 第一轮解密
    state = shift_rows(state)
    state = sub_nibbles(state, inverse=True)
    first_round_key = [
        (round_keys[1] >> 12) & 0xF,
        (round_keys[1] >> 8) & 0xF,
        (round_keys[1] >> 4) & 0xF,
        round_keys[1] & 0xF
    ]
    state = add_round_key(state, first_round_key)
    state = mix_columns(state, inverse=True)

    # 第二轮解密
    state = shift_rows(state)
    state = sub_nibbles(state, inverse=True)
    second_round_key = [
        (round_keys[0] >> 12) & 0xF,
        (round_keys[0] >> 8) & 0xF,
        (round_keys[0] >> 4) & 0xF,
        round_keys[0] & 0xF
    ]
    state = add_round_key(state, second_round_key)

    # 组合状态为16位明文块
    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]


# 扩展功能实现
def str_to_blocks(input_str):
    """将ASCII字符串转换为16位块列表

    参数:
        input_str: 待转换的ASCII字符串

    返回:
        16位整数列表，每个元素代表一个块
    """
    blocks = []
    for i in range(0, len(input_str), 2):
        # 取两个字符组成一个16位块，不足补0
        char1 = ord(input_str[i]) if i < len(input_str) else 0
        char2 = ord(input_str[i + 1]) if (i + 1) < len(input_str) else 0
        blocks.append((char1 << 8) | char2)
    return blocks


def blocks_to_str(block_list):
    """将16位块列表转换为ASCII字符串

    参数:
        block_list: 16位整数列表

    返回:
        转换后的ASCII字符串
    """
    result_str = []
    for block in block_list:
        char1 = (block >> 8) & 0xFF
        char2 = block & 0xFF
        # 忽略补位的0字符
        result_str.append(chr(char1) if char1 != 0 else '')
        result_str.append(chr(char2) if char2 != 0 else '')
    return ''.join(result_str)


# 多重加密实现
def double_encrypt(plaintext_block, key_32bit):
    """双重加密（使用32位密钥）

    参数:
        plaintext_block: 16位整数，明文块
        key_32bit: 32位整数，双重加密密钥（前16位为k1，后16位为k2）

    返回:
        16位整数，加密后的密文块
    """
    key1 = (key_32bit >> 16) & 0xFFFF
    key2 = key_32bit & 0xFFFF
    return encrypt_block(encrypt_block(plaintext_block, key1), key2)


def double_decrypt(ciphertext_block, key_32bit):
    """双重解密（使用32位密钥）

    参数:
        ciphertext_block: 16位整数，密文块
        key_32bit: 32位整数，双重解密密钥（前16位为k1，后16位为k2）

    返回:
        16位整数，解密后的明文块
    """
    key1 = (key_32bit >> 16) & 0xFFFF
    key2 = key_32bit & 0xFFFF
    return decrypt_block(decrypt_block(ciphertext_block, key2), key1)


def meet_in_the_middle(plaintext_block, ciphertext_block):
    """中间相遇攻击，破解双重加密的32位密钥

    参数:
        plaintext_block: 16位整数，明文块
        ciphertext_block: 16位整数，对应的密文块

    返回:
        32位整数，破解得到的密钥（None表示未找到）
    """
    forward_map = {}
    # 构建正向映射表：k1 -> 中间结果
    for key1 in range(0x10000):
        forward_map[encrypt_block(plaintext_block, key1)] = key1

    # 反向搜索匹配的中间结果
    for key2 in range(0x10000):
        mid_result = decrypt_block(ciphertext_block, key2)
        if mid_result in forward_map:
            return (forward_map[mid_result] << 16) | key2
    return None


def triple_encrypt(plaintext_block, key_48bit):
    """三重加密（使用48位密钥）

    参数:
        plaintext_block: 16位整数，明文块
        key_48bit: 48位整数，三重加密密钥（k1, k2, k3各16位）

    返回:
        16位整数，加密后的密文块
    """
    key1 = (key_48bit >> 32) & 0xFFFF
    key2 = (key_48bit >> 16) & 0xFFFF
    key3 = key_48bit & 0xFFFF
    return encrypt_block(decrypt_block(encrypt_block(plaintext_block, key1), key2), key3)


def triple_decrypt(ciphertext_block, key_48bit):
    """三重解密（使用48位密钥）

    参数:
        ciphertext_block: 16位整数，密文块
        key_48bit: 48位整数，三重解密密钥（k1, k2, k3各16位）

    返回:
        16位整数，解密后的明文块
    """
    key1 = (key_48bit >> 32) & 0xFFFF
    key2 = (key_48bit >> 16) & 0xFFFF
    key3 = key_48bit & 0xFFFF
    return decrypt_block(encrypt_block(decrypt_block(ciphertext_block, key3), key2), key1)


# CBC工作模式
def cbc_encrypt(plaintext_str, key_16bit, iv_16bit):
    """CBC模式加密

    参数:
        plaintext_str: 待加密的字符串
        key_16bit: 16位整数，加密密钥
        iv_16bit: 16位整数，初始向量

    返回:
        密文块列表和使用的IV
    """
    plaintext_blocks = str_to_blocks(plaintext_str)
    ciphertext_blocks = []
    prev_block = iv_16bit

    for block in plaintext_blocks:
        xor_block = block ^ prev_block
        enc_block = encrypt_block(xor_block, key_16bit)
        ciphertext_blocks.append(enc_block)
        prev_block = enc_block

    return ciphertext_blocks, iv_16bit


def cbc_decrypt(ciphertext_blocks, key_16bit, iv_16bit):
    """CBC模式解密

    参数:
        ciphertext_blocks: 密文块列表
        key_16bit: 16位整数，解密密钥
        iv_16bit: 16位整数，初始向量

    返回:
        解密后的字符串
    """
    plaintext_blocks = []
    prev_block = iv_16bit

    for block in ciphertext_blocks:
        dec_block = decrypt_block(block, key_16bit)
        plain_block = dec_block ^ prev_block
        plaintext_blocks.append(plain_block)
        prev_block = block

    return blocks_to_str(plaintext_blocks)


# GUI实现
class S_AES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES加密解密工具")
        self.root.geometry("800x600")

        # 创建标签页
        self.tab_control = ttk.Notebook(root)

        self.tab_basic = ttk.Frame(self.tab_control)
        self.tab_str = ttk.Frame(self.tab_control)
        self.tab_double = ttk.Frame(self.tab_control)
        self.tab_triple = ttk.Frame(self.tab_control)
        self.tab_cbc = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_basic, text="基本加解密")
        self.tab_control.add(self.tab_str, text="字符串处理")
        self.tab_control.add(self.tab_double, text="双重加密与攻击")
        self.tab_control.add(self.tab_triple, text="三重加密")
        self.tab_control.add(self.tab_cbc, text="CBC工作模式")

        self.tab_control.pack(expand=1, fill="both")

        self.init_basic_tab()
        self.init_str_tab()
        self.init_double_tab()
        self.init_triple_tab()
        self.init_cbc_tab()

    def init_basic_tab(self):
        # 明文输入
        ttk.Label(self.tab_basic, text="16位明文 (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.plaintext_entry = ttk.Entry(self.tab_basic, width=20)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)
        self.plaintext_entry.insert(0, "0000")

        # 密钥输入
        ttk.Label(self.tab_basic, text="16位密钥 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry = ttk.Entry(self.tab_basic, width=20)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)
        self.key_entry.insert(0, "0000")

        # 加密按钮
        encrypt_btn = ttk.Button(self.tab_basic, text="加密", command=self.basic_encrypt)
        encrypt_btn.grid(row=2, column=0, padx=5, pady=5)

        # 解密按钮
        decrypt_btn = ttk.Button(self.tab_basic, text="解密", command=self.basic_decrypt)
        decrypt_btn.grid(row=2, column=1, padx=5, pady=5)

        # 结果显示
        ttk.Label(self.tab_basic, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.result_var = tk.StringVar()
        ttk.Label(self.tab_basic, textvariable=self.result_var).grid(row=3, column=1, padx=5, pady=5)

    def basic_encrypt(self):
        try:
            plaintext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFF):
                raise ValueError
            ciphertext = encrypt_block(plaintext, key)
            self.result_var.set(f"{ciphertext:04X}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的16位十六进制数")

    def basic_decrypt(self):
        try:
            ciphertext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFF):
                raise ValueError
            plaintext = decrypt_block(ciphertext, key)
            self.result_var.set(f"{plaintext:04X}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的16位十六进制数")

    def init_str_tab(self):
        # 字符串输入
        ttk.Label(self.tab_str, text="输入字符串:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.NW)
        self.str_input = tk.Text(self.tab_str, width=40, height=5)
        self.str_input.grid(row=0, column=1, padx=5, pady=5)
        self.str_input.insert(tk.END, "Hello, S-AES!")

        # 密钥输入
        ttk.Label(self.tab_str, text="16位密钥 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.str_key_entry = ttk.Entry(self.tab_str, width=20)
        self.str_key_entry.grid(row=1, column=1, padx=5, pady=5)
        self.str_key_entry.insert(0, "A1B2")

        # 加密解密按钮
        ttk.Button(self.tab_str, text="加密", command=self.str_encrypt).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(self.tab_str, text="解密", command=self.str_decrypt).grid(row=2, column=1, padx=5, pady=5)

        # 结果显示
        ttk.Label(self.tab_str, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.NW)
        self.str_result = tk.Text(self.tab_str, width=40, height=5)
        self.str_result.grid(row=3, column=1, padx=5, pady=5)

    def str_encrypt(self):
        try:
            input_str = self.str_input.get("1.0", tk.END).strip()
            key = int(self.str_key_entry.get(), 16)
            if not (0 <= key <= 0xFFFF):
                raise ValueError

            plaintext_blocks = str_to_blocks(input_str)
            ciphertext_blocks = [encrypt_block(block, key) for block in plaintext_blocks]
            self.str_result.delete("1.0", tk.END)
            self.str_result.insert(tk.END, blocks_to_str(ciphertext_blocks))
        except ValueError:
            messagebox.showerror("错误", "请输入有效的16位十六进制密钥")

    def str_decrypt(self):
        try:
            input_str = self.str_input.get("1.0", tk.END).strip()
            key = int(self.str_key_entry.get(), 16)
            if not (0 <= key <= 0xFFFF):
                raise ValueError

            ciphertext_blocks = str_to_blocks(input_str)
            plaintext_blocks = [decrypt_block(block, key) for block in ciphertext_blocks]
            self.str_result.delete("1.0", tk.END)
            self.str_result.insert(tk.END, blocks_to_str(plaintext_blocks))
        except ValueError:
            messagebox.showerror("错误", "请输入有效的16位十六进制密钥")

    def init_double_tab(self):
        # 明文密文对输入
        ttk.Label(self.tab_double, text="明文 (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_plaintext = ttk.Entry(self.tab_double, width=20)
        self.double_plaintext.grid(row=0, column=1, padx=5, pady=5)
        self.double_plaintext.insert(0, "0000")

        ttk.Label(self.tab_double, text="密文 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_ciphertext = ttk.Entry(self.tab_double, width=20)
        self.double_ciphertext.grid(row=1, column=1, padx=5, pady=5)
        self.double_ciphertext.insert(0, "0000")

        # 32位密钥输入
        ttk.Label(self.tab_double, text="32位密钥 (十六进制):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_key = ttk.Entry(self.tab_double, width=20)
        self.double_key.grid(row=2, column=1, padx=5, pady=5)
        self.double_key.insert(0, "00000000")

        # 按钮
        ttk.Button(self.tab_double, text="双重加密", command=self.perform_double_encrypt).grid(
            row=3, column=0, padx=5, pady=5
        )
        ttk.Button(self.tab_double, text="双重解密", command=self.perform_double_decrypt).grid(
            row=3, column=1, padx=5, pady=5
        )
        ttk.Button(self.tab_double, text="中间相遇攻击", command=self.perform_mitm).grid(
            row=4, column=0, columnspan=2, padx=5, pady=5
        )

        # 结果
        ttk.Label(self.tab_double, text="结果:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.double_result = ttk.Entry(self.tab_double, width=20)
        self.double_result.grid(row=5, column=1, padx=5, pady=5)

    def perform_double_encrypt(self):
        try:
            plaintext = int(self.double_plaintext.get(), 16)
            key = int(self.double_key.get(), 16)
            if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFFFFFF):
                raise ValueError
            ciphertext = double_encrypt(plaintext, key)
            self.double_result.delete(0, tk.END)
            self.double_result.insert(0, f"{ciphertext:04X}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def perform_double_decrypt(self):
        try:
            ciphertext = int(self.double_ciphertext.get(), 16)
            key = int(self.double_key.get(), 16)
            if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFFFFFF):
                raise ValueError
            plaintext = double_decrypt(ciphertext, key)
            self.double_result.delete(0, tk.END)
            self.double_result.insert(0, f"{plaintext:04X}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def perform_mitm(self):
        try:
            plaintext = int(self.double_plaintext.get(), 16)
            ciphertext = int(self.double_ciphertext.get(), 16)
            if not (0 <= plaintext <= 0xFFFF and 0 <= ciphertext <= 0xFFFF):
                raise ValueError

            self.double_result.delete(0, tk.END)
            self.double_result.insert(0, "正在攻击中...")
            self.root.update()

            key = meet_in_the_middle(plaintext, ciphertext)
            if key is not None:
                self.double_result.delete(0, tk.END)
                self.double_result.insert(0, f"{key:08X}")
            else:
                self.double_result.delete(0, tk.END)
                self.double_result.insert(0, "未找到密钥")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def init_triple_tab(self):
        # 明文输入
        ttk.Label(self.tab_triple, text="明文 (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_plaintext = ttk.Entry(self.tab_triple, width=20)
        self.triple_plaintext.grid(row=0, column=1, padx=5, pady=5)
        self.triple_plaintext.insert(0, "0000")

        # 密文输入
        ttk.Label(self.tab_triple, text="密文 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_ciphertext = ttk.Entry(self.tab_triple, width=20)
        self.triple_ciphertext.grid(row=1, column=1, padx=5, pady=5)
        self.triple_ciphertext.insert(0, "0000")

        # 48位密钥输入
        ttk.Label(self.tab_triple, text="48位密钥 (十六进制):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_key = ttk.Entry(self.tab_triple, width=20)
        self.triple_key.grid(row=2, column=1, padx=5, pady=5)
        self.triple_key.insert(0, "000000000000")

        # 按钮
        ttk.Button(self.tab_triple, text="三重加密", command=self.perform_triple_encrypt).grid(
            row=3, column=0, padx=5, pady=5
        )
        ttk.Button(self.tab_triple, text="三重解密", command=self.perform_triple_decrypt).grid(
            row=3, column=1, padx=5, pady=5
        )

        # 结果
        ttk.Label(self.tab_triple, text="结果:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.triple_result = ttk.Entry(self.tab_triple, width=20)
        self.triple_result.grid(row=4, column=1, padx=5, pady=5)

    def perform_triple_encrypt(self):
        try:
            plaintext = int(self.triple_plaintext.get(), 16)
            key = int(self.triple_key.get(), 16)
            if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFFFFFFFFFF):
                raise ValueError
            ciphertext = triple_encrypt(plaintext, key)
            self.triple_result.delete(0, tk.END)
            self.triple_result.insert(0, f"{ciphertext:04X}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def perform_triple_decrypt(self):
        try:
            ciphertext = int(self.triple_ciphertext.get(), 16)
            key = int(self.triple_key.get(), 16)
            if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFFFFFFFFFF):
                raise ValueError
            plaintext = triple_decrypt(ciphertext, key)
            self.triple_result.delete(0, tk.END)
            self.triple_result.insert(0, f"{plaintext:04X}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def init_cbc_tab(self):
        # 明文输入
        ttk.Label(self.tab_cbc, text="明文:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.NW)
        self.cbc_plaintext = tk.Text(self.tab_cbc, width=40, height=5)
        self.cbc_plaintext.grid(row=0, column=1, padx=5, pady=5)
        self.cbc_plaintext.insert(tk.END, "这是CBC模式测试消息")

        # 密文输入
        ttk.Label(self.tab_cbc, text="密文块 (逗号分隔):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.NW)
        self.cbc_ciphertext = ttk.Entry(self.tab_cbc, width=50)
        self.cbc_ciphertext.grid(row=1, column=1, padx=5, pady=5)

        # 密钥和IV
        ttk.Label(self.tab_cbc, text="16位密钥 (十六进制):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_key = ttk.Entry(self.tab_cbc, width=20)
        self.cbc_key.grid(row=2, column=1, padx=5, pady=5)
        self.cbc_key.insert(0, "A1B2")

        ttk.Label(self.tab_cbc, text="16位IV (十六进制):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.cbc_iv = ttk.Entry(self.tab_cbc, width=20)
        self.cbc_iv.grid(row=3, column=1, padx=5, pady=5)
        self.cbc_iv.insert(0, "C3D4")

        # 生成随机IV按钮
        ttk.Button(self.tab_cbc, text="生成随机IV", command=self.gen_random_iv).grid(
            row=3, column=2, padx=5, pady=5
        )

        # 篡改密文输入
        ttk.Label(self.tab_cbc, text="篡改密文索引:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.tamper_index = ttk.Entry(self.tab_cbc, width=5)
        self.tamper_index.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        self.tamper_index.insert(0, "0")

        ttk.Label(self.tab_cbc, text="新值:").grid(row=4, column=1, padx=5, pady=5, sticky=tk.E)
        self.tamper_value = ttk.Entry(self.tab_cbc, width=10)
        self.tamper_value.grid(row=4, column=2, padx=5, pady=5, sticky=tk.W)
        self.tamper_value.insert(0, "FFFF")

        # 按钮
        ttk.Button(self.tab_cbc, text="CBC加密", command=self.perform_cbc_encrypt).grid(
            row=5, column=0, padx=5, pady=5
        )
        ttk.Button(self.tab_cbc, text="CBC解密", command=self.perform_cbc_decrypt).grid(
            row=5, column=1, padx=5, pady=5
        )
        ttk.Button(self.tab_cbc, text="篡改密文并解密", command=self.tamper_and_decrypt).grid(
            row=5, column=2, padx=5, pady=5
        )

        # 结果
        ttk.Label(self.tab_cbc, text="结果:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.NW)
        self.cbc_result = tk.Text(self.tab_cbc, width=40, height=5)
        self.cbc_result.grid(row=6, column=1, padx=5, pady=5)

        # 加密后IV显示
        ttk.Label(self.tab_cbc, text="使用的IV:").grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)
        self.used_iv = ttk.Entry(self.tab_cbc, width=20)
        self.used_iv.grid(row=7, column=1, padx=5, pady=5)

    def gen_random_iv(self):
        """生成随机16位IV并显示"""
        iv = random.randint(0, 0xFFFF)
        self.cbc_iv.delete(0, tk.END)
        self.cbc_iv.insert(0, f"{iv:04X}")

    def perform_cbc_encrypt(self):
        try:
            plaintext = self.cbc_plaintext.get("1.0", tk.END).strip()
            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            if not (0 <= key <= 0xFFFF and 0 <= iv <= 0xFFFF):
                raise ValueError

            cipher_blocks, used_iv = cbc_encrypt(plaintext, key, iv)
            self.cbc_ciphertext.delete(0, tk.END)
            self.cbc_ciphertext.insert(0, ",".join(f"{block:04X}" for block in cipher_blocks))
            self.used_iv.delete(0, tk.END)
            self.used_iv.insert(0, f"{used_iv:04X}")

            self.cbc_result.delete("1.0", tk.END)
            self.cbc_result.insert(tk.END, "加密完成")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的密钥或IV")

    def perform_cbc_decrypt(self):
        try:
            cipher_str = self.cbc_ciphertext.get()
            if not cipher_str:
                raise ValueError
            cipher_blocks = [int(block, 16) for block in cipher_str.split(",")]
            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            if not (0 <= key <= 0xFFFF and 0 <= iv <= 0xFFFF):
                raise ValueError

            plaintext = cbc_decrypt(cipher_blocks, key, iv)
            self.cbc_result.delete("1.0", tk.END)
            self.cbc_result.insert(tk.END, plaintext)
        except ValueError:
            messagebox.showerror("错误", "请输入有效的密文、密钥或IV")

    def tamper_and_decrypt(self):
        try:
            cipher_str = self.cbc_ciphertext.get()
            if not cipher_str:
                raise ValueError
            cipher_blocks = [int(block, 16) for block in cipher_str.split(",")]
            index = int(self.tamper_index.get())
            new_value = int(self.tamper_value.get(), 16)

            if not (0 <= index < len(cipher_blocks) and 0 <= new_value <= 0xFFFF):
                raise ValueError

            # 篡改密文
            tampered_blocks = cipher_blocks.copy()
            tampered_blocks[index] = new_value

            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            if not (0 <= key <= 0xFFFF and 0 <= iv <= 0xFFFF):
                raise ValueError

            # 解密篡改后的密文
            plaintext = cbc_decrypt(tampered_blocks, key, iv)
            self.cbc_result.delete("1.0", tk.END)
            self.cbc_result.insert(tk.END, f"篡改后解密结果:\n{plaintext}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的参数")


if __name__ == "__main__":
    root = tk.Tk()
    app = S_AES_GUI(root)
    root.mainloop()