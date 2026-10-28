<div align="center">

# 🔬 HexScope

**零依赖 · 离线优先 · 二进制文件取证探查工具箱**

[简体中文](#简体中文) ｜ [繁體中文](#繁體中文) ｜ [English](#english)

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Offline](https://img.shields.io/badge/network-none-lightgrey)
![Tests](https://img.shields.io/badge/tests-59%20passing-brightgreen)

</div>

---

## 简体中文

### 🎉 项目介绍

拿到一个来源不明的二进制文件，你的第一分钟通常花在这些问题上：**它到底是什么格式？里面藏着什么？是不是被加密或压缩过？改动过哪几个字节？里面是不是还嵌着别的文件？**

回答它们本来需要 `xxd` + `file` + `strings` + `binwalk` + `ent` + `cmp` 一整套工具链，还常常装不上（Windows 没有、容器镜像里没有、安全环境不让装）。

**HexScope 把这一整套能力收进一个零依赖的纯 Python 包**：不需要任何第三方库、不联网、不写临时文件、不调用外部命令，只要有 Python 3.8+ 就能跑。它既是一个带彩色终端输出的 CLI，也是一个可以直接 `import` 的分析库，并且**每条命令都支持 `--json`**，能直接塞进 CI / 自动化流水线。

**自研差异化亮点**

| 亮点 | 说明 |
| --- | --- |
| 🧩 **真·零依赖** | 只用标准库；打包产物是一个 **30 KB 的单文件可执行归档**（zipapp），拷走就能跑 |
| 🎨 **为终端而生的渲染** | 字节按语义着色（NUL / 可打印 / 高位 / 控制字符）、Unicode 迷你趋势图、柱状直方图，全部自动适配 TTY 与 `NO_COLOR` |
| 🧠 **熵不止一个数** | 同时给出整体熵、分块熵、滑动窗口熵剖面，直接定位"哪一段被加密/压缩" |
| 🕵️ **复合文件侦察** | 内置 100+ 条魔数规则，既识别文件头，也扫描**嵌入在内部**的文件（固件 / 磁盘镜像 / 加壳样本） |
| 🔁 **机器可读优先** | `--json` / `--md` 输出稳定结构，可作为安全流水线的判断依据 |
| 🧪 **可测试的设计** | 分析函数与渲染函数分离，纯函数返回结果对象，59 个单元测试覆盖核心算法 |

灵感来源：经典 UNIX 工具链（`xxd`、`file`、`strings`、`ent`、`cmp`、`binwalk`）在跨平台场景下"装不全"的痛点。HexScope 只借鉴它们要解决的问题，代码 100% 自研。

### ✨ 核心特性

- 🔍 **`identify`** —— 魔数识别 + 文本嗅探：100+ 条签名（图片 / 音视频 / 压缩包 / 可执行文件 / 文档 / 数据库 / 字体 / 密钥证书），支持 BOM 与 shebang、JSON / XML / HTML 判别，支持 **`--magic-file` 自定义签名表**
- 🧱 **`hex`** —— 可配置 hex dump：宽度、分组、2/8/10/16 进制、大小写、ASCII 栏、填充字符、起始偏移、读取窗口
- 🔤 **`strings`** —— 字符串提取：ASCII / UTF-8 / UTF-16LE / UTF-16BE / latin-1，最小长度、正则过滤、带偏移
- 📈 **`entropy`** —— 香农熵分析：整体值 + 语义标签 + 分块映射 + 滑动窗口剖面 + 迷你趋势图（可切 ASCII）
- 📊 **`hist`** —— 字节值直方图：Top-N 频率、覆盖率、按字节类别（NUL / 控制 / 空白 / 数字 / 字母 / 高位）聚合
- 🔀 **`diff`** —— 字节级二进制差异：差异区段聚合、可配置合并间距、并排 hex 对照、长度变化提示
- 🕳️ **`carve`** —— 嵌入文件侦察：扫描非起始位置的魔数命中，定位固件/容器里的"文件里的文件"
- 📋 **`stats`** —— 一次性总览：SHA-256 / MD5 / 熵 / 可打印率 / NUL 率 / 行尾风格 / 类型判定 + 一句人话结论
- 🧾 **`report`** —— 一次跑完上面全部，输出完整报告（文本或 JSON）
- 📦 **库模式** —— `from hexscope import identify, shannon_entropy, carve ...`，带 `py.typed` 类型标注
- 🧯 **工程细节** —— 8 MiB 默认读取上限、`--limit/--offset` 窗口、管道 stdin 支持（`cat x | hexscope identify -`）、非零退出码、`NO_COLOR` / `FORCE_COLOR` 支持

### 🚀 快速开始

**环境要求**

- Python **3.8 及以上**（Windows / macOS / Linux 通用）
- 无第三方依赖，无需联网

**方式一：单文件可执行归档（推荐，无需安装）**

```bash
# 从 Release 下载 hexscope.pyz 后：
python3 hexscope.pyz stats sample.bin

# Linux / macOS 也可以直接执行
chmod +x hexscope.pyz && ./hexscope.pyz stats sample.bin
```

**方式二：pip 安装**

```bash
pip install .
hexscope stats sample.bin
```

**方式三：免安装直接跑**

```bash
git clone https://github.com/gitstq/hexscope.git
cd hexscope
python3 -m hexscope stats examples/sample.bin
```

**三十秒体验**

```bash
python3 scripts/make_samples.py          # 生成演示样本 examples/sample.bin
python3 -m hexscope report examples/sample.bin
python3 -m hexscope hex examples/sample.bin --limit 64
python3 -m hexscope carve examples/sample.bin
```

### 📖 详细使用指南

#### 1️⃣ `stats` —— 先问"这是什么"

```bash
$ python3 -m hexscope stats examples/sample.bin
Stats — examples/sample.bin
Name       : examples/sample.bin
Size       : 1272 bytes (1.24 KiB)
SHA-256    : fce7f219e3413f97b8ef1040211b5887dfb5d0324fb916a5b6a3daa3dfd13f8c
MD5        : eb6148e61f2fc72295fd0f26b6453004
Type       : PNG image
MIME       : image/png
Encoding   : —
Entropy    : 7.3891 bits/byte (compressed)
Printable  : 36.64%
NUL bytes  : 11.71%
Control    : 11.01%
High bytes : 40.64%
Distinct   : 251/256
Line ends  : LF×9, CR×5, CRLF×1
Top bytes  : 0x00×149, 0x6f×15, 0x64×14, 0x61×11, 0x65×11, 0x72×11, 0x0a×10

Verdict  : likely compressed data — identified as PNG image
```

> `Verdict` 是给人类看的一句话结论：纯文本 / 可能被加密或压缩 / 稀疏填充的二进制 / 结构化二进制。

#### 2️⃣ `identify` —— 魔数识别与文本嗅探

```bash
$ python3 -m hexscope identify examples/sample.bin
Type       : PNG image (png)
MIME       : image/png
Signature  : 89504e470d0a1a0a @ offset 19
Note        : signature sits at offset 19, not at the file start — this is a padded / embedded container
```

自定义签名表（`偏移|十六进制|扩展名|MIME|描述`，`*` 表示"在头部窗口内搜索"）：

```bash
cat > my.magic <<'EOF'
# 偏移 | 魔数 | 扩展名 | MIME | 描述
0|de ad be ef|bin|application/x-my|我的私有格式
*|ca fe ba be|bin|application/x-float|浮动签名
EOF
python3 -m hexscope identify blob.bin --magic-file my.magic
```

#### 3️⃣ `hex` —— 可配置的 hex dump

```bash
$ python3 -m hexscope hex examples/sample.bin --limit 64
00000000  46 49 52 4d 57 41 52 45 2d 49 4d 41 47 45 2d 56  |FIRMWARE-IMAGE-V|
00000010  32 00 00 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49  |2...PNG........I|
00000020  48 44 52 00 00 00 08 00 00 00 08 08 06 00 00 00  |HDR.............|
00000030  00 1c 20 7a 3f 52 91 8c 4e 55 6f d1 7e 8e 1b 3f  |.. z?R..NUo.~..?|
```

常用参数：`--width`（每行字节数）、`--group`（分组）、`--base 2|8|10|16`、`--uppercase`、`--no-ascii`、`--pad`、`--offset`、`--limit`、`--max-lines`。

```bash
python3 -m hexscope hex firmware.bin --offset 0x1000 --limit 256 --width 32 --group 4
```

#### 4️⃣ `strings` —— 字符串提取

```bash
$ python3 -m hexscope strings examples/sample.bin --min-len 6
0x00000000  FIRMWARE-IMAGE-V2
0x00000500  bootloader ready

# UTF-16 与正则过滤
python3 -m hexscope strings dump.bin --encoding utf-16-le --min-len 6
python3 -m hexscope strings dump.bin --pattern 'https?://' --min-len 8
```

#### 5️⃣ `entropy` —— 熵分析（定位加密 / 压缩区段）

```bash
$ python3 -m hexscope entropy examples/sample.bin --window 256 --step 128 --width 60
Entropy     : 7.3891 bits/byte (compressed)
Size        : 1272 bytes
Distinct    : 251/256 byte values

Entropy profile (0 ────── 8 bits/byte)
  ▇▇▇▇▇▇▃▆▇▆
  min 2.519 @ 768   max 6.871 @ 384
```

语义标签：`<1.0` very-low ｜ `<3.5` structured ｜ `<5.0` text-like ｜ `<6.8` mixed ｜ `<7.6` compressed ｜ `≥7.6` encrypted/random。
在不支持 Unicode 的终端上加 `--ascii` 即可切换为 ASCII 迷你图。

#### 6️⃣ `hist` —— 字节直方图

```bash
$ python3 -m hexscope hist examples/sample.bin --top 8
Byte histogram — top 8 of 251 values
  0x00 \0  ████████████████████████████████████████       149  11.71%
  0x6f o   ████                                            15   1.18%
  0x64 d   ████                                            14   1.10%
  ...
Byte classes
  high byte           ████████                                 20.52%
  continuation/high   ████████                                 20.13%
```

#### 7️⃣ `diff` —— 字节级二进制差异

```bash
$ python3 -m hexscope diff old.bin new.bin --excerpt 32
A : 929 bytes      B : 929 bytes
Regions : 1 differing region(s), 4 changed byte(s) in the compared window

[1] offset 0x00000064 – 0x00000068 (4 bytes)
  A:
    00000064  54 af 4d fa                                      |T.M.|
  B:
    00000064  de ad be ef                                      |....|
```

`--context` 控制"多近的差异合并成一段"，`--max-regions`、`--max-scan`、`--no-hex` 便于大文件与 CI 场景。

#### 8️⃣ `carve` —— 嵌入文件侦察

```bash
$ python3 -m hexscope carve examples/sample.bin
Embedded candidates — 2 hit(s)
  0x00000013  png    PNG image  89504e470d0a1a0a
  0x000003b0  zip    ZIP archive (also jar/docx/xlsx/apk)  504b0304
```

#### 9️⃣ `report` 与 `--json` / `--md`

```bash
python3 -m hexscope report examples/sample.bin                    # 完整报告（人读）
python3 -m hexscope report examples/sample.bin --json > r.json    # 完整报告（机器读）
python3 -m hexscope strings sample.bin --md                       # Markdown 表格
```

🔟 **库模式**

```python
from hexscope import identify, shannon_entropy, extract_strings, carve, diff_bytes

blob = open("firmware.bin", "rb").read()

identify(blob).best.signature.desc          # 'PNG image'
shannon_entropy(blob[:1024])                # 7.42
[h.text for h in extract_strings(blob, min_len=6).hits]
[hex(h.offset) for h in carve(blob).hits]
diff_bytes(open("a.bin","rb").read(), open("b.bin","rb").read()).changed_bytes
```

**CI 集成示例**（一旦检测到"疑似加密/压缩的可执行文件"就失败）：

```bash
python3 -m hexscope stats ./build/app.bin --json > stats.json
python3 - <<'EOF'
import json, sys
d = json.load(open("stats.json"))
sys.exit(1 if d["entropy"] > 7.6 and "executable" in (d["kind"] or "") else 0)
EOF
```

**退出码**：`0` 成功 / `1` 运行错误（文件不存在等）/ `2` 用法错误。

### 💡 设计思路与迭代规划

**设计原则**

1. **分析归分析，渲染归渲染** —— 每个算法模块返回 dataclass 结果对象（`to_dict()` / `render_text()`），CLI 只是薄薄一层，因此库模式与 CLI 永远同能力
2. **绝不猜用户的带宽和磁盘** —— 默认 8 MiB 读取上限，所有大文件操作都能用 `--limit/--offset` 限定窗口
3. **终端是二等公民** —— 颜色、Unicode 都是可选装饰；`NO_COLOR=1`、`--no-color`、非 TTY 环境下自动退化为纯文本，保证日志干净
4. **机器可读是一等公民** —— 每个命令都能 `--json`，CI 里不需要解析彩色文本
5. **零依赖是硬约束** —— 宁可自己写直方图，也不引入 numpy

**当前取舍**

- `carve` 只做"定位"，不做真正的文件重建（ carving 需要格式解析器，超出零依赖范围）
- 熵阈值（如 7.6 = 加密/压缩）是经验值，用于快速分类而非密码学判定
- 两/三字节魔数（如 `MZ`）置信度被刻意压低，避免误报

**迭代规划**

- [ ] 结构化解析器：ELF / PE / Mach-O 头部字段解析
- [ ] 签名表扩展到 300+，并支持社区贡献的规则包
- [ ] 目录级批量模式：`hexscope scan ./dir --json`
- [ ] 熵剖面导出为 SVG / PNG（仍保持零依赖）
- [ ] SARIF 输出，直接接入 GitHub Code Scanning
- [ ] 可交互 TUI（方向键翻阅大文件）

### 📦 打包与部署指南

| 方式 | 命令 | 产物 |
| --- | --- | --- |
| 单文件归档 | `python3 scripts/build.py` | `dist/hexscope.pyz`（约 30 KB，需 Python 3.8+） |
| wheel / sdist | `pip install build && python3 -m build` | `dist/hexscope-1.0.0-py3-none-any.whl`、`.tar.gz` |
| pip 安装 | `pip install .` | `hexscope` 命令 |
| PyInstaller | `pyinstaller -F hexscope/cli.py -n hexscope` | 原生可执行文件（第三方工具，非本项目依赖） |

- `scripts/build.py` 会**先跑测试再打包**，打包后自动做一次 `--version` 冒烟验证
- `make test` / `make build` / `make run` / `make clean` 为常用快捷方式
- 兼容范围：Python 3.8 – 3.12+，Windows / macOS / Linux；单文件归档在任意有 Python 的机器上可直接执行

### 🤝 贡献指南

见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交信息请使用 Angular 规范（`feat:` `fix:` `docs:` `refactor:` `test:` `chore:`），并且**不要引入任何第三方运行时依赖**。

### 📄 开源协议

[MIT License](LICENSE) © 2026 HexScope contributors

---

## 繁體中文

### 🎉 專案介紹

拿到一個來源不明的二進位檔案，第一分鐘通常都花在這些問題上：**它究竟是什麼格式？裡面藏了什麼？有沒有被加密或壓縮？改動了哪幾個位元組？裡面是不是還包著別的檔案？**

要回答這些問題，傳統上得湊齊 `xxd` + `file` + `strings` + `binwalk` + `ent` + `cmp` 一整串工具，而且往往裝不起來（Windows 沒有、容器映像裡沒有、資安環境不給裝）。

**HexScope 把整套能力收進一個零依賴的純 Python 套件**：不需要任何第三方函式庫、不連網、不寫暫存檔、不呼叫外部程式，只要有 Python 3.8+ 就能執行。它同時是具備彩色終端輸出的 CLI，也是能直接 `import` 的分析函式庫，而且**每個指令都支援 `--json`**，可以直接放進 CI / 自動化流程。

**自研差異化亮點**

| 亮點 | 說明 |
| --- | --- |
| 🧩 **真·零依賴** | 只用標準函式庫；封裝產物是 **30 KB 的單檔可執行封存**（zipapp），複製過去就能跑 |
| 🎨 **為終端而生** | 位元組依語義上色（NUL / 可列印 / 高位元 / 控制字元）、Unicode 迷你趨勢圖、長條直方圖，自動適應 TTY 與 `NO_COLOR` |
| 🧠 **熵不只有一個數字** | 同時給出整體熵、分塊熵、滑動視窗熵剖面，直接指出「哪一段被加密/壓縮」 |
| 🕵️ **複合檔案偵察** | 內建 100+ 條魔數規則，除了辨識檔頭，也掃描**嵌在檔案內部**的檔案（韌體 / 磁碟映像 / 加殼樣本） |
| 🔁 **機器可讀優先** | `--json` / `--md` 輸出結構穩定，可作為資安流程的判斷依據 |
| 🧪 **可測試的設計** | 分析與渲染分離，純函式回傳結果物件，59 個單元測試覆蓋核心演算法 |

靈感來源：經典 UNIX 工具鏈在跨平台情境下「永遠裝不齊」的痛點。HexScope 只借鏡它們想解決的問題，程式碼 100% 自研。

### ✨ 核心功能

- 🔍 **`identify`** —— 魔數辨識 + 文字嗅探：100+ 條簽章（圖片 / 影音 / 壓縮檔 / 執行檔 / 文件 / 資料庫 / 字型 / 金鑰憑證），支援 BOM 與 shebang、JSON / XML / HTML 判斷，並可用 **`--magic-file` 自訂簽章表**
- 🧱 **`hex`** —— 可設定的 hex dump：寬度、分組、2/8/10/16 進位、大小寫、ASCII 欄、填充字元、起始偏移、讀取視窗
- 🔤 **`strings`** —— 字串擷取：ASCII / UTF-8 / UTF-16LE / UTF-16BE / latin-1，最小長度、正則過濾、附偏移
- 📈 **`entropy`** —— 夏農熵分析：整體值 + 語義標籤 + 分塊圖 + 滑動視窗剖面 + 迷你趨勢圖（可切 ASCII）
- 📊 **`hist`** —— 位元組值直方圖：Top-N 頻率、覆蓋率、依位元組類別（NUL / 控制 / 空白 / 數字 / 字母 / 高位元）聚合
- 🔀 **`diff`** —— 位元組級二進位差異：差異區段聚合、可設定合併間距、並排 hex 對照、長度變化提示
- 🕳️ **`carve`** —— 內嵌檔案偵察：掃描非起始位置的魔數命中，定位「檔案裡的檔案」
- 📋 **`stats`** —— 一次總覽：SHA-256 / MD5 / 熵 / 可列印率 / NUL 率 / 換行風格 / 類型判定 + 一句白話結論
- 🧾 **`report`** —— 一次跑完上述所有分析，輸出完整報告（文字或 JSON）
- 📦 **函式庫模式** —— `from hexscope import identify, shannon_entropy, carve ...`，附 `py.typed` 型別標註
- 🧯 **工程細節** —— 8 MiB 預設讀取上限、`--limit/--offset` 視窗、支援管線 stdin（`cat x | hexscope identify -`）、非零結束碼、`NO_COLOR` / `FORCE_COLOR`

### 🚀 快速開始

**環境需求**

- Python **3.8 以上**（Windows / macOS / Linux 皆可）
- 無第三方依賴，不需連網

**方式一：單檔可執行封存（建議，免安裝）**

```bash
python3 hexscope.pyz stats sample.bin
chmod +x hexscope.pyz && ./hexscope.pyz stats sample.bin   # Linux / macOS
```

**方式二：pip 安裝**

```bash
pip install .
hexscope stats sample.bin
```

**方式三：免安裝直接跑**

```bash
git clone https://github.com/gitstq/hexscope.git
cd hexscope
python3 -m hexscope stats examples/sample.bin
```

**三十秒體驗**

```bash
python3 scripts/make_samples.py
python3 -m hexscope report examples/sample.bin
python3 -m hexscope hex examples/sample.bin --limit 64
python3 -m hexscope carve examples/sample.bin
```

### 📖 詳細使用指南

#### 1️⃣ `stats` —— 先問「這是什麼」

```bash
$ python3 -m hexscope stats examples/sample.bin
Stats — examples/sample.bin
Size       : 1272 bytes (1.24 KiB)
SHA-256    : fce7f219e3413f97b8ef1040211b5887dfb5d0324fb916a5b6a3daa3dfd13f8c
Type       : PNG image
Entropy    : 7.3891 bits/byte (compressed)
Printable  : 36.64%
Verdict  : likely compressed data — identified as PNG image
```

#### 2️⃣ `identify` —— 魔數辨識與文字嗅探

```bash
$ python3 -m hexscope identify examples/sample.bin
Type       : PNG image (png)
Signature  : 89504e470d0a1a0a @ offset 19
Note        : signature sits at offset 19, not at the file start — this is a padded / embedded container
```

自訂簽章表（`偏移|十六進位|副檔名|MIME|描述`，`*` 表示在檔頭視窗內搜尋）：

```bash
python3 -m hexscope identify blob.bin --magic-file my.magic
```

#### 3️⃣ `hex` —— 可設定的 hex dump

```bash
python3 -m hexscope hex examples/sample.bin --limit 64
python3 -m hexscope hex firmware.bin --offset 0x1000 --limit 256 --width 32 --group 4
```

參數：`--width`、`--group`、`--base 2|8|10|16`、`--uppercase`、`--no-ascii`、`--pad`、`--offset`、`--limit`、`--max-lines`。

#### 4️⃣ `strings` —— 字串擷取

```bash
python3 -m hexscope strings examples/sample.bin --min-len 6
python3 -m hexscope strings dump.bin --encoding utf-16-le --min-len 6
python3 -m hexscope strings dump.bin --pattern 'https?://' --min-len 8
```

#### 5️⃣ `entropy` —— 熵分析（定位加密 / 壓縮區段）

```bash
python3 -m hexscope entropy examples/sample.bin --window 256 --step 128 --width 60
```

語義標籤：`<1.0` very-low ｜ `<3.5` structured ｜ `<5.0` text-like ｜ `<6.8` mixed ｜ `<7.6` compressed ｜ `≥7.6` encrypted/random。終端不支援 Unicode 時加 `--ascii`。

#### 6️⃣ `hist` —— 位元組直方圖

```bash
python3 -m hexscope hist examples/sample.bin --top 8
```

#### 7️⃣ `diff` —— 位元組級差異

```bash
python3 -m hexscope diff old.bin new.bin --excerpt 32 --no-hex
```

`--context` 控制合併間距，`--max-regions` / `--max-scan` 便於大檔案與 CI 情境。

#### 8️⃣ `carve` —— 內嵌檔案偵察

```bash
python3 -m hexscope carve examples/sample.bin
```

#### 9️⃣ `report` 與 `--json` / `--md`

```bash
python3 -m hexscope report examples/sample.bin --json > r.json
python3 -m hexscope strings sample.bin --md
```

🔟 **函式庫模式**

```python
from hexscope import identify, shannon_entropy, extract_strings, carve, diff_bytes

blob = open("firmware.bin", "rb").read()
identify(blob).best.signature.desc      # 'PNG image'
shannon_entropy(blob[:1024])            # 7.42
[hex(h.offset) for h in carve(blob).hits]
```

**結束碼**：`0` 成功 ｜ `1` 執行錯誤 ｜ `2` 用法錯誤。

### 💡 設計思路與迭代規劃

**設計原則**

1. **分析歸分析，渲染歸渲染** —— 演算法模組回傳 dataclass（`to_dict()` / `render_text()`），CLI 只是薄薄一層
2. **不浪費使用者的磁碟與頻寬** —— 預設 8 MiB 讀取上限，全部可用 `--limit/--offset` 限定
3. **終端是二等公民** —— `NO_COLOR=1`、`--no-color`、非 TTY 自動退化為純文字
4. **機器可讀是一等公民** —— 每個指令都能 `--json`
5. **零依賴是硬約束** —— 寧可自己寫直方圖，也不引入 numpy

**目前取捨**

- `carve` 只做「定位」，不做真正的檔案重建
- 熵閾值為經驗值，僅供快速分類
- 兩/三位元組魔數（如 `MZ`）置信度刻意調低以減少誤報

**後續規劃**

- [ ] 結構化解析器：ELF / PE / Mach-O 檔頭欄位
- [ ] 簽章表擴充至 300+，支援社群規則包
- [ ] 目錄級批次模式：`hexscope scan ./dir --json`
- [ ] 熵剖面匯出 SVG / PNG（仍維持零依賴）
- [ ] SARIF 輸出，直接接入 GitHub Code Scanning

### 📦 打包與部署指南

| 方式 | 指令 | 產物 |
| --- | --- | --- |
| 單檔封存 | `python3 scripts/build.py` | `dist/hexscope.pyz`（約 30 KB） |
| wheel / sdist | `pip install build && python3 -m build` | `dist/hexscope-1.0.0-py3-none-any.whl`、`.tar.gz` |
| pip 安裝 | `pip install .` | `hexscope` 指令 |
| PyInstaller | `pyinstaller -F hexscope/cli.py -n hexscope` | 原生執行檔（第三方工具） |

`scripts/build.py` 會**先跑測試再打包**，打包後自動做一次 `--version` 煙霧測試。`make test` / `make build` / `make run` / `make clean` 為常用快捷指令。

### 🤝 貢獻指南

詳見 [CONTRIBUTING.md](CONTRIBUTING.md)。提交訊息請使用 Angular 規範，且**請勿引入任何第三方執行期依賴**。

### 📄 授權條款

[MIT License](LICENSE) © 2026 HexScope contributors

---

## English

### 🎉 Introduction

You are handed a binary of unknown origin. The first minute always goes to the
same questions: **what format is this? what is hidden inside? is it encrypted
or compressed? which bytes changed? does it embed other files?**

Answering them normally means assembling `xxd` + `file` + `strings` +
`binwalk` + `ent` + `cmp` — a toolchain that is frequently impossible to
install (no Windows build, absent from slim container images, blocked in
locked-down environments).

**HexScope packs that whole toolchain into a zero-dependency, pure-Python
package.** No third-party libraries, no network access, no temp files, no
subprocesses — just Python 3.8+. It is both a colourful terminal CLI and an
importable analysis library, and **every command supports `--json`**, so it
drops straight into CI pipelines.

**What makes it different**

| Highlight | Detail |
| --- | --- |
| 🧩 **Genuinely zero-dependency** | Standard library only; ships as a **~30 KB single-file executable archive** (zipapp) |
| 🎨 **Built for the terminal** | Semantic byte colouring (NUL / printable / high / control), Unicode sparklines, bar histograms — all TTY- and `NO_COLOR`-aware |
| 🧠 **Entropy is more than one number** | Overall + block + sliding-window profile, so you can point at *which region* is encrypted or compressed |
| 🕵️ **Compound-file reconnaissance** | 100+ magic rules that match the header **and** sweep for embedded files (firmware, disk images, packed samples) |
| 🔁 **Machine-readable first** | `--json` / `--md` output with stable structure for automation |
| 🧪 **Testable by design** | Analysis and rendering are separated; pure functions return result objects; 59 unit tests cover the core algorithms |

Inspired by the pain of never having the classic UNIX toolchain available
cross-platform. Only the *problems* were borrowed — the code is 100% original.

### ✨ Features

- 🔍 **`identify`** — magic detection + text sniffing: 100+ signatures (images, audio/video, archives, executables, documents, databases, fonts, keys/certs), BOM & shebang detection, JSON/XML/HTML discrimination, **`--magic-file` custom rules**
- 🧱 **`hex`** — configurable hex dump: width, grouping, radix 2/8/10/16, case, ASCII gutter, pad char, start offset, read window
- 🔤 **`strings`** — extraction for ASCII / UTF-8 / UTF-16LE / UTF-16BE / latin-1 with min length, regex filter and offsets
- 📈 **`entropy`** — Shannon entropy: overall value + semantic label + block map + sliding-window profile + sparkline (ASCII mode available)
- 📊 **`hist`** — byte-value histogram: top-N, coverage, byte-class aggregation (NUL / control / whitespace / digits / letters / high)
- 🔀 **`diff`** — byte-level binary diff: region merging, configurable gap, side-by-side hex, size delta
- 🕳️ **`carve`** — embedded-file sweep: finds magic numbers at non-zero offsets ("a file inside a file")
- 📋 **`stats`** — one-shot overview: SHA-256 / MD5 / entropy / printable ratio / NUL ratio / line endings / type + a plain-English verdict
- 🧾 **`report`** — everything above in a single pass (text or JSON)
- 📦 **Library mode** — `from hexscope import identify, shannon_entropy, carve ...`, ships `py.typed`
- 🧯 **Engineering details** — 8 MiB default read cap, `--limit/--offset` windows, stdin support (`cat x | hexscope identify -`), meaningful exit codes, `NO_COLOR` / `FORCE_COLOR`

### 🚀 Quick start

**Requirements**

- Python **3.8+** (Windows / macOS / Linux)
- No third-party dependencies, no network access

**Option 1 — single-file archive (recommended, nothing to install)**

```bash
python3 hexscope.pyz stats sample.bin
chmod +x hexscope.pyz && ./hexscope.pyz stats sample.bin   # Linux / macOS
```

**Option 2 — pip install**

```bash
pip install .
hexscope stats sample.bin
```

**Option 3 — run from a clone**

```bash
git clone https://github.com/gitstq/hexscope.git
cd hexscope
python3 -m hexscope stats examples/sample.bin
```

**Thirty-second tour**

```bash
python3 scripts/make_samples.py          # generate examples/sample.bin
python3 -m hexscope report examples/sample.bin
python3 -m hexscope hex examples/sample.bin --limit 64
python3 -m hexscope carve examples/sample.bin
```

### 📖 Usage guide

#### 1️⃣ `stats` — start with "what is this?"

```bash
$ python3 -m hexscope stats examples/sample.bin
Stats — examples/sample.bin
Size       : 1272 bytes (1.24 KiB)
SHA-256    : fce7f219e3413f97b8ef1040211b5887dfb5d0324fb916a5b6a3daa3dfd13f8c
Type       : PNG image
Entropy    : 7.3891 bits/byte (compressed)
Printable  : 36.64%
Verdict  : likely compressed data — identified as PNG image
```

#### 2️⃣ `identify` — magic numbers and text sniffing

```bash
$ python3 -m hexscope identify examples/sample.bin
Type       : PNG image (png)
Signature  : 89504e470d0a1a0a @ offset 19
Note        : signature sits at offset 19, not at the file start — this is a padded / embedded container
```

Custom signature table (`offset|hex|ext|mime|description`; `*` = search inside the header window):

```bash
python3 -m hexscope identify blob.bin --magic-file my.magic
```

#### 3️⃣ `hex` — configurable dump

```bash
python3 -m hexscope hex examples/sample.bin --limit 64
python3 -m hexscope hex firmware.bin --offset 0x1000 --limit 256 --width 32 --group 4
```

Options: `--width`, `--group`, `--base 2|8|10|16`, `--uppercase`, `--no-ascii`, `--pad`, `--offset`, `--limit`, `--max-lines`.

#### 4️⃣ `strings`

```bash
python3 -m hexscope strings examples/sample.bin --min-len 6
python3 -m hexscope strings dump.bin --encoding utf-16-le --min-len 6
python3 -m hexscope strings dump.bin --pattern 'https?://' --min-len 8
```

#### 5️⃣ `entropy` — locate encrypted / compressed regions

```bash
python3 -m hexscope entropy examples/sample.bin --window 256 --step 128 --width 60
```

Labels: `<1.0` very-low · `<3.5` structured · `<5.0` text-like · `<6.8` mixed · `<7.6` compressed · `≥7.6` encrypted/random. Use `--ascii` on terminals without Unicode support.

#### 6️⃣ `hist` — byte histogram

```bash
python3 -m hexscope hist examples/sample.bin --top 8
```

#### 7️⃣ `diff` — byte-level compare

```bash
python3 -m hexscope diff old.bin new.bin --excerpt 32 --no-hex
```

`--context` controls region merging; `--max-regions` / `--max-scan` suit large files and CI.

#### 8️⃣ `carve` — embedded files

```bash
python3 -m hexscope carve examples/sample.bin
```

#### 9️⃣ `report`, `--json` and `--md`

```bash
python3 -m hexscope report examples/sample.bin --json > r.json
python3 -m hexscope strings sample.bin --md
```

🔟 **Library mode**

```python
from hexscope import identify, shannon_entropy, extract_strings, carve, diff_bytes

blob = open("firmware.bin", "rb").read()
identify(blob).best.signature.desc      # 'PNG image'
shannon_entropy(blob[:1024])            # 7.42
[hex(h.offset) for h in carve(blob).hits]
```

**Exit codes**: `0` success · `1` runtime error · `2` usage error.

### 💡 Design notes & roadmap

**Principles**

1. **Analysis ≠ rendering** — algorithms return dataclasses (`to_dict()` / `render_text()`); the CLI is a thin shell, so the library always matches the CLI
2. **Never waste the user's disk** — 8 MiB default read cap, every large operation window-able via `--limit/--offset`
3. **The terminal is a second-class citizen** — colour and Unicode are decoration; `NO_COLOR=1`, `--no-color` and non-TTY all degrade to plain text
4. **Machine readability is first-class** — every command has `--json`
5. **Zero dependencies is a hard constraint** — we hand-roll histograms rather than pull in numpy

**Current trade-offs**

- `carve` only *locates* embedded files; real carving would need format parsers
- Entropy thresholds are heuristics for triage, not cryptographic judgements
- Two/three-byte magics (e.g. `MZ`) deliberately receive low confidence to limit false positives

**Roadmap**

- [ ] Structured header parsers: ELF / PE / Mach-O
- [ ] Grow the signature table past 300 rules, with community rule packs
- [ ] Directory batch mode: `hexscope scan ./dir --json`
- [ ] Export entropy profiles as SVG / PNG (still zero-dependency)
- [ ] SARIF output for GitHub Code Scanning
- [ ] Interactive TUI for paging through large files

### 📦 Packaging & deployment

| Method | Command | Artefact |
| --- | --- | --- |
| Single-file archive | `python3 scripts/build.py` | `dist/hexscope.pyz` (~30 KB, needs Python 3.8+) |
| wheel / sdist | `pip install build && python3 -m build` | `dist/hexscope-1.0.0-py3-none-any.whl`, `.tar.gz` |
| pip install | `pip install .` | `hexscope` command |
| PyInstaller | `pyinstaller -F hexscope/cli.py -n hexscope` | native binary (third-party tool) |

`scripts/build.py` **runs the tests first** and smoke-tests the archive afterwards. `make test` / `make build` / `make run` / `make clean` are the everyday shortcuts.

### 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commit messages follow the Angular convention (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`) and **no third-party runtime dependency may be introduced**.

### 📄 License

[MIT License](LICENSE) © 2026 HexScope contributors
