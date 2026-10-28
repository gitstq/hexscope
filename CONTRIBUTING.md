# 🤝 贡献指南 / Contributing

感谢你愿意让 HexScope 变得更好！本项目坚持**零第三方依赖**，因此贡献时请务必遵守下面的约定。

## 🧭 行为准则

- 保持友善、就事论事，不针对个人
- 提交前先搜索既有 Issue / PR，避免重复劳动
- 不接受任何形式的恶意代码、后门、"仅供研究"的攻击载荷

## 🚀 开发流程

```bash
git clone https://github.com/gitstq/hexscope.git
cd hexscope

# 1) 跑一遍测试，确保基线是绿的
python3 -m unittest discover -s tests -v

# 2) 生成演示样本（可选）
python3 scripts/make_samples.py

# 3) 改代码
#    - 新增能力放在 hexscope/ 下的独立模块
#    - 同步更新 hexscope/__init__.py 的 __all__ 导出
#    - 同步更新 hexscope/cli.py 的子命令（如需要）

# 4) 补测试 + 再跑一遍
python3 -m unittest discover -s tests -v

# 5) 打包自检
python3 scripts/build.py
```

## ✅ 提交规范（Angular Commit Convention）

| 前缀 | 用途 | 示例 |
| --- | --- | --- |
| `feat:` | 新功能 | `feat(carve): 支持自定义魔数表` |
| `fix:` | 修复缺陷 | `fix(hexdump): 修正末行对齐` |
| `docs:` | 文档更新 | `docs: 补充繁体中文 README` |
| `refactor:` | 重构（无行为变化） | `refactor(cli): 抽出公共参数解析器` |
| `test:` | 测试相关 | `test: 覆盖 utf-16 字符串提取` |
| `chore:` | 构建 / 杂项 | `chore: 添加 .gitignore` |
| `perf:` | 性能优化 | `perf(entropy): 复用直方图计数` |

## 🚫 硬性约束

1. **不允许引入任何第三方运行时依赖**（标准库之外一律不接受；`dev` 额外依赖只允许出现在 `[project.optional-dependencies]`）
2. **不允许引入网络请求、遥测、隐式文件写入**
3. 新增命令必须同时支持 `--json`，保证可在 CI 中使用
4. 所有渲染函数必须在 `NO_COLOR=1` / 非 TTY 环境下输出纯文本
5. 新增逻辑必须有对应单元测试，且 `python3 -m unittest discover -s tests` 全绿

## 🐛 提交 Issue

请附上：

- HexScope 版本（`hexscope --version`）与 Python 版本、操作系统
- 复现命令（如 `hexscope entropy ./x.bin --window 512`）
- 期望输出 vs 实际输出
- 若涉及具体文件，请给出**最小复现片段**（例如前 64 字节的 hex），不要上传敏感原始数据

## 📄 许可

提交 PR 即表示你同意你的贡献以本项目相同的 **MIT License** 授权发布。
