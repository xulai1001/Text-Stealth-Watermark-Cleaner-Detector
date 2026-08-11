import unicodedata
import re
import sys
import json
import argparse
import os
from datetime import datetime

# --- Configuration ---

# Set of known invisible or problematic formatting characters to REMOVE
INVISIBLE_CHARS_TO_REMOVE = {
    # 零宽字符
    '\u200B',  # Zero Width Space (零宽空格)
    '\u200C',  # Zero Width Non-Joiner (零宽非连接符)
    '\u200D',  # Zero Width Joiner (零宽连接符)
    '\u2060',  # Word Joiner (词连接符)
    '\uFEFF',  # Zero Width No-Break Space (BOM) - remove only if not at start
    
    # 软连字符
    '\u00AD',  # Soft Hyphen (软连字符)
    
    # 方向控制字符
    '\u200E',  # Left-to-Right Mark (从左到右标记)
    '\u200F',  # Right-to-Left Mark (从右到左标记)
    '\u202A',  # Left-to-Right Embedding (从左到右嵌入)
    '\u202B',  # Right-to-Left Embedding (从右到左嵌入)
    '\u202C',  # Pop Directional Formatting (弹出方向格式)
    '\u202D',  # Left-to-Right Override (从左到右覆盖)
    '\u202E',  # Right-to-Left Override (从右到左覆盖)
    '\u2066',  # Left-to-Right Isolate (从左到右隔离)
    '\u2067',  # Right-to-Left Isolate (从右到左隔离)
    '\u2068',  # First Strong Isolate (首个强隔离)
    '\u2069',  # Pop Directional Isolate (弹出方向隔离)
    '\u061C',  # Arabic Letter Mark (阿拉伯字母标记)
    
    # 数学不可见字符
    '\u2061',  # Function Application (函数应用)
    '\u2062',  # Invisible Times (不可见乘号)
    '\u2063',  # Invisible Separator (不可见分隔符)
    '\u2064',  # Invisible Plus (不可见加号)
    
    # 组合用字符
    '\u034F',  # Combining Grapheme Joiner (组合用字形连接符)
    
    # 变体选择符 (VS1-VS16)
    '\uFE00', '\uFE01', '\uFE02', '\uFE03', '\uFE04', '\uFE05', '\uFE06', '\uFE07',
    '\uFE08', '\uFE09', '\uFE0A', '\uFE0B', '\uFE0C', '\uFE0D', '\uFE0E', '\uFE0F',
    
    # 蒙古文变体选择符
    '\u180B', '\u180C', '\u180D', '\u180E', '\u180F',
}

# 标签字符 (U+E0001-U+E007F) - 用于AI水印和元数据
# 这些字符需要单独处理，因为它们是多字节UTF-8字符
TAG_CHARACTERS = set()
TAG_CHARACTERS.add('\U000E0001')  # Tag Identifier
for i in range(0x0020, 0x007F):
    TAG_CHARACTERS.add(chr(0xE0000 + i))  # Tag characters

# 合并所有需要移除的不可见字符
INVISIBLE_CHARS_TO_REMOVE |= TAG_CHARACTERS

# 扩展变体选择符 (VS17-VS256) - 用于Glassworm攻击
# 这些字符需要单独处理，因为它们是多字节UTF-8字符
EXTENDED_VARIATION_SELECTORS = set()
for i in range(0xE0100, 0xE01EF + 1):
    EXTENDED_VARIATION_SELECTORS.add(chr(i))

# 合并所有需要移除的不可见字符
INVISIBLE_CHARS_TO_REMOVE |= EXTENDED_VARIATION_SELECTORS


# ASCII Control Characters (0x00-0x1F) + DEL (0x7F) to REMOVE
# Except for Tab (0x09), LineFeed (0x0A), Carriage Return (0x0D)
ASCII_CONTROL_CHARS_TO_REMOVE = {
    chr(i) for i in range(0x00, 0x20) if chr(i) not in ('\t', '\n', '\r')
} | {chr(0x7F)}

# Regex to find sequences of 2+ whitespace characters for reporting
EXCESSIVE_WHITESPACE_REGEX = re.compile(r'\s{2,}')
# Regex used in cleaning to normalize ALL whitespace sequences to a single space
WHITESPACE_NORMALIZATION_REGEX = re.compile(r'\s+')

# Standard/Common Whitespace characters (for detection reporting)
STANDARD_WHITESPACE = {' ', '\t', '\n', '\r', '\u00A0', '\u3000'} # Include NBSP and fullwidth space as somewhat common

# 中文字符Unicode范围列表（起始码点，结束码点）
# 注意：全角空格（U+3000）虽然是CJK符号，但它是空白字符，不在此范围内
CHINESE_CHAR_RANGES = [
    (0x4E00, 0x9FFF),    # CJK统一汉字（基本汉字）
    (0x3400, 0x4DBF),    # CJK扩展A
    (0x20000, 0x2A6DF),  # CJK扩展B
    (0xF900, 0xFAFF),    # CJK兼容汉字
    (0x3001, 0x303F),    # CJK符号和标点（包含中文标点，但不包括全角空格）
    (0xFF00, 0xFFEF),    # 全角ASCII和半角标点（包含全角标点）
    (0xFE30, 0xFE4F),    # CJK兼容形式
    (0xFE10, 0xFE1F),    # 中文竖排标点
    (0x31C0, 0x31EF),    # 中文笔画
]

# 中文常用标点（不在上述范围内）
CHINESE_PUNCTUATION_EXTRA = {
    0x201C, 0x201D, 0x2018, 0x2019,  # 引号
    0x2014,  # 破折号
    0x2026,  # 省略号
    0x2013,  # 连接号
    0x00B7,  # 间隔号
}


def is_chinese_char(char: str) -> bool:
    """
    判断字符是否属于中文字符范围（包括汉字、中文标点等）。
    注意：全角空格（U+3000）虽然是CJK符号，但它是空白字符，不在此范围内。
    
    Args:
        char: 单个字符
        
    Returns:
        如果是中文字符返回True，否则返回False
    """
    cp = ord(char)
    return any(start <= cp <= end for start, end in CHINESE_CHAR_RANGES) or cp in CHINESE_PUNCTUATION_EXTRA

# --- 检测辅助函数 ---

def _check_invisible_char(char: str, idx: int, findings: dict) -> bool:
    """检查是否为不可见/格式化字符（排除索引0处的BOM）。"""
    if char in INVISIBLE_CHARS_TO_REMOVE:
        if not (char == '\uFEFF' and idx == 0):
            findings["details"]["invisible_chars"].append({
                "index": idx, "char": char, "codepoint": f"U+{ord(char):04X}",
                "description": "已知的不可见/格式化字符"
            })
            return True
    return False


def _check_ascii_control_char(char: str, idx: int, findings: dict) -> bool:
    """检查是否为不允许的ASCII控制字符。"""
    if char in ASCII_CONTROL_CHARS_TO_REMOVE:
        findings["details"]["ascii_control_chars"].append({
            "index": idx, "char": repr(char), "codepoint": f"U+{ord(char):04X}",
            "description": "不允许的ASCII控制字符"
        })
        return True
    return False


def _check_non_standard_whitespace(char: str, idx: int, findings: dict) -> bool:
    """检查是否为非标准空白字符。"""
    if char.isspace() and char not in STANDARD_WHITESPACE:
        findings["details"]["non_standard_whitespace"].append({
            "index": idx, "char": repr(char), "codepoint": f"U+{ord(char):04X}",
            "description": "非标准空白字符"
        })
        return True
    return False


def _check_normalized_char(char: str, idx: int, findings: dict, skip: bool) -> bool:
    """检查NFKC标准化后是否改变（潜在同形字符/兼容性字符）。"""
    if skip or char.isspace() or is_chinese_char(char):
        return False
    normalized = unicodedata.normalize('NFKC', char)
    if char != normalized and normalized:
        # 避免将合法多字符分解（如 'ﬁ' -> 'fi'）标记为同形字符
        is_common = len(normalized) > 1 and all(
            'a' <= c.lower() <= 'z' or c.isdigit() or c in ' -' for c in normalized
        )
        if not is_common:
            findings["details"]["normalized_chars"].append({
                "index": idx, "original_char": char, "original_codepoint": f"U+{ord(char):04X}",
                "normalized_char": normalized,
                "normalized_codepoint": " ".join(f"U+{ord(c):04X}" for c in normalized),
                "description": "NFKC标准化后改变的字符（潜在同形字符或兼容性字符）"
            })
        return True
    return False


def _find_excessive_whitespace(text: str) -> list[dict]:
    """查找所有连续>=2的空白字符序列。"""
    results = []
    for match in EXCESSIVE_WHITESPACE_REGEX.finditer(text):
        results.append({
            "start_index": match.start(),
            "end_index": match.end(),
            "sequence": repr(match.group(0)),
            "length": len(match.group(0)),
            "description": "连续的多个空白字符"
        })
    return results


# --- 创建空的检测结果结构 ---

def _make_empty_findings() -> dict:
    """创建一个空的检测结果字典。"""
    return {
        "metadata": {},
        "summary": {
            "invisible_chars": 0,
            "ascii_control_chars": 0,
            "non_standard_whitespace": 0,
            "excessive_whitespace_sequences": 0,
            "normalized_chars": 0,
            "total_anomalies_found": 0,
        },
        "details": {
            "invisible_chars": [],
            "ascii_control_chars": [],
            "non_standard_whitespace": [],
            "excessive_whitespace_sequences": [],
            "normalized_chars": [],
        }
    }


def _update_summary(findings: dict) -> None:
    """更新汇总计数。"""
    for key in findings["summary"]:
        if key != "total_anomalies_found":
            findings["summary"][key] = len(findings["details"][key])
    findings["summary"]["total_anomalies_found"] = sum(
        findings["summary"][k] for k in findings["summary"] if k != "total_anomalies_found"
    )


# --- 检测主函数 ---

def detect_potential_watermarks(original_text: str) -> dict:
    """
    分析文本以检测潜在的隐藏水印特征。

    Args:
        original_text: 待分析的输入字符串。

    Returns:
        包含详细检测结果的字典。
    """
    if not isinstance(original_text, str):
        raise TypeError("输入必须是字符串类型")

    findings = _make_empty_findings()

    # 1. 逐字符检测：不可见字符、控制字符、非标准空白、NFKC变化
    for i, char in enumerate(original_text):
        flagged = False
        flagged |= _check_invisible_char(char, i, findings)
        flagged |= _check_ascii_control_char(char, i, findings)
        flagged |= _check_non_standard_whitespace(char, i, findings)
        _check_normalized_char(char, i, findings, skip=flagged)

    # 2. 扫描连续空白序列
    findings["details"]["excessive_whitespace_sequences"] = _find_excessive_whitespace(original_text)

    # 3. 更新汇总
    _update_summary(findings)

    return findings

# --- 清理辅助函数 ---

# 学术类空白符范围（U+2000-U+200A），保留原样不替换
ACADEMIC_WHITESPACE_RANGE = range(0x2000, 0x200B)


def _handle_bom(text: str) -> tuple[str, str, bool]:
    """处理BOM：如果不在最开头则移除。返回(文本, bom字符, 是否有初始bom)。"""
    if text and text[0] == '\uFEFF':
        return text[1:], text[0], True
    return text, "", False


def _restore_bom(text: str, bom: str, has_initial_bom: bool) -> str:
    """如果原来有BOM且清理后不空，则恢复。"""
    if has_initial_bom and text:
        return bom + text
    return text


def _normalize_with_chinese_preservation(text: str) -> str:
    """NFKC标准化时保留中文字符不被转换。"""
    positions = {i: c for i, c in enumerate(text) if is_chinese_char(c)}
    text = unicodedata.normalize('NFKC', text)
    for i, c in positions.items():
        if i < len(text):
            text = text[:i] + c + text[i+1:]
    return text


def _remove_chars(text: str, charset: set) -> str:
    """移除文本中属于charset的所有字符。"""
    return "".join(c for c in text if c not in charset)


def _preserve_linebreaks(text: str) -> tuple[str, list[int]]:
    """将换行符替换为占位符，返回(替换后的文本, 换行符位置列表)。"""
    PLACEHOLDER = '\x00LB\x00'
    linebreak = re.compile(r'\r?\n')
    positions = [m.start() for m in linebreak.finditer(text)]
    result = linebreak.sub(PLACEHOLDER, text)
    return result, positions


def _restore_linebreaks(text: str) -> str:
    """恢复被替换的换行符。"""
    return text.replace('\x00LB\x00', '\n')


def _preserve_academic_whitespace(text: str) -> tuple[str, dict]:
    """保存学术类空白符用占位符替换。返回(替换后的文本, 位置表)。"""
    PLACEHOLDER = '\x00AW\x00'
    positions = {}
    for i, c in enumerate(text):
        if c.isspace() and ord(c) in ACADEMIC_WHITESPACE_RANGE:
            positions[i] = c
    for i in sorted(positions.keys(), reverse=True):
        text = text[:i] + PLACEHOLDER + text[i+1:]
    return text, positions


def _restore_academic_whitespace(text: str, positions: dict) -> str:
    """恢复被替换的学术类空白符。"""
    PLACEHOLDER = '\x00AW\x00'
    result = []
    count = 0
    ordered = sorted(positions.items())
    for c in text:
        if c == PLACEHOLDER and count < len(ordered):
            result.append(ordered[count][1])
            count += 1
        else:
            result.append(c)
    return ''.join(result)


# --- 清理主函数 ---

def clean_text_from_watermarks(text: str) -> str:
    """
    通过标准化Unicode、移除已知的不可见/控制字符以及标准化空白字符来清理文本，
    以消除潜在的隐藏水印。

    Args:
        text: 待清理的输入字符串。

    Returns:
        清理后的字符串。
    """
    if not isinstance(text, str):
        raise TypeError("输入必须是字符串类型")
    if not text:
        return ""

    text, bom, has_bom = _handle_bom(text)          # 1. 处理BOM
    text = _normalize_with_chinese_preservation(text)  # 2. NFKC标准化（保留中文）
    text = _remove_chars(text, INVISIBLE_CHARS_TO_REMOVE)  # 3. 移除不可见字符
    text = _remove_chars(text, ASCII_CONTROL_CHARS_TO_REMOVE)  # 4. 移除ASCII控制字符

    # 5. 标准化空白字符
    #   a. 保护换行符
    text, _ = _preserve_linebreaks(text)
    #   b. 保护学术类空白符（U+2000-U+200A）
    text, acad_positions = _preserve_academic_whitespace(text)
    #   c. 标准化其他空白（包括其他非ASCII空白符如U+2800等）
    text = WHITESPACE_NORMALIZATION_REGEX.sub(' ', text)
    #   d. 恢复学术类空白符
    text = _restore_academic_whitespace(text, acad_positions)
    #   e. 恢复换行符
    text = _restore_linebreaks(text)

    text = text.strip()          # 6. 去除首尾空白
    text = _restore_bom(text, bom, has_bom)  # 7. 恢复BOM

    return text

# --- Report Generation Functions ---

def generate_human_report(findings: dict, input_filename: str) -> str:
    """生成人类可读的Markdown报告。"""
    report_lines = [
        f"# 水印分析报告：`{os.path.basename(input_filename)}`",
        f"分析时间：{findings['metadata']['timestamp']}",
        f"原始文件大小：{findings['metadata']['original_size']} 字节",
        f"检测到的异常总数：{findings['summary']['total_anomalies_found']}",
        "\n## 检测结果摘要",
        f"- **已知的不可见/格式化字符：** {findings['summary']['invisible_chars']}",
        f"- **不允许的ASCII控制字符：** {findings['summary']['ascii_control_chars']}",
        f"- **非标准空白字符：** {findings['summary']['non_standard_whitespace']}",
        f"- **连续的空白字符序列（>=2）：** {findings['summary']['excessive_whitespace_sequences']}",
        f"- **NFKC标准化后改变的字符：** {findings['summary']['normalized_chars']}",
        "\n## 详细检测结果"
    ]

    if not findings['summary']['total_anomalies_found']:
        report_lines.append("\n*未检测到潜在的水印异常。*")
    else:
        category_names = {
            "invisible_chars": "不可见字符",
            "ascii_control_chars": "ASCII控制字符",
            "non_standard_whitespace": "非标准空白字符",
            "excessive_whitespace_sequences": "连续空白字符序列",
            "normalized_chars": "标准化改变的字符"
        }
        # 只汇报总数的类别（不列出每个出现位置）
        summary_only_categories = {"excessive_whitespace_sequences"}
        for category, details in findings["details"].items():
            if details:
                category_title = category_names.get(category, category.replace('_', ' ').title())
                report_lines.append(f"\n### {category_title}")
                if category in summary_only_categories:
                    # 只汇报总数，不列出详细信息
                    report_lines.append(f"\n共检测到 **{len(details)}** 处连续空白字符序列。")
                else:
                    report_lines.append("| 位置 | 字符 | 码点 | 详情 |")
                    report_lines.append("|---|---|---|---|")
                    for item in details:
                        char_repr = item.get('char', item.get('original_char', item.get('sequence', 'N/A')))
                        # 转义Markdown表格中的管道字符
                        char_display = repr(char_repr).replace('|', '\\|')
                        codepoint = item.get('codepoint', item.get('original_codepoint', 'N/A'))
                        desc = item.get('description', '')
                        if 'normalized_char' in item:
                            desc += f" （标准化为：{repr(item['normalized_char'])} {item['normalized_codepoint']}）"
                        if 'length' in item:
                            desc += f" （长度：{item['length']}）"

                        report_lines.append(f"| {item.get('index', item.get('start_index', 'N/A'))} | `{char_display}` | {codepoint} | {desc} |")

    return "\n".join(report_lines)

def generate_json_report(findings: dict, input_filename: str, output_path: str):
    """生成JSON格式的报告文件。"""
    # 在转储前将元数据添加到findings结构中
    findings["metadata"]["input_filename"] = os.path.basename(input_filename)
    # 时间戳和大小已在main()中添加

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, ensure_ascii=False, indent=4)
        print(f"已成功生成JSON报告：{output_path}")
    except IOError as e:
        print(f"写入JSON报告时出错 {output_path}: {e}", file=sys.stderr)
    except TypeError as e:
        print(f"序列化findings为JSON时出错: {e}", file=sys.stderr)


# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="检测并移除文件中潜在的隐藏文本水印。"
                    "生成清理后的文本文件、人类可读的Markdown报告和机器可读的JSON报告。"
    )
    parser.add_argument("input_file", help="输入文本文件的路径（UTF-8编码）。")
    parser.add_argument(
        "-o", "--output-basename",
        help="输出文件的基本名称。如果未提供，则使用输入文件名（不含扩展名）。"
             "输出文件将命名为：<basename>_cleaned.txt、<basename>_report.md、<basename>_report.json"
    )
    # 如需要可使用logging模块添加详细输出选项

    args = parser.parse_args()

    input_path = args.input_file
    if not os.path.isfile(input_path):
        print(f"错误：未找到输入文件：{input_path}", file=sys.stderr)
        sys.exit(1)

    # 确定输出基本名称
    if args.output_basename:
        base_name = args.output_basename
    else:
        base_name = os.path.splitext(os.path.basename(input_path))[0]

    output_dir = os.path.dirname(input_path) # 默认在输入文件所在目录输出
    cleaned_path = os.path.join(output_dir, f"{base_name}_cleaned.txt")
    report_md_path = os.path.join(output_dir, f"{base_name}_report.md")
    report_json_path = os.path.join(output_dir, f"{base_name}_report.json")

    # 读取输入文件
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            original_text = f.read()
        original_size = os.path.getsize(input_path)
        print(f"已成功读取输入文件：{input_path}（{original_size} 字节）")
    except Exception as e:
        print(f"读取输入文件时出错 {input_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 分析 ---
    print("正在分析文本中的潜在水印...")
    analysis_findings = detect_potential_watermarks(original_text)

    # 添加报告所需的元数据
    analysis_findings["metadata"]["timestamp"] = datetime.now().isoformat()
    analysis_findings["metadata"]["original_size"] = original_size

    # --- 清理 ---
    print("正在清理文本...")
    cleaned_text = clean_text_from_watermarks(original_text)

    # --- 生成输出 ---

    # 1. 写入清理后的文本文件
    try:
        with open(cleaned_path, 'w', encoding='utf-8') as f:
            f.write(cleaned_text)
        print(f"已成功生成清理后的文本文件：{cleaned_path}")
    except IOError as e:
        print(f"写入清理文件时出错 {cleaned_path}: {e}", file=sys.stderr)

    # 2. 生成并写入人类可读的报告（Markdown）
    try:
        markdown_report = generate_human_report(analysis_findings, input_path)
        with open(report_md_path, 'w', encoding='utf-8') as f:
            f.write(markdown_report)
        print(f"已成功生成Markdown报告：{report_md_path}")
    except IOError as e:
        print(f"写入Markdown报告时出错 {report_md_path}: {e}", file=sys.stderr)

    # 3. 生成并写入JSON报告
    generate_json_report(analysis_findings, input_path, report_json_path)

    print("\n处理完成。")
    if analysis_findings["summary"]["total_anomalies_found"] > 0:
        print(f"检测到 {analysis_findings['summary']['total_anomalies_found']} 个潜在异常。请查看报告获取详细信息。")
    else:
        print("未检测到潜在的水印异常。")


if __name__ == "__main__":
    main()