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
    '\u200B',  # Zero Width Space
    '\u200C',  # Zero Width Non-Joiner
    '\u200D',  # Zero Width Joiner
    '\u2060',  # Word Joiner
    '\u00AD',  # Soft Hyphen
    '\u200E',  # Left-to-Right Mark
    '\u200F',  # Right-to-Left Mark
    '\u202A',  # Left-to-Right Embedding
    '\u202B',  # Right-to-Left Embedding
    '\u202C',  # Pop Directional Formatting
    '\u202D',  # Left-to-Right Override
    '\u202E',  # Right-to-Left Override
    '\u2061',  # Function Application
    '\u2062',  # Invisible Times
    '\u2063',  # Invisible Separator
    '\u2064',  # Invisible Plus
    '\uFEFF',  # Zero Width No-Break Space (BOM) - remove only if not at start
}
# Add category Cf (Format) chars, excluding the ones above and whitespace/controls already handled
# Be cautious with this, might include things needed by some scripts (e.g., Arabic shaping)
# for i in range(sys.maxunicode):
#     char = chr(i)
#     if unicodedata.category(char) == 'Cf' and char not in INVISIBLE_CHARS_TO_REMOVE:
#         INVISIBLE_CHARS_TO_REMOVE.add(char)


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
STANDARD_WHITESPACE = {' ', '\t', '\n', '\r', '\u00A0'} # Include NBSP as somewhat common

# --- Detection Function ---

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

    findings = {
        "metadata": {}, # Will be added later
        "summary": {
            "invisible_chars": 0,
            "ascii_control_chars": 0,
            "non_standard_whitespace": 0,
            "excessive_whitespace_sequences": 0,
            "normalized_chars": 0, # Potential homoglyphs/compatibility chars changed by NFKC
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

    # 1. Check for specific invisible and control characters
    for i, char in enumerate(original_text):
        codepoint = f"U+{ord(char):04X}"
        anomaly_found = False

        # 检查不可见/格式化字符（排除索引0处的BOM）
        if char in INVISIBLE_CHARS_TO_REMOVE:
            if not (char == '\uFEFF' and i == 0):
                findings["details"]["invisible_chars"].append({
                    "index": i, "char": char, "codepoint": codepoint,
                    "description": "已知的不可见/格式化字符"
                })
                anomaly_found = True

        # 检查ASCII控制字符（排除允许的空白字符）
        if char in ASCII_CONTROL_CHARS_TO_REMOVE:
            findings["details"]["ascii_control_chars"].append({
                "index": i, "char": repr(char), "codepoint": codepoint,
                "description": "不允许的ASCII控制字符"
            })
            anomaly_found = True

        # 检查非标准空白字符
        if char.isspace() and char not in STANDARD_WHITESPACE:
            findings["details"]["non_standard_whitespace"].append({
                "index": i, "char": repr(char), "codepoint": codepoint,
                "description": "非标准空白字符"
            })
            anomaly_found = True

        # 检查因NFKC标准化而改变的字符（潜在的同形字符/兼容性字符）
        # 排除已标记的字符和标准空白字符的变化
        if not anomaly_found and not char.isspace():
            normalized_char = unicodedata.normalize('NFKC', char)
            if char != normalized_char and normalized_char: # 确保结果不是空字符串
                 # 避免将合法的多字符分解（如 'ﬁ' -> 'fi'）标记为简单同形字符
                 # 检查标准化形式是否只是标准ASCII/常见字符
                 is_common_decomposition = len(normalized_char) > 1 and all('a' <= c.lower() <= 'z' or c.isdigit() or c in ' -' for c in normalized_char)

                 if not is_common_decomposition:
                     findings["details"]["normalized_chars"].append({
                         "index": i, "original_char": char, "original_codepoint": codepoint,
                         "normalized_char": normalized_char,
                         "normalized_codepoint": " ".join(f"U+{ord(c):04X}" for c in normalized_char),
                         "description": "NFKC标准化后改变的字符（潜在同形字符或兼容性字符）"
                     })
                 # 即使是常见分解，我们也计数为变化
                 # findings["summary"]["normalized_chars"] += 1 # 在下方计数

    # 2. 检查过多的空白字符序列
    for match in EXCESSIVE_WHITESPACE_REGEX.finditer(original_text):
        findings["details"]["excessive_whitespace_sequences"].append({
            "start_index": match.start(),
            "end_index": match.end(),
            "sequence": repr(match.group(0)),
            "length": len(match.group(0)),
            "description": "连续的多个空白字符"
        })

    # 3. 更新汇总计数
    findings["summary"]["invisible_chars"] = len(findings["details"]["invisible_chars"])
    findings["summary"]["ascii_control_chars"] = len(findings["details"]["ascii_control_chars"])
    findings["summary"]["non_standard_whitespace"] = len(findings["details"]["non_standard_whitespace"])
    findings["summary"]["excessive_whitespace_sequences"] = len(findings["details"]["excessive_whitespace_sequences"])
    findings["summary"]["normalized_chars"] = len(findings["details"]["normalized_chars"])

    findings["summary"]["total_anomalies_found"] = (
        findings["summary"]["invisible_chars"] +
        findings["summary"]["ascii_control_chars"] +
        findings["summary"]["non_standard_whitespace"] +
        findings["summary"]["excessive_whitespace_sequences"] +
        findings["summary"]["normalized_chars"]
    )

    return findings

# --- Cleaning Function ---

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

    cleaned_text = text

    # 1. 特别处理BOM（U+FEFF）：如果不在最开头则移除
    if len(cleaned_text) > 0 and cleaned_text[0] == '\uFEFF':
        bom = cleaned_text[0]
        cleaned_text = cleaned_text[1:]
        has_initial_bom = True
    else:
        bom = ""
        has_initial_bom = False

    # 2. Unicode标准化（NFKC）
    cleaned_text = unicodedata.normalize('NFKC', cleaned_text)

    # 3. 移除特定的不可见和格式化字符（标准化后）
    # 注意：一些字符可能已经在标准化过程中被移除
    cleaned_text = "".join(c for c in cleaned_text if c not in INVISIBLE_CHARS_TO_REMOVE)

    # 4. 移除特定的ASCII控制字符（\t、\n、\r除外）
    cleaned_text = "".join(c for c in cleaned_text if c not in ASCII_CONTROL_CHARS_TO_REMOVE)

    # 5. 标准化空白字符
    # 保留所有换行符（包括单个和连续的），将其他空白字符序列替换为单个标准空格。
    # 首先将所有换行符替换为特殊标记
    LINEBREAK_PLACEHOLDER = '\x00LINEBREAK\x00'
    # 匹配换行符（可能包含回车符）
    linebreak_pattern = re.compile(r'\r?\n')
    cleaned_text = linebreak_pattern.sub(LINEBREAK_PLACEHOLDER, cleaned_text)
    # 标准化其他空白字符
    cleaned_text = WHITESPACE_NORMALIZATION_REGEX.sub(' ', cleaned_text)
    # 恢复换行符
    cleaned_text = cleaned_text.replace(LINEBREAK_PLACEHOLDER, '\n')

    # 6. 去除首尾空白字符（包括替换后的空格）
    cleaned_text = cleaned_text.strip()

    # 7. 如果原本有初始BOM且清理后文本不为空，则重新添加
    if has_initial_bom and cleaned_text:
        cleaned_text = bom + cleaned_text
    elif has_initial_bom and not cleaned_text:
         # 如果清理后内容为空，则不添加BOM
         pass

    return cleaned_text

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