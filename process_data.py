import pandas as pd
import os
import re
from urllib.parse import urlparse

# ==================== 配置项（不用改，自动适配你的路径）====================
# 存放CSV的文件夹路径
ARCHIVE_FOLDER = "./archive"
# 输出到项目的钓鱼情报文件夹
OUTPUT_FOLDER = "./sample_data/phishingti"
# 输出的最终域名文件名
OUTPUT_FILE = "email_phishing_domains.txt"
# URL提取正则（匹配http/https开头的链接）
URL_REGEX = r'https?://[^\s<>"\']+'
# 邮件内容列名（常见的列名，脚本会自动匹配）
CONTENT_COLUMNS = ["body", "content", "text", "message", "email_text", "email_body"]
# 钓鱼/恶意标签列名（常见的列名）
LABEL_COLUMNS = ["label", "is_phishing", "is_spam", "phish", "spam", "malicious"]
# 恶意标签的取值（只提取标签为恶意的邮件里的URL）
MALICIOUS_LABEL_VALUES = [1, "1", "phishing", "spam", "malicious", "yes", "true"]

def extract_domains_from_email_csv():
    # 自动创建输出文件夹
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
    
    all_domains = set()  # 用set自动去重
    csv_files = [f for f in os.listdir(ARCHIVE_FOLDER) if f.lower().endswith(".csv")]

    if not csv_files:
        print(f"❌ 在 {ARCHIVE_FOLDER} 文件夹里没找到CSV文件，请检查路径")
        return

    print(f"✅ 找到 {len(csv_files)} 个CSV文件，开始处理...\n")

    # 遍历每个CSV文件
    for csv_file in csv_files:
        csv_path = os.path.join(ARCHIVE_FOLDER, csv_file)
        print(f"正在处理: {csv_file}")

        try:
            # 读取CSV（兼容不同编码）
            df = pd.read_csv(csv_path, encoding_errors="ignore", low_memory=False)
            df.columns = df.columns.str.strip().str.lower()  # 列名转小写，避免大小写问题
        except Exception as e:
            print(f"⚠️  读取 {csv_file} 失败: {str(e)}，跳过\n")
            continue

        # 自动匹配邮件内容列
        content_col = None
        for col in CONTENT_COLUMNS:
            if col.lower() in df.columns:
                content_col = col.lower()
                break
        if not content_col:
            print(f"⚠️  在 {csv_file} 里没找到邮件内容列，可用列名: {df.columns.tolist()}\n")
            continue

        # 自动匹配标签列（可选，没有就全量提取）
        label_col = None
        for col in LABEL_COLUMNS:
            if col.lower() in df.columns:
                label_col = col.lower()
                break

        # 遍历每一行邮件，提取URL
        extracted_count = 0
        for idx, row in df.iterrows():
            # 只处理恶意邮件（如果有标签列）
            if label_col:
                label_val = str(row[label_col]).strip().lower()
                if label_val not in [str(v).lower() for v in MALICIOUS_LABEL_VALUES]:
                    continue

            email_content = str(row[content_col])
            # 提取所有URL
            urls = re.findall(URL_REGEX, email_content)

            for url in urls:
                try:
                    # 从URL里提取纯域名
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    # 清洗域名：去掉端口号、转小写、去掉www.前缀
                    domain = domain.split(":")[0].lower().lstrip("www.")
                    # 过滤无效域名
                    if len(domain) > 5 and "." in domain and not domain.endswith((".local", ".internal")):
                        all_domains.add(domain)
                        extracted_count += 1
                except:
                    continue

        print(f"✅ {csv_file} 处理完成，本次提取 {extracted_count} 个域名\n")

    # 保存最终结果
    output_path = os.path.join(OUTPUT_FOLDER, OUTPUT_FILE)
    with open(output_path, "w", encoding="utf-8") as f:
        for domain in sorted(all_domains):
            f.write(domain + "\n")

    print("="*50)
    print(f"🎉 全部处理完成！")
    print(f"✅ 总共提取到 {len(all_domains)} 个不重复的钓鱼域名")
    print(f"✅ 结果已保存到: {output_path}")
    print("="*50)

if __name__ == "__main__":
    extract_domains_from_email_csv()