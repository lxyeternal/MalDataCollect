from google.cloud import storage
from google.oauth2 import service_account
from collections import defaultdict

def count_folders(bucket_name, prefixes, key_path):
    """
    统计存储桶中特定前缀下的文件夹数量
    """
    try:
        # 使用服务账户密钥进行认证
        credentials = service_account.Credentials.from_service_account_file(key_path)
        storage_client = storage.Client(credentials=credentials)
        bucket = storage_client.bucket(bucket_name)

        folder_counts = defaultdict(int)

        for prefix in prefixes:
            blobs = bucket.list_blobs(prefix=prefix, delimiter='/')

            # 遍历获取子文件夹
            for page in blobs.pages:
                for folder in page.prefixes:
                    folder_counts[prefix] += 1
                    print(f"Found folder: {folder}")

        return folder_counts

    except Exception as e:
        print(f"Failed to count folders: {e}")
        return {}

if __name__ == "__main__":
    # 设置服务账户 JSON 文件路径
    key_path = '../configs/metatrust-01-a8043294c5af.json'

    # 替换为你的存储桶名称
    bucket_name = "scantist-malicious"

    # 定义需要统计的文件夹前缀
    prefixes = ['npm/', 'pypi/']

    # 统计文件夹数量
    folder_counts = count_folders(bucket_name, prefixes, key_path)

    # 打印结果
    for prefix, count in folder_counts.items():
        print(f"Folder count under '{prefix}': {count}")
