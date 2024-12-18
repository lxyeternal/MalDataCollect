from google.cloud import storage
from google.oauth2 import service_account
from collections import defaultdict
import os


def count_folders(bucket_name, prefixes, key_path):
    """
    统计存储桶中特定前缀下的文件夹数量
    """
    try:
        # 转换为规范化的路径
        absolute_key_path = os.path.abspath(key_path)

        # 检查密钥文件是否存在
        if not os.path.exists(absolute_key_path):
            raise FileNotFoundError(f"Service account key file not found at: {absolute_key_path}")

        # 使用服务账户密钥进行认证
        credentials = service_account.Credentials.from_service_account_file(absolute_key_path)
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
        print(f"Failed to count folders: {str(e)}")
        return {}


if __name__ == "__main__":
    # 使用相对路径，通过 os.path.join 构建路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    key_path = os.path.join(parent_dir, 'configs', 'metatrust-01-a8043294c5af.json')

    # 替换为你的存储桶名称
    bucket_name = "scantist-malicious"

    # 定义需要统计的文件夹前缀
    prefixes = ['npm/', 'pypi/']

    # 打印路径信息以便调试
    print(f"Looking for key file at: {key_path}")

    # 统计文件夹数量
    folder_counts = count_folders(bucket_name, prefixes, key_path)

    # 打印结果
    if folder_counts:
        for prefix, count in folder_counts.items():
            print(f"Folder count under '{prefix}': {count}")
    else:
        print("No folders were counted. Please check the error messages above.")