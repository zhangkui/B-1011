import requests
import io
from PIL import Image
import os
import tempfile

BASE_URL = "http://127.0.0.1:5000"
TEST_USER = "admin"
TEST_PASS = "password"
MEMORY_ID = "c84dfa3d-7a4f-4fc2-b5a0-4fa27abc7ff0"

session = requests.Session()

def login():
    print("1. 登录...")
    res = session.post(f"{BASE_URL}/api/auth/login", json={
        "username": TEST_USER,
        "password": TEST_PASS
    })
    data = res.json()
    print(f"   登录结果: {data}")
    assert data['success'], "登录失败"
    print("   [OK] 登录成功")
    return True

def get_memory_info():
    print("\n2. 获取记忆信息...")
    res = session.get(f"{BASE_URL}/api/memories/{MEMORY_ID}")
    data = res.json()
    print(f"   logo_url: {data.get('logo_url')}")
    print(f"   bg_url: {data.get('bg_url')}")
    print(f"   has_logo in config: {data.get('design_config', {}).get('has_logo')}")
    print(f"   has_bg_image in config: {data.get('design_config', {}).get('has_bg_image')}")
    return data

def create_test_image_file(color, size=(100, 100), suffix=".png"):
    img = Image.new('RGBA', size, color)
    tmp_file = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    img.save(tmp_file.name, format='PNG')
    tmp_file.close()
    return tmp_file.name

def test_upload_images():
    print("\n3. 上传 Logo 和背景图片并生成二维码...")
    
    logo_file = create_test_image_file((255, 0, 0, 255), (100, 100), "_logo.png")
    bg_file = create_test_image_file((200, 200, 255, 255), (512, 512), "_bg.png")
    
    try:
        form_data = {
            'template': 'classic',
            'logo_shape': 'circle',
            'logo_radius': '30',
            'logo_border_width': '3',
            'logo_border_color': '#ffffff',
            'logo_opacity': '100',
            'logo_padding': '10',
        }
        
        with open(logo_file, 'rb') as lf, open(bg_file, 'rb') as bf:
            files = {
                'logo_image': ('logo_test.png', lf, 'image/png'),
                'bg_image': ('bg_test.png', bf, 'image/png'),
            }
            
            res = session.post(
                f"{BASE_URL}/api/memories/{MEMORY_ID}/design",
                data=form_data,
                files=files
            )
        data = res.json()
        print(f"   成功: {data.get('success')}")
        if not data.get('success'):
            print(f"   错误: {data.get('message')} {data.get('error')}")
        print(f"   logo_url: {data.get('logo_url')}")
        print(f"   bg_url: {data.get('bg_url')}")
        print(f"   has_logo: {data.get('design_config', {}).get('has_logo')}")
        print(f"   has_bg_image: {data.get('design_config', {}).get('has_bg_image')}")
        print(f"   quality_score: {data.get('quality_score', {}).get('score')}")
        
        assert data['success'], "生成失败"
        assert data['logo_url'], "未返回 logo_url"
        assert data['bg_url'], "未返回 bg_url"
        assert data['design_config']['has_logo'] == True, "has_logo 应为 True"
        assert data['design_config']['has_bg_image'] == True, "has_bg_image 应为 True"
        print("   [OK] 上传图片成功")
        return data
    finally:
        os.unlink(logo_file)
        os.unlink(bg_file)

def test_reload_without_new_images():
    print("\n4. 重新生成二维码（不上传新图片，验证图片持久化）...")
    
    form_data = {
        'template': 'ocean',
        'logo_shape': 'circle',
        'logo_radius': '30',
        'logo_border_width': '3',
        'logo_border_color': '#ffffff',
        'logo_opacity': '100',
        'logo_padding': '10',
    }
    
    res = session.post(
        f"{BASE_URL}/api/memories/{MEMORY_ID}/design",
        data=form_data
    )
    data = res.json()
    print(f"   成功: {data.get('success')}")
    if not data.get('success'):
        print(f"   错误: {data.get('message')} {data.get('error')}")
    print(f"   logo_url: {data.get('logo_url')}")
    print(f"   bg_url: {data.get('bg_url')}")
    print(f"   has_logo: {data.get('design_config', {}).get('has_logo')}")
    print(f"   has_bg_image: {data.get('design_config', {}).get('has_bg_image')}")
    print(f"   quality_score: {data.get('quality_score', {}).get('score')}")
    
    assert data['success'], "生成失败"
    assert data['logo_url'], "未返回 logo_url（图片应该已持久化）"
    assert data['bg_url'], "未返回 bg_url（图片应该已持久化）"
    assert data['design_config']['has_logo'] == True, "has_logo 应为 True（图片已持久化）"
    assert data['design_config']['has_bg_image'] == True, "has_bg_image 应为 True（图片已持久化）"
    print("   [OK] 图片持久化成功！重新生成时自动加载了之前的 Logo 和背景图")
    return data

def test_verify_image_files_exist():
    print("\n5. 验证图片文件是否存在于文件系统...")
    
    qr_folder = os.path.join(os.path.dirname(__file__), 'static', 'qrcodes')
    logo_file = os.path.join(qr_folder, f"logo_{MEMORY_ID}.png")
    bg_file = os.path.join(qr_folder, f"bg_{MEMORY_ID}.png")
    
    print(f"   Logo 文件: {logo_file}")
    print(f"   存在: {os.path.exists(logo_file)}")
    print(f"   背景图文件: {bg_file}")
    print(f"   存在: {os.path.exists(bg_file)}")
    
    assert os.path.exists(logo_file), "Logo 文件不存在"
    assert os.path.exists(bg_file), "背景图文件不存在"
    print("   [OK] 图片文件已正确保存到文件系统")

def test_reload_page():
    print("\n6. 模拟页面重新加载，验证数据恢复...")
    data = get_memory_info()
    assert data.get('logo_url'), "重新加载时未返回 logo_url"
    assert data.get('bg_url'), "重新加载时未返回 bg_url"
    assert data.get('design_config', {}).get('has_logo') == True, "重新加载时 has_logo 应为 True"
    assert data.get('design_config', {}).get('has_bg_image') == True, "重新加载时 has_bg_image 应为 True"
    print("   [OK] 页面重新加载时正确恢复了 Logo 和背景图信息")

if __name__ == "__main__":
    print("=" * 60)
    print("测试二维码 LOGO 和背景图片持久化功能")
    print("=" * 60)
    
    try:
        login()
        get_memory_info()
        test_upload_images()
        test_reload_without_new_images()
        test_verify_image_files_exist()
        test_reload_page()
        
        print("\n" + "=" * 60)
        print("[OK] 所有测试通过！图片持久化功能正常工作")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

