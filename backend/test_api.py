import requests
import json

BASE_URL = 'http://127.0.0.1:5000'
s = requests.Session()

print('=== 1. 测试模板 API ===')
r = s.get(f'{BASE_URL}/api/qr/templates')
print(f'Status: {r.status_code}')
data = r.json()
print(f'Templates count: {len(data["templates"])}')
for t in data['templates']:
    print(f'  - {t["id"]}: {t["name"]} ({t["dark"]} on {t["light"]})')
print()

print('=== 2. 测试导出尺寸 API ===')
r = s.get(f'{BASE_URL}/api/qr/export-sizes')
print(f'Status: {r.status_code}')
data = r.json()
print(f'Sizes count: {len(data["sizes"])}')
for sz in data['sizes']:
    print(f'  - {sz["id"]}: {sz["name"]} (scale={sz["scale"]})')
print()

print('=== 3. 登录 ===')
r = s.post(f'{BASE_URL}/api/auth/login', json={'username': 'admin', 'password': 'password'})
print(f'Status: {r.status_code}')
print(f'Response: {r.json()}')
print()

print('=== 4. 创建记忆 ===')
r = s.post(f'{BASE_URL}/api/memories', data={
    'title': '测试记忆二维码',
    'text': '这是测试内容，用于验证二维码设计功能。',
    'status': 'active'
})
print(f'Status: {r.status_code}')
mem_data = r.json()
print(f'Memory ID: {mem_data.get("id")}')
memory_id = mem_data['id']
print()

print('=== 5. 设计二维码 (Ocean 模板) ===')
r = s.post(f'{BASE_URL}/api/memories/{memory_id}/design', data={
    'template': 'ocean',
    'dark_color': '#0ea5e9',
    'light_color': '#f0f9ff',
    'finder_dark': '#0369a1',
    'finder_light': '#f0f9ff',
    'dot_style': 'rounded',
    'corner_style': 'rounded',
    'size_type': 'standard',
    'logo_shape': 'circle',
    'logo_radius': '50',
    'logo_border_width': '3',
    'logo_border_color': '#ffffff',
    'logo_opacity': '100',
    'logo_padding': '8',
})
print(f'Status: {r.status_code}')
result = r.json()
print(f'Success: {result.get("success")}')
if result.get('success'):
    print(f'QR URL: {result["qr_url"]}')
    print(f'Quality score: {result["quality_score"]["score"]} ({result["quality_score"]["grade"]})')
    print(f'Recommendation: {result["quality_score"]["recommendation"]}')
    print(f'Design config keys: {list(result["design_config"].keys())}')
else:
    print(f'Error: {result.get("message") or result.get("error")}')
print()

print('=== 6. 测试导出变体 ===')
r = s.get(f'{BASE_URL}/api/memories/{memory_id}/export')
print(f'Status: {r.status_code}')
export_data = r.json()
if export_data.get('success'):
    print(f'Variants: {list(export_data["variants"].keys())}')
    for key, v in export_data['variants'].items():
        print(f'  - {v["name"]}: {v["size"]} -> {v["url"]}')
else:
    print(f'Error: {export_data}')
print()

print('=== 7. 获取记忆详情 (验证设计配置保存) ===')
r = s.get(f'{BASE_URL}/api/memories/{memory_id}')
print(f'Status: {r.status_code}')
mem_detail = r.json()
print(f'QR URL: {mem_detail.get("qr_url")}')
print(f'Quality score: {mem_detail.get("qr_quality_score")}')
print(f'Design config saved: {len(mem_detail.get("design_config", {})) > 0}')
if mem_detail.get('design_config'):
    print(f'  template: {mem_detail["design_config"].get("template")}')
    print(f'  dot_style: {mem_detail["design_config"].get("dot_style")}')
print()

print('=== 8. 测试其他模板 (sunset, neon) ===')
for tpl in ['sunset', 'neon']:
    r = s.post(f'{BASE_URL}/api/memories/{memory_id}/design', data={
        'template': tpl,
        'size_type': 'hd',
    })
    result = r.json()
    if result.get('success'):
        print(f'{tpl}: score={result["quality_score"]["score"]}, grade={result["quality_score"]["grade"]}')
    else:
        print(f'{tpl}: FAILED - {result.get("message")}')
print()

print('=== 9. 测试 BASE_URL 配置 ===')
print(f'Memory full_view_url: {mem_detail.get("full_view_url")}')
print()

print('=== ALL TESTS COMPLETED ===')
