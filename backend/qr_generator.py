import os
import re
import math
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
import segno
import cv2

QR_TEMPLATES = {
    "classic": {
        "name": "经典黑白",
        "dark": "#000000",
        "light": "#ffffff",
        "finder_dark": "#000000",
        "finder_light": "#ffffff",
        "corner_style": "square",
        "dot_style": "square",
    },
    "ocean": {
        "name": "海洋蓝",
        "dark": "#0ea5e9",
        "light": "#f0f9ff",
        "finder_dark": "#0369a1",
        "finder_light": "#f0f9ff",
        "corner_style": "rounded",
        "dot_style": "rounded",
    },
    "sunset": {
        "name": "日落橙",
        "dark": "#f97316",
        "light": "#fff7ed",
        "finder_dark": "#c2410c",
        "finder_light": "#fff7ed",
        "corner_style": "rounded",
        "dot_style": "circle",
    },
    "forest": {
        "name": "森林绿",
        "dark": "#16a34a",
        "light": "#f0fdf4",
        "finder_dark": "#15803d",
        "finder_light": "#f0fdf4",
        "corner_style": "square",
        "dot_style": "rounded",
    },
    "purple": {
        "name": "梦幻紫",
        "dark": "#a855f7",
        "light": "#faf5ff",
        "finder_dark": "#7e22ce",
        "finder_light": "#faf5ff",
        "corner_style": "rounded",
        "dot_style": "circle",
    },
    "neon": {
        "name": "赛博霓虹",
        "dark": "#f472b6",
        "light": "#0f172a",
        "finder_dark": "#38bdf8",
        "finder_light": "#0f172a",
        "corner_style": "square",
        "dot_style": "square",
    },
    "minimal": {
        "name": "极简灰",
        "dark": "#374151",
        "light": "#f9fafb",
        "finder_dark": "#111827",
        "finder_light": "#f9fafb",
        "corner_style": "rounded",
        "dot_style": "rounded",
    },
}

EXPORT_SIZES = {
    "standard": {"name": "标准图", "scale": 10, "margin": 4},
    "hd": {"name": "高精图", "scale": 20, "margin": 4},
    "poster": {"name": "海报图", "scale": 15, "margin": 40},
}

def hex_to_rgb(hex_color):
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def hex_to_rgba(hex_color, alpha=255):
    rgb = hex_to_rgb(hex_color)
    return (*rgb, alpha)

def validate_hex_color(color):
    return bool(re.match(r'^#[0-9A-Fa-f]{6}$', color))

def create_rounded_rect_mask(size, radius):
    mask = Image.new('L', size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([(0, 0), (size[0]-1, size[1]-1)], radius=radius, fill=255)
    return mask

def create_circle_mask(size):
    mask = Image.new('L', size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse([(0, 0), (size[0]-1, size[1]-1)], fill=255)
    return mask

def process_logo(logo_img, size, options=None):
    options = options or {}
    shape = options.get('shape', 'square')
    radius_percent = options.get('radius_percent', 0)
    border_width = options.get('border_width', 0)
    border_color = options.get('border_color', '#ffffff')
    opacity = options.get('opacity', 100)
    padding = options.get('padding', 8)

    logo_size = size - border_width * 2 - padding * 2
    if logo_size < 10:
        logo_size = 10

    logo_img = logo_img.convert("RGBA")
    logo_img = logo_img.resize((logo_size, logo_size), Image.Resampling.LANCZOS)

    if opacity < 100:
        alpha = logo_img.split()[-1]
        alpha = alpha.point(lambda p: int(p * opacity / 100))
        logo_img.putalpha(alpha)

    canvas_size = size
    canvas = Image.new('RGBA', (canvas_size, canvas_size), (0, 0, 0, 0))

    mask_size = logo_size
    if shape == 'circle':
        mask = create_circle_mask((mask_size, mask_size))
    elif shape == 'rounded' or radius_percent > 0:
        radius = int(mask_size * radius_percent / 100)
        if radius < 2:
            radius = 2
        mask = create_rounded_rect_mask((mask_size, mask_size), radius)
    else:
        mask = Image.new('L', (mask_size, mask_size), 255)

    logo_with_mask = Image.new('RGBA', (mask_size, mask_size), (0, 0, 0, 0))
    logo_with_mask.paste(logo_img, (0, 0), mask)

    logo_pos = ((canvas_size - logo_size) // 2, (canvas_size - logo_size) // 2)

    if border_width > 0:
        border_layer = Image.new('RGBA', (canvas_size, canvas_size), (0, 0, 0, 0))
        border_draw = ImageDraw.Draw(border_layer)
        border_rgba = hex_to_rgba(border_color, 255)
        content_size = logo_size + padding * 2
        content_pos = ((canvas_size - content_size) // 2, (canvas_size - content_size) // 2)
        if shape == 'circle':
            border_draw.ellipse(
                [content_pos[0] - border_width, content_pos[1] - border_width,
                 content_pos[0] + content_size + border_width, content_pos[1] + content_size + border_width],
                fill=border_rgba
            )
        elif shape == 'rounded' or radius_percent > 0:
            r = int(content_size * radius_percent / 100) + border_width
            if r < 2:
                r = 2
            border_draw.rounded_rectangle(
                [content_pos[0] - border_width, content_pos[1] - border_width,
                 content_pos[0] + content_size + border_width, content_pos[1] + content_size + border_width],
                radius=r, fill=border_rgba
            )
        else:
            border_draw.rectangle(
                [content_pos[0] - border_width, content_pos[1] - border_width,
                 content_pos[0] + content_size + border_width, content_pos[1] + content_size + border_width],
                fill=border_rgba
            )
        canvas = Image.alpha_composite(canvas, border_layer)
        logo_pos = ((canvas_size - logo_size) // 2, (canvas_size - logo_size) // 2)

    canvas.paste(logo_with_mask, logo_pos, logo_with_mask)
    return canvas

def add_background(qr_img, bg_img, margin=20):
    bg_img = bg_img.convert("RGBA")
    target_w = qr_img.width + margin * 2
    target_h = qr_img.height + margin * 2

    bg_ratio = bg_img.width / bg_img.height
    target_ratio = target_w / target_h

    if bg_ratio > target_ratio:
        new_h = target_h
        new_w = int(new_h * bg_ratio)
    else:
        new_w = target_w
        new_h = int(new_w / bg_ratio)

    bg_img = bg_img.resize((new_w, new_h), Image.Resampling.LANCZOS)

    bg_canvas = Image.new("RGBA", (target_w, target_h), (255, 255, 255, 255))
    bg_x = (target_w - new_w) // 2
    bg_y = (target_h - new_h) // 2
    bg_canvas.paste(bg_img, (bg_x, bg_y), bg_img)

    qr_x = (target_w - qr_img.width) // 2
    qr_y = (target_h - qr_img.height) // 2
    bg_canvas.paste(qr_img, (qr_x, qr_y), qr_img)

    return bg_canvas

def render_qr_with_style(data, template, custom_options=None, scale=10, margin=4):
    custom_options = custom_options or {}

    dark = custom_options.get('dark_color', template.get('dark', '#000000'))
    light = custom_options.get('light_color', template.get('light', '#ffffff'))
    finder_dark = custom_options.get('finder_dark', template.get('finder_dark', dark))
    finder_light = custom_options.get('finder_light', template.get('finder_light', light))
    dot_style = custom_options.get('dot_style', template.get('dot_style', 'square'))
    corner_style = custom_options.get('corner_style', template.get('corner_style', 'square'))

    if not validate_hex_color(dark):
        dark = '#000000'
    if not validate_hex_color(light):
        light = '#ffffff'

    qr = segno.make_qr(data, error='h')

    temp_path = os.path.join(os.path.dirname(__file__), 'static', 'qrcodes', f'temp_render_{os.getpid()}.png')
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)

    qr.save(temp_path, scale=scale, border=margin, dark=dark, light=light)

    img = Image.open(temp_path).convert("RGBA")

    if dot_style != 'square' or corner_style != 'square' or finder_dark != dark:
        img = _style_qr_modules(img, qr, scale, margin, dark, light, finder_dark, finder_light,
                                dot_style, corner_style)

    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except:
        pass

    return img

def _style_qr_modules(img, qr, scale, margin, dark, light, finder_dark, finder_light,
                      dot_style, corner_style):
    modules = qr.matrix
    n = len(modules)

    width, height = img.size
    output = Image.new('RGBA', (width, height), hex_to_rgba(light, 255))
    draw = ImageDraw.Draw(output)

    offset = margin * scale
    module_size = (width - 2 * offset) / n

    finder_size = 7
    finder_positions = [
        (0, 0),
        (0, n - finder_size),
        (n - finder_size, 0),
    ]

    def is_in_finder(row, col):
        for fr, fc in finder_positions:
            if fr <= row < fr + finder_size and fc <= col < fc + finder_size:
                return True, fr, fc
        return False, 0, 0

    def is_finder_pattern(row, col, fr, fc):
        r = row - fr
        c = col - fc
        if r == 0 or r == 6 or c == 0 or c == 6:
            return True
        if 2 <= r <= 4 and 2 <= c <= 4:
            return True
        return False

    for row in range(n):
        for col in range(n):
            if not modules[row][col]:
                continue

            in_finder, fr, fc = is_in_finder(row, col)
            color = finder_dark if in_finder else dark

            x0 = offset + col * module_size
            y0 = offset + row * module_size
            x1 = x0 + module_size
            y1 = y0 + module_size

            if in_finder:
                if corner_style == 'rounded':
                    if is_finder_pattern(row, col, fr, fc):
                        radius = module_size * 0.3
                        draw.rounded_rectangle([x0, y0, x1-0.5, y1-0.5], radius=radius, fill=hex_to_rgba(color, 255))
                    else:
                        draw.rectangle([x0, y0, x1-0.5, y1-0.5], fill=hex_to_rgba(color, 255))
                else:
                    draw.rectangle([x0, y0, x1-0.5, y1-0.5], fill=hex_to_rgba(color, 255))
            else:
                if dot_style == 'circle':
                    pad = module_size * 0.15
                    draw.ellipse([x0 + pad, y0 + pad, x1 - pad, y1 - pad], fill=hex_to_rgba(color, 255))
                elif dot_style == 'rounded':
                    radius = module_size * 0.35
                    draw.rounded_rectangle([x0 + 0.5, y0 + 0.5, x1 - 0.5, y1 - 0.5], radius=radius, fill=hex_to_rgba(color, 255))
                else:
                    draw.rectangle([x0, y0, x1-0.5, y1-0.5], fill=hex_to_rgba(color, 255))

    return output

def generate_qr_full(data, design_config, qr_folder, memory_id):
    template_name = design_config.get('template', 'classic')
    template = QR_TEMPLATES.get(template_name, QR_TEMPLATES['classic'])

    custom_options = {
        'dark_color': design_config.get('dark_color', template['dark']),
        'light_color': design_config.get('light_color', template['light']),
        'finder_dark': design_config.get('finder_dark', template.get('finder_dark', template['dark'])),
        'finder_light': design_config.get('finder_light', template.get('finder_light', template['light'])),
        'dot_style': design_config.get('dot_style', template.get('dot_style', 'square')),
        'corner_style': design_config.get('corner_style', template.get('corner_style', 'square')),
    }

    size_type = design_config.get('size_type', 'standard')
    size_config = EXPORT_SIZES.get(size_type, EXPORT_SIZES['standard'])
    scale = size_config['scale']
    margin = size_config['margin']

    qr_img = render_qr_with_style(data, template, custom_options, scale=scale, margin=margin)

    bg_image_file = design_config.get('_bg_image_file')
    if bg_image_file:
        qr_img = add_background(qr_img, bg_image_file, margin=20)

    logo_image_file = design_config.get('_logo_image_file')
    if logo_image_file:
        logo_options = {
            'shape': design_config.get('logo_shape', 'square'),
            'radius_percent': design_config.get('logo_radius', 0),
            'border_width': design_config.get('logo_border_width', 0),
            'border_color': design_config.get('logo_border_color', '#ffffff'),
            'opacity': design_config.get('logo_opacity', 100),
            'padding': design_config.get('logo_padding', 8),
        }

        logo_size = qr_img.width // 4
        if logo_size < 40:
            logo_size = 40
        if logo_size > qr_img.width // 3:
            logo_size = qr_img.width // 3

        logo_processed = process_logo(logo_image_file, logo_size, logo_options)

        pos = ((qr_img.width - logo_size) // 2, (qr_img.height - logo_size) // 2)

        white_pad_size = logo_size + 10
        white_bg = Image.new('RGBA', (white_pad_size, white_pad_size), (255, 255, 255, 255))
        white_pos = ((qr_img.width - white_pad_size) // 2, (qr_img.height - white_pad_size) // 2)
        qr_img.paste(white_bg, white_pos, white_bg)

        qr_img.paste(logo_processed, pos, logo_processed)

    quality_score = assess_qr_readability(qr_img)

    qr_filename = f"qr_{memory_id}.png"
    qr_path = os.path.join(qr_folder, qr_filename)
    qr_img.save(qr_path, 'PNG')

    return qr_filename, qr_img, quality_score

def assess_qr_readability(qr_img):
    cv_img = cv2.cvtColor(np.array(qr_img.convert('RGB')), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(cv_img)

    score = 0
    details = {}

    if data and len(data) > 0:
        score += 50
        details['decodable'] = True
        details['decoded_data'] = data[:50]
    else:
        details['decodable'] = False

    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    contrast = gray.std()
    contrast_score = min(contrast / 80, 1) * 25
    score += int(contrast_score)
    details['contrast_score'] = int(contrast_score)

    if bbox is not None and len(bbox) > 0:
        score += 15
        details['detected'] = True
        points = bbox[0]
        if len(points) == 4:
            angles = []
            for i in range(4):
                p1 = points[i]
                p2 = points[(i + 1) % 4]
                p3 = points[(i + 2) % 4]
                v1 = p2 - p1
                v2 = p3 - p2
                dot = np.dot(v1, v2)
                norm = np.linalg.norm(v1) * np.linalg.norm(v2)
                if norm > 0:
                    cos_angle = dot / norm
                    cos_angle = max(-1, min(1, cos_angle))
                    angle = abs(np.degrees(np.arccos(cos_angle)) - 90)
                    angles.append(angle)
            if angles:
                avg_deviation = np.mean(angles)
                squareness_score = max(0, 10 - avg_deviation) / 10 * 10
                score += int(squareness_score)
                details['squareness_score'] = int(squareness_score)
    else:
        details['detected'] = False

    score = min(score, 100)

    if score >= 80:
        grade = '优秀'
        recommendation = '二维码质量优秀，各种设备均可轻松识别。'
    elif score >= 60:
        grade = '良好'
        recommendation = '二维码质量良好，大多数设备可以识别。'
    elif score >= 40:
        grade = '一般'
        recommendation = '二维码识别可能存在困难，建议提高对比度或减少装饰元素。'
    else:
        grade = '较差'
        recommendation = '二维码可读性较差，建议使用更高对比度配色、减少Logo遮挡。'

    return {
        'score': score,
        'grade': grade,
        'recommendation': recommendation,
        'details': details,
    }

def generate_export_variants(qr_img, qr_folder, memory_id, base_filename):
    variants = {}

    standard_size = 512
    hd_size = 1024
    poster_size = 1080

    standard_img = qr_img.copy()
    if standard_img.width != standard_size:
        ratio = standard_size / standard_img.width
        new_size = (int(standard_img.width * ratio), int(standard_img.height * ratio))
        standard_img = standard_img.resize(new_size, Image.Resampling.LANCZOS)
    standard_filename = f"qr_{memory_id}_standard.png"
    standard_path = os.path.join(qr_folder, standard_filename)
    standard_img.save(standard_path, 'PNG')
    variants['standard'] = {
        'name': '标准图',
        'filename': standard_filename,
        'size': f"{standard_img.width}x{standard_img.height}",
        'url': f'/static/qrcodes/{standard_filename}',
    }

    hd_img = qr_img.copy()
    if hd_img.width < hd_size:
        ratio = hd_size / hd_img.width
        new_size = (int(hd_img.width * ratio), int(hd_img.height * ratio))
        hd_img = hd_img.resize(new_size, Image.Resampling.LANCZOS)
    hd_filename = f"qr_{memory_id}_hd.png"
    hd_path = os.path.join(qr_folder, hd_filename)
    hd_img.save(hd_path, 'PNG')
    variants['hd'] = {
        'name': '高精图',
        'filename': hd_filename,
        'size': f"{hd_img.width}x{hd_img.height}",
        'url': f'/static/qrcodes/{hd_filename}',
    }

    poster_img = create_poster_image(qr_img, poster_size)
    poster_filename = f"qr_{memory_id}_poster.png"
    poster_path = os.path.join(qr_folder, poster_filename)
    poster_img.save(poster_path, 'PNG')
    variants['poster'] = {
        'name': '海报图',
        'filename': poster_filename,
        'size': f"{poster_img.width}x{poster_img.height}",
        'url': f'/static/qrcodes/{poster_filename}',
    }

    return variants

def create_poster_image(qr_img, target_height=1080):
    width = int(target_height * 3 / 4)
    poster = Image.new('RGB', (width, target_height), '#f8fafc')
    draw = ImageDraw.Draw(poster)

    header_h = int(target_height * 0.15)
    footer_h = int(target_height * 0.1)

    draw.rectangle([0, 0, width, header_h], fill='#0f172a')
    draw.rectangle([0, target_height - footer_h, width, target_height], fill='#0f172a')

    qr_max_size = min(width - 80, target_height - header_h - footer_h - 80)
    qr_size = qr_img.width
    if qr_size > qr_max_size:
        ratio = qr_max_size / qr_size
        new_size = (int(qr_size * ratio), int(qr_size * ratio))
        qr_resized = qr_img.resize(new_size, Image.Resampling.LANCZOS)
    else:
        qr_resized = qr_img.copy()

    qr_x = (width - qr_resized.width) // 2
    qr_y = header_h + (target_height - header_h - footer_h - qr_resized.height) // 2
    poster.paste(qr_resized, (qr_x, qr_y), qr_resized)

    return poster
