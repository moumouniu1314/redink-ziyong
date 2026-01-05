"""
管理面板路由

提供管理面板的所有路由：
- 登录/登出
- 仪表盘
- 用户管理
- API 配置管理
- 密码修改
"""

import logging
from pathlib import Path
from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash, jsonify
import yaml

from . import admin_bp
from backend.services.user import get_user_service

logger = logging.getLogger(__name__)

# 配置文件路径
CONFIG_DIR = Path(__file__).parent.parent.parent
IMAGE_CONFIG_PATH = CONFIG_DIR / 'image_providers.yaml'
TEXT_CONFIG_PATH = CONFIG_DIR / 'text_providers.yaml'


def admin_required(f):
    """管理员登录验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated


# ==================== 登录/登出 ====================

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """管理员登录页面"""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin.dashboard'))

    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        user_service = get_user_service()

        if user_service.verify_admin_password(password):
            session['admin_logged_in'] = True
            session.permanent = True
            logger.info("管理员登录成功")
            return redirect(url_for('admin.dashboard'))
        else:
            error = '密码错误'
            logger.warning("管理员登录失败：密码错误")

    return render_template('login.html', error=error)


@admin_bp.route('/logout')
def logout():
    """管理员登出"""
    session.pop('admin_logged_in', None)
    logger.info("管理员已登出")
    return redirect(url_for('admin.login'))


# ==================== 仪表盘 ====================

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """管理面板仪表盘"""
    user_service = get_user_service()
    users = user_service.get_all_users()
    return render_template('dashboard.html', users=users, user_count=len(users))


# ==================== 用户管理 ====================

@admin_bp.route('/users')
@admin_required
def users():
    """用户列表页面"""
    user_service = get_user_service()
    users = user_service.get_all_users()
    return render_template('users.html', users=users)


@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """添加新用户"""
    username = request.form.get('username', '').strip()
    if not username:
        flash('用户名不能为空', 'error')
        return redirect(url_for('admin.users'))

    user_service = get_user_service()
    try:
        new_user = user_service.create_user(username)
        flash(f'用户 "{username}" 创建成功', 'success')
        # 返回新用户的 Token（仅显示一次）
        flash(f'访问令牌: {new_user["access_token"]}', 'token')
    except ValueError as e:
        flash(str(e), 'error')

    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    """切换用户启用/禁用状态"""
    user_service = get_user_service()
    result = user_service.toggle_user(user_id)

    if result is not None:
        status = "启用" if result else "禁用"
        flash(f'用户已{status}', 'success')
    else:
        flash('用户不存在', 'error')

    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<user_id>/regenerate', methods=['POST'])
@admin_required
def regenerate_token(user_id):
    """重新生成用户 Token"""
    user_service = get_user_service()
    new_token = user_service.regenerate_token(user_id)

    if new_token:
        flash('Token 已重新生成', 'success')
        flash(f'新访问令牌: {new_token}', 'token')
    else:
        flash('用户不存在', 'error')

    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """删除用户"""
    user_service = get_user_service()
    if user_service.delete_user(user_id):
        flash('用户已删除', 'success')
    else:
        flash('用户不存在', 'error')

    return redirect(url_for('admin.users'))


# ==================== 密码修改 ====================

@admin_bp.route('/password', methods=['GET', 'POST'])
@admin_required
def change_password():
    """修改管理员密码"""
    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not all([old_password, new_password, confirm_password]):
            flash('所有字段都必须填写', 'error')
        elif new_password != confirm_password:
            flash('两次输入的新密码不一致', 'error')
        elif len(new_password) < 6:
            flash('新密码长度至少为 6 位', 'error')
        else:
            user_service = get_user_service()
            if user_service.change_admin_password(old_password, new_password):
                flash('密码修改成功', 'success')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('原密码错误', 'error')

    return render_template('password.html')


# ==================== API 端点（供 AJAX 调用） ====================

@admin_bp.route('/api/users/<user_id>/token', methods=['GET'])
@admin_required
def get_user_token(user_id):
    """获取用户 Token（API）"""
    user_service = get_user_service()
    user = user_service.get_user_by_id(user_id)

    if user:
        return jsonify({
            'success': True,
            'token': user.get('access_token', '')
        })
    return jsonify({'success': False, 'error': '用户不存在'}), 404


# ==================== API 配置管理 ====================

def _read_config(path: Path, default: dict) -> dict:
    """读取配置文件"""
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or default
    return default


def _write_config(path: Path, config: dict):
    """写入配置文件"""
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)


def _clear_config_cache():
    """清除配置缓存"""
    try:
        from backend.config import Config
        Config._image_providers_config = None
        Config._text_providers_config = None
    except Exception:
        pass
    # 重置图片服务实例，使新配置生效
    try:
        from backend.services.image import reset_image_service
        reset_image_service()
    except Exception:
        pass


@admin_bp.route('/config')
@admin_required
def config():
    """API 配置页面"""
    text_config = _read_config(TEXT_CONFIG_PATH, {
        'active_provider': '',
        'providers': {}
    })
    image_config = _read_config(IMAGE_CONFIG_PATH, {
        'active_provider': '',
        'providers': {}
    })
    return render_template('config.html', text_config=text_config, image_config=image_config)


def _parse_form_providers(form_data):
    """解析表单中的 providers 数据"""
    providers = {}
    for key, value in form_data.items():
        if key.startswith('providers['):
            # 解析 providers[name][field] 格式
            parts = key.replace('providers[', '').replace(']', '[').split('[')
            name = parts[0]
            field = parts[1] if len(parts) > 1 else None
            if name and field:
                if name not in providers:
                    providers[name] = {}
                providers[name][field] = value
    return providers


@admin_bp.route('/config/text', methods=['POST'])
@admin_required
def save_text_config():
    """保存文本生成配置"""
    try:
        existing_config = _read_config(TEXT_CONFIG_PATH, {'providers': {}})
        existing_providers = existing_config.get('providers', {})

        active_provider = request.form.get('active_provider', '')
        provider_names = request.form.getlist('provider_names')

        new_providers = {}
        for name in provider_names:
            new_providers[name] = {
                'type': request.form.get(f'type_{name}', ''),
                'model': request.form.get(f'model_{name}', ''),
                'api_key': request.form.get(f'api_key_{name}', ''),
                'base_url': request.form.get(f'base_url_{name}', '')
            }
            # API Key 为空时保留原有
            if not new_providers[name]['api_key'] and name in existing_providers:
                new_providers[name]['api_key'] = existing_providers[name].get('api_key', '')
            # 移除空的 base_url
            if not new_providers[name]['base_url']:
                del new_providers[name]['base_url']

        config = {
            'active_provider': active_provider,
            'providers': new_providers
        }
        _write_config(TEXT_CONFIG_PATH, config)
        _clear_config_cache()
        flash('文本配置已保存', 'success')
    except Exception as e:
        flash(f'保存失败: {str(e)}', 'error')

    return redirect(url_for('admin.config'))


@admin_bp.route('/config/image', methods=['POST'])
@admin_required
def save_image_config():
    """保存图片生成配置"""
    try:
        existing_config = _read_config(IMAGE_CONFIG_PATH, {'providers': {}})
        existing_providers = existing_config.get('providers', {})

        active_provider = request.form.get('active_provider', '')
        provider_names = request.form.getlist('provider_names')

        new_providers = {}
        for name in provider_names:
            new_providers[name] = {
                'type': request.form.get(f'type_{name}', ''),
                'model': request.form.get(f'model_{name}', ''),
                'api_key': request.form.get(f'api_key_{name}', ''),
                'base_url': request.form.get(f'base_url_{name}', ''),
                'endpoint_type': request.form.get(f'endpoint_type_{name}', ''),
                'high_concurrency': f'high_concurrency_{name}' in request.form
            }
            # API Key 为空时保留原有
            if not new_providers[name]['api_key'] and name in existing_providers:
                new_providers[name]['api_key'] = existing_providers[name].get('api_key', '')
            # 移除空的 base_url
            if not new_providers[name]['base_url']:
                del new_providers[name]['base_url']
            # endpoint_type 保留空字符串（表示不添加路径后缀）

        config = {
            'active_provider': active_provider,
            'providers': new_providers
        }
        _write_config(IMAGE_CONFIG_PATH, config)
        _clear_config_cache()
        flash('图片配置已保存', 'success')
    except Exception as e:
        flash(f'保存失败: {str(e)}', 'error')

    return redirect(url_for('admin.config'))


# ==================== 添加/删除服务商 ====================

@admin_bp.route('/config/text/add', methods=['POST'])
@admin_required
def add_text_provider():
    """添加文本服务商"""
    try:
        name = request.form.get('name', '').strip()
        if not name:
            flash('服务商名称不能为空', 'error')
            return redirect(url_for('admin.config'))

        config = _read_config(TEXT_CONFIG_PATH, {'active_provider': '', 'providers': {}})
        if name in config.get('providers', {}):
            flash(f'服务商 "{name}" 已存在', 'error')
            return redirect(url_for('admin.config'))

        provider = {
            'type': request.form.get('type', 'google_gemini'),
            'model': request.form.get('model', ''),
            'api_key': request.form.get('api_key', '')
        }
        base_url = request.form.get('base_url', '').strip()
        if base_url:
            provider['base_url'] = base_url

        if 'providers' not in config:
            config['providers'] = {}
        config['providers'][name] = provider

        # 如果是第一个服务商，自动激活
        if not config.get('active_provider'):
            config['active_provider'] = name

        _write_config(TEXT_CONFIG_PATH, config)
        _clear_config_cache()
        flash(f'服务商 "{name}" 添加成功', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'error')

    return redirect(url_for('admin.config'))


@admin_bp.route('/config/text/delete/<name>')
@admin_required
def delete_text_provider(name):
    """删除文本服务商"""
    try:
        config = _read_config(TEXT_CONFIG_PATH, {'providers': {}})
        if name in config.get('providers', {}):
            del config['providers'][name]
            # 如果删除的是激活的服务商，切换到第一个
            if config.get('active_provider') == name:
                config['active_provider'] = next(iter(config['providers'].keys()), '')
            _write_config(TEXT_CONFIG_PATH, config)
            _clear_config_cache()
            flash(f'服务商 "{name}" 已删除', 'success')
        else:
            flash(f'服务商 "{name}" 不存在', 'error')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'error')

    return redirect(url_for('admin.config'))


@admin_bp.route('/config/image/add', methods=['POST'])
@admin_required
def add_image_provider():
    """添加图片服务商"""
    try:
        name = request.form.get('name', '').strip()
        if not name:
            flash('服务商名称不能为空', 'error')
            return redirect(url_for('admin.config'))

        config = _read_config(IMAGE_CONFIG_PATH, {'active_provider': '', 'providers': {}})
        if name in config.get('providers', {}):
            flash(f'服务商 "{name}" 已存在', 'error')
            return redirect(url_for('admin.config'))

        provider = {
            'type': request.form.get('type', 'google_genai'),
            'model': request.form.get('model', ''),
            'api_key': request.form.get('api_key', ''),
            'high_concurrency': 'high_concurrency' in request.form
        }
        base_url = request.form.get('base_url', '').strip()
        if base_url:
            provider['base_url'] = base_url
        endpoint_type = request.form.get('endpoint_type', '').strip()
        if endpoint_type:
            provider['endpoint_type'] = endpoint_type

        if 'providers' not in config:
            config['providers'] = {}
        config['providers'][name] = provider

        # 如果是第一个服务商，自动激活
        if not config.get('active_provider'):
            config['active_provider'] = name

        _write_config(IMAGE_CONFIG_PATH, config)
        _clear_config_cache()
        flash(f'服务商 "{name}" 添加成功', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'error')

    return redirect(url_for('admin.config'))


@admin_bp.route('/config/image/delete/<name>')
@admin_required
def delete_image_provider(name):
    """删除图片服务商"""
    try:
        config = _read_config(IMAGE_CONFIG_PATH, {'providers': {}})
        if name in config.get('providers', {}):
            del config['providers'][name]
            # 如果删除的是激活的服务商，切换到第一个
            if config.get('active_provider') == name:
                config['active_provider'] = next(iter(config['providers'].keys()), '')
            _write_config(IMAGE_CONFIG_PATH, config)
            _clear_config_cache()
            flash(f'服务商 "{name}" 已删除', 'success')
        else:
            flash(f'服务商 "{name}" 不存在', 'error')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'error')

    return redirect(url_for('admin.config'))
