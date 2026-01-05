"""
Token 认证中间件

提供 API 路由的 Token 认证功能：
- before_request hook 自动验证 /api/* 路由
- 白名单机制排除特定路由
- 支持 Authorization: Bearer <token> 和 X-Access-Token header
"""

import logging
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

# 不需要认证的路由白名单
AUTH_WHITELIST = [
    '/api/health',
    '/api/auth/validate',
    '/api/images/',  # 图片路由保持公开（<img> 标签无法携带 Authorization header）
    '/api/history/',  # 历史记录下载路由（浏览器直接打开无法携带 header）
]


def _extract_token() -> str | None:
    """从请求中提取 Token"""
    # 优先从 Authorization header 提取
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]

    # 备选：从 X-Access-Token header 提取
    return request.headers.get('X-Access-Token')


def _is_whitelisted(path: str) -> bool:
    """检查路径是否在白名单中"""
    for whitelist_path in AUTH_WHITELIST:
        if path.startswith(whitelist_path):
            return True
    return False


def setup_token_auth(app):
    """
    设置 Token 认证中间件

    在 Flask app 上注册 before_request hook，
    自动验证所有 /api/* 路由（白名单除外）
    """
    from backend.services.user import get_user_service

    @app.before_request
    def check_token_auth():
        # 只处理 /api/* 路由
        if not request.path.startswith('/api/'):
            return None

        # 跳过 OPTIONS 请求（CORS 预检）
        if request.method == 'OPTIONS':
            return None

        # 跳过白名单路由
        if _is_whitelisted(request.path):
            return None

        # 提取并验证 Token
        token = _extract_token()
        if not token:
            logger.warning(f"未授权访问: {request.path} - 缺少 Token")
            return jsonify({
                'success': False,
                'error': '未授权访问，请提供有效的访问令牌'
            }), 401

        user_service = get_user_service()
        user = user_service.validate_token(token)

        if not user:
            logger.warning(f"未授权访问: {request.path} - Token 无效")
            return jsonify({
                'success': False,
                'error': '访问令牌无效或已禁用'
            }), 401

        # 将用户信息存储到 g 对象，供后续处理使用
        g.current_user = user
        return None

    logger.info("Token 认证中间件已启用")


def token_required(f):
    """
    Token 认证装饰器（用于需要额外认证的路由）

    用法：
    @app.route('/api/some-route')
    @token_required
    def some_route():
        user = g.current_user
        ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from backend.services.user import get_user_service

        token = _extract_token()
        if not token:
            return jsonify({
                'success': False,
                'error': '未授权访问，请提供有效的访问令牌'
            }), 401

        user_service = get_user_service()
        user = user_service.validate_token(token)

        if not user:
            return jsonify({
                'success': False,
                'error': '访问令牌无效或已禁用'
            }), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated
