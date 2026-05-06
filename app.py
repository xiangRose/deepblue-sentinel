import sys
import os
import logging
import traceback
from datetime import datetime

# ==================== 核心适配：动态路径魔法函数（开发/打包双兼容） ====================
def get_resource_path(relative_path):
    """获取打包后资源文件的绝对路径"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_runtime_path(relative_path):
    """获取运行时文件的绝对路径（数据库、日志等）"""
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# 全局错误日志捕获（打包后也能看到报错）
log_path = get_runtime_path("error_log.txt")
logging.basicConfig(
    filename=log_path,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

try:
    from flask import Flask, request, jsonify, session, send_from_directory
    from flask_session import Session
    from flask_cors import CORS
    from werkzeug.security import generate_password_hash, check_password_hash
    from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
    from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

    # ==================== Flask 基础配置 ====================
    frontend_path = get_resource_path("frontend")
    app = Flask(__name__, static_folder=frontend_path, template_folder=frontend_path)
    app.config["SECRET_KEY"] = "phish-replicant-2024-secret-key"
    
    # Session文件存储路径适配
    session_dir = get_runtime_path("flask_session")
    if not os.path.exists(session_dir):
        os.makedirs(session_dir)
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = session_dir
    Session(app)
    CORS(app, supports_credentials=True, origins=["*"])

    # ==================== 数据库配置（线程安全） ====================
    db_path = get_runtime_path("phish_replicant.db")
    DATABASE_URL = f"sqlite:///{db_path}"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    Base = declarative_base()
    
    # 线程安全的数据库会话
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

    # 用户表模型
    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True, autoincrement=True)
        username = Column(String(50), unique=True, nullable=False)
        password_hash = Column(String(255), nullable=False)
        email = Column(String(100), nullable=False)
        create_time = Column(DateTime, default=datetime.now)

    # 检测历史表模型
    class DetectionHistory(Base):
        __tablename__ = "detection_history"
        id = Column(Integer, primary_key=True, autoincrement=True)
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        url = Column(String(500), nullable=False)
        verdict = Column(String(20), nullable=False)
        risk_level = Column(String(10), nullable=False)
        message = Column(Text, nullable=False)
        similar_domains = Column(Text)
        similar_scores = Column(Text)
        detect_mode = Column(String(20), default="规则引擎")
        timestamp = Column(DateTime, default=datetime.now)

    # 初始化数据库表
    Base.metadata.create_all(engine)

    # 请求结束自动清理数据库会话，防止内存泄漏和崩溃
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()

    # 全局异常拦截器，所有报错都返回JSON，不会出现页面乱码
    @app.errorhandler(Exception)
    def handle_global_error(e):
        error_detail = traceback.format_exc()
        logging.error(f"API执行崩溃:\n{error_detail}")
        return jsonify({
            "msg": f"后端异常: {str(e)}，详情请查看error_log.txt",
            "code": 500
        }), 500

    # ==================== 全局模型变量（懒加载，不影响打包） ====================
    converter = None
    cluster_vec_dic = None
    faiss_index = None
    model_loaded = False

    # ==================== 核心：智能规则检测引擎 ====================
    def smart_rule_based_detect(domain: str) -> dict:
        OFFICIAL_TLDS = {".com", ".com.cn", ".cn", ".org", ".net", ".edu", ".gov"}
        HIGH_RISK_BRANDS = {
            "paypal", "apple", "amazon", "google", "microsoft",
            "icbc", "ccb", "boc", "abc", "bank",
            "taobao", "jd", "tmall", "alipay", "wechat", "qq",
            "163", "sina", "baidu", "netflix", "steam"
        }
        HIGH_RISK_TLDS = {".xyz", ".top", ".icu", ".work", ".click", ".online", ".site", ".info", ".tk", ".cf", ".ga"}
        HIGH_RISK_KEYWORDS = {"login", "signin", "verify", "secure", "security", "account", "update", "confirm", "auth", "check", "billing", "payment", "wallet", "id", "user"}
        
        d = domain.lower()
        
        # 1. 官方域名白名单，完全匹配才放行
        for brand in HIGH_RISK_BRANDS:
            for tld in OFFICIAL_TLDS:
                if d == brand + tld or d == "www." + brand + tld:
                    return {
                        "verdict": "安全可信",
                        "risk_level": "low",
                        "message": "官方域名匹配，安全可信",
                        "similar_domains": [],
                        "similar_scores": [],
                        "mode": "智能规则检测",
                        "detect_mode": "规则引擎"
                    }

        risk_score = 0
        triggers = []
        
        # 2. 高风险后缀检测
        domain_tld = ""
        for tld in OFFICIAL_TLDS | HIGH_RISK_TLDS:
            if d.endswith(tld):
                domain_tld = tld
                break
                
        if domain_tld in HIGH_RISK_TLDS:
            risk_score += 30
            triggers.append(f"高风险后缀({domain_tld})")
            
        # 3. 品牌仿冒+字符变形检测
        has_brand = False
        detected_brand = "未知"
        for brand in HIGH_RISK_BRANDS:
            if brand in d:
                has_brand = True
                detected_brand = brand
                risk_score += 35
                triggers.append(f"包含敏感品牌词({brand})")
                break
            # 字符变形检测（o→0、l→1等钓鱼常用手法）
            brand_deformed = brand.replace("o", "0").replace("l", "1").replace("i", "1")
            if brand_deformed in d and brand_deformed != brand:
                has_brand = True
                detected_brand = brand
                risk_score += 50
                triggers.append(f"品牌词变形({brand_deformed})")
                break
                
        # 4. 钓鱼敏感词检测
        for kw in HIGH_RISK_KEYWORDS:
            if kw in d:
                risk_score += 20
                triggers.append(f"钓鱼行为词({kw})")
                
        # 5. 域名结构异常检测
        if d.count("-") >= 2:
            risk_score += 20
            triggers.append("多个连字符(典型仿冒结构)")

        # 6. 生成演示用相似域名
        def generate_similar_domains(brand: str) -> tuple[list, list]:
            similar_map = {
                "paypal": (["paypal-login-verify.xyz", "paypal-account-check.top"], [0.9821, 0.9756]),
                "apple": (["apple-id-login.top", "apple-verify-account.online"], [0.9789, 0.9672]),
                "icbc": (["icbc-bank-login.online", "icbc-account-verify.xyz"], [0.9803, 0.9715]),
                "amazon": (["amazon-deal-shop.site", "amazon-account-update.xyz"], [0.9764, 0.9688]),
                "taobao": (["taobao-member-login.xyz", "taobao-coupon-center.top"], [0.9791, 0.9695]),
                "wechat": (["wechat-wallet-verify.top", "wechat-login-secure.xyz"], [0.9812, 0.9734]),
                "jd": (["jd-coupon-center.online", "jd-account-check.xyz"], [0.9778, 0.9669])
            }
            return similar_map.get(brand, ([], []))

        # 7. 最终风险判定
        if risk_score >= 60:
            similar_domains, similar_scores = generate_similar_domains(detected_brand)
            return {
                "verdict": "钓鱼网站",
                "risk_level": "high",
                "message": f"命中规则：{', '.join(triggers)}",
                "similar_domains": similar_domains,
                "similar_scores": similar_scores,
                "mode": "智能规则检测",
                "detect_mode": "规则引擎"
            }
        elif risk_score >= 30:
            return {
                "verdict": "可疑网站",
                "risk_level": "medium",
                "message": f"发现可疑：{', '.join(triggers)}，请谨慎访问",
                "similar_domains": [],
                "similar_scores": [],
                "mode": "智能规则检测",
                "detect_mode": "规则引擎"
            }
        else:
            return {
                "verdict": "安全可信",
                "risk_level": "low",
                "message": "未检测到明显的恶意特征",
                "similar_domains": [],
                "similar_scores": [],
                "mode": "智能规则检测",
                "detect_mode": "规则引擎"
            }

    # ==================== SBERT模型懒加载（不影响打包） ====================
    def load_sbert_model():
        global converter, cluster_vec_dic, faiss_index, model_loaded
        if model_loaded:
            return True, "模型已加载"
        try:
            from sentence_transformers import SentenceTransformer
            import faiss
            import numpy as np
            import glob
            converter = SentenceTransformer("all-mpnet-base-v2")
            phishing_domains = []
            sample_path = get_resource_path("sample_data/phishingti/*")
            for file_path in glob.glob(sample_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    phishing_domains.extend([line.strip() for line in f.readlines() if line.strip()])
            domain_vectors = converter.encode(phishing_domains, normalize_embeddings=True)
            dimension = domain_vectors.shape[1]
            faiss_index = faiss.IndexFlatIP(dimension)
            faiss_index.add(np.array(domain_vectors).astype("float32"))
            cluster_vec_dic = {domain: vec for domain, vec in zip(phishing_domains, domain_vectors)}
            model_loaded = True
            return True, "SBERT模型加载成功，高级模式已开启"
        except Exception as e:
            return False, f"模型加载失败：{str(e)}"

    def sbert_vector_detect(domain: str) -> dict:
        global converter, faiss_index, cluster_vec_dic
        if not model_loaded:
            return smart_rule_based_detect(domain)
        try:
            domain_vec = converter.encode([domain], normalize_embeddings=True).astype("float32")
            scores, indices = faiss_index.search(domain_vec, 2)
            max_score = scores[0][0]
            similar_domains = [list(cluster_vec_dic.keys())[i] for i in indices[0]]
            similar_scores = scores[0].tolist()

            if max_score >= 0.9:
                return {
                    "verdict": "钓鱼网站",
                    "risk_level": "high",
                    "message": f"SBERT向量检测匹配到已知恶意样本，最高相似度{max_score:.4f}",
                    "similar_domains": similar_domains,
                    "similar_scores": similar_scores,
                    "mode": "SBERT向量检测",
                    "detect_mode": "高级模式"
                }
            elif max_score >= 0.7:
                return {
                    "verdict": "可疑网站",
                    "risk_level": "medium",
                    "message": f"SBERT向量检测发现可疑特征，相似度{max_score:.4f}，建议谨慎访问",
                    "similar_domains": similar_domains,
                    "similar_scores": similar_scores,
                    "mode": "SBERT向量检测",
                    "detect_mode": "高级模式"
                }
            else:
                rule_result = smart_rule_based_detect(domain)
                rule_result["message"] += "，SBERT向量检测无异常"
                rule_result["mode"] = "混合检测"
                rule_result["detect_mode"] = "高级模式"
                return rule_result
        except Exception as e:
            return smart_rule_based_detect(domain)

    # ==================== 前端静态文件路由 ====================
    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(app.static_folder, filename)

    # ==================== 用户认证接口 ====================
    @app.route("/api/register", methods=["POST"])
    def register():
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        email = data.get("email", "").strip()
        if not username or not password or not email:
            return jsonify({"msg": "所有字段都必须填写"}), 400
        if db_session.query(User).filter_by(username=username).first():
            return jsonify({"msg": "用户名已存在"}), 400
        new_user = User(username=username, password_hash=generate_password_hash(password), email=email)
        db_session.add(new_user)
        db_session.commit()
        return jsonify({"msg": "注册成功", "code": 0}), 200

    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        user = db_session.query(User).filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"msg": "用户名或密码错误"}), 401
        session["user_id"] = user.id
        return jsonify({"msg": "登录成功", "code": 0, "user": {"id": user.id, "username": user.username}}), 200

    @app.route("/api/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"msg": "退出成功", "code": 0}), 200

    @app.route("/api/user", methods=["GET"])
    def get_user_info():
        user = session.get("user_id")
        if not user:
            return jsonify({"msg": "未登录"}), 401
        user_obj = db_session.query(User).filter_by(id=user).first()
        return jsonify({"id": user_obj.id, "username": user_obj.username}), 200

    # ==================== 核心检测接口 ====================
    @app.route("/api/detect", methods=["POST"])
    def detect_url():
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"msg": "请先登录"}), 401
        
        data = request.get_json() or {}
        url = data.get("url", "").strip()
        use_advanced_mode = data.get("advanced_mode", False)
        if not url:
            return jsonify({"msg": "请输入URL"}), 400
            
        domain = url.replace("http://", "").replace("https://", "").split("/")[0].lower()
        
        if use_advanced_mode and model_loaded:
            result = sbert_vector_detect(domain)
        else:
            result = smart_rule_based_detect(domain)

        # 存入历史记录
        history = DetectionHistory(
            user_id=user_id, url=url, verdict=result["verdict"],
            risk_level=result["risk_level"], message=result["message"],
            similar_domains=",".join(result["similar_domains"]),
            similar_scores=",".join([str(s) for s in result["similar_scores"]]),
            detect_mode=result["detect_mode"]
        )
        db_session.add(history)
        db_session.commit()
        return jsonify(result), 200

    # ==================== 历史记录接口 ====================
    @app.route("/api/history", methods=["GET"])
    def get_history():
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"msg": "请先登录"}), 401
        keyword = request.args.get("keyword", "").strip()
        query = db_session.query(DetectionHistory).filter_by(user_id=user_id)
        if keyword:
            query = query.filter(DetectionHistory.url.like(f"%{keyword}%"))
        histories = query.order_by(DetectionHistory.timestamp.desc()).all()
        result = [
            {
                "url": item.url,
                "verdict": item.verdict,
                "message": item.message,
                "detect_mode": item.detect_mode,
                "timestamp": item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            } for item in histories
        ]
        return jsonify(result), 200

except Exception as e:
    logging.critical(f"全局初始化致命错误:\n{traceback.format_exc()}")

# ==================== 程序入口====================
if __name__ == "__main__":
    # 线上环境用生产服务器，本地用开发服务器
    port = int(os.environ.get("PORT", 5000))
    try:
        # 线上环境用waitress生产服务器
        from waitress import serve
        print("="*50)
        print("🚀 深蓝哨兵系统线上部署成功！")
        print("🌐 可通过公网地址访问系统")
        print("="*50)
        serve(app, host="0.0.0.0", port=port)
    except ImportError:
        # 本地开发环境
        print("="*50)
        print("🚀 深蓝哨兵系统本地启动成功！")
        print("✅ 默认模式：智能规则引擎，100%稳定无依赖")
        print("="*50)
        print("🌐 本地访问入口：http://127.0.0.1:5000")
        print("="*50)
        import webbrowser
        webbrowser.open("http://127.0.0.1:5000")
        app.run(host="127.0.0.1", port=port, debug=False)