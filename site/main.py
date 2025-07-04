from flask import Flask, render_template, request, redirect, session, flash, url_for
from pymongo import MongoClient
from bs4 import BeautifulSoup
from datetime import datetime
from zoneinfo import ZoneInfo
import requests
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "секретный_ключ"

# Подключение к MongoDB
client = MongoClient("mongodb+srv://Admin1:Admin1234@cluster0.pg8mygq.mongodb.net/?retryWrites=true&w=majority")
db = client["loli_db"]
users_col = db["users"]
logins_col = db["logins"]
reports_col = db["reports"]

teams = {
    1: ["ilan229", "ScoudAdam", "RitsuTainaka", "Fish_Lover", "Elementalgod", "buterbrodius", "jjlancer", "Miron4ik240"],
    2: ["4ERNOVIK", "druidlegenda", "drunkencities", "loriz32","Rimura_7615", "S4yrEks", "Solution_Lop", "Frikezz"],
    3: ["Bufi161", "aheron123", "gromus123", "MERACK", "Tapo4kaTop", "vrscxd", "Hetutun", "Emilli", "Hirex_0", "ttimurk", "artem4k477"],
    4: ["CheloBechek", "EspadaWQ", "Globall", "Namero", "Siukumi", "Chipsi","Kotik_Krutoy","MNks","Ygasai"],
    5: ["Ksaylot", "timofey1236", "Wziro ", "xFresh11", "Quisimor", "ksen00n", "Frosty", "saweii", "Loulend", "holodtm1"],
    6: ["_F1ReX_","Matay", "Coci4_ka", "Die_Lay", "eewrqwer", "HluPa", "HuKa_HeT", "Icyer", "JohnDo3", "sh1nri", "Velezzz", "Dima2043", "TheFarbian"],
    7: ["F1GION_1","mitsuru", "Nesquik_", "playbodya_", "s0k1man", "vancyyy", "vendetta143vb", "Saxorok_931", "l0r3yz"],
    8: ["SoL0VeY112", "krrill", "Nemoralist", "Roksyyy", "CLIXXX", "menotis", "spusiwalker"],
    9: ["TheSomeDrop", "SpaYmiX", "Matrixx", "ivan_fox", "CRAZYSHOWYT", "Fifyz044", "di1lux", "sasha132100"],
    10: ["-_mandarin_-", "3lanau", "adws8", "dikiWark", "kousetsukini", "Martyres", "Mr_Kompaver", "PeChEniKa"]
}

role_priority = {
    "admin": 1,
    "user": 999
}

def parse_time_string(time_str):
    hours, minutes = 0, 0
    if "ч" in time_str:
        parts = time_str.split("ч")
        hours = int(parts[0].strip())
        if "мин" in parts[1]:
            minutes = int(parts[1].split("мин")[0].strip())
    elif "мин" in time_str:
        minutes = int(time_str.split("мин")[0].strip())
    return f"{hours} ч {minutes} мин"

def fetch_player_times(teams_list):
    try:
        url = "https://loliland.net/ru/team"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        players = soup.find_all("div", class_="player-card")
        print(f"Всего найдено игроков на странице: {len(players)}")  # <--- Добавлено

        result = {}
        all_team_players = set().union(*teams_list)

        for player in players:
            nickname_tag = player.find("div", class_="player__nickname")
            time_tags = player.find_all("p", class_="pc-data-text__main-text")
            role_tag = player.find("span", class_="player-group__name")

            if nickname_tag and len(time_tags) >= 2:
                nickname = nickname_tag.get_text(strip=True)
                if nickname in all_team_players:
                    session_time = parse_time_string(time_tags[0].get_text(strip=True))
                    total_time = parse_time_string(time_tags[1].get_text(strip=True))
                    role = role_tag.get_text(strip=True) if role_tag else ""
                    result[nickname] = {
                        "session": session_time,
                        "total": total_time,
                        "role": role
                    }
        print(f"Игроков из команды найдено: {len(result)}")  # <--- Добавлено
        return result
    except Exception as e:
        return {"error": f"Ошибка: {str(e)}"}


def format_report(players, player_data):
    report_date = datetime.now(ZoneInfo("Europe/Moscow")).strftime("%Y-%m-%d")
    lines = [f"Роль{' ' * 10}| Ник{' ' * 16}| Сессия{' ' * 10}| Месяц{' ' * 10}| Дата"]
    lines.append("-" * 80)

    def sort_key(p):
        data = player_data.get(p, {})
        role = data.get("role", "")
        return (role_priority.get(role.lower(), 999), p.lower())

    sorted_players = [p for p in sorted(players, key=sort_key) if p in player_data]

    for player in sorted_players:
        data = player_data[player]
        session = data["session"]
        total = data["total"]
        role = data["role"]
        lines.append(f"{role:13} | {player:20} | {session:13} | {total:13} | {report_date}")
    return "\n".join(lines)

def is_admin():
    if "user" not in session:
        return False
    user = users_col.find_one({"username": session["user"]})
    return user and user.get("role") == "admin"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form["username"]
        password = request.form["password"]

        user = users_col.find_one({"username": name})
        if user and check_password_hash(user["password"], password):
            session["user"] = name
            session["team_id"] = user["team_id"]
            logins_col.insert_one({
                "username": name,
                "team_id": user["team_id"],
                "login_time": datetime.now(ZoneInfo("Europe/Moscow"))
            })
            return redirect("/profile")
        flash("Неверное имя пользователя или пароль", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["username"]
        password = request.form["password"]
        team_id = int(request.form["team_id"])

        if not users_col.find_one({"username": name}):
            hashed_password = generate_password_hash(password)
            users_col.insert_one({
                "username": name,
                "password": hashed_password,
                "team_id": team_id,
                "role": "user"
            })
            flash("Регистрация успешна! Теперь войдите.", "success")
            return redirect("/")
        flash("Пользователь уже существует", "danger")
    return render_template("register.html")

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/")
    team_id = session["team_id"]
    players = teams.get(team_id, [])
    data = fetch_player_times([players])
    if "error" in data:
        return render_template("index.html", report="", team_num=team_id, error=data["error"], user_role="user")
    report = format_report(players, data)
    user = users_col.find_one({"username": session["user"]})
    role = user.get("role", "user") if user else "user"
    return render_template("index.html", report=report, team_num=team_id, error="", user_role=role)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/save_report", methods=["POST"])
def save_report():
    if "user" not in session:
        return redirect("/")
    team_id = session["team_id"]
    players = teams.get(team_id, [])
    data = fetch_player_times([players])
    if "error" in data:
        return render_template("index.html", report="", team_num=team_id, error=data["error"], user_role="user")

    report_text = format_report(players, data)

    reports_col.insert_one({
        "username": session["user"],
        "team_id": team_id,
        "report": report_text,
        "timestamp": datetime.now(ZoneInfo("Europe/Moscow"))
    })

    user = users_col.find_one({"username": session["user"]})
    role = user.get("role", "user") if user else "user"

    flash("Отчёт сохранён", "success")
    return render_template("index.html", report=report_text, team_num=team_id, error="", user_role=role)

@app.route("/old_reports")
def old_reports():
    if "user" not in session:
        return redirect("/")
    username = session["user"]
    user_reports = list(reports_col.find({"username": username}).sort("timestamp", -1))
    return render_template("old_reports.html", reports=user_reports)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect("/")

    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        user = users_col.find_one({"username": session["user"]})

        if not user or not check_password_hash(user["password"], old_password):
            flash("Старый пароль неверный", "danger")
            return redirect("/change_password")

        new_hashed = generate_password_hash(new_password)
        users_col.update_one({"username": session["user"]}, {"$set": {"password": new_hashed}})
        flash("Пароль успешно изменён", "success")
        return redirect("/profile")

    return render_template("change_password.html")

@app.route("/admin")
def admin_panel():
    if not is_admin():
        return "Доступ запрещён", 403

    all_reports = list(reports_col.find().sort("timestamp", -1))
    all_users = list(users_col.find())

    for r in all_reports:
        if "timestamp" in r and isinstance(r["timestamp"], datetime):
            r["timestamp"] = r["timestamp"].astimezone(ZoneInfo("Europe/Moscow"))

    return render_template("admin.html", reports=all_reports, users=all_users)

@app.route("/grant_admin/<username>")
def grant_admin(username):
    if not is_admin():
        return "Доступ запрещён", 403

    users_col.update_one({"username": username}, {"$set": {"role": "admin"}})
    flash(f"Пользователь {username} теперь администратор!", "success")
    return redirect("/admin")

@app.route("/delete_user/<username>", methods=["GET"])
def delete_user(username):
    if not is_admin():
        return "Доступ запрещён", 403

    if username == session.get("user"):
        flash("Нельзя удалить самого себя!", "danger")
        return redirect("/admin")

    result = users_col.delete_one({"username": username})
    if result.deleted_count == 1:
        flash(f"Пользователь {username} удалён.", "success")
    else:
        flash(f"Пользователь {username} не найден.", "danger")

    return redirect("/admin")

@app.route("/admin/switch_user/<username>")
def admin_switch_user(username):
    if not is_admin():
        return "Доступ запрещён", 403

    user = users_col.find_one({"username": username})
    if not user:
        flash("Пользователь не найден", "danger")
        return redirect("/admin")

    if "admin_original_user" not in session:
        session["admin_original_user"] = session["user"]

    session["user"] = user["username"]
    session["team_id"] = user.get("team_id", 0)

    flash(f"Вы вошли как {username}", "info")
    return redirect("/profile")

@app.route("/admin/switch_back")
def admin_switch_back():
    if "admin_original_user" not in session:
        flash("Нет сохранённого админ-аккаунта", "danger")
        return redirect("/")

    session["user"] = session["admin_original_user"]
    user = users_col.find_one({"username": session["user"]})
    session["team_id"] = user.get("team_id", 0)
    session.pop("admin_original_user")

    flash("Вы вернулись в админский аккаунт", "info")
    return redirect("/admin")

def ensure_users_collection():
    existing_collections = db.list_collection_names()
    if "users" not in existing_collections:
        print("[INFO] Создаём коллекцию 'users' и заполняем...")
        default_users = [
            {
                "username": "admin",
                "team_id": 0,
                "password": generate_password_hash("adminpass"),
                "role": "admin"
            },
            {
                "username": "BeeX",
                "team_id": 3,
                "password": generate_password_hash("pass"),
                "role": "admin"
            },
            {
                "username": "TheSomeDrop",
                "team_id": 9,
                "password": generate_password_hash("pass"),
                "role": "user"
            }
        ]
        db.create_collection("users")
        users_col.insert_many(default_users)
        print("[INFO] Коллекция 'users' успешно создана и заполнена.")
    else:
        print("[INFO] Коллекция 'users' уже существует.")




if __name__ == "__main__":
    ensure_users_collection()
    app.run(debug=True)
