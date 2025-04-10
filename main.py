import os
import tkinter as tk
from tkinter import messagebox, filedialog
import random
import string
import json
import pyotp
import datetime
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# AES kryptering och dekryptering med PBKDF2
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

def encrypt(password, data):
    salt = get_random_bytes(16)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
    encrypted = cipher.encrypt(padded_data.encode())
    return base64.b64encode(salt + iv + encrypted).decode()

def decrypt(password, enc_data):
    raw = base64.b64decode(enc_data)
    salt, iv, encrypted = raw[:16], raw[16:32], raw[32:]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted).decode()
    pad_len = ord(decrypted[-1])
    return decrypted[:-pad_len]

def generate_password(length=12, special_chars=True, digits=True):
    characters = string.ascii_letters
    if special_chars:
        characters += string.punctuation
    if digits:
        characters += string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Språkdata
LANGUAGES = {
    "en": {
        "master_password": "Master Password",
        "service": "Service",
        "username": "Username",
        "category": "Category",
        "save_password": "Save Password",
        "show_history": "Show History",
        "login_failed": "Incorrect username or password.",
        "login": "Login",
        "password_saved": "Password saved for",
        "backup_created": "Backup created successfully.",
        "restore_success": "Passwords restored successfully.",
        "backup_not_found": "Backup file not found.",
        "no_passwords": "No passwords to backup.",
        "no_history": "No history available.",
        "success": "Success",
        "error": "Error",
        "all_fields_required": "All fields are required.",
        "action_history": "Action History"
    },
    "sv": {
        "master_password": "Huvudlösenord",
        "service": "Tjänst",
        "username": "Användarnamn",
        "category": "Kategori",
        "save_password": "Spara Lösenord",
        "show_history": "Visa Historik",
        "login_failed": "Fel användarnamn eller lösenord.",
        "login": "Logga In",
        "password_saved": "Lösenord sparat för",
        "backup_created": "Säkerhetskopia skapad.",
        "restore_success": "Lösenord återställda.",
        "backup_not_found": "Säkerhetskopia hittades inte.",
        "no_passwords": "Inga lösenord att säkerhetskopiera.",
        "no_history": "Ingen historik tillgänglig.",
        "success": "Klar",
        "error": "Fel",
        "all_fields_required": "Alla fält krävs.",
        "action_history": "Åtgärdshistorik"
    },
    "es": {
        "master_password": "Contraseña Maestra",
        "service": "Servicio",
        "username": "Nombre de usuario",
        "category": "Categoría",
        "save_password": "Guardar Contraseña",
        "show_history": "Mostrar Historial",
        "login_failed": "Nombre de usuario o contraseña incorrectos.",
        "login": "Iniciar sesión",
        "password_saved": "Contraseña guardada para",
        "backup_created": "Copia de seguridad creada correctamente.",
        "restore_success": "Contraseñas restauradas correctamente.",
        "backup_not_found": "No se encontró el archivo de copia de seguridad.",
        "no_passwords": "No hay contraseñas para respaldar.",
        "no_history": "No hay historial disponible.",
        "success": "Éxito",
        "error": "Error",
        "all_fields_required": "Todos los campos son obligatorios.",
        "action_history": "Historial de acciones"
    },
    "fr": {
        "master_password": "Mot de passe principal",
        "service": "Service",
        "username": "Nom d'utilisateur",
        "category": "Catégorie",
        "save_password": "Enregistrer le mot de passe",
        "show_history": "Afficher l'historique",
        "login_failed": "Nom d'utilisateur ou mot de passe incorrect.",
        "login": "Se connecter",
        "password_saved": "Mot de passe enregistré pour",
        "backup_created": "Sauvegarde créée avec succès.",
        "restore_success": "Mots de passe restaurés avec succès.",
        "backup_not_found": "Fichier de sauvegarde introuvable.",
        "no_passwords": "Aucun mot de passe à sauvegarder.",
        "no_history": "Aucun historique disponible.",
        "success": "Succès",
        "error": "Erreur",
        "all_fields_required": "Tous les champs sont requis.",
        "action_history": "Historique des actions"
    },
    "de": {
        "master_password": "Hauptpasswort",
        "service": "Dienst",
        "username": "Benutzername",
        "category": "Kategorie",
        "save_password": "Passwort speichern",
        "show_history": "Verlauf anzeigen",
        "login_failed": "Benutzername oder Passwort ist falsch.",
        "login": "Einloggen",
        "password_saved": "Passwort für gespeichert",
        "backup_created": "Backup erfolgreich erstellt.",
        "restore_success": "Passwörter erfolgreich wiederhergestellt.",
        "backup_not_found": "Backup-Datei nicht gefunden.",
        "no_passwords": "Keine Passwörter zum Sichern.",
        "no_history": "Kein Verlauf verfügbar.",
        "success": "Erfolg",
        "error": "Fehler",
        "all_fields_required": "Alle Felder sind erforderlich.",
        "action_history": "Aktionverlauf"
    },
    "it": {
        "master_password": "Password principale",
        "service": "Servizio",
        "username": "Nome utente",
        "category": "Categoria",
        "save_password": "Salva password",
        "show_history": "Mostra cronologia",
        "login_failed": "Nome utente o password errati.",
        "login": "Accedi",
        "password_saved": "Password salvata per",
        "backup_created": "Backup creato con successo.",
        "restore_success": "Password ripristinate con successo.",
        "backup_not_found": "File di backup non trovato.",
        "no_passwords": "Nessuna password da fare il backup.",
        "no_history": "Nessuna cronologia disponibile.",
        "success": "Successo",
        "error": "Errore",
        "all_fields_required": "Tutti i campi sono obbligatori.",
        "action_history": "Cronologia delle azioni"
    },
    "pt": {
        "master_password": "Senha mestra",
        "service": "Serviço",
        "username": "Nome de usuário",
        "category": "Categoria",
        "save_password": "Salvar senha",
        "show_history": "Mostrar histórico",
        "login_failed": "Nome de usuário ou senha incorretos.",
        "login": "Entrar",
        "password_saved": "Senha salva para",
        "backup_created": "Backup criado com sucesso.",
        "restore_success": "Senhas restauradas com sucesso.",
        "backup_not_found": "Arquivo de backup não encontrado.",
        "no_passwords": "Sem senhas para fazer backup.",
        "no_history": "Nenhum histórico disponível.",
        "success": "Sucesso",
        "error": "Erro",
        "all_fields_required": "Todos os campos são obrigatórios.",
        "action_history": "Histórico de ações"
    },
    "ru": {
        "master_password": "Основной пароль",
        "service": "Служба",
        "username": "Имя пользователя",
        "category": "Категория",
        "save_password": "Сохранить пароль",
        "show_history": "Показать историю",
        "login_failed": "Неверное имя пользователя или пароль.",
        "login": "Войти",
        "password_saved": "Пароль сохранен для",
        "backup_created": "Резервная копия успешно создана.",
        "restore_success": "Пароли успешно восстановлены.",
        "backup_not_found": "Файл резервной копии не найден.",
        "no_passwords": "Нет паролей для резервного копирования.",
        "no_history": "История не доступна.",
        "success": "Успех",
        "error": "Ошибка",
        "all_fields_required": "Все поля обязательны.",
        "action_history": "История действий"
    },
    "zh": {
        "master_password": "主密码",
        "service": "服务",
        "username": "用户名",
        "category": "类别",
        "save_password": "保存密码",
        "show_history": "显示历史",
        "login_failed": "用户名或密码错误。",
        "login": "登录",
        "password_saved": "密码已保存",
        "backup_created": "备份成功创建。",
        "restore_success": "密码已成功恢复。",
        "backup_not_found": "未找到备份文件。",
        "no_passwords": "没有密码可备份。",
        "no_history": "没有历史记录。",
        "success": "成功",
        "error": "错误",
        "all_fields_required": "所有字段为必填。",
        "action_history": "操作历史"
    },
    "ja": {
        "master_password": "マスターパスワード",
        "service": "サービス",
        "username": "ユーザー名",
        "category": "カテゴリ",
        "save_password": "パスワードを保存",
        "show_history": "履歴を表示",
        "login_failed": "ユーザー名またはパスワードが間違っています。",
        "login": "ログイン",
        "password_saved": "パスワードが保存されました",
        "backup_created": "バックアップが正常に作成されました。",
        "restore_success": "パスワードが正常に復元されました。",
        "backup_not_found": "バックアップファイルが見つかりません。",
        "no_passwords": "バックアップするパスワードがありません。",
        "no_history": "履歴は利用できません。",
        "success": "成功",
        "error": "エラー",
        "all_fields_required": "すべてのフィールドは必須です。",
        "action_history": "アクション履歴"
    },
    "ar": {
        "master_password": "كلمة السر الرئيسية",
        "service": "الخدمة",
        "username": "اسم المستخدم",
        "category": "الفئة",
        "save_password": "حفظ كلمة السر",
        "show_history": "عرض التاريخ",
        "login_failed": "اسم المستخدم أو كلمة السر غير صحيحة.",
        "login": "تسجيل الدخول",
        "password_saved": "تم حفظ كلمة السر لـ",
        "backup_created": "تم إنشاء النسخة الاحتياطية بنجاح.",
        "restore_success": "تم استعادة كلمات السر بنجاح.",
        "backup_not_found": "لم يتم العثور على ملف النسخة الاحتياطية.",
        "no_passwords": "لا توجد كلمات سر للاحتفاظ بها.",
        "no_history": "لا توجد تاريخ متاح.",
        "success": "نجاح",
        "error": "خطأ",
        "all_fields_required": "جميع الحقول مطلوبة.",
        "action_history": "تاريخ الإجراءات"
    },
    "nl": {
        "master_password": "Masterwachtwoord",
        "service": "Service",
        "username": "Gebruikersnaam",
        "category": "Categorie",
        "save_password": "Wachtwoord opslaan",
        "show_history": "Toon geschiedenis",
        "login_failed": "Onjuiste gebruikersnaam of wachtwoord.",
        "login": "Inloggen",
        "password_saved": "Wachtwoord opgeslagen voor",
        "backup_created": "Back-up succesvol gemaakt.",
        "restore_success": "Wachtwoorden succesvol hersteld.",
        "backup_not_found": "Back-upbestand niet gevonden.",
        "no_passwords": "Geen wachtwoorden om op te slaan.",
        "no_history": "Geen geschiedenis beschikbaar.",
        "success": "Succes",
        "error": "Fout",
        "all_fields_required": "Alle velden zijn verplicht.",
        "action_history": "Actiegeschiedenis"
    },
    "tr": {
        "master_password": "Ana Şifre",
        "service": "Hizmet",
        "username": "Kullanıcı adı",
        "category": "Kategori",
        "save_password": "Şifreyi Kaydet",
        "show_history": "Geçmişi Göster",
        "login_failed": "Kullanıcı adı veya şifre yanlış.",
        "login": "Giriş Yap",
        "password_saved": "Şifre kaydedildi",
        "backup_created": "Yedek başarıyla oluşturuldu.",
        "restore_success": "Şifreler başarıyla geri yüklendi.",
        "backup_not_found": "Yedek dosyası bulunamadı.",
        "no_passwords": "Yedeklenecek şifre yok.",
        "no_history": "Geçmiş mevcut değil.",
        "success": "Başarı",
        "error": "Hata",
        "all_fields_required": "Tüm alanlar gereklidir.",
        "action_history": "İşlem Geçmişi"
    },
    "hi": {
        "master_password": "मुख्य पासवर्ड",
        "service": "सेवा",
        "username": "उपयोगकर्ता नाम",
        "category": "श्रेणी",
        "save_password": "पासवर्ड सेव करें",
        "show_history": "इतिहास दिखाएं",
        "login_failed": "गलत उपयोगकर्ता नाम या पासवर्ड।",
        "login": "लॉग इन करें",
        "password_saved": "पासवर्ड सेव किया गया",
        "backup_created": "बैकअप सफलतापूर्वक बनाया गया।",
        "restore_success": "पासवर्ड सफलतापूर्वक बहाल किए गए।",
        "backup_not_found": "बैकअप फ़ाइल नहीं मिली।",
        "no_passwords": "बैकअप करने के लिए कोई पासवर्ड नहीं है।",
        "no_history": "कोई इतिहास उपलब्ध नहीं है।",
        "success": "सफलता",
        "error": "त्रुटि",
        "all_fields_required": "सभी फ़ील्ड आवश्यक हैं।",
        "action_history": "क्रियाओं का इतिहास"
    },
    "ko": {
        "master_password": "마스터 비밀번호",
        "service": "서비스",
        "username": "사용자 이름",
        "category": "카테고리",
        "save_password": "비밀번호 저장",
        "show_history": "기록 보기",
        "login_failed": "잘못된 사용자 이름 또는 비밀번호.",
        "login": "로그인",
        "password_saved": "비밀번호가 저장되었습니다",
        "backup_created": "백업이 성공적으로 생성되었습니다.",
        "restore_success": "비밀번호가 성공적으로 복원되었습니다.",
        "backup_not_found": "백업 파일을 찾을 수 없습니다.",
        "no_passwords": "백업할 비밀번호가 없습니다.",
        "no_history": "기록이 없습니다.",
        "success": "성공",
        "error": "오류",
        "all_fields_required": "모든 필드가 필수입니다.",
        "action_history": "작업 기록"
    },
    "uk": {
        "master_password": "Головний пароль",
        "service": "Сервіс",
        "username": "Ім'я користувача",
        "category": "Категорія",
        "save_password": "Зберегти пароль",
        "show_history": "Показати історію",
        "login_failed": "Невірне ім'я користувача або пароль.",
        "login": "Увійти",
        "password_saved": "Пароль збережено для",
        "backup_created": "Резервну копію успішно створено.",
        "restore_success": "Паролі успішно відновлено.",
        "backup_not_found": "Файл резервної копії не знайдено.",
        "no_passwords": "Немає паролів для резервного копіювання.",
        "no_history": "Історія не доступна.",
        "success": "Успіх",
        "error": "Помилка",
        "all_fields_required": "Усі поля обов'язкові.",
        "action_history": "Історія дій"
    }
}

# Funktion för att hämta text baserat på valt språk
def get_text(key, language="en"):
    return LANGUAGES.get(language, LANGUAGES["en"]).get(key, key)

# Funktion för att visa meddelande baserat på valt språk
def show_message(title, message, language="en"):
    messagebox.showinfo(get_text(title, language), get_text(message, language))

# Huvudfunktioner för lösenordshanteraren
def save_password_ui(user, language="en"):
    service = service_entry.get()
    username = username_entry.get()
    category = category_entry.get()
    master_password = master_password_entry.get()
    if not all([service, username, category, master_password]):
        show_message("error", "All fields are required.", language)
        return
    password = generate_password()
    encrypted_password = encrypt(master_password, password)
    password_data = load_passwords(master_password, user)
    if category not in password_data:
        password_data[category] = {}
    password_data[category][service] = {
        'username': username,
        'password': encrypted_password,
        'last_updated': str(datetime.datetime.now())
    }
    with open(f"{user}_passwords.json", "w") as file:
        json.dump(password_data, file, indent=4)
    show_message("success", f"Password saved for {service}:\n{password}", language)

def load_passwords(master_password, user):
    file_name = f"{user}_passwords.json"
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            data = json.load(file)
            for category, services in data.items():
                for service, details in services.items():
                    encrypted_password = details['password']
                    decrypted_password = decrypt(master_password, encrypted_password)
                    details['password'] = decrypted_password
            return data
    return {}

def login(username, password):
    return username == "admin" and password == "root"

def login_ui(language="en"):
    username = username_entry.get()
    password = password_entry.get()
    if login(username, password):
        login_window.destroy()
        show_main_window(username, language)
    else:
        show_message("login_failed", "Incorrect username or password.", language)

def create_hamburger_menu(root, user):
    # Skapa en knapp för hamburgermenyn
    menu_button = tk.Button(root, text="☰", font=("Arial", 20), bg="#2d2d2d", fg="#ffffff", command=open_menu)
    menu_button.pack(side="left", padx=10)

    # Funktion för att öppna menyn
    def open_menu():
        menu = tk.Toplevel(root)
        menu.title("Menu")
        menu.geometry("200x150")
        menu.configure(bg="#2d2d2d")

        # Skapa en knapp för att visa historik
        history_button = tk.Button(menu, text="Show History", command=lambda: show_history(user), bg="#1e90ff", fg="#ffffff", font=("Arial", 12), width=20, height=2)
        history_button.pack(pady=10)

    # Funktion för att visa historik
    def show_history(user):
        history_file = f"{user}_history.json"
        if not os.path.exists(history_file):
            messagebox.showinfo("Action History", "No history available.")
            return
        
        with open(history_file, "r") as file:
            history = json.load(file)

        history_window = tk.Toplevel()
        history_window.title("Action History")
        history_window.configure(bg="#2d2d2d")

        for entry in history[::-1]:
            text = f"[{entry['timestamp']}] {entry['action']} - Service: {entry.get('service', '')}, Category: {entry.get('category', '')}"
            label = tk.Label(history_window, text=text, bg="#2d2d2d", fg="#ffffff", anchor="w", justify="left")
            label.pack(fill="both", padx=10, pady=2)

def show_main_window(user, language):
    global service_entry, username_entry, category_entry, master_password_entry
    root = tk.Tk()
    root.title("Password Manager")
    root.configure(bg="#2d2d2d")

    label_style = {'bg': "#2d2d2d", 'fg': "#ffffff", 'font': ("Arial", 12, "bold")}
    entry_style = {'bg': "#424242", 'fg': "#ffffff", 'font': ("Arial", 12), 'bd': 2, 'relief': "solid"}
    button_style = {'bg': "#1e90ff", 'fg': "#ffffff", 'font': ("Arial", 12, "bold"), 'width': 20, 'height': 2, 'bd': 0}

    tk.Label(root, text="Master Password", **label_style).pack(pady=5)
    master_password_entry = tk.Entry(root, show="*", **entry_style)
    master_password_entry.pack(pady=5)

    tk.Label(root, text="Service", **label_style).pack(pady=5)
    service_entry = tk.Entry(root, **entry_style)
    service_entry.pack(pady=5)

    tk.Label(root, text="Username", **label_style).pack(pady=5)
    username_entry = tk.Entry(root, **entry_style)
    username_entry.pack(pady=5)

    tk.Label(root, text="Category", **label_style).pack(pady=5)
    category_entry = tk.Entry(root, **entry_style)
    category_entry.pack(pady=5)

    save_button = tk.Button(root, text="Save Password", command=lambda: save_password_ui(user), **button_style)
    save_button.pack(pady=15)

    # Skapa hamburgermenyn här
    create_hamburger_menu(root, user)

    root.mainloop()

def show_login_window(language="en"):
    global login_window, username_entry, password_entry
    login_window = tk.Tk()
    login_window.title(get_text("login", language))
    login_window.configure(bg="#2d2d2d")

    label_style = {'bg': "#2d2d2d", 'fg': "#ffffff", 'font': ("Arial", 12, "bold")}
    entry_style = {'bg': "#424242", 'fg': "#ffffff", 'font': ("Arial", 12), 'bd': 2, 'relief': "solid"}
    button_style = {'bg': "#1e90ff", 'fg': "#ffffff", 'font': ("Arial", 12, "bold"), 'width': 20, 'height': 2, 'bd': 0}

    tk.Label(login_window, text=get_text("login", language), **label_style).pack(pady=10)
    tk.Label(login_window, text=get_text("username", language), **label_style).pack(pady=5)
    username_entry = tk.Entry(login_window, **entry_style)
    username_entry.pack(pady=5)

    tk.Label(login_window, text=get_text("master_password", language), **label_style).pack(pady=5)
    password_entry = tk.Entry(login_window, show="*", **entry_style)
    password_entry.pack(pady=5)

    login_button = tk.Button(login_window, text=get_text("login", language), command=lambda: login_ui(username_entry.get(), password_entry.get(), language), **button_style)
    login_button.pack(pady=15)

    login_window.mainloop()

# Kör login-fönstret
show_login_window(language="en")
