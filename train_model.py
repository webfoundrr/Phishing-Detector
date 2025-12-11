import numpy as np
import pandas as pd
import re
import math
import joblib
import os
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import sys

try:
    import idna
    IDNA_AVAILABLE = True
except ImportError:
    IDNA_AVAILABLE = False

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

print("=" * 60)
print("ОБУЧЕНИЕ МОДЕЛИ PHISHING DETECTOR")
print("=" * 60)

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def normalize_hostname(hostname):
    if not hostname:
        return hostname
    
    try:
        if hostname.startswith('xn--'):
            parts = hostname.split('.')
            normalized_parts = []
            for part in parts:
                if part.startswith('xn--'):
                    try:
                        if IDNA_AVAILABLE:
                            decoded = idna.decode(part.encode('ascii'))
                            normalized_parts.append(decoded)
                        else:
                            if part == 'xn--p1ai':
                                normalized_parts.append('рф')
                            else:
                                normalized_parts.append(part)
                    except:
                        normalized_parts.append(part)
                else:
                    normalized_parts.append(part)
            return '.'.join(normalized_parts)
    except:
        pass
    
    return hostname

def extract_features(url):
    features = []
    
    if not re.match(r'^https?://', url):
        parse_url = 'http://' + url
    else:
        parse_url = url

    try:
        parsed = urlparse(parse_url)
        hostname = parsed.netloc
        path = parsed.path
    except:
        hostname = ""
        path = ""

    hostname_normalized = normalize_hostname(hostname)
    hostname_lower = hostname_normalized.lower() if hostname_normalized else ""
    path = path.lower() if path else ""

    ip_pattern = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
    features.append(1 if ip_pattern else 0)
    
    features.append(1 if len(url) > 75 else 0)
    
    hostname_lower = hostname.lower() if hostname else ""
    short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    is_short_url = any(short in hostname_lower for short in short_domains)
    features.append(1 if is_short_url else 0)
    
    features.append(1 if '@' in url else 0)
    
    if '://' in url:
        after_protocol = url.split('://', 1)[1]
        features.append(1 if '//' in after_protocol else 0)
    else:
        features.append(0)
    
    if hostname:
        has_prefix_suffix = hostname.startswith('-') or hostname.endswith('-')
        if not has_prefix_suffix:
            for part in hostname.split('.'):
                if part.startswith('-') or part.endswith('-'):
                    has_prefix_suffix = True
                    break
        features.append(1 if has_prefix_suffix else 0)
    else:
        features.append(0)
    
    if hostname:
        features.append(max(0, hostname.count('.') - 1))
    else:
        features.append(0)
    
    features.append(1 if parsed.scheme == 'https' else 0)
    
    if hostname:
        domain_parts = hostname.split('.')
        if len(domain_parts) > 1:
            main_domain = '.'.join(domain_parts[:-1])
            domain_len = len(main_domain)
        else:
            domain_len = len(hostname)
        known_short_domains = ['ya.ru', 'go.com', 'tv', 'io', 'ai', 'me', 'co', 'cc']
        if any(short in hostname_lower for short in known_short_domains):
            features.append(max(domain_len, 4))
        else:
            features.append(domain_len)
    else:
        features.append(0)
    
    if hostname and ':' in hostname:
        try:
            port_str = hostname.split(':')[1]
            if '/' in port_str:
                port_str = port_str.split('/')[0]
            port = int(port_str)
            features.append(1 if port not in [80, 443, 8080] else 0)
        except (ValueError, IndexError):
            features.append(0)
    else:
        features.append(0)
    
    special_chars = ['%', '&', '=', '?', '#', '+']
    special_count = sum(url.count(char) for char in special_chars)
    features.append(1 if special_count > 3 else 0)
    
    features.append(calculate_entropy(hostname))
    
    path = parsed.path.lower()
    
    known_domains = [
        'instagram.com', 'facebook.com', 'google.com', 'gmail.com', 'github.com', 
        'microsoft.com', 'apple.com', 'amazon.com', 'twitter.com',
        'linkedin.com', 'youtube.com', 'netflix.com', 'paypal.com',
        'telegram.org',
        'yandex.ru', 'ya.ru', 'mail.ru', 'rambler.ru', 'km.ru', 'qip.ru',
        'vk.com', 'ok.ru', 'livejournal.com', 'my.mail.ru',
        'ria.ru', 'tass.ru', 'kommersant.ru', 'iz.ru', 'rg.ru', 'lenta.ru',
        'gazeta.ru', 'rt.com', 'mk.ru', 'rbc.ru', 'vedomosti.ru', 'forbes.ru',
        'takiedela.ru', 'meduza.io', 'novayagazeta.ru', 'fontanka.ru', '74.ru',
        'baikal24.ru', 'chelob.ru', 'sibirrealty.ru',
        'rutube.ru', 'smotrim.ru', 'ivi.ru', 'kinopoisk.ru', 'more.tv',
        'start.ru', 'premier.ru', 'okko.tv', 'megogo.ru', 'amediateka.ru',
        'wildberries.ru', 'wildberries.com', 'ozon.ru', 'market.yandex.ru', 'aliexpress.ru',
        'citilink.ru', 'mvideo.ru', 'dns-shop.ru', 'eldorado.ru', 'lamoda.ru',
        'beru.ru', 'ulmart.ru', 'svyaznoy.ru', 'technopark.ru', 'obi.ru',
        'auchan.ru', 'lenta.com', 'magnit.ru', 'perekrestok.ru', '5ka.ru',
        'sberbank.ru', 'vtb.ru', 'alfabank.ru', 'tinkoff.ru', 'gazprombank.ru',
        'raiffeisen.ru', 'open.ru', 'sovcombank.ru', 'pochtabank.ru', 'rshb.ru',
        'mkb.ru', 'homecredit.ru', 'rsb.ru', 'yoomoney.ru', 'vbr.ru', 'tbank.ru',
        'gosuslugi.ru', 'nalog.ru', 'pfr.gov.ru', 'fss.ru', 'rosreestr.ru',
        'minzdrav.gov.ru', 'minobrnauki.gov.ru', 'economy.gov.ru',
        'uchi.ru', 'yaklass.ru', 'foxford.ru', 'gb.ru', 'netology.ru',
        'skillbox.ru', 'stepik.org', 'openedu.ru', 'lektorium.tv',
        'arzamas.academy', 'postnauka.ru', 'intuit.ru', 'universarium.org',
        'resh.edu.ru', 'mos.ru',
        'hh.ru', 'superjob.ru', 'rabota.ru', 'avito.ru', 'zarplata.ru',
        'trud.com', 'unity.ru', 'gorodrabot.ru', 'rabotamail.ru',
        'cian.ru', 'yard.ru', 'mirkvartir.ru', 'domclick.ru', 'ngs.ru',
        'etagi.com', 'youla.ru',
        'auto.ru', 'drom.ru', 'cars.ru', 'car.ru', 'zr.ru', 'autoreview.ru',
        'kolesa.ru', 'abw.by', 'mladsha.ru', 'avtopodbor.ru', 'autostat.ru',
        'autovesti.ru',
        'sberhealth.ru', 'napopravku.ru', 'prodoctorov.ru', 'medportal.ru',
        'stomatologii.ru', 'apteki.ru', 'eapteka.ru', 'health.mail.ru',
        'medicina.ru',
        'store.steampowered.com', 'kanobu.ru', 'stopgame.ru', 'igromania.ru',
        'gamexp.ru', 'gmbox.ru', 'ag.ru', 'playground.ru', 'riotgames.com',
        'worldoftanks.ru', 'worldofwarships.ru', 'cfire.mail.ru', 'warthunder.ru',
        'eda.ru', 'recepty.ru', 'povarenok.ru', 'gotovim-doma.ru', 'menu.ru',
        'delivery-club.ru', 'sbermarket.ru',
        'championat.com', 'sport-express.ru', 'sports.ru', 'matchtv.ru',
        'sportbox.ru', 'rfs.ru', 'fnl.ru', 'khl.ru', 'ffr.ru', 'volley.ru',
        'russiabasket.ru', 'tennis-russia.ru',
        'music.yandex.ru', 'zvuk.com', 'boom.ru', 'stereo.ru',
        'habr.com', '3dnews.ru', 'ixbt.com', 'cnews.ru', 'server.ru',
        'hosting.ru', 'reg.ru', 'nic.ru', 'timeweb.com', 'beget.com',
        'sprinthost.ru', 'firstvds.ru', 'selectel.ru', 'cloud.ru',
        'pikabu.ru', 'yaplakal.com', 'dirty.ru', 'fishki.net', 'beha.ru',
        'kp.ru', 'aif.ru', 'vm.ru', 'spbdnevnik.ru', 'nevnov.ru', '47news.ru',
        'gorod-plus.tv', 'online47.ru', 'lentv24.ru', 'moika78.ru', '78.ru',
        '5-tv.ru', 'saint-petersburg.ru', 'peterburg2.ru', 'spbinfo.ru',
        'karpovka.com', 'newkaliningrad.ru', 'klops.ru', 'kaliningrad.ru',
        'rugrad.eu', 'kgd.ru', 'drugoigorod.ru', 'samaratoday.ru',
        'progorodsamara.ru', 'volgnews.ru', 'sgpress.ru', '63.ru', 'niasamara.ru',
        'irr.ru', 'kufar.by', 'tut.by', 'onliner.by', '2gis.ru', 'nigma.ru',
        'sputnik.ru', 'yandex.ru', 'gismeteo.ru',
        'екатеринбург.рф', 'москва.рф', 'спб.рф', 'санкт-петербург.рф',
        'школа.рф', 'гимназия.рф', 'лицей.рф',
        'edu.ru', 'school.edu.ru', 'gymnasium.edu.ru', 'lyceum.edu.ru'
    ]
    
    is_educational = False
    if hostname_lower:
        educational_tlds = ['.рф', '.edu.ru', '.edu', '.school']
        if any(hostname_lower.endswith(tld) for tld in educational_tlds):
            is_educational = True
        
        educational_keywords = ['школа', 'гимназия', 'лицей', 'университет', 'институт', 
                               'колледж', 'училище', 'school', 'gymnasium', 'lyceum', 
                               'university', 'college', 'edu', 'екатеринбург', 'москва']
        if any(keyword in hostname_lower for keyword in educational_keywords):
            is_educational = True
    
    is_known_domain = any(
        hostname_lower == domain or 
        hostname_lower.endswith('.' + domain) or 
        (hostname_lower.endswith(domain) and (len(hostname_lower) == len(domain) or hostname_lower[-(len(domain)+1)] == '.'))
        for domain in known_domains
    )
    
    if is_educational:
        is_known_domain = True
    
    suspicious_words = ['verify', 'update', 'secure', 'confirm', 'validate']
    path_suspicious = ['login', 'account', 'bank']
    
    count_suspicious = sum(1 for word in suspicious_words if word in url.lower())
    
    if not is_known_domain:
        count_suspicious += sum(1 for word in path_suspicious if word in path and word not in hostname_lower)
    
    features.append(count_suspicious)
    features.append(1 if is_known_domain else 0)
    features.append(hostname.count('-') if hostname else 0)

    return features

print("\n[1/5] Загрузка датасетов из корня проекта...")

legit_data = []
phishing_data = []

if os.path.exists('legitimate_dataset.csv'):
    print("   Загрузка legitimate_dataset.csv...")
    df_legit = pd.read_csv('legitimate_dataset.csv')
    for _, row in df_legit.iterrows():
        url = str(row['url']).strip()
        if url and url != 'nan':
            legit_data.append({'url': url, 'label': 0})
    print(f"   Легитимные из legitimate_dataset.csv: {len(legit_data)}")

df_malicious = None
if os.path.exists('malicious_phish.csv'):
    print("   Загрузка malicious_phish.csv...")
    df_malicious = pd.read_csv('malicious_phish.csv')
    
    benign_df = df_malicious[df_malicious['type'] == 'benign']
    for url in benign_df['url']:
        url_str = str(url).strip()
        if url_str and url_str != 'nan':
            legit_data.append({'url': url_str, 'label': 0})
    print(f"   Легитимные (benign) из malicious_phish.csv: +{len(benign_df)}")
    
    phishing_df = df_malicious[df_malicious['type'].isin(['phishing', 'defacement', 'malware'])]
    for url in phishing_df['url']:
        url_str = str(url).strip()
        if url_str and url_str != 'nan':
            phishing_data.append({'url': url_str, 'label': 1})
    print(f"   Фишинговые из malicious_phish.csv: +{len(phishing_df)}")

if os.path.exists('phishing_site_urls.csv'):
    print("   Загрузка phishing_site_urls.csv...")
    df_phishing_sites = pd.read_csv('phishing_site_urls.csv')
    
    good_df = df_phishing_sites[df_phishing_sites['Label'].str.lower() == 'good']
    for url in good_df['URL']:
        url_str = str(url).strip()
        if url_str and url_str != 'nan':
            legit_data.append({'url': url_str, 'label': 0})
    print(f"   Легитимные (good) из phishing_site_urls.csv: +{len(good_df)}")
    
    bad_df = df_phishing_sites[df_phishing_sites['Label'].str.lower() == 'bad']
    for url in bad_df['URL']:
        url_str = str(url).strip()
        if url_str and url_str != 'nan':
            phishing_data.append({'url': url_str, 'label': 1})
    print(f"   Фишинговые (bad) из phishing_site_urls.csv: +{len(bad_df)}")

if os.path.exists('PhiUSIIL_Phishing_URL_Dataset.csv'):
    print("   Загрузка PhiUSIIL_Phishing_URL_Dataset.csv...")
    try:
        df_phiusil = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv')
        
        if 'URL' in df_phiusil.columns and 'label' in df_phiusil.columns:
            legit_phiusil = df_phiusil[df_phiusil['label'] == 0]
            for url in legit_phiusil['URL']:
                url_str = str(url).strip()
                if url_str and url_str != 'nan':
                    legit_data.append({'url': url_str, 'label': 0})
            print(f"   Легитимные из PhiUSIIL_Phishing_URL_Dataset.csv: +{len(legit_phiusil)}")
            
            phishing_phiusil = df_phiusil[df_phiusil['label'] == 1]
            for url in phishing_phiusil['URL']:
                url_str = str(url).strip()
                if url_str and url_str != 'nan':
                    phishing_data.append({'url': url_str, 'label': 1})
            print(f"   Фишинговые из PhiUSIIL_Phishing_URL_Dataset.csv: +{len(phishing_phiusil)}")
        else:
            print("   ⚠️ Файл PhiUSIIL_Phishing_URL_Dataset.csv не содержит колонки URL и label")
    except Exception as e:
        print(f"   ⚠️ Ошибка загрузки PhiUSIIL_Phishing_URL_Dataset.csv: {e}")

if os.path.exists('dataset_example.csv'):
    print("   Загрузка dataset_example.csv...")
    df_example = pd.read_csv('dataset_example.csv')
    for _, row in df_example.iterrows():
        url = str(row['url']).strip()
        if url and url != 'nan':
            label = int(row['label'])
            if label == 0:
                legit_data.append({'url': url, 'label': 0})
            else:
        phishing_data.append({'url': url, 'label': 1})
    print(f"   Из dataset_example.csv: легитимные +{sum(1 for _, r in df_example.iterrows() if int(r['label']) == 0)}, фишинговые +{sum(1 for _, r in df_example.iterrows() if int(r['label']) == 1)}")

print(f"\n   Итого загружено:")
print(f"   Легитимных URL: {len(legit_data)}")
print(f"   Фишинговых URL: {len(phishing_data)}")

print("\n   Удаление дубликатов...")
df_legit = pd.DataFrame(legit_data)
df_legit = df_legit.drop_duplicates(subset=['url'])
df_phishing = pd.DataFrame(phishing_data)
df_phishing = df_phishing.drop_duplicates(subset=['url'])

print(f"   Легитимные (уникальные): {len(df_legit)}")
print(f"   Фишинговые (уникальные): {len(df_phishing)}")

df_combined = pd.concat([pd.DataFrame(legit_data), df_phishing], ignore_index=True)
df = df_combined
print(f"   Всего: {len(df)} URL")
print(f"   Фишинг (1): {df['label'].sum()}")
print(f"   Легитимные (0): {len(df) - df['label'].sum()}")

print("\n[2/5] Извлечение признаков из URL...")
print("   Это может занять несколько минут...")

data = []
labels = []

chunk_size = 50000
total_chunks = (len(df) + chunk_size - 1) // chunk_size

for i in range(0, len(df), chunk_size):
    chunk = df.iloc[i:i+chunk_size]
    chunk_num = i // chunk_size + 1
    
    for _, row in chunk.iterrows():
        url = str(row['url']).strip()
        label = int(row['label'])
        if url and url != 'nan':
            try:
                features = extract_features(url)
                data.append(features)
                labels.append(label)
            except Exception as e:
                        continue
    
    if chunk_num % 5 == 0 or chunk_num == total_chunks:
        print(f"   Обработано: {chunk_num}/{total_chunks} частей ({len(data)} URL)")

X = np.array(data)
y = np.array(labels)

print(f"\n   Итого обработано: {len(X)} URL")
print(f"   Размерность признаков: {X.shape[1]}")

print("\n[3/5] Разделение на обучающую и тестовую выборки...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"   Обучающая выборка: {len(X_train)} URL")
print(f"   Тестовая выборка: {len(X_test)} URL")

print("\n[4/5] Обучение модели Random Forest...")
print("   Это займет несколько минут...")

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

clf.fit(X_train, y_train)
print("   Обучение завершено!")

print("\n[5/5] Оценка качества модели...")

train_pred = clf.predict(X_train)
train_accuracy = accuracy_score(y_train, train_pred)

test_pred = clf.predict(X_test)
test_accuracy = accuracy_score(y_test, test_pred)

print(f"\n   Точность на обучающей выборке: {train_accuracy:.4f} ({train_accuracy:.2%})")
print(f"   Точность на тестовой выборке: {test_accuracy:.4f} ({test_accuracy:.2%})")

print("\n   Детальный отчет:")
print(classification_report(y_test, test_pred, target_names=['Легитимный', 'Фишинг']))

cm = confusion_matrix(y_test, test_pred)
print("\n   Матрица ошибок:")
print(f"   [Легитимные правильно: {cm[0][0]}, ошибочно как фишинг: {cm[0][1]}]")
print(f"   [Фишинг ошибочно как легитимный: {cm[1][0]}, правильно: {cm[1][1]}]")

print("\n[СОХРАНЕНИЕ] Сохранение обученной модели...")
    model_path = 'phishing_model.pkl'
joblib.dump(clf, model_path)
print(f"   Модель сохранена в: {model_path}")

print("\n" + "=" * 60)
print("ОБУЧЕНИЕ ЗАВЕРШЕНО УСПЕШНО!")
print("=" * 60)
print(f"\nИспользуйте сохраненную модель в app.py для быстрой загрузки.")

